import { existsSync, mkdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import {
  debianManifestPath,
  driftProblems,
  imageSources,
  IMAGES,
  loadDebianManifest,
  type ImageName,
} from './debian-sources';
import { releasedVersions } from '../release/version';
import { alsoProblems, release, releaseArgs } from './release';
import { must, REPO_ROOT, run } from './stack';
import {
  loadManifest,
  pinnedVersions,
  sha256File,
  sha256sums,
  sideFiles,
  SOURCES_DOCKERFILE,
  sourcesDir,
  sourcesIndex,
  versionProblems,
} from './sources';

/**
 * `pnpm deploy:release-images [--tag <tag>] [--also <tag>]… [--namespace <name>]` (rulings L1
 * and L2, release.md §5): builds qualor/server and qualor/scanner, checks that the Debian
 * packages each one contains are exactly those deploy/<image>/debian-sources.json pins (apt-get
 * installs the current versions, so a later build can differ), checks that `pnpm deploy:sources`
 * left every pinned file, verified, in .tmp/<image>-sources/, builds qualor/server-sources and
 * qualor/scanner-sources, and builds qualor/scanner-dotnet from the checked staging scanner: five
 * images, each tagged with --tag and every --also (the moving tags of release.md §2). Everything
 * is built under staging names first and only tagged `qualor/…:<tag>` once every check has passed
 * (release.ts). It never pushes: publishing is the release step of deploy/README.md.
 */
const SOURCE_URL = 'https://github.com/qualor-dev/qualor';

function build(ref: string, tag: string, args: string[]): void {
  process.stdout.write(`building ${ref}\n`);
  must(
    run(
      'docker',
      [
        'build',
        '--label',
        `org.opencontainers.image.version=${tag}`,
        '--label',
        `org.opencontainers.image.source=${SOURCE_URL}`,
        '-t',
        ref,
        ...args,
      ],
      { inherit: true },
    ),
    `docker build ${ref}`,
  );
}

/** Every file of .tmp/<image>-sources verified against SHA256SUMS as the manifests make it. */
async function checkSources(image: ImageName): Promise<string> {
  const entries = image === 'scanner' ? loadManifest() : [];
  const debian = loadDebianManifest(image);
  const dir = path.join(REPO_ROOT, sourcesDir(image));
  for (const side of sideFiles(image)) {
    if (!existsSync(path.join(dir, side))) {
      throw new Error(`${sourcesDir(image)}/${side} is missing: run pnpm deploy:sources first`);
    }
  }
  const sums = sha256sums(entries, debian);
  const stale =
    readFileSync(path.join(dir, 'SHA256SUMS'), 'utf8') !== sums ||
    readFileSync(path.join(dir, 'SOURCES.md'), 'utf8') !== sourcesIndex(image, entries, debian);
  if (stale) throw new Error(`${sourcesDir(image)} is stale: run pnpm deploy:sources`);
  for (const line of sums.trim().split('\n')) {
    const [sha256, file = ''] = line.split('  ');
    const full = path.join(dir, file);
    if (!existsSync(full) || (await sha256File(full)) !== sha256) {
      throw new Error(`${sourcesDir(image)}/${file} is missing or wrong: run pnpm deploy:sources`);
    }
  }
  return dir;
}

async function main(): Promise<void> {
  const args = releaseArgs(process.argv.slice(2));
  // release.md §5: the moving tags must be the ones imageTags gives, before anything is built.
  const moving = alsoProblems(args, releasedVersions());
  if (moving.length > 0) throw new Error(moving.join('\n'));
  const problems = versionProblems(loadManifest(), pinnedVersions());
  if (problems.length > 0) throw new Error(problems.join('\n'));
  const dirs = new Map<ImageName, string>();
  for (const image of IMAGES) dirs.set(image, await checkSources(image));
  const sourcesArgs = (image: ImageName): string[] => [
    '-f',
    SOURCES_DOCKERFILE,
    dirs.get(image) ?? '',
  ];
  const released = release(
    args,
    {
      imageArgs: {
        scanner: ['-f', path.join('deploy', 'scanner', 'Dockerfile'), '.'],
        server: ['-f', path.join('deploy', 'server', 'Dockerfile'), '.'],
      },
      sourcesArgs: { scanner: sourcesArgs('scanner'), server: sourcesArgs('server') },
      dotnetArgs: (scannerRef) => [
        '-f',
        path.join('deploy', 'scanner-dotnet', 'Dockerfile'),
        '--build-arg',
        `SCANNER_IMAGE=${scannerRef}`,
        '.',
      ],
      driftMessage: (image, ref, drift) =>
        `${ref} has other Debian packages than ${debianManifestPath(image)}; no release name ` +
        `was tagged. Run pnpm deploy:debian-sources ${image} --image ${ref}, then ` +
        `pnpm deploy:sources:\n  ${drift.join('\n  ')}`,
    },
    {
      build: (ref, buildArgs) => {
        build(ref, args.tag, buildArgs);
      },
      drift: (ref, image) => {
        const work = path.join(REPO_ROOT, '.tmp', 'debian-sources-work', `dpkg-${image}`);
        mkdirSync(work, { recursive: true });
        return driftProblems(imageSources(ref, work), loadDebianManifest(image));
      },
      tag: (source, target) => {
        must(run('docker', ['tag', source, target]), `docker tag ${source} ${target}`);
      },
      untag: (ref) => {
        must(run('docker', ['image', 'rm', ref]), `docker image rm ${ref}`);
      },
    },
  );
  process.stdout.write(
    `built ${released.join(', ')}; push them in this order, each sources image before its image ` +
      `(deploy/README.md, "Releasing the images")\n`,
  );
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
