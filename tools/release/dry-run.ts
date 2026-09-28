import {
  copyFileSync,
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { parse, parseDocument } from 'yaml';
import { BUN_VERSION, RELEASE_TARGETS, type ReleaseTarget } from '../../cli/scripts/targets';
import { freePort, must, REPO_ROOT, run } from '../deploy/stack';
import { releaseNotes } from './changelog';
import { releaseFiles, sha256sums, SUMS, SUMS_BUNDLE } from './checksums';
import { buildCliRelease, copyCliSources } from './cli';
import { signBlobArgs, verifyAttestationArgs, verifyImageArgs } from './cosign';
import { releaseRefs } from './images';
import { generateKeys, removeKeys, type Keys } from './keys';
import { buildManifest, type ImageRecord } from './manifest';
import {
  DRY_RUN_OPTIONS,
  hostRef,
  internalRef,
  newRegistry,
  pushChartToDryRun,
  pushToDryRun,
  signInDryRun,
  startRegistry,
  stopRegistry,
  type DryRunRegistry,
} from './registry';
import {
  cliDepsArgs,
  cliSbomArgs,
  pnpmCommand,
  REGISTRY_SOURCE_ENV,
  SBOM_IMAGES,
  spdxProblems,
  syftArgs,
} from './sbom';
import { buildToolbox, runTool, toWork } from './toolbox';
import { cosignVerifier, resolveVerifyKey, verifyRelease } from './verify';
import { currentVersion, imageTags, releasedVersions, type Version } from './version';

/**
 * `pnpm release:dry-run [--version <v>] [--skip-images] [--skip-cli-sources] [--targets a,b]`
 * (release.md §10). Everything lands in .tmp/release/<version>/; nothing leaves this machine: the
 * images go to a registry on 127.0.0.1 (removed afterwards), and the signatures are made with a
 * throwaway key (deleted afterwards). No git tag is created: the version is the checkout's.
 */
export interface DryRunOptions {
  version: Version;
  skipImages: boolean;
  skipCliSources: boolean;
  targets: ReleaseTarget[];
}

export function parseDryRunArgs(argv: readonly string[], current: Version): DryRunOptions {
  const args = argv[0] === '--' ? argv.slice(1) : argv;
  const value = (name: string): string | undefined => {
    const i = args.indexOf(name);
    return i === -1 ? undefined : (args[i + 1] ?? '');
  };
  const wanted = value('--version');
  if (wanted !== undefined && wanted !== current.text) {
    throw new Error(
      `the checkout is at ${current.text}, not ${wanted}: run pnpm release:version ${wanted} first`,
    );
  }
  const all = Object.keys(RELEASE_TARGETS) as ReleaseTarget[];
  const list = value('--targets');
  const targets =
    list === undefined
      ? all
      : list.split(',').map((t) => {
          if (!all.includes(t as ReleaseTarget)) {
            throw new Error(`unknown target ${t}; expected ${all.join(', ')}`);
          }
          return t as ReleaseTarget;
        });
  return {
    version: current,
    skipImages: args.includes('--skip-images'),
    skipCliSources: args.includes('--skip-cli-sources'),
    targets,
  };
}

/** Where a dry run writes by default (release.md §10); the tools test passes a scratch root. */
export const DEFAULT_OUTPUT_ROOT = path.join(REPO_ROOT, '.tmp');
export const releaseDir = (v: Version, root = DEFAULT_OUTPUT_ROOT): string =>
  path.join(root, 'release', v.text);
/** release.md §3: the keys and the CLI's production install; never in the release directory. */
export const workDir = (v: Version, root = DEFAULT_OUTPUT_ROOT): string =>
  path.join(root, 'release-work', v.text);

export const CHART_SOURCE = path.join(REPO_ROOT, 'deploy', 'helm', 'qualor');
const DIGEST = /^sha256:[0-9a-f]{64}$/;

/**
 * Ruling R-DIGEST: the chart in the repository pins the server by its tag (ruling RE6), but the
 * packaged chart of a release pins it by the digest the dry-run registry reported, so a published
 * chart always pulls exactly the image that was signed. Only `image.digest` changes.
 */
export function pinServerDigest(valuesYaml: string, digest: string): string {
  if (!DIGEST.test(digest)) throw new Error(`${digest} is not a sha256 digest`);
  const doc = parseDocument(valuesYaml);
  if (!doc.hasIn(['image', 'digest'])) throw new Error('values.yaml has no image.digest');
  doc.setIn(['image', 'digest'], digest);
  return doc.toString();
}

/**
 * release.md §10 step 5: lints and packages a copy of the chart (with the server digest when the
 * images were pushed) into <dir>/helm/, and checks that the package carries that digest.
 */
export function packageChart(
  v: Version,
  dir: string,
  work: string,
  serverDigest: string | null,
): string {
  const copy = path.join(work, 'chart', 'qualor');
  rmSync(copy, { recursive: true, force: true });
  cpSync(CHART_SOURCE, copy, { recursive: true });
  const valuesFile = path.join(copy, 'values.yaml');
  if (serverDigest !== null) {
    writeFileSync(valuesFile, pinServerDigest(readFileSync(valuesFile, 'utf8'), serverDigest));
  }
  const chart = toWork(copy);
  must(
    runTool('helm', ['lint', '--strict', chart, '-f', `${chart}/ci/embedded-values.yaml`]),
    'helm lint',
  );
  mkdirSync(path.join(dir, 'helm'), { recursive: true });
  must(
    runTool('helm', [
      'package',
      chart,
      '--version',
      v.text,
      '--app-version',
      v.text,
      '--destination',
      toWork(path.join(dir, 'helm')),
    ]),
    'helm package',
  );
  const file = `helm/qualor-${v.text}.tgz`;
  const shown = must(
    runTool('helm', ['show', 'values', toWork(path.join(dir, file))]),
    'helm show',
  );
  const packaged = (parse(shown.stdout) as { image?: { digest?: unknown } }).image?.digest;
  if (packaged !== (serverDigest ?? '')) {
    throw new Error(
      `${file}: image.digest is ${JSON.stringify(packaged)}, not ${JSON.stringify(serverDigest ?? '')}`,
    );
  }
  return file;
}

function gitCommit(): string {
  const head = must(run('git', ['rev-parse', 'HEAD']), 'git rev-parse').stdout.trim();
  const dirty = run('git', ['status', '--porcelain']).stdout.trim() !== '';
  return dirty ? `${head}-dirty` : head;
}

async function waitForRegistry(port: number): Promise<void> {
  const deadline = Date.now() + 30_000;
  while (Date.now() < deadline) {
    try {
      if ((await fetch(`http://127.0.0.1:${port}/v2/`)).status === 200) return;
    } catch {
      // not up yet
    }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error('the dry-run registry did not start in 30 s');
}

export async function dryRun(o: DryRunOptions, root = DEFAULT_OUTPUT_ROOT): Promise<string> {
  const v = o.version;
  const dir = releaseDir(v, root);
  const work = workDir(v, root);
  rmSync(dir, { recursive: true, force: true });
  rmSync(work, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  // Before the long build: the CLI's SBOM step needs pnpm's own entry.
  const pnpm = pnpmCommand();
  mkdirSync(work, { recursive: true });

  // The keys, the registry and the work directory go in `finally`, and on SIGINT and SIGTERM.
  let keys: Keys | undefined;
  let registry: DryRunRegistry | undefined;
  const cleanup = (): string[] => {
    if (keys) removeKeys(keys);
    const failures = registry ? stopRegistry(registry) : [];
    registry = undefined;
    rmSync(work, { recursive: true, force: true });
    return failures;
  };
  const onSignal = (): void => {
    cleanup();
    process.exit(130);
  };
  process.once('SIGINT', onSignal);
  process.once('SIGTERM', onSignal);
  const images: ImageRecord[] = [];
  let chartFile: string;
  let chartDigest: string | null = null;
  try {
    buildToolbox();

    // 3. CLI binaries and their sources.
    await buildCliRelease(v, dir, o.targets);
    if (!o.skipCliSources) await copyCliSources(dir);
    else {
      process.stderr.write('warning: --skip-cli-sources: this directory can never be published\n');
    }

    // 6. The CLI's SBOM, from a production install in the work directory (release.md §8).
    const sbomDir = path.join(dir, 'sbom');
    mkdirSync(sbomDir, { recursive: true });
    const deps = path.join(work, 'cli-deps');
    must(run(pnpm.command, [...pnpm.args, ...cliDepsArgs(deps)]), 'pnpm deploy @qualor/cli');
    const cliSbom = path.join(sbomDir, 'cli.spdx.json');
    must(runTool('syft', cliSbomArgs(toWork(deps), toWork(cliSbom), v.text)), 'syft cli');
    const cliProblems = spdxProblems(readFileSync(cliSbom, 'utf8'));
    if (cliProblems.length > 0) throw new Error(`sbom/cli.spdx.json: ${cliProblems.join(', ')}`);

    // 7. The throwaway key pair (release.md §7.3).
    const k = generateKeys(path.join(work, 'keys'));
    keys = k;
    const cosignEnv = { COSIGN_PASSWORD: k.password };

    // 4. Images, into the loopback registry.
    if (!o.skipImages) {
      const released = releasedVersions();
      const tags = imageTags(v, released);
      const tsx = path.join(REPO_ROOT, 'node_modules', 'tsx', 'dist', 'cli.mjs');
      const also = tags.slice(1).flatMap((t) => ['--also', t]);
      must(
        run(process.execPath, [tsx, 'tools/deploy/release-images.ts', '--tag', v.text, ...also], {
          inherit: true,
        }),
        'pnpm deploy:release-images',
      );
      registry = newRegistry(await freePort());
      startRegistry(registry);
      await waitForRegistry(registry.port);
      const net = { network: registry.network };
      for (const { image, refs } of releaseRefs('qualor', v, released)) {
        const digests = new Set<string>();
        for (const ref of refs) {
          const tag = ref.slice(ref.lastIndexOf(':') + 1);
          const local = hostRef(registry, `qualor/${image}`, tag);
          must(run('docker', ['tag', ref, local]), `docker tag ${ref} ${local}`);
          try {
            digests.add(pushToDryRun(local));
          } finally {
            run('docker', ['image', 'rm', local]);
          }
        }
        const [digest, ...other] = [...digests];
        if (digest === undefined || other.length > 0) {
          throw new Error(
            `qualor/${image}: its tags pushed different digests: ${[...digests].join(', ')}`,
          );
        }
        const inRegistry = internalRef(`qualor/${image}`, digest);
        let sbom: string | null = null;
        if ((SBOM_IMAGES as readonly string[]).includes(image)) {
          sbom = `sbom/${image}.spdx.json`;
          must(
            runTool('syft', syftArgs(`registry:${inRegistry}`, toWork(path.join(dir, sbom))), {
              ...net,
              env: REGISTRY_SOURCE_ENV,
            }),
            `syft ${image}`,
          );
          const problems = spdxProblems(readFileSync(path.join(dir, sbom), 'utf8'));
          if (problems.length > 0) throw new Error(`${sbom}: ${problems.join(', ')}`);
        }
        // 7. Sign and attest by digest (registry.ts); verify each.
        signInDryRun(registry, k, inRegistry, sbom === null ? null : toWork(path.join(dir, sbom)));
        must(
          runTool('cosign', verifyImageArgs(k.pub, inRegistry, DRY_RUN_OPTIONS), net),
          `cosign verify ${image}`,
        );
        if (sbom) {
          must(
            runTool('cosign', verifyAttestationArgs(k.pub, inRegistry, DRY_RUN_OPTIONS), net),
            `cosign verify-attestation ${image}`,
          );
        }
        images.push({ image, refs, digest, sbom });
      }
    }

    // 5. The chart: pinned by the server's digest when the images were pushed (R-DIGEST).
    const server = images.find((i) => i.image === 'server');
    chartFile = packageChart(v, dir, work, server?.digest ?? null);
    if (registry) {
      const net = { network: registry.network };
      chartDigest = pushChartToDryRun(registry, toWork(path.join(dir, chartFile)));
      const chartRef = internalRef('qualor/qualor', chartDigest);
      signInDryRun(registry, k, chartRef, null);
      must(
        runTool('cosign', verifyImageArgs(k.pub, chartRef, DRY_RUN_OPTIONS), net),
        'cosign verify chart',
      );
      writeFileSync(path.join(dir, 'images.json'), `${JSON.stringify(images, null, 2)}\n`);
    }

    // 8. Notes, public key, manifest; then SHA256SUMS over all of them, signed. 9. Verify.
    const notes = releaseNotes(readFileSync(path.join(REPO_ROOT, 'CHANGELOG.md'), 'utf8'), v.text, {
      allowUnreleased: true,
    });
    if (notes.fromUnreleased) {
      process.stderr.write(`warning: CHANGELOG.md has no ${v.text} section; using Unreleased\n`);
    }
    writeFileSync(
      path.join(dir, 'release-notes.md'),
      `${notes.notes}\n\nThe \`qualor\` binaries are built with Bun ${BUN_VERSION}.\n`,
    );
    copyFileSync(path.join(k.hostDir, 'cosign.pub'), path.join(dir, 'cosign.pub'));
    const manifest = buildManifest(
      {
        version: v.text,
        gitCommit: gitCommit(),
        createdAt: new Date().toISOString(),
        dryRun: true,
        targets: o.targets,
        cliSources: !o.skipCliSources,
        images,
        chart: { file: chartFile, digest: chartDigest },
      },
      releaseFiles(dir),
    );
    writeFileSync(
      path.join(dir, 'release-manifest.json'),
      `${JSON.stringify(manifest, null, 2)}\n`,
    );
    writeFileSync(path.join(dir, SUMS), await sha256sums(dir));
    must(
      runTool(
        'cosign',
        signBlobArgs(k.key, toWork(path.join(dir, SUMS)), toWork(path.join(dir, SUMS_BUNDLE)), {
          offline: true,
        }),
        { env: cosignEnv },
      ),
      'cosign sign-blob',
    );
    // release:verify --self-check: the throwaway key the directory carries (release.md §10, §12).
    const key = resolveVerifyKey({ dir, selfCheck: true });
    process.stdout.write(`key: ${key.pub} (${key.source})
`);
    const problems = await verifyRelease(dir, key.pub, cosignVerifier);
    if (problems.length > 0) {
      throw new Error(`the dry run does not verify:\n  ${problems.join('\n  ')}`);
    }
  } finally {
    process.off('SIGINT', onSignal);
    process.off('SIGTERM', onSignal);
    const failures = cleanup();
    if (failures.length > 0) {
      process.stderr.write(
        `warning: the dry-run registry was not removed:\n  ${failures.join('\n  ')}\n`,
      );
    }
  }
  if (existsSync(path.join(dir, 'keys')) || releaseFiles(dir).some((f) => f.endsWith('.key'))) {
    throw new Error('a private key was left in the release directory');
  }
  process.stdout.write(`${dir}\ndry run complete: nothing was published\n`);
  return dir;
}

if (process.argv[1]?.endsWith('dry-run.ts')) {
  dryRun(parseDryRunArgs(process.argv.slice(2), currentVersion())).catch((error: unknown) => {
    process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
    process.exitCode = 1;
  });
}
