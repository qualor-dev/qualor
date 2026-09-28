import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { must, REPO_ROOT, run } from './stack';
import {
  debianManifestPath,
  dockerfilePath,
  driftProblems,
  dscProblems,
  finalStage,
  IMAGES,
  imageSources,
  loadDebianManifest,
  parseChecksums,
  parseDeb822,
  unsign,
  type DebManifest,
  type DebSource,
  type ImageName,
} from './debian-sources';
import { curlArgs, hashFile, sha256File } from './sources';

/**
 * `pnpm deploy:debian-sources <scanner|server> [--image <ref>] [--check]` (ruling L2).
 *
 * Reads the dpkg database of a built image (without running it: `docker cp` from a created
 * container) and maps every installed binary package to its source package and version. Without
 * `--check` it looks each one up in the Debian Sources indexes of bookworm, bookworm-updates and
 * bookworm-security, downloads the .dsc, checks it against the index's SHA-256 and its file list
 * against the index, and writes deploy/<image>/debian-sources.json. With `--check` it only
 * compares the image with the committed manifest and exits 1 on any difference.
 *
 * The Sources indexes are trusted as deb.debian.org serves them over TLS: they are not checked
 * against the suite's signed InRelease file (no PGP verification). The SHA-256 digests then pin
 * what was fetched, so a later download that differs fails closed (deploy/README.md).
 */
const WORK = path.join(REPO_ROOT, '.tmp', 'debian-sources-work');
const SUITES = [
  { archive: 'debian', suite: 'bookworm' },
  { archive: 'debian', suite: 'bookworm-updates' },
  { archive: 'debian-security', suite: 'bookworm-security' },
] as const;

function log(line: string): void {
  process.stdout.write(`${line}\n`);
}

function download(url: string, out: string): void {
  const r = run('curl', curlArgs(url, out));
  if (r.code !== 0) throw new Error(`download of ${url} failed: ${r.stderr.trim()}`);
}

interface IndexEntry {
  archive: DebSource['archive'];
  directory: string;
  sha256: Map<string, { hash: string; size: number }>;
}

function loadIndexes(): { entries: Map<string, IndexEntry>; urls: string[] } {
  const entries = new Map<string, IndexEntry>();
  const urls: string[] = [];
  for (const { archive, suite } of SUITES) {
    const url = `https://deb.debian.org/${archive}/dists/${suite}/main/source/Sources.xz`;
    urls.push(url);
    const xz = path.join(WORK, `${suite}-Sources.xz`);
    download(url, xz);
    const text = must(run('xz', ['-dc', xz]), `xz -dc ${xz}`).stdout;
    for (const s of parseDeb822(text)) {
      const key = `${s['Package']} ${s['Version']}`;
      if (entries.has(key)) continue;
      entries.set(key, {
        archive,
        directory: s['Directory'] ?? '',
        sha256: new Map(parseChecksums(s['Checksums-Sha256']).map((c) => [c.name, c])),
      });
    }
  }
  return { entries, urls };
}

async function resolve(
  key: string,
  binaries: string[],
  index: Map<string, IndexEntry>,
): Promise<DebSource> {
  const [source = '', version = ''] = key.split(' ');
  const e = index.get(key);
  if (e === undefined) {
    throw new Error(`${key} is in no current Sources index (superseded? see deploy/README.md)`);
  }
  const dscName = [...e.sha256.keys()].find((n) => n.endsWith('.dsc'));
  const dscSum = dscName === undefined ? undefined : e.sha256.get(dscName);
  if (dscName === undefined || dscSum === undefined)
    throw new Error(`${key}: no .dsc in the index`);
  const dscPath = path.join(WORK, dscName);
  download(`https://deb.debian.org/${e.archive}/${e.directory}/${dscName}`, dscPath);
  if ((await sha256File(dscPath)) !== dscSum.hash) {
    throw new Error(`${dscName}: SHA-256 differs from the Sources index`);
  }
  const dscText = readFileSync(dscPath, 'utf8');
  const dsc = parseDeb822(unsign(dscText))[0] ?? {};
  const listed = parseChecksums(dsc['Checksums-Sha256']);
  // The Sources index has no SHA-1 any more: the .dsc's own (checked by SHA-256) and its list.
  const sha1 = new Map(parseChecksums(dsc['Checksums-Sha1']).map((c) => [c.name, c.hash]));
  sha1.set(dscName, await hashFile(dscPath, 'sha1'));
  const file = (name: string) => {
    const c = e.sha256.get(name);
    const s1 = sha1.get(name);
    if (c === undefined || s1 === undefined)
      throw new Error(`${key}: ${name} not in the index or the .dsc`);
    return { name, size: c.size, sha256: c.hash, sha1: s1 };
  };
  const pkg: DebSource = {
    source,
    version,
    binaries,
    archive: e.archive,
    directory: e.directory,
    files: [file(dscName), ...listed.map((c) => file(c.name))],
  };
  const problems = dscProblems(pkg, dscText);
  if (problems.length > 0) throw new Error(`${key}:\n  ${problems.join('\n  ')}`);
  return pkg;
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const image = argv[0] as ImageName;
  if (!IMAGES.includes(image))
    throw new Error(`usage: deploy:debian-sources <${IMAGES.join('|')}>`);
  const i = argv.indexOf('--image');
  const ref = i === -1 ? `qualor/${image}:dev` : (argv[i + 1] ?? '');
  mkdirSync(WORK, { recursive: true });
  const installed = imageSources(ref, path.join(WORK, 'dpkg'));
  const stage = finalStage(readFileSync(path.join(REPO_ROOT, dockerfilePath(image)), 'utf8'));
  if (argv.includes('--check')) {
    const m = loadDebianManifest(image);
    const problems = driftProblems(installed, m);
    if (m.base !== stage.base)
      problems.push(`the manifest is for ${m.base}, the Dockerfile uses ${stage.base}`);
    if (problems.length > 0) {
      throw new Error(
        `${ref} differs from ${debianManifestPath(image)} (run pnpm deploy:debian-sources ${image}):\n  ` +
          problems.join('\n  '),
      );
    }
    log(`${ref}: ${installed.size} source packages, as ${debianManifestPath(image)} pins`);
    return;
  }
  const { entries, urls } = loadIndexes();
  const packages: DebSource[] = [];
  for (const [key, binaries] of installed) packages.push(await resolve(key, binaries, entries));
  const manifest: DebManifest = {
    image: `qualor/${image}`,
    base: stage.base,
    aptPackages: stage.aptPackages,
    sourcesIndexes: urls,
    packages,
  };
  writeFileSync(
    path.join(REPO_ROOT, debianManifestPath(image)),
    `${JSON.stringify(manifest, null, 2)}\n`,
  );
  const bytes = packages.flatMap((p) => p.files).reduce((s, f) => s + f.size, 0);
  log(
    `wrote ${debianManifestPath(image)}: ${packages.length} source packages, ` +
      `${(bytes / 1024 / 1024).toFixed(1)} MiB of source`,
  );
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
