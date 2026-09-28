import {
  copyFileSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import {
  debianManifestPath,
  debianUrls,
  dscProblems,
  IMAGES,
  loadDebianManifest,
  type DebManifest,
  type ImageName,
} from './debian-sources';
import { REPO_ROOT, run } from './stack';
import {
  curlArgs,
  indexPath,
  loadManifest,
  MANIFEST_PATH,
  pinnedVersions,
  readmePath,
  sha256File,
  sha256sums,
  sideFiles,
  sourcesDir,
  sourcesIndex,
  versionProblems,
  type SourceEntry,
} from './sources';

/**
 * `pnpm deploy:sources [scanner|server] [--index]`: downloads the pinned corresponding source
 * of the images into .tmp/<image>-sources/: for the scanner the archives of
 * deploy/scanner/sources.json, and for both images every Debian source file of
 * deploy/<image>/debian-sources.json into debian/. It verifies every SHA-256 before it keeps a
 * file (and every Debian file against its .dsc too), then writes SOURCES.md, SHA256SUMS,
 * README.md and the manifests next to them. Fails closed: on a mismatch it deletes the file,
 * writes no index and exits 1. It never runs anything it downloads. `--index` only regenerates
 * the committed deploy/<image>/SOURCES.md.
 */
const WORK = path.join(REPO_ROOT, '.tmp', 'scanner-sources-work');

function log(line: string): void {
  process.stdout.write(`${line}\n`);
}

function mib(bytes: number): string {
  return `${(bytes / 1024 / 1024).toFixed(1)} MiB`;
}

/** git with no system or user configuration (autocrlf, attributes, hooks) and https only. */
function git(args: string[], cwd: string, inherit = false) {
  const emptyConfig = path.join(WORK, 'empty.gitconfig');
  writeFileSync(emptyConfig, '');
  const r = run(
    'git',
    [
      '-c',
      'protocol.allow=never',
      '-c',
      'protocol.https.allow=always',
      '-c',
      'core.autocrlf=false',
      '-c',
      'core.eol=lf',
      '-c',
      'tar.umask=022',
      ...args,
    ],
    {
      cwd,
      inherit,
      env: {
        GIT_CONFIG_NOSYSTEM: '1',
        GIT_CONFIG_GLOBAL: emptyConfig,
        GIT_TERMINAL_PROMPT: '0',
        MSYS_NO_PATHCONV: '1',
      },
    },
  );
  if (r.code !== 0) throw new Error(`git ${args[0] ?? ''} failed (exit ${r.code}):\n${r.stderr}`);
  return r.stdout;
}

/** A shallow fetch of the one commit, then `git archive` of it without the excluded directories. */
function gitArchive(e: SourceEntry, part: string): void {
  if (e.fetch.type !== 'git-archive') return;
  const { repository, commit, exclude } = e.fetch;
  const repo = path.join(WORK, e.file.replace(/\.tar$/, ''));
  mkdirSync(repo, { recursive: true });
  git(['init', '--quiet'], repo);
  // Resumes a fetch an earlier run completed; otherwise fetches the commit alone.
  const have = run('git', ['cat-file', '-e', `${commit}^{commit}`], { cwd: repo }).code === 0;
  if (!have) {
    let fetched = false;
    for (let attempt = 1; attempt <= 3 && !fetched; attempt++) {
      try {
        git(['fetch', '--depth', '1', '--no-tags', repository, commit], repo, true);
        fetched = true;
      } catch (error) {
        if (attempt === 3) throw error;
        log(`    fetch failed, retrying (${attempt}/3)`);
      }
    }
  }
  const top = git(['ls-tree', '-z', '--name-only', commit], repo)
    .split('\0')
    .filter((name) => name !== '' && !exclude.includes(name));
  const prefix = `${path.basename(repository, '.git')}-${commit}/`;
  git(
    ['archive', '--format=tar', `--prefix=${prefix}`, '--output', part, commit, '--', ...top],
    repo,
  );
}

/** Keeps `target` when it already verifies; otherwise gets it through `get` and verifies it. */
async function fetchVerified(
  target: string,
  sha256: string,
  get: (part: string) => void,
): Promise<'kept' | 'new'> {
  try {
    if ((await sha256File(target)) === sha256) return 'kept';
    rmSync(target);
  } catch {
    // not downloaded yet
  }
  const part = `${target}.part`;
  rmSync(part, { force: true });
  get(part);
  const actual = await sha256File(part);
  if (actual !== sha256) {
    rmSync(part, { force: true });
    throw new Error(
      `checksum mismatch for ${path.basename(target)}: expected ${sha256}, got ${actual}. ` +
        'Nothing was kept; check the upstream change before updating the manifest.',
    );
  }
  renameSync(part, target);
  return 'new';
}

function curl(url: string, out: string): void {
  const r = run('curl', curlArgs(url, out));
  if (r.code !== 0) throw new Error(`download of ${url} failed: ${r.stderr.trim()}`);
}

/** Tries each URL in turn (the Debian archive, then snapshot.debian.org). */
function curlAny(urls: readonly string[], out: string): void {
  const errors: string[] = [];
  for (const url of urls) {
    try {
      curl(url, out);
      return;
    } catch (error) {
      errors.push(error instanceof Error ? error.message : String(error));
    }
  }
  throw new Error(errors.join('\n'));
}

async function fetchDebian(out: string, debian: DebManifest): Promise<number> {
  const dir = path.join(out, 'debian');
  mkdirSync(dir, { recursive: true });
  const wanted = new Set(debian.packages.flatMap((p) => p.files.map((f) => f.name)));
  for (const name of readdirSync(dir)) {
    if (!wanted.has(name)) rmSync(path.join(dir, name), { recursive: true, force: true });
  }
  let bytes = 0;
  let added = 0;
  for (const p of debian.packages) {
    for (const f of p.files) {
      const target = path.join(dir, f.name);
      const state = await fetchVerified(target, f.sha256, (part) =>
        curlAny(debianUrls(p, f), part),
      );
      if (state === 'new') added++;
      bytes += statSync(target).size;
    }
    const dsc = p.files[0];
    const problems = dsc ? dscProblems(p, readFileSync(path.join(dir, dsc.name), 'utf8')) : [];
    if (problems.length > 0)
      throw new Error(`${p.source} ${p.version}:\n  ${problems.join('\n  ')}`);
  }
  log(
    `  debian/: ${debian.packages.length} source packages, ${wanted.size} files ` +
      `(${added} new), ${mib(bytes)}`,
  );
  return bytes;
}

async function fetchImage(image: ImageName): Promise<void> {
  const entries = image === 'scanner' ? loadManifest() : [];
  const debian = loadDebianManifest(image);
  const out = path.join(REPO_ROOT, sourcesDir(image));
  mkdirSync(out, { recursive: true });
  mkdirSync(WORK, { recursive: true });
  // No index until every file is verified; nothing in the directory the manifests do not name.
  const wanted = new Set<string>([...entries.map((e) => e.file), 'debian']);
  for (const name of readdirSync(out)) {
    if (!wanted.has(name)) rmSync(path.join(out, name), { recursive: true, force: true });
  }
  log(`qualor/${image}: into ${sourcesDir(image)}/`);
  let bytes = 0;
  for (const e of entries) {
    const target = path.join(out, e.file);
    const state = await fetchVerified(target, e.sha256, (part) => {
      if (e.fetch.type === 'https') curl(e.fetch.url, part);
      else gitArchive(e, part);
    });
    bytes += statSync(target).size;
    log(`  ${state === 'new' ? 'new ' : 'ok  '} ${e.file} (${mib(statSync(target).size)})`);
  }
  bytes += await fetchDebian(out, debian);
  if (image === 'scanner')
    copyFileSync(path.join(REPO_ROOT, MANIFEST_PATH), path.join(out, 'sources.json'));
  copyFileSync(
    path.join(REPO_ROOT, debianManifestPath(image)),
    path.join(out, 'debian-sources.json'),
  );
  copyFileSync(path.join(REPO_ROOT, readmePath(image)), path.join(out, 'README.md'));
  writeFileSync(path.join(out, 'SHA256SUMS'), sha256sums(entries, debian));
  writeFileSync(path.join(out, 'SOURCES.md'), sourcesIndex(image, entries, debian));
  const names = readdirSync(out).sort();
  const expected = [...wanted, ...sideFiles(image)].sort();
  if (names.join('\n') !== expected.join('\n')) throw new Error(`unexpected files in ${out}`);
  log(`verified qualor/${image} sources: ${mib(bytes)} in total`);
}

async function main(): Promise<void> {
  const argv = process.argv.slice(2);
  const chosen = IMAGES.filter((i) => argv.includes(i));
  const images = chosen.length > 0 ? chosen : IMAGES;
  const problems = versionProblems(loadManifest(), pinnedVersions());
  if (problems.length > 0) throw new Error(problems.join('\n'));
  if (argv.includes('--index')) {
    for (const image of images) {
      const entries = image === 'scanner' ? loadManifest() : [];
      writeFileSync(
        path.join(REPO_ROOT, indexPath(image)),
        sourcesIndex(image, entries, loadDebianManifest(image)),
      );
      log(`wrote ${indexPath(image)}`);
    }
    return;
  }
  for (const image of images) await fetchImage(image);
}

main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
