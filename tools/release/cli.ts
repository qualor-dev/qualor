import {
  closeSync,
  copyFileSync,
  existsSync,
  mkdirSync,
  openSync,
  readSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import {
  bun,
  BUN_VERSION,
  bunReleaseArgs,
  CLI_DIR,
  releaseBinaryName,
  type ReleaseTarget,
} from '../../cli/scripts/targets';
import { loadManifest, sha256File, sourcesDir, type SourceEntry } from '../deploy/sources';
import { must, REPO_ROOT, run } from '../deploy/stack';
import { binaryFormat, EXPECTED_FORMAT, hostTarget } from './binary';
import { bunRuntime } from './runtimes';
import type { Version } from './version';

function header(file: string): Uint8Array {
  const fd = openSync(file, 'r');
  try {
    const b = new Uint8Array(4096);
    const n = readSync(fd, b, 0, b.length, 0);
    return b.subarray(0, n);
  } finally {
    closeSync(fd);
  }
}

/** release.md §4: compiles every target into <releaseDir>/cli/, checks its header, runs the host's. */
export async function buildCliRelease(
  v: Version,
  releaseDir: string,
  targets: ReleaseTarget[],
): Promise<string[]> {
  const found = String(bun(['--version'], { encoding: 'utf8' }).stdout ?? '').trim();
  if (found !== BUN_VERSION) {
    throw new Error(`bun ${BUN_VERSION} is required to build the binaries, found "${found}"`);
  }
  mkdirSync(path.join(releaseDir, 'cli'), { recursive: true });
  const written: string[] = [];
  for (const target of targets) {
    const rel = `cli/${releaseBinaryName(v.text, target)}`;
    // Absolute: bun runs in CLI_DIR, so a relative releaseDir would land under cli/.
    const out = path.resolve(releaseDir, rel);
    // Ruling R-MAC: every target is built with a pinned, checked runtime, never one bun downloads for itself.
    const runtime = await bunRuntime(target);
    const r = bun(bunReleaseArgs(target, out, runtime), { cwd: CLI_DIR, stdio: 'inherit' });
    if (r.status !== 0) throw new Error(`bun build ${target} failed (exit ${r.status ?? 1})`);
    const got = binaryFormat(header(out));
    const want = EXPECTED_FORMAT[target];
    if (got?.format !== want.format || got.arch !== want.arch) {
      const seen = got ? `${got.format}/${got.arch}` : 'no known header';
      throw new Error(`${rel}: expected ${want.format}/${want.arch}, found ${seen}`);
    }
    if (target === hostTarget()) {
      const version = must(run(out, ['version']), `${rel} version`).stdout;
      if (!version.startsWith(`qualor ${v.text} `)) {
        throw new Error(`${rel} version printed "${version.trim()}", not ${v.text}`);
      }
    }
    written.push(rel);
  }
  return written;
}

/** release.md §4, ruling L1: the Bun, WebKit and TinyCC sources every binary carries. */
export async function copyCliSources(
  releaseDir: string,
  root = REPO_ROOT,
  load: (root: string) => Pick<SourceEntry, 'file' | 'component' | 'sha256'>[] = loadManifest,
): Promise<string[]> {
  const entries = load(root)
    .filter((e) => e.component === 'bun')
    .sort((a, b) => (a.file < b.file ? -1 : a.file > b.file ? 1 : 0)); // byte order, as sha256sum lists
  const dir = path.join(releaseDir, 'cli-sources');
  mkdirSync(dir, { recursive: true });
  const lines: string[] = [];
  for (const e of entries) {
    const from = path.join(root, sourcesDir('scanner'), e.file);
    if (!existsSync(from) || (await sha256File(from)) !== e.sha256) {
      throw new Error(
        `${sourcesDir('scanner')}/${e.file} is missing or wrong: run pnpm deploy:sources`,
      );
    }
    copyFileSync(from, path.join(dir, e.file));
    lines.push(`${e.sha256}  ${e.file}`);
  }
  writeFileSync(path.join(dir, 'SHA256SUMS'), `${lines.join('\n')}\n`);
  return ['cli-sources/SHA256SUMS', ...entries.map((e) => `cli-sources/${e.file}`)];
}
