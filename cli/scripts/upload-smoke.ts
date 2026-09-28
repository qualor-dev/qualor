import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { bun, BUN_VERSION, CLI_DIR, TARGETS } from './targets';

const ENTRY = path.join(CLI_DIR, 'scripts', 'upload-smoke.entry.ts');

/** The linger probe's request allows 30 s; a prompt exit takes well under a second. */
const MAX_LINGER_PROBE_MS = 10_000;

/**
 * Runs the linger probe (`--linger-probe`) and checks the process exits promptly after its JSON
 * exchange: under Bun a leftover response timeout once kept the binary alive for
 * `server.timeoutSeconds` after every request (fixed in CLI step 13).
 */
function lingerCheck(run: (args: string[]) => { status: number | null }): number {
  const started = Date.now();
  const probe = run(['--linger-probe']);
  const took = Date.now() - started;
  if (probe.status !== 0) {
    console.error(`✗ the linger probe failed (exit ${probe.status ?? 'none'})`);
    return 1;
  }
  if (took > MAX_LINGER_PROBE_MS) {
    console.error(`✗ the process lingered ${took} ms after its last JSON exchange`);
    return 1;
  }
  console.log(`✓ exits promptly after a JSON exchange (${took} ms)`);
  return 0;
}

/**
 * Runs the upload checks of `upload-smoke-check.ts` on the pinned bun (`upload-smoke.test.ts`
 * runs the same checks under Node). On Linux (the `cli-binary` CI job) the entry is compiled with
 * `bun build --compile` (with the release `--target` for this machine) into a temporary directory (never `cli/dist`, which CI uploads as the
 * release artifact), like the shipped binary, then run and deleted. On other hosts bun runs the
 * entry directly (the same runtime): Windows may refuse to start a freshly compiled, unsigned
 * executable.
 */
function uploadSmoke(): number {
  const version = bun(['--version'], { encoding: 'utf8' });
  if (version.status !== 0 || String(version.stdout ?? '').trim() !== BUN_VERSION) {
    console.error(`bun ${BUN_VERSION} is required for the upload smoke checks`);
    return 1;
  }
  if (process.platform !== 'linux') {
    const run = (args: string[]) =>
      bun(['run', ENTRY, ...args], { cwd: CLI_DIR, stdio: 'inherit', timeout: 120_000 });
    return (run([]).status ?? 1) || lingerCheck(run);
  }
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-upload-smoke-bin-'));
  try {
    const out = path.join(dir, 'upload-smoke');
    // The release target flag for this machine (`bunBuildArgs`), when it is one we ship.
    const target = `linux-${process.arch}`;
    const targetFlag = Object.hasOwn(TARGETS, target)
      ? [`--target=${TARGETS[target as keyof typeof TARGETS]}`]
      : [];
    const build = bun(['build', '--compile', ...targetFlag, ENTRY, '--outfile', out], {
      cwd: CLI_DIR,
      stdio: 'inherit',
    });
    if (build.status !== 0) return build.status ?? 1;
    const run = (args: string[]) => {
      const r = spawnSync(out, args, { stdio: 'inherit', timeout: 120_000 });
      if (r.error !== undefined)
        console.error(`cannot run the upload smoke binary: ${r.error.message}`);
      return r;
    };
    return (run([]).status ?? 1) || lingerCheck(run);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

process.exitCode = uploadSmoke();
