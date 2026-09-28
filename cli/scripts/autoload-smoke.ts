import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { bun, BUN_VERSION, CLI_DIR, NO_AUTOLOAD } from './targets';

/**
 * The `cli-binary` CI job, and any host with the pinned bun: a compiled binary must not load a
 * `.env` from the directory it runs in, which for `qualor scan` is the scanned repository (ruling
 * V8). Compiles `autoload-smoke.entry.ts` twice in a temporary directory, with NO_AUTOLOAD (the
 * flags of every shipped binary) and without it as the control, and runs both in a directory whose
 * `.env` sets QUALOR_TEST_X=from-repo. The hardened binary must not see it; the control must, or
 * the check proves nothing.
 */
export function autoloadVerdict(hardened: string, control: string): string | null {
  if (control.trim() !== '"from-repo"') {
    return `the control binary did not load .env (printed ${control.trim()}), so the check proves nothing`;
  }
  if (hardened.trim() !== 'null') {
    return `a binary built with ${NO_AUTOLOAD.join(' ')} loaded .env (printed ${hardened.trim()})`;
  }
  return null;
}

function build(entry: string, out: string, flags: readonly string[]): void {
  const r = bun(['build', '--compile', ...flags, entry, '--outfile', out], {
    cwd: CLI_DIR,
    stdio: 'inherit',
  });
  if (r.status !== 0) throw new Error(`bun build ${out} failed (exit ${r.status ?? 1})`);
}

function runIn(dir: string, binary: string): string {
  const env = { ...process.env };
  delete env['QUALOR_TEST_X'];
  const r = spawnSync(binary, [], { cwd: dir, env, encoding: 'utf8', timeout: 60_000 });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`${binary} exited ${r.status ?? 1}: ${r.stderr}`);
  return r.stdout;
}

function autoloadSmoke(): number {
  const found = String(bun(['--version'], { encoding: 'utf8' }).stdout ?? '').trim();
  if (found !== BUN_VERSION) {
    console.error(`bun ${BUN_VERSION} is required for the autoload smoke, found "${found}"`);
    return 1;
  }
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-autoload-smoke-'));
  try {
    const exe = process.platform === 'win32' ? '.exe' : '';
    const entry = path.join(CLI_DIR, 'scripts', 'autoload-smoke.entry.ts');
    const hardened = path.join(dir, `autoload-off${exe}`);
    // Not "control.exe": on Windows 11, spawning a program of that name from %TEMP% failed with
    // UNKNOWN (the name of the Control Panel).
    const control = path.join(dir, `autoload-on${exe}`);
    build(entry, hardened, NO_AUTOLOAD);
    build(entry, control, []);
    const repo = path.join(dir, 'repo');
    mkdirSync(repo);
    writeFileSync(path.join(repo, '.env'), 'QUALOR_TEST_X=from-repo\n');
    const failure = autoloadVerdict(runIn(repo, hardened), runIn(repo, control));
    if (failure !== null) {
      console.error(`✗ ${failure}`);
      return 1;
    }
    console.log('✓ a binary built with NO_AUTOLOAD ignores the .env of its working directory');
    return 0;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

if (process.argv[1]?.endsWith('autoload-smoke.ts')) process.exitCode = autoloadSmoke();
