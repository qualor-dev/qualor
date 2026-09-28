import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { BUN_VERSION, CLI_DIR } from './targets';

/**
 * Linux only (the `cli-binary` CI job): compiles `process-smoke.entry.ts` with bun into a native
 * binary in a temporary directory (never `cli/dist`, which CI uploads as the release artifact),
 * runs it and deletes it. See `process-smoke-check.ts`.
 */
function processSmoke(): number {
  if (process.platform !== 'linux') {
    console.log('process smoke: Linux only, skipped on this host');
    return 0;
  }
  const version = spawnSync('bun', ['--version'], { encoding: 'utf8' });
  if (version.status !== 0 || version.stdout.trim() !== BUN_VERSION) {
    console.error(`bun ${BUN_VERSION} is required for the process smoke binary`);
    return 1;
  }
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-process-smoke-bin-'));
  try {
    return buildAndRun(path.join(dir, 'process-smoke'));
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

function buildAndRun(out: string): number {
  const build = spawnSync(
    'bun',
    [
      'build',
      '--compile',
      path.join(CLI_DIR, 'scripts', 'process-smoke.entry.ts'),
      '--outfile',
      out,
    ],
    { cwd: CLI_DIR, stdio: 'inherit' },
  );
  if (build.status !== 0) return build.status ?? 1;
  const run = spawnSync(out, [], { stdio: 'inherit', timeout: 60_000 });
  return run.status ?? 1;
}

process.exitCode = processSmoke();
