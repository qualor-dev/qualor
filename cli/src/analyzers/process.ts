import { spawn, spawnSync } from 'node:child_process';
import path from 'node:path';
import type { Logger } from '../log';

export interface ProcessSpec {
  command: string;
  args: readonly string[];
  cwd: string;
  /**
   * The complete child environment. Required, so no caller can fall back to `process.env` (and
   * hand an analyzer the server token) by omission: build it with `sanitizeAnalyzerEnv`.
   */
  env: Readonly<Record<string, string>>;
  timeoutMs: number;
}

export interface ProcessResult {
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  /** The last 64 KiB of each stream (config.md §6: debug log only). */
  stdout: string;
  stderr: string;
  spawnError?: string;
  /** The underlying `NodeJS.ErrnoException.code`, e.g. `'ENOENT'` (fix-round-2 finding 5). */
  spawnErrorCode?: string;
}

const TAIL_CHARS = 64 * 1024;
/** After 'exit', wait this long for the pipes to close (a grandchild may still hold them). */
const CLOSE_GRACE_MS = 1_000;

/** Fix-round finding 8: an absolute path, not a bare command resolved through PATH. */
function taskkillPath(): string {
  return path.join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'taskkill.exe');
}

/** Kills a process and everything it started (Review Focus 5). */
export function killTree(pid: number | undefined): void {
  if (pid === undefined) return;
  if (process.platform === 'win32') {
    spawnSync(taskkillPath(), ['/pid', String(pid), '/T', '/F'], {
      stdio: 'ignore',
      windowsHide: true,
    });
    return;
  }
  try {
    process.kill(-pid, 'SIGKILL'); // the child leads its own process group (detached: true)
  } catch {
    try {
      process.kill(pid, 'SIGKILL');
    } catch {
      // already gone
    }
  }
}

/**
 * Fix-round finding 10: every currently-spawned analyzer process, tracked so `runner.ts`'s
 * SIGINT/SIGTERM handler (installed only for the duration of `runAnalyzers`, fix-round-2 finding
 * 3) can kill each whole tree before the CLI exits. Analyzer children are spawned detached (their
 * own process group) specifically so `killTree` can reach the whole tree, which also means a
 * signal delivered to the CLI's own process group does not reach them on its own — without this,
 * Ctrl+C would leave an orphaned analyzer subtree running.
 */
const activePids = new Set<number>();

/** Kills every currently tracked analyzer process tree. */
export function killActiveProcesses(): void {
  for (const pid of activePids) killTree(pid);
}

export function runProcess(spec: ProcessSpec, log: Logger): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const started = performance.now();
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    let settled = false;
    let exitCode: number | null = null;
    const child = spawn(spec.command, [...spec.args], {
      cwd: spec.cwd,
      env: spec.env,
      shell: false,
      windowsHide: true,
      detached: process.platform !== 'win32',
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    if (child.pid !== undefined) activePids.add(child.pid);
    const finish = (extra: Partial<ProcessResult> = {}) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (child.pid !== undefined) activePids.delete(child.pid);
      const durationMs = performance.now() - started;
      log.debug(`${spec.command} exited ${exitCode ?? 'null'} after ${Math.round(durationMs)} ms`);
      if (stderr !== '') log.debug(stderr);
      resolve({ exitCode, timedOut, durationMs, stdout, stderr, ...extra });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child.pid);
    }, spec.timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => {
      stdout = (stdout + chunk.toString('utf8')).slice(-TAIL_CHARS);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      stderr = (stderr + chunk.toString('utf8')).slice(-TAIL_CHARS);
    });
    child.on('error', (err: NodeJS.ErrnoException) =>
      finish({
        spawnError: err.message,
        ...(err.code !== undefined && { spawnErrorCode: err.code }),
      }),
    );
    child.on('exit', (code) => {
      exitCode = code;
      setTimeout(() => {
        child.stdout.destroy();
        child.stderr.destroy();
        finish();
      }, CLOSE_GRACE_MS).unref();
    });
    child.on('close', (code) => {
      exitCode = code;
      finish();
    });
  });
}
