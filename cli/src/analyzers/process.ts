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
  /** How much of the end of each stream to keep (64 KiB unless given; ruling T12j). */
  outputLimitBytes?: number;
}

export interface ProcessResult {
  exitCode: number | null;
  timedOut: boolean;
  durationMs: number;
  /** The end of each stream: the last 64 KiB unless `outputLimitBytes` says (config.md §6). */
  stdout: string;
  stderr: string;
  /** Whether either stream was longer than its limit, so its text is only the end (T15e). */
  truncated?: boolean;
  spawnError?: string;
  /** The underlying `NodeJS.ErrnoException.code`, e.g. `'ENOENT'` (fix-round-2 finding 5). */
  spawnErrorCode?: string;
}

const TAIL_BYTES = 64 * 1024;

/** The last `limit` bytes of a stream, kept as it comes, decoded from a whole character. */
class Tail {
  private chunks: Buffer[] = [];
  private size = 0;
  /** Every byte seen, to tell a stream that was cut from one that just fits. */
  private total = 0;
  constructor(private readonly limit: number) {}

  add(chunk: Buffer): void {
    this.chunks.push(chunk);
    this.size += chunk.length;
    this.total += chunk.length;
    if (this.size > this.limit * 2) this.trim();
  }

  private trim(): void {
    const all = Buffer.concat(this.chunks);
    const kept = all.subarray(Math.max(0, all.length - this.limit));
    this.chunks = [kept];
    this.size = kept.length;
  }

  get cut(): boolean {
    return this.total > this.limit;
  }

  text(): string {
    this.trim();
    const bytes = this.chunks[0] ?? Buffer.alloc(0);
    let start = 0;
    // A continuation byte (10xxxxxx) at the cut is the inside of a character.
    if (this.size === this.limit) {
      while (start < bytes.length && ((bytes[start] ?? 0) & 0xc0) === 0x80) start++;
    }
    return bytes.subarray(start).toString('utf8');
  }
}
/** After 'exit', wait this long for the pipes to close (a grandchild may still hold them). */
const CLOSE_GRACE_MS = 1_000;

/** Fix-round finding 8: an absolute path, not a bare command resolved through PATH. */
function taskkillPath(): string {
  return path.join(process.env['SystemRoot'] ?? 'C:\\Windows', 'System32', 'taskkill.exe');
}

export interface ProcessRow {
  pid: number;
  parentPid: number;
  /** Creation time in ms; NaN when it could not be read. */
  created: number;
}

/**
 * Every process below the given roots in a process table, breadth first. The roots themselves are
 * not returned. A pid met twice (a cycle, a pid reused as its own parent) is visited once.
 * `ParentProcessId` is not updated when a parent exits, so it can name a pid that a root got
 * later: a process counts only when it was created no earlier than its parent, and one whose
 * time (or its parent's) is unknown does not count.
 */
export function descendantsOf(roots: readonly number[], table: readonly ProcessRow[]): number[] {
  const children = new Map<number, number[]>();
  const created = new Map<number, number>();
  for (const row of table) {
    created.set(row.pid, row.created);
    if (row.pid === row.parentPid) continue;
    const list = children.get(row.parentPid);
    if (list === undefined) children.set(row.parentPid, [row.pid]);
    else list.push(row.pid);
  }
  const seen = new Set<number>(roots);
  const found: number[] = [];
  const queue = [...roots];
  // The iterator also visits the children pushed while it runs: a breadth-first walk.
  for (const parent of queue) {
    const parentCreated = created.get(parent) ?? Number.NaN;
    for (const child of children.get(parent) ?? []) {
      if (seen.has(child)) continue;
      const childCreated = created.get(child) ?? Number.NaN;
      const afterParent = childCreated >= parentCreated; // false for NaN too
      if (!afterParent) continue;
      seen.add(child);
      found.push(child);
      queue.push(child);
    }
  }
  return found;
}

const SWEEP_TIMEOUT_MS = 5_000;
const KILL_BATCH = 50;

/** Windows PowerShell 5.1 ships with Windows; `wmic` does not on current releases. */
function powershellPath(): string {
  return path.join(
    process.env['SystemRoot'] ?? 'C:\\Windows',
    'System32',
    'WindowsPowerShell',
    'v1.0',
    'powershell.exe',
  );
}

/**
 * The pids below the roots, read from one process-table snapshot. `taskkill /T` misses a child
 * that was started after its snapshot or whose parent has gone, so the descendants are found
 * first. Any failure (no PowerShell, a policy, a timeout) gives an empty list.
 */
function sweepDescendants(roots: readonly number[]): number[] {
  try {
    const r = spawnSync(
      powershellPath(),
      [
        '-NoProfile',
        '-NonInteractive',
        '-Command',
        'Get-CimInstance Win32_Process | ForEach-Object { "$($_.ProcessId) $($_.ParentProcessId) $(if ($_.CreationDate) { ([DateTimeOffset]$_.CreationDate).ToUnixTimeMilliseconds() })" }',
      ],
      {
        encoding: 'utf8',
        timeout: SWEEP_TIMEOUT_MS,
        windowsHide: true,
        stdio: ['ignore', 'pipe', 'ignore'],
      },
    );
    if (r.status !== 0 || typeof r.stdout !== 'string') return [];
    const table: ProcessRow[] = [];
    for (const line of r.stdout.split(/\r?\n/)) {
      const m = /^(\d+) (\d+)(?: (\d+))?$/.exec(line.trim());
      if (m !== null)
        table.push({
          pid: Number(m[1]),
          parentPid: Number(m[2]),
          created: m[3] === undefined ? Number.NaN : Number(m[3]),
        });
    }
    return descendantsOf(roots, table);
  } catch {
    return [];
  }
}

function killWindowsTrees(roots: readonly number[]): void {
  const taskkill = taskkillPath();
  // A pid reused between the snapshot and the kill is not covered; the window is milliseconds.
  const options = { stdio: 'ignore', windowsHide: true } as const;
  // Descendants first, by pid found under the roots; then today's tree kill for the roots.
  const descendants = sweepDescendants(roots);
  for (let i = 0; i < descendants.length; i += KILL_BATCH) {
    const args = descendants.slice(i, i + KILL_BATCH).flatMap((pid) => ['/pid', String(pid)]);
    spawnSync(taskkill, [...args, '/F'], options);
  }
  for (const pid of roots) spawnSync(taskkill, ['/pid', String(pid), '/T', '/F'], options);
}

function killPosixTree(pid: number): void {
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

/** Kills several processes and everything they started (one process-table sweep on Windows). */
export function killTrees(pids: readonly number[]): void {
  if (pids.length === 0) return;
  if (process.platform === 'win32') killWindowsTrees(pids);
  else for (const pid of pids) killPosixTree(pid);
}

/** Kills a process and everything it started (Review Focus 5). */
export function killTree(pid: number | undefined): void {
  if (pid !== undefined) killTrees([pid]);
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
  killTrees([...activePids]);
}

export function runProcess(spec: ProcessSpec, log: Logger): Promise<ProcessResult> {
  return new Promise((resolve) => {
    const started = performance.now();
    const stdout = new Tail(spec.outputLimitBytes ?? TAIL_BYTES);
    const stderr = new Tail(spec.outputLimitBytes ?? TAIL_BYTES);
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
      const err = stderr.text();
      if (err !== '') log.debug(err);
      resolve({
        exitCode,
        timedOut,
        durationMs,
        stdout: stdout.text(),
        stderr: err,
        truncated: stdout.cut || stderr.cut,
        ...extra,
      });
    };
    const timer = setTimeout(() => {
      timedOut = true;
      killTree(child.pid);
    }, spec.timeoutMs);
    child.stdout.on('data', (chunk: Buffer) => stdout.add(chunk));
    child.stderr.on('data', (chunk: Buffer) => stderr.add(chunk));
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
