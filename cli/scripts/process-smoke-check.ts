import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { runProcess } from '../src/analyzers/process';
import { silentLogger } from '../src/log';

/** Linux only: a process is gone once `/proc/<pid>` is gone or it is a zombie awaiting reaping. */
function isAlive(pid: number): boolean {
  let stat: string;
  try {
    stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
  } catch {
    return false;
  }
  return !/^\d+ \(.*\) Z /s.test(stat);
}

/**
 * Review Focus 5 on the real runtime: a fake analyzer (`/bin/sh`) forks a grandchild (`sleep`)
 * and hangs. `runProcess` must time it out and kill the whole process group, grandchild
 * included. Returns null when that holds, otherwise what went wrong. Run by
 * `process-smoke.entry.ts` inside a `bun build --compile` binary (the same runtime and code as
 * the shipped `qualor` binary, without any test hook in the shipped binary) and by
 * `process-smoke.test.ts` under Node.
 */
export async function checkProcessGroupKill(): Promise<string | null> {
  if (process.platform !== 'linux') return null;
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-process-smoke-'));
  try {
    const pidFile = path.join(dir, 'grandchild.pid');
    const result = await runProcess(
      {
        command: '/bin/sh',
        args: ['-c', `sleep 300 >/dev/null 2>&1 & echo $! > "${pidFile}"; wait`],
        cwd: dir,
        env: { PATH: process.env['PATH'] ?? '/usr/bin:/bin' },
        timeoutMs: 1_000,
      },
      silentLogger,
    );
    if (!result.timedOut) return `the fake analyzer was not timed out (exit ${result.exitCode})`;
    const pid = Number(readFileSync(pidFile, 'utf8').trim());
    if (!Number.isInteger(pid) || pid <= 0) return 'the fake analyzer did not record its child';
    // SIGKILL delivery is asynchronous: poll the condition, with a deadline.
    const deadline = Date.now() + 5_000;
    while (isAlive(pid)) {
      if (Date.now() > deadline) return `grandchild ${pid} survived the analyzer timeout`;
      await delay(20);
    }
    return null;
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}
