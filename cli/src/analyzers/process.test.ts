import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../../test/tmp';
import { silentLogger } from '../log';
import { sanitizeAnalyzerEnv } from './env';
import { descendantsOf, killActiveProcesses, runProcess } from './process';

const tmp = useTempDirs();
const node = (code: string, timeoutMs = 10_000) => ({
  command: process.execPath,
  args: ['-e', code],
  cwd: process.cwd(),
  env: sanitizeAnalyzerEnv(process.env),
  timeoutMs,
});

describe('descendantsOf', () => {
  const row = (pid: number, parentPid: number, created = 100) => ({ pid, parentPid, created });

  it('follows a chain', () => {
    expect(descendantsOf([1], [row(1, 0), row(2, 1), row(3, 2), row(4, 3), row(9, 8)])).toEqual([
      2, 3, 4,
    ]);
  });

  it('finds siblings and their children, breadth first', () => {
    expect(descendantsOf([1], [row(1, 0), row(2, 1), row(3, 1), row(4, 2), row(5, 3)])).toEqual([
      2, 3, 4, 5,
    ]);
  });

  it('serves several roots and never returns a root', () => {
    expect(
      descendantsOf(
        [1, 10],
        [row(1, 0), row(10, 0), row(2, 1), row(11, 10), row(12, 11), row(1, 12)],
      ),
    ).toEqual([2, 11, 12]);
  });

  it('survives a cycle', () => {
    expect(descendantsOf([1], [row(1, 0), row(2, 1), row(3, 2), row(2, 3)])).toEqual([2, 3]);
  });

  it('ignores a pid that is its own parent', () => {
    expect(descendantsOf([1], [row(1, 0), row(2, 1), row(2, 2), row(5, 5)])).toEqual([2]);
  });

  it('does not find an orphan whose parent is gone', () => {
    expect(descendantsOf([1], [row(1, 0), row(2, 1), row(7, 99)])).toEqual([2]);
  });

  it('skips a stale process that only carries a root pid as its parent', () => {
    // 7 is older than root 1, so its parent pid 1 belonged to someone else; 8 hangs under 7.
    const table = [row(1, 0, 500), row(7, 1, 400), row(8, 7, 600), row(2, 1, 550)];
    expect(descendantsOf([1], table)).toEqual([2]);
  });

  it('counts a process created at the same time as its parent', () => {
    expect(descendantsOf([1], [row(1, 0, 500), row(2, 1, 500), row(3, 2, 500)])).toEqual([2, 3]);
  });

  it('skips a process whose creation time is unknown, and what hangs under it', () => {
    const table = [row(1, 0, 500), row(2, 1, Number.NaN), row(3, 2, 600), row(4, 1, 600)];
    expect(descendantsOf([1], table)).toEqual([4]);
  });

  it('finds nothing under a root missing from the snapshot', () => {
    expect(descendantsOf([1], [row(2, 1, 600)])).toEqual([]);
  });

  it('returns nothing for an unknown root', () => {
    expect(descendantsOf([42], [row(2, 1)])).toEqual([]);
  });
});

describe('runProcess', () => {
  it('returns the exit code and output tails', async () => {
    const r = await runProcess(
      node('process.stdout.write("out"); process.stderr.write("err"); process.exit(3)'),
      silentLogger,
    );
    expect(r).toMatchObject({ exitCode: 3, timedOut: false, stdout: 'out', stderr: 'err' });
  });

  it('passes exactly the given environment, never falling back to process.env', async () => {
    const r = await runProcess(
      {
        ...node('process.stdout.write(JSON.stringify(Object.keys(process.env)))'),
        env: { ONLY_VAR: '1' },
      },
      silentLogger,
    );
    // libuv always adds a fixed set of system variables to a Windows child's environment.
    const windowsDefaults = new Set(
      'HOMEDRIVE HOMEPATH LOGONSERVER PATH SYSTEMDRIVE SYSTEMROOT TEMP USERDOMAIN USERNAME USERPROFILE WINDIR'.split(
        ' ',
      ),
    );
    const keys = (JSON.parse(r.stdout) as string[]).filter(
      (k) => process.platform !== 'win32' || !windowsDefaults.has(k.toUpperCase()),
    );
    expect(keys).toEqual(['ONLY_VAR']);
  });

  it('keeps only the last 64 KiB of output', async () => {
    const r = await runProcess(
      node('process.stdout.write("x".repeat(200000) + "END")'),
      silentLogger,
    );
    expect(r.stdout).toHaveLength(64 * 1024);
    expect(r.stdout.endsWith('END')).toBe(true);
  });

  it('reports a command that cannot be started', async () => {
    const r = await runProcess(
      {
        command: path.join(tmp(), 'no-such-tool'),
        args: [],
        cwd: process.cwd(),
        env: {},
        timeoutMs: 5_000,
      },
      silentLogger,
    );
    expect(r.exitCode).toBeNull();
    expect(r.spawnError).toBeDefined();
  });

  it(
    'kills a hanging process and the children it started when the timeout expires',
    { timeout: 40_000 },
    async () => {
      const marker = path.join(tmp(), 'grandchild-survived');
      const started = path.join(tmp(), 'grandchild-started');
      // The grandchild announces itself, then would write the marker 15 s later. The timeout
      // (6 s) is far past the grandchild's start, which the test checks before the kill happens,
      // and the kill comes before the marker is due even when the sweep takes its whole 5 s.
      const grandchild = `require('fs').writeFileSync(${JSON.stringify(started)}, 'up'); setTimeout(() => require('fs').writeFileSync(${JSON.stringify(marker)}, 'alive'), 15000)`;
      const promise = runProcess(
        node(
          `require('child_process').spawn(process.execPath, ['-e', ${JSON.stringify(grandchild)}], { stdio: 'ignore' }); setInterval(() => {}, 1000)`,
          6_000,
        ),
        silentLogger,
      );
      const deadline = Date.now() + 5_000;
      while (!existsSync(started) && Date.now() < deadline) await sleep(20);
      expect(existsSync(started)).toBe(true); // before the timeout can fire
      const markerDue = Date.now() + 15_000;
      const r = await promise;
      expect(r.timedOut).toBe(true);
      // Look only once the marker would have been written, so a survivor cannot be missed.
      await sleep(Math.max(0, markerDue + 1_500 - Date.now()));
      expect(existsSync(marker)).toBe(false);
    },
  );

  it(
    'killActiveProcesses kills every currently tracked process tree (fix-round finding 10)',
    { timeout: 60_000 },
    async () => {
      const marker = path.join(tmp(), 'grandchild-survived-2');
      const ready = path.join(tmp(), 'grandchild-pid');
      // The grandchild announces its pid once it runs, then would write the marker 5 s later.
      const grandchild = `require('fs').writeFileSync(${JSON.stringify(ready)}, String(process.pid)); setTimeout(() => require('fs').writeFileSync(${JSON.stringify(marker)}, 'alive'), 5000)`;
      const promise = runProcess(
        node(
          `require('child_process').spawn(process.execPath, ['-e', ${JSON.stringify(grandchild)}], { stdio: 'ignore' }); setInterval(() => {}, 1000)`,
          30_000,
        ),
        silentLogger,
      );
      // Under load a fixed delay may end before the grandchild exists (or while it is being
      // spawned), so wait until it has announced itself, up to a deadline.
      const deadline = Date.now() + 20_000;
      while (!existsSync(ready) && Date.now() < deadline) await sleep(20);
      expect(existsSync(ready)).toBe(true);
      const pid = Number(readFileSync(ready, 'utf8'));
      killActiveProcesses();
      const r = await promise;
      expect(r.timedOut).toBe(false); // killed directly, not by its own timeout
      // The grandchild must be gone: poll for it instead of sleeping past its timer, then the
      // marker can no longer appear.
      const alive = (): boolean => {
        try {
          process.kill(pid, 0);
          return true;
        } catch {
          return false;
        }
      };
      const gone = Date.now() + 10_000;
      while (alive() && Date.now() < gone) await sleep(50);
      expect(alive()).toBe(false);
      expect(existsSync(marker)).toBe(false);
    },
  );
});
