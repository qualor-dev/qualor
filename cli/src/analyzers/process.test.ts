import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { setTimeout as sleep } from 'node:timers/promises';
import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../../test/tmp';
import { silentLogger } from '../log';
import { sanitizeAnalyzerEnv } from './env';
import { killActiveProcesses, runProcess } from './process';

const tmp = useTempDirs();
const node = (code: string, timeoutMs = 10_000) => ({
  command: process.execPath,
  args: ['-e', code],
  cwd: process.cwd(),
  env: sanitizeAnalyzerEnv(process.env),
  timeoutMs,
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
    { timeout: 20_000 },
    async () => {
      const marker = path.join(tmp(), 'grandchild-survived');
      const grandchild = `setTimeout(() => require('fs').writeFileSync(${JSON.stringify(marker)}, 'alive'), 1500)`;
      const started = performance.now();
      const r = await runProcess(
        node(
          `require('child_process').spawn(process.execPath, ['-e', ${JSON.stringify(grandchild)}], { stdio: 'ignore' }); setInterval(() => {}, 1000)`,
          500,
        ),
        silentLogger,
      );
      expect(r.timedOut).toBe(true);
      expect(performance.now() - started).toBeLessThan(5_000);
      await sleep(2_500);
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
