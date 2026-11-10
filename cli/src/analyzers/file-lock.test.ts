import { spawn } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  linkSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { describe, expect, it } from 'vitest';
import { useTempDirs } from '../../test/tmp';
import { claimOf, takeOverStale, withFileLock } from './file-lock';

const tmp = useTempDirs();
const pause = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
const MODULE = pathToFileURL(path.join(import.meta.dirname, 'file-lock.ts')).href;

/** Runs `code` (an ES module given `withFileLock`) in a child process through tsx. */
function child(dir: string, code: string, args: string[]): Promise<number | null> {
  const script = path.join(dir, `child-${Math.random().toString(36).slice(2)}.mts`);
  writeFileSync(script, `import { withFileLock } from ${JSON.stringify(MODULE)};\n${code}`);
  const proc = spawn(process.execPath, ['--import', 'tsx', script, ...args], {
    cwd: path.join(import.meta.dirname, '..', '..'),
    stdio: ['ignore', 'ignore', 'inherit'],
  });
  return new Promise((resolve) => proc.on('exit', (c) => resolve(c)));
}

/** The most holders at once, from `start`/`end` lines in the order they were appended. */
function maxHolders(log: string): number {
  let held = 0;
  let max = 0;
  for (const line of log.trim().split('\n')) {
    held += line.startsWith('start') ? 1 : -1;
    max = Math.max(max, held);
  }
  return max;
}

/** Sets the file's modification time `ms` in the past (negative: in the future). */
const age = (file: string, ms = 60_000) => {
  const at = new Date(Date.now() - ms);
  utimesSync(file, at, at);
};

/** A child that waits until `at`, then holds the lock for 100 ms and logs it. */
const HOLDER = [
  'import { appendFileSync } from "node:fs";',
  'const [file, log, id, at] = process.argv.slice(2);',
  'while (Date.now() < Number(at)) { /* start together */ }',
  'await withFileLock(file, async () => {',
  '  appendFileSync(log, "start " + id + "\\n");',
  '  await new Promise((r) => setTimeout(r, 100));',
  '  appendFileSync(log, "end " + id + "\\n");',
  '}, { staleMs: 5_000, pollMs: 5 });',
  '',
].join('\n');

describe('withFileLock (the OpenGrep cache across qualor scan processes)', () => {
  it('never lets two holders in at once, and removes the lock file afterwards', async () => {
    const file = path.join(tmp(), 'cache', 'opengrep', '.lock');
    const log: string[] = [];
    const hold = (name: string) =>
      withFileLock(
        file,
        async () => {
          log.push(`start ${name}`);
          expect(existsSync(file)).toBe(true);
          await pause(30);
          log.push(`end ${name}`);
          return name;
        },
        { pollMs: 5 },
      );
    expect(await Promise.all([hold('a'), hold('b'), hold('c')])).toEqual(['a', 'b', 'c']);
    for (let i = 0; i < log.length; i += 2) {
      expect(log[i]?.replace('start', 'end')).toBe(log[i + 1]);
    }
    expect(log).toHaveLength(6);
    expect(existsSync(file)).toBe(false);
  });

  it('waits while another process holds the lock, then takes it', async () => {
    const file = path.join(tmp(), '.lock');
    writeFileSync(file, 'another process');
    let ran = false;
    const held = withFileLock(
      file,
      () => {
        ran = true;
        return Promise.resolve();
      },
      { pollMs: 5 },
    );
    await pause(50);
    expect(ran).toBe(false);
    // The other process releases it.
    rmSync(file);
    await held;
    expect(ran).toBe(true);
  });

  it('breaks a lock older than staleMs (a process killed while it held it)', async () => {
    const file = path.join(tmp(), '.lock');
    writeFileSync(file, 'killed process');
    age(file);
    expect(await withFileLock(file, () => Promise.resolve('ran'), { staleMs: 30_000 })).toBe('ran');
    expect(existsSync(file)).toBe(false);
  });

  it(
    'lets one process at a time take over a stale lock (6 processes, 3 trials)',
    {
      timeout: 120_000,
    },
    async () => {
      const dir = tmp();
      for (let trial = 0; trial < 3; trial++) {
        const file = path.join(dir, `t${trial}.lock`);
        const log = path.join(dir, `t${trial}.log`);
        writeFileSync(file, 'a process killed while it held the lock');
        age(file);
        writeFileSync(log, '');
        const at = String(Date.now() + 4_000);
        const codes = await Promise.all(
          Array.from({ length: 6 }, (_, i) => child(dir, HOLDER, [file, log, String(i), at])),
        );
        expect(codes, `trial ${trial}`).toEqual([0, 0, 0, 0, 0, 0]);
        const text = readFileSync(log, 'utf8');
        expect(text.match(/^start/gm), `trial ${trial}`).toHaveLength(6);
        expect(maxHolders(text), `trial ${trial}: ${text}`).toBe(1);
        expect(existsSync(file)).toBe(false);
      }
      // No claim on a stale lock is left behind.
      expect(readdirSync(dir).filter((f) => f.endsWith('.stale'))).toEqual([]);
    },
  );

  it(
    'removes its lock when the process exits while holding it (Ctrl+C, process.exit)',
    {
      timeout: 30_000,
    },
    async () => {
      const dir = tmp();
      const file = path.join(dir, '.lock');
      const code = await child(
        dir,
        'await withFileLock(process.argv[2], () => { process.exit(130); });\n',
        [file],
      );
      expect(code).toBe(130);
      expect(existsSync(file)).toBe(false);
    },
  );

  it('treats a lock with a modification time in the future as stale (clock skew)', async () => {
    const file = path.join(tmp(), '.lock');
    writeFileSync(file, 'another host');
    age(file, -3_600_000);
    expect(await withFileLock(file, () => Promise.resolve('ran'), { staleMs: 30_000 })).toBe('ran');
  });

  it('stops waiting after maxWaitMs and runs unlocked, leaving the other lock alone', async () => {
    const file = path.join(tmp(), '.lock');
    writeFileSync(file, 'a live process');
    const started = Date.now();
    expect(
      await withFileLock(file, () => Promise.resolve('ran'), { pollMs: 5, maxWaitMs: 100 }),
    ).toBe('ran');
    expect(Date.now() - started).toBeGreaterThanOrEqual(100);
    expect(readFileSync(file, 'utf8')).toBe('a live process');
  });

  it('says once that it waits, after noticeMs', async () => {
    const file = path.join(tmp(), '.lock');
    writeFileSync(file, 'a live process');
    let notices = 0;
    const held = withFileLock(file, () => Promise.resolve(), {
      pollMs: 5,
      // Ten times the first check: a loaded CI runner delays timers by tens of milliseconds.
      noticeMs: 200,
      onWait: () => {
        notices += 1;
      },
    });
    await pause(20);
    expect(notices).toBe(0);
    await pause(400);
    rmSync(file);
    await held;
    expect(notices).toBe(1);
  });

  it('runs unlocked at once when a directory is at the lock path', async () => {
    const file = path.join(tmp(), '.lock');
    mkdirSync(file);
    age(file);
    const started = Date.now();
    expect(await withFileLock(file, () => Promise.resolve('ran'), { pollMs: 5 })).toBe('ran');
    expect(Date.now() - started).toBeLessThan(5_000);
    expect(existsSync(file)).toBe(true);
  });

  it.runIf(process.platform !== 'win32' && process.getuid?.() !== 0)(
    'never fails when it may not remove a stale lock (another user in a shared cache)',
    async () => {
      const dir = path.join(tmp(), 'cache');
      mkdirSync(dir);
      const file = path.join(dir, '.lock');
      writeFileSync(file, 'another user');
      age(file);
      chmodSync(dir, 0o555);
      try {
        expect(
          await withFileLock(file, () => Promise.resolve('ran'), {
            pollMs: 5,
            staleMs: 1_000,
            maxWaitMs: 60_000,
          }),
        ).toBe('ran');
        expect(readFileSync(file, 'utf8')).toBe('another user');
      } finally {
        chmodSync(dir, 0o755);
      }
    },
  );

  it('leaves alone a fresh lock that holds the content it judged stale (re-checked on the claim)', () => {
    const dir = tmp();
    const file = path.join(dir, '.lock');
    // Between the age check and the read, another waiter took the stale lock over and wrote a
    // fresh one: the content read is the fresh lock's.
    writeFileSync(file, 'token of a fresh lock');
    expect(takeOverStale(file, 'token of a fresh lock', 30_000)).toBe('wait');
    expect(readFileSync(file, 'utf8')).toBe('token of a fresh lock');
    expect(readdirSync(dir)).toEqual(['.lock']);
  });

  it('takes over a stale lock through its claim, and leaves nothing behind', () => {
    const dir = tmp();
    const file = path.join(dir, '.lock');
    writeFileSync(file, 'dead holder');
    age(file);
    expect(takeOverStale(file, 'dead holder', 30_000)).toBe('retry');
    expect(readdirSync(dir)).toEqual([]);
  });

  it('runs unlocked at once where hard links cannot be made, and says why', () => {
    const file = path.join(tmp(), '.lock');
    writeFileSync(file, 'dead holder');
    age(file);
    const fail = (code: string) => () => {
      throw Object.assign(new Error(code), { code });
    };
    for (const code of ['ENOTSUP', 'EOPNOTSUPP', 'ENOSYS', 'EXDEV']) {
      expect(takeOverStale(file, 'dead holder', 30_000, fail(code)), code).toEqual({
        unusable: `no hard link can be made next to ${file} (${code})`,
      });
    }
    // The lock went away meanwhile: try again; on Windows it may be pending deletion: wait.
    expect(takeOverStale(file, 'dead holder', 30_000, fail('ENOENT'))).toBe('retry');
    if (process.platform === 'win32') {
      expect(takeOverStale(file, 'dead holder', 30_000, fail('EPERM'))).toBe('wait');
    }
    expect(readFileSync(file, 'utf8')).toBe('dead holder');
  });

  it('runs unlocked at once, and names both files, when a dead claimer left its claim', async () => {
    const dir = tmp();
    const file = path.join(dir, '.lock');
    writeFileSync(file, 'dead holder');
    age(file);
    const found: string[] = [];
    const run = (staleMs: number, maxWaitMs: number) =>
      withFileLock(file, () => Promise.resolve('ran'), {
        pollMs: 5,
        staleMs,
        maxWaitMs,
        onUnlocked: (why) => found.push(why),
      });
    // A claimer killed between its claim and its cleanup.
    linkSync(file, claimOf(file, 'dead holder'));
    // A young claim belongs to a live claimer: wait for it.
    const started = Date.now();
    expect(await run(30_000, 150)).toBe('ran');
    expect(Date.now() - started).toBeGreaterThanOrEqual(150);
    expect(found).toEqual([`waited 0.15 s for ${file}`]);
    await pause(120);
    found.length = 0;
    const again = Date.now();
    expect(await run(100, 60_000)).toBe('ran');
    expect(Date.now() - again).toBeLessThan(5_000);
    expect(found).toEqual([
      `${claimOf(file, 'dead holder')} is left from a process that died while it took over ${file}; remove both`,
    ]);
    expect(readFileSync(file, 'utf8')).toBe('dead holder');
  });

  it('releases the lock when the work fails', async () => {
    const file = path.join(tmp(), '.lock');
    await expect(withFileLock(file, () => Promise.reject(new Error('boom')))).rejects.toThrow(
      'boom',
    );
    expect(existsSync(file)).toBe(false);
  });

  it('never removes a lock that is no longer its own', async () => {
    const file = path.join(tmp(), '.lock');
    await withFileLock(file, () => {
      // Taken over as stale by another process meanwhile.
      writeFileSync(file, 'another process');
      return Promise.resolve();
    });
    expect(readFileSync(file, 'utf8')).toBe('another process');
  });

  it('runs the work without a lock when none can be created (a read-only cache)', async () => {
    const parent = path.join(tmp(), 'not-a-directory');
    writeFileSync(parent, '');
    expect(
      await withFileLock(path.join(parent, '.lock'), () => Promise.resolve('ran'), { pollMs: 5 }),
    ).toBe('ran');
  });
});
