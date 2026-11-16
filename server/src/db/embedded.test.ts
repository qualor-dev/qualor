import { spawn } from 'node:child_process';
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import {
  acquireLease,
  clearStalePostmaster,
  EmbeddedPostgresError,
  liveLease,
  prepareCluster,
  socketUrl,
  startEmbeddedPostgres,
  type EmbeddedLogger,
} from './embedded';

// embedded-postgres.md §8 criterion 2: the embedded start with a fake PostgreSQL.

let root: string;
let postgresDir: string;
let dataDir: string;
const lines: string[] = [];
const logger: EmbeddedLogger = {
  info: (_obj, msg) => lines.push(msg),
  warn: (_obj, msg) => lines.push(msg),
};

beforeEach(() => {
  root = mkdtempSync(path.join(os.tmpdir(), 'qualor-embedded-'));
  postgresDir = path.join(root, 'pg');
  dataDir = path.join(root, 'data');
  mkdirSync(path.join(postgresDir, 'bin'), { recursive: true });
  writeFileSync(path.join(postgresDir, 'bin', 'postgres'), '');
  writeFileSync(path.join(postgresDir, 'VERSION'), '18.6\n');
  mkdirSync(path.join(postgresDir, 'template', 'base', '1'), { recursive: true });
  writeFileSync(path.join(postgresDir, 'template', 'PG_VERSION'), '18\n');
  writeFileSync(path.join(postgresDir, 'template', 'base', '1', 'heap'), 'rows');
  lines.length = 0;
});

afterEach(() => rmSync(root, { recursive: true, force: true }));

/** A fake postgres: a Node script that prints `say`, then exits or keeps running. */
function fakePostgres(script: string) {
  return () => spawn(process.execPath, ['-e', script], { stdio: ['ignore', 'pipe', 'pipe'] });
}

describe('prepareCluster', () => {
  it('copies the template into a missing data directory, with private modes', async () => {
    const cluster = await prepareCluster({ dataDir, postgresDir });
    expect(cluster).toBe(path.join(dataDir, 'postgres'));
    expect(readFileSync(path.join(cluster, 'base', '1', 'heap'), 'utf8')).toBe('rows');
    if (process.platform !== 'win32') {
      expect(statSync(cluster).mode & 0o777).toBe(0o700);
      expect(statSync(path.join(cluster, 'base')).mode & 0o777).toBe(0o700);
      expect(statSync(path.join(cluster, 'PG_VERSION')).mode & 0o777).toBe(0o600);
      expect(statSync(path.join(dataDir, 'run')).mode & 0o777).toBe(0o700);
    }
  });

  it('copies the template into an empty data directory too, and keeps an existing cluster', async () => {
    mkdirSync(path.join(dataDir, 'postgres'), { recursive: true });
    await prepareCluster({ dataDir, postgresDir });
    writeFileSync(path.join(dataDir, 'postgres', 'base', '1', 'heap'), 'changed');
    await prepareCluster({ dataDir, postgresDir });
    expect(readFileSync(path.join(dataDir, 'postgres', 'base', '1', 'heap'), 'utf8')).toBe(
      'changed',
    );
  });

  it('never overwrites a non-empty directory that is not a cluster', async () => {
    mkdirSync(path.join(dataDir, 'postgres'), { recursive: true });
    writeFileSync(path.join(dataDir, 'postgres', 'notes.txt'), 'mine');
    await expect(prepareCluster({ dataDir, postgresDir })).rejects.toThrow(
      /is not empty and holds no PostgreSQL cluster/,
    );
    expect(readFileSync(path.join(dataDir, 'postgres', 'notes.txt'), 'utf8')).toBe('mine');
  });

  it.skipIf(process.platform === 'win32')(
    'restores the private modes of an existing cluster on every start',
    async () => {
      // A volume restored, copied or re-owned since (a recursive fsGroup change makes it 2770):
      // PostgreSQL refuses a group-accessible data directory.
      const cluster = await prepareCluster({ dataDir, postgresDir });
      chmodSync(cluster, 0o770);
      chmodSync(path.join(cluster, 'base'), 0o2770);
      chmodSync(path.join(cluster, 'base', '1', 'heap'), 0o660);
      await prepareCluster({ dataDir, postgresDir });
      expect(statSync(cluster).mode & 0o7777).toBe(0o700);
      expect(statSync(path.join(cluster, 'base')).mode & 0o777).toBe(0o700);
      expect(statSync(path.join(cluster, 'base', '1', 'heap')).mode & 0o777).toBe(0o600);
    },
  );

  it('refuses a cluster of another major version', async () => {
    mkdirSync(path.join(dataDir, 'postgres'), { recursive: true });
    writeFileSync(path.join(dataDir, 'postgres', 'PG_VERSION'), '16\n');
    await expect(prepareCluster({ dataDir, postgresDir })).rejects.toThrow(
      'the data directory holds a PostgreSQL 16 cluster and this image carries PostgreSQL 18.6',
    );
  });

  it('asks for DATABASE_URL when the image carries no PostgreSQL', async () => {
    rmSync(path.join(postgresDir, 'bin', 'postgres'));
    const err = await prepareCluster({ dataDir, postgresDir }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(EmbeddedPostgresError);
    expect((err as Error).message).toMatch(
      /DATABASE_URL is not set and no embedded PostgreSQL was found/,
    );
  });
});

describe('startEmbeddedPostgres', () => {
  it('starts with the socket-only arguments, logs its lines and returns the socket URL', async () => {
    let args: string[] = [];
    let probes = 0;
    const embedded = await startEmbeddedPostgres({
      dataDir,
      postgresDir,
      logger,
      spawnPostgres: (_bin, argv) => {
        args = argv;
        return fakePostgres(
          "console.log('database system is ready'); setInterval(() => {}, 1000)",
        )();
      },
      probe: async () => {
        probes += 1;
        if (probes < 3) throw new Error('not yet');
      },
    });
    expect(embedded.url).toBe(socketUrl(path.join(dataDir, 'run')));
    expect(args).toEqual([
      '-D',
      path.join(dataDir, 'postgres'),
      '-c',
      'listen_addresses=',
      '-c',
      `unix_socket_directories=${path.join(dataDir, 'run')}`,
      '-c',
      'unix_socket_permissions=0700',
    ]);
    await embedded.stop();
    await embedded.stop();
    expect(await embedded.exited).toMatch(/^(signal|code)/);
    expect(lines).toContain('database system is ready');
  });

  it('stops the start with the last lines when PostgreSQL exits before it is ready', async () => {
    await expect(
      startEmbeddedPostgres({
        dataDir,
        postgresDir,
        logger,
        lease: { settleMs: 0 },
        spawnPostgres: fakePostgres(
          'console.error(\'FATAL:  lock file "postmaster.pid" already exists\'); process.exit(1)',
        ),
        probe: () => Promise.reject(new Error('no socket')),
      }),
    ).rejects.toThrow(
      /exited before it was ready \(code 1\):\nFATAL: {2}lock file "postmaster.pid" already exists/,
    );
  });

  it('gives up after the readiness timeout and stops PostgreSQL', async () => {
    let child: ReturnType<ReturnType<typeof fakePostgres>> | undefined;
    await expect(
      startEmbeddedPostgres({
        dataDir,
        postgresDir,
        logger,
        lease: { settleMs: 0 },
        spawnPostgres: () => (child = fakePostgres('setInterval(() => {}, 1000)')()),
        probe: () => Promise.reject(new Error('no socket')),
        readyTimeoutMs: 600,
      }),
    ).rejects.toThrow(/was not ready within 1 s/);
    expect(child?.exitCode !== null || child?.signalCode !== null).toBe(true);
  });

  it.skipIf(process.platform === 'win32')(
    'kills PostgreSQL when a fast shutdown does not finish in time',
    async () => {
      // The fake writes `ready` once it ignores SIGINT, and the probe waits for that file: on a
      // busy CI runner Node can take longer to boot than a fixed delay, and a SIGINT sent before
      // the handler exists stops the fake at once (`signal SIGINT`).
      const ready = path.join(dataDir, 'fake-postgres-ready');
      const embedded = await startEmbeddedPostgres({
        dataDir,
        postgresDir,
        logger,
        lease: { settleMs: 0 },
        spawnPostgres: fakePostgres(
          `process.on('SIGINT', () => {}); require('node:fs').writeFileSync(${JSON.stringify(ready)}, ''); setInterval(() => {}, 1000)`,
        ),
        probe: async () => {
          const deadline = Date.now() + 30_000;
          while (!existsSync(ready)) {
            if (Date.now() > deadline) throw new Error('the fake PostgreSQL never got ready');
            await new Promise((resolve) => setTimeout(resolve, 20));
          }
        },
        stopTimeoutMs: 300,
      });
      await embedded.stop();
      expect(await embedded.exited).toBe('signal SIGKILL');
      expect(lines).toContain('PostgreSQL did not stop in time; killing it');
    },
  );
});

describe('acquireLease', () => {
  const leaseFile = () => path.join(dataDir, 'server.lease');
  beforeEach(() => mkdirSync(dataDir, { recursive: true }));

  it('refuses a data directory another host renewed recently, and names it', async () => {
    writeFileSync(
      leaseFile(),
      JSON.stringify({ instance: 'x', host: 'other', renewedAt: Date.now() }),
    );
    await expect(acquireLease(dataDir, { hostname: 'me', settleMs: 0 })).rejects.toThrow(
      /another Qualor server \(host other\) is using .*one server per data directory/,
    );
  });

  it('takes over a stale lease, and a lease of the same host (a restarted container)', async () => {
    writeFileSync(
      leaseFile(),
      JSON.stringify({ instance: 'x', host: 'other', renewedAt: Date.now() - 31_000 }),
    );
    const release = await acquireLease(dataDir, { hostname: 'me', settleMs: 0 });
    expect(JSON.parse(readFileSync(leaseFile(), 'utf8'))).toMatchObject({ host: 'me' });
    await release();
    writeFileSync(
      leaseFile(),
      JSON.stringify({ instance: 'y', host: 'me', renewedAt: Date.now() }),
    );
    const again = await acquireLease(dataDir, { hostname: 'me', settleMs: 0 });
    await again();
  });

  // Timer-driven: under a loaded test run a 50 ms timer can fire much later, so each step waits
  // for its event up to a deadline (10 s) instead of assuming it happened within a fixed delay.
  it(
    'removes its lease on release, renews it, and reports a take-over',
    { timeout: 30_000 },
    async () => {
      const until = async (done: () => boolean): Promise<void> => {
        for (const end = Date.now() + 10_000; !done() && Date.now() < end;) {
          await new Promise((resolve) => setTimeout(resolve, 20));
        }
      };
      // The lease is replaced by a rename; on Windows a read can meet it mid-rename, so retry.
      const renewedAt = (): number | undefined => {
        try {
          return JSON.parse(readFileSync(leaseFile(), 'utf8')).renewedAt as number;
        } catch {
          return undefined;
        }
      };
      let lost = false;
      const release = await acquireLease(dataDir, {
        hostname: 'me',
        settleMs: 0,
        renewMs: 50,
        onLost: () => (lost = true),
      });
      const first = JSON.parse(readFileSync(leaseFile(), 'utf8')).renewedAt as number;
      let renewed = first;
      await until(() => (renewed = renewedAt() ?? first) > first);
      expect(renewed).toBeGreaterThan(first);
      // Another server that took over keeps renewing its own lease, as a real one does.
      const takeOver = (): void =>
        writeFileSync(
          leaseFile(),
          JSON.stringify({ instance: 'z', host: 'other', renewedAt: Date.now() }),
        );
      const other = setInterval(takeOver, 10);
      try {
        await until(() => lost);
      } finally {
        clearInterval(other);
      }
      takeOver();
      expect(lost).toBe(true);
      await release();
      expect(JSON.parse(readFileSync(leaseFile(), 'utf8')).instance).toBe('z');
    },
  );

  it('is released when the embedded start fails', async () => {
    await expect(
      startEmbeddedPostgres({
        dataDir,
        postgresDir,
        logger,
        lease: { settleMs: 0 },
        spawnPostgres: fakePostgres('process.exit(3)'),
        probe: () => Promise.reject(new Error('no socket')),
      }),
    ).rejects.toThrow(/exited before it was ready/);
    expect(() => statSync(leaseFile())).toThrow();
  });
});

describe('clearStalePostmaster (R27)', () => {
  const PID = '4242';
  let cluster: string;
  let run: string;
  let proc: string;

  beforeEach(() => {
    cluster = path.join(dataDir, 'postgres');
    run = path.join(dataDir, 'run');
    proc = path.join(root, 'proc');
    mkdirSync(cluster, { recursive: true });
    mkdirSync(run, { recursive: true });
    mkdirSync(proc, { recursive: true });
    // What an OOM-killed PostgreSQL leaves: its pid file and its socket's lock file.
    writeFileSync(path.join(cluster, 'postmaster.pid'), `${PID}\n${cluster}\n1763300000\n5432\n`);
    writeFileSync(path.join(run, '.s.PGSQL.5432.lock'), `${PID}\n${cluster}\n`);
    writeFileSync(path.join(run, '.s.PGSQL.5432'), '');
  });

  /** A process in the fake /proc, with its NUL-separated command line. */
  const processWith = (pid: string, argv: string[]) => {
    mkdirSync(path.join(proc, pid), { recursive: true });
    writeFileSync(path.join(proc, pid, 'cmdline'), `${argv.join('\0')}\0`);
  };
  const left = () => ({
    pid: existsSync(path.join(cluster, 'postmaster.pid')),
    lock: existsSync(path.join(run, '.s.PGSQL.5432.lock')),
    socket: existsSync(path.join(run, '.s.PGSQL.5432')),
  });

  it('removes the pid file and the socket lock of a PostgreSQL that no longer runs', async () => {
    await clearStalePostmaster(cluster, run, logger, proc);
    expect(left()).toEqual({ pid: false, lock: false, socket: true });
    expect(lines.some((l) => l.includes(PID))).toBe(true);
  });

  it('removes them when the PID now belongs to another process (the server itself)', async () => {
    processWith(PID, ['node', '/app/server/dist/main.js']);
    await clearStalePostmaster(cluster, run, logger, proc);
    expect(left()).toEqual({ pid: false, lock: false, socket: true });
  });

  it('leaves them while the PID is a live PostgreSQL', async () => {
    processWith(PID, ['/opt/postgres/bin/postgres', '-D', cluster]);
    await clearStalePostmaster(cluster, run, logger, proc);
    expect(left()).toEqual({ pid: true, lock: true, socket: true });
    expect(lines).toEqual([]);
  });

  it('leaves them where there is no /proc (not Linux)', async () => {
    await clearStalePostmaster(cluster, run, logger, path.join(root, 'no-proc'));
    expect(left()).toEqual({ pid: true, lock: true, socket: true });
  });

  it('does nothing without a pid file', async () => {
    rmSync(path.join(cluster, 'postmaster.pid'));
    await clearStalePostmaster(cluster, run, logger, proc);
    expect(left()).toEqual({ pid: false, lock: true, socket: true });
    expect(lines).toEqual([]);
  });

  it('runs on start, before PostgreSQL is spawned', async () => {
    mkdirSync(path.join(cluster, 'base'), { recursive: true });
    writeFileSync(path.join(cluster, 'PG_VERSION'), '18\n');
    let atSpawn: ReturnType<typeof left> | undefined;
    const embedded = await startEmbeddedPostgres({
      dataDir,
      postgresDir,
      logger,
      lease: { settleMs: 0 },
      procDir: proc,
      spawnPostgres: () => {
        atSpawn = left();
        return fakePostgres('setInterval(() => {}, 1000)')();
      },
      probe: async () => undefined,
    });
    await embedded.stop();
    expect(atSpawn).toEqual({ pid: false, lock: false, socket: true });
  });
});

describe('liveLease', () => {
  const write = (lease: object): void =>
    writeFileSync(path.join(dataDir, 'server.lease'), JSON.stringify(lease));
  beforeEach(() => mkdirSync(dataDir, { recursive: true }));

  it('reports a lease renewed within the TTL, by another host or this one', async () => {
    for (const host of ['other', os.hostname()]) {
      write({ instance: 'i', host, renewedAt: 1_000_000 });
      await expect(liveLease(dataDir, { now: 1_000_000 + 29_999 })).resolves.toEqual({
        host,
        renewedAt: 1_000_000,
      });
    }
  });

  it('reports none when the lease is stale, missing or malformed', async () => {
    await expect(liveLease(dataDir)).resolves.toBeNull();
    write({ instance: 'i', host: 'other', renewedAt: 1_000_000 });
    await expect(liveLease(dataDir, { now: 1_000_000 + 30_000 })).resolves.toBeNull();
    write({ host: 'other' });
    await expect(liveLease(dataDir, { now: 1_000_000 })).resolves.toBeNull();
  });
});
