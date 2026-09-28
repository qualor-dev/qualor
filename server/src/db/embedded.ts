import { spawn, type ChildProcess } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { chmod, cp, mkdir, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import pg from 'pg';
import type { EmbeddedPostgresDirs } from '../config';

/**
 * The embedded PostgreSQL: when DATABASE_URL is not set, the
 * server runs the PostgreSQL its image carries, on a Unix socket only, with the cluster in
 * QUALOR_DATA_DIR.
 */

/** §5 step 4: how often and how long to try the first connection. */
const READY_POLL_MS = 250;
const READY_TIMEOUT_MS = 60_000;
/** §5: a fast shutdown gets this long before SIGKILL. */
const STOP_TIMEOUT_MS = 30_000;
/** §5 step 4: the child's last lines that go into a start failure. */
const TAIL_LINES = 20;
/**
 * §5 step 1: the data directory's lease. PostgreSQL's own postmaster.pid cannot tell a live
 * server in another container (other PID and IPC namespaces) from a stale file, so two containers
 * on one volume would both start and corrupt the cluster. The lease is renewed every 10 s and
 * taken over after 30 s without renewal, or at once by the same host (a restarted container).
 */
const LEASE_TTL_MS = 30_000;
const LEASE_RENEW_MS = 10_000;
/** Two servers starting at the same moment: the later write wins, the other one sees it here. */
const LEASE_SETTLE_MS = 1_000;

export class EmbeddedPostgresError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EmbeddedPostgresError';
  }
}

export interface EmbeddedLogger {
  info(obj: object, msg: string): void;
  warn(obj: object, msg: string): void;
}

export interface EmbeddedPostgres {
  /** postgresql://qualor@<socket dir>/qualor */
  url: string;
  /** Resolves with the exit code (or signal) when PostgreSQL exits, for whatever reason. */
  exited: Promise<string>;
  /** Fast shutdown (SIGINT), then SIGKILL after the timeout. Safe to call twice. */
  stop(): Promise<void>;
}

export interface LeaseOptions {
  ttlMs?: number;
  renewMs?: number;
  settleMs?: number;
  hostname?: string;
  /** Called when another server took the lease over while this one runs. */
  onLost?: () => void;
}

interface Lease {
  instance: string;
  host: string;
  renewedAt: number;
}

export interface EmbeddedOptions extends EmbeddedPostgresDirs {
  logger: EmbeddedLogger;
  lease?: LeaseOptions;
  /** Tests replace how PostgreSQL is started and probed. */
  spawnPostgres?: (bin: string, args: string[]) => ChildProcess;
  probe?: (url: string) => Promise<void>;
  readyTimeoutMs?: number;
  stopTimeoutMs?: number;
}

const exists = async (p: string): Promise<boolean> =>
  stat(p).then(
    () => true,
    () => false,
  );

/** The major version of "18.6" or "18" (a PG_VERSION file holds only the major). */
const major = (version: string): string => version.trim().split('.')[0] ?? '';

/**
 * §5 step 2: 0700 directories and 0600 files, or PostgreSQL refuses the data directory. Applied
 * on every start, not only to a fresh copy: a volume restored, copied or re-owned since (a
 * recursive fsGroup change leaves it group-writable) would otherwise stop the start.
 */
async function restrictModes(dir: string): Promise<void> {
  await chmod(dir, 0o700);
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) await restrictModes(full);
    else if (entry.isFile()) await chmod(full, 0o600);
  }
}

async function readLease(file: string): Promise<Lease | null> {
  try {
    const value = JSON.parse(await readFile(file, 'utf8')) as Partial<Lease>;
    if (
      typeof value.instance === 'string' &&
      typeof value.host === 'string' &&
      typeof value.renewedAt === 'number'
    ) {
      return value as Lease;
    }
  } catch {
    // Missing or unreadable: no lease.
  }
  return null;
}

async function writeLease(file: string, lease: Lease): Promise<void> {
  const tmp = `${file}.${lease.instance}.tmp`;
  await writeFile(tmp, JSON.stringify(lease));
  await rename(tmp, file);
}

/**
 * Takes the data directory's lease (§5 step 1) and keeps renewing it. Returns its release.
 * Refuses a lease another host renewed within the TTL.
 */
export async function acquireLease(
  dataDir: string,
  options: LeaseOptions = {},
): Promise<() => Promise<void>> {
  const file = path.join(dataDir, 'server.lease');
  const ttl = options.ttlMs ?? LEASE_TTL_MS;
  const host = options.hostname ?? os.hostname();
  const mine: Lease = { instance: randomUUID(), host, renewedAt: Date.now() };
  const held = await readLease(file);
  if (held && held.host !== host && Date.now() - held.renewedAt < ttl) {
    throw new EmbeddedPostgresError(
      `another Qualor server (host ${held.host}) is using ${dataDir}: one server per data directory. If it has stopped, start again in ${Math.ceil(ttl / 1000)} s`,
    );
  }
  await writeLease(file, mine);
  await new Promise((resolve) => setTimeout(resolve, options.settleMs ?? LEASE_SETTLE_MS));
  const after = await readLease(file);
  if (after?.instance !== mine.instance) {
    throw new EmbeddedPostgresError(
      `another Qualor server (host ${after?.host ?? 'unknown'}) took ${dataDir} at the same moment: one server per data directory`,
    );
  }
  let released = false;
  const timer = setInterval(() => {
    void (async () => {
      const current = await readLease(file);
      if (released) return;
      if (current?.instance !== mine.instance) {
        clearInterval(timer);
        options.onLost?.();
        return;
      }
      await writeLease(file, { ...mine, renewedAt: Date.now() }).catch(() => undefined);
    })();
  }, options.renewMs ?? LEASE_RENEW_MS);
  timer.unref();
  return async () => {
    if (released) return;
    released = true;
    clearInterval(timer);
    if ((await readLease(file))?.instance === mine.instance) await rm(file, { force: true });
  };
}

/** The socket URL; the directory is percent-encoded into the host, as pg's parser expects. */
export function socketUrl(runDir: string): string {
  return `postgresql://qualor@${encodeURIComponent(runDir)}/qualor`;
}

/**
 * §5 steps 1 and 2: makes sure `<dataDir>/postgres` holds a cluster this image can run, copying
 * the template into an empty directory. Returns the cluster directory.
 */
export async function prepareCluster(dirs: EmbeddedPostgresDirs): Promise<string> {
  const bin = path.join(dirs.postgresDir, 'bin', 'postgres');
  if (!(await exists(bin))) {
    throw new EmbeddedPostgresError(
      `DATABASE_URL is not set and no embedded PostgreSQL was found in ${dirs.postgresDir}; set DATABASE_URL`,
    );
  }
  const imageVersion = (await readFile(path.join(dirs.postgresDir, 'VERSION'), 'utf8')).trim();
  const cluster = path.join(dirs.dataDir, 'postgres');
  const run = path.join(dirs.dataDir, 'run');
  await mkdir(dirs.dataDir, { recursive: true });
  await mkdir(run, { recursive: true });
  await chmod(run, 0o700);

  const versionFile = path.join(cluster, 'PG_VERSION');
  if (await exists(versionFile)) {
    const clusterMajor = major(await readFile(versionFile, 'utf8'));
    if (clusterMajor !== major(imageVersion)) {
      throw new EmbeddedPostgresError(
        `the data directory holds a PostgreSQL ${clusterMajor} cluster and this image carries PostgreSQL ${imageVersion}; see the upgrade notes`,
      );
    }
    await restrictModes(cluster);
    return cluster;
  }
  const entries = (await exists(cluster)) ? await readdir(cluster) : [];
  if (entries.length > 0) {
    throw new EmbeddedPostgresError(
      `${cluster} is not empty and holds no PostgreSQL cluster (no PG_VERSION); it is never overwritten`,
    );
  }
  await cp(path.join(dirs.postgresDir, 'template'), cluster, { recursive: true });
  await restrictModes(cluster);
  return cluster;
}

async function connectOnce(url: string): Promise<void> {
  const client = new pg.Client({ connectionString: url, connectionTimeoutMillis: 2_000 });
  try {
    await client.connect();
    await client.query('SELECT 1');
  } finally {
    await client.end().catch(() => undefined);
  }
}

/** Starts the embedded PostgreSQL and waits until it accepts connections (§5 steps 3 and 4). */
export async function startEmbeddedPostgres(options: EmbeddedOptions): Promise<EmbeddedPostgres> {
  await mkdir(options.dataDir, { recursive: true });
  const release = await acquireLease(options.dataDir, {
    ...options.lease,
    onLost: () => {
      options.logger.warn({ component: 'postgres' }, 'another server took over the data directory');
      options.lease?.onLost?.();
    },
  });
  try {
    return await startCluster(options, release);
  } catch (err) {
    await release();
    throw err;
  }
}

async function startCluster(
  options: EmbeddedOptions,
  release: () => Promise<void>,
): Promise<EmbeddedPostgres> {
  const cluster = await prepareCluster(options);
  const run = path.join(options.dataDir, 'run');
  const bin = path.join(options.postgresDir, 'bin', 'postgres');
  const args = [
    '-D',
    cluster,
    '-c',
    'listen_addresses=',
    '-c',
    `unix_socket_directories=${run}`,
    '-c',
    'unix_socket_permissions=0700',
  ];
  const spawnPostgres =
    options.spawnPostgres ??
    ((file: string, argv: string[]) => spawn(file, argv, { stdio: ['ignore', 'pipe', 'pipe'] }));
  const child = spawnPostgres(bin, args);

  const tail: string[] = [];
  const onLine = (line: string): void => {
    if (line.trim() === '') return;
    tail.push(line);
    if (tail.length > TAIL_LINES) tail.shift();
    options.logger.info({ component: 'postgres' }, line);
  };
  for (const stream of [child.stdout, child.stderr]) {
    let pending = '';
    stream?.setEncoding('utf8');
    stream?.on('data', (chunk: string) => {
      pending += chunk;
      const lines = pending.split('\n');
      pending = lines.pop() ?? '';
      lines.forEach(onLine);
    });
    stream?.on('end', () => {
      if (pending) onLine(pending);
      pending = '';
    });
  }

  let hasExited = false;
  const exited = new Promise<string>((resolve) => {
    child.once('error', (err) => {
      hasExited = true;
      resolve(`failed to start (${(err as NodeJS.ErrnoException).code ?? err.name})`);
    });
    child.once('exit', (code, signal) => {
      hasExited = true;
      resolve(signal ? `signal ${signal}` : `code ${code}`);
    });
  });

  const stopTimeout = options.stopTimeoutMs ?? STOP_TIMEOUT_MS;
  let stopping: Promise<void> | undefined;
  const stop = (): Promise<void> => {
    stopping ??= (async () => {
      if (hasExited) {
        await release();
        return;
      }
      child.kill('SIGINT');
      const timer = new Promise<'timeout'>((resolve) => {
        setTimeout(() => resolve('timeout'), stopTimeout).unref();
      });
      if ((await Promise.race([exited, timer])) === 'timeout') {
        options.logger.warn(
          { component: 'postgres' },
          'PostgreSQL did not stop in time; killing it',
        );
        child.kill('SIGKILL');
        await exited;
      }
      await release();
    })();
    return stopping;
  };

  const url = socketUrl(run);
  const probe = options.probe ?? connectOnce;
  const deadline = Date.now() + (options.readyTimeoutMs ?? READY_TIMEOUT_MS);
  for (;;) {
    if (hasExited) {
      throw new EmbeddedPostgresError(
        `the embedded PostgreSQL exited before it was ready (${await exited}):\n${tail.join('\n')}`,
      );
    }
    try {
      await probe(url);
      break;
    } catch {
      // Not accepting connections yet.
    }
    if (Date.now() >= deadline) {
      await stop();
      throw new EmbeddedPostgresError(
        `the embedded PostgreSQL was not ready within ${Math.round((options.readyTimeoutMs ?? READY_TIMEOUT_MS) / 1000)} s:\n${tail.join('\n')}`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, READY_POLL_MS));
  }
  options.logger.info({ component: 'postgres' }, 'the embedded PostgreSQL is ready');
  return { url, exited, stop };
}
