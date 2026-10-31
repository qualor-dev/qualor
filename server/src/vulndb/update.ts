import { sql } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import type { Config } from '../config';
import { decryptSecret, encryptionKey } from '../crypto/secrets';
import type { Db } from '../db/client';
import { uuidv7 } from '../db/ids';
import { LOCKS } from '../db/locks';
import { notifyIfVulndbStale } from '../mail/alerts/vulndb-stale';
import type { MailDeps } from '../mail/outbox';
import type { JobHandlers } from '../queue/worker';
import {
  DOWNLOAD_MAX_BYTES,
  fetchLayerDescriptor as realFetchLayerDescriptor,
  isOciProblem,
  openBlob as realOpenBlob,
  type OciAuth,
} from './oci';
import { enqueueRecheck as realEnqueueRecheck } from './recheck-queue';
import {
  OFFICIAL_REPOSITORY,
  readVulndbSettings,
  VULNDB_PASSWORD_AAD,
  type VulndbSettings,
} from './settings';
import { readVulndbState, updateVulndbState, VULNDB_UPDATE_QUEUE, type VulndbState } from './state';
import { currentDataset, makeDatasetCurrent, pruneDatasets, storeDataset } from './store';

/** The first check after a start: a start never waits a whole interval for its first data. */
export const VULNDB_BOOT_DELAY_SECONDS = 60;
/** The `vulndb` worker (main.ts): one job at a time, and a download may take 15 min. */
export const VULNDB_WORKER_CONCURRENCY = 1;
export const VULNDB_LEASE_MS = 30 * 60_000;

type LastError = NonNullable<VulndbState['lastError']>;

export interface VulndbUpdateDeps extends MailDeps {
  db: Db;
  config: MailDeps['config'] & { vulndb: Pick<Config['vulndb'], 'internalHosts'> };
  /** Tests substitute the registry client. */
  fetchLayerDescriptor?: typeof realFetchLayerDescriptor;
  openBlob?: typeof realOpenBlob;
  /** Tests substitute the re-check queue. */
  enqueueRecheck?: typeof realEnqueueRecheck;
  now?: () => Date;
  logger?: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
  /** The server is stopping (main.ts): a download is cut, and the run ends without a verdict. */
  shutdown?: AbortSignal;
}

type ScheduleMode =
  /** Insert a run in `delaySeconds` unless one is queued (`alsoRunning`: or running). */
  | { kind: 'ensure'; delaySeconds: number; alsoRunning: boolean }
  /** Boot: a queued run due later than `delaySeconds` moves up to it; none queued: insert. */
  | { kind: 'boot'; delaySeconds: number }
  /** Update now: a queued run moves to now; while one runs (and none is queued) nothing is added. */
  | { kind: 'now' };

/**
 * Every `vulndb.update` job shares one concurrency key, so two presses of Update now, a scheduled
 * run during a manual one and two replicas leave one queued job and at most one running. Under
 * LOCKS.vulndbSchedule. True when a job was inserted or moved.
 */
async function schedule(db: Db, mode: ScheduleMode): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulndbSchedule})`);
    const delay = mode.kind === 'now' ? 0 : mode.delaySeconds;
    const queued = await tx.execute<{ id: string }>(
      sql`SELECT id FROM jobs WHERE queue = ${VULNDB_UPDATE_QUEUE} AND status = 'queued' LIMIT 1`,
    );
    const queuedId = queued.rows[0]?.id;
    if (queuedId !== undefined) {
      if (mode.kind === 'ensure') return false;
      await tx.execute(sql`
        UPDATE jobs SET run_at = least(run_at, now() + make_interval(secs => ${delay})),
                        updated_at = now()
         WHERE id = ${queuedId}`);
      return true;
    }
    if (mode.kind === 'now' || (mode.kind === 'ensure' && mode.alsoRunning)) {
      const running = await tx.execute(
        sql`SELECT 1 FROM jobs WHERE queue = ${VULNDB_UPDATE_QUEUE} AND status = 'running' LIMIT 1`,
      );
      if (running.rows.length > 0) return false;
    }
    await tx.execute(sql`
      INSERT INTO jobs (id, queue, concurrency_key, payload, run_at)
      VALUES (${uuidv7()}, ${VULNDB_UPDATE_QUEUE}, ${VULNDB_UPDATE_QUEUE}, '{}'::jsonb,
              now() + make_interval(secs => ${delay}))`);
    return true;
  });
}

const intervalSeconds = async (db: Db): Promise<number> =>
  (await readVulndbSettings(db)).intervalHours * 3600;

/** At boot: a check a minute after a start; one run across replicas. */
export async function scheduleVulndbAtBoot(db: Db): Promise<void> {
  await schedule(db, { kind: 'boot', delaySeconds: VULNDB_BOOT_DELAY_SECONDS });
}

/** After every reap: a run lost with its worker is replaced, one interval later. */
export async function ensureVulndbScheduled(db: Db): Promise<boolean> {
  return schedule(db, {
    kind: 'ensure',
    delaySeconds: await intervalSeconds(db),
    alsoRunning: true,
  });
}

/**
 * Update now (POST update, and a PUT that turns monitoring on or changes the source): the queued
 * run moves to now, or one is inserted. While an update runs, nothing is added.
 */
export function requestVulndbUpdateNow(db: Db): Promise<boolean> {
  return schedule(db, { kind: 'now' });
}

/**
 * A new check interval (PUT): the waiting run moves to the last check plus the new interval, or to
 * now when that time has passed, and `nextCheckAt` follows. Before a first check the waiting run
 * stays where it is (a minute after the start); a running check schedules the next one with the
 * new interval itself. Under LOCKS.vulndbSchedule.
 */
export async function rescheduleVulndbUpdate(db: Db): Promise<void> {
  const { lastCheckAt } = await readVulndbState(db);
  if (lastCheckAt === null) return;
  const hours = (await readVulndbSettings(db)).intervalHours;
  const runAt = await db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulndbSchedule})`);
    const moved = await tx.execute<{ run_at: string | Date }>(sql`
      UPDATE jobs
         SET run_at = greatest(now(), ${lastCheckAt}::timestamptz + make_interval(hours => ${hours})),
             updated_at = now()
       WHERE queue = ${VULNDB_UPDATE_QUEUE} AND status = 'queued'
      RETURNING run_at`);
    return moved.rows[0]?.run_at ?? null;
  });
  if (runAt === null) return;
  const next = new Date(runAt).toISOString();
  await updateVulndbState(db, (state) => ({ ...state, nextCheckAt: next }));
}

const problemOf = (code: string, message: string): LastError => ({ code, message });

const errorClass = (err: unknown): string =>
  err instanceof Error ? err.constructor.name : typeof err;

/** The mirror's credentials; a stored password that no longer decrypts is an AUTH problem. */
function sourceOf(
  settings: VulndbSettings,
  secretKey: string,
): { repository: string; auth: OciAuth } | LastError {
  const source = settings.source;
  if (source.kind !== 'mirror') return { repository: OFFICIAL_REPOSITORY, auth: {} };
  const auth: OciAuth = {};
  if (source.username !== null) auth.username = source.username;
  if (source.passwordEnc !== null) {
    const password = decryptSecret(
      encryptionKey(secretKey),
      source.passwordEnc,
      VULNDB_PASSWORD_AAD,
    );
    if (password === null) {
      return problemOf(
        'AUTH',
        'The stored mirror password cannot be read. Enter the password again in the mirror settings',
      );
    }
    auth.password = password;
  }
  return { repository: source.repository, auth };
}

/** One check: null when the source is current or its newest database is now current. */
async function checkSource(
  deps: VulndbUpdateDeps,
  settings: VulndbSettings,
): Promise<LastError | null> {
  const resolved = sourceOf(settings, deps.config.secretKey);
  if ('code' in resolved) return resolved;
  const { repository, auth } = resolved;
  const fetchDescriptor = deps.fetchLayerDescriptor ?? realFetchLayerDescriptor;
  const open = deps.openBlob ?? realOpenBlob;
  const opts = {
    internalHosts: deps.config.vulndb.internalHosts,
    ...(deps.shutdown ? { signal: deps.shutdown } : {}),
  };

  const descriptor = await fetchDescriptor(repository, auth, opts);
  if (isOciProblem(descriptor)) return problemOf(descriptor.code, descriptor.message);

  const before = await currentDataset(deps.db, await readVulndbState(deps.db));
  if (before !== null && before.digest === descriptor.digest) return null;

  const chunks = await open(repository, descriptor.digest, auth, opts);
  if (isOciProblem(chunks)) return problemOf(chunks.code, chunks.message);

  const stored = await storeDataset(deps.db, {
    kind: 'trivy',
    source: settings.source.kind === 'mirror' ? 'mirror' : 'official',
    chunks,
    expectedDigest: descriptor.digest,
    maxBytes: DOWNLOAD_MAX_BYTES,
  });
  if ('problem' in stored) return problemOf(stored.problem.code, stored.problem.message);
  if (!(await makeDatasetCurrent(deps.db, stored.dataset.id))) {
    return problemOf(
      'STORE_FAILED',
      'The downloaded database was removed before it could be used. The next check tries again',
    );
  }
  await (deps.enqueueRecheck ?? realEnqueueRecheck)(deps.db, { all: true });
  // After the re-check is queued, and never the run's problem: an old dataset left now goes with
  // the next new one.
  try {
    await pruneDatasets(deps.db);
  } catch (err) {
    deps.logger?.warn(
      { component: 'vulndb', errorClass: errorClass(err) },
      'old vulnerability datasets were not pruned',
    );
  }
  deps.logger?.info(
    { component: 'vulndb', sizeBytes: stored.dataset.sizeBytes },
    'vulnerability database updated',
  );
  return null;
}

/**
 * One run of the `vulndb.update` job. Never throws: a problem becomes `lastError` and the current
 * dataset stays. Switched off: only the next run is scheduled. Source `upload`: only staleness is
 * checked. Always ends by scheduling the next run.
 *
 * A stop of the server (`shutdown`) cuts the download: the run ends at once, writes neither the
 * problem the cut caused nor the check times, and the next run is due in
 * {@link VULNDB_BOOT_DELAY_SECONDS}, for whichever server is up then.
 */
export async function runVulndbUpdate(deps: VulndbUpdateDeps): Promise<void> {
  const now = deps.now ?? (() => new Date());
  const stopping = (): boolean => deps.shutdown?.aborted === true;
  let stopped = false;
  try {
    if (stopping()) {
      stopped = true;
      return;
    }
    const settings = await readVulndbSettings(deps.db);
    if (!settings.enabled) return;
    {
      // undefined: an uploaded file has no source to check, so the last error stays.
      let error: LastError | null | undefined;
      try {
        error = settings.source.kind === 'upload' ? undefined : await checkSource(deps, settings);
      } catch (err) {
        // Neither the registry's answer nor a classified storage problem: log it, show a fixed text.
        deps.logger?.warn(
          { component: 'vulndb', errorClass: errorClass(err) },
          'vulnerability database update failed',
        );
        error = problemOf('UPDATE_FAILED', 'The update failed. See the server log');
      }
      // The stop cut the check: what it ran into says nothing about the source.
      if (stopping() && error !== undefined && error !== null) {
        stopped = true;
        deps.logger?.info(
          { component: 'vulndb' },
          'vulnerability database update stopped: the server is stopping',
        );
        return;
      }
      const checkedAt = now();
      await updateVulndbState(deps.db, (state) => ({
        ...state,
        lastCheckAt: checkedAt.toISOString(),
        nextCheckAt: new Date(
          checkedAt.getTime() + settings.intervalHours * 3_600_000,
        ).toISOString(),
        lastError: error === undefined ? state.lastError : error,
      }));
    }
    try {
      await notifyIfVulndbStale({ ...deps, now });
    } catch (err) {
      deps.logger?.warn(
        { component: 'vulndb', errorClass: errorClass(err) },
        'vulnerability database stale mail failed',
      );
    }
  } catch (err) {
    deps.logger?.warn(
      { component: 'vulndb', errorClass: errorClass(err) },
      'vulnerability database update run failed',
    );
  } finally {
    try {
      await schedule(
        deps.db,
        stopped
          ? { kind: 'boot', delaySeconds: VULNDB_BOOT_DELAY_SECONDS }
          : { kind: 'ensure', delaySeconds: await intervalSeconds(deps.db), alsoRunning: false },
      );
    } catch (err) {
      // Not retried: afterReap's ensureVulndbScheduled re-creates the run.
      deps.logger?.warn(
        { component: 'vulndb', errorClass: errorClass(err) },
        'vulnerability database next run not scheduled',
      );
    }
  }
}

/**
 * The `vulndb` worker's handler for `vulndb.update` (main.ts). The same worker runs
 * `vulnerabilities.recheck` (vulnerabilities/recheck.ts `recheckHandlers`).
 */
export function vulndbUpdateHandlers(deps: VulndbUpdateDeps): JobHandlers {
  return {
    [VULNDB_UPDATE_QUEUE]: () => runVulndbUpdate(deps),
  };
}
