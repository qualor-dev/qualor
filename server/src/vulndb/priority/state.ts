import { eq, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Db, Executor } from '../../db/client';
import { LOCKS } from '../../db/locks';
import { instanceSettings } from '../../db/schema';
import type { PriorityDataset } from '../settings';
import { STALE_AFTER_MS, type VulndbStatus } from '../state';

export const PRIORITY_STATE_KEY = 'vulndb_priority_state';

export interface PriorityDatasetState {
  source: 'official' | 'mirror' | 'upload' | null;
  /** EPSS: the model date of the file; null when the file carries none. */
  dataDate: string | null;
  storedAt: string | null;
  /** The last time the source confirmed or replaced the data. */
  refreshedAt: string | null;
  lastCheckAt: string | null;
  sizeBytes: number | null;
  count: number | null;
  digest: string | null;
  etag: string | null;
  lastModified: string | null;
  url: string | null;
  lastError: { code: string; message: string } | null;
  staleNotifiedDigest: string | null;
}

export interface PriorityState {
  kev: PriorityDatasetState;
  epss: PriorityDatasetState;
}

const str = z.string().nullable().catch(null);
const datasetShape = z.object({
  source: z.enum(['official', 'mirror', 'upload']).nullable().catch(null),
  dataDate: str,
  storedAt: str,
  refreshedAt: str,
  lastCheckAt: str,
  sizeBytes: z.number().int().nonnegative().nullable().catch(null),
  count: z.number().int().nonnegative().nullable().catch(null),
  digest: str,
  etag: str,
  lastModified: str,
  url: str,
  lastError: z.object({ code: z.string(), message: z.string() }).nullable().catch(null),
  staleNotifiedDigest: str,
});
const datasetOnRead = datasetShape.catch(() => datasetShape.parse({}));

/** Each key reads on its own: a damaged one is its empty value, the others survive. */
const onRead = z.object({ kev: datasetOnRead, epss: datasetOnRead });

export async function readPriorityState(db: Executor): Promise<PriorityState> {
  const [row] = await db
    .select({ value: instanceSettings.value })
    .from(instanceSettings)
    .where(eq(instanceSettings.key, PRIORITY_STATE_KEY));
  const value =
    typeof row?.value === 'object' && row.value !== null && !Array.isArray(row.value)
      ? row.value
      : {};
  return onRead.parse(value);
}

/** Read-modify-write of one dataset's state under LOCKS.vulndbPriorityState; returns it. */
export async function updatePriorityState(
  db: Db,
  dataset: PriorityDataset,
  change: (s: PriorityDatasetState) => PriorityDatasetState,
): Promise<PriorityDatasetState> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulndbPriorityState})`);
    return updatePriorityStateLocked(tx, dataset, change);
  });
}

/** {@link updatePriorityState} for a caller that already holds the lock in `tx`. */
export async function updatePriorityStateLocked(
  tx: Executor,
  dataset: PriorityDataset,
  change: (s: PriorityDatasetState) => PriorityDatasetState,
): Promise<PriorityDatasetState> {
  const state = await readPriorityState(tx);
  const next = change(state[dataset]);
  const value: PriorityState = { ...state, [dataset]: next };
  await tx
    .insert(instanceSettings)
    .values({ key: PRIORITY_STATE_KEY, value })
    .onConflictDoUpdate({
      target: instanceSettings.key,
      set: { value, updatedAt: sql`now()` },
    });
  return next;
}

/**
 * KEV is stale when its last confirmation is older than STALE_AFTER_MS. EPSS counts from the
 * earlier of its model date and the time it was stored, so a future model date cannot hide an old
 * file. An empty state, or one whose timestamps do not parse, is never stale.
 */
export function isPriorityStale(
  dataset: PriorityDataset,
  s: PriorityDatasetState,
  now: Date,
): boolean {
  if (s.storedAt === null) return false;
  const stored = Date.parse(s.storedAt);
  let since: number;
  if (dataset === 'kev') {
    since = s.refreshedAt === null ? Number.NaN : Date.parse(s.refreshedAt);
  } else {
    const date = s.dataDate === null ? stored : Date.parse(s.dataDate);
    since = Math.min(date, stored);
  }
  if (Number.isNaN(since)) return false;
  return now.getTime() - since > STALE_AFTER_MS;
}

/** The same precedence as vulndbStatus: off, updating, failed with no data, no data, stale, failed. */
export function priorityStatus(
  dataset: PriorityDataset,
  s: PriorityDatasetState,
  opts: { enabled: boolean; running: boolean; now: Date },
): VulndbStatus {
  if (!opts.enabled) return 'off';
  if (opts.running) return 'updating';
  const failing = s.lastError !== null;
  if (s.storedAt === null) return failing ? 'failed' : 'no_data';
  if (isPriorityStale(dataset, s, opts.now)) return 'stale';
  return failing ? 'failed' : 'up_to_date';
}
