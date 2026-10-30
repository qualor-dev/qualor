import { eq, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { instanceSettings } from '../db/schema';
import type { VulndbSettings } from './settings';
import type { DatasetRow } from './store';

export const VULNDB_STATE_KEY = 'vulndb_state';
/** The queue of the update job; a `jobs` row on it with status `running` is an update in progress. */
export const VULNDB_UPDATE_QUEUE = 'vulndb.update';
/** A dataset built more than this long ago is stale. */
export const STALE_AFTER_MS = 3 * 24 * 60 * 60 * 1000;

export interface VulndbState {
  currentDatasetId: string | null;
  lastCheckAt: string | null;
  nextCheckAt: string | null;
  lastError: { code: string; message: string } | null;
  lastRecheck: {
    at: string;
    projects: number;
    packages: number;
    unchecked: number;
    durationMs: number;
  } | null;
  staleNotifiedDigest: string | null;
}

const int = z.number().int().nonnegative();
/** Each key reads on its own: a damaged one is its empty value, the others survive. */
const onRead = z.object({
  currentDatasetId: z.string().nullable().catch(null),
  lastCheckAt: z.string().nullable().catch(null),
  nextCheckAt: z.string().nullable().catch(null),
  lastError: z.object({ code: z.string(), message: z.string() }).nullable().catch(null),
  lastRecheck: z
    .object({
      at: z.string(),
      projects: int,
      packages: int,
      unchecked: int,
      durationMs: int,
    })
    .nullable()
    .catch(null),
  staleNotifiedDigest: z.string().nullable().catch(null),
});

export async function readVulndbState(db: Executor): Promise<VulndbState> {
  const [row] = await db
    .select({ value: instanceSettings.value })
    .from(instanceSettings)
    .where(eq(instanceSettings.key, VULNDB_STATE_KEY));
  const value =
    typeof row?.value === 'object' && row.value !== null && !Array.isArray(row.value)
      ? row.value
      : {};
  return onRead.parse(value);
}

/** Read-modify-write of the state row under LOCKS.vulndbState; returns the new state. */
export async function updateVulndbState(
  db: Db,
  fn: (state: VulndbState) => VulndbState,
): Promise<VulndbState> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulndbState})`);
    const next = fn(await readVulndbState(tx));
    await tx
      .insert(instanceSettings)
      .values({ key: VULNDB_STATE_KEY, value: next })
      .onConflictDoUpdate({
        target: instanceSettings.key,
        set: { value: next, updatedAt: sql`now()` },
      });
    return next;
  });
}

export type VulndbStatus = 'off' | 'no_data' | 'updating' | 'up_to_date' | 'stale' | 'failed';

/**
 * What the settings tab shows. Order: off, updating, failed with no dataset, no data, stale,
 * failed, up to date (ruling R7).
 */
export function vulndbStatus(
  settings: Pick<VulndbSettings, 'enabled'>,
  state: Pick<VulndbState, 'lastError'>,
  current: Pick<DatasetRow, 'builtAt'> | null,
  running: boolean,
  now: Date = new Date(),
): VulndbStatus {
  if (!settings.enabled) return 'off';
  if (running) return 'updating';
  if (current === null) return state.lastError !== null ? 'failed' : 'no_data';
  // A dataset without a build time has unknown age: stale.
  if (current.builtAt === null || now.getTime() - current.builtAt.getTime() > STALE_AFTER_MS) {
    return 'stale';
  }
  if (state.lastError !== null) return 'failed';
  return 'up_to_date';
}
