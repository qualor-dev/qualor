import { sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { instanceSettings } from '../db/schema';
import { instanceSetting } from '../settings';

/** The `instance_settings` row of the server defaults (issue #38). */
export const CLEANUP_SETTINGS_KEY = 'cleanup';
/** The most days a rule may wait; migration 0038's checks hold the same bound. */
export const CLEANUP_MAX_DAYS = 3650;
/** The most keep patterns of a project; migration 0038's check holds the same bound. */
export const MAX_KEEP_BRANCHES = 20;

/** The days of an active rule. */
export const cleanupDaysSchema = z.number().int().min(1).max(CLEANUP_MAX_DAYS);

/** The server defaults: the days after which each kind is deleted, null while the rule is off. */
export interface CleanupDefaults {
  branchesDays: number | null;
  mergeRequestsDays: number | null;
}

/** The rules in force for a project: the days of each, null while it is off. */
export type EffectiveCleanup = CleanupDefaults;

const cleanupDefaultsShape = {
  branchesDays: cleanupDaysSchema.nullable(),
  mergeRequestsDays: cleanupDaysSchema.nullable(),
};

/** The body of `PUT /system/cleanup` and its answer. */
export const cleanupDefaultsSchema = z.strictObject(cleanupDefaultsShape);

/** The stored row; a field a later version adds is ignored. */
const storedDefaultsSchema = z.object(cleanupDefaultsShape);

/**
 * The server defaults. Both are off while the row is absent, and when it does not match (an
 * operator's typo must never delete anything).
 */
export function readCleanupDefaults(db: Executor): Promise<CleanupDefaults> {
  return instanceSetting(db, CLEANUP_SETTINGS_KEY, storedDefaultsSchema, {
    branchesDays: null,
    mergeRequestsDays: null,
  });
}

/** Stores the server defaults. */
export async function writeCleanupDefaults(db: Executor, value: CleanupDefaults): Promise<void> {
  const stored = { branchesDays: value.branchesDays, mergeRequestsDays: value.mergeRequestsDays };
  await db
    .insert(instanceSettings)
    .values({ key: CLEANUP_SETTINGS_KEY, value: stored })
    .onConflictDoUpdate({
      target: instanceSettings.key,
      set: { value: stored, updatedAt: sql`now()` },
    });
}

/**
 * Takes the lock of the server defaults for the rest of the transaction `tx` and reads them: a
 * writer's `before`, so two saves never record the same change.
 */
export async function lockCleanupDefaults(tx: Executor): Promise<CleanupDefaults> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.cleanupSettings})`);
  return readCleanupDefaults(tx);
}

/** A project's own value: NULL inherits the server default, 0 is off, N is N days. */
function effectiveDays(own: number | null, serverDefault: number | null): number | null {
  if (own === null) return serverDefault;
  return own === 0 ? null : own;
}

/** The rules in force for `project` under the server defaults (null: off). */
export function effectiveCleanup(
  project: { cleanupBranchesDays: number | null; cleanupMergeRequestsDays: number | null },
  defaults: CleanupDefaults,
): EffectiveCleanup {
  return {
    branchesDays: effectiveDays(project.cleanupBranchesDays, defaults.branchesDays),
    mergeRequestsDays: effectiveDays(project.cleanupMergeRequestsDays, defaults.mergeRequestsDays),
  };
}
