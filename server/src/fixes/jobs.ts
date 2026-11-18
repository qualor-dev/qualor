import { sql } from 'drizzle-orm';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { enqueue, enqueueMany } from '../queue/queue';
import {
  after,
  lockSchedule,
  pullPassForward,
  queuePass,
  type PassSchedule,
} from '../queue/schedule';

/** The queue of the fix MR jobs, on the SCM worker (R17). */
export const FIX_QUEUE = 'fixes';

export type FixJobPayload =
  | { kind: 'commit' | 'close'; fixId: string; generation: number; attempt: number }
  | { kind: 'sync'; organizationId: string };

/** spec §6.7: a pass runs every 15 minutes per organisation. */
export const FIX_SYNC_INTERVAL_SECONDS = 900;

/** The concurrency key of a fix's commit and close jobs: one at a time per fix. */
export const fixKey = (fixId: string): string => `fix:${fixId}`;
/** The concurrency key of an organisation's pass. */
export const fixSyncKey = (organizationId: string): string => `fix-sync:${organizationId}`;

const syncPass = (organizationId: string): PassSchedule => ({
  lock: LOCKS.fixSchedule,
  queue: FIX_QUEUE,
  key: fixSyncKey(organizationId),
  payload: { kind: 'sync', organizationId } satisfies FixJobPayload,
});

/**
 * Queues a commit or close job of one fix, `delaySeconds` from now. Under `LOCKS.fixSchedule`,
 * like the passes, so the caller's transaction commits the fix's rows before the worker sees it.
 */
export async function enqueueFixJob(
  db: Executor,
  payload: Extract<FixJobPayload, { kind: 'commit' | 'close' }>,
  delaySeconds = 0,
): Promise<void> {
  await db.transaction(async (tx) => {
    await lockSchedule(tx, LOCKS.fixSchedule);
    await enqueue(tx, {
      queue: FIX_QUEUE,
      concurrencyKey: fixKey(payload.fixId),
      payload,
      runAt: after(delaySeconds),
    });
  });
}

/**
 * Queues the organisation's next pass `delaySeconds` from now unless one is queued (a running
 * pass does not count, so it reschedules itself from its own `finally`); true when this call
 * queued it.
 */
export async function scheduleFixSync(
  db: Executor,
  organizationId: string,
  delaySeconds: number,
): Promise<boolean> {
  return queuePass(db, syncPass(organizationId), delaySeconds);
}

/** Moves the organisation's waiting pass to now, or queues one when none waits. */
export async function syncFixesNow(db: Executor, organizationId: string): Promise<void> {
  await pullPassForward(db, syncPass(organizationId));
}

/** R18: the organisations a pass runs for: those with an enabled project or an active fix. */
const PASS_ORGANIZATIONS = sql`
  SELECT p.organization_id FROM project_fix_settings s
    JOIN projects p ON p.id = s.project_id WHERE s.enabled
  UNION
  SELECT p.organization_id FROM dependency_fixes f
    JOIN projects p ON p.id = f.project_id
   WHERE f.state IN ('requested', 'preparing', 'committing', 'open')`;

/**
 * R18: whether the organisation still gets a pass (an enabled project or an active fix); a pass
 * that ends reschedules itself only then.
 */
export async function fixPassWanted(db: Executor, organizationId: string): Promise<boolean> {
  const found = await db.execute<{ wanted: boolean }>(sql`
    SELECT EXISTS (
      SELECT 1 FROM (${PASS_ORGANIZATIONS}) o WHERE o.organization_id = ${organizationId}
    ) AS wanted`);
  return found.rows[0]?.wanted === true;
}

/**
 * Boot and reaping (R18): one pass at now for each organisation with an enabled project or an
 * active fix that has none queued or running. The schedule lock makes replicas that boot together
 * queue one each; returns how many it queued.
 */
export async function ensureFixSyncScheduled(db: Db): Promise<number> {
  return db.transaction(async (tx) => {
    await lockSchedule(tx, LOCKS.fixSchedule);
    const missing = await tx.execute<{ organization_id: string }>(sql`
      SELECT o.organization_id FROM (${PASS_ORGANIZATIONS}) o
      WHERE NOT EXISTS (
        SELECT 1 FROM jobs j
         WHERE j.queue = ${FIX_QUEUE} AND j.status IN ('queued', 'running')
           AND j.concurrency_key = 'fix-sync:' || o.organization_id::text)`);
    const ids = await enqueueMany(
      tx,
      missing.rows.map((r) => ({
        queue: FIX_QUEUE,
        concurrencyKey: fixSyncKey(r.organization_id),
        payload: { kind: 'sync', organizationId: r.organization_id } satisfies FixJobPayload,
      })),
    );
    return ids.length;
  });
}
