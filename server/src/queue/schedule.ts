import { sql, type SQL } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { enqueue } from './queue';

/** `now()` plus `seconds`, on the database clock. */
export const after = (seconds: number): SQL => sql`now() + make_interval(secs => ${seconds})`;

/** Takes a schedule lock (`LOCKS.*`), which the caller's transaction holds to its end. */
export async function lockSchedule(tx: Executor, lock: number): Promise<void> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${lock})`);
}

/** The id of the queued job with this key, its row locked until the caller's transaction ends. */
export async function queuedJob(tx: Executor, queue: string, key: string): Promise<string | null> {
  const queued = await tx.execute<{ id: string }>(sql`
    SELECT id FROM jobs
     WHERE queue = ${queue} AND status = 'queued' AND concurrency_key = ${key}
     LIMIT 1 FOR UPDATE`);
  return queued.rows[0]?.id ?? null;
}

/** A self-rescheduling pass: the schedule lock that guards it, its queue, key and payload. */
export interface PassSchedule {
  lock: number;
  queue: string;
  key: string;
  payload: unknown;
}

/**
 * Queues the pass `delaySeconds` from now unless one is queued (a running pass does not count, so
 * it reschedules itself from its own `finally`); true when this call queued it.
 */
export async function queuePass(
  db: Executor,
  pass: PassSchedule,
  delaySeconds: number,
): Promise<boolean> {
  return db.transaction(async (tx) => {
    await lockSchedule(tx, pass.lock);
    if ((await queuedJob(tx, pass.queue, pass.key)) !== null) return false;
    await enqueue(tx, {
      queue: pass.queue,
      concurrencyKey: pass.key,
      payload: pass.payload,
      runAt: after(delaySeconds),
    });
    return true;
  });
}

/**
 * Moves the waiting pass to now, or queues one (behind a running pass, which the concurrency key
 * holds back until it ends) when none waits.
 */
export async function pullPassForward(db: Executor, pass: PassSchedule): Promise<void> {
  await db.transaction(async (tx) => {
    await lockSchedule(tx, pass.lock);
    const queued = await queuedJob(tx, pass.queue, pass.key);
    if (queued === null) {
      await enqueue(tx, { queue: pass.queue, concurrencyKey: pass.key, payload: pass.payload });
      return;
    }
    await tx.execute(sql`
      UPDATE jobs SET run_at = now(), updated_at = now()
       WHERE id = ${queued} AND run_at > now()`);
  });
}
