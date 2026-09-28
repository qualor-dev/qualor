import { sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { uuidv7 } from '../db/ids';
import { LOCKS } from '../db/locks';

/** rbac-audit.md §15: `ctx.schedule` takes whole seconds from 10 s to a day. */
export const PLUGIN_SCHEDULE_MIN_SECONDS = 10;
export const PLUGIN_SCHEDULE_MAX_SECONDS = 86_400;

/**
 * rbac-audit.md §15: enqueues the queue's next run `delaySeconds` from now unless one is already
 * queued (the housekeeping pattern, data-model.md §7). The advisory lock makes this safe when
 * several replicas boot or finish a run at the same moment; the concurrency key (the queue name)
 * keeps two replicas from running it at once. A scheduled job has one attempt: a failed run is
 * not retried by the queue, the next scheduled run is its retry, so a queue never holds more than
 * one waiting job.
 */
export async function ensurePluginScheduled(
  db: Db,
  queue: string,
  delaySeconds: number,
): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.execute(
      sql`SELECT pg_advisory_xact_lock(${LOCKS.pluginSchedule}, hashtext(${queue}))`,
    );
    const existing = await tx.execute(
      sql`SELECT 1 FROM jobs WHERE queue = ${queue} AND status = 'queued' LIMIT 1`,
    );
    if (existing.rows.length > 0) return false;
    await tx.execute(sql`
      INSERT INTO jobs (id, queue, concurrency_key, payload, max_attempts, run_at)
      VALUES (${uuidv7()}, ${queue}, ${queue}, '{}'::jsonb, 1,
              now() + make_interval(secs => ${delaySeconds}))`);
    return true;
  });
}
