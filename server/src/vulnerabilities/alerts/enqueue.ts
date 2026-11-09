import { sql } from 'drizzle-orm';
import type { Executor } from '../../db/client';
import { LOCKS } from '../../db/locks';
import { enqueue } from '../../queue/queue';

/** The alert job's queue, and its concurrency key: a run and a queued follow-up never overlap. */
export const ALERTS_QUEUE = 'vulnerabilities.alerts';

/**
 * Asks for a run of the alert job unless one is queued; true when this call queued it. A running
 * job does not count: the new one covers what the running one has already passed.
 *
 * Under LOCKS.vulnerabilityAlertsSchedule, with a queued job's row locked until the caller's
 * transaction commits: the worker cannot claim it (SKIP LOCKED) before the rows this request is
 * about are committed, and a run that started too early cannot miss them.
 *
 * A leaf module, so the re-check and the KEV update can ask for a run without importing the job.
 */
export async function enqueueVulnerabilityAlerts(db: Executor): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityAlertsSchedule})`);
    const queued = await tx.execute(sql`
      SELECT 1 FROM jobs WHERE queue = ${ALERTS_QUEUE} AND status = 'queued' LIMIT 1 FOR UPDATE`);
    if (queued.rows.length > 0) return false;
    await enqueue(tx, { queue: ALERTS_QUEUE, concurrencyKey: ALERTS_QUEUE, payload: {} });
    return true;
  });
}
