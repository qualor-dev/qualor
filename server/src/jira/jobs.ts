import { sql } from 'drizzle-orm';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { enqueue, enqueueMany } from '../queue/queue';
import {
  after,
  lockSchedule,
  pullPassForward,
  queuedJob,
  queuePass,
  type PassSchedule,
} from '../queue/schedule';

/** The queue of both kinds of Jira job (a worker of its own, ruling R2). */
export const JIRA_QUEUE = 'jira';

export type JiraJobPayload = { kind: 'create' | 'sync'; organizationId: string };

/** spec §6.5: a pass runs every 15 minutes per organisation. */
export const JIRA_SYNC_INTERVAL_SECONDS = 900;

/**
 * Ruling R1: the two kinds do not share a concurrency key, so a create is never held up to 15
 * minutes behind the waiting pass (`claimJob` blocks a queued job behind any earlier queued job
 * of its key, whatever its `run_at`).
 */
export const jiraCreateKey = (organizationId: string): string => `jira-create:${organizationId}`;
export const jiraSyncKey = (organizationId: string): string => `jira-sync:${organizationId}`;

/**
 * Asks for a create run of the organisation `delaySeconds` from now, unless one is queued; true
 * when this call queued it. A queued one is held back to `delaySeconds` from now when it is due
 * sooner (a 429's `Retry-After` holds for every run). Under `LOCKS.jiraSchedule`, with a queued
 * job's row locked until the caller's transaction commits, as `enqueueVulnerabilityAlerts` does:
 * the worker cannot claim a job before the rows it is about are committed.
 */
export async function enqueueJiraCreate(
  db: Executor,
  organizationId: string,
  delaySeconds = 0,
): Promise<boolean> {
  return db.transaction(async (tx) => {
    await lockSchedule(tx, LOCKS.jiraSchedule);
    const queued = await queuedJob(tx, JIRA_QUEUE, jiraCreateKey(organizationId));
    if (queued !== null) {
      if (delaySeconds > 0) {
        await tx.execute(sql`
          UPDATE jobs SET run_at = ${after(delaySeconds)}, updated_at = now()
           WHERE id = ${queued} AND run_at < ${after(delaySeconds)}`);
      }
      return false;
    }
    const payload: JiraJobPayload = { kind: 'create', organizationId };
    await enqueue(tx, {
      queue: JIRA_QUEUE,
      concurrencyKey: jiraCreateKey(organizationId),
      payload,
      runAt: after(delaySeconds),
    });
    return true;
  });
}

const syncPass = (organizationId: string): PassSchedule => ({
  lock: LOCKS.jiraSchedule,
  queue: JIRA_QUEUE,
  key: jiraSyncKey(organizationId),
  payload: { kind: 'sync', organizationId } satisfies JiraJobPayload,
});

/**
 * Queues the organisation's next pass `delaySeconds` from now unless one is queued (ruling P1:
 * a running pass does not count, so it reschedules itself from its own `finally`); true when
 * this call queued it.
 */
export async function scheduleJiraSync(
  db: Executor,
  organizationId: string,
  delaySeconds: number,
): Promise<boolean> {
  return queuePass(db, syncPass(organizationId), delaySeconds);
}

/**
 * Moves the organisation's waiting pass to now, or queues one (behind a running pass, which the
 * concurrency key holds back until it ends) when none waits.
 */
export async function syncJiraNow(db: Executor, organizationId: string): Promise<void> {
  await pullPassForward(db, syncPass(organizationId));
}

/**
 * Boot and reaping: one pass at now for each connection that has none queued or running, so a
 * restart or a lost lease never leaves an organisation without its pass. The schedule lock makes
 * replicas that boot together queue one each; returns how many it queued.
 */
export async function ensureJiraSyncScheduled(db: Db): Promise<number> {
  return db.transaction(async (tx) => {
    await lockSchedule(tx, LOCKS.jiraSchedule);
    const missing = await tx.execute<{ organization_id: string }>(sql`
      SELECT c.organization_id FROM jira_connections c
       WHERE NOT EXISTS (
         SELECT 1 FROM jobs j
          WHERE j.queue = ${JIRA_QUEUE} AND j.status IN ('queued', 'running')
            AND j.concurrency_key = 'jira-sync:' || c.organization_id::text)`);
    const ids = await enqueueMany(
      tx,
      missing.rows.map((r) => ({
        queue: JIRA_QUEUE,
        concurrencyKey: jiraSyncKey(r.organization_id),
        payload: { kind: 'sync', organizationId: r.organization_id } satisfies JiraJobPayload,
      })),
    );
    return ids.length;
  });
}
