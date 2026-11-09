import { sql } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import type { Db, Executor } from '../../db/client';
import { LOCKS } from '../../db/locks';
import type { Limits } from '../../limits';
import type { NotifyDeps } from '../../notifications/deps';
import { enqueue } from '../../queue/queue';
import type { JobHandlers } from '../../queue/worker';
import { sendExploitedAlerts } from './exploited';

/** The alert job's queue, and its concurrency key: a run and a queued follow-up never overlap. */
export const ALERTS_QUEUE = 'vulnerabilities.alerts';

export interface AlertDeps extends NotifyDeps {
  db: Db;
  limits: () => Pick<Limits, 'vulnerabilities'>;
  now?: () => Date;
  logger?: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
}

/**
 * Asks for a run of the alert job unless one is queued; true when this call queued it. A running
 * job does not count: the new one covers what the running one has already passed.
 *
 * Under LOCKS.vulnerabilityAlertsSchedule, with a queued job's row locked until the caller's
 * transaction commits: the worker cannot claim it (SKIP LOCKED) before the rows this request is
 * about are committed, and a run that started too early cannot miss them.
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

/** On the analysis worker (main.ts). An error reaches the queue: the transaction rolled back, so the retry starts clean. */
export function alertHandlers(deps: AlertDeps): JobHandlers {
  return {
    [ALERTS_QUEUE]: async () => {
      const { mails, items } = await sendExploitedAlerts(deps);
      if (mails > 0) {
        deps.logger?.info(
          { component: 'vulnerabilities', mails, items },
          'exploited vulnerability emails queued',
        );
      }
    },
  };
}
