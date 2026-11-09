import type { FastifyBaseLogger } from 'fastify';
import type { Db } from '../../db/client';
import type { Limits } from '../../limits';
import type { NotifyDeps } from '../../notifications/deps';
import type { JobHandlers } from '../../queue/worker';
import { DIGEST_QUEUE, ensureVulnerabilityDigestScheduled, runVulnerabilityDigest } from './digest';
import { ALERTS_QUEUE } from './enqueue';
import { sendExploitedAlerts } from './exploited';

export { ALERTS_QUEUE, enqueueVulnerabilityAlerts } from './enqueue';

export interface AlertDeps extends NotifyDeps {
  db: Db;
  limits: () => Pick<Limits, 'vulnerabilities'>;
  now?: () => Date;
  logger?: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
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
    [DIGEST_QUEUE]: async () => {
      try {
        const { mails, deliveries, items } = await runVulnerabilityDigest(deps);
        if (mails + deliveries > 0) {
          deps.logger?.info(
            { component: 'vulnerabilities', mails, deliveries, items },
            'vulnerability digest queued',
          );
        }
      } finally {
        // Also after a failure: tomorrow's run does not depend on today's retries.
        await ensureVulnerabilityDigestScheduled(deps.db);
      }
    },
  };
}
