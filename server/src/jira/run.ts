import { z } from 'zod';
import type { Db } from '../db/client';
import type { Limits } from '../limits';
import type { JobHandlers, WorkerLogger } from '../queue/worker';
import type { JiraClient } from './client';
import { connectionOf, jiraClientFor, type JiraConnectionRow, type JiraDeps } from './connection';
import { createPending } from './create';
import { JIRA_QUEUE } from './jobs';
import { setConnectionProblem } from './problems';

/** Ruling R2: the `jira` queue's own worker runs two jobs at once ... */
export const JIRA_WORKER_CONCURRENCY = 2;
/** ... each with a 2-minute lease, which the heartbeat extends while a slow Jira answers. */
export const JIRA_LEASE_MS = 2 * 60_000;

export interface JiraJobDeps extends JiraDeps {
  db: Db;
  /** `QUALOR_PUBLIC_URL`: the Qualor links in a Jira issue; none without it. */
  publicUrl: string | null;
  /** Read for each run: the Exploited and EPSS lines need `vuln.priority`. */
  limits: () => Pick<Limits, 'vulnerabilities'>;
  logger?: WorkerLogger;
}

/** One run of a `jira` job: the organisation's connection and a client (one request budget). */
export interface JiraRunContext {
  deps: JiraJobDeps;
  connection: JiraConnectionRow;
  client: JiraClient;
}

const jiraJobPayload = z.object({
  kind: z.enum(['create', 'sync']),
  organizationId: z.uuid(),
});

/**
 * The organisation's connection and a client for it, or null: without a connection (deleted
 * since the job was queued, ruling T3b), or when no client can be made, which is recorded as the
 * background problem (`undecryptable`, `url_not_allowed`).
 */
export async function openRun(
  deps: JiraJobDeps,
  organizationId: string,
): Promise<JiraRunContext | null> {
  const connection = await connectionOf(deps.db, organizationId);
  if (!connection) return null;
  const found = jiraClientFor(connection, deps);
  if ('problem' in found) {
    await setConnectionProblem(deps.db, connection.id, found.problem);
    return null;
  }
  return { deps, connection, client: found.client };
}

/**
 * The `jira` queue's handler (spec §6.4, §6.5), run by its own worker (R2): `create` sends the
 * organisation's pending rows to Jira; `sync`, the pass, comes with Task 8. A job whose
 * connection is gone ends without an error and queues nothing.
 */
export function jiraHandlers(deps: JiraJobDeps): JobHandlers {
  return {
    [JIRA_QUEUE]: async (job) => {
      const parsed = jiraJobPayload.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn({ jobId: job.id }, 'malformed Jira job payload; completing');
        return;
      }
      const { kind, organizationId } = parsed.data;
      if (kind !== 'create') return;
      const ctx = await openRun(deps, organizationId);
      if (ctx === null) return;
      const outcome = await createPending(ctx);
      if (ctx.client.requests > 0 || outcome.failed > 0) {
        deps.logger?.info(
          {
            organizationId,
            connectionId: ctx.connection.id,
            requests: ctx.client.requests,
            ...outcome,
          },
          'Jira create run',
        );
      }
    },
  };
}
