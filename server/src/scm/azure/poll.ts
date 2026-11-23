import { and, desc, eq, gte, max, sql } from 'drizzle-orm';
import { z } from 'zod';
import type { Db } from '../../db/client';
import { LOCKS } from '../../db/locks';
import { analyses, branches, projects, reviewRuns, scmConnections } from '../../db/schema';
import { readLlmSettings } from '../../llm/settings';
import { enqueueMany } from '../../queue/queue';
import { lockSchedule, queuePass, type PassSchedule } from '../../queue/schedule';
import type { JobHandlers, WorkerLogger } from '../../queue/worker';
import { queueScan, REPLY_MAX_AGE_DAYS } from '../../review/reply-queue';
import { reviewActive } from '../../review/settings';
import type { ScmDeps } from '../connections';
import { ScmError } from '../provider';
import { clearScmProblem, recordScmProblem, SCM_HOOK_PROBLEM_CODES } from '../problems';
import type { ScmRuntime } from '../runtime';
import { azureClientFor } from './connections';
import { hookState, ownSubscriptions } from './hooks';
import { azureWebhookUrl } from './url';

/**
 * The backstop of the service hooks (sub-plan 5): Azure DevOps drops events while a subscription
 * is on probation and disables one that fails for long, so every 15 minutes each Azure connection
 * with a mapped project gets a pass. It queues a reply scan for each recent AI-reviewed pull
 * request, so replies and commands are answered without hooks, and records "hook on probation" or
 * "hook disabled" as the connection's background problem.
 */

/** The queue of the passes, on the SCM worker. */
export const AZURE_POLL_QUEUE = 'azure-poll';

/** A pass runs every 15 minutes per connection. */
export const AZURE_POLL_INTERVAL_SECONDS = 900;

/** The most pull requests one pass queues a scan for, the newest analysis first. */
export const MAX_POLLED_BRANCHES = 50;

/** The concurrency key of a connection's pass. */
export const azurePollKey = (connectionId: string): string => `azure-poll:${connectionId}`;

const pollJob = z.object({ connectionId: z.uuid() });

const pollPass = (connectionId: string): PassSchedule => ({
  lock: LOCKS.azurePollSchedule,
  queue: AZURE_POLL_QUEUE,
  key: azurePollKey(connectionId),
  payload: { connectionId } satisfies z.infer<typeof pollJob>,
});

/** What a pass needs: the SCM worker's dependencies. */
export interface AzurePollDeps {
  db: Db;
  scm: ScmDeps;
  runtime: ScmRuntime;
  /** `QUALOR_PUBLIC_URL`; Qualor has subscriptions to read only with an `https` one. */
  publicUrl: string | null;
  logger?: WorkerLogger;
}

/** The Azure connections that have a mapped project: the ones a pass runs for. */
const WANTED = sql`
  SELECT c.id FROM scm_connections c
   WHERE c.provider = 'azure'
     AND EXISTS (SELECT 1 FROM projects p WHERE p.scm_connection_id = c.id)`;

async function passWanted(db: Db, connectionId: string): Promise<boolean> {
  const found = await db.execute<{ wanted: boolean }>(sql`
    SELECT EXISTS (SELECT 1 FROM (${WANTED}) w WHERE w.id = ${connectionId}) AS wanted`);
  return found.rows[0]?.wanted === true;
}

/**
 * Boot and reaping: one pass at now for each Azure connection with a mapped project that has none
 * queued or running. The schedule lock makes replicas that boot together queue one each; returns
 * how many it queued.
 */
export async function ensureAzurePollScheduled(db: Db): Promise<number> {
  return db.transaction(async (tx) => {
    await lockSchedule(tx, LOCKS.azurePollSchedule);
    const missing = await tx.execute<{ id: string }>(sql`
      SELECT w.id FROM (${WANTED}) w
      WHERE NOT EXISTS (
        SELECT 1 FROM jobs j
         WHERE j.queue = ${AZURE_POLL_QUEUE} AND j.status IN ('queued', 'running')
           AND j.concurrency_key = 'azure-poll:' || w.id::text)`);
    const ids = await enqueueMany(
      tx,
      missing.rows.map((r) => ({
        queue: AZURE_POLL_QUEUE,
        concurrencyKey: azurePollKey(r.id),
        payload: { connectionId: r.id } satisfies z.infer<typeof pollJob>,
      })),
    );
    return ids.length;
  });
}

/**
 * The pull requests to scan: branches of the connection's projects with a done review run whose
 * analysis is at most {@link REPLY_MAX_AGE_DAYS} days old, in a project with AI review active,
 * the newest analysis first, at most {@link MAX_POLLED_BRANCHES}.
 */
async function candidates(db: Db, connectionId: string, now: Date): Promise<string[]> {
  const cutoff = new Date(now.getTime() - REPLY_MAX_AGE_DAYS * 86_400_000);
  const newest = max(analyses.createdAt);
  const rows = await db
    .select({
      branchId: branches.id,
      projectId: projects.id,
      organizationId: projects.organizationId,
    })
    .from(reviewRuns)
    .innerJoin(analyses, eq(analyses.id, reviewRuns.analysisId))
    .innerJoin(branches, eq(branches.id, reviewRuns.branchId))
    .innerJoin(projects, eq(projects.id, branches.projectId))
    .where(
      and(
        eq(projects.scmConnectionId, connectionId),
        eq(branches.kind, 'merge_request'),
        eq(reviewRuns.status, 'done'),
        gte(analyses.createdAt, cutoff),
      ),
    )
    .groupBy(branches.id, projects.id)
    .orderBy(desc(newest), desc(branches.id));
  if (rows.length === 0) return [];
  const settings = await readLlmSettings(db);
  return rows
    .filter(
      (r) =>
        reviewActive(settings, {
          id: r.projectId,
          organizationId: r.organizationId,
          scmConnectionId: connectionId,
        }).active,
    )
    .slice(0, MAX_POLLED_BRANCHES)
    .map((r) => r.branchId);
}

/**
 * Reads Qualor's own subscriptions once and records what they say: `hook_disabled` when any is
 * disabled, else `hook_probation` when any is on probation, else the hook codes are cleared. No
 * subscription of Qualor's (or no `https` public URL, which Azure DevOps needs for the password)
 * records nothing. A failure of the read records nothing either: a credential failure is the
 * decorator's to record, and a transient one passes by itself.
 */
async function recordHookState(
  deps: AzurePollDeps,
  connection: typeof scmConnections.$inferSelect,
): Promise<void> {
  if (deps.publicUrl === null || !deps.publicUrl.startsWith('https://')) return;
  const found = azureClientFor(connection, deps.scm, deps.runtime);
  if ('problem' in found) return;
  let own;
  try {
    own = ownSubscriptions(
      await found.client.subscriptions(),
      azureWebhookUrl(deps.publicUrl, connection.id),
    );
  } catch (err) {
    if (err instanceof ScmError) return;
    throw err;
  }
  if (own.length === 0) return;
  const states = own.map((s) => hookState(s.status));
  if (states.includes('disabled')) await recordScmProblem(deps.db, connection.id, 'hook_disabled');
  else if (states.includes('onProbation')) {
    await recordScmProblem(deps.db, connection.id, 'hook_probation');
  } else await clearScmProblem(deps.db, connection.id, SCM_HOOK_PROBLEM_CODES);
}

/**
 * One pass of the connection: the hook state, then a reply scan for each candidate pull request.
 * A failure of the hook state is logged and the scans are still queued.
 */
export async function runAzurePass(
  deps: AzurePollDeps,
  connectionId: string,
  now: Date = new Date(),
): Promise<void> {
  const [connection] = await deps.db
    .select()
    .from(scmConnections)
    .where(eq(scmConnections.id, connectionId));
  if (connection?.provider !== 'azure') return;
  try {
    await recordHookState(deps, connection);
  } catch {
    deps.logger?.warn({ connectionId }, 'could not read the Azure DevOps service hooks');
  }
  for (const branchId of await candidates(deps.db, connectionId, now)) {
    await queueScan(deps.db, branchId);
  }
}

/**
 * The pass, then the next one 15 minutes out from `finally`, so a pass that throws keeps its
 * schedule too, while the connection still has a mapped project.
 */
async function runAndReschedule(deps: AzurePollDeps, connectionId: string): Promise<void> {
  try {
    await runAzurePass(deps, connectionId);
  } finally {
    if (await passWanted(deps.db, connectionId)) {
      await queuePass(deps.db, pollPass(connectionId), AZURE_POLL_INTERVAL_SECONDS);
    }
  }
}

/** The `azure-poll` queue's handler, run by the SCM worker. A malformed payload is logged and completed. */
export function azurePollHandlers(deps: AzurePollDeps): JobHandlers {
  return {
    [AZURE_POLL_QUEUE]: async (job) => {
      const parsed = pollJob.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn({ jobId: job.id }, 'malformed Azure DevOps poll payload; completing');
        return;
      }
      await runAndReschedule(deps, parsed.data.connectionId);
    },
  };
}
