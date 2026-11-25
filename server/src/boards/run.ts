import { and, eq } from 'drizzle-orm';
import { z } from 'zod';
import type { Db } from '../db/client';
import { scmConnections } from '../db/schema';
import type { Limits } from '../limits';
import type { JobHandlers, WorkerLogger } from '../queue/worker';
import type { AzureDevOpsClient } from '../scm/azure/client';
import { azureClientFor, clientProblemCode } from '../scm/azure/connections';
import type { ScmConnectionRow, ScmDeps } from '../scm/connections';
import type { InstallationTokenCache } from '../scm/github/app-auth';
import { isScmBackgroundProblem, recordScmProblem } from '../scm/problems';
import { createPendingWorkItems } from './create';
import {
  BOARDS_QUEUE,
  BOARDS_SYNC_INTERVAL_SECONDS,
  boardsPassWanted,
  scheduleBoardsSync,
} from './jobs';

/** The `boards` queue's own worker runs two jobs at once ... */
export const BOARDS_WORKER_CONCURRENCY = 2;
/** ... each with a 2-minute lease, which the heartbeat extends while a slow Azure DevOps answers. */
export const BOARDS_LEASE_MS = 120_000;

export interface BoardsJobDeps {
  db: Db;
  /** The SCM worker's settings: the secret key, `QUALOR_SCM_INTERNAL_HOSTS`, the test origins. */
  scm: ScmDeps;
  /** The process's Microsoft Entra tokens (`ScmRuntime.azureTokens`), shared with the SCM worker. */
  azureTokens: InstallationTokenCache;
  /** `QUALOR_PUBLIC_URL`: the Qualor links in a work item; none without it. */
  publicUrl: string | null;
  /** Read for each run: the Exploited and EPSS lines need `vuln.priority`. */
  limits: () => Pick<Limits, 'vulnerabilities'>;
  logger?: WorkerLogger;
}

/**
 * One run of a `boards` job: the Azure DevOps connection as the run read it (its address fences
 * every write, its `problem` is the run's view) and a client (one request budget,
 * `MAX_AZURE_REQUESTS`).
 */
export interface BoardsRunContext {
  deps: BoardsJobDeps;
  connection: ScmConnectionRow;
  client: AzureDevOpsClient;
}

const boardsJobPayload = z.object({
  kind: z.enum(['create', 'sync']),
  connectionId: z.uuid(),
});

/**
 * The Azure DevOps connection and a client for it, or null: without the connection (deleted since
 * the job was queued, or no longer an Azure DevOps one), or when no client can be made, which is
 * recorded as the connection's problem (`undecryptable`, `token_endpoint` for an expired
 * certificate, `url_not_allowed`).
 */
export async function openBoardsRun(
  deps: BoardsJobDeps,
  connectionId: string,
): Promise<BoardsRunContext | null> {
  const [connection] = await deps.db
    .select()
    .from(scmConnections)
    .where(and(eq(scmConnections.id, connectionId), eq(scmConnections.provider, 'azure')));
  if (!connection) return null;
  const found = azureClientFor(connection, deps.scm, { azureTokens: deps.azureTokens });
  if ('problem' in found) {
    const code = clientProblemCode(found.problem);
    if (isScmBackgroundProblem(code)) await recordScmProblem(deps.db, connection.id, code);
    return null;
  }
  return { deps, connection, client: found.client };
}

/** One create run of the connection's pending rows. */
async function runCreate(deps: BoardsJobDeps, connectionId: string): Promise<void> {
  const ctx = await openBoardsRun(deps, connectionId);
  if (ctx === null) return;
  const outcome = await createPendingWorkItems(ctx);
  if (ctx.client.requestCount > 0 || outcome.failed > 0) {
    deps.logger?.info(
      { connectionId, requests: ctx.client.requestCount, ...outcome },
      'Azure Boards create run',
    );
  }
}

/**
 * One pass, then the next one 15 minutes out, from `finally` so a pass that throws keeps its
 * schedule too, while the connection still wants a pass (a mapping or a live link): a pass whose
 * connection is gone ends without an error and queues nothing.
 *
 * Plan Task 6: until the pass's steps exist (Task 7), the pass runs the create step alone.
 */
async function runSync(deps: BoardsJobDeps, connectionId: string): Promise<void> {
  try {
    const ctx = await openBoardsRun(deps, connectionId);
    if (ctx !== null) await createPendingWorkItems(ctx);
  } finally {
    if (await boardsPassWanted(deps.db, connectionId)) {
      await scheduleBoardsSync(deps.db, connectionId, BOARDS_SYNC_INTERVAL_SECONDS);
    }
  }
}

/**
 * The `boards` queue's handler, run by its own worker: `create` sends the connection's pending
 * rows to Azure Boards; `sync` runs the pass and schedules the next. A job whose connection is
 * gone ends without an error and queues nothing; a malformed payload is logged and completed.
 */
export function boardsHandlers(deps: BoardsJobDeps): JobHandlers {
  return {
    [BOARDS_QUEUE]: async (job) => {
      const parsed = boardsJobPayload.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn({ jobId: job.id }, 'malformed Azure Boards job payload; completing');
        return;
      }
      const { kind, connectionId } = parsed.data;
      if (kind === 'create') await runCreate(deps, connectionId);
      else await runSync(deps, connectionId);
    },
  };
}
