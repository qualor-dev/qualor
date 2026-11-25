import { and, eq, sql } from 'drizzle-orm';
import { BOARDS_QUEUE } from '../src/boards/jobs';
import { boardsHandlers, type BoardsJobDeps } from '../src/boards/run';
import { jobs } from '../src/db/schema';
import { communityLimits } from '../src/limits';
import { runUntilIdle } from '../src/queue/worker';
import { InstallationTokenCache } from '../src/scm/github/app-auth';
import type { IngestHarness } from './ingest';

/**
 * The Boards jobs' deps for the harness's app: its SCM settings (the fakes' hosts and origins),
 * public URL and limits, and a 2 s deadline per Azure DevOps request so a hang costs two seconds,
 * not ten.
 */
export function boardsJobDeps(
  h: IngestHarness,
  overrides: Partial<BoardsJobDeps> = {},
): BoardsJobDeps {
  return {
    db: h.ctx.db,
    scm: {
      secretKey: h.ctx.config.secretKey,
      internalHosts: h.ctx.config.scmInternalHosts,
      azureTokenOrigin: h.ctx.config.azureTokenOrigin,
      azureTestOrigin: h.ctx.config.azureTestOrigin,
      azureClientOptions: { timeoutMs: 2_000 },
    },
    azureTokens: new InstallationTokenCache(),
    publicUrl: h.ctx.config.publicUrl,
    limits: () => h.ctx.edition?.limits() ?? communityLimits(),
    ...overrides,
  };
}

/**
 * Makes the queued `boards` jobs of this kind due now and runs the queue until idle (a job those
 * jobs queue for now runs too). Returns how many jobs ran.
 */
export async function runBoardsJobs(
  h: IngestHarness,
  deps: BoardsJobDeps,
  kind: 'create' | 'sync',
): Promise<number> {
  await h.ctx.db
    .update(jobs)
    .set({ runAt: sql`now()` })
    .where(
      and(
        eq(jobs.queue, BOARDS_QUEUE),
        eq(jobs.status, 'queued'),
        sql`${jobs.payload} ->> 'kind' = ${kind}`,
      ),
    );
  return runUntilIdle(h.ctx.db, boardsHandlers(deps), deps.logger ?? h.ctx.app.log);
}
