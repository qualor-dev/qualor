import { and, eq, inArray, sql, type SQL } from 'drizzle-orm';
import type { Db, Executor } from '../db/client';
import {
  analyses,
  projects,
  reviewRuns,
  scmConnections,
  type ReviewFailureReason,
  type ReviewRunRow,
  type ReviewRunStatus,
  type ReviewSkipReason,
} from '../db/schema';
import type { WorkerLogger } from '../queue/worker';
import { readScmContext } from '../scm/context';
import { enqueueLatestDecoration, lockBranchQueue } from '../scm/queue';

/*
 * How a review run ends (6I-3, R15): its status, reason and detail in one update, with what it
 * spent when its own job ends it, and then the decoration of its analysis, so that the summary of
 * the merge request says how the review ended (every end but `superseded`). The job (job.ts) and
 * the sweep of the runs whose job is gone (runs.ts) end runs through here.
 *
 * An end and its decoration are one transaction. It takes the branch's decoration lock first, then
 * the run's row, as ingestion takes them (the lock in its SCM and review snapshot stages, the runs
 * after it), so that the two never wait on each other the other way round.
 */

/** How a run ends. */
export type RunEnd =
  | { status: 'superseded' }
  | { status: 'skipped'; reason: ReviewSkipReason; detail?: string | null }
  | {
      status: 'failed';
      reason: ReviewFailureReason;
      /**
       * `window_full`: the model's context window had no room for the judge's call; `time_limit`:
       * the judge had no answer when the review's time was up.
       */
      detail?: string | null;
    };

/** What a run spent, as its columns hold it. */
export interface RunSpend {
  providerHost: string | null;
  model: string | null;
  modelCalls: number;
  toolCalls: number;
  inputTokens: number;
  outputTokens: number;
  costMicroUsd: number | null;
}

/** The parts of a run its end and its decoration need. */
export type RunRef = Pick<ReviewRunRow, 'id' | 'analysisId' | 'branchId'>;

type Logger = Pick<WorkerLogger, 'info' | 'warn'>;

/**
 * The run is the one a job started: the `started_at` that job set is still on it. A restart clears
 * `started_at` and the next job sets its own, so a job that outlived its lease finds the run, ended
 * and started again, no longer its own, and writes nothing into it. The column keeps microseconds
 * and a Date only milliseconds, so the column is cut to milliseconds, as the Date was when it was
 * read. A null is a run no job started: nobody's.
 */
export const startedAtIs = (startedAt: Date | null): SQL =>
  startedAt === null
    ? sql`false`
    : sql`date_trunc('milliseconds', ${reviewRuns.startedAt}) = ${startedAt.toISOString()}::timestamptz`;

export interface EndExtra {
  /**
   * What the run spent, as its own job counted it. Left out, the spend columns are left as they
   * are: whoever ends a run that is not its own job's knows nothing of what it spent.
   */
  spend?: RunSpend;
  /** The digest of the reviewed diff, when it was made. */
  diffDigest?: string | null;
  /**
   * The `started_at` the ending job set when it started the run: the run is ended only while it is
   * still that start of it ({@link startedAtIs}), not one that was ended and started again since.
   * Left out, any run in `from` is ended: the sweep's, which knows no job.
   */
  startedAt?: Date | null;
}

/**
 * Ends the run when its status is one of `from`: its status, reason and detail are set and its
 * phase cleared in one update, with `extra`. Answers whether it ended it. In the transaction that
 * holds the branch's decoration lock, which then decorates the run (decorateRun); endAndDecorate
 * does all three.
 */
export async function endRun(
  tx: Executor,
  run: Pick<RunRef, 'id'>,
  from: readonly ReviewRunStatus[],
  end: RunEnd,
  extra: EndExtra = {},
): Promise<boolean> {
  const ended = await tx
    .update(reviewRuns)
    .set({
      status: end.status,
      phase: null,
      reason: end.status === 'superseded' ? null : end.reason,
      detail: end.status === 'superseded' ? null : (end.detail ?? null),
      finishedAt: sql`now()`,
      ...(extra.spend ?? {}),
      ...(extra.diffDigest === undefined || extra.diffDigest === null
        ? {}
        : { diffDigest: extra.diffDigest }),
    })
    .where(
      and(
        eq(reviewRuns.id, run.id),
        inArray(reviewRuns.status, [...from]),
        extra.startedAt === undefined ? undefined : startedAtIs(extra.startedAt),
      ),
    )
    .returning({ id: reviewRuns.id });
  return ended.length > 0;
}

/** The class of a thrown value, for a log line that holds no message (it could hold content). */
export const errorClass = (err: unknown): string =>
  err instanceof Error ? err.constructor.name : typeof err;

/**
 * The log line of a run's end, once it is committed: its id, status and reason, and its detail
 * when it has one. The detail is a fixed token (`too_large`, `window_too_small`, `window_full`,
 * `time_limit`, `snapshot_deleted`, or the reason review is inactive), never free text.
 */
export function logRunEnd(logger: Logger, runId: string, end: RunEnd): void {
  const detail = end.status === 'superseded' ? null : (end.detail ?? null);
  logger.info(
    {
      runId,
      status: end.status,
      reason: end.status === 'superseded' ? null : end.reason,
      ...(detail === null ? {} : { detail }),
    },
    'AI review run ended',
  );
}

/**
 * Queues the decoration of the run's analysis (scm.md §4.1) with the CI context its ingestion
 * stored, through the connection of the analysis' own provider, so that the summary says how the
 * review ended. Only while the analysis is the branch's newest: a newer one has a decoration of
 * its own (enqueueLatestDecoration). An analysis of a project without a connection is not
 * decorated; one whose context is missing or not valid, of another provider than the project's
 * connection, or of GitHub without its Actions context is not decorated either, each said once
 * (as a re-evaluation fails closed). In the transaction that ended the run.
 */
export async function decorateRun(db: Executor, run: RunRef, logger: Logger): Promise<void> {
  const [found] = await db
    .select({
      scmContext: analyses.scmContext,
      ref: projects.scmProjectRef,
      provider: scmConnections.provider,
    })
    .from(analyses)
    .innerJoin(projects, eq(projects.id, analyses.projectId))
    .innerJoin(scmConnections, eq(scmConnections.id, projects.scmConnectionId))
    .where(eq(analyses.id, run.analysisId));
  if (found === undefined || found.ref === null) return;
  const where = { runId: run.id, analysisId: run.analysisId };
  const stored = readScmContext(found.scmContext);
  if (stored.kind !== 'ok') {
    logger.warn(
      { ...where, context: stored.kind },
      'AI review ended but not decorated: the stored SCM context of the analysis is missing or not valid',
    );
    return;
  }
  if (stored.context.provider !== found.provider) {
    // github.md §5.1: an analysis is decorated only through a connection of its own provider.
    logger.warn(
      { ...where, provider: stored.context.provider, connection: found.provider },
      "AI review ended but not decorated: the analysis is not of the provider of its project's SCM connection",
    );
    return;
  }
  const target = { analysisId: run.analysisId, branchId: run.branchId };
  if (stored.context.provider === 'gitlab') {
    await enqueueLatestDecoration(db, { ...target, gitlab: stored.context.gitlab });
    return;
  }
  const github = stored.context.github ?? null;
  if (github === null) {
    // Without the GitHub context, which revision was checked out is unknown: fail closed.
    logger.warn(
      where,
      'AI review ended but not decorated: the analysis has no stored GitHub Actions context',
    );
    return;
  }
  await enqueueLatestDecoration(db, { ...target, gitlab: null, github });
}

/**
 * Ends the run as `end` (from `from`) and, unless it was superseded, queues its decoration, in one
 * transaction that takes the branch's decoration lock before the run's row. Answers whether it
 * ended it; the end is logged once committed.
 */
export async function endAndDecorate(
  db: Db,
  run: RunRef,
  from: readonly ReviewRunStatus[],
  end: RunEnd,
  extra: EndExtra,
  logger: Logger,
): Promise<boolean> {
  const ended = await db.transaction(async (tx) => {
    await lockBranchQueue(tx, run.branchId);
    if (!(await endRun(tx, run, from, end, extra))) return false;
    if (end.status !== 'superseded') await decorateRun(tx, run, logger);
    return true;
  });
  if (ended) logRunEnd(logger, run.id, end);
  return ended;
}

/**
 * What a run spent, written on it as it is: a run another job or a newer analysis ended. Only while
 * the run is still the start of it that `startedAt` names ({@link startedAtIs}): a run that was
 * started again since is another job's, and what this job spent is not written on it.
 */
export async function writeRunSpend(
  db: Executor,
  runId: string,
  spend: RunSpend,
  startedAt: Date | null,
): Promise<void> {
  await db
    .update(reviewRuns)
    .set(spend)
    .where(and(eq(reviewRuns.id, runId), startedAtIs(startedAt)));
}
