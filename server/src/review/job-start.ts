import type { ScmProvider } from '@qualor/shared';
import { and, eq, sql, type SQL } from 'drizzle-orm';
import type { Executor } from '../db/client';
import {
  branches,
  projects,
  reviewRuns,
  reviewSnapshots,
  scmConnections,
  type ReviewRunRow,
  type ReviewRunStatus,
} from '../db/schema';
import { readLlmSettings, type StoredLlmSettings } from '../llm/settings';
import { lockBranchQueue } from '../scm/queue';
import type { ReviewJobDeps } from './job';
import { decorateRun, endRun, type RunEnd } from './run-ends';
import { queueAfterStop, queueAtDeadline } from './runs';
import { reviewActive, reviewProvider, type ReviewProvider } from './settings';

/** The run's own state while the job works on it, once it is running. */
export interface Running {
  run: ReviewRunRow;
  /** The merge request's id: its branch's name. */
  mergeRequestId: string;
  settings: StoredLlmSettings;
  provider: ReviewProvider;
  /** The SCM provider of the merge request: the nouns of the prompts; GitLab's without a connection. */
  scm: ScmProvider;
  organizationId: string;
}

/** What steps 1 to 5 decided, in the transaction that holds the run's row. */
export type Decision =
  { kind: 'started'; running: Running } | { kind: 'ended'; end: RunEnd } | { kind: 'none' };

/** The time the run's deadline is compared with: the database's, unless the deps fix one. */
const clockOf = (deps: Pick<ReviewJobDeps, 'now'>): SQL =>
  deps.now === undefined ? sql`now()` : sql`${deps.now().toISOString()}::timestamptz`;

/**
 * Steps 1 to 5: decides, holding the run's row, whether the run starts, waits on or ends; a run
 * that ends here is decorated in the same transaction. A run that starts is reviewed.
 */
export async function decideStart(
  deps: ReviewJobDeps,
  runId: string,
  tx: Executor,
): Promise<Decision> {
  // A run's branch never changes. Its decoration lock is taken before the run's row, as
  // ingestion takes them: an end here and its decoration are one step (run-ends.ts).
  const [ref] = await tx
    .select({ branchId: reviewRuns.branchId })
    .from(reviewRuns)
    .where(eq(reviewRuns.id, runId));
  if (ref === undefined) return { kind: 'none' };
  await lockBranchQueue(tx, ref.branchId);
  const clock = clockOf(deps);
  const [found] = await tx
    .select({ run: reviewRuns, due: sql<boolean>`${reviewRuns.deadlineAt} <= ${clock}` })
    .from(reviewRuns)
    .where(eq(reviewRuns.id, runId))
    .for('update');
  if (found === undefined) return { kind: 'none' };
  const { run, due } = found;
  const from: ReviewRunStatus[] = [run.status];
  // Nothing is spent yet: an end here leaves the spend columns as they are.
  const ended = async (end: RunEnd): Promise<Decision> => {
    if (!(await endRun(tx, run, from, end))) return { kind: 'none' };
    if (end.status !== 'superseded') await decorateRun(tx, run, deps.logger);
    return { kind: 'ended', end };
  };
  // A job that died left its run running (its lease expired, or it could not end the run): this
  // is its second try. What that job spent is on the run as far as it wrote it, and stays so.
  if (run.status === 'running') return ended({ status: 'failed', reason: 'internal' });
  if (run.status !== 'waiting') return { kind: 'none' };

  const [branch] = await tx
    .select({ name: branches.name, lastAnalysisId: branches.lastAnalysisId })
    .from(branches)
    .where(eq(branches.id, run.branchId));
  if (branch === undefined || branch.lastAnalysisId !== run.analysisId) {
    return ended({ status: 'superseded' });
  }
  const settings = await readLlmSettings(tx);
  const [project] = await tx
    .select({
      id: projects.id,
      organizationId: projects.organizationId,
      scmConnectionId: projects.scmConnectionId,
    })
    .from(projects)
    .where(eq(projects.id, run.projectId));
  if (project === undefined) return { kind: 'none' };
  const [connection] =
    project.scmConnectionId === null
      ? []
      : await tx
          .select({ provider: scmConnections.provider })
          .from(scmConnections)
          .where(eq(scmConnections.id, project.scmConnectionId));
  const active = reviewActive(settings, project);
  const provider = reviewProvider(settings);
  if (!active.active || provider === null) {
    const detail = active.active ? 'no_provider' : active.reason;
    return ended({ status: 'skipped', reason: 'inactive', detail });
  }

  const [snapshot] = await tx
    .select({
      id: reviewSnapshots.id,
      status: reviewSnapshots.status,
      error: reviewSnapshots.error,
      headSha: reviewSnapshots.headSha,
      sinceSha: reviewSnapshots.sinceSha,
      partial: reviewSnapshots.partial,
    })
    .from(reviewSnapshots)
    .where(eq(reviewSnapshots.analysisId, run.analysisId));
  if (snapshot?.status === 'rejected') {
    // The code of the reason (`SNAPSHOT_INVALID`), never what follows it.
    const detail = (snapshot.error ?? '').split(':', 1)[0] || null;
    return ended({ status: 'skipped', reason: 'snapshot_rejected', detail });
  }
  if (snapshot?.status !== 'ready') {
    if (!due) {
      await queueAtDeadline(tx, run);
      return { kind: 'none' };
    }
    return ended({ status: 'skipped', reason: 'no_snapshot' });
  }
  if (deps.shutdown.aborted) {
    // A stopping server starts no review: the run waits for the server that takes its job next.
    await queueAfterStop(tx, run);
    return { kind: 'none' };
  }

  const [started] = await tx
    .update(reviewRuns)
    .set({
      status: 'running',
      startedAt: sql`now()`,
      snapshotId: snapshot.id,
      headSha: snapshot.headSha,
      sinceSha: snapshot.sinceSha,
      snapshotPartial: snapshot.partial,
    })
    .where(and(eq(reviewRuns.id, run.id), eq(reviewRuns.status, 'waiting')))
    .returning();
  if (started === undefined) return { kind: 'none' };
  return {
    kind: 'started',
    running: {
      run: started,
      mergeRequestId: branch.name,
      settings,
      provider,
      scm: connection?.provider ?? 'gitlab',
      organizationId: project.organizationId,
    },
  };
}
