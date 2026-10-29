import { eq } from 'drizzle-orm';
import { branches, reviewRuns, type ReviewRunRow } from '../db/schema';
import type { ReviewContext } from './context';
import type { ReviewJobDeps } from './job';
import type { Running } from './job-start';
import type { RunLedger } from './job-spend';
import type { StopReason, StopState } from './job-stop';
import type { MaskedFiles } from './masked-files';
import type { Masker } from './masker';
import type { PipelineOutcome } from './pipeline';
import { ensureAiRules } from './rules';
import { decorateRun, endAndDecorate, type RunEnd } from './run-ends';
import {
  prepareReviewOutcome,
  ReviewNotStoringError,
  startStoring,
  storeReviewOutcome,
} from './store';
import type { ToolPolicy } from './tools';
import { lockBranchQueue } from '../scm/queue';

/** What the end of a run that reviewed needs besides the pipeline's outcome. */
export interface FinishInputs {
  context: ReviewContext;
  files: MaskedFiles;
  masker: Masker;
  policy: ToolPolicy;
  shouldStop: () => Promise<boolean>;
}

/** How a run ends: what it stored or why it stopped, and what it spent, written with the end. */
export class RunEnder {
  constructor(
    private readonly deps: ReviewJobDeps,
    private readonly ledger: RunLedger,
    private readonly state: StopState,
  ) {}

  /**
   * The pipeline's outcome. A review is stored once the run is `storing`, which a guarded update
   * makes it (`startStoring`), and only this job's run, still running and not storing, passes: from
   * then on no newer analysis supersedes it. The values are made before the transaction (masking
   * takes time), which only writes; the store refuses a run no longer storing, under its lock, and
   * one whose snapshot was deleted since the last stop check, which then ends with nothing stored:
   * `superseded` when a newer push replaced the snapshot, `skipped: closed` when the merge request
   * was merged or closed (`snapshotGone`). A review that ran out of time asks the stop check first:
   * a judge whose time was up before it started made no call, so nothing asked it, and a stop that
   * came meanwhile (a merge, review switched off, the server stopping) is how the run ends.
   */
  async finish(running: Running, outcome: PipelineOutcome, o: FinishInputs): Promise<void> {
    const { db } = this.deps;
    const { run } = running;
    if (outcome.kind === 'failed') {
      if (outcome.detail === 'time_limit' && (await o.shouldStop())) return this.stopped(run);
      return this.endRunning(run, {
        status: 'failed',
        reason: outcome.reason,
        detail: outcome.detail ?? null,
      });
    }
    // Asked once more after the last call: nothing is stored for a run that should have stopped.
    if (outcome.kind === 'stopped' || (await o.shouldStop())) return this.stopped(run);
    const storing = await startStoring(db, run);
    if (storing === undefined) return this.stopped(run);
    const ruleIds = await ensureAiRules(db);
    const prepared = await prepareReviewOutcome(o.context, outcome, {
      files: o.files,
      masker: o.masker,
      budget: o.policy.budget,
    });
    try {
      // One step with its decoration, the branch's decoration lock first (run-ends.ts).
      await db.transaction(async (tx) => {
        await lockBranchQueue(tx, run.branchId);
        await storeReviewOutcome(tx, storing, prepared, ruleIds);
        await tx.update(reviewRuns).set(this.ledger.spend()).where(eq(reviewRuns.id, run.id));
        await decorateRun(tx, run, this.deps.logger);
      });
    } catch (err) {
      if (!(err instanceof ReviewNotStoringError)) throw err;
      const [now] = await db
        .select({
          status: reviewRuns.status,
          phase: reviewRuns.phase,
          snapshotId: reviewRuns.snapshotId,
        })
        .from(reviewRuns)
        .where(eq(reviewRuns.id, run.id));
      if (now?.status === 'running' && now.phase === 'storing' && now.snapshotId === null) {
        // Its snapshot was deleted after the last stop check: what the review read is gone, and the
        // run ends as the stop check ends it.
        return this.snapshotGone(run);
      }
      // Ended meanwhile by a job tried again after this one's lease expired: that one decorated.
      await this.ledger.writeSpend(run);
      return;
    }
    this.deps.logger.info(
      { runId: run.id, status: 'done', findings: prepared.created.length },
      'AI review run ended',
    );
  }

  /**
   * The pipeline stopped: the run was superseded, review was switched off meanwhile, its snapshot
   * was deleted, or the server is stopping. A call the stopping server gave up stops a conversation
   * without the stop check, so the signal itself is asked when the check gave no reason.
   */
  async stopped(run: ReviewRunRow): Promise<void> {
    const stop: StopReason | null =
      this.state.stop ?? (this.deps.shutdown.aborted ? { kind: 'shutdown' } : null);
    if (stop?.kind === 'shutdown') return this.givenUp(run);
    if (stop?.kind === 'inactive') {
      return this.endRunning(run, {
        status: 'skipped',
        reason: 'inactive',
        detail: stop.detail,
      });
    }
    if (stop?.kind === 'snapshot_deleted') return this.snapshotGone(run);
    // Superseded by a newer analysis (already ended), or its analysis is no longer the newest.
    return this.endRunning(run, { status: 'superseded' });
  }

  /**
   * The run's snapshot is gone, and nothing is stored of what the review read of it. Either a newer
   * push replaced it, which deletes the snapshots of the branch's older analyses but lets a run that
   * stores finish: the run's analysis is no longer the branch's newest, and the run ends superseded,
   * as every run a newer push replaces. Or the merge request was merged or closed, which deletes
   * them as well: its analysis is still the newest, and the run is skipped, closed.
   */
  async snapshotGone(run: ReviewRunRow): Promise<void> {
    const [branch] = await this.deps.db
      .select({ newest: branches.lastAnalysisId })
      .from(branches)
      .where(eq(branches.id, run.branchId));
    if (branch?.newest !== run.analysisId) return this.endRunning(run, { status: 'superseded' });
    return this.endRunning(run, {
      status: 'skipped',
      reason: 'closed',
      detail: 'snapshot_deleted',
    });
  }

  /**
   * The server is stopping: the run ends now, `failed: internal`, with its decoration, rather than
   * keep the stop waiting for a review that takes minutes. The next push reviews again.
   */
  async givenUp(run: ReviewRunRow): Promise<void> {
    this.deps.logger.warn({ runId: run.id }, 'AI review run given up: the server is stopping');
    await this.endRunning(run, { status: 'failed', reason: 'internal' });
  }

  /**
   * Ends the running run with what it spent, and queues its decoration unless it was superseded,
   * in one transaction. A run that something else ended meanwhile keeps that end, with this
   * job's spend written on it; one that was ended and started again since is another job's, and
   * is left as it is.
   */
  async endRunning(
    run: ReviewRunRow,
    end: RunEnd,
    extra: { diffDigest?: string | null } = {},
  ): Promise<void> {
    const ended = await endAndDecorate(
      this.deps.db,
      run,
      ['running'],
      end,
      { ...extra, spend: this.ledger.spend(), startedAt: run.startedAt },
      this.deps.logger,
    );
    if (!ended) await this.ledger.writeSpend(run);
  }
}
