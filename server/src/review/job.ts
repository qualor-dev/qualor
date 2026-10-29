import { eq } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import type { AuditRecorder } from '../audit/recorder';
import type { Config } from '../config';
import type { Db } from '../db/client';
import { pgErrorCode } from '../db/errors';
import { reviewRuns, type ReviewRunRow } from '../db/schema';
import type { LlmRuntime } from '../llm/job';
import { providerApiKey } from '../llm/settings';
import type { JobHandlers, WorkerLogger } from '../queue/worker';
import type { DecorationDeps } from '../scm/decorate';
import { readMergeRequestState } from '../scm/mr-state';
import type { ScmRuntime } from '../scm/runtime';
import { deleteBranchSnapshots } from './lifecycle';
import { RunEnder } from './job-end';
import { changesReadOnce, reviewTokensLeft, runContext, type ContextOutcome } from './job-context';
import { RunLedger } from './job-spend';
import { decideStart, type Running } from './job-start';
import { stopCheck, type StopState } from './job-stop';
import { MaskedFiles } from './masked-files';
import { Masker } from './masker';
import { runReviewPipeline } from './pipeline';
import { endAndDecorate, errorClass, logRunEnd } from './run-ends';
import { AI_REVIEW_QUEUE } from './runs';
import { effectiveReviewBudgets } from './settings';
import { openSnapshotReader } from './snapshot-reader';
import { DEFAULT_CONTEXT_WINDOW_TOKENS, newToolPolicy } from './tool-conversation';

export { sameProvider } from './job-stop';

/*
 * The `ai-review` job (6I-3, R15, R21): one review run, from waiting for its snapshot to the
 * findings it stores. In order:
 * 1. a run that is not `waiting` is left as it is; one found `running` was left so by a job that
 *    died, and ends `failed: internal`;
 * 2. an analysis that is no longer its branch's newest is `superseded`;
 * 3. review no longer on for the project: `skipped: inactive`;
 * 4. no snapshot yet: before the deadline the job comes back at it; at or after it,
 *    `skipped: no_snapshot` (a snapshot that comes later starts the run again, runs.ts); a refused
 *    one, `skipped: snapshot_rejected`;
 * 5. the run is `running`, with its snapshot, head and last reviewed commit;
 * 6. the merge request as its provider says it is now: merged or closed, the branch's snapshots
 *    are deleted and the run `skipped: closed`; a draft, `skipped: draft`, unless a person asked for
 *    this run (`qualor review`, `requested_by`); no answer, the review goes on;
 * 7–9. nothing reviewable changed (`empty_diff`), the same diff as the last review that was done
 *    (`unchanged`), no tokens left today or too few for the smallest share of the review
 *    (`budget_spent`; detail `too_large` when even Tokens per review is too few for a merge request
 *    this large, `window_too_small` when Tokens per review holds it and the model's context window
 *    does not): decided before anything is masked or sent;
 * 10. the pipeline (pipeline.ts), its calls recorded as the review's own (usage.ts), stopping at
 *    the next call to the provider when the run is superseded, review is switched off or its
 *    snapshot is deleted (the merge request was merged or closed: `skipped: closed`), and given
 *    the review's time (REVIEW_TIME_BUDGET_MS); then the findings are stored (store.ts), or the run
 *    fails with the pipeline's reason.
 *
 * A stop of the server (`ReviewJobDeps.shutdown`) ends a running review at once, `failed:
 * internal`: its masking and its call in flight are given up, no other call is made and nothing is
 * stored. A stopping server starts no run: the run waits for the next server's job.
 *
 * A job writes to its run only while the run is the start of it that the job made: the
 * `started_at` it set (run-ends.ts, `startedAtIs`). A job that lost its lease and is still alive
 * finds a run that was ended and started again (a `qualor review`) to be another job's: it stops
 * at its next check, and writes no phase, no end, no spend and no store into it.
 *
 * Every end but `superseded` queues the decoration of the analysis in the same transaction
 * (run-ends.ts), so the summary of the merge request says how the review ended. An exception once
 * the run is running ends it `failed: internal`, and the job completes: a review is never tried
 * again into more spend. One before (steps 1 to 5 decide in one transaction, which then wrote
 * nothing) fails the job into its second try, which decides again; on that last try it ends the
 * run `failed: internal` too, so an error that comes every time is said as one. A run whose job is
 * gone for good is ended by the sweep (runs.ts). Nothing the model said, no prompt and no file of
 * the repository is ever logged: the run's id, codes and counts only.
 */

/** The job's lease: a review waits on its provider, call after call; the worker extends it. */
export const REVIEW_LEASE_MS = 20 * 60_000;
/**
 * A review's time in all, from its first conversation (pipeline.ts): three times what a big merge
 * request takes. QUALOR_AI_REVIEW_MAX_MINUTES sets another for a slower model.
 */
export const REVIEW_TIME_BUDGET_MS = 45 * 60_000;

/** The time of a review on this server: QUALOR_AI_REVIEW_MAX_MINUTES, or REVIEW_TIME_BUDGET_MS. */
const reviewTimeBudgetMs = (config: Config): number =>
  config.aiReviewMaxMinutes === null ? REVIEW_TIME_BUDGET_MS : config.aiReviewMaxMinutes * 60_000;

/** The worker's logger; a line that only says what a job left alone goes out at debug, when it can. */
type Logger = WorkerLogger & Partial<Pick<FastifyBaseLogger, 'debug'>>;

/** What the review worker's jobs share: the reviews' (`ai-review`) and the answers' (`ai-reply`). */
export interface ReviewJobDeps {
  db: Db;
  config: Config;
  logger: Logger;
  /**
   * The circuit of reviews and replies (R40): one of their own, keyed by the provider's base URL,
   * apart from the `llm` worker's, so failing reviews never pause explain, triage and fix, and the
   * other way round. A review takes no slot of the organisation's AI requests (R21).
   */
  llmCircuit: LlmRuntime['circuit'];
  scm: DecorationDeps['scm'];
  /**
   * The `scm` worker's per-process state (main.ts): an answer reads its merge request through the
   * organisation's slots and the connection's circuit, and its GitHub client shares the
   * installation tokens and the pacing of mutations. Each job builds its own client, with its own
   * request budget.
   */
  scmRuntime: ScmRuntime;
  /** The recorder a status an answer changes is recorded through, as the system's. */
  audit?: AuditRecorder;
  /**
   * Aborted when the server stops (main.ts), before it waits for its workers: a review takes
   * minutes, and would keep the stop waiting past its grace period. A running review then ends at
   * once, `failed: internal` (the next push reviews again): its masking and its call in flight are
   * given up, and no other call is made. A run not yet started is left waiting for the next server.
   */
  shutdown: AbortSignal;
  /**
   * The clock a run's deadlines are compared with: its snapshot's (the database's clock when left
   * out) and its review's time (Date.now when left out).
   */
  now?: () => Date;
}

const payloadSchema = z.object({ runId: z.uuid() });

class ReviewJob {
  /** What the run spent, counted over its conversations. */
  private readonly ledger: RunLedger;
  /** Why the pipeline was told to stop, once the stop check says so. */
  private readonly state: StopState = { stop: null };
  /** How the run ends. */
  private readonly ender: RunEnder;
  /** The run, once this job has made it `running`: from then on an exception ends it. */
  private started: ReviewRunRow | null = null;

  constructor(
    private readonly deps: ReviewJobDeps,
    private readonly runId: string,
    /** Whether this is the job's last try (its attempts are spent with it). */
    private readonly lastTry: boolean,
  ) {
    this.ledger = new RunLedger(deps);
    this.ender = new RunEnder(deps, this.ledger, this.state);
  }

  async run(): Promise<void> {
    try {
      await this.review();
    } catch (err) {
      const fields = {
        runId: this.runId,
        errorClass: errorClass(err),
        code: pgErrorCode(err) ?? null,
      };
      const running = this.started;
      if (running === null && !this.lastTry) {
        // Steps 1 to 5 wrote nothing: the run is as it was, and the job's next try decides it (a
        // snapshot deleted under the start, say, is found gone then).
        this.deps.logger.warn(fields, 'AI review run not decided; its job is tried again');
        throw err;
      }
      if (running !== null && this.deps.shutdown.aborted) {
        // The stop gave up what the review was waiting on (its masking, say): no error of its own.
        await this.ender.givenUp(running);
        return;
      }
      this.deps.logger.error(fields, 'AI review run failed');
      if (running !== null) {
        await this.ender.endRunning(running, { status: 'failed', reason: 'internal' });
        return;
      }
      // The last try: nothing will try again, so the run ends here rather than be left to the
      // sweep, which would end it for want of a snapshot.
      const [run] = await this.deps.db
        .select({
          id: reviewRuns.id,
          analysisId: reviewRuns.analysisId,
          branchId: reviewRuns.branchId,
        })
        .from(reviewRuns)
        .where(eq(reviewRuns.id, this.runId));
      if (run === undefined) return;
      await endAndDecorate(
        this.deps.db,
        run,
        ['waiting', 'running'],
        { status: 'failed', reason: 'internal' },
        {},
        this.deps.logger,
      );
    }
  }

  // ─── Steps 1 to 5: waiting for the snapshot ─────────────────────────────────

  /**
   * Decides, holding the run's row, whether the run starts, waits on or ends; a run that ends here
   * is decorated in the same transaction. A run that starts is reviewed.
   */
  private async review(): Promise<void> {
    const decided = await this.deps.db.transaction((tx) => decideStart(this.deps, this.runId, tx));
    if (decided.kind === 'ended') {
      logRunEnd(this.deps.logger, this.runId, decided.end);
      return;
    }
    if (decided.kind === 'started') {
      this.started = decided.running.run;
      await this.reviewRunning(decided.running);
    }
  }

  // ─── Steps 6 to 10: the review ──────────────────────────────────────────────

  private async reviewRunning(running: Running): Promise<void> {
    const { db } = this.deps;
    const { run, settings } = running;
    const state = await readMergeRequestState(
      { db, scm: this.deps.scm },
      run.projectId,
      running.mergeRequestId,
    );
    if (state !== null && state.state !== 'open') {
      // R16: a merge request that is merged or closed keeps no copy of its repository.
      await deleteBranchSnapshots(db, run.branchId);
      return this.ender.endRunning(run, { status: 'skipped', reason: 'closed' });
    }
    // A draft is reviewed when a person asked for this run. A push after it makes a run of its own,
    // which nobody asked for.
    if (state?.draft === true && run.requestedBy === null) {
      return this.ender.endRunning(run, { status: 'skipped', reason: 'draft' });
    }

    const opened = run.snapshotId === null ? null : await openSnapshotReader(db, run.snapshotId);
    if (opened === null) {
      // Deleted since it was found ready: a newer push, or the snapshot's retention.
      return this.ender.endRunning(run, { status: 'skipped', reason: 'no_snapshot' });
    }
    const { reader, release } = changesReadOnce(opened);
    const controller = new AbortController();
    // A stop of the server gives up the masking at once, whatever is masked: the review ends.
    const masker = new Masker({ signal: AbortSignal.any([controller.signal, this.deps.shutdown]) });
    try {
      const files = new MaskedFiles(reader, { masker });
      const policy = newToolPolicy({ excludePaths: settings.excludePaths, masked: files, masker });
      const budget = await reviewTokensLeft(db, running);
      const perReview = effectiveReviewBudgets(settings, running.organizationId).maxTokensPerReview;
      // R46: no call of the review sends more than the model's window less its answer.
      const window = settings.provider?.contextWindowTokens ?? DEFAULT_CONTEXT_WINDOW_TOKENS;
      let built: ContextOutcome;
      try {
        built = await runContext(this.deps, running, {
          files,
          masker,
          policy,
          budget,
          perReview,
          window,
        });
      } finally {
        // The patches were read for the context and the digest: nothing else reads them.
        release();
      }
      if (built.kind === 'skipped') {
        return await this.ender.endRunning(
          run,
          { status: 'skipped', reason: built.reason, detail: built.detail },
          { diffDigest: built.digest },
        );
      }
      const { context } = built;

      const key = providerApiKey(settings, this.deps.config.secretKey);
      const { provider: storedProvider } = settings;
      if (!key.ok || storedProvider === null) {
        // The key no longer decrypts (QUALOR_SECRET_KEY changed): no call could be made.
        return await this.ender.endRunning(run, { status: 'failed', reason: 'provider_error' });
      }
      this.ledger.provider = {
        host: new URL(storedProvider.baseUrl).host,
        model: storedProvider.model,
        pricing: settings.pricing,
      };
      const shouldStop = stopCheck(this.deps, running, controller, this.state);
      // The review's time starts with its first conversation.
      const { now: clockOf } = this.deps;
      const now = clockOf === undefined ? Date.now : () => clockOf().getTime();
      const outcome = await runReviewPipeline(
        context,
        budget,
        {
          converse: (role, user, nonce, tokenBudget, accept, modelTier, deadline) =>
            this.ledger.converse(
              { running, storedProvider, reader, policy, context, shouldStop, now },
              { role, user, nonce, tokenBudget, accept, deadline },
              modelTier,
            ),
          providerKey: key.key,
          deadline: now() + reviewTimeBudgetMs(this.deps.config),
          now,
        },
        (phase) => this.ledger.phase(run, phase),
        window,
      );
      await this.ender.finish(running, outcome, { context, files, masker, policy, shouldStop });
    } finally {
      await masker.close();
    }
  }
}

/**
 * The `ai-review` queue's handler (R21): main.ts runs it on a worker of its own, with the reviews'
 * own circuit (R40, `reviewCircuitDeps`), not the `llm` worker's. A payload that does not parse
 * never will: the job completes. A review's job fails into its retry only for an error before its
 * run started, which left the run as it was, and never on its last try; once the run is running, an
 * error ends it `failed: internal` and the job completes, so a review is never run twice.
 */
export function reviewHandlers(deps: ReviewJobDeps): JobHandlers {
  return {
    [AI_REVIEW_QUEUE]: async (job) => {
      const parsed = payloadSchema.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger.warn(
          { jobId: job.id, queue: job.queue },
          'malformed AI review job payload; completing without retry',
        );
        return;
      }
      await new ReviewJob(deps, parsed.data.runId, job.attempts >= job.maxAttempts).run();
    },
  };
}
