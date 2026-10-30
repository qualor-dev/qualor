import { and, eq, inArray, sql } from 'drizzle-orm';
import type { Report } from '@qualor/shared';
import type { FastifyBaseLogger } from 'fastify';
import type { UploadLimits } from '../config';
import type { Db, Executor, Tx } from '../db/client';
import { first } from '../db/rows';
import {
  analyses,
  analysisReports,
  branches,
  projects,
  type AnalysisError,
  type AnalysisWarning,
  type FieldIssue,
} from '../db/schema';
import { communityLimits, type Limits } from '../limits';
import { notifyAnalysisFailed, type BranchHint } from '../notifications/analysis';
import type { NotifyDeps } from '../notifications/deps';
import type { ProjectRow } from '../projects/access';
import { decodeStoredReport } from './decode';
import { ANALYSIS_QUEUE } from './service';
import type { IngestionState } from './state';
import { scmContextOf } from '../scm/context';
import { ingestVersion } from '../versions/ingest';

type BranchRow = typeof branches.$inferSelect;
type AnalysisRow = typeof analyses.$inferSelect;

/** The subset of the app logger the job needs. `warn` is for routine-but-worth-a-look conditions
 *  (a malformed job payload); never used at `error` level here — nothing in this module is an
 *  unexpected server fault. */
export type ProcessLogger = Pick<FastifyBaseLogger, 'debug' | 'info' | 'warn'>;

const SILENT_LOGGER: ProcessLogger = {
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
};

export interface IngestionContext {
  readonly tx: Tx;
  readonly analysisId: string;
  /** The analysis row as claimed for this run (`status: 'processing'`). */
  readonly analysis: AnalysisRow;
  readonly project: ProjectRow;
  readonly branch: BranchRow;
  /** The branch's latest succeeded analysis before this one (`branches.last_analysis_id`), or
   *  null on its first analysis. */
  readonly previousAnalysis: AnalysisRow | null;
  readonly report: Report;
  /** Stages may append; stored on the analysis when it succeeds. */
  readonly warnings: AnalysisWarning[];
  readonly logger: ProcessLogger;
  /** mail E3: how project notifications are queued; null when the caller queues none (tests). */
  readonly notify: NotifyDeps | null;
  /** Values earlier stages hand to later ones (see state.ts). */
  readonly state: IngestionState;
  /** The edition's limits when the ingestion began (enterprise.md §7). */
  readonly limits: Limits;
}

/**
 * Thrown by a stage for a deterministic rejection of the report (retrying cannot help): the
 * ingestion transaction rolls back, the analysis is marked `failed` with this code, message and
 * `errors`, and the job completes without a retry. Any other error is treated as transient and
 * retried (then PROCESSING_ERROR).
 */
export class AnalysisFailure extends Error {
  readonly code: string;
  readonly errors: FieldIssue[] | undefined;

  constructor(code: string, message: string, errors?: FieldIssue[]) {
    super(message);
    this.name = 'AnalysisFailure';
    this.code = code;
    this.errors = errors;
  }

  toAnalysisError(): AnalysisError {
    return {
      code: this.code,
      message: this.message,
      ...(this.errors === undefined ? {} : { errors: this.errors }),
    };
  }
}

export interface IngestionStage {
  readonly name: string;
  run(ctx: IngestionContext): Promise<void>;
}

/** Ruling S13 #4: a stage may misbehave and push far more warnings than anyone will read; cap the
 *  total stored on the analysis and summarise the rest instead of growing `analyses.warnings`
 *  without bound. */
export const MAX_WARNINGS = 100;

export function capWarnings(warnings: readonly AnalysisWarning[]): AnalysisWarning[] {
  if (warnings.length <= MAX_WARNINGS) return [...warnings];
  const dropped = warnings.length - (MAX_WARNINGS - 1);
  return [
    ...warnings.slice(0, MAX_WARNINGS - 1),
    {
      code: 'WARNINGS_TRUNCATED',
      message: `${dropped} additional warning(s) were omitted`,
      count: dropped,
    },
  ];
}

export interface ProcessDeps {
  db: Db;
  upload: UploadLimits;
  stages: readonly IngestionStage[];
  logger?: ProcessLogger;
  notify?: NotifyDeps | undefined;
  /** The edition's limits (main.ts: `edition.limits`); the community limits without it. */
  limits?: (() => Limits) | undefined;
}

type BranchTarget =
  | { kind: 'branch'; name: string }
  | { kind: 'merge_request'; name: string; sourceBranch: string; targetBranch: string };

function branchTarget(report: Report): BranchTarget | null {
  const mr = report.scm.mergeRequest;
  if (mr)
    return {
      kind: 'merge_request',
      name: mr.id,
      sourceBranch: mr.sourceBranch,
      targetBranch: mr.targetBranch,
    };
  return report.scm.branch ? { kind: 'branch', name: report.scm.branch } : null;
}

/** mail E3: the branch a decoded report names, for the failure email (the branch row may not exist). */
function branchHintOf(project: ProjectRow, target: BranchTarget | null): BranchHint | null {
  if (!target) return null;
  return {
    name: target.name,
    kind: target.kind,
    isMain: target.kind === 'branch' && target.name === project.mainBranchName,
  };
}

/** The analysis columns a report fills (also the webhook payload's view of them, webhooks/stage.ts). */
export function analysisFields(
  report: Report,
  branchId: string | null,
  logger?: Pick<FastifyBaseLogger, 'warn'>,
) {
  return {
    branchId,
    // The report's ignore list for vulnerability monitoring; NULL when it carried none.
    dependencyIgnores: report.dependencyIgnores ?? null,
    // scm.md §7: what a later re-evaluation needs of the report, which is not kept.
    scmContext: scmContextOf(report, logger),
    revision: report.scm.revision,
    baselineRevision: report.scm.baseline.revision,
    baselineStatus: report.scm.baseline.status,
    // An empty version is no version (gates.md §5): stored as NULL, so `previous_version` never
    // takes "" for a label.
    versionLabel: report.project.version === '' ? null : (report.project.version ?? null),
    analysisDate: new Date(report.analysisDate),
    scannerVersion: report.scanner.version,
    engines: report.engines.map((e) => ({
      id: e.id,
      kind: e.kind,
      version: e.version ?? null,
      status: e.status,
      reason: e.reason ?? null,
      durationMs: e.durationMs,
      ...(e.database !== undefined && { database: e.database }),
    })),
  };
}

async function upsertBranch(tx: Tx, project: ProjectRow, target: BranchTarget): Promise<BranchRow> {
  const mr =
    target.kind === 'merge_request'
      ? { mrSourceBranch: target.sourceBranch, mrTargetBranch: target.targetBranch }
      : {};
  return first(
    await tx
      .insert(branches)
      .values({ projectId: project.id, kind: target.kind, name: target.name, isMain: false, ...mr })
      .onConflictDoUpdate({
        target: [branches.projectId, branches.kind, branches.name],
        set: { ...mr, updatedAt: sql`now()` },
      })
      .returning(),
  );
}

/**
 * Ruling S13 #1: guarded the same way as the outer claim in {@link processAnalysis} — only an
 * analysis still `queued`/`processing` can be flipped to `failed`. Without this, a stale duplicate
 * run (see the row-lock comment below) whose last attempt fails *after* another run already
 * committed `succeeded` would silently overwrite a correct, already-visible result.
 */
export async function markFailed(
  db: Executor,
  analysisId: string,
  error: AnalysisError,
  fields: Partial<typeof analyses.$inferInsert> = {},
): Promise<boolean> {
  const changed = await db
    .update(analyses)
    // gates.md §6: "if ingestion itself fails, gate_status = 'error'" (ruling G4).
    .set({ ...fields, status: 'failed', error, gateStatus: 'error', finishedAt: sql`now()` })
    .where(and(eq(analyses.id, analysisId), inArray(analyses.status, ['queued', 'processing'])))
    .returning({ id: analyses.id });
  // mail E3: callers notify only when this call failed the analysis.
  return changed.length > 0;
}

const ABANDONED_JOB_ERROR: AnalysisError = {
  code: 'PROCESSING_ERROR',
  message:
    'The processing job was abandoned (the worker crashed, or its lease simply expired without it ever reporting failure) after exhausting its retries',
};

/**
 * Ruling S13 #2: a worker that crashes — or whose lease expires while it is still alive but too
 * slow — never runs `jobHandlers`' catch block, so `markFailed` never gets called for it. The
 * queue's reaper (`reapExpiredLeases`) still notices the expired lease and moves the job straight
 * to `'dead'` once its attempts are exhausted, but nothing then tells the analysis that its job is
 * never coming back — it would stay `'queued'`/`'processing'` forever. Call this after every reap
 * cycle (see `queue/worker.ts`'s `afterReap`) to sweep every analysis whose ingest job already
 * went `'dead'` behind its back. Idempotent: an analysis already `failed`/`succeeded` is excluded
 * by the same `status IN ('queued','processing')` guard as everywhere else here. Returns the ids
 * it failed, so the caller can notify each (mail E3).
 */
export async function reconcileDeadAnalyses(db: Executor): Promise<string[]> {
  const result = await db.execute<{ id: string }>(sql`
    UPDATE analyses a
       SET status = 'failed',
           error = ${JSON.stringify(ABANDONED_JOB_ERROR)}::jsonb,
           gate_status = 'error',
           finished_at = now(),
           updated_at = now()
      FROM jobs j
     WHERE j.queue = ${ANALYSIS_QUEUE}
       AND j.status = 'dead'
       -- Compared as text: a malformed payload must not make the cast (and the whole sweep) fail.
       AND j.payload ->> 'analysisId' = a.id::text
       AND a.status IN ('queued', 'processing')
    RETURNING a.id
  `);
  return result.rows.map((row) => row.id);
}

/**
 * Validates the stored report and finishes the analysis. Deterministic rejections mark the
 * analysis failed and return; unexpected errors propagate so the job is retried.
 *
 * At-least-once delivery: re-running this for an analysis that already left 'queued'/'processing'
 * (succeeded or failed) is a no-op — the guard update below matches no row and this returns
 * immediately. It also tolerates the project (and therefore this analysis row, and its stored
 * report) having been deleted after upload — `analyses.project_id` and
 * `analysis_reports.analysis_id` both cascade on delete, so a queued job can outlive the row it
 * refers to; that is not a processing failure, so the job still completes rather than retrying
 * into 'dead' (progress.md Task 9 carry-over).
 */
export async function processAnalysis(deps: ProcessDeps, analysisId: string): Promise<void> {
  const { db } = deps;
  const logger = deps.logger ?? SILENT_LOGGER;
  // 'processing' is re-claimable: a worker may have died mid-run.
  const [analysis] = await db
    .update(analyses)
    .set({ status: 'processing', startedAt: sql`now()` })
    .where(and(eq(analyses.id, analysisId), inArray(analyses.status, ['queued', 'processing'])))
    .returning();
  if (!analysis) {
    logger.debug(
      { analysisId },
      'skipping analysis job: no queued/processing analysis with this id (already finished, or its project was deleted)',
    );
    return;
  }
  /** Fails the analysis; when this call changed it, mails its watchers (mail E3). */
  const fail = async (
    error: AnalysisError,
    options: { fields?: Partial<typeof analyses.$inferInsert>; hint?: BranchHint | null } = {},
  ): Promise<void> => {
    if (!(await markFailed(db, analysisId, error, options.fields))) return;
    if (deps.notify) {
      await notifyAnalysisFailed(
        db,
        deps.notify,
        { analysisId, branchHint: options.hint ?? null },
        logger,
      );
    }
  };
  // Defensive, not currently reachable: `analyses.project_id` references `projects.id` ON DELETE
  // CASCADE, so a deleted project takes this very analysis row down with it — the `!analysis`
  // check above already caught that case. Kept in case a future migration relaxes that FK (e.g.
  // to ON DELETE SET NULL), which would make this reachable again.
  const [project] = await db.select().from(projects).where(eq(projects.id, analysis.projectId));
  if (!project) {
    logger.info(
      { analysisId, projectId: analysis.projectId },
      'skipping analysis job: its project no longer exists',
    );
    return;
  }
  const [stored] = await db
    .select()
    .from(analysisReports)
    .where(eq(analysisReports.analysisId, analysisId));
  if (!stored) {
    logger.info(
      { analysisId },
      'the uploaded report is no longer stored; marking the analysis failed',
    );
    return fail({
      code: 'REPORT_MISSING',
      message: 'The uploaded report is no longer stored',
    });
  }

  const decoded = decodeStoredReport(stored.body, deps.upload, logger);
  if (!decoded.ok) return fail(decoded.error);
  const report = decoded.report;
  if (report.project.key !== project.key) {
    return fail(
      {
        code: 'PROJECT_KEY_MISMATCH',
        message: `The report is for project "${report.project.key}" but was uploaded to "${project.key}"`,
      },
      { hint: branchHintOf(project, branchTarget(report)) },
    );
  }
  const target = branchTarget(report);
  if (!target) {
    // A tag scan is a project version (vulnerability monitoring, 0.15); nothing else lacks a branch.
    if (report.scm.tag) return ingestVersion(deps, analysis, project, report, logger);
    return fail({
      code: 'BRANCH_REQUIRED',
      message:
        'The report names no branch, merge request or tag (a detached checkout?). Scanners from 0.15 record a tag scan as a version.',
    });
  }

  try {
    await ingest(deps, analysis, project, report, target, logger);
  } catch (err) {
    if (!(err instanceof AnalysisFailure)) throw err;
    // The ingestion transaction (branch upsert included) has rolled back; record what the report
    // said, without the branch, which may not exist.
    logger.info({ analysisId, code: err.code }, 'an ingestion stage rejected the analysis');
    await fail(err.toAnalysisError(), {
      fields: { ...analysisFields(report, null), warnings: capWarnings(report.warnings) },
      hint: branchHintOf(project, target),
    });
  }
}

async function ingest(
  deps: ProcessDeps,
  analysis: AnalysisRow,
  project: ProjectRow,
  report: Report,
  target: BranchTarget,
  logger: ProcessLogger,
): Promise<void> {
  const analysisId = analysis.id;
  await deps.db.transaction(async (tx) => {
    // Ruling S13 #1: the outer guard update above accepts both 'queued' and 'processing' (to
    // re-claim a run whose worker actually died), which means a second call for the same
    // analysisId — e.g. a lease that expired while the first worker was merely slow, not dead,
    // so a second worker also passed that same guard — sails through it too: Postgres doesn't
    // care that the row was already 'processing'. Only this row lock actually serialises the two:
    // whichever transaction gets here first holds it until it commits; the other blocks, then
    // (under READ COMMITTED) sees the just-committed row on wake and finds status is no longer
    // 'processing' — so it no-ops instead of re-running stages or re-deriving a result that
    // already committed.
    // FOR NO KEY UPDATE, not FOR UPDATE (6I-2): it conflicts with itself, so the duplicate run
    // still waits here, and with FOR SHARE (a review snapshot's link reads the analysis as this
    // transaction commits it, review/snapshot-store.ts); but not with the FOR KEY SHARE of a
    // foreign-key check, so a row inserted meanwhile that references this analysis (its review
    // snapshot, uploaded right after the report) never waits out the whole ingestion. The
    // ingestion's own updates of the row change no key column, so they hold this level too.
    await tx
      .select({ id: analyses.id })
      .from(analyses)
      .where(eq(analyses.id, analysisId))
      .for('no key update');
    const [current] = await tx
      .select({ status: analyses.status })
      .from(analyses)
      .where(eq(analyses.id, analysisId));
    if (!current || current.status !== 'processing') return;

    const branch = await upsertBranch(tx, project, target);
    const fields = analysisFields(report, branch.id, logger);
    let previousAnalysis: AnalysisRow | null = null;
    if (branch.lastAnalysisId) {
      [previousAnalysis = null] = await tx
        .select()
        .from(analyses)
        .where(eq(analyses.id, branch.lastAnalysisId));
      if (
        previousAnalysis?.analysisDate &&
        fields.analysisDate.getTime() < previousAnalysis.analysisDate.getTime()
      ) {
        await markFailed(
          tx,
          analysisId,
          {
            code: 'STALE_ANALYSIS',
            message: 'A newer analysis of this branch has already been processed',
          },
          { ...fields, warnings: capWarnings(report.warnings) },
        );
        return;
      }
    }
    const ctx: IngestionContext = {
      tx,
      analysisId,
      analysis,
      project,
      branch,
      previousAnalysis,
      report,
      warnings: [...report.warnings],
      logger,
      notify: deps.notify ?? null,
      state: {},
      limits: deps.limits?.() ?? communityLimits(),
    };
    for (const stage of deps.stages) await stage.run(ctx);
    // The database clock, like every stored time (retention compares finished_at with now()).
    // statement_timestamp(), not now(): now() is the transaction start, which would understate
    // how long a long ingestion took. The webhook stage takes it first (ctx.state.finishedAt), so
    // its payload carries exactly the finished_at stored here.
    const finishedAt = ctx.state.finishedAt ?? sql`statement_timestamp()`;
    await tx
      .update(analyses)
      .set({
        ...fields,
        warnings: capWarnings(ctx.warnings),
        status: 'succeeded',
        error: null,
        finishedAt,
      })
      .where(eq(analyses.id, analysisId));
    await tx
      .update(branches)
      .set({ lastAnalysisId: analysisId, lastAnalyzedAt: finishedAt })
      .where(eq(branches.id, branch.id));
  });
}
