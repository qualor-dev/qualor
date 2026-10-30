import { and, eq, inArray, sql } from 'drizzle-orm';
import type { Report } from '@qualor/shared';
import type { FastifyBaseLogger } from 'fastify';
import type { Executor } from '../db/client';
import { analyses, type AnalysisError, type AnalysisWarning } from '../db/schema';
import { scmContextOf } from '../scm/context';

/** The subset of the app logger the job needs. `warn` is for routine-but-worth-a-look conditions
 *  (a malformed job payload); never used at `error` level here — nothing in this module is an
 *  unexpected server fault. */
export type ProcessLogger = Pick<FastifyBaseLogger, 'debug' | 'info' | 'warn'>;

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

/**
 * Ruling S13 #1: guarded the same way as the outer claim in `processAnalysis` — only an
 * analysis still `queued`/`processing` can be flipped to `failed`. Without this, a stale duplicate
 * run (see the row-lock comment in process.ts) whose last attempt fails *after* another run already
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
