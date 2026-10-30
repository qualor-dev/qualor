import { eq, sql } from 'drizzle-orm';
import type { Report } from '@qualor/shared';
import type { Db } from '../db/client';
import { analyses } from '../db/schema';
import { analysisFields, capWarnings, markFailed, type ProcessLogger } from '../ingest/fields';
import type { ProjectRow } from '../projects/access';
import { upsertVersion } from './store';

type AnalysisRow = typeof analyses.$inferSelect;

/** What a tag scan's ingestion needs of the job's dependencies (`ProcessDeps` has it). */
export interface VersionIngestDeps {
  db: Db;
}

/** The longest version label (`project_versions_label_check`). */
const MAX_LABEL_CHARS = 100;

/** The version a report stands for: `project.version` when not blank, else the tag of a tag scan. */
export function versionLabelOf(report: Report): string | null {
  const version = report.project.version?.trim();
  if (version) return version;
  return report.scm.tag ?? null;
}

/**
 * A tag scan is a project version, not a branch analysis: the version row and its inventory are
 * written, the analysis is released as succeeded with no gate, and no ingestion stage runs (no
 * rules, issues, measures, gate, decoration or notifications).
 */
export async function ingestVersion(
  deps: VersionIngestDeps,
  analysis: AnalysisRow,
  project: ProjectRow,
  report: Report,
  logger: ProcessLogger,
): Promise<void> {
  const analysisId = analysis.id;
  const label = versionLabelOf(report);
  const fields = {
    ...analysisFields(report, null, logger),
    warnings: capWarnings(report.warnings),
  };
  if (label === null || label.length > MAX_LABEL_CHARS) {
    await markFailed(
      deps.db,
      analysisId,
      {
        code: 'VERSION_LABEL_INVALID',
        message: `The version label (project.version, else the tag) must be 1 to ${MAX_LABEL_CHARS} characters`,
      },
      fields,
    );
    return;
  }
  await deps.db.transaction(async (tx) => {
    // As in the branch ingestion: the row lock serialises a duplicate run of this analysis.
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

    // Without an inventory, an existing version keeps the one it has (its packages and ids).
    const version = await upsertVersion(tx, {
      projectId: project.id,
      label,
      source: 'tag',
      tag: report.scm.tag ?? null,
      analysisId,
      analyzedAt: fields.analysisDate,
      ...(report.dependencies !== undefined && {
        inventory: { dependencies: report.dependencies, ignores: report.dependencyIgnores ?? null },
      }),
    });
    // A tag scan never meets 'kept' (only a label write does).
    if (version === 'kept') throw new Error('A tag scan cannot be kept out by a tag version');
    if (version === 'stale') {
      await markFailed(
        tx,
        analysisId,
        {
          code: 'STALE_ANALYSIS',
          message: 'A newer analysis of this version has already been processed',
        },
        fields,
      );
      return;
    }
    const warnings = [...report.warnings];
    if (report.dependencies === undefined) {
      warnings.push({
        code: 'VERSION_WITHOUT_INVENTORY',
        message:
          'The report carries no dependency inventory; the version keeps the packages it had, if any',
      });
    }
    await tx
      .update(analyses)
      .set({
        ...fields,
        versionId: version.id,
        versionLabel: label,
        warnings: capWarnings(warnings),
        gateStatus: 'none',
        status: 'succeeded',
        error: null,
        finishedAt: sql`statement_timestamp()`,
      })
      .where(eq(analyses.id, analysisId));
  });
}
