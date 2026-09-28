import { and, asc, desc, eq, isNotNull, ne, sql } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { analyses, type NewCodeDefinition } from '../db/schema';
import type { ProjectRow } from '../projects/access';

const DEFAULT_DAYS = 30;

/** gates.md §5 and the default main-branch definition, also every fallback's. */
export const DEFAULT_NEW_CODE_DEFINITION: NewCodeDefinition = { type: 'days', value: DEFAULT_DAYS };

export interface BaselineAnalysis {
  id: string;
  revision: string;
  analysisDate: Date;
}

/** The warnings a resolved baseline can carry (the response enumerates them). */
export const BASELINE_WARNINGS = [
  'NEW_CODE_DEFINITION_FALLBACK',
  'NEW_CODE_BASELINE_MISSING',
] as const;
export type BaselineWarning = (typeof BASELINE_WARNINGS)[number];

export interface ResolvedBaseline {
  /** The analysis whose revision new code is diffed against; null on the first analysis. */
  baseline: BaselineAnalysis | null;
  /** The project's definition as configured (the default when it has none). */
  definition: NewCodeDefinition;
  /** `NEW_CODE_DEFINITION_FALLBACK` when `previous_version` found no labelled analysis of another
   *  version, and `NEW_CODE_BASELINE_MISSING` when a fixed `analysis` baseline no longer exists. */
  warnings: BaselineWarning[];
}

const columns = {
  id: analyses.id,
  revision: analyses.revision,
  analysisDate: analyses.analysisDate,
  versionLabel: analyses.versionLabel,
};

type Row = { id: string; revision: string | null; analysisDate: Date | null };

function toBaseline(row: Row | undefined): BaselineAnalysis | null {
  if (!row || row.revision === null || row.analysisDate === null) return null;
  return { id: row.id, revision: row.revision, analysisDate: row.analysisDate };
}

const succeededOn = (branchId: string) =>
  and(eq(analyses.branchId, branchId), eq(analyses.status, 'succeeded'));

/** A version label: ingestion stores an empty version as NULL, and a stored '' (a restore, a
 *  hand edit) counts as no label either. */
const hasLabel = and(isNotNull(analyses.versionLabel), ne(analyses.versionLabel, ''));

/**
 * gates.md §5 `days: N`: the oldest succeeded analysis dated within the last N days (database
 * clock). If none is that recent, the most recent analysis (ruling N1): new code is then what
 * changed since the last analysis rather than nothing.
 */
async function byDays(
  tx: Executor,
  branchId: string,
  days: number,
): Promise<BaselineAnalysis | null> {
  const [recent] = await tx
    .select(columns)
    .from(analyses)
    .where(
      and(
        succeededOn(branchId),
        sql`${analyses.analysisDate} >= now() - make_interval(days => ${days})`,
      ),
    )
    .orderBy(asc(analyses.analysisDate), asc(analyses.id))
    .limit(1);
  if (recent) return toBaseline(recent);
  const [latest] = await tx
    .select(columns)
    .from(analyses)
    .where(succeededOn(branchId))
    .orderBy(desc(analyses.analysisDate), desc(analyses.id))
    .limit(1);
  return toBaseline(latest);
}

/**
 * Resolves the new-code baseline of the project's main branch (gates.md §5). `version` is the
 * version the scan is about to report (`?version=`); without it, the latest version label on the
 * main branch stands in for it.
 */
export async function resolveBaseline(
  tx: Executor,
  project: ProjectRow,
  mainBranchId: string,
  version: string | undefined,
): Promise<ResolvedBaseline> {
  const definition = project.newCodeDefinition ?? DEFAULT_NEW_CODE_DEFINITION;
  const [latest] = await tx
    .select(columns)
    .from(analyses)
    .where(succeededOn(mainBranchId))
    .orderBy(desc(analyses.analysisDate), desc(analyses.id))
    .limit(1);
  if (!latest) return { baseline: null, definition, warnings: [] };

  if (definition.type === 'days') {
    return { baseline: await byDays(tx, mainBranchId, definition.value), definition, warnings: [] };
  }
  if (definition.type === 'analysis') {
    const [fixed] = await tx
      .select(columns)
      .from(analyses)
      .where(and(succeededOn(mainBranchId), eq(analyses.id, definition.analysisId)));
    if (fixed) return { baseline: toBaseline(fixed), definition, warnings: [] };
    return {
      baseline: await byDays(tx, mainBranchId, DEFAULT_DAYS),
      definition,
      warnings: ['NEW_CODE_BASELINE_MISSING'],
    };
  }
  // previous_version (ruling U8): unlabelled analyses (untagged commits) are ignored. The current
  // version is ?version, else the latest label; the baseline is the latest labelled analysis of
  // another version. Without one, days: 30 applies with a warning.
  let current = version;
  if (current === undefined) {
    const [labelled] = await tx
      .select({ versionLabel: analyses.versionLabel })
      .from(analyses)
      .where(and(succeededOn(mainBranchId), hasLabel))
      .orderBy(desc(analyses.analysisDate), desc(analyses.id))
      .limit(1);
    current = labelled?.versionLabel ?? undefined;
  }
  const [previous] =
    current === undefined
      ? []
      : await tx
          .select(columns)
          .from(analyses)
          .where(and(succeededOn(mainBranchId), hasLabel, ne(analyses.versionLabel, current)))
          .orderBy(desc(analyses.analysisDate), desc(analyses.id))
          .limit(1);
  if (previous) return { baseline: toBaseline(previous), definition, warnings: [] };
  return {
    baseline: await byDays(tx, mainBranchId, DEFAULT_DAYS),
    definition,
    warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
  };
}
