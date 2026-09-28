import { coverageMeasures, ratio, resolveMetricKey } from '@qualor/shared';
import { and, asc, eq, inArray, ne, sql } from 'drizzle-orm';
import { textList } from '../db/bulk';
import type { Executor } from '../db/client';
import { branchFiles, issues, measures, rules } from '../db/schema';

/** Shown next to every project and branch in list responses (api.md: "headline measures"). */
export const HEADLINE_METRICS = [
  'ncloc',
  'coverage',
  'duplicated_lines_density',
  'issues',
  'security_rating',
  'reliability_rating',
  'new_issues',
  'new_coverage',
  'new_duplicated_lines_density',
] as const;

/** api.md: at most this many points per metric in a history response. */
export const MAX_HISTORY_POINTS = 1_000;

function split(key: string): { metricKey: string; scope: 'overall' | 'new' } {
  return key.startsWith('new_')
    ? { metricKey: key.slice(4), scope: 'new' }
    : { metricKey: key, scope: 'overall' };
}

/** Headline measures by analysis id, keyed like gate metrics (`new_coverage`). */
export async function headlineMeasures(
  db: Executor,
  analysisIds: readonly string[],
): Promise<Map<string, Record<string, number | null>>> {
  const result = new Map<string, Record<string, number | null>>();
  if (analysisIds.length === 0) return result;
  const rows = await db
    .select()
    .from(measures)
    .where(
      and(
        inArray(measures.analysisId, [...analysisIds]),
        inArray(measures.metricKey, [...new Set(HEADLINE_METRICS.map((k) => split(k).metricKey))]),
      ),
    );
  const wanted = new Set<string>(HEADLINE_METRICS);
  for (const row of rows) {
    const key = row.scope === 'new' ? `new_${row.metricKey}` : row.metricKey;
    if (!wanted.has(key)) continue;
    const entry = result.get(row.analysisId) ?? {};
    entry[key] = row.value;
    result.set(row.analysisId, entry);
  }
  return result;
}

/** The latest values of an analysis: `{ metric, overall, new }` per base metric key. */
export async function latestMeasures(
  db: Executor,
  analysisId: string,
  metricKeys: readonly string[],
): Promise<{ metric: string; overall: number | null; new: number | null }[]> {
  const rows = await db
    .select()
    .from(measures)
    .where(and(eq(measures.analysisId, analysisId), inArray(measures.metricKey, [...metricKeys])));
  const value = new Map(rows.map((r) => [`${r.scope}:${r.metricKey}`, r.value]));
  return metricKeys.map((metric) => ({
    metric,
    overall: value.get(`overall:${metric}`) ?? null,
    new: value.get(`new:${metric}`) ?? null,
  }));
}

/** Evenly spaced points, always keeping the first and the last. */
export function downsample<T>(points: readonly T[], max: number): T[] {
  if (points.length <= max) return [...points];
  if (max <= 1) return points.slice(-1);
  const out: T[] = [];
  for (let i = 0; i < max; i++) {
    const point = points[Math.round((i * (points.length - 1)) / (max - 1))];
    if (point !== undefined) out.push(point);
  }
  return out;
}

export interface HistoryPoint {
  analysisId: string;
  date: string;
  value: number | null;
}

interface HistoryRow extends Record<string, unknown> {
  analysis_id: string;
  analysis_date: Date | string;
  metric_key: string;
  scope: string;
  value: number | null;
}

/**
 * Measure history of a branch's succeeded analyses, by analysis date (keys like `new_coverage`).
 * The analyses are downsampled in SQL, in O(1) per analysis, to the same evenly spaced indices as
 * {@link downsample} (first and last kept), so a branch with 100 000 analyses never loads more
 * than `maxPoints` analyses' measures into memory.
 */
export async function measureHistory(
  db: Executor,
  branchId: string,
  keys: readonly string[],
  range: { from?: Date | undefined; to?: Date | undefined },
  maxPoints: number = MAX_HISTORY_POINTS,
): Promise<{ metric: string; points: HistoryPoint[] }[]> {
  const max = Math.max(1, Math.floor(maxPoints));
  const metricKeys = [...new Set(keys.map((k) => split(k).metricKey))];
  const result = await db.execute<HistoryRow>(sql`
    WITH a AS (
      SELECT id, analysis_date,
             (row_number() OVER (ORDER BY analysis_date, id) - 1)::bigint AS i,
             count(*) OVER ()::bigint AS n
        FROM analyses
       WHERE branch_id = ${branchId} AND status = 'succeeded'
         AND (${range.from ?? null}::timestamptz IS NULL
              OR analysis_date >= ${range.from ?? null}::timestamptz)
         AND (${range.to ?? null}::timestamptz IS NULL
              OR analysis_date <= ${range.to ?? null}::timestamptz)
    ), kept AS (
      SELECT id, analysis_date FROM a
       -- A CASE, and NULLIF on each divisor, rather than OR/AND: SQL does not promise to
       -- evaluate OR and AND operands in order, so a division by n - 1 = 0 or max - 1 = 0
       -- guarded only by a sibling operand could still run.
       WHERE CASE
         WHEN n <= ${max} THEN true
         WHEN ${max}::int = 1 THEN i = n - 1
         -- i is kept iff some k in 0..max-1 has round(k * (n-1)/(max-1)) = i. With n > max the
         -- step (n-1)/(max-1) is > 1, so that k can only be round(i * (max-1)/(n-1)): an O(1)
         -- test per row instead of a search over the max indices.
         ELSE round(
                round(i::numeric * (${max}::int - 1) / NULLIF(n - 1, 0))
                  * (n - 1) / NULLIF(${max}::int - 1, 0)
              )::bigint = i
       END
    )
    SELECT kept.id AS analysis_id, kept.analysis_date, m.metric_key, m.scope, m.value
      FROM kept
      JOIN measures m ON m.analysis_id = kept.id
     WHERE m.metric_key IN ${textList(metricKeys)}
     ORDER BY kept.analysis_date, kept.id`);
  return keys.map((metric) => {
    const { metricKey, scope } = split(metric);
    const points = result.rows
      .filter((r) => r.metric_key === metricKey && r.scope === scope)
      .map((r) => ({
        analysisId: r.analysis_id,
        date: new Date(r.analysis_date).toISOString(),
        value: r.value,
      }));
    return { metric, points };
  });
}

/** Whether `key` is a catalog metric key with that scope (`coverage`, `new_coverage`). */
export function isMetricKey(key: string): boolean {
  return resolveMetricKey(key) !== undefined;
}

export interface TreeItem {
  type: 'dir' | 'file';
  name: string;
  path: string;
  language: string | null;
  kind: 'main' | 'test' | null;
  measures: Record<string, number | null>;
}

/** Summed per-file counts: a file's own row, or a directory's main files. */
export interface SummedCounts {
  files: number;
  lines: number | null;
  ncloc: number | null;
  complexity: number | null;
  cognitive_complexity: number | null;
  lines_to_cover: number | null;
  uncovered_lines: number | null;
  conditions_to_cover: number | null;
  uncovered_conditions: number | null;
  duplicated_lines: number | null;
}

type TreeRow = SummedCounts &
  Record<string, unknown> & {
    name: string;
    is_file: boolean;
    language: string | null;
    kind: 'main' | 'test' | null;
  };

/** The measures shown for one tree item or file (gates.md §2 formulas on summed counts). */
export function itemMeasures(row: SummedCounts, issueCount: number): Record<string, number | null> {
  const coverage = coverageMeasures(
    row.lines_to_cover === null
      ? null
      : {
          linesToCover: row.lines_to_cover,
          uncoveredLines: row.uncovered_lines ?? 0,
          conditionsToCover: row.conditions_to_cover ?? 0,
          uncoveredConditions: row.uncovered_conditions ?? 0,
        },
  );
  const lines = row.lines ?? 0;
  return {
    files: row.files,
    lines,
    ncloc: row.ncloc ?? 0,
    complexity: row.complexity ?? 0,
    cognitive_complexity: row.cognitive_complexity ?? 0,
    lines_to_cover: coverage.lines_to_cover,
    uncovered_lines: coverage.uncovered_lines,
    coverage: coverage.coverage,
    duplicated_lines: row.duplicated_lines ?? 0,
    duplicated_lines_density: ratio(row.duplicated_lines ?? 0, lines),
    issues: issueCount,
  };
}

/** The `branch_files.metrics` fields the tree sums (fixed names, never user input). */
const SUMMED_FIELDS = [
  ['lines', 'lines'],
  ['ncloc', 'ncloc'],
  ['complexity', 'complexity'],
  ['cognitiveComplexity', 'cognitive_complexity'],
  ['linesToCover', 'lines_to_cover'],
  ['uncoveredLines', 'uncovered_lines'],
  ['conditionsToCover', 'conditions_to_cover'],
  ['uncoveredConditions', 'uncovered_conditions'],
  ['duplicatedLines', 'duplicated_lines'],
] as const;

const summed = sql.join(
  SUMMED_FIELDS.map(([field, alias]) =>
    sql.raw(
      `sum((metrics->>'${field}')::float8) FILTER (WHERE kind = 'main' OR position('/' in rest) = 0) AS ${alias}`,
    ),
  ),
  sql`, `,
);

/**
 * The direct children of `dir` in the branch's latest file snapshot: directories aggregate their
 * main files (like the branch totals), files show their own values. Keyset-paginated by name in
 * byte order (ruling F1: `sort=name` only in v0).
 */
export async function fileTree(
  db: Executor,
  branchId: string,
  dir: string,
  after: string | undefined,
  limit: number,
): Promise<TreeItem[]> {
  const prefix = dir === '' ? '' : `${dir}/`;
  const result = await db.execute<TreeRow>(sql`
    WITH f AS (
      SELECT substr(path, char_length(${prefix}::text) + 1) AS rest, language, kind, metrics
        FROM branch_files
       WHERE branch_id = ${branchId} AND starts_with(path, ${prefix})
    )
    SELECT split_part(rest, '/', 1) AS name,
           bool_and(position('/' in rest) = 0) AS is_file,
           min(language) FILTER (WHERE position('/' in rest) = 0) AS language,
           min(kind) FILTER (WHERE position('/' in rest) = 0) AS kind,
           (count(*) FILTER (WHERE kind = 'main' OR position('/' in rest) = 0))::int AS files,
           ${summed}
      FROM f
     WHERE ${after === undefined ? sql`true` : sql`split_part(rest, '/', 1) COLLATE "C" > ${after}`}
     GROUP BY split_part(rest, '/', 1)
     ORDER BY split_part(rest, '/', 1) COLLATE "C"
     LIMIT ${limit}`);
  const names = result.rows.map((r) => r.name);
  const counts = new Map<string, number>();
  if (names.length > 0) {
    // Only the issues under the entries of this page are counted.
    const issueRows = await db.execute<{ name: string; n: number }>(sql`
      SELECT split_part(substr(path, char_length(${prefix}::text) + 1), '/', 1) AS name, count(*)::int AS n
        FROM issues
       WHERE branch_id = ${branchId} AND status = 'open' AND duplicate_of_issue_id IS NULL
         AND kind = 'issue' AND starts_with(path, ${prefix})
         AND split_part(substr(path, char_length(${prefix}::text) + 1), '/', 1) IN ${textList(names)}
       GROUP BY 1`);
    for (const r of issueRows.rows) counts.set(r.name, r.n);
  }
  return result.rows.map((r) => ({
    type: r.is_file ? 'file' : 'dir',
    name: r.name,
    path: `${prefix}${r.name}`,
    language: r.is_file ? r.language : null,
    kind: r.is_file ? r.kind : null,
    measures: itemMeasures(r, counts.get(r.name) ?? 0),
  }));
}

/** api.md GET /branches/{id}/file: at most this many issues are listed for one file. */
export const MAX_FILE_ISSUES = 500;

export async function fileDetail(db: Executor, branchId: string, path: string) {
  const [row] = await db
    .select()
    .from(branchFiles)
    .where(and(eq(branchFiles.branchId, branchId), eq(branchFiles.path, path)));
  if (!row) return null;
  const issueRows = await db.execute<{ n: number }>(sql`
    SELECT count(*)::int AS n FROM issues
     WHERE branch_id = ${branchId} AND path = ${path} AND status = 'open'
       AND duplicate_of_issue_id IS NULL AND kind = 'issue'`);
  const m = (row.metrics ?? {}) as Record<string, number | undefined>;
  const measuresOfFile = itemMeasures(
    {
      files: 1,
      lines: m.lines ?? null,
      ncloc: m.ncloc ?? null,
      complexity: m.complexity ?? null,
      cognitive_complexity: m.cognitiveComplexity ?? null,
      lines_to_cover: m.linesToCover ?? null,
      uncovered_lines: m.uncoveredLines ?? null,
      conditions_to_cover: m.conditionsToCover ?? null,
      uncovered_conditions: m.uncoveredConditions ?? null,
      duplicated_lines: m.duplicatedLines ?? null,
    },
    issueRows.rows[0]?.n ?? 0,
  );
  return { row, measures: measuresOfFile };
}

/** The file's issues that are not closed (duplicates included, flagged), by line. */
export async function fileIssues(db: Executor, branchId: string, path: string) {
  const rows = await db
    .select({ issue: issues, ruleKey: rules.key })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .where(and(eq(issues.branchId, branchId), eq(issues.path, path), ne(issues.status, 'closed')))
    .orderBy(asc(issues.startLine), asc(issues.id))
    .limit(MAX_FILE_ISSUES + 1);
  return { rows: rows.slice(0, MAX_FILE_ISSUES), truncated: rows.length > MAX_FILE_ISSUES };
}
