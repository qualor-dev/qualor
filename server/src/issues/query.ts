import type { IssueKind, Quality, Severity } from '@qualor/shared';
import { and, asc, desc, eq, inArray, isNull, or, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import { textList } from '../db/bulk';
import type { Db, Executor } from '../db/client';
import { issues, rules } from '../db/schema';
import { decodeKeyset, encodeKeyset } from '../http/keyset';
import { hasNoNul } from '../http/schemas';
import type { IssueStatus } from '../tracking/plan';

export const ISSUE_STATUSES = ['open', 'resolved', 'wont_fix', 'false_positive', 'closed'] as const;
export const ISSUE_SORTS = ['severity', 'createdAt', 'path'] as const;
export type IssueSort = (typeof ISSUE_SORTS)[number];
export const ISSUE_FACETS = ['severity', 'quality', 'rule', 'engine', 'status', 'path'] as const;
export type IssueFacet = (typeof ISSUE_FACETS)[number];
/** api.md §3: each facet lists at most this many values. */
export const FACET_LIMIT = 100;
/**
 * At most this many facet queries of one request run at once, so a request asking for all six
 * holds at most three pool connections (the page and two facets), not seven.
 */
export const FACET_CONCURRENCY = 2;

/** `GET /issues` filters: OR within a filter, AND across filters (api.md §3). */
export interface IssueFilters {
  branchId: string;
  statuses: readonly IssueStatus[];
  severities?: readonly Severity[] | undefined;
  qualities?: readonly Quality[] | undefined;
  kinds?: readonly IssueKind[] | undefined;
  ruleKeys?: readonly string[] | undefined;
  engines?: readonly string[] | undefined;
  pathPrefixes?: readonly string[] | undefined;
  inNewCode?: boolean | undefined;
  q?: string | undefined;
  includeDuplicates: boolean;
}

/**
 * An ILIKE pattern matching `q` anywhere: `%`, `_` and `\` in the search text are literal
 * characters (ILIKE's default escape is `\`). Shared by every `q` search (projects, issues).
 */
export function containsPattern(q: string): string {
  return `%${q.replace(/[\\%_]/g, (c) => `\\${c}`)}%`;
}

/**
 * The WHERE clause of a filtered issue list. Rule and engine filters resolve through small
 * subqueries on `rules`, so the issue scan never joins; path filters are literal prefixes
 * (`starts_with`, independent of the column collation); `q` is a case-insensitive substring of
 * the message, served by the trigram index.
 */
export function issueFilter(f: IssueFilters): SQL {
  const conditions: (SQL | undefined)[] = [
    eq(issues.branchId, f.branchId),
    inArray(issues.status, [...f.statuses]),
  ];
  if (f.severities) conditions.push(inArray(issues.severity, [...f.severities]));
  if (f.qualities) conditions.push(inArray(issues.quality, [...f.qualities]));
  if (f.kinds) conditions.push(inArray(issues.kind, [...f.kinds]));
  if (f.ruleKeys) {
    conditions.push(
      sql`${issues.ruleId} IN (SELECT r.id FROM rules r WHERE r.key IN ${textList(f.ruleKeys)})`,
    );
  }
  if (f.engines) {
    conditions.push(
      sql`${issues.ruleId} IN (SELECT r.id FROM rules r WHERE r.engine_id IN ${textList(f.engines)})`,
    );
  }
  if (f.pathPrefixes) {
    conditions.push(or(...f.pathPrefixes.map((p) => sql`starts_with(${issues.path}, ${p})`)));
  }
  if (f.inNewCode !== undefined) conditions.push(eq(issues.inNewCode, f.inNewCode));
  if (f.q !== undefined) conditions.push(sql`${issues.message} ILIKE ${containsPattern(f.q)}`);
  if (!f.includeDuplicates) conditions.push(isNull(issues.duplicateOfIssueId));
  return and(...conditions) ?? sql`true`;
}

const severityCursor = z.strictObject({
  s: z.literal('severity'),
  r: z.number().int().min(0).max(4),
  id: z.uuid(),
});
const createdAtCursor = z.strictObject({ s: z.literal('createdAt'), id: z.uuid() });
/** `p` and `l` go into comparisons with `text` and `integer` columns, so both stay in range. */
const pathCursor = z.strictObject({
  s: z.literal('path'),
  p: z.string().max(4_096).refine(hasNoNul).nullable(),
  l: z.number().int().min(0).max(2_147_483_647).nullable(),
  id: z.uuid(),
});

export interface IssueListRow {
  id: string;
  projectId: string;
  branchId: string;
  ruleKey: string;
  ruleName: string;
  engineId: string;
  severity: string;
  severityRank: number;
  severityOverridden: boolean;
  quality: string;
  kind: string;
  status: string;
  message: string;
  path: string | null;
  startLine: number | null;
  startColumn: number | null;
  endLine: number | null;
  endColumn: number | null;
  inNewCode: boolean;
  duplicateOfIssueId: string | null;
  firstSeenAt: Date;
  resolvedAt: Date | null;
  closedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}

const listColumns = {
  id: issues.id,
  projectId: issues.projectId,
  branchId: issues.branchId,
  ruleKey: rules.key,
  ruleName: rules.name,
  engineId: rules.engineId,
  severity: issues.severity,
  severityRank: issues.severityRank,
  severityOverridden: issues.severityOverridden,
  quality: issues.quality,
  kind: issues.kind,
  status: issues.status,
  message: issues.message,
  path: issues.path,
  startLine: issues.startLine,
  startColumn: issues.startColumn,
  endLine: issues.endLine,
  endColumn: issues.endColumn,
  inNewCode: issues.inNewCode,
  duplicateOfIssueId: issues.duplicateOfIssueId,
  firstSeenAt: issues.firstSeenAt,
  resolvedAt: issues.resolvedAt,
  closedAt: issues.closedAt,
  createdAt: issues.createdAt,
  updatedAt: issues.updatedAt,
};

/**
 * "After (p, l, id)" in the order `path ASC NULLS LAST, start_line ASC NULLS LAST, id ASC`
 * (Postgres' default for ASC, so `issues_path_idx` serves it), as consecutive segments of that
 * order. A single predicate would need ORs for the NULLs (a row comparison is unknown as soon as
 * it meets one), and an OR is only a filter: the scan would walk every row before the cursor.
 * Each segment is one index range instead (`path = p AND (start_line, id) > (l, id)`,
 * `path > p`, ...), so a page deep in the list costs what the first page costs.
 */
function afterPath(p: string | null, l: number | null, id: string): SQL[] {
  const { path, startLine } = issues;
  const nullLineAfter = sql`${startLine} IS NULL AND ${issues.id} > ${id}`;
  if (p === null) {
    return l === null
      ? [sql`${path} IS NULL AND ${nullLineAfter}`]
      : [
          sql`${path} IS NULL AND (${startLine}, ${issues.id}) > (${l}, ${id})`,
          sql`${path} IS NULL AND ${startLine} IS NULL`,
        ];
  }
  const rest = [sql`${path} > ${p}`, sql`${path} IS NULL`];
  return l === null
    ? [sql`${path} = ${p} AND ${nullLineAfter}`, ...rest]
    : [
        sql`${path} = ${p} AND (${startLine}, ${issues.id}) > (${l}, ${id})`,
        sql`${path} = ${p} AND ${startLine} IS NULL`,
        ...rest,
      ];
}

/** A sort order with its decoded cursor: built before any query of the request runs. */
export interface IssueSortPlan {
  /**
   * The rows after the cursor, as predicates for consecutive runs of the sort order: the page is
   * filled from the first, then the next, and so on. One `undefined` segment without a cursor.
   */
  segments: (SQL | undefined)[];
  order: SQL[];
  cursorOf(row: IssueListRow): unknown;
}

/** Decodes and validates the cursor for `sort`: 422 on `query.cursor` if it does not fit. */
export function issueSortPlan(sort: IssueSort, cursor: string | undefined): IssueSortPlan {
  switch (sort) {
    case 'severity': {
      const c = decodeKeyset(cursor, severityCursor);
      return {
        segments: [c ? sql`(${issues.severityRank}, ${issues.id}) > (${c.r}, ${c.id})` : undefined],
        order: [asc(issues.severityRank), asc(issues.id)],
        cursorOf: (row) => ({ s: 'severity', r: row.severityRank, id: row.id }),
      };
    }
    case 'createdAt': {
      // Ids are UUIDv7, so id order is creation order; newest first.
      const c = decodeKeyset(cursor, createdAtCursor);
      return {
        segments: [c ? sql`${issues.id} < ${c.id}` : undefined],
        order: [desc(issues.id)],
        cursorOf: (row) => ({ s: 'createdAt', id: row.id }),
      };
    }
    case 'path': {
      const c = decodeKeyset(cursor, pathCursor);
      return {
        segments: c ? afterPath(c.p, c.l, c.id) : [undefined],
        order: [
          sql`${issues.path} ASC NULLS LAST`,
          sql`${issues.startLine} ASC NULLS LAST`,
          asc(issues.id),
        ],
        cursorOf: (row) => ({ s: 'path', p: row.path, l: row.startLine, id: row.id }),
      };
    }
  }
}

export interface IssuePage {
  items: IssueListRow[];
  nextCursor: string | null;
}

/**
 * One keyset page in the order of `options.plan` (from {@link issueSortPlan}). A plan of several
 * segments (the path sort) reads them in one read-only REPEATABLE READ transaction, so the page is
 * one snapshot: an issue that moves between segments while the page is read (a transition, an
 * ingestion) is neither returned twice nor skipped. `afterSegment` lets tests act between reads.
 */
export async function listIssues(
  db: Db,
  filters: IssueFilters,
  options: { plan: IssueSortPlan; limit: number; afterSegment?: () => Promise<void> },
): Promise<IssuePage> {
  const { plan } = options;
  const where = issueFilter(filters);
  const read = async (executor: Executor): Promise<IssueListRow[]> => {
    // One row more than the page tells whether another page follows.
    const rows: IssueListRow[] = [];
    for (const segment of plan.segments) {
      const wanted = options.limit + 1 - rows.length;
      if (wanted <= 0) break;
      rows.push(
        ...(await executor
          .select(listColumns)
          .from(issues)
          .innerJoin(rules, eq(rules.id, issues.ruleId))
          .where(and(where, segment))
          .orderBy(...plan.order)
          .limit(wanted)),
      );
      await options.afterSegment?.();
    }
    return rows;
  };
  const rows =
    plan.segments.length > 1
      ? await db.transaction(read, { isolationLevel: 'repeatable read', accessMode: 'read only' })
      : await read(db);
  const items = rows.slice(0, options.limit);
  const last = items.at(-1);
  return {
    items,
    nextCursor: rows.length > options.limit && last ? encodeKeyset(plan.cursorOf(last)) : null,
  };
}

export interface FacetValue {
  value: string;
  count: number;
}

const FACET_EXPR: Record<IssueFacet, { expr: SQL; joinsRules: boolean }> = {
  severity: { expr: sql`${issues.severity}`, joinsRules: false },
  quality: { expr: sql`${issues.quality}`, joinsRules: false },
  status: { expr: sql`${issues.status}`, joinsRules: false },
  path: { expr: sql`${issues.path}`, joinsRules: false },
  rule: { expr: sql`${rules.key}`, joinsRules: true },
  engine: { expr: sql`${rules.engineId}`, joinsRules: true },
};

/**
 * Maps `items` with at most `limit` calls of `fn` in flight, keeping the input order. The first
 * failure rejects the whole map, and no call starts after it.
 */
export async function mapConcurrent<T, R>(
  items: readonly T[],
  limit: number,
  fn: (item: T) => Promise<R>,
): Promise<R[]> {
  const results: R[] = [];
  let next = 0;
  let failed = false;
  const worker = async (): Promise<void> => {
    while (!failed && next < items.length) {
      const index = next++;
      try {
        results[index] = await fn(items[index] as T);
      } catch (error) {
        failed = true;
        throw error;
      }
    }
  };
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, worker));
  return results;
}

/**
 * api.md §3/§4: counts per value over the filtered set (one `GROUP BY` per facet, at most
 * {@link FACET_CONCURRENCY} at a time), most frequent first, at most {@link FACET_LIMIT} values
 * each. Issues without a path are not counted in the `path` facet.
 */
export async function issueFacets(
  db: Executor,
  filters: IssueFilters,
  facets: readonly IssueFacet[],
): Promise<Partial<Record<IssueFacet, FacetValue[]>>> {
  const where = issueFilter(filters);
  const entries = await mapConcurrent(facets, FACET_CONCURRENCY, async (facet) => {
    const { expr, joinsRules } = FACET_EXPR[facet];
    const base = db
      .select({ value: sql<string>`${expr}`, count: sql<number>`count(*)::int` })
      .from(issues);
    const joined = joinsRules ? base.innerJoin(rules, eq(rules.id, issues.ruleId)) : base;
    const rows = await joined
      .where(and(where, sql`${expr} IS NOT NULL`))
      .groupBy(expr)
      .orderBy(sql`count(*) DESC`, expr)
      .limit(FACET_LIMIT);
    return [facet, rows] as const;
  });
  return Object.fromEntries(entries);
}
