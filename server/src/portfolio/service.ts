import { sql } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import { z } from 'zod';
import { requireOrganizationAccess, requireUser, type AccessContext } from '../auth/access';
import type { UserPrincipal } from '../auth/principal';
import type { Db, Executor } from '../db/client';
import { pgErrorCode } from '../db/errors';
import { uuidv7Timestamp } from '../db/ids';
import { decodeKeyset, encodeKeyset } from '../http/keyset';
import { notFound, ProblemError, validationFailed } from '../http/problem';
import type { PluginPortfolio } from '../plugins/contract';
import {
  portfolioVulnerabilityFacts,
  type PortfolioVulnerabilityFacts,
} from '../vulnerabilities/portfolio';
import { periods, type Granularity } from './periods';
import {
  activity,
  currentFindings,
  measuresOf,
  organizationOf,
  statesAt,
  transactionNow,
  visibleProjects,
  type BranchState,
  type MeasureValues,
  type VisibleProject,
} from './query';
import type {
  PortfolioAggregate,
  PortfolioOverview,
  PortfolioProjectRow,
  PortfolioScopeInput,
  PortfolioSort,
  Rating,
  SeverityCounts,
} from './types';

export const FEATURE = 'portfolio';
/** Plan 5, V1: the feature that shows the exploited (KEV) numbers. */
const PRIORITY_FEATURE = 'vuln.priority';
/** 4E-2 §1: no succeeded main-branch analysis in this long, or never, is abandoned. */
const ABANDONED_MS = 30 * 86_400_000;
/** 4E-2 §1: each attention list holds this many projects. */
const ATTENTION_SIZE = 10;
/** 4E-2 §2: the statement budget of the reads. */
const STATEMENT_TIMEOUT_MS = 20_000;
const PG_QUERY_CANCELED = '57014';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const RATINGS: readonly Rating[] = ['A', 'B', 'C', 'D', 'E'];
const SEVERITIES = ['blocker', 'high', 'medium', 'low', 'info'] as const;
const GATES = ['passed', 'failed', 'error', 'none'] as const;
/** 4E-2 §2: a page holds 1–100 rows. */
const MAX_PAGE = 100;

/** A project's row at a time, with the quality sums the aggregates need besides the row. */
export interface ProjectState extends PortfolioProjectRow {
  organizationId: string;
  /** Each severity's measure, a missing one null (the row's `bySeverity` is all or nothing). */
  severities: Record<(typeof SEVERITIES)[number], number | null>;
  securityIssues: number | null;
  reliabilityIssues: number | null;
  maintainabilityIssues: number | null;
}

/** A rating 1–5 as A–E; anything else (a missing or a stray value) is null. */
export function ratingOf(value: number | null): Rating | null {
  return value !== null && Number.isInteger(value) && value >= 1 && value <= 5
    ? (RATINGS[value - 1] ?? null)
    : null;
}

/** A cancelled statement (57014: the budget ran out) is 503 PORTFOLIO_TIMEOUT; else as it came. */
export function translateTimeout(err: unknown): unknown {
  return pgErrorCode(err) === PG_QUERY_CANCELED
    ? new ProblemError(503, 'PORTFOLIO_TIMEOUT', 'The portfolio took too long to compute')
    : err;
}

/**
 * 4E-2 §2: one repeatable-read, read-only transaction, so every number comes from the same
 * moment, under a statement budget of `timeoutMs` local to it.
 */
export async function readSnapshot<T>(
  db: Db,
  timeoutMs: number,
  read: (tx: Executor) => Promise<T>,
): Promise<T> {
  try {
    return await db.transaction(
      async (tx) => {
        // SET LOCAL statement_timeout = <ms>, with the value bound as a parameter.
        await tx.execute(sql`SELECT set_config('statement_timeout', ${String(timeoutMs)}, true)`);
        return read(tx);
      },
      { isolationLevel: 'repeatable read', accessMode: 'read only' },
    );
  } catch (err) {
    throw translateTimeout(err);
  }
}

/** §1: the project's row from its state at `at` (absent: never analysed by then). */
function projectState(
  p: VisibleProject,
  branch: BranchState | undefined,
  values: MeasureValues | undefined,
  at: Date,
  findings: { secrets: number; vulnerableDependencies: number } | undefined,
  vulnerabilities: PortfolioVulnerabilityFacts | undefined,
): ProjectState {
  const last = branch === undefined ? null : uuidv7Timestamp(branch.analysisId);
  const m = (key: keyof MeasureValues): number | null =>
    branch === undefined ? null : (values?.[key] ?? null);
  const severities = {
    blocker: m('blocker_issues'),
    high: m('high_issues'),
    medium: m('medium_issues'),
    low: m('low_issues'),
    info: m('info_issues'),
  };
  const bySeverity: SeverityCounts | null = SEVERITIES.every((s) => severities[s] !== null)
    ? (severities as SeverityCounts)
    : null;
  const gate =
    branch === undefined ? null : (GATES.find((g) => g === branch.gateStatus) ?? ('none' as const));
  return {
    organizationId: p.organizationId,
    severities,
    organization: { key: p.organizationKey, name: p.organizationName },
    project: { id: p.id, key: p.key, name: p.name },
    lastAnalysisAt: last === null ? null : new Date(last).toISOString(),
    abandoned: last === null || last < at.getTime() - ABANDONED_MS,
    gate,
    securityRating: ratingOf(m('security_rating')),
    reliabilityRating: ratingOf(m('reliability_rating')),
    ncloc: m('ncloc'),
    coverage: m('coverage'),
    duplication: m('duplicated_lines_density'),
    issues: m('issues'),
    bySeverity,
    newIssues: m('new_issues'),
    secrets: findings?.secrets ?? 0,
    vulnerableDependencies: findings?.vulnerableDependencies ?? 0,
    vulnerableReleases: vulnerabilities?.vulnerableReleases ?? null,
    exploited: vulnerabilities?.exploited ?? null,
    securityIssues: m('security_issues'),
    reliabilityIssues: m('reliability_issues'),
    maintainabilityIssues: m('maintainability_issues'),
  };
}

const ratingCounts = (): Record<Rating, number> => ({ A: 0, B: 0, C: 0, D: 0, E: 0 });

/** The sums and weights the ncloc-weighted shares (coverage, duplication) are made of. */
type Weighted = Record<'coverage' | 'duplication', { sum: number; weight: number }>;

/** Counts one row into the aggregate's counts and sums, and its shares into `weighted`. */
function tally(out: PortfolioAggregate, weighted: Weighted, r: ProjectState): void {
  if (r.lastAnalysisAt !== null) out.analysed += 1;
  if (r.abandoned) out.abandoned += 1;
  if (r.gate !== null) out.gate[r.gate] += 1;
  if (r.securityRating !== null) out.securityRating[r.securityRating] += 1;
  if (r.reliabilityRating !== null) out.reliabilityRating[r.reliabilityRating] += 1;
  out.ncloc += r.ncloc ?? 0;
  for (const key of ['coverage', 'duplication'] as const) {
    const value = r[key];
    if (value !== null && r.ncloc !== null) {
      weighted[key].sum += value * r.ncloc;
      weighted[key].weight += r.ncloc;
    }
  }
  out.issues += r.issues ?? 0;
  for (const s of SEVERITIES) out.bySeverity[s] += r.severities[s] ?? 0;
  out.securityIssues += r.securityIssues ?? 0;
  out.reliabilityIssues += r.reliabilityIssues ?? 0;
  out.maintainabilityIssues += r.maintainabilityIssues ?? 0;
  out.newIssues += r.newIssues ?? 0;
}

/**
 * 4E-2 §1: the aggregates over a set of projects. Nulls are left out of every one; coverage and
 * duplication are weighted by ncloc over the projects that have both, and a share with nothing
 * to divide by is null.
 */
export function aggregate(rows: readonly ProjectState[]): PortfolioAggregate {
  const out: PortfolioAggregate = {
    projects: rows.length,
    analysed: 0,
    abandoned: 0,
    gate: { passed: 0, failed: 0, error: 0, none: 0 },
    passedShare: null,
    securityRating: ratingCounts(),
    reliabilityRating: ratingCounts(),
    ncloc: 0,
    coverage: null,
    duplication: null,
    issues: 0,
    bySeverity: { blocker: 0, high: 0, medium: 0, low: 0, info: 0 },
    securityIssues: 0,
    reliabilityIssues: 0,
    maintainabilityIssues: 0,
    newIssues: 0,
  };
  const weighted: Weighted = {
    coverage: { sum: 0, weight: 0 },
    duplication: { sum: 0, weight: 0 },
  };
  for (const r of rows) tally(out, weighted, r);
  out.passedShare = out.analysed === 0 ? null : out.gate.passed / out.analysed;
  for (const key of ['coverage', 'duplication'] as const) {
    const { sum, weight } = weighted[key];
    out[key] = weight > 0 ? sum / weight : null;
  }
  return out;
}

/** The public row: the state without the fields only the aggregates read. */
function rowOf(s: ProjectState): PortfolioProjectRow {
  return {
    organization: s.organization,
    project: s.project,
    lastAnalysisAt: s.lastAnalysisAt,
    abandoned: s.abandoned,
    gate: s.gate,
    securityRating: s.securityRating,
    reliabilityRating: s.reliabilityRating,
    ncloc: s.ncloc,
    coverage: s.coverage,
    duplication: s.duplication,
    issues: s.issues,
    bySeverity: s.bySeverity,
    newIssues: s.newIssues,
    secrets: s.secrets,
    vulnerableDependencies: s.vulnerableDependencies,
    vulnerableReleases: s.vulnerableReleases,
    exploited: s.exploited,
  };
}

/** R5: code-unit (byte) order, as SQL's `COLLATE "C"`. */
function byteOrder(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

/**
 * The order of two values either of which may be missing: equal ones tie, a missing one goes
 * first (`missing` -1) or last (1), and `present` orders the rest.
 */
function withMissing<T>(
  a: T | null,
  b: T | null,
  missing: 1 | -1,
  present: (a: T, b: T) => number,
): number {
  if (a === b) return 0;
  if (a === null) return missing;
  if (b === null) return -missing;
  return present(a, b);
}

/** Descending, a missing value last. */
const desc = (a: number | null, b: number | null): number => withMissing(a, b, 1, (x, y) => y - x);
const byKey = (a: ProjectState, b: ProjectState): number => byteOrder(a.project.key, b.project.key);
/** blocker_issues + high_issues, a missing one left out; null when both are missing. */
const severe = ({ severities: { blocker, high } }: ProjectState): number | null =>
  blocker === null && high === null ? null : (blocker ?? 0) + (high ?? 0);
const ratingRank = (r: Rating | null): number | null => (r === null ? null : RATINGS.indexOf(r));

function top(
  rows: readonly ProjectState[],
  keep: (s: ProjectState) => boolean,
  order: (a: ProjectState, b: ProjectState) => number,
): PortfolioProjectRow[] {
  return rows
    .filter(keep)
    .sort((a, b) => order(a, b) || byKey(a, b))
    .slice(0, ATTENTION_SIZE)
    .map(rowOf);
}

/** 4E-2 §1: the four attention lists, ties broken by project key. */
function attention(
  rows: readonly ProjectState[],
  priority: boolean,
): PortfolioOverview['attention'] {
  return {
    // V2: without `vuln.priority` nothing hints at KEV.
    exploited: priority
      ? top(
          rows,
          (s) => (s.exploited ?? 0) > 0,
          (a, b) => desc(a.exploited, b.exploited),
        )
      : null,
    failingGates: top(
      rows,
      (s) => s.gate === 'failed',
      (a, b) => desc(severe(a), severe(b)),
    ),
    worstSecurity: top(
      rows,
      // R3: only projects rated B–E need attention.
      (s) => s.securityRating !== null && s.securityRating !== 'A',
      (a, b) =>
        desc(ratingRank(a.securityRating), ratingRank(b.securityRating)) ||
        desc(a.securityIssues, b.securityIssues),
    ),
    mostSevere: top(
      rows,
      // R3: only projects with a blocker or high finding.
      (s) => (severe(s) ?? 0) > 0,
      (a, b) => desc(severe(a), severe(b)),
    ),
    // Never analysed first, then the oldest last analysis.
    abandoned: top(
      rows,
      (s) => s.abandoned,
      (a, b) =>
        withMissing(
          a.lastAnalysisAt,
          b.lastAnalysisAt,
          -1,
          (x, y) => Date.parse(x) - Date.parse(y),
        ),
    ),
  };
}

/** The sum of a count over the rows. */
function total(rows: readonly ProjectState[], key: 'secrets' | 'vulnerableDependencies'): number {
  return rows.reduce((n, r) => n + r[key], 0);
}

/** The sum of the non-null values of a nullable count; null when every row is null. */
function nullableTotal(
  rows: readonly ProjectState[],
  key: 'vulnerableReleases' | 'exploited',
): number | null {
  let sum: number | null = null;
  for (const r of rows) {
    const value = r[key];
    if (value !== null) sum = (sum ?? 0) + value;
  }
  return sum;
}

/** The all scope's organisations: those with a visible project, sorted by key. */
function byOrganization(
  rows: readonly ProjectState[],
): NonNullable<PortfolioOverview['organizations']> {
  const groups = new Map<string, { key: string; name: string; rows: ProjectState[] }>();
  for (const r of rows) {
    const group = groups.get(r.organizationId) ?? { ...r.organization, rows: [] };
    group.rows.push(r);
    groups.set(r.organizationId, group);
  }
  return [...groups]
    .sort(([, a], [, b]) => byteOrder(a.key, b.key))
    .map(([id, g]) => ({ id, key: g.key, name: g.name, ...aggregate(g.rows) }));
}

/** Ascending, a missing value last. */
const ascNullLast = (a: number | null, b: number | null): number =>
  withMissing(a, b, 1, (x, y) => x - y);
/** Ascending, a missing value first. */
const ascNullFirst = (a: string | null, b: string | null): number =>
  withMissing(a, b, -1, byteOrder);
/** A rating as its measure, 1 (A) to 5 (E). */
const ratingValue = (r: Rating | null): number | null =>
  r === null ? null : RATINGS.indexOf(r) + 1;
const GATE_RANK: Record<NonNullable<PortfolioProjectRow['gate']>, number> = {
  failed: 0,
  error: 1,
  none: 2,
  passed: 3,
};

/**
 * One sort of the projects table: the row's sort value (what the cursor carries as `v`), the
 * order of two values, and the schema a cursor's `v` must match. Ties are broken by project id.
 */
interface SortOrder {
  value: (row: PortfolioProjectRow) => unknown;
  compare: (a: unknown, b: unknown) => number;
  schema: z.ZodType;
}

/** A sort over values of type V: `compare` only ever sees `value`'s results or `schema`'s. */
function sortOrder<V>(
  value: (row: PortfolioProjectRow) => V,
  compare: (a: V, b: V) => number,
  schema: z.ZodType<V>,
): SortOrder {
  return { value, compare: compare as (a: unknown, b: unknown) => number, schema };
}

const ratingSchema = z.number().int().min(1).max(5).nullable();
const ratingOrder = (rating: (row: PortfolioProjectRow) => Rating | null): SortOrder =>
  sortOrder((r) => ratingValue(rating(r)), desc, ratingSchema);
const measureOrder = (key: 'issues' | 'ncloc' | 'vulnerableReleases' | 'exploited'): SortOrder =>
  sortOrder((r) => r[key], desc, z.number().nullable());

/** 4E-2 §2: the sorts of the projects table. A missing value sorts last, except where noted. */
const SORTS: Record<PortfolioSort, SortOrder> = {
  key: sortOrder(
    (r): [string, string] => [r.organization.key, r.project.key],
    (a, b) => byteOrder(a[0], b[0]) || byteOrder(a[1], b[1]),
    z.tuple([z.string(), z.string()]),
  ),
  // R11: within a gate status, the worst security rating first (E to A, unrated last). The
  // tie-break is part of the value the cursor carries, so paging never skips or repeats a row.
  gate: sortOrder(
    (r): [number | null, number | null] => [
      r.gate === null ? null : GATE_RANK[r.gate],
      ratingValue(r.securityRating),
    ],
    (a, b) => ascNullLast(a[0], b[0]) || desc(a[1], b[1]),
    z.tuple([z.number().int().min(0).max(3).nullable(), ratingSchema]),
  ),
  security: ratingOrder((r) => r.securityRating),
  reliability: ratingOrder((r) => r.reliabilityRating),
  issues: measureOrder('issues'),
  ncloc: measureOrder('ncloc'),
  // Plan 5, V3: the most first, monitoring off (null) last.
  vulnerableReleases: measureOrder('vulnerableReleases'),
  exploited: measureOrder('exploited'),
  // R12: the lowest coverage first (the projects that need tests), unmeasured last.
  coverage: sortOrder((r) => r.coverage, ascNullLast, z.number().nullable()),
  // Oldest first, and never analysed before all: those are the most stale. The values are
  // toISOString()'s, so byte order is time order.
  lastAnalysis: sortOrder(
    (r) => r.lastAnalysisAt,
    ascNullFirst,
    z.iso.datetime({ precision: 3 }).nullable(),
  ),
};

/** A cursor: the last row's sort value and project id. */
interface Position {
  v: unknown;
  id: string;
}

function sortedRows(rows: readonly ProjectState[], order: SortOrder) {
  const compare = (a: Position, b: Position): number =>
    order.compare(a.v, b.v) || byteOrder(a.id, b.id);
  const entries = rows.map((s) => {
    const row = rowOf(s);
    return { row, at: { v: order.value(row), id: row.project.id } satisfies Position };
  });
  entries.sort((a, b) => compare(a.at, b.at));
  return { entries, compare };
}

/**
 * 4E-2 §2: the core service behind `ctx.portfolio`, computed on request over the projects the
 * caller can read (the filter of `GET /projects`). Every member answers 403 FEATURE_NOT_LICENSED
 * while the feature is inactive. `now` fixes the clock (tests); by default `generatedAt` is the
 * transaction's `now()`.
 */
export function createPortfolioService(deps: {
  db: Db;
  isFeatureActive: (feature: string) => boolean;
  now?: () => Date;
  statementTimeoutMs?: number;
}): PluginPortfolio {
  const { db } = deps;
  const access: AccessContext = { db };
  const timeoutMs = deps.statementTimeoutMs ?? STATEMENT_TIMEOUT_MS;
  if (!Number.isInteger(timeoutMs) || timeoutMs < 1) {
    throw new Error('statementTimeoutMs is a positive whole number of milliseconds');
  }

  const gate = (): void => {
    if (!deps.isFeatureActive(FEATURE)) {
      throw new ProblemError(
        403,
        'FEATURE_NOT_LICENSED',
        `The enterprise feature "${FEATURE}" is not licensed`,
      );
    }
  };

  /**
   * §2 access for a scope: the organisation scope needs `org.read` on it (an invisible or
   * malformed one is 404); the all scope only a signed-in user. Its organisation id, or null.
   */
  const organizationOfScope = async (
    principal: UserPrincipal,
    input: PortfolioScopeInput,
  ): Promise<string | null> => {
    const scope = input as Partial<{ scope: string; organizationId: string }>;
    if (scope.scope === 'all') return null;
    if (scope.scope !== 'organization') {
      throw validationFailed([{ path: 'query.scope', message: 'Use organization or all' }]);
    }
    if (typeof scope.organizationId !== 'string' || !UUID.test(scope.organizationId)) {
      throw notFound('Organization');
    }
    await requireOrganizationAccess(access, principal, scope.organizationId, 'org.read');
    return scope.organizationId;
  };

  const clock = async (tx: Executor): Promise<Date> =>
    deps.now ? deps.now() : await transactionNow(tx);

  /**
   * §1: the states of `visible` at each time in `ends`. `rowsAt(i)` counts only the projects
   * existing by then (R4), unless `all` asks for every one.
   */
  const statesOver = async (tx: Executor, visible: readonly VisibleProject[], ends: Date[]) => {
    const ids = visible.map((p) => p.id);
    const states = await statesAt(tx, ids, ends);
    const analysisIds = [
      ...new Set(states.flatMap((m) => [...m.values()].map((s) => s.analysisId))),
    ];
    const values = await measuresOf(tx, analysisIds);
    const findings = await currentFindings(tx, ids);
    const vulnerabilities = await portfolioVulnerabilityFacts(tx, ids, {
      priority: deps.isFeatureActive(PRIORITY_FEATURE),
    });
    return (i: number, existing: 'existing' | 'all' = 'existing'): ProjectState[] => {
      const end = ends[i];
      if (end === undefined) throw new RangeError(`no state time ${i}`);
      return visible
        .filter((p) => existing === 'all' || p.createdAt.getTime() <= end.getTime())
        .map((p) => {
          const branch = states[i]?.get(p.id);
          return projectState(
            p,
            branch,
            branch === undefined ? undefined : values.get(branch.analysisId),
            end,
            findings.get(p.id),
            vulnerabilities.get(p.id),
          );
        });
    };
  };

  /** The current rows of every project in the scope the caller can read, in one snapshot. */
  const currentRows = (principal: UserPrincipal, organizationId: string | null) =>
    readSnapshot(db, timeoutMs, async (tx) => {
      const now = await clock(tx);
      const visible = await visibleProjects(tx, principal.user, organizationId);
      return (await statesOver(tx, visible, [now]))(0, 'all');
    });

  const overview: PluginPortfolio['overview'] = async (request, input, options) => {
    gate();
    const principal = requireUser(request, 'read');
    const granularity = (options as Partial<{ granularity: Granularity }> | undefined)?.granularity;
    if (granularity !== 'week' && granularity !== 'month') {
      throw validationFailed([{ path: 'query.granularity', message: 'Use week or month' }]);
    }
    const organizationId = await organizationOfScope(principal, input);

    const priority = deps.isFeatureActive(PRIORITY_FEATURE);
    return readSnapshot(db, timeoutMs, async (tx): Promise<PortfolioOverview> => {
      const generatedAt = await clock(tx);
      const organization =
        organizationId === null ? null : await organizationOf(tx, organizationId);
      if (organizationId !== null && organization === null) throw notFound('Organization');
      const visible = await visibleProjects(tx, principal.user, organizationId);
      const buckets = periods(generatedAt, granularity);
      const rowsAt = await statesOver(
        tx,
        visible,
        buckets.map((b) => b.end),
      );
      const counts = await activity(
        tx,
        visible.map((p) => p.id),
        [...buckets.map((b) => b.start), generatedAt],
      );

      // The last bucket ends at generatedAt: its state is the state now, over every visible project.
      const now = rowsAt(buckets.length - 1, 'all');
      return {
        generatedAt: generatedAt.toISOString(),
        scope: { kind: organization === null ? 'all' : 'organization', organization },
        granularity,
        totals: {
          ...aggregate(now),
          secrets: total(now, 'secrets'),
          vulnerableDependencies: total(now, 'vulnerableDependencies'),
          vulnerableReleases: nullableTotal(now, 'vulnerableReleases'),
          exploited: nullableTotal(now, 'exploited'),
        },
        organizations: organization === null ? byOrganization(now) : null,
        trend: buckets.map((b, i) => ({
          start: b.start.toISOString(),
          end: b.end.toISOString(),
          ...aggregate(rowsAt(i)),
          analyses: counts.analyses[i] ?? 0,
          triage: counts.triage[i] ?? 0,
        })),
        attention: attention(now, priority),
      };
    });
  };

  /**
   * 4E-2 §2: one page of the current rows in `sort` order, after the cursor's row. The page is
   * cut here, after the scope's whole current state: one state query, over at most a few
   * thousand projects.
   */
  const projectsPage: PluginPortfolio['projects'] = async (request, input, page) => {
    gate();
    const principal = requireUser(request, 'read');
    const { sort, cursor, limit } = page as Partial<typeof page>;
    const order = typeof sort === 'string' && Object.hasOwn(SORTS, sort) ? SORTS[sort] : undefined;
    if (order === undefined) {
      throw validationFailed([
        { path: 'query.sort', message: `Use one of ${Object.keys(SORTS).join(', ')}` },
      ]);
    }
    if (typeof limit !== 'number' || !Number.isInteger(limit) || limit < 1 || limit > MAX_PAGE) {
      throw validationFailed([
        { path: 'query.limit', message: `limit is a whole number from 1 to ${MAX_PAGE}` },
      ]);
    }
    const after = decodeKeyset(cursor, z.strictObject({ v: order.schema, id: z.uuid() }));
    const organizationId = await organizationOfScope(principal, input);

    const { entries, compare } = sortedRows(await currentRows(principal, organizationId), order);
    const first = after === undefined ? 0 : entries.findIndex((e) => compare(e.at, after) > 0);
    const rest = first < 0 ? [] : entries.slice(first);
    const items = rest.slice(0, limit);
    const last = items.at(-1);
    return {
      items: items.map((e) => e.row),
      nextCursor: rest.length > items.length && last ? encodeKeyset(last.at) : null,
    };
  };

  /**
   * 4E-2 §2: every current row of the scope, by key (organisation, then project). Computed once,
   * in one snapshot that is closed before the first row is yielded, so a slow reader holds no
   * connection. The checks run on the first `next()`.
   */
  async function* exportRows(
    request: FastifyRequest,
    input: PortfolioScopeInput,
  ): AsyncGenerator<PortfolioProjectRow> {
    gate();
    const principal = requireUser(request, 'read');
    const organizationId = await organizationOfScope(principal, input);
    const { entries } = sortedRows(await currentRows(principal, organizationId), SORTS.key);
    for (const e of entries) yield e.row;
  }

  return Object.freeze({
    overview,
    projects: projectsPage,
    exportRows,
  } satisfies PluginPortfolio);
}
