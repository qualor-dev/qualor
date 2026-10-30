import { LICENSE_GROUPS, type LicenseGroupId } from '@qualor/shared';
import { and, asc, eq, ilike, sql, type SQL } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { analyses, branchDependencies, projectVersions, versionDependencies } from '../db/schema';
import { containsPattern } from '../issues/query';

/** The filters of the inventory list (6M §8). Every filter narrows; none means the whole list. */
export interface DependencyFilter {
  /** Entries that carry this licence string as one of their licences (exact match). */
  license?: string;
  /** Entries with a licence string that is one of the group's members. */
  group?: LicenseGroupId;
  ecosystem?: string;
  /** `true`: no licence known; `false`: at least one. */
  unknown?: boolean;
  /** `true`: direct dependencies; `false`: the others (transitive, or not known to be direct). */
  direct?: boolean;
  /** A case-insensitive substring of the package name. */
  q?: string;
}

export interface DependencyPage {
  /** 1-based. */
  page: number;
  pageSize: number;
}

/** One inventory entry as the API returns it. */
export interface DependencyRow {
  ecosystem: string;
  path: string;
  line: number | null;
  name: string;
  version: string;
  licenses: string[];
  direct: boolean | null;
}

export interface DependencySummary {
  total: number;
  /** Entries with at least one licence. */
  known: number;
  /** Entries without a licence (`licenses = {}`). */
  unknown: number;
  /** The most frequent licence strings, at most {@link SUMMARY_LICENSES}, by count then name. */
  byLicense: { license: string; count: number }[];
}

export const SUMMARY_LICENSES = 20;

/** The CLI's engine entry for its licence pass (cli/src/analyzers/trivy-licenses.ts). */
const LICENSE_ENGINE_ID = 'trivy-licenses';

/** Whose inventory: a branch's latest snapshot, or a released version's. */
export type DependencyTarget =
  { kind: 'branch'; branchId: string } | { kind: 'version'; versionId: string };

/** The inventory table of the target, and its owner column. */
function tableOf(target: DependencyTarget) {
  return target.kind === 'branch'
    ? { d: branchDependencies, owner: branchDependencies.branchId, id: target.branchId }
    : { d: versionDependencies, owner: versionDependencies.versionId, id: target.versionId };
}

const GROUP_MEMBERS = new Map<LicenseGroupId, readonly string[]>(
  LICENSE_GROUPS.map((g) => [g.id, g.members]),
);

function textArray(values: readonly string[]): SQL {
  return sql`(SELECT coalesce(array_agg(v), '{}'::text[]) FROM jsonb_array_elements_text(${JSON.stringify(values)}::jsonb) AS v)`;
}

/** The condition of a yes-or-no filter: none when it is not given. */
function whenGiven(value: boolean | undefined, yes: SQL, no: SQL): SQL | undefined {
  if (value === undefined) return undefined;
  return value ? yes : no;
}

function dependencyFilter(target: DependencyTarget, f: DependencyFilter): SQL | undefined {
  const { d, owner, id } = tableOf(target);
  return and(
    eq(owner, id),
    f.license === undefined ? undefined : sql`${d.licenses} @> ARRAY[${f.license}]::text[]`,
    f.group === undefined
      ? undefined
      : sql`${d.licenses} && ${textArray(GROUP_MEMBERS.get(f.group) ?? [])}`,
    f.ecosystem === undefined ? undefined : eq(d.ecosystem, f.ecosystem),
    whenGiven(f.unknown, sql`cardinality(${d.licenses}) = 0`, sql`cardinality(${d.licenses}) > 0`),
    whenGiven(f.direct, sql`${d.direct} IS TRUE`, sql`${d.direct} IS NOT TRUE`),
    f.q === undefined ? undefined : ilike(d.name, containsPattern(f.q)),
  );
}

function selectRows(db: Executor, target: DependencyTarget, where: SQL | undefined) {
  const { d } = tableOf(target);
  return db
    .select({
      ecosystem: d.ecosystem,
      path: d.path,
      line: d.line,
      name: d.name,
      version: d.version,
      licenses: d.licenses,
      direct: d.direct,
    })
    .from(d)
    .where(where)
    .orderBy(asc(d.name), asc(d.version), asc(d.path), asc(d.ecosystem));
}

/** One page of an inventory, by name, version, lockfile and ecosystem, and the filtered total. */
export async function listDependencies(
  db: Executor,
  target: DependencyTarget,
  filter: DependencyFilter,
  page: DependencyPage,
): Promise<{ rows: DependencyRow[]; total: number }> {
  const { d } = tableOf(target);
  const where = dependencyFilter(target, filter);
  const [rows, [count]] = await Promise.all([
    selectRows(db, target, where)
      .limit(page.pageSize)
      .offset((page.page - 1) * page.pageSize),
    db
      .select({ total: sql<number>`count(*)::int` })
      .from(d)
      .where(where),
  ]);
  return { rows, total: count?.total ?? 0 };
}

/**
 * Every entry of an inventory that matches `filter`, in the list's order: for a filter
 * SQL cannot apply (the licence policy's verdict). A snapshot holds at most 50 000 entries.
 */
export async function listAllDependencies(
  db: Executor,
  target: DependencyTarget,
  filter: DependencyFilter,
): Promise<DependencyRow[]> {
  return selectRows(db, target, dependencyFilter(target, filter));
}

/** The whole inventory at a glance; filters do not apply. */
export async function dependencySummary(
  db: Executor,
  target: DependencyTarget,
): Promise<DependencySummary> {
  const { d, owner, id } = tableOf(target);
  const [[counts], byLicense] = await Promise.all([
    db
      .select({
        total: sql<number>`count(*)::int`,
        unknown: sql<number>`count(*) FILTER (WHERE cardinality(${d.licenses}) = 0)::int`,
      })
      .from(d)
      .where(eq(owner, id)),
    db.execute<{ license: string; count: number }>(sql`
      SELECT l.license, count(*)::int AS count
      FROM ${d}, unnest(${d.licenses}) AS l(license)
      WHERE ${owner} = ${id}
      GROUP BY l.license
      ORDER BY count DESC, l.license
      LIMIT ${SUMMARY_LICENSES}`),
  ]);
  const total = counts?.total ?? 0;
  const unknown = counts?.unknown ?? 0;
  return {
    total,
    known: total - unknown,
    unknown,
    byLicense: byLicense.rows.map((r) => ({ license: r.license, count: r.count })),
  };
}

/**
 * Whether the target has an inventory snapshot. Rows prove it; without rows, the latest snapshot
 * may still be an empty one: a succeeded analysis (the branch's, or the one the version holds)
 * whose licence pass completed (its `trivy-licenses` engine is `ok`, which is when the report
 * carries `dependencies`).
 */
export async function hasInventory(
  db: Executor,
  target: DependencyTarget,
  rowCount: number,
): Promise<boolean> {
  if (rowCount > 0) return true;
  const licensePassDone = and(
    eq(analyses.status, 'succeeded'),
    sql`${analyses.engines} @> ${JSON.stringify([{ id: LICENSE_ENGINE_ID, status: 'ok' }])}::jsonb`,
  );
  const [row] =
    target.kind === 'branch'
      ? await db
          .select({ id: analyses.id })
          .from(analyses)
          .where(and(eq(analyses.branchId, target.branchId), licensePassDone))
          .limit(1)
      : await db
          .select({ id: analyses.id })
          .from(analyses)
          .innerJoin(projectVersions, eq(projectVersions.analysisId, analyses.id))
          .where(and(eq(projectVersions.id, target.versionId), licensePassDone))
          .limit(1);
  return row !== undefined;
}
