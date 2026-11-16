import {
  inventoryName,
  inventoryVersion,
  isOsPackageType,
  osFamilyOf,
  parsePurl,
  type SbomDistribution,
} from '@qualor/shared';
import { sql, type SQL } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { projects } from '../db/schema';
import { validationFailed } from '../http/problem';
import { containsPattern, likeLiteral } from '../issues/query';
import { distributionOf } from '../versions/distribution';
import { ecosystemsOfType, matchKeyOf, purlTypeOf } from '../vulnerabilities/purl';
import { scopedRows } from '../vulnerabilities/summary';

/** What `GET /packages/usages` asks (spec §6.8): `q` trimmed, the rest as the route checked it. */
export interface UsagesQuery {
  /** A purl when it starts with `pkg:`, else a package name. */
  q: string;
  /** A purl type: every ecosystem that maps to it. */
  ecosystem?: string;
  /** Exact. */
  version?: string;
  page: number;
  pageSize: number;
}

/** One package in one branch or version of a project. */
export interface UsageRow {
  project: { id: string; key: string; name: string };
  target: { kind: 'branch' | 'version'; id: string; name: string; main: boolean };
  ecosystem: string;
  purlType: string | null;
  name: string;
  version: string;
  path: string;
  direct: boolean | null;
  /** The operating system of an SBOM version; null on a branch and on other versions. */
  distribution: SbomDistribution | null;
  /**
   * Open vulnerabilities of the package in the target, as the Vulnerabilities tab counts them;
   * null when the package is not checked or the target has no re-check result.
   */
  vulnerabilities: number | null;
}

export interface UsagesAnswer {
  rows: UsageRow[];
  page: number;
  pageSize: number;
  /** The matching rows, at most {@link USAGES_TOTAL_CAP}. */
  total: number;
  /** More rows match than `total` says. */
  totalCapped: boolean;
}

/** The most rows `total` counts: 100 pages of 100. */
export const USAGES_TOTAL_CAP = 10_000;

/** Names shorter than this match whole (npm has `qs` and `ms`), longer ones anywhere. */
const CONTAINS_FROM = 3;
const PURL_PREFIX = /^pkg:/i;
const NUMERIC = /^\d+$/;

export const NOT_A_PURL =
  'Not a package URL: give pkg:type/namespace/name@version, or a name without pkg:';

/** What `q` searches the inventories for ({@link usageSearchOf}). */
export type UsageSearch =
  /** An ILIKE pattern over the name, its wildcards escaped. */
  | { kind: 'name'; pattern: string }
  | {
      kind: 'purl';
      /** The purl's type and every ecosystem that maps to it. */
      ecosystems: string[];
      /** As an inventory row stores it (`inventoryName`). */
      name: string;
      /** As stored (`inventoryVersion`: deb and rpm fold the `epoch` qualifier in); any when null. */
      version: string | null;
      /** The OS family a deb, rpm or apk package's version must have (ruling R7); any when null. */
      family: string | null;
      /** PyPI names compare as `purlOf` writes them (ruling R1). */
      pypi: boolean;
    };

/**
 * The search `q` asks for, or null for a `pkg:` value that is no package URL, or whose deb or rpm
 * `epoch` is not a number. A name of 3 or more characters matches anywhere in a name, a shorter
 * one a whole name, both ignoring case; `%`, `_` and `\` are literal. A purl matches its type's
 * ecosystems, its name and its version (when it has one) exactly; qualifiers other than `epoch`
 * are ignored.
 */
export function usageSearchOf(q: string): UsageSearch | null {
  if (!PURL_PREFIX.test(q)) {
    const short = Array.from(q).length < CONTAINS_FROM;
    return { kind: 'name', pattern: short ? likeLiteral(q) : containsPattern(q) };
  }
  const purl = parsePurl(q);
  if (purl === null) return null;
  const epoch = purl.qualifiers.epoch;
  if ((purl.type === 'deb' || purl.type === 'rpm') && epoch !== undefined && !NUMERIC.test(epoch)) {
    return null;
  }
  return {
    kind: 'purl',
    ecosystems: ecosystemsOfType(purl.type),
    name: inventoryName(purl),
    version: inventoryVersion(purl),
    family:
      isOsPackageType(purl.type) && purl.namespace !== null
        ? osFamilyOf(purl.namespace).family
        : null,
    pypi: purl.type === 'pypi',
  };
}

/**
 * The name condition on `d.name`, in a form the GIN trigram index on `name` serves: ILIKE, or
 * equality (PostgreSQL 14+). A PyPI name is matched as `purlOf` writes it, lowercase with `_` as
 * `-`: the ILIKE, each `-` a one-character wildcard, finds the candidates by the index, and the
 * second condition keeps the exact ones.
 */
function nameCondition(search: UsageSearch): SQL {
  if (search.kind === 'name') return sql`d.name ILIKE ${search.pattern}`;
  if (!search.pypi) return sql`d.name = ${search.name}`;
  const candidates = likeLiteral(search.name).replaceAll('-', '_');
  return sql`d.name ILIKE ${candidates} AND lower(replace(d.name, '_', '-')) = ${search.name}`;
}

const textArray = (values: readonly string[]): SQL => sql`${sql.param(values)}::text[]`;
const uuidArray = (values: readonly string[]): SQL => sql`${sql.param(values)}::uuid[]`;

/** The conditions on an inventory row `d`, the same on both tables. */
function packageConditions(search: UsageSearch, query: UsagesQuery): SQL {
  const conditions = [nameCondition(search)];
  if (search.kind === 'purl') {
    conditions.push(sql`d.ecosystem = ANY(${textArray(search.ecosystems)})`);
    if (search.version !== null) conditions.push(sql`d.version = ${search.version}`);
  }
  if (query.ecosystem !== undefined) {
    conditions.push(sql`d.ecosystem = ANY(${textArray(ecosystemsOfType(query.ecosystem))})`);
  }
  if (query.version !== undefined) conditions.push(sql`d.version = ${query.version}`);
  return sql.join(conditions, sql` AND `);
}

/**
 * The matching rows of both inventories, each with its target and project id: the branches
 * (never a merge request, ruling R8) and every version. An OS purl with a namespace searches only
 * the versions of that family: a branch has no distribution.
 */
function inventoryRows(search: UsageSearch, query: UsagesQuery): SQL {
  const where = packageConditions(search, query);
  const family = search.kind === 'purl' ? search.family : null;
  const versions = sql`
    SELECT 'version'::text AS kind, v.id AS target_id, v.label AS target_name, false AS main,
           2 AS target_rank, v.project_id,
           d.ecosystem, d.name, d.version, d.path, d.direct,
           v.os_family, v.os_version, d.source_name, d.source_version, d.arch, d.modularity_label
      FROM version_dependencies d JOIN project_versions v ON v.id = d.version_id
     WHERE ${where}${family === null ? sql`` : sql` AND v.os_family = ${family}`}`;
  if (family !== null) return versions;
  return sql`
    SELECT 'branch'::text AS kind, b.id AS target_id, b.name AS target_name, b.is_main AS main,
           CASE WHEN b.is_main THEN 0 ELSE 1 END AS target_rank, b.project_id,
           d.ecosystem, d.name, d.version, d.path, d.direct,
           NULL::text AS os_family, NULL::text AS os_version, NULL::text AS source_name,
           NULL::text AS source_version, NULL::text AS arch, NULL::text AS modularity_label
      FROM branch_dependencies d JOIN branches b ON b.id = d.branch_id
     WHERE b.kind = 'branch' AND ${where}
    UNION ALL ${versions}`;
}

interface UsageRecord extends Record<string, unknown> {
  kind: 'branch' | 'version';
  target_id: string;
  target_name: string;
  main: boolean;
  project_id: string;
  project_key: string;
  project_name: string;
  ecosystem: string;
  name: string;
  version: string;
  path: string;
  direct: boolean | null;
  os_family: string | null;
  os_version: string | null;
  source_name: string | null;
  source_version: string | null;
  arch: string | null;
  modularity_label: string | null;
}

const targetKey = (kind: 'branch' | 'version', id: string): string => `${kind}:${id}`;

/** The key the re-check stores a row's vulnerabilities under ({@link matchKeyOf}), or null. */
function keyOf(row: UsageRecord): string | null {
  return matchKeyOf({
    ecosystem: row.ecosystem,
    name: row.name,
    version: row.version,
    osFamily: row.os_family,
    osVersion: row.os_version,
    sourceName: row.source_name,
    sourceVersion: row.source_version,
    arch: row.arch,
    modularityLabel: row.modularity_label,
  });
}

/**
 * The open vulnerabilities of each row, in order: the effective-open, not ignored rows of
 * `target_vulnerabilities` under the row's match key in its target ({@link scopedRows}, as the
 * Vulnerabilities tab counts them). Null for a row without a key (not checked) and for a target
 * without a re-check result. Two queries for the page, whatever its size.
 */
async function vulnerabilitiesOf(
  db: Executor,
  rows: readonly UsageRecord[],
): Promise<(number | null)[]> {
  const keys = rows.map(keyOf);
  const wanted = [...new Set(keys.filter((k): k is string => k !== null))];
  if (wanted.length === 0) return keys.map(() => null);
  const ids = (kind: 'branch' | 'version') => [
    ...new Set(rows.filter((r) => r.kind === kind).map((r) => r.target_id)),
  ];
  const branchIds = uuidArray(ids('branch'));
  const versionIds = uuidArray(ids('version'));
  const [checks, counts] = await Promise.all([
    db.execute<{ branch_id: string | null; version_id: string | null }>(sql`
      SELECT branch_id, version_id FROM vulnerability_target_checks
       WHERE branch_id = ANY(${branchIds}) OR version_id = ANY(${versionIds})`),
    db.execute<{ branch_id: string | null; version_id: string | null; purl: string; open: number }>(
      sql`
      WITH r AS (${scopedRows(
        sql`tv.purl = ANY(${textArray(wanted)})
            AND (tv.branch_id = ANY(${branchIds}) OR tv.version_id = ANY(${versionIds}))`,
      )})
      SELECT branch_id, version_id, purl,
             count(*) FILTER (WHERE eff_status = 'open' AND NOT ignored)::int AS open
        FROM r
       GROUP BY branch_id, version_id, purl`,
    ),
  ]);
  const targetOf = (r: { branch_id: string | null; version_id: string | null }): string =>
    r.branch_id !== null
      ? targetKey('branch', r.branch_id)
      : targetKey('version', r.version_id ?? '');
  const checked = new Set(checks.rows.map(targetOf));
  const open = new Map(counts.rows.map((r) => [`${targetOf(r)} ${r.purl}`, r.open]));
  return rows.map((row, i) => {
    const key = keys[i];
    const target = targetKey(row.kind, row.target_id);
    if (key === null || key === undefined || !checked.has(target)) return null;
    return open.get(`${target} ${key}`) ?? 0;
  });
}

/**
 * Where used (spec §6.8): the packages of every branch and version of the projects `visible`
 * names that match the query, ordered by name, version, project name, then the main branch, the
 * other branches and the versions, then path; one page, with the total up to
 * {@link USAGES_TOTAL_CAP}.
 *
 * `visible` is `visibleProjectsCondition(access, user)`, which the route calls (it is a
 * `list:project.read` route): a condition on the un-aliased `projects` table, joined here, in the
 * SQL that pages and counts. Undefined (an instance admin) filters nothing.
 */
export async function packageUsages(
  db: Executor,
  visible: SQL | undefined,
  query: UsagesQuery,
): Promise<UsagesAnswer> {
  const search = usageSearchOf(query.q);
  if (search === null) throw validationFailed([{ path: 'query.q', message: NOT_A_PURL }]);
  const matching = sql`
      FROM (${inventoryRows(search, query)}) u
      JOIN ${projects} ON ${projects.id} = u.project_id
     WHERE ${visible ?? sql`true`}`;
  const [page, counted] = await Promise.all([
    db.execute<UsageRecord>(sql`
      SELECT u.kind, u.target_id, u.target_name, u.main, u.project_id,
             ${projects.key} AS project_key, ${projects.name} AS project_name,
             u.ecosystem, u.name, u.version, u.path, u.direct, u.os_family, u.os_version,
             u.source_name, u.source_version, u.arch, u.modularity_label
      ${matching}
      ORDER BY u.name, u.version, ${projects.name}, ${projects.id}, u.target_rank, u.target_name,
               u.target_id, u.path, u.ecosystem
      LIMIT ${query.pageSize} OFFSET ${(query.page - 1) * query.pageSize}`),
    db.execute<{ n: number }>(sql`
      SELECT count(*)::int AS n FROM (SELECT 1 ${matching} LIMIT ${USAGES_TOTAL_CAP + 1}) c`),
  ]);
  const n = counted.rows[0]?.n ?? 0;
  const vulnerabilities = await vulnerabilitiesOf(db, page.rows);
  return {
    rows: page.rows.map((r, i) => ({
      project: { id: r.project_id, key: r.project_key, name: r.project_name },
      target: { kind: r.kind, id: r.target_id, name: r.target_name, main: r.main },
      ecosystem: r.ecosystem,
      purlType: purlTypeOf(r.ecosystem),
      name: r.name,
      version: r.version,
      path: r.path,
      direct: r.direct,
      distribution: distributionOf({ osFamily: r.os_family, osVersion: r.os_version }),
      vulnerabilities: vulnerabilities[i] ?? null,
    })),
    page: query.page,
    pageSize: query.pageSize,
    total: Math.min(n, USAGES_TOTAL_CAP),
    totalCapped: n > USAGES_TOTAL_CAP,
  };
}
