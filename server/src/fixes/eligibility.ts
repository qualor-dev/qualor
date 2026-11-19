import {
  ecosystemsOf,
  familyOfEcosystem,
  FIX_FAMILIES,
  parseFixedVersions,
  type FixFamily,
} from '@qualor/shared/fix';
import { and, eq, sql, type SQL } from 'drizzle-orm';
import { textList } from '../db/bulk';
import type { Executor } from '../db/client';
import { branches, dependencyFixes } from '../db/schema';
import { pairKey, pairPlaces, type VulnerabilityPair } from '../jira/presence';
import type { VulnerabilitySeverity } from '../vulnerabilities/order';
import { IS_NEW, scopedRows } from '../vulnerabilities/summary';
import { fixDto, fixPackageName, type DependencyFix, type DependencyFixRow } from './rows';

/** R3: the Go standard library is fixed by the Go version, never by a module update. */
export const GO_STDLIB = 'stdlib';

/** Whether the package is Go's standard library (R3). */
export const isGoStdlib = (family: FixFamily, packageName: string): boolean =>
  family === 'go' && packageName === GO_STDLIB;

/** The project's main branch, its id and name; null when it has none (it always has, but races). */
export async function mainBranchOf(
  db: Executor,
  projectId: string,
): Promise<{ id: string; name: string } | null> {
  const [row] = await db
    .select({ id: branches.id, name: branches.name })
    .from(branches)
    .where(and(eq(branches.projectId, projectId), eq(branches.isMain, true)));
  return row ?? null;
}

/** The project's main branch id; null when it has none. */
export async function mainBranchId(db: Executor, projectId: string): Promise<string | null> {
  return (await mainBranchOf(db, projectId))?.id ?? null;
}

/** A {@link scopedRows} condition: the row is on the project's main-branch target. */
const onMain = (projectId: string): SQL =>
  sql`tv.project_id = ${projectId}
      AND tv.branch_id = (SELECT b.id FROM branches b WHERE b.project_id = ${projectId} AND b.is_main)`;

/**
 * spec §6.2, B5: one `target_vulnerabilities` row of the package on the main-branch target, not
 * ignored, with an open effective decision, and the facts the claim and the MR need.
 */
export interface MainVulnerability {
  vulnerabilityId: string;
  severity: VulnerabilitySeverity;
  title: string | null;
  primaryUrl: string | null;
  /** Trivy's package type of the row (`npm`, `yarn`, …). */
  ecosystem: string;
  /** The installed version. */
  packageVersion: string;
  /** Trivy's fixed versions, split and trimmed (`parseFixedVersions`); empty when there is none. */
  fixedVersions: string[];
  firstSeenAt: Date;
  /** New as the Vulnerabilities tab counts it (`IS_NEW`, D3). */
  isNew: boolean;
  /** In the CISA KEV catalog (not delisted); the caller decides whether it may use it. */
  kev: boolean;
  /** CISA's `date_added`, `YYYY-MM-DD`; null when not listed. */
  kevDateAdded: string | null;
}

interface MainRow extends Record<string, unknown> {
  vulnerability_id: string;
  severity: VulnerabilitySeverity;
  title: string | null;
  primary_url: string | null;
  ecosystem: string;
  package_version: string;
  fixed_version: string | null;
  first_seen_at: Date | string;
  is_new: boolean;
  kev: boolean;
  kev_date_added: string | null;
}

/** Ruling T8b in SQL: a package name as a Python fix stores it (PEP 503, `normalizePythonName`). */
export const pep503Name = (name: SQL): SQL =>
  sql`lower(regexp_replace(${name}, '[-_.]+', '-', 'g'))`;

/**
 * A {@link scopedRows} condition: the row is of the package. A Python package matches by its PEP
 * 503 name, every spelling of it (ruling T8b); any other exactly.
 */
function ofPackage(family: FixFamily, packageName: string): SQL {
  return family === 'python'
    ? sql`${pep503Name(sql.raw('tv.package_name'))} = ${fixPackageName(family, packageName)}`
    : sql`tv.package_name = ${packageName}`;
}

/**
 * spec §6.2, B5, B7: the vulnerabilities a fix of the package handles: its rows on the main-branch
 * target of every Trivy type of the family (a Python package under any spelling of its name, T8b),
 * not ignored, with an open effective decision (D6), by vulnerability id, installed version and
 * type.
 */
export async function mainVulnerabilities(
  db: Executor,
  projectId: string,
  family: FixFamily,
  packageName: string,
): Promise<MainVulnerability[]> {
  const rows = await db.execute<MainRow>(sql`
    SELECT vulnerability_id, severity, title, primary_url, ecosystem, package_version,
           fixed_version, first_seen_at, ${IS_NEW} AS is_new, kev, kev_date_added
      FROM (${scopedRows(
        sql`${onMain(projectId)} AND ${ofPackage(family, packageName)}
            AND tv.ecosystem IN ${textList(ecosystemsOf(family))}`,
      )}) r
     WHERE eff_status = 'open' AND NOT ignored
     ORDER BY vulnerability_id COLLATE "C", package_version COLLATE "C", ecosystem COLLATE "C"`);
  return rows.rows.map((r) => ({
    vulnerabilityId: r.vulnerability_id,
    severity: r.severity,
    title: r.title,
    primaryUrl: r.primary_url,
    ecosystem: r.ecosystem,
    packageVersion: r.package_version,
    fixedVersions: parseFixedVersions(r.fixed_version),
    firstSeenAt: new Date(r.first_seen_at),
    isNew: r.is_new,
    kev: r.kev,
    kevDateAdded: r.kev_date_added,
  }));
}

/**
 * Ruling T11a, spec §6.7 step 3: whether main still has the fix's package, by the Jira presence
 * rule restricted to the main-branch target (`pairPlaces`, ruling F23): a `target_vulnerabilities`
 * row on main in any state (an ignored or triaged one keeps the package present), or a non-closed
 * Trivy issue on main. The pairs judged are the package's rows on main (the family's Trivy types,
 * every spelling of a Python name, T8b) and the ones the fix handled (`vulnerability_ids`).
 */
export async function packageOnMain(
  db: Executor,
  fix: Pick<DependencyFixRow, 'projectId' | 'family' | 'packageName' | 'vulnerabilityIds'>,
): Promise<boolean> {
  const main = await mainBranchOf(db, fix.projectId);
  if (main === null) return false;
  const rows = await db.execute<{ package_name: string; vulnerability_id: string }>(sql`
    SELECT DISTINCT tv.package_name, tv.vulnerability_id
      FROM target_vulnerabilities tv
     WHERE ${onMain(fix.projectId)} AND ${ofPackage(fix.family, fix.packageName)}
       AND tv.ecosystem IN ${textList(ecosystemsOf(fix.family))}`);
  const pairs: VulnerabilityPair[] = [
    ...rows.rows.map((r) => ({ packageName: r.package_name, vulnerabilityId: r.vulnerability_id })),
    ...fix.vulnerabilityIds.map((vulnerabilityId) => ({
      packageName: fix.packageName,
      vulnerabilityId,
    })),
  ];
  const scope = { targets: [{ kind: 'branch' as const, branchId: main.id }] };
  const { present } = await pairPlaces(db, fix.projectId, scope, pairs);
  return [...present.values()].some((places) => places.includes(main.name));
}

/**
 * spec §6.2, R3: why a request for the package cannot be fixed, or null when it can: no family
 * for the Trivy type (`FIX_ECOSYSTEM_UNSUPPORTED`), Go's standard library, or no main row with a
 * fixed version (`NOT_FIXABLE`).
 */
export function fixProblem(
  family: FixFamily | null,
  packageName: string,
  rows: readonly MainVulnerability[],
): 'FIX_ECOSYSTEM_UNSUPPORTED' | 'NOT_FIXABLE' | null {
  if (family === null) return 'FIX_ECOSYSTEM_UNSUPPORTED';
  if (isGoStdlib(family, packageName)) return 'NOT_FIXABLE';
  return rows.some((r) => r.fixedVersions.length > 0) ? null : 'NOT_FIXABLE';
}

/** R12: what a vulnerability item or a Trivy issue of main carries of the package's fix. */
export interface FixFacet {
  fix: DependencyFix | null;
  fixable: boolean;
  /** The Trivy package type of the pair's main row, the `ecosystem` a request names (T18b). */
  ecosystem: string | null;
}

const NO_FACET: FixFacet = Object.freeze({
  fix: null,
  fixable: false,
  ecosystem: null,
});

interface FacetRow extends Record<string, unknown> {
  package_name: string;
  vulnerability_id: string;
  ecosystem: string;
  /** The fixed versions of its effective-open, not ignored rows; null when it has none. */
  fixed: (string | null)[] | null;
}

/** What the main rows of one pair say: the families they belong to, and whether one is fixable. */
interface PairFamilies {
  packageName: string;
  families: Set<FixFamily>;
  fixable: boolean;
  ecosystem: string;
}

function familiesOf(rows: readonly FacetRow[]): Map<string, PairFamilies> {
  const byPair = new Map<string, PairFamilies>();
  for (const r of rows) {
    const family = familyOfEcosystem(r.ecosystem);
    if (family === null) continue;
    const key = pairKey(r.package_name, r.vulnerability_id);
    const entry = byPair.get(key) ?? {
      packageName: r.package_name,
      families: new Set<FixFamily>(),
      fixable: false,
      ecosystem: r.ecosystem,
    };
    entry.families.add(family);
    // The least spelling, so the answer does not depend on the order of the rows.
    if (r.ecosystem < entry.ecosystem) entry.ecosystem = r.ecosystem;
    const fixed = (r.fixed ?? []).some((v) => parseFixedVersions(v).length > 0);
    if (fixed && !isGoStdlib(family, r.package_name)) entry.fixable = true;
    byPair.set(key, entry);
  }
  return byPair;
}

const fixKey = (family: FixFamily, packageName: string): string =>
  JSON.stringify([family, packageName]);

/**
 * R12: each pair's fix and whether one may be requested, by {@link pairKey}, in two queries for a
 * page: the pairs' rows on the main-branch target, then the fixes of their packages. A pair has
 * the fix of its package (in the family of its main rows) while main has a row of it, whatever
 * its decision; it is fixable when such a row is effective-open, not ignored and has a fixed
 * version, its family is supported and it is not Go's standard library. A Python fix is found by
 * the PEP 503 name of the pair's package (ruling T8b). Every pair is a key.
 */
export async function fixFacets(
  db: Executor,
  projectId: string,
  pairs: readonly { packageName: string; vulnerabilityId: string }[],
): Promise<Map<string, FixFacet>> {
  const unique = new Map(pairs.map((p) => [pairKey(p.packageName, p.vulnerabilityId), p]));
  const facets = new Map<string, FixFacet>([...unique.keys()].map((key) => [key, NO_FACET]));
  if (unique.size === 0) return facets;
  const wanted = JSON.stringify(
    [...unique.values()].map((p) => ({
      package_name: p.packageName,
      vulnerability_id: p.vulnerabilityId,
    })),
  );
  const rows = await db.execute<FacetRow>(sql`
    SELECT package_name, vulnerability_id, ecosystem,
           array_agg(fixed_version) FILTER (WHERE eff_status = 'open' AND NOT ignored) AS fixed
      FROM (${scopedRows(
        sql`${onMain(projectId)}
            AND (tv.package_name, tv.vulnerability_id) IN (
                  SELECT p.package_name, p.vulnerability_id
                    FROM jsonb_to_recordset(${wanted}::jsonb)
                         AS p(package_name text, vulnerability_id text))`,
      )}) r
     GROUP BY package_name, vulnerability_id, ecosystem`);
  const byPair = familiesOf(rows.rows);
  if (byPair.size === 0) return facets;
  const fixName = (family: FixFamily, entry: PairFamilies) =>
    fixPackageName(family, entry.packageName);
  const names = new Set(
    [...byPair.values()].flatMap((entry) => [...entry.families].map((f) => fixName(f, entry))),
  );
  const fixes = await db
    .select()
    .from(dependencyFixes)
    .where(
      and(
        eq(dependencyFixes.projectId, projectId),
        sql`${dependencyFixes.packageName} IN ${textList([...names])}`,
      ),
    );
  const fixOf = new Map<string, DependencyFixRow>(
    fixes.map((f) => [fixKey(f.family, f.packageName), f]),
  );
  for (const [key, entry] of byPair) {
    // One family in practice; with several, the first of B7's order that has a fix.
    const row = FIX_FAMILIES.filter((f) => entry.families.has(f))
      .map((f) => fixOf.get(fixKey(f, fixName(f, entry))))
      .find((f) => f !== undefined);
    facets.set(key, {
      fix: row ? fixDto(row) : null,
      fixable: entry.fixable,
      ecosystem: entry.ecosystem,
    });
  }
  return facets;
}
