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
import { pairKey } from '../jira/presence';
import type { VulnerabilitySeverity } from '../vulnerabilities/order';
import { IS_NEW, scopedRows } from '../vulnerabilities/summary';
import { fixDto, type DependencyFix, type DependencyFixRow } from './rows';

/** R3: the Go standard library is fixed by the Go version, never by a module update. */
export const GO_STDLIB = 'stdlib';

/** Whether the package is Go's standard library (R3). */
export const isGoStdlib = (family: FixFamily, packageName: string): boolean =>
  family === 'go' && packageName === GO_STDLIB;

/** The project's main branch; null when it has none (a project always has one, but races). */
export async function mainBranchId(db: Executor, projectId: string): Promise<string | null> {
  const [row] = await db
    .select({ id: branches.id })
    .from(branches)
    .where(and(eq(branches.projectId, projectId), eq(branches.isMain, true)));
  return row?.id ?? null;
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

/**
 * spec §6.2, B5, B7: the vulnerabilities a fix of the package handles: its rows on the main-branch
 * target of every Trivy type of the family, not ignored, with an open effective decision (D6), by
 * vulnerability id, installed version and type.
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
        sql`${onMain(projectId)} AND tv.package_name = ${packageName}
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
}

const NO_FACET: FixFacet = Object.freeze({ fix: null, fixable: false });

interface FacetRow extends Record<string, unknown> {
  package_name: string;
  vulnerability_id: string;
  ecosystem: string;
  /** The fixed versions of its effective-open, not ignored rows; null when it has none. */
  fixed: (string | null)[] | null;
}

/** What the main rows of one pair say: the families they belong to, and whether one is fixable. */
interface PairFamilies {
  families: Set<FixFamily>;
  fixable: boolean;
}

function familiesOf(rows: readonly FacetRow[]): Map<string, PairFamilies> {
  const byPair = new Map<string, PairFamilies>();
  for (const r of rows) {
    const family = familyOfEcosystem(r.ecosystem);
    if (family === null) continue;
    const key = pairKey(r.package_name, r.vulnerability_id);
    const entry = byPair.get(key) ?? { families: new Set<FixFamily>(), fixable: false };
    entry.families.add(family);
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
 * version, its family is supported and it is not Go's standard library. Every pair is a key.
 */
export async function fixFacets(
  db: Executor,
  projectId: string,
  pairs: readonly { packageName: string; vulnerabilityId: string }[],
): Promise<Map<string, FixFacet>> {
  const facets = new Map<string, FixFacet>(
    pairs.map((p) => [pairKey(p.packageName, p.vulnerabilityId), NO_FACET]),
  );
  if (pairs.length === 0) return facets;
  const wanted = JSON.stringify(
    [...facets.keys()].map((key) => {
      const [packageName, vulnerabilityId] = JSON.parse(key) as [string, string];
      return { package_name: packageName, vulnerability_id: vulnerabilityId };
    }),
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
  const names = [...new Set(rows.rows.map((r) => r.package_name))];
  const fixes = await db
    .select()
    .from(dependencyFixes)
    .where(
      and(
        eq(dependencyFixes.projectId, projectId),
        sql`${dependencyFixes.packageName} IN ${textList(names)}`,
      ),
    );
  const fixOf = new Map<string, DependencyFixRow>(
    fixes.map((f) => [fixKey(f.family, f.packageName), f]),
  );
  for (const [key, { families, fixable }] of byPair) {
    const [packageName] = JSON.parse(key) as [string, string];
    // One family in practice; with several, the first of B7's order that has a fix.
    const row = FIX_FAMILIES.filter((f) => families.has(f))
      .map((f) => fixOf.get(fixKey(f, packageName)))
      .find((f) => f !== undefined);
    facets.set(key, { fix: row ? fixDto(row) : null, fixable });
  }
  return facets;
}
