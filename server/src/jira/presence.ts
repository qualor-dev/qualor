import { and, eq, inArray, sql } from 'drizzle-orm';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { issues } from '../db/schema';
import {
  isTrackedBranch,
  vulnerabilitySettings,
  vulnerabilitySettingsOf,
  type VulnerabilitySettings,
} from '../versions/settings';
import { compare } from '../vulnerabilities/order';
import { projectTargets, type Target } from '../vulnerabilities/targets';
import { TRIVY_ENGINE } from '../vulnerabilities/trivy-issues';
import { readVulndbSettings } from '../vulndb/settings';

/**
 * Presence as the sync pass judges it (spec §6.5, "gone"), the one definition the links routes
 * use too (ruling T6d: only a present pair may be linked).
 */

/** The map key of a vulnerability: its package and id. */
export const pairKey = (packageName: string, vulnerabilityId: string): string =>
  JSON.stringify([packageName, vulnerabilityId]);

export interface VulnerabilityPair {
  packageName: string;
  vulnerabilityId: string;
}

/**
 * What a project's presence is judged against: its tracked targets, and its settings, which say
 * which branches of its Trivy issues are tracked (read when needed if not given).
 */
export interface PresenceScope {
  targets: readonly Target[];
  settings?: VulnerabilitySettings;
}

/** How the project holds each pair, by {@link pairKey}. */
export interface PairPlaces {
  /** A `target_vulnerabilities` row on any target, or a Trivy issue in any state, of the pair. */
  known: Set<string>;
  /**
   * The present pairs, each with the names of where it is now, in tracked order (main first):
   * a tracked target with a `target_vulnerabilities` row, or main or a tracked branch with a
   * non-closed Trivy issue for the package and `trivy:<id>`. A pair absent here is gone.
   */
  present: Map<string, string[]>;
}

interface PlaceRow extends Record<string, unknown> {
  package_name: string;
  vulnerability_id: string;
  /** `branch:<id>` or `version:<id>`. */
  place: string;
  name: string;
  /** Null for a vulnerability row; for a Trivy issue whether it is not closed. */
  open: boolean | null;
  is_main: boolean;
  kind: string;
}

const placeOf = (t: Target): string =>
  t.kind === 'branch' ? `branch:${t.branchId}` : `version:${t.versionId}`;

/** Whether the row is a place where its pair is present (T6d). */
function presentAt(
  r: PlaceRow,
  tracked: ReadonlyMap<string, number>,
  settings: VulnerabilitySettings | null,
): boolean {
  if (r.open === null) return tracked.has(r.place);
  if (!r.open || settings === null) return false;
  return isTrackedBranch(settings, { name: r.name, isMain: r.is_main, kind: r.kind });
}

/**
 * The names of each pair's places in tracked order; a Trivy issue's branch outside the scope (the
 * links routes judge with monitoring off) comes after, main first, then by name.
 */
function placeNames(
  places: ReadonlyMap<string, PlaceRow[]>,
  tracked: ReadonlyMap<string, number>,
): Map<string, string[]> {
  const rank = (r: PlaceRow): number => tracked.get(r.place) ?? tracked.size + (r.is_main ? 0 : 1);
  const names = new Map<string, string[]>();
  for (const [key, list] of places) {
    list.sort((a, b) => rank(a) - rank(b) || compare(a.name, b.name));
    names.set(
      key,
      list.map((r) => r.name),
    );
  }
  return names;
}

/**
 * {@link PairPlaces} of the pairs in one query over the project's vulnerability rows and its Trivy
 * issues (and its settings when a Trivy issue is among them and `scope` has none).
 */
export async function pairPlaces(
  db: Executor,
  projectId: string,
  scope: PresenceScope,
  pairs: readonly VulnerabilityPair[],
): Promise<PairPlaces> {
  if (pairs.length === 0) return { known: new Set(), present: new Map() };
  const json = JSON.stringify(
    pairs.map((p) => ({ package_name: p.packageName, vulnerability_id: p.vulnerabilityId })),
  );
  const rows = await db.execute<PlaceRow>(sql`
    WITH p AS (SELECT DISTINCT * FROM jsonb_to_recordset(${json}::jsonb)
                      AS p(package_name text, vulnerability_id text))
    SELECT DISTINCT tv.package_name, tv.vulnerability_id,
           CASE WHEN tv.branch_id IS NOT NULL THEN 'branch:' || tv.branch_id::text
                ELSE 'version:' || tv.version_id::text END AS place,
           coalesce(b.name, v.label) AS name, NULL::boolean AS open,
           coalesce(b.is_main, false) AS is_main, coalesce(b.kind, 'version') AS kind
      FROM p
      JOIN target_vulnerabilities tv
        ON tv.project_id = ${projectId} AND tv.package_name = p.package_name
       AND tv.vulnerability_id = p.vulnerability_id
      LEFT JOIN branches b ON b.id = tv.branch_id
      LEFT JOIN project_versions v ON v.id = tv.version_id
    UNION ALL
    SELECT DISTINCT p.package_name, p.vulnerability_id, 'branch:' || b.id::text, b.name,
           i.status <> 'closed', b.is_main, b.kind
      FROM p
      JOIN issues i ON i.project_id = ${projectId} AND i.package_name = p.package_name
      JOIN rules r ON r.id = i.rule_id AND r.engine_id = ${TRIVY_ENGINE}
                  AND r.engine_rule_id = p.vulnerability_id
      JOIN branches b ON b.id = i.branch_id`);
  const tracked = new Map(scope.targets.map((t, i) => [placeOf(t), i]));
  const trivy = rows.rows.some((r) => r.open !== null);
  const settings = trivy ? (scope.settings ?? (await vulnerabilitySettings(db, projectId))) : null;
  const known = new Set<string>();
  const places = new Map<string, PlaceRow[]>();
  for (const r of rows.rows) {
    const key = pairKey(r.package_name, r.vulnerability_id);
    known.add(key);
    if (!presentAt(r, tracked, settings)) continue;
    const list = places.get(key) ?? [];
    if (!list.some((p) => p.place === r.place)) list.push(r);
    places.set(key, list);
  }
  return { known, present: placeNames(places, tracked) };
}

/**
 * spec §6.5: the scope of each project's presence, or null while vulnerability monitoring is off
 * for the instance or the project (as `monitoringOn` says): its vulnerability links are not judged
 * then, as `trackedTargets` returns nothing and every pair would read as gone. The instance switch
 * is read once, the projects' settings and targets for all of them at once.
 */
export async function presenceScopes(
  db: Executor,
  projectIds: readonly string[],
): Promise<Map<string, PresenceScope | null>> {
  const ids = [...new Set(projectIds)];
  if (ids.length === 0) return new Map();
  if (!(await readVulndbSettings(db)).enabled) return new Map(ids.map((id) => [id, null]));
  const settings = await vulnerabilitySettingsOf(db, ids);
  const targets = await projectTargets(db, ids);
  return new Map(
    ids.map((id) => {
      const own = settings.get(id);
      return [id, own?.enabled ? { targets: targets.get(id) ?? [], settings: own } : null];
    }),
  );
}

/**
 * Whether each pair is present (true) or gone (false), by {@link pairKey}; null while monitoring
 * is off for the instance or the project.
 */
export async function vulnerabilityPresence(
  db: Executor,
  projectId: string,
  pairs: readonly VulnerabilityPair[],
): Promise<Map<string, boolean> | null> {
  const scope = (await presenceScopes(db, [projectId])).get(projectId) ?? null;
  if (scope === null) return null;
  const { present } = await pairPlaces(db, projectId, scope, pairs);
  return new Map(
    pairs.map((p) => {
      const key = pairKey(p.packageName, p.vulnerabilityId);
      return [key, present.has(key)];
    }),
  );
}

/**
 * spec §6.5: the code issues that are gone, their status `closed` (only the system closes, after
 * an analysis whose analyzer ran fine; resolved, won't fix and false positive are not gone).
 */
export async function goneIssueIds(
  db: Executor,
  issueIds: readonly string[],
): Promise<Set<string>> {
  if (issueIds.length === 0) return new Set();
  const rows = await db
    .select({ id: issues.id })
    .from(issues)
    .where(and(inArray(issues.id, uuidList([...new Set(issueIds)])), eq(issues.status, 'closed')));
  return new Set(rows.map((r) => r.id));
}
