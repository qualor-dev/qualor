import { eq, inArray, sql, type SQL } from 'drizzle-orm';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { branches, projectVersions, vulnerabilityTargetChecks } from '../db/schema';
import {
  isTrackedBranch,
  vulnerabilitySettings,
  vulnerabilitySettingsOf,
} from '../versions/settings';
import { computeTracking, type TrackingReason } from '../versions/tracking';
import { readVulndbSettings } from '../vulndb/settings';
import { readVulndbState } from '../vulndb/state';
import { currentDataset } from '../vulndb/store';
import { effectiveDecisionJoin } from './decisions';
import { projectTargets } from './targets';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'unknown'] as const;
export type VulnerabilitySeverity = (typeof SEVERITIES)[number];

export type SeverityCounts = Record<VulnerabilitySeverity, number>;

export interface TargetSummary {
  kind: 'branch' | 'version';
  id: string;
  name: string;
  isMain: boolean;
  /** A version's override; null for a branch. */
  tracking: 'auto' | 'pinned' | 'unsupported' | null;
  hasInventory: boolean;
  counts: SeverityCounts;
  /** Open, not ignored rows in the KEV catalog; null without `vuln.priority`. */
  exploited: number | null;
  new: number;
  checkedAt: string | null;
}

export interface UntrackedVersion {
  id: string;
  name: string;
  tracking: 'auto' | 'pinned' | 'unsupported';
  trackingReason: TrackingReason;
  /** From the rows the version kept when it stopped being tracked. */
  counts: SeverityCounts;
  exploited: number | null;
  checkedAt: string | null;
}

export interface TargetsAnswer {
  /** Whether `vuln.priority` (KEV and EPSS) is licensed. */
  priority: boolean;
  monitoring: 'on' | 'off';
  data: { builtAt: string | null } | null;
  checkedAt: string | null;
  versionCount: number;
  targets: TargetSummary[];
  untracked: UntrackedVersion[];
}

/**
 * The vulnerability rows of `where` (a condition on `tv`, `target_vulnerabilities`), each with
 * its match and the facts the tab computes from, for use as a CTE:
 *
 * - `eff_status`, `d_id`: the effective decision of the row's own target (D6);
 * - `pd_id`, `pd_status`: the project-wide decision, else open;
 * - `kev`, `kev_date_added`, `kev_ransomware`, `epss_score`, `epss_percentile`: the CISA KEV and
 *   FIRST EPSS facts of the vulnerability id; the callers decide whether they may show them;
 * - `after_baseline`: first seen after its target's baseline, strictly (D3); false without a
 *   check row.
 *
 * A row is counted and shown as new only when it is also effective-open and not ignored.
 */
export function scopedRows(where: SQL): SQL {
  return sql`
    SELECT tv.project_id, tv.branch_id, tv.version_id, tv.package_name, tv.vulnerability_id,
           tv.package_version, tv.ecosystem, tv.ignored, tv.first_seen_at,
           m.severity, m.title, m.fixed_version, m.primary_url,
           COALESCE(d.status, 'open') AS eff_status,
           k.vulnerability_id IS NOT NULL AS kev,
           to_char(k.date_added, 'YYYY-MM-DD') AS kev_date_added,
           k.ransomware AS kev_ransomware,
           e.score AS epss_score,
           e.percentile AS epss_percentile,
           d.id AS d_id,
           pd.id AS pd_id,
           COALESCE(pd.status, 'open') AS pd_status,
           COALESCE(cb.baseline_at, cv.baseline_at) IS NOT NULL
             AND tv.first_seen_at > COALESCE(cb.baseline_at, cv.baseline_at) AS after_baseline
      FROM target_vulnerabilities tv
      JOIN vulnerability_matches m ON m.purl = tv.purl AND m.vulnerability_id = tv.vulnerability_id
      LEFT JOIN vulnerability_target_checks cb ON cb.branch_id = tv.branch_id
      LEFT JOIN vulnerability_target_checks cv ON cv.version_id = tv.version_id
      LEFT JOIN vulnerability_kev k
        ON k.vulnerability_id = tv.vulnerability_id AND k.delisted_at IS NULL
      LEFT JOIN vulnerability_epss e ON e.vulnerability_id = tv.vulnerability_id
      ${effectiveDecisionJoin('tv', 'd')}
      LEFT JOIN vulnerability_decisions pd
        ON pd.project_id = tv.project_id AND pd.package_name = tv.package_name
       AND pd.vulnerability_id = tv.vulnerability_id
       AND pd.branch_id IS NULL AND pd.version_id IS NULL
     WHERE ${where}`;
}

/** An effective-open, not ignored row of the {@link scopedRows} that is new. */
export const IS_NEW = sql.raw(`after_baseline AND eff_status = 'open' AND NOT ignored`);

const emptyCounts = (): SeverityCounts => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });

const keyOf = (kind: 'branch' | 'version', id: string): string => `${kind}:${id}`;

interface CountRow extends Record<string, unknown> {
  branch_id: string | null;
  version_id: string | null;
  critical: number;
  high: number;
  medium: number;
  low: number;
  unknown: number;
  exploited: number;
  new: number;
}

/** Counts (D6) and new rows (D3) of each target, by `kind:id`, in one query. */
async function countsOf(
  db: Executor,
  projectId: string,
  branchIds: readonly string[],
  versionIds: readonly string[],
): Promise<Map<string, { counts: SeverityCounts; exploited: number; new: number }>> {
  const open = (severity: VulnerabilitySeverity) =>
    sql.raw(
      `count(*) FILTER (WHERE severity = '${severity}' AND eff_status = 'open' AND NOT ignored)::int AS ${severity}`,
    );
  const rows = await db.execute<CountRow>(sql`
    WITH r AS (${scopedRows(
      sql`tv.project_id = ${projectId}
          AND (tv.branch_id IN ${uuidList(branchIds)} OR tv.version_id IN ${uuidList(versionIds)})`,
    )})
    SELECT branch_id, version_id,
           ${open('critical')}, ${open('high')}, ${open('medium')}, ${open('low')}, ${open('unknown')},
           count(*) FILTER (WHERE kev AND eff_status = 'open' AND NOT ignored)::int AS exploited,
           count(*) FILTER (WHERE ${IS_NEW})::int AS new
      FROM r
     GROUP BY branch_id, version_id`);
  return new Map(
    rows.rows.map((row) => [
      row.branch_id === null
        ? keyOf('version', row.version_id ?? '')
        : keyOf('branch', row.branch_id),
      {
        counts: {
          critical: row.critical,
          high: row.high,
          medium: row.medium,
          low: row.low,
          unknown: row.unknown,
        },
        exploited: row.exploited,
        new: row.new,
      },
    ]),
  );
}

/**
 * The By version table: the tracked targets (main, branches by name, versions newest first) with
 * their counts and new rows, the versions that are not tracked with the counts they froze, and the
 * header facts. While the instance or project switch is off, only the header and `versionCount`.
 */
export async function readTargetSummary(
  db: Executor,
  projectId: string,
  options: { priority: boolean },
): Promise<TargetsAnswer> {
  const [dataset, instance, settings, versions] = await Promise.all([
    readVulndbState(db).then((state) => currentDataset(db, state)),
    readVulndbSettings(db),
    vulnerabilitySettings(db, projectId),
    db
      .select({
        id: projectVersions.id,
        label: projectVersions.label,
        analyzedAt: projectVersions.analyzedAt,
        tracking: projectVersions.tracking,
        hasInventory: projectVersions.hasInventory,
      })
      .from(projectVersions)
      .where(eq(projectVersions.projectId, projectId)),
  ]);
  const base = {
    priority: options.priority,
    data: dataset ? { builtAt: dataset.builtAt?.toISOString() ?? null } : null,
    versionCount: versions.length,
  };
  if (!instance.enabled || !settings.enabled) {
    return { monitoring: 'off', checkedAt: null, targets: [], untracked: [], ...base };
  }

  const tracked = (await projectTargets(db, [projectId])).get(projectId) ?? [];
  const branchIds = tracked.flatMap((t) => (t.kind === 'branch' ? [t.branchId] : []));
  const decisions = computeTracking(versions, settings.versionRule);
  const untrackedVersions = versions
    .filter((v) => decisions.get(v.id)?.tracked !== true)
    .sort(
      (a, b) =>
        b.analyzedAt.getTime() - a.analyzedAt.getTime() || (a.id < b.id ? 1 : a.id > b.id ? -1 : 0),
    );
  const trackedVersionIds = tracked.flatMap((t) => (t.kind === 'version' ? [t.versionId] : []));
  const allVersionIds = [...trackedVersionIds, ...untrackedVersions.map((v) => v.id)];

  const [branchRows, withInventory, counts, checks] = await Promise.all([
    branchIds.length === 0
      ? []
      : db
          .select({ id: branches.id, name: branches.name, isMain: branches.isMain })
          .from(branches)
          .where(inArray(branches.id, branchIds)),
    branchesWithInventory(db, branchIds),
    countsOf(db, projectId, branchIds, allVersionIds),
    db
      .select({
        branchId: vulnerabilityTargetChecks.branchId,
        versionId: vulnerabilityTargetChecks.versionId,
        checkedAt: vulnerabilityTargetChecks.checkedAt,
      })
      .from(vulnerabilityTargetChecks)
      .where(eq(vulnerabilityTargetChecks.projectId, projectId)),
  ]);
  const checkedAt = new Map(
    checks.map((c) => [
      c.branchId !== null ? keyOf('branch', c.branchId) : keyOf('version', c.versionId ?? ''),
      c.checkedAt,
    ]),
  );
  const branchById = new Map(branchRows.map((b) => [b.id, b]));
  const versionById = new Map(versions.map((v) => [v.id, v]));
  const factsOf = (key: string) => ({
    counts: counts.get(key)?.counts ?? emptyCounts(),
    exploited: options.priority ? (counts.get(key)?.exploited ?? 0) : null,
    checkedAt: checkedAt.get(key)?.toISOString() ?? null,
  });

  const targets: TargetSummary[] = [];
  let newest: Date | null = null;
  for (const target of tracked) {
    const kind = target.kind;
    const id = target.kind === 'branch' ? target.branchId : target.versionId;
    const key = keyOf(kind, id);
    const branch = target.kind === 'branch' ? branchById.get(id) : undefined;
    const version = target.kind === 'version' ? versionById.get(id) : undefined;
    if (!branch && !version) continue;
    const checked = checkedAt.get(key);
    if (checked && (newest === null || checked > newest)) newest = checked;
    targets.push({
      kind,
      id,
      name: branch?.name ?? version?.label ?? '',
      isMain: branch?.isMain ?? false,
      tracking: version?.tracking ?? null,
      hasInventory: version?.hasInventory ?? withInventory.has(id),
      ...factsOf(key),
      new: counts.get(key)?.new ?? 0,
    });
  }
  const untracked: UntrackedVersion[] = untrackedVersions.map((v) => ({
    id: v.id,
    name: v.label,
    tracking: v.tracking,
    trackingReason: decisions.get(v.id)?.reason ?? 'older',
    ...factsOf(keyOf('version', v.id)),
  }));
  return {
    monitoring: 'on',
    checkedAt: newest?.toISOString() ?? null,
    targets,
    untracked,
    ...base,
  };
}

/** The branches of `ids` whose latest analysis carried a dependency inventory. */
async function branchesWithInventory(db: Executor, ids: readonly string[]): Promise<Set<string>> {
  if (ids.length === 0) return new Set();
  const rows = await db.execute<{ id: string }>(sql`
    SELECT b.id FROM branches b
     WHERE b.id IN ${uuidList(ids)}
       AND EXISTS (SELECT 1 FROM branch_dependencies bd WHERE bd.branch_id = b.id)`);
  return new Set(rows.rows.map((r) => r.id));
}

export interface NewMarker {
  main: boolean;
  branches: number;
  versions: number;
}

/**
 * Per project, whether main and how many tracked branches and versions have new vulnerabilities,
 * for the projects list. Every id is a key; a project switched off has none. Never a query per
 * project: the project settings, the targets with new rows and, for those that are versions, the
 * versions of their projects (the tracking rule needs all of them). The instance switch is the
 * caller's to check.
 */
export async function newVulnerabilityMarkers(
  db: Executor,
  projectIds: readonly string[],
): Promise<Map<string, NewMarker>> {
  const result = new Map<string, NewMarker>(
    projectIds.map((id) => [id, { main: false, branches: 0, versions: 0 }]),
  );
  const settings = await vulnerabilitySettingsOf(db, projectIds);
  const on = projectIds.filter((id) => settings.get(id)?.enabled === true);
  if (on.length === 0) return result;

  const candidates = await db.execute<{
    project_id: string;
    branch_id: string | null;
    version_id: string | null;
    name: string | null;
    is_main: boolean | null;
    kind: string | null;
  }>(sql`
    SELECT DISTINCT n.project_id, n.branch_id, n.version_id, b.name, b.is_main, b.kind
      FROM (
        SELECT tv.project_id, tv.branch_id, tv.version_id, tv.package_name, tv.vulnerability_id
          FROM target_vulnerabilities tv
          JOIN vulnerability_matches m ON m.purl = tv.purl AND m.vulnerability_id = tv.vulnerability_id
          LEFT JOIN vulnerability_target_checks cb ON cb.branch_id = tv.branch_id
          LEFT JOIN vulnerability_target_checks cv ON cv.version_id = tv.version_id
         WHERE tv.project_id IN ${uuidList(on)}
           AND NOT tv.ignored
           AND tv.first_seen_at > COALESCE(cb.baseline_at, cv.baseline_at)
      ) n
      ${effectiveDecisionJoin('n', 'd')}
      LEFT JOIN branches b ON b.id = n.branch_id
     WHERE COALESCE(d.status, 'open') = 'open'`);

  const versionCandidates = new Map<string, Set<string>>();
  for (const row of candidates.rows) {
    const marker = result.get(row.project_id);
    const own = settings.get(row.project_id);
    if (!marker || !own) continue;
    if (row.version_id !== null) {
      const set = versionCandidates.get(row.project_id) ?? new Set<string>();
      set.add(row.version_id);
      versionCandidates.set(row.project_id, set);
    } else if (
      row.kind === 'branch' &&
      row.name !== null &&
      isTrackedBranch(own, { name: row.name, isMain: row.is_main === true, kind: row.kind ?? '' })
    ) {
      if (row.is_main === true) marker.main = true;
      else marker.branches += 1;
    }
  }
  if (versionCandidates.size === 0) return result;

  const versions = await db
    .select({
      id: projectVersions.id,
      projectId: projectVersions.projectId,
      label: projectVersions.label,
      analyzedAt: projectVersions.analyzedAt,
      tracking: projectVersions.tracking,
    })
    .from(projectVersions)
    .where(inArray(projectVersions.projectId, [...versionCandidates.keys()]));
  const byProject = new Map<string, typeof versions>();
  for (const v of versions) {
    const list = byProject.get(v.projectId);
    if (list) list.push(v);
    else byProject.set(v.projectId, [v]);
  }
  for (const [projectId, wanted] of versionCandidates) {
    const rule = settings.get(projectId)?.versionRule;
    const marker = result.get(projectId);
    if (!rule || !marker) continue;
    const decisions = computeTracking(byProject.get(projectId) ?? [], rule);
    for (const id of wanted) if (decisions.get(id)?.tracked === true) marker.versions += 1;
  }
  return result;
}
