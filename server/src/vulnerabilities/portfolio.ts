import { sql } from 'drizzle-orm';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { readVulndbSettings } from '../vulndb/settings';
import { scopedRows } from './summary';
import { projectTargets } from './targets';

export interface PortfolioVulnerabilityFacts {
  vulnerableReleases: number | null;
  exploited: number | null;
}

/**
 * The version and branch ids of the projects' tracked targets. Each project with targets starts at
 * zero in `result`; one without stays null.
 */
async function targetIdsOf(
  tx: Executor,
  projectIds: readonly string[],
  priority: boolean,
  result: Map<string, PortfolioVulnerabilityFacts>,
): Promise<{ versionIds: string[]; branchIds: string[] }> {
  const versionIds: string[] = [];
  const branchIds: string[] = [];
  for (const [projectId, targets] of await projectTargets(tx, projectIds)) {
    // A project with its switch off has no targets. One switched on has them too, unless it has
    // neither a branch the server tracks nor a version: it stays null, like a project switched off.
    if (targets.length === 0) continue;
    result.set(projectId, { vulnerableReleases: 0, exploited: priority ? 0 : null });
    for (const target of targets) {
      if (target.kind === 'version') versionIds.push(target.versionId);
      else branchIds.push(target.branchId);
    }
  }
  return { versionIds, branchIds };
}

/**
 * The portfolio's two vulnerability numbers per project (plan 5, V1), current state only. An
 * open row has the effective status `open` and is not ignored.
 *
 * - `vulnerableReleases`: the tracked versions with at least one open row; other branches count
 *   toward neither number.
 * - `exploited`: the distinct vulnerability ids that are open and in KEV (not delisted) on the
 *   main branch or a tracked version; null without `priority`.
 *
 * Both are null while the instance switch or the project's switch is off. Every id is a key.
 * Never a query per project: the instance switch (unless the caller passes it), the targets (three
 * queries) and one aggregate over all of them.
 */
export async function portfolioVulnerabilityFacts(
  tx: Executor,
  projectIds: readonly string[],
  options: {
    priority: boolean;
    /** The instance switch, when the caller has read it already. */
    instanceEnabled?: boolean;
  },
): Promise<Map<string, PortfolioVulnerabilityFacts>> {
  const result = new Map<string, PortfolioVulnerabilityFacts>(
    projectIds.map((id) => [id, { vulnerableReleases: null, exploited: null }]),
  );
  if (projectIds.length === 0) return result;
  if (!(options.instanceEnabled ?? (await readVulndbSettings(tx)).enabled)) return result;

  const { versionIds, branchIds } = await targetIdsOf(tx, projectIds, options.priority, result);
  if (versionIds.length === 0 && branchIds.length === 0) return result;

  const rows = await tx.execute<{ project_id: string; releases: number; exploited: number }>(sql`
    WITH r AS (${scopedRows(
      sql`(tv.version_id IN ${uuidList(versionIds)}
           OR tv.branch_id IN (SELECT b.id FROM branches b
                                WHERE b.is_main AND b.id IN ${uuidList(branchIds)}))`,
    )})
    SELECT project_id,
           count(DISTINCT version_id) FILTER (
             WHERE version_id IS NOT NULL AND eff_status = 'open' AND NOT ignored)::int AS releases,
           count(DISTINCT vulnerability_id) FILTER (
             WHERE kev AND eff_status = 'open' AND NOT ignored)::int AS exploited
      FROM r
     GROUP BY project_id`);
  for (const row of rows.rows) {
    if (!result.has(row.project_id)) continue;
    result.set(row.project_id, {
      vulnerableReleases: row.releases,
      exploited: options.priority ? row.exploited : null,
    });
  }
  return result;
}

/** The main branch's open Critical and High vulnerabilities; null until it has an inventory. */
export type MainOpenCounts = { critical: number; high: number } | null;

/**
 * The open (effective-open, not ignored) Critical and High rows of each main branch, by project,
 * for the projects list (brief §A). A main branch whose latest analysis carried no dependency
 * inventory has no counts yet: null. One grouped query over the {@link scopedRows} of the given
 * branches; the switches are the caller's to check.
 */
export async function mainOpenCounts(
  tx: Executor,
  mains: readonly { projectId: string; branchId: string }[],
): Promise<Map<string, MainOpenCounts>> {
  const result = new Map<string, MainOpenCounts>(mains.map((m) => [m.projectId, null]));
  if (mains.length === 0) return result;
  const ids = uuidList(mains.map((m) => m.branchId));
  const rows = await tx.execute<{
    project_id: string;
    has_inventory: boolean;
    critical: number;
    high: number;
  }>(sql`
    WITH r AS (${scopedRows(sql`tv.branch_id IN ${ids}`)})
    SELECT b.project_id,
           EXISTS (SELECT 1 FROM branch_dependencies bd WHERE bd.branch_id = b.id) AS has_inventory,
           count(r.row_id) FILTER (
             WHERE r.severity = 'critical' AND r.eff_status = 'open' AND NOT r.ignored)::int AS critical,
           count(r.row_id) FILTER (
             WHERE r.severity = 'high' AND r.eff_status = 'open' AND NOT r.ignored)::int AS high
      FROM branches b
      LEFT JOIN r ON r.branch_id = b.id
     WHERE b.id IN ${ids}
     GROUP BY b.project_id, b.id`);
  for (const row of rows.rows) {
    if (!result.has(row.project_id) || !row.has_inventory) continue;
    result.set(row.project_id, { critical: row.critical, high: row.high });
  }
  return result;
}
