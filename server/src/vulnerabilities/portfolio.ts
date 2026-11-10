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
 * The portfolio's two vulnerability numbers per project (plan 5, V1), current state only. An
 * open row has the effective status `open` and is not ignored.
 *
 * - `vulnerableReleases`: the tracked versions with at least one open row; other branches count
 *   toward neither number.
 * - `exploited`: the distinct vulnerability ids that are open and in KEV (not delisted) on the
 *   main branch or a tracked version; null without `priority`.
 *
 * Both are null while the instance switch or the project's switch is off. Every id is a key.
 * Never a query per project: the instance switch, the targets (three queries) and one aggregate
 * over all of them.
 */
export async function portfolioVulnerabilityFacts(
  tx: Executor,
  projectIds: readonly string[],
  options: { priority: boolean },
): Promise<Map<string, PortfolioVulnerabilityFacts>> {
  const result = new Map<string, PortfolioVulnerabilityFacts>(
    projectIds.map((id) => [id, { vulnerableReleases: null, exploited: null }]),
  );
  if (projectIds.length === 0 || !(await readVulndbSettings(tx)).enabled) return result;

  const versionIds: string[] = [];
  const branchIds: string[] = [];
  for (const [projectId, targets] of await projectTargets(tx, projectIds)) {
    // A project with its switch off has no targets; one switched on always tracks its main branch.
    if (targets.length === 0) continue;
    result.set(projectId, { vulnerableReleases: 0, exploited: options.priority ? 0 : null });
    for (const target of targets) {
      if (target.kind === 'version') versionIds.push(target.versionId);
      else branchIds.push(target.branchId);
    }
  }
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
