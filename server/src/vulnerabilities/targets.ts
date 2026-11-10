import { and, eq, inArray } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { branches, projectVersions } from '../db/schema';
import {
  isTrackedBranch,
  vulnerabilitySettings,
  vulnerabilitySettingsOf,
  type VulnerabilitySettings,
} from '../versions/settings';
import { computeTracking, type TrackingInput } from '../versions/tracking';
import { readVulndbSettings } from '../vulndb/settings';

/** What a re-check keeps vulnerability rows for (spec §8.2). */
export type Target = { kind: 'branch'; branchId: string } | { kind: 'version'; versionId: string };

/**
 * The project's tracked targets: its main branch, the branches matching its patterns, and the
 * versions {@link computeTracking} tracks. None while the instance or the project switch is off.
 */
export async function trackedTargets(db: Executor, projectId: string): Promise<Target[]> {
  if (!(await readVulndbSettings(db)).enabled) return [];
  return (await projectTargets(db, [projectId])).get(projectId) ?? [];
}

/** Whether both the instance switch and the project's switch are on. */
export async function monitoringOn(db: Executor, projectId: string): Promise<boolean> {
  const [instance, project] = await Promise.all([
    readVulndbSettings(db),
    vulnerabilitySettings(db, projectId),
  ]);
  return instance.enabled && project.enabled;
}

/**
 * {@link trackedTargets} of several projects in three queries, without the instance switch: the
 * re-check reads that once, at its start. Every project id is a key; a project switched off has
 * none. Branches come first (main, then by name), then versions (newest analysis first).
 */
export async function projectTargets(
  db: Executor,
  projectIds: readonly string[],
): Promise<Map<string, Target[]>> {
  const result = new Map<string, Target[]>(projectIds.map((id) => [id, []]));
  const settings = await vulnerabilitySettingsOf(db, projectIds);
  const on = projectIds.filter((id) => settings.get(id)?.enabled === true);
  if (on.length > 0) await addTargets(db, on, settings, result);
  return result;
}

/** Code-unit order (not locale-dependent). */
function compare(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/** Appends the tracked branches, then the tracked versions, of the projects `on` to `result`. */
async function addTargets(
  db: Executor,
  on: string[],
  settings: Map<string, VulnerabilitySettings>,
  result: Map<string, Target[]>,
): Promise<void> {
  const [branchRows, versionRows] = await Promise.all([
    db
      .select({
        id: branches.id,
        projectId: branches.projectId,
        name: branches.name,
        isMain: branches.isMain,
        kind: branches.kind,
      })
      .from(branches)
      .where(and(inArray(branches.projectId, on), eq(branches.kind, 'branch'))),
    db
      .select({
        id: projectVersions.id,
        projectId: projectVersions.projectId,
        label: projectVersions.label,
        analyzedAt: projectVersions.analyzedAt,
        tracking: projectVersions.tracking,
      })
      .from(projectVersions)
      .where(inArray(projectVersions.projectId, on)),
  ]);
  branchRows.sort((a, b) => Number(b.isMain) - Number(a.isMain) || compare(a.name, b.name));
  for (const row of branchRows) {
    const own = settings.get(row.projectId);
    if (own && isTrackedBranch(own, row)) {
      result.get(row.projectId)?.push({ kind: 'branch', branchId: row.id });
    }
  }
  const versionsOf = new Map<string, TrackingInput[]>();
  for (const row of versionRows) {
    const list = versionsOf.get(row.projectId);
    if (list === undefined) versionsOf.set(row.projectId, [row]);
    else list.push(row);
  }
  for (const [projectId, versions] of versionsOf) {
    const rule = settings.get(projectId)?.versionRule;
    if (rule === undefined) continue;
    const decisions = computeTracking(versions, rule);
    const tracked = versions
      .filter((v) => decisions.get(v.id)?.tracked === true)
      .sort((a, b) => b.analyzedAt.getTime() - a.analyzedAt.getTime());
    for (const v of tracked) result.get(projectId)?.push({ kind: 'version', versionId: v.id });
  }
}
