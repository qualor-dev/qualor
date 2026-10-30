import { eq } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { projectVulnerabilitySettings } from '../db/schema';
import { branchMatches } from './branches';
import type { VersionRule } from './tracking';

export interface VulnerabilitySettings {
  enabled: boolean;
  branchPatterns: string[];
  versionRule: VersionRule;
  labelVersions: boolean;
}

export const DEFAULT_VULNERABILITY_SETTINGS: VulnerabilitySettings = {
  enabled: true,
  branchPatterns: [],
  versionRule: { kind: 'lines', lines: 5 },
  labelVersions: false,
};

/** The project's settings, or the defaults when it has no row. */
export async function vulnerabilitySettings(
  db: Executor,
  projectId: string,
): Promise<VulnerabilitySettings> {
  const [row] = await db
    .select()
    .from(projectVulnerabilitySettings)
    .where(eq(projectVulnerabilitySettings.projectId, projectId))
    .limit(1);
  if (!row) {
    return {
      ...DEFAULT_VULNERABILITY_SETTINGS,
      branchPatterns: [],
      versionRule: { ...DEFAULT_VULNERABILITY_SETTINGS.versionRule },
    };
  }
  const versionRule: VersionRule =
    row.versionRule === 'lines'
      ? { kind: 'lines', lines: row.versionLines }
      : { kind: row.versionRule };
  return {
    enabled: row.enabled,
    branchPatterns: [...row.branchPatterns],
    versionRule,
    labelVersions: row.labelVersions,
  };
}

/** The main branch, or a `branch` kind matching a pattern; never a merge request. */
export function isTrackedBranch(
  settings: VulnerabilitySettings,
  branch: { name: string; isMain: boolean; kind: string },
): boolean {
  if (branch.isMain) return true;
  return branch.kind === 'branch' && branchMatches(branch.name, settings.branchPatterns);
}
