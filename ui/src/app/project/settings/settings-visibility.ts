import { can } from '../../auth/permissions';

/**
 * The project permissions that open the Settings tab (the organisation's webhooks one besides).
 * `project.read` shows the Cleanup panel, read-only: whoever reads a project sees which of its
 * branches and merge requests Qualor deletes (issue #38).
 */
export const SETTINGS_PERMISSIONS = [
  'project.read',
  'project.settings',
  'project.tokens.manage',
  'project.delete',
] as const;

/** Whether the Settings tab has anything for a caller (project permissions, org webhooks). */
export function settingsVisible(
  projectPermissions: readonly string[],
  orgWebhooks: boolean,
): boolean {
  return orgWebhooks || SETTINGS_PERMISSIONS.some((p) => can(projectPermissions, p));
}
