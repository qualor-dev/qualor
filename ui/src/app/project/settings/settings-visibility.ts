import { can } from '../../auth/permissions';

/** The project permissions that open the Settings tab (the organisation's webhooks one besides). */
export const SETTINGS_PERMISSIONS = [
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
