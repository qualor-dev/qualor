import { label } from '../i18n/labels';

/** Organisation roles (rbac-audit.md §3.2), strongest first; every edition has all four. */
export const ROLES = ['admin', 'project_admin', 'member', 'viewer'] as const;
export type Role = (typeof ROLES)[number];

/**
 * Whether a `permissions` list (from `GET /auth/me` or a project DTO) names a permission. An
 * unknown list (still loading, or not answered) allows nothing, so a button appears only once the
 * server said the caller may use it.
 */
export function can(permissions: readonly string[] | undefined, permission: string): boolean {
  return permissions?.includes(permission) ?? false;
}

/**
 * A role's name (rbac-audit.md §17): the same four names in every edition, since 5B (§1.3). A
 * `null` role is an organisation the caller sees only through a project grant (`GET /auth/me`).
 */
export function roleLabel(role: string | null): string {
  if (role === null) return $localize`:@@label.role.grantOnly:Project access only`;
  return label('role', role);
}
