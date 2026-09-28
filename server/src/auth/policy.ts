import {
  ORGANIZATION_ROLES,
  PROJECT_ROLES,
  type OrganizationRole,
  type ProjectRole,
} from '../db/schema';

export { ORGANIZATION_ROLES, PROJECT_ROLES };
export type { OrganizationRole, ProjectRole };

/**
 * rbac-audit.md §3–§4 (ruling RB1): the one place that knows what a role may do. Routes name a
 * permission; guarded helpers read the facts and ask this module. Custom roles later replace
 * ROLE_PERMISSIONS by rows; nothing else changes.
 */
export const ORGANIZATION_PERMISSIONS = [
  'org.read',
  'org.members.read',
  'org.members.manage',
  'org.projects.create',
  'org.gates.manage',
  'org.profiles.manage',
  'org.webhooks.manage',
  'org.scm.manage',
  'org.audit.read',
] as const;
export const PROJECT_PERMISSIONS = [
  'project.read',
  'project.analyze',
  'issue.triage',
  'ai.use',
  'project.settings',
  'project.tokens.manage',
  'project.branches.delete',
  'project.issues.import',
  'project.delete',
] as const;
export type OrganizationPermission = (typeof ORGANIZATION_PERMISSIONS)[number];
export type ProjectPermission = (typeof PROJECT_PERMISSIONS)[number];
export type Permission = OrganizationPermission | ProjectPermission;

interface RolePermissions {
  organization: readonly OrganizationPermission[];
  project: readonly ProjectPermission[];
}

const MAINTAIN = ['project.read', 'project.analyze', 'issue.triage', 'ai.use'] as const;
const ADMINISTER_PROJECT = [
  ...MAINTAIN,
  'project.settings',
  'project.tokens.manage',
  'project.branches.delete',
  'project.issues.import',
] as const;

/** §3.2. A project grant uses the `project` part of its role. */
export const ROLE_PERMISSIONS: Readonly<Record<OrganizationRole, Readonly<RolePermissions>>> =
  Object.freeze({
    admin: Object.freeze({ organization: ORGANIZATION_PERMISSIONS, project: PROJECT_PERMISSIONS }),
    project_admin: Object.freeze({
      organization: ['org.read'] as const,
      project: ADMINISTER_PROJECT,
    }),
    member: Object.freeze({ organization: ['org.read'] as const, project: MAINTAIN }),
    viewer: Object.freeze({
      organization: ['org.read'] as const,
      project: ['project.read'] as const,
    }),
  });

export type PermissionScope = 'read' | 'write' | 'admin' | 'analysis:write';

const SCOPES: Readonly<Record<Permission, PermissionScope>> = Object.freeze({
  'org.read': 'read',
  'org.members.read': 'admin',
  'org.members.manage': 'admin',
  'org.projects.create': 'admin',
  'org.gates.manage': 'admin',
  'org.profiles.manage': 'admin',
  'org.webhooks.manage': 'admin',
  'org.scm.manage': 'admin',
  'org.audit.read': 'admin',
  'project.read': 'read',
  'project.analyze': 'analysis:write',
  'issue.triage': 'write',
  'ai.use': 'write',
  'project.settings': 'admin',
  'project.tokens.manage': 'admin',
  'project.branches.delete': 'admin',
  'project.issues.import': 'admin',
  'project.delete': 'admin',
});

export function permissionScope(permission: Permission): PermissionScope {
  return SCOPES[permission];
}

export function isOrganizationPermission(p: string): p is OrganizationPermission {
  return (ORGANIZATION_PERMISSIONS as readonly string[]).includes(p);
}

export function isProjectPermission(p: string): p is ProjectPermission {
  return (PROJECT_PERMISSIONS as readonly string[]).includes(p);
}

export interface AccessFacts {
  instanceAdmin: boolean;
  organizationRole: OrganizationRole | null;
  projectRole: ProjectRole | null;
  hasProjectGrantInOrganization: boolean;
}

/**
 * §4, §6: the stored roles and grants, with no licence input, in every edition. A new set on every
 * call, so no caller can change what the next one gets.
 */
export function organizationPermissions(facts: AccessFacts): ReadonlySet<OrganizationPermission> {
  if (facts.instanceAdmin) return new Set(ORGANIZATION_PERMISSIONS);
  const granted = new Set<OrganizationPermission>();
  if (facts.organizationRole) {
    for (const p of ROLE_PERMISSIONS[facts.organizationRole].organization) granted.add(p);
  }
  // a grant-only user sees its organisation, read-only.
  if (facts.hasProjectGrantInOrganization) granted.add('org.read');
  return granted;
}

export function projectPermissions(facts: AccessFacts): ReadonlySet<ProjectPermission> {
  if (facts.instanceAdmin) return new Set(PROJECT_PERMISSIONS);
  const granted = new Set<ProjectPermission>();
  if (facts.organizationRole) {
    for (const p of ROLE_PERMISSIONS[facts.organizationRole].project) granted.add(p);
  }
  // a grant only adds.
  if (facts.projectRole) {
    for (const p of ROLE_PERMISSIONS[facts.projectRole].project) granted.add(p);
  }
  return granted;
}
