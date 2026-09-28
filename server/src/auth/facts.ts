import { eq, inArray, or, sql, type SQL } from 'drizzle-orm';
import type { AnyPgColumn } from 'drizzle-orm/pg-core';
import {
  memberships,
  organizations,
  projectMemberships,
  projects,
  type OrganizationRole,
  type ProjectRole,
} from '../db/schema';
import type { AccessContext } from './access';
import type { AccessFacts } from './policy';
import type { UserRow } from './sessions';

/**
 * rbac-audit.md §5 (ruling RB2): the SQL that lets a guarded helper read the object, the caller's
 * organisation role and its project grant in the one query it already runs, so a missing object
 * and an invisible one cost the same.
 */

/** Join condition: the user's membership of the organisation in `organizationId`. */
export function memberOf(user: UserRow, organizationId: AnyPgColumn): SQL {
  return sql`(${eq(memberships.organizationId, organizationId)} AND ${eq(memberships.userId, user.id)})`;
}

/** Join condition: the user's grant on the project in `projectId`. */
export function grantOf(user: UserRow, projectId: AnyPgColumn): SQL {
  return sql`(${eq(projectMemberships.projectId, projectId)} AND ${eq(projectMemberships.userId, user.id)})`;
}

/** Whether the user holds a grant on any project of the organisation in `organizationId`. */
export function grantInOrganization(user: UserRow, organizationId: AnyPgColumn): SQL<boolean> {
  return sql<boolean>`EXISTS (
    SELECT 1 FROM project_memberships g_pm JOIN projects g_p ON g_p.id = g_pm.project_id
     WHERE g_p.organization_id = ${organizationId} AND g_pm.user_id = ${user.id})`;
}

/** The facts of one project for the policy's `projectPermissions`. */
export function projectFacts(
  user: UserRow,
  row: { organizationRole: OrganizationRole | null; projectRole: ProjectRole | null },
): AccessFacts {
  return {
    instanceAdmin: user.isInstanceAdmin,
    organizationRole: row.organizationRole,
    projectRole: row.projectRole,
    hasProjectGrantInOrganization: row.projectRole !== null,
  };
}

/** The facts of one organisation for the policy's `organizationPermissions`. */
export function organizationFacts(
  user: UserRow,
  row: { organizationRole: OrganizationRole | null; hasProjectGrant: boolean },
): AccessFacts {
  return {
    instanceAdmin: user.isInstanceAdmin,
    organizationRole: row.organizationRole,
    projectRole: null,
    hasProjectGrantInOrganization: row.hasProjectGrant,
  };
}

/** What a caller holds on an object that does not exist: nothing, so every check is a 404. */
export const NO_PERMISSIONS: ReadonlySet<never> = new Set<never>();

/**
 * `list:project.read` (rbac-audit.md §5): the projects of the organisations the user holds any
 * role in (every role reads), and the projects it holds a grant on. Undefined (no
 * filter) for an instance admin.
 */
export function visibleProjectsCondition(access: AccessContext, user: UserRow): SQL | undefined {
  if (user.isInstanceAdmin) return undefined;
  const member = inArray(
    projects.organizationId,
    access.db
      .select({ id: memberships.organizationId })
      .from(memberships)
      .where(eq(memberships.userId, user.id)),
  );
  return or(
    member,
    inArray(
      projects.id,
      access.db
        .select({ id: projectMemberships.projectId })
        .from(projectMemberships)
        .where(eq(projectMemberships.userId, user.id)),
    ),
  );
}

/**
 * `list:org.read`: the organisations the user holds a role in or a grant on one of
 * whose projects. Undefined (no filter) for an instance admin, unless `own` asks for the
 * organisations it belongs to itself (`GET /auth/me` lists those, rbac-audit.md §16).
 */
export function visibleOrganizationsCondition(
  access: AccessContext,
  user: UserRow,
  options: { own?: boolean } = {},
): SQL | undefined {
  if (user.isInstanceAdmin && options.own !== true) return undefined;
  const member = inArray(
    organizations.id,
    access.db
      .select({ id: memberships.organizationId })
      .from(memberships)
      .where(eq(memberships.userId, user.id)),
  );
  return or(
    member,
    inArray(
      organizations.id,
      access.db
        .select({ id: projects.organizationId })
        .from(projectMemberships)
        .innerJoin(projects, eq(projects.id, projectMemberships.projectId))
        .where(eq(projectMemberships.userId, user.id)),
    ),
  );
}
