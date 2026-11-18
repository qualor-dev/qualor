import { and, eq } from 'drizzle-orm';
import { requirePermission, type AccessContext } from '../auth/access';
import { grantOf, memberOf, projectFacts } from '../auth/facts';
import { projectPermissions, type ProjectPermission } from '../auth/policy';
import type { Principal, UserPrincipal } from '../auth/principal';
import { dependencyFixes, memberships, projectMemberships, projects } from '../db/schema';
import { notFound } from '../http/problem';
import type { ProjectRow } from '../projects/access';
import type { DependencyFixRow } from './rows';

/**
 * A dependency fix whose project grants the caller `permission` (rbac-audit.md §5), with the
 * non-disclosure of `issueForUser`: a missing fix and a fix of a project the caller cannot see are
 * the same 404 (`Fix not found`), answered by one query either way.
 */
export async function dependencyFixFor(
  access: AccessContext,
  principal: UserPrincipal,
  fixId: string,
  permission: ProjectPermission,
): Promise<{ fix: DependencyFixRow; project: ProjectRow }> {
  const [row] = await access.db
    .select({
      fix: dependencyFixes,
      project: projects,
      organizationRole: memberships.role,
      projectRole: projectMemberships.role,
    })
    .from(dependencyFixes)
    .innerJoin(projects, eq(projects.id, dependencyFixes.projectId))
    .leftJoin(memberships, memberOf(principal.user, projects.organizationId))
    .leftJoin(projectMemberships, grantOf(principal.user, projects.id))
    .where(eq(dependencyFixes.id, fixId));
  if (!row) throw notFound('Fix');
  requirePermission(
    principal,
    projectPermissions(projectFacts(principal.user, row)),
    permission,
    'project.read',
    'Fix',
  );
  return { fix: row.fix, project: row.project };
}

/**
 * 0.16 fix MRs B1 (rbac-audit.md §5): a dependency fix of the project a project analysis token
 * belongs to (`project.analyze`, the token's only permission). A missing fix and another
 * project's fix are the same 404 (`Fix not found`), answered by one query either way.
 */
export async function dependencyFixForUpload(
  access: AccessContext,
  principal: Extract<Principal, { kind: 'project' }>,
  fixId: string,
): Promise<{ fix: DependencyFixRow; project: ProjectRow }> {
  const [row] = await access.db
    .select({ fix: dependencyFixes, project: projects })
    .from(dependencyFixes)
    .innerJoin(projects, eq(projects.id, dependencyFixes.projectId))
    .where(and(eq(dependencyFixes.id, fixId), eq(dependencyFixes.projectId, principal.projectId)));
  if (!row) throw notFound('Fix');
  return row;
}
