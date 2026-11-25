import { eq } from 'drizzle-orm';
import { requirePermission, type AccessContext } from '../auth/access';
import { grantOf, memberOf, projectFacts } from '../auth/facts';
import { projectPermissions, type ProjectPermission } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import { boardsLinks, memberships, projectMemberships, projects } from '../db/schema';
import { notFound } from '../http/problem';
import type { ProjectRow } from '../projects/access';
import type { BoardsLinkRow } from './links';

/**
 * An Azure Boards link whose project grants the caller `permission` (rbac-audit.md §5), as
 * `jiraLinkFor`: a missing link and a link of a project the caller cannot see are the same 404
 * (`Boards link not found`), answered by one query either way.
 */
export async function boardsLinkFor(
  access: AccessContext,
  principal: UserPrincipal,
  linkId: string,
  permission: ProjectPermission,
): Promise<{ link: BoardsLinkRow; project: ProjectRow }> {
  const [row] = await access.db
    .select({
      link: boardsLinks,
      project: projects,
      organizationRole: memberships.role,
      projectRole: projectMemberships.role,
    })
    .from(boardsLinks)
    .innerJoin(projects, eq(projects.id, boardsLinks.projectId))
    .leftJoin(memberships, memberOf(principal.user, projects.organizationId))
    .leftJoin(projectMemberships, grantOf(principal.user, projects.id))
    .where(eq(boardsLinks.id, linkId));
  if (!row) throw notFound('Boards link');
  requirePermission(
    principal,
    projectPermissions(projectFacts(principal.user, row)),
    permission,
    'project.read',
    'Boards link',
  );
  return { link: row.link, project: row.project };
}
