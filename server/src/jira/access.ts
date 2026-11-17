import { eq } from 'drizzle-orm';
import { requirePermission, type AccessContext } from '../auth/access';
import { grantOf, memberOf, projectFacts } from '../auth/facts';
import { projectPermissions, type ProjectPermission } from '../auth/policy';
import type { UserPrincipal } from '../auth/principal';
import { jiraLinks, memberships, projectMemberships, projects } from '../db/schema';
import { notFound } from '../http/problem';
import type { ProjectRow } from '../projects/access';
import type { JiraLinkRow } from './links';

/**
 * A Jira link whose project grants the caller `permission` (rbac-audit.md §5), with the
 * non-disclosure of `issueForUser`: a missing link and a link of a project the caller cannot see
 * are the same 404 (`Jira link not found`), answered by one query either way.
 */
export async function jiraLinkFor(
  access: AccessContext,
  principal: UserPrincipal,
  linkId: string,
  permission: ProjectPermission,
): Promise<{ link: JiraLinkRow; project: ProjectRow }> {
  const [row] = await access.db
    .select({
      link: jiraLinks,
      project: projects,
      organizationRole: memberships.role,
      projectRole: projectMemberships.role,
    })
    .from(jiraLinks)
    .innerJoin(projects, eq(projects.id, jiraLinks.projectId))
    .leftJoin(memberships, memberOf(principal.user, projects.organizationId))
    .leftJoin(projectMemberships, grantOf(principal.user, projects.id))
    .where(eq(jiraLinks.id, linkId));
  if (!row) throw notFound('Jira link');
  requirePermission(
    principal,
    projectPermissions(projectFacts(principal.user, row)),
    permission,
    'project.read',
    'Jira link',
  );
  return { link: row.link, project: row.project };
}
