import { eq } from 'drizzle-orm';
import { hasScope, requirePermission, type AccessContext } from '../auth/access';
import { grantOf, memberOf, projectFacts } from '../auth/facts';
import { projectPermissions, type ProjectPermission } from '../auth/policy';
import type { Principal, UserPrincipal } from '../auth/principal';
import type { UserRow } from '../auth/sessions';
import {
  analyses,
  branches,
  issues,
  llmRequests,
  memberships,
  projectMemberships,
  projects,
  type LlmRequestRow,
  type OrganizationRole,
  type ProjectRole,
} from '../db/schema';
import { forbidden, notFound, ProblemError } from '../http/problem';

export type ProjectRow = typeof projects.$inferSelect;

/** The access facts every project helper selects next to its object (ruling RB2). */
const FACTS = { organizationRole: memberships.role, projectRole: projectMemberships.role };

/** What the caller may do on the project of `row`. */
function granted(
  user: UserRow,
  row: { organizationRole: OrganizationRole | null; projectRole: ProjectRole | null },
): ReadonlySet<ProjectPermission> {
  return projectPermissions(projectFacts(user, row));
}

/**
 * The project in the path. rbac-audit.md §3.3: 404 when it does not exist or the caller cannot
 * read it, 403 FORBIDDEN when its role lacks `permission`, 403 INSUFFICIENT_SCOPE when its token
 * does.
 */
export async function projectForUser(
  access: AccessContext,
  principal: UserPrincipal,
  projectId: string,
  permission: ProjectPermission,
): Promise<ProjectRow> {
  const [row] = await access.db
    .select({ project: projects, ...FACTS })
    .from(projects)
    .leftJoin(memberships, memberOf(principal.user, projects.organizationId))
    .leftJoin(projectMemberships, grantOf(principal.user, projects.id))
    .where(eq(projects.id, projectId));
  if (!row) throw notFound('Project');
  requirePermission(principal, granted(principal.user, row), permission, 'project.read', 'Project');
  return row.project;
}

/**
 * The 📤 endpoints (ruling R2): the project named by `?projectKey`. A project token must belong to
 * it; a user needs `project.analyze` on it and a token with `analysis:write` (a session has every
 * scope). An unknown or invisible project is 404 `PROJECT_NOT_FOUND` — distinct from the plain
 * `NOT_FOUND` of a route this server does not have (the CLI relies on that, ruling N3).
 */
export async function projectForUpload(
  access: AccessContext,
  principal: Principal,
  projectKey: string,
): Promise<ProjectRow> {
  const missing = new ProblemError(404, 'PROJECT_NOT_FOUND', 'Project not found');
  if (principal.kind === 'project') {
    const [project] = await access.db.select().from(projects).where(eq(projects.key, projectKey));
    if (!project || project.id !== principal.projectId) throw missing;
    return project;
  }
  const [row] = await access.db
    .select({ project: projects, ...FACTS })
    .from(projects)
    .leftJoin(memberships, memberOf(principal.user, projects.organizationId))
    .leftJoin(projectMemberships, grantOf(principal.user, projects.id))
    .where(eq(projects.key, projectKey));
  if (!row) throw missing;
  const permissions = granted(principal.user, row);
  if (!permissions.has('project.read')) throw missing;
  requirePermission(principal, permissions, 'project.analyze', 'project.read', 'Project');
  return row.project;
}

export type BranchRow = typeof branches.$inferSelect;

/**
 * A branch whose project grants the caller `permission`. A missing branch and a branch of a
 * project the caller cannot see are the same 404 (`Branch not found`), so the answer never
 * reveals that another organisation's branch exists. One query either way (the facts are
 * joined), so neither can be told apart by timing.
 */
export async function branchForUser(
  access: AccessContext,
  principal: UserPrincipal,
  branchId: string,
  permission: ProjectPermission,
): Promise<BranchRow> {
  const [row] = await access.db
    .select({ branch: branches, organizationId: projects.organizationId, ...FACTS })
    .from(branches)
    .innerJoin(projects, eq(projects.id, branches.projectId))
    .leftJoin(memberships, memberOf(principal.user, projects.organizationId))
    .leftJoin(projectMemberships, grantOf(principal.user, projects.id))
    .where(eq(branches.id, branchId));
  if (!row) throw notFound('Branch');
  requirePermission(principal, granted(principal.user, row), permission, 'project.read', 'Branch');
  return row.branch;
}

export type IssueRow = typeof issues.$inferSelect;

/**
 * An issue whose project grants the caller `permission`, with the same non-disclosure as
 * {@link branchForUser}: a missing issue and an issue of a project the caller cannot see are the
 * same 404 (`Issue not found`), answered by one query either way.
 */
export async function issueForUser(
  access: AccessContext,
  principal: UserPrincipal,
  issueId: string,
  permission: ProjectPermission,
): Promise<IssueRow> {
  const [row] = await access.db
    .select({ issue: issues, organizationId: projects.organizationId, ...FACTS })
    .from(issues)
    .innerJoin(projects, eq(projects.id, issues.projectId))
    .leftJoin(memberships, memberOf(principal.user, projects.organizationId))
    .leftJoin(projectMemberships, grantOf(principal.user, projects.id))
    .where(eq(issues.id, issueId));
  if (!row) throw notFound('Issue');
  requirePermission(principal, granted(principal.user, row), permission, 'project.read', 'Issue');
  return row.issue;
}

export type AnalysisRow = typeof analyses.$inferSelect;

/**
 * GET /analyses/:id: the project token of its project, or a user with `project.read` on it and a
 * token of the `read` or `analysis:write` scope (api.md §3). A missing and an invisible analysis
 * are one 404, answered by one query either way.
 */
export async function analysisForPrincipal(
  access: AccessContext,
  principal: Principal,
  analysisId: string,
): Promise<{ analysis: AnalysisRow; branch: BranchRow | null }> {
  if (principal.kind === 'project') {
    const [row] = await access.db
      .select({ analysis: analyses, branch: branches })
      .from(analyses)
      .leftJoin(branches, eq(branches.id, analyses.branchId))
      .where(eq(analyses.id, analysisId));
    if (!row || row.analysis.projectId !== principal.projectId) throw notFound('Analysis');
    return row;
  }
  const [row] = await access.db
    .select({ analysis: analyses, branch: branches, ...FACTS })
    .from(analyses)
    .innerJoin(projects, eq(projects.id, analyses.projectId))
    .leftJoin(branches, eq(branches.id, analyses.branchId))
    .leftJoin(memberships, memberOf(principal.user, projects.organizationId))
    .leftJoin(projectMemberships, grantOf(principal.user, projects.id))
    .where(eq(analyses.id, analysisId));
  if (!row || !granted(principal.user, row).has('project.read')) {
    throw notFound('Analysis');
  }
  if (!hasScope(principal, 'read') && !hasScope(principal, 'analysis:write')) {
    throw forbidden('INSUFFICIENT_SCOPE', 'This token lacks the "read" scope');
  }
  return { analysis: row.analysis, branch: row.branch };
}

/**
 * An AI request, through its project (rbac-audit.md §3.4 notes), so a project grant counts: read
 * it with `project.read`, post it with `ai.use`. A missing request and one of a project the
 * caller cannot see are the same 404 (`Request not found`), answered by one query either way.
 */
export async function aiRequestFor(
  access: AccessContext,
  principal: UserPrincipal,
  requestId: string,
  permission: ProjectPermission,
): Promise<LlmRequestRow> {
  const [row] = await access.db
    .select({ request: llmRequests, ...FACTS })
    .from(llmRequests)
    .innerJoin(projects, eq(projects.id, llmRequests.projectId))
    .leftJoin(memberships, memberOf(principal.user, projects.organizationId))
    .leftJoin(projectMemberships, grantOf(principal.user, projects.id))
    .where(eq(llmRequests.id, requestId));
  if (!row) throw notFound('Request');
  requirePermission(principal, granted(principal.user, row), permission, 'project.read', 'Request');
  return row.request;
}
