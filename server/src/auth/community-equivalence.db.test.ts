import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  createUser,
  DEFAULT_TEST_PASSWORD,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { gzipJson, REPORT_CONTENT_TYPE, sampleReport } from '../../test/reports';
import { grantProject } from '../../test/rbac';
import {
  branches,
  organizations,
  projects,
  scmConnections,
  webhookSubscriptions,
} from '../db/schema';
import { fixedEdition } from '../license/edition';
import { communityLimits } from '../limits';

/**
 * rbac-audit.md §3.5: the regression net of the role model. The `admin`, `member`, token,
 * outsider and instance-admin rows are the pre-4C behaviour and never change. Since 5B the roles
 * have no licence input, so the grant (`granted`) and extra-role (`storedProjectAdmin`,
 * `storedViewer`) rows follow the §3.2 table on a community server.
 */
type Who =
  | 'root'
  | 'admin'
  | 'adminWrite'
  | 'member'
  | 'memberRead'
  | 'memberWrite'
  | 'outsider'
  | 'projectToken'
  | 'granted'
  | 'storedProjectAdmin'
  | 'storedViewer'
  | 'storedViewerUpload';
type Method = 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
type Row = [Who, Method, string, unknown, number, string?];

async function personalToken(
  ctx: TestContext,
  session: Record<string, string>,
  scopes: string[],
): Promise<Record<string, string>> {
  const res = await ctx.app.inject({
    method: 'POST',
    url: '/api/v0/tokens',
    headers: session,
    payload: { name: scopes.join('-'), scopes },
  });
  if (res.statusCode !== 201) throw new Error(`token: ${res.statusCode} ${res.body}`);
  return bearer((res.json() as { token: string }).token);
}

async function run(
  ctx: TestContext,
  headers: Partial<Record<Who, Record<string, string>>>,
  rows: Row[],
): Promise<void> {
  for (const [who, method, url, payload, status, code] of rows) {
    const upload = url.startsWith('/api/v0/analyses?');
    const res = await ctx.app.inject({
      method,
      url,
      headers: upload
        ? { ...headers[who], 'content-type': REPORT_CONTENT_TYPE, 'content-encoding': 'gzip' }
        : headers[who],
      ...(upload ? { payload: gzipJson(sampleReport()) } : {}),
      ...(payload === undefined ? {} : { payload: payload as never }),
    });
    expect(res.statusCode, `${who} ${method} ${url}: ${res.body}`).toBe(status);
    if (code) expect((res.json() as { code: string }).code, `${who} ${method} ${url}`).toBe(code);
  }
}

describe('community roles keep today’s answers on every route family (rbac-audit.md §3.5)', () => {
  let ctx: TestContext;
  const headers: Partial<Record<Who, Record<string, string>>> = {};
  let org: string;
  let project: { id: string; key: string };
  let branchId: string;
  let issueId: string;
  let gateId: string;
  let profileId: string;
  let webhookId: string;
  let connectionId: string;

  beforeAll(async () => {
    ctx = await createTestContext();
    const root = await login(ctx, 'admin', ADMIN_PASSWORD);
    headers.root = root.headers;
    org = await organizationId(ctx, 'default');
    const bob = await createUser(ctx, { username: 'bob' });
    const alice = await createUser(ctx, { username: 'alice' });
    await createUser(ctx, { username: 'carol' });
    await addMember(ctx, org, bob.id, 'admin');
    await addMember(ctx, org, alice.id, 'member');
    headers.admin = (await login(ctx, 'bob', bob.password)).headers;
    headers.member = (await login(ctx, 'alice', alice.password)).headers;
    headers.outsider = (await login(ctx, 'carol', DEFAULT_TEST_PASSWORD)).headers;
    headers.memberRead = await personalToken(ctx, headers.member, ['read']);
    headers.memberWrite = await personalToken(ctx, headers.member, ['write']);
    headers.adminWrite = await personalToken(ctx, headers.admin, ['write']);
    project = await createProject(ctx, root, { organizationId: org, key: 'eq-app' });
    headers.projectToken = bearer(await createProjectToken(ctx, root, project.id));
    branchId = await mainBranchId(ctx.db, project.id);
    const ruleId = await seedRule(ctx.db, { key: 'eslint:no-eval' });
    issueId = await seedIssue(ctx.db, { projectId: project.id, branchId, ruleId });
    const gates = await ctx.app.inject({
      method: 'GET',
      url: `/api/v0/quality-gates?organizationId=${org}`,
      headers: root.headers,
    });
    gateId = (gates.json() as { items: { id: string }[] }).items[0]!.id;
    const profiles = await ctx.app.inject({
      method: 'GET',
      url: `/api/v0/quality-profiles?organizationId=${org}`,
      headers: root.headers,
    });
    profileId = (profiles.json() as { items: { id: string }[] }).items[0]!.id;
    const [webhook] = await ctx.db
      .insert(webhookSubscriptions)
      .values({
        organizationId: org,
        url: 'https://hooks.example.com/qualor',
        secretEnc: { v: 1, iv: 'x', tag: 'x', data: 'x' } as never,
        events: ['analysis.completed'],
      })
      .returning({ id: webhookSubscriptions.id });
    webhookId = webhook!.id;
    const [connection] = await ctx.db
      .insert(scmConnections)
      .values({
        organizationId: org,
        provider: 'gitlab',
        baseUrl: 'https://gitlab.example.com',
        tokenEnc: { v: 1, iv: 'x', tag: 'x', data: 'x' } as never,
      })
      .returning({ id: scmConnections.id });
    connectionId = connection!.id;
  });
  afterAll(async () => ctx.close());

  // [who, method, url, payload, status, code?]: what main answered before plan 4C.
  const rows = (): Row[] => [
    // Projects (projectForUser)
    ['member', 'GET', `/api/v0/projects/${project.id}`, undefined, 200],
    ['memberRead', 'GET', `/api/v0/projects/${project.id}`, undefined, 200],
    ['outsider', 'GET', `/api/v0/projects/${project.id}`, undefined, 404, 'NOT_FOUND'],
    ['projectToken', 'GET', `/api/v0/projects/${project.id}`, undefined, 403, 'TOKEN_NOT_ALLOWED'],
    ['member', 'GET', `/api/v0/projects/by-key?key=${project.key}`, undefined, 200],
    ['outsider', 'GET', `/api/v0/projects/by-key?key=${project.key}`, undefined, 404, 'NOT_FOUND'],
    ['member', 'PATCH', `/api/v0/projects/${project.id}`, { name: 'x' }, 403, 'FORBIDDEN'],
    ['memberRead', 'PATCH', `/api/v0/projects/${project.id}`, { name: 'x' }, 403, 'FORBIDDEN'],
    ['outsider', 'PATCH', `/api/v0/projects/${project.id}`, { name: 'x' }, 404, 'NOT_FOUND'],
    [
      'adminWrite',
      'PATCH',
      `/api/v0/projects/${project.id}`,
      { name: 'x' },
      403,
      'INSUFFICIENT_SCOPE',
    ],
    ['admin', 'PATCH', `/api/v0/projects/${project.id}`, { name: 'eq-app' }, 200],
    ['root', 'PATCH', `/api/v0/projects/${project.id}`, { name: 'eq-app' }, 200],
    ['member', 'GET', `/api/v0/projects/${project.id}/tokens`, undefined, 403, 'FORBIDDEN'],
    ['admin', 'GET', `/api/v0/projects/${project.id}/tokens`, undefined, 200],
    [
      'adminWrite',
      'GET',
      `/api/v0/projects/${project.id}/tokens`,
      undefined,
      403,
      'INSUFFICIENT_SCOPE',
    ],
    [
      'member',
      'DELETE',
      `/api/v0/projects/${project.id}?confirm=eq-app`,
      undefined,
      403,
      'FORBIDDEN',
    ],
    ['member', 'GET', `/api/v0/projects/${project.id}/branches`, undefined, 200],
    [
      'member',
      'POST',
      '/api/v0/projects',
      { organizationId: org, key: 'm2', name: 'm2' },
      403,
      'FORBIDDEN',
    ],
    [
      'outsider',
      'POST',
      '/api/v0/projects',
      { organizationId: org, key: 'o2', name: 'o2' },
      404,
      'NOT_FOUND',
    ],
    [
      'adminWrite',
      'POST',
      '/api/v0/projects',
      { organizationId: org, key: 'w2', name: 'w2' },
      403,
      'INSUFFICIENT_SCOPE',
    ],
    ['member', 'GET', '/api/v0/projects', undefined, 200],
    // Issues (branchForUser, issueForUser)
    ['member', 'GET', `/api/v0/issues?branchId=${branchId}`, undefined, 200],
    ['outsider', 'GET', `/api/v0/issues?branchId=${branchId}`, undefined, 404, 'NOT_FOUND'],
    ['member', 'GET', `/api/v0/issues/${issueId}`, undefined, 200],
    ['outsider', 'GET', `/api/v0/issues/${issueId}`, undefined, 404, 'NOT_FOUND'],
    ['member', 'GET', `/api/v0/issues/${issueId}/changelog`, undefined, 200],
    [
      'memberRead',
      'POST',
      `/api/v0/issues/${issueId}/transition`,
      { to: 'resolved' },
      403,
      'INSUFFICIENT_SCOPE',
    ],
    ['member', 'POST', `/api/v0/issues/${issueId}/transition`, { to: 'resolved' }, 200],
    ['admin', 'POST', `/api/v0/issues/${issueId}/transition`, { to: 'open' }, 200],
    ['memberWrite', 'POST', `/api/v0/issues/${issueId}/transition`, { to: 'resolved' }, 200],
    ['member', 'POST', `/api/v0/issues/${issueId}/transition`, { to: 'open' }, 200],
    [
      'outsider',
      'POST',
      `/api/v0/issues/${issueId}/transition`,
      { to: 'resolved' },
      404,
      'NOT_FOUND',
    ],
    [
      'memberRead',
      'PATCH',
      `/api/v0/issues/${issueId}`,
      { severity: 'low' },
      403,
      'INSUFFICIENT_SCOPE',
    ],
    ['outsider', 'PATCH', `/api/v0/issues/${issueId}`, { severity: 'low' }, 404, 'NOT_FOUND'],
    ['member', 'PATCH', `/api/v0/issues/${issueId}`, { severity: 'low' }, 200],
    [
      'member',
      'POST',
      `/api/v0/projects/${project.id}/issue-status-import`,
      {
        dryRun: true,
        items: [
          {
            ref: 'a',
            ruleKeys: ['eslint:no-eval'],
            path: 'a.ts',
            line: 1,
            sonarLineHash: null,
            message: null,
            status: 'open',
          },
        ],
      },
      403,
      'FORBIDDEN',
    ],
    // Measures (branchForUser)
    ['member', 'GET', `/api/v0/branches/${branchId}/measures`, undefined, 200],
    ['outsider', 'GET', `/api/v0/branches/${branchId}/measures`, undefined, 404, 'NOT_FOUND'],
    ['member', 'GET', `/api/v0/branches/${branchId}/analyses`, undefined, 200],
    ['outsider', 'GET', `/api/v0/branches/${branchId}/analyses`, undefined, 404, 'NOT_FOUND'],
    // Branches
    ['member', 'DELETE', `/api/v0/branches/${branchId}`, undefined, 403, 'FORBIDDEN'],
    ['outsider', 'DELETE', `/api/v0/branches/${branchId}`, undefined, 404, 'NOT_FOUND'],
    ['adminWrite', 'DELETE', `/api/v0/branches/${branchId}`, undefined, 403, 'INSUFFICIENT_SCOPE'],
    ['admin', 'DELETE', `/api/v0/branches/${branchId}`, undefined, 409, 'MAIN_BRANCH'],
    // Uploads and the new-code baseline (projectForUpload)
    [
      'outsider',
      'POST',
      `/api/v0/analyses?projectKey=${project.key}`,
      undefined,
      404,
      'PROJECT_NOT_FOUND',
    ],
    [
      'memberRead',
      'POST',
      `/api/v0/analyses?projectKey=${project.key}`,
      undefined,
      403,
      'INSUFFICIENT_SCOPE',
    ],
    [
      'memberWrite',
      'POST',
      `/api/v0/analyses?projectKey=${project.key}`,
      undefined,
      403,
      'INSUFFICIENT_SCOPE',
    ],
    [
      'outsider',
      'GET',
      `/api/v0/projects/new-code-baseline?projectKey=${project.key}&branch=main`,
      undefined,
      404,
      'PROJECT_NOT_FOUND',
    ],
    [
      'memberRead',
      'GET',
      `/api/v0/projects/new-code-baseline?projectKey=${project.key}&branch=main`,
      undefined,
      403,
      'INSUFFICIENT_SCOPE',
    ],
    [
      'member',
      'GET',
      `/api/v0/projects/new-code-baseline?projectKey=${project.key}&branch=main`,
      undefined,
      200,
    ],
    [
      'projectToken',
      'GET',
      `/api/v0/projects/new-code-baseline?projectKey=${project.key}&branch=main`,
      undefined,
      200,
    ],
    // Quality gates (requireOrganizationAccess, gateFor)
    ['member', 'GET', `/api/v0/quality-gates?organizationId=${org}`, undefined, 200],
    ['outsider', 'GET', `/api/v0/quality-gates?organizationId=${org}`, undefined, 404, 'NOT_FOUND'],
    [
      'member',
      'POST',
      '/api/v0/quality-gates',
      { organizationId: org, name: 'm' },
      403,
      'FORBIDDEN',
    ],
    [
      'adminWrite',
      'POST',
      '/api/v0/quality-gates',
      { organizationId: org, name: 'w' },
      403,
      'INSUFFICIENT_SCOPE',
    ],
    ['admin', 'POST', '/api/v0/quality-gates', { organizationId: org, name: 'a' }, 201],
    ['member', 'GET', `/api/v0/quality-gates/${gateId}`, undefined, 200],
    ['outsider', 'GET', `/api/v0/quality-gates/${gateId}`, undefined, 404, 'NOT_FOUND'],
    ['member', 'POST', `/api/v0/quality-gates/${gateId}/copy`, { name: 'c' }, 403, 'FORBIDDEN'],
    ['memberRead', 'POST', `/api/v0/quality-gates/${gateId}/copy`, { name: 'c' }, 403, 'FORBIDDEN'],
    ['outsider', 'POST', `/api/v0/quality-gates/${gateId}/copy`, { name: 'c' }, 404, 'NOT_FOUND'],
    [
      'adminWrite',
      'POST',
      `/api/v0/quality-gates/${gateId}/copy`,
      { name: 'c' },
      403,
      'INSUFFICIENT_SCOPE',
    ],
    ['admin', 'POST', `/api/v0/quality-gates/${gateId}/copy`, { name: 'c' }, 201],
    // Quality profiles (requireOrganizationAccess, profileFor, projectForUser)
    ['member', 'GET', `/api/v0/quality-profiles?organizationId=${org}`, undefined, 200],
    [
      'outsider',
      'GET',
      `/api/v0/quality-profiles?organizationId=${org}`,
      undefined,
      404,
      'NOT_FOUND',
    ],
    ['member', 'GET', `/api/v0/quality-profiles/${profileId}`, undefined, 200],
    ['outsider', 'GET', `/api/v0/quality-profiles/${profileId}`, undefined, 404, 'NOT_FOUND'],
    [
      'member',
      'POST',
      `/api/v0/quality-profiles/${profileId}/copy`,
      { name: 'c' },
      403,
      'FORBIDDEN',
    ],
    [
      'adminWrite',
      'POST',
      `/api/v0/quality-profiles/${profileId}/copy`,
      { name: 'c' },
      403,
      'INSUFFICIENT_SCOPE',
    ],
    ['admin', 'POST', `/api/v0/quality-profiles/${profileId}/copy`, { name: 'c' }, 201],
    ['member', 'GET', `/api/v0/projects/${project.id}/quality-profiles`, undefined, 200],
    [
      'member',
      'PUT',
      `/api/v0/projects/${project.id}/quality-profiles/javascript`,
      { profileId: null },
      403,
      'FORBIDDEN',
    ],
    // Organisation members
    ['member', 'GET', `/api/v0/organizations/${org}/members`, undefined, 403, 'FORBIDDEN'],
    ['outsider', 'GET', `/api/v0/organizations/${org}/members`, undefined, 404, 'NOT_FOUND'],
    [
      'adminWrite',
      'GET',
      `/api/v0/organizations/${org}/members`,
      undefined,
      403,
      'INSUFFICIENT_SCOPE',
    ],
    ['admin', 'GET', `/api/v0/organizations/${org}/members`, undefined, 200],
    ['root', 'GET', `/api/v0/organizations/${org}/members`, undefined, 200],
    // Webhooks (requireOrganizationAccess, webhookFor)
    ['member', 'GET', `/api/v0/webhooks?organizationId=${org}`, undefined, 403, 'FORBIDDEN'],
    ['outsider', 'GET', `/api/v0/webhooks?organizationId=${org}`, undefined, 404, 'NOT_FOUND'],
    ['admin', 'GET', `/api/v0/webhooks?organizationId=${org}`, undefined, 200],
    ['member', 'GET', `/api/v0/webhooks/${webhookId}`, undefined, 403, 'FORBIDDEN'],
    ['outsider', 'GET', `/api/v0/webhooks/${webhookId}`, undefined, 404, 'NOT_FOUND'],
    ['adminWrite', 'GET', `/api/v0/webhooks/${webhookId}`, undefined, 403, 'INSUFFICIENT_SCOPE'],
    // SCM connections (requireOrganizationAccess, connectionFor)
    ['member', 'GET', `/api/v0/scm-connections?organizationId=${org}`, undefined, 403, 'FORBIDDEN'],
    [
      'outsider',
      'GET',
      `/api/v0/scm-connections?organizationId=${org}`,
      undefined,
      404,
      'NOT_FOUND',
    ],
    ['admin', 'GET', `/api/v0/scm-connections?organizationId=${org}`, undefined, 200],
    ['member', 'DELETE', `/api/v0/scm-connections/${connectionId}`, undefined, 403, 'FORBIDDEN'],
    ['outsider', 'DELETE', `/api/v0/scm-connections/${connectionId}`, undefined, 404, 'NOT_FOUND'],
    [
      'adminWrite',
      'DELETE',
      `/api/v0/scm-connections/${connectionId}`,
      undefined,
      403,
      'INSUFFICIENT_SCOPE',
    ],
    // AI (requireOrganizationAccess, issueForUser, requestAi)
    ['member', 'GET', `/api/v0/organizations/${org}/ai`, undefined, 200],
    ['outsider', 'GET', `/api/v0/organizations/${org}/ai`, undefined, 404, 'NOT_FOUND'],
    ['member', 'GET', `/api/v0/issues/${issueId}/ai`, undefined, 200],
    ['outsider', 'GET', `/api/v0/issues/${issueId}/ai`, undefined, 404, 'NOT_FOUND'],
    ['memberRead', 'POST', `/api/v0/issues/${issueId}/ai/explain`, {}, 403, 'INSUFFICIENT_SCOPE'],
    ['outsider', 'POST', `/api/v0/issues/${issueId}/ai/explain`, {}, 404, 'NOT_FOUND'],
    ['member', 'POST', `/api/v0/issues/${issueId}/ai/explain`, {}, 409, 'AI_DISABLED'],
    // Rules (requireOrganizationAccess, ruleFor)
    ['member', 'GET', `/api/v0/rules?organizationId=${org}`, undefined, 200],
    ['outsider', 'GET', `/api/v0/rules?organizationId=${org}`, undefined, 404, 'NOT_FOUND'],
    ['member', 'GET', `/api/v0/rules/eslint%3Ano-eval?organizationId=${org}`, undefined, 200],
    [
      'outsider',
      'GET',
      `/api/v0/rules/eslint%3Ano-eval?organizationId=${org}`,
      undefined,
      404,
      'NOT_FOUND',
    ],
  ];

  it('answers each request as before', async () => {
    await run(ctx, headers, rows());
  });

  it('shows the outsider no project in the list', async () => {
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/projects',
      headers: headers.outsider,
    });
    expect((res.json() as { items: unknown[] }).items).toEqual([]);
  });
});

describe('community roles keep today’s order in a second organisation (rbac-audit.md §3.3)', () => {
  let ctx: TestContext;
  const headers: Partial<Record<Who, Record<string, string>>> = {};
  let org: string;
  let project: { id: string; key: string };
  let issueId: string;

  beforeAll(async () => {
    ctx = await createTestContext({
      edition: fixedEdition(communityLimits()),
    });
    const root: Session = await login(ctx, 'admin', ADMIN_PASSWORD);
    headers.root = root.headers;
    // A second organisation, newer than `default` (enterprise.md §8: none is ever read-only).
    const [created] = await ctx.db
      .insert(organizations)
      .values({ key: 'late', name: 'late', createdAt: sql`now() + interval '1 minute'` })
      .returning({ id: organizations.id });
    org = created!.id;
    const bob = await createUser(ctx, { username: 'bob' });
    const alice = await createUser(ctx, { username: 'alice' });
    await createUser(ctx, { username: 'carol' });
    await addMember(ctx, org, bob.id, 'admin');
    await addMember(ctx, org, alice.id, 'member');
    headers.admin = (await login(ctx, 'bob', bob.password)).headers;
    headers.member = (await login(ctx, 'alice', alice.password)).headers;
    headers.outsider = (await login(ctx, 'carol', DEFAULT_TEST_PASSWORD)).headers;
    headers.memberRead = await personalToken(ctx, headers.member, ['read']);
    headers.adminWrite = await personalToken(ctx, headers.admin, ['write']);
    // Seeded directly, as this block always did.
    const [p] = await ctx.db
      .insert(projects)
      .values({ organizationId: org, key: 'ro-app', name: 'ro-app', mainBranchName: 'main' })
      .returning({ id: projects.id, key: projects.key });
    project = p!;
    const [b] = await ctx.db
      .insert(branches)
      .values({ projectId: project.id, kind: 'branch', name: 'main', isMain: true })
      .returning({ id: branches.id });
    const ruleId = await seedRule(ctx.db, { key: 'eslint:no-eval' });
    issueId = await seedIssue(ctx.db, { projectId: project.id, branchId: b!.id, ruleId });
  });
  afterAll(async () => ctx.close());

  const rows = (): Row[] => [
    ['member', 'GET', `/api/v0/projects/${project.id}`, undefined, 200],
    ['outsider', 'PATCH', `/api/v0/projects/${project.id}`, { name: 'x' }, 404, 'NOT_FOUND'],
    ['member', 'PATCH', `/api/v0/projects/${project.id}`, { name: 'x' }, 403, 'FORBIDDEN'],
    [
      'adminWrite',
      'PATCH',
      `/api/v0/projects/${project.id}`,
      { name: 'x' },
      403,
      'INSUFFICIENT_SCOPE',
    ],
    [
      'outsider',
      'POST',
      `/api/v0/issues/${issueId}/transition`,
      { to: 'resolved' },
      404,
      'NOT_FOUND',
    ],
    [
      'memberRead',
      'POST',
      `/api/v0/issues/${issueId}/transition`,
      { to: 'resolved' },
      403,
      'INSUFFICIENT_SCOPE',
    ],
    ['member', 'GET', `/api/v0/issues/${issueId}`, undefined, 200],
    [
      'member',
      'POST',
      '/api/v0/quality-gates',
      { organizationId: org, name: 'm' },
      403,
      'FORBIDDEN',
    ],
    ['member', 'GET', `/api/v0/quality-gates?organizationId=${org}`, undefined, 200],
    [
      'memberRead',
      'POST',
      `/api/v0/analyses?projectKey=${project.key}`,
      undefined,
      403,
      'INSUFFICIENT_SCOPE',
    ],
    [
      'outsider',
      'POST',
      `/api/v0/analyses?projectKey=${project.key}`,
      undefined,
      404,
      'PROJECT_NOT_FOUND',
    ],
  ];

  it('answers each request as before', async () => {
    await run(ctx, headers, rows());
  });
});

/**
 * rbac-audit.md §3.2, §6: a community server (no licence) with the extra roles and a grant. They
 * act as stored: the grant gives its project set and org.read, a stored project_admin
 * administers projects, a stored viewer stays read-only.
 */
describe('stored roles and grants act as §3.2 says on a community server (rbac-audit.md §6)', () => {
  let ctx: TestContext;
  const headers: Partial<Record<Who, Record<string, string>>> = {};
  let org: string;
  let project: { id: string; key: string };
  let issueId: string;

  beforeAll(async () => {
    ctx = await createTestContext();
    const root = await login(ctx, 'admin', ADMIN_PASSWORD);
    headers.root = root.headers;
    org = await organizationId(ctx, 'default');
    project = await createProject(ctx, root, { organizationId: org, key: 'stored' });
    const branchId = await mainBranchId(ctx.db, project.id);
    const ruleId = await seedRule(ctx.db, { key: 'eslint:no-eval' });
    issueId = await seedIssue(ctx.db, { projectId: project.id, branchId, ruleId });
    const admin = await createUser(ctx, { username: 'bob' });
    const granted = await createUser(ctx, { username: 'gina' });
    const padmin = await createUser(ctx, { username: 'pete' });
    const viewer = await createUser(ctx, { username: 'vera' });
    await addMember(ctx, org, admin.id, 'admin');
    await addMember(ctx, org, padmin.id, 'project_admin');
    await addMember(ctx, org, viewer.id, 'viewer');
    await grantProject(ctx, project.id, granted.id, 'project_admin');
    headers.admin = (await login(ctx, 'bob', admin.password)).headers;
    headers.granted = (await login(ctx, 'gina', granted.password)).headers;
    headers.storedProjectAdmin = (await login(ctx, 'pete', padmin.password)).headers;
    headers.storedViewer = (await login(ctx, 'vera', viewer.password)).headers;
    headers.storedViewerUpload = await personalToken(ctx, headers.storedViewer, ['analysis:write']);
  });
  afterAll(async () => ctx.close());

  const rows = (): Row[] => [
    // A project_admin grant without a membership: its project set and org.read (§3.2).
    ['granted', 'GET', `/api/v0/projects/${project.id}`, undefined, 200],
    ['granted', 'GET', `/api/v0/projects/by-key?key=${project.key}`, undefined, 200],
    ['granted', 'GET', `/api/v0/issues/${issueId}`, undefined, 200],
    ['granted', 'GET', `/api/v0/quality-gates?organizationId=${org}`, undefined, 200],
    ['granted', 'POST', `/api/v0/analyses?projectKey=${project.key}`, undefined, 202],
    ['granted', 'PATCH', `/api/v0/projects/${project.id}`, { name: 'x' }, 200],
    ['granted', 'GET', `/api/v0/projects/${project.id}/tokens`, undefined, 200],
    [
      'granted',
      'DELETE',
      `/api/v0/projects/${project.id}?confirm=${project.key}`,
      undefined,
      403,
      'FORBIDDEN',
    ],
    // A stored project_admin administers the organisation's projects.
    ['storedProjectAdmin', 'GET', `/api/v0/projects/${project.id}`, undefined, 200],
    ['storedProjectAdmin', 'PATCH', `/api/v0/projects/${project.id}`, { name: 'x' }, 200],
    ['storedProjectAdmin', 'GET', `/api/v0/projects/${project.id}/tokens`, undefined, 200],
    [
      'storedProjectAdmin',
      'POST',
      `/api/v0/quality-gates`,
      { organizationId: org, name: 'g' },
      403,
      'FORBIDDEN',
    ],
    ['storedProjectAdmin', 'POST', `/api/v0/issues/${issueId}/transition`, { to: 'resolved' }, 200],
    ['storedProjectAdmin', 'POST', `/api/v0/issues/${issueId}/transition`, { to: 'open' }, 200],
    // A stored viewer stays read-only.
    ['storedViewer', 'GET', `/api/v0/projects/${project.id}`, undefined, 200],
    ['storedViewer', 'GET', `/api/v0/issues/${issueId}`, undefined, 200],
    [
      'storedViewer',
      'POST',
      `/api/v0/issues/${issueId}/transition`,
      { to: 'resolved' },
      403,
      'FORBIDDEN',
    ],
    [
      'storedViewer',
      'POST',
      `/api/v0/analyses?projectKey=${project.key}`,
      undefined,
      403,
      'FORBIDDEN',
    ],
    [
      'storedViewerUpload',
      'POST',
      `/api/v0/analyses?projectKey=${project.key}`,
      undefined,
      403,
      'FORBIDDEN',
    ],
    // An organisation admin still uploads.
    ['admin', 'POST', `/api/v0/analyses?projectKey=${project.key}`, undefined, 202],
  ];

  it('answers each request as the table says', async () => {
    await run(ctx, headers, rows());
  });

  it('leaves the viewer’s refused transition unwritten', async () => {
    const res = await ctx.db.execute<{ status: string; changes: number }>(sql`
      SELECT i.status, (SELECT count(*) FROM issue_changes c WHERE c.issue_id = i.id)::int AS changes
        FROM issues i WHERE i.id = ${issueId}`);
    // Two changes by the stored project_admin (resolved, then open); none by the viewer.
    expect(res.rows).toEqual([{ status: 'open', changes: 2 }]);
  });

  it('lists the project and the organisation a grant makes visible', async () => {
    const projectsRes = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/projects',
      headers: headers.granted,
    });
    expect((projectsRes.json() as { items: { id: string }[] }).items.map((p) => p.id)).toEqual([
      project.id,
    ]);
    const orgsRes = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/organizations',
      headers: headers.granted,
    });
    expect((orgsRes.json() as { items: { id: string }[] }).items.map((o) => o.id)).toEqual([org]);
    const me = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/auth/me',
      headers: headers.granted,
    });
    expect(me.json()).toMatchObject({
      memberships: [{ organizationId: org, role: null, permissions: ['org.read'] }],
      projectGrants: [
        {
          projectId: project.id,
          projectKey: project.key,
          organizationId: org,
          role: 'project_admin',
        },
      ],
    });
  });
});
