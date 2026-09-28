import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  bearer,
  createProject,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { AFTER_GRACE, grantProject, rbacContext } from '../../test/rbac';
import { gzipJson, REPORT_CONTENT_TYPE, sampleReport } from '../../test/reports';
import { issueChanges, issues } from '../db/schema';
import { communityLimits } from '../limits';

const LICENSED = new Date('2027-01-01T00:00:00Z');

interface Me {
  memberships: { organizationId: string; role: string | null; permissions: string[] }[];
  projectGrants: { projectId: string; projectKey: string; organizationId: string; role: string }[];
}

describe('roles and project grants (rbac-audit.md §3.2, §6)', () => {
  let now = LICENSED;
  let ctx: TestContext;
  let org: string;
  let otherOrg: string;
  let p1: { id: string; key: string };
  let p2: { id: string; key: string };
  let p3: { id: string; key: string };
  let issue1: string;
  let viewerId: string;
  const s: Record<string, Session> = {};

  beforeAll(async () => {
    ctx = await rbacContext({ now: () => now });
    const root = await login(ctx, 'admin', ADMIN_PASSWORD);
    s.root = root;
    org = await organizationId(ctx, 'default');
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/organizations',
      headers: root.headers,
      payload: { key: 'other', name: 'Other' },
    });
    expect(created.statusCode).toBe(201);
    otherOrg = (created.json() as { id: string }).id;
    p1 = await createProject(ctx, root, { organizationId: org, key: 'r1' });
    p2 = await createProject(ctx, root, { organizationId: org, key: 'r2' });
    p3 = await createProject(ctx, root, { organizationId: otherOrg, key: 'r3' });
    const ruleId = await seedRule(ctx.db, { key: 'eslint:no-eval' });
    issue1 = await seedIssue(ctx.db, {
      projectId: p1.id,
      branchId: await mainBranchId(ctx.db, p1.id),
      ruleId,
    });
    const viewer = await createUser(ctx, { username: 'viewer' });
    viewerId = viewer.id;
    const padmin = await createUser(ctx, { username: 'padmin' });
    const grantOnly = await createUser(ctx, { username: 'grantonly' });
    const widened = await createUser(ctx, { username: 'widened' });
    const orgAdmin = await createUser(ctx, { username: 'orgadmin' });
    await addMember(ctx, org, viewer.id, 'viewer');
    await addMember(ctx, org, padmin.id, 'project_admin');
    await addMember(ctx, org, widened.id, 'viewer');
    await addMember(ctx, org, orgAdmin.id, 'admin');
    await grantProject(ctx, p1.id, grantOnly.id, 'viewer');
    await grantProject(ctx, p1.id, widened.id, 'member');
    // A grant below the organisation role takes nothing away (ruling RB4).
    await grantProject(ctx, p1.id, padmin.id, 'viewer');
    for (const u of [viewer, padmin, grantOnly, widened, orgAdmin]) {
      s[u.username] = await login(ctx, u.username, u.password);
    }
  });
  afterAll(async () => ctx.close());

  const call = (
    who: string,
    method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE',
    url: string,
    payload?: unknown,
  ) =>
    ctx.app.inject({
      method,
      url,
      headers: s[who]!.headers,
      ...(payload === undefined ? {} : { payload: payload as never }),
    });

  const upload = (headers: Record<string, string>, projectKey: string) =>
    ctx.app.inject({
      method: 'POST',
      url: `/api/v0/analyses?projectKey=${projectKey}`,
      headers: { ...headers, 'content-type': REPORT_CONTENT_TYPE, 'content-encoding': 'gzip' },
      payload: gzipJson(sampleReport()),
    });

  const issueTrail = async () => {
    const [issue] = await ctx.db
      .select({ status: issues.status })
      .from(issues)
      .where(eq(issues.id, issue1));
    const changes = await ctx.db
      .select({ id: issueChanges.id })
      .from(issueChanges)
      .where(eq(issueChanges.issueId, issue1));
    return { status: issue!.status, changes: changes.length };
  };

  it('a viewer reads and does nothing else', async () => {
    expect((await call('viewer', 'GET', `/api/v0/projects/${p1.id}`)).statusCode).toBe(200);
    expect((await call('viewer', 'GET', `/api/v0/issues/${issue1}`)).statusCode).toBe(200);
    expect(
      (await call('viewer', 'GET', `/api/v0/quality-gates?organizationId=${org}`)).statusCode,
    ).toBe(200);
    const before = await issueTrail();
    const transition = await call('viewer', 'POST', `/api/v0/issues/${issue1}/transition`, {
      to: 'resolved',
    });
    expect([transition.statusCode, transition.json().code]).toEqual([403, 'FORBIDDEN']);
    expect(await issueTrail()).toEqual(before);
    const ai = await call('viewer', 'POST', `/api/v0/issues/${issue1}/ai/explain`, {});
    expect([ai.statusCode, ai.json().code]).toEqual([403, 'FORBIDDEN']);
    expect(
      (await call('viewer', 'PATCH', `/api/v0/projects/${p1.id}`, { name: 'x' })).statusCode,
    ).toBe(403);
  });

  it('a viewer’s personal token with analysis:write cannot upload', async () => {
    const created = await call('viewer', 'POST', '/api/v0/tokens', {
      name: 'ci',
      scopes: ['analysis:write'],
    });
    expect(created.statusCode).toBe(201);
    const res = await upload(bearer((created.json() as { token: string }).token), p1.key);
    expect([res.statusCode, res.json().code]).toEqual([403, 'FORBIDDEN']);
  });

  it('a project admin administers projects, not the organisation', async () => {
    expect(
      (await call('padmin', 'PATCH', `/api/v0/projects/${p1.id}`, { name: 'r1' })).statusCode,
    ).toBe(200);
    expect(
      (await call('padmin', 'POST', `/api/v0/projects/${p1.id}/tokens`, { name: 'ci' })).statusCode,
    ).toBe(201);
    expect((await call('padmin', 'GET', `/api/v0/projects/${p2.id}/tokens`)).statusCode).toBe(200);
    expect(
      (await call('padmin', 'POST', '/api/v0/quality-gates', { organizationId: org, name: 'g' }))
        .statusCode,
    ).toBe(403);
    const del = await call('padmin', 'DELETE', `/api/v0/projects/${p1.id}?confirm=${p1.key}`);
    expect([del.statusCode, del.json().code]).toEqual([403, 'FORBIDDEN']);
    const members = await call(
      'padmin',
      'PUT',
      `/api/v0/organizations/${org}/members/${viewerId}`,
      {
        role: 'member',
      },
    );
    expect([members.statusCode, members.json().code]).toEqual([403, 'FORBIDDEN']);
  });

  it('only an org admin maps a project to an SCM repository (§3.4 notes)', async () => {
    const granted = await createUser(ctx, { username: 'grantpadmin' });
    await grantProject(ctx, p2.id, granted.id, 'project_admin');
    s.grantpadmin = await login(ctx, granted.username, granted.password);
    const mappings = [
      { scmConnectionId: null },
      { scmProjectRef: null },
      { scmConnectionId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60', scmProjectRef: 'group/repo' },
      { name: 'r2', scmProjectRef: null },
    ];
    for (const who of ['padmin', 'grantpadmin']) {
      for (const body of mappings) {
        const res = await call(who, 'PATCH', `/api/v0/projects/${p2.id}`, body);
        expect([who, body, res.statusCode, res.json().code]).toEqual([who, body, 403, 'FORBIDDEN']);
      }
      const other = await call(who, 'PATCH', `/api/v0/projects/${p2.id}`, { name: 'r2' });
      expect([who, other.statusCode]).toEqual([who, 200]);
    }
    for (const who of ['orgadmin', 'root']) {
      const res = await call(who, 'PATCH', `/api/v0/projects/${p2.id}`, {
        scmConnectionId: null,
        scmProjectRef: null,
      });
      expect([who, res.statusCode]).toEqual([who, 200]);
    }
  });

  it('a grant-only user sees the granted project and its organisation, nothing else', async () => {
    const list = await call('grantonly', 'GET', '/api/v0/projects');
    expect((list.json() as { items: { id: string }[] }).items.map((p) => p.id)).toEqual([p1.id]);
    expect((await call('grantonly', 'GET', `/api/v0/projects/${p2.id}`)).statusCode).toBe(404);
    expect((await call('grantonly', 'GET', `/api/v0/projects/${p3.id}`)).statusCode).toBe(404);
    expect(
      (await call('grantonly', 'GET', `/api/v0/quality-gates?organizationId=${org}`)).statusCode,
    ).toBe(200);
    expect(
      (await call('grantonly', 'GET', `/api/v0/quality-gates?organizationId=${otherOrg}`))
        .statusCode,
    ).toBe(404);
    const orgs = await call('grantonly', 'GET', '/api/v0/organizations');
    expect((orgs.json() as { items: { id: string }[] }).items.map((o) => o.id)).toEqual([org]);
    const me = (await call('grantonly', 'GET', '/api/v0/auth/me')).json() as Me;
    expect(me.memberships).toEqual([
      expect.objectContaining({ organizationId: org, role: null, permissions: ['org.read'] }),
    ]);
    expect(me.projectGrants).toEqual([
      { projectId: p1.id, projectKey: 'r1', organizationId: org, role: 'viewer' },
    ]);
  });

  it('a project grant widens an organisation viewer on that project only', async () => {
    expect(
      (await call('widened', 'POST', `/api/v0/issues/${issue1}/transition`, { to: 'resolved' }))
        .statusCode,
    ).toBe(200);
    expect(
      (await call('widened', 'POST', `/api/v0/issues/${issue1}/transition`, { to: 'open' }))
        .statusCode,
    ).toBe(200);
    const other = (await call('widened', 'GET', `/api/v0/projects/${p2.id}`)).json() as {
      permissions: string[];
    };
    expect(other.permissions).toEqual(['project.read']);
  });

  it('reports each caller’s permissions (/auth/me, project DTOs)', async () => {
    const me = (await call('padmin', 'GET', '/api/v0/auth/me')).json() as Me;
    expect(me.memberships).toEqual([
      expect.objectContaining({
        organizationId: org,
        role: 'project_admin',
        permissions: ['org.read'],
      }),
    ]);
    const project = (await call('grantonly', 'GET', `/api/v0/projects/${p1.id}`)).json() as {
      permissions: string[];
    };
    expect(project.permissions).toEqual(['project.read']);
    const padminP1 = (await call('padmin', 'GET', `/api/v0/projects/by-key?key=r1`)).json() as {
      permissions: string[];
    };
    expect(padminP1.permissions).toEqual(
      [
        'ai.use',
        'issue.triage',
        'project.analyze',
        'project.branches.delete',
        'project.issues.import',
        'project.read',
        'project.settings',
        'project.tokens.manage',
      ].sort(),
    );
    const admin = (await call('orgadmin', 'GET', '/api/v0/auth/me')).json() as Me;
    expect(admin.memberships[0]?.permissions).toContain('org.members.manage');
    const rootMe = (await call('root', 'GET', '/api/v0/auth/me')).json() as Me;
    // The instance admin lists its own organisations, not every one it may administer.
    expect(rootMe.memberships.map((m) => m.organizationId).sort()).toEqual([org, otherOrg].sort());
    const listed = (await call('root', 'GET', '/api/v0/projects')).json() as {
      items: { permissions: string[] }[];
    };
    expect(listed.items.every((p) => p.permissions.includes('project.delete'))).toBe(true);
  });

  it('no role lapse: roles and grants act as stored after grace', async () => {
    const snapshot = sql`SELECT
      (SELECT json_agg(m ORDER BY m.organization_id, m.user_id) FROM memberships m) AS m,
      (SELECT json_agg(g ORDER BY g.project_id, g.user_id) FROM project_memberships g) AS g`;
    const counts = sql`SELECT (SELECT count(*) FROM memberships)::int AS m,
      (SELECT count(*) FROM project_memberships)::int AS g`;
    const before = await ctx.db.execute(snapshot);
    const countsBefore = await ctx.db.execute(counts);
    now = AFTER_GRACE;
    try {
      // The viewer is still read-only: nothing widens.
      const trail = await issueTrail();
      const transition = await call('viewer', 'POST', `/api/v0/issues/${issue1}/transition`, {
        to: 'resolved',
      });
      expect([transition.statusCode, transition.json().code]).toEqual([403, 'FORBIDDEN']);
      expect(await issueTrail()).toEqual(trail);
      const viewerP1 = await call('viewer', 'GET', `/api/v0/projects/${p1.id}`);
      expect(viewerP1.statusCode).toBe(200);
      expect((viewerP1.json() as { permissions: string[] }).permissions).toEqual(['project.read']);
      // The organisation-level project admin still changes project settings.
      expect(
        (await call('padmin', 'PATCH', `/api/v0/projects/${p1.id}`, { name: 'r1' })).statusCode,
      ).toBe(200);
      const padminMe = (await call('padmin', 'GET', '/api/v0/auth/me')).json() as Me;
      expect(padminMe.memberships).toEqual([
        expect.objectContaining({ role: 'project_admin', permissions: ['org.read'] }),
      ]);
      expect(padminMe.projectGrants).toEqual([
        { projectId: p1.id, projectKey: 'r1', organizationId: org, role: 'viewer' },
      ]);
      // The grant still widens the organisation viewer on its project.
      expect(
        (await call('widened', 'POST', `/api/v0/issues/${issue1}/transition`, { to: 'resolved' }))
          .statusCode,
      ).toBe(200);
      expect(
        (await call('widened', 'POST', `/api/v0/issues/${issue1}/transition`, { to: 'open' }))
          .statusCode,
      ).toBe(200);
      // The grant-only user still reads its project, and only it.
      expect((await call('grantonly', 'GET', `/api/v0/projects/${p1.id}`)).statusCode).toBe(200);
      const list = (await call('grantonly', 'GET', '/api/v0/projects')).json() as {
        items: { id: string }[];
      };
      expect(list.items.map((p) => p.id)).toEqual([p1.id]);
      const me = (await call('grantonly', 'GET', '/api/v0/auth/me')).json() as Me;
      expect(me.projectGrants).toEqual([
        { projectId: p1.id, projectKey: 'r1', organizationId: org, role: 'viewer' },
      ]);
      expect((await ctx.db.execute(counts)).rows).toEqual(countsBefore.rows);
      expect((await ctx.db.execute(snapshot)).rows).toEqual(before.rows);
    } finally {
      now = LICENSED;
    }
  });
});

describe('a community server (rbac-audit.md §6.1)', () => {
  let ctx: TestContext;
  let root: Session;
  let org: string;
  let project: { id: string; key: string };
  let issue: string;
  let branchId: string;
  const s: Record<string, Session> = {};
  const ids: Record<string, string> = {};

  beforeAll(async () => {
    ctx = await createTestContext({ limits: communityLimits() });
    root = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    project = await createProject(ctx, root, { organizationId: org, key: 'c1' });
    branchId = await mainBranchId(ctx.db, project.id);
    issue = await seedIssue(ctx.db, {
      projectId: project.id,
      branchId,
      ruleId: await seedRule(ctx.db, { key: 'eslint:no-eval' }),
    });
    for (const username of ['eve', 'cviewer', 'cpadmin', 'cgrant']) {
      const u = await createUser(ctx, { username });
      ids[username] = u.id;
      s[username] = await login(ctx, u.username, u.password);
    }
  });
  afterAll(async () => ctx.close());

  const put = (userId: string, role: string) =>
    ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/organizations/${org}/members/${userId}`,
      headers: root.headers,
      payload: { role },
    });

  const call = (who: string, method: 'GET' | 'POST' | 'PATCH', url: string, payload?: unknown) =>
    ctx.app.inject({
      method,
      url,
      headers: s[who]!.headers,
      ...(payload === undefined ? {} : { payload: payload as never }),
    });

  it.each(['viewer', 'project_admin', 'member', 'admin'])('accepts %s', async (role) => {
    const res = await put(ids.eve!, role);
    expect([res.statusCode, res.json().role]).toEqual([200, role]);
  });

  it('a community server assigns all four roles and enforces them', async () => {
    const viewer = await put(ids.cviewer!, 'viewer');
    expect([viewer.statusCode, viewer.json().role]).toEqual([200, 'viewer']);
    const padmin = await put(ids.cpadmin!, 'project_admin');
    expect([padmin.statusCode, padmin.json().role]).toEqual([200, 'project_admin']);

    expect((await call('cviewer', 'GET', `/api/v0/issues?branchId=${branchId}`)).statusCode).toBe(
      200,
    );
    const transition = await call('cviewer', 'POST', `/api/v0/issues/${issue}/transition`, {
      to: 'resolved',
    });
    expect([transition.statusCode, transition.json().code]).toEqual([403, 'FORBIDDEN']);

    expect(
      (await call('cpadmin', 'PATCH', `/api/v0/projects/${project.id}`, { name: 'c1' })).statusCode,
    ).toBe(200);
    const gate = await call('cpadmin', 'POST', '/api/v0/quality-gates', {
      organizationId: org,
      name: 'g',
    });
    expect([gate.statusCode, gate.json().code]).toEqual([403, 'FORBIDDEN']);
  });

  it('lists memberships with their permissions and the project grants in /auth/me', async () => {
    const me = (
      await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/me', headers: root.headers })
    ).json() as Me;
    expect(me.memberships).toEqual([
      expect.objectContaining({ organizationId: org, role: 'admin' }),
    ]);
    expect(me.memberships[0]!.permissions).toContain('org.members.manage');
    expect(me.projectGrants).toEqual([]);

    await grantProject(ctx, project.id, ids.cgrant!, 'member');
    const granted = (await call('cgrant', 'GET', '/api/v0/auth/me')).json() as Me;
    expect(granted.memberships).toEqual([
      expect.objectContaining({ organizationId: org, role: null, permissions: ['org.read'] }),
    ]);
    expect(granted.projectGrants).toEqual([
      { projectId: project.id, projectKey: 'c1', organizationId: org, role: 'member' },
    ]);
    expect((await call('cgrant', 'GET', `/api/v0/projects/${project.id}`)).statusCode).toBe(200);
  });

  it('writes no audit event', async () => {
    const counts = await ctx.db.execute(sql`SELECT count(*)::int AS a FROM audit_events`);
    expect(counts.rows[0]).toEqual({ a: 0 });
  });
});

describe('assigning roles under a pre-5B licence listing rbac (rbac-audit.md §6.1)', () => {
  let ctx: TestContext;
  let root: Session;
  let org: string;
  let userId: string;

  beforeAll(async () => {
    ctx = await rbacContext({ now: () => LICENSED });
    root = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    userId = (await createUser(ctx, { username: 'eve' })).id;
  });
  afterAll(async () => ctx.close());

  it.each(['viewer', 'project_admin', 'member', 'admin'])('accepts %s', async (role) => {
    const res = await ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/organizations/${org}/members/${userId}`,
      headers: root.headers,
      payload: { role },
    });
    expect([res.statusCode, res.json().role]).toEqual([200, role]);
  });
});
