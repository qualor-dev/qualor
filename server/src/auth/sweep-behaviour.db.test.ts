import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  createProject,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';

describe('reads, lists and bulk changes through the policy (rbac-audit.md §5, §6)', () => {
  let ctx: TestContext;
  let viewer: Session;
  let orgAdmin: Session;
  let outsider: Session;
  let org: string;
  let issueId: string;
  let projectId: string;

  beforeAll(async () => {
    ctx = await createTestContext();
    const root = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    projectId = (await createProject(ctx, root, { organizationId: org, key: 'sw' })).id;
    const ruleId = await seedRule(ctx.db, { key: 'eslint:no-eval' });
    issueId = await seedIssue(ctx.db, {
      projectId,
      branchId: await mainBranchId(ctx.db, projectId),
      ruleId,
    });
    const v = await createUser(ctx, { username: 'vic' });
    const a = await createUser(ctx, { username: 'ada' });
    const o = await createUser(ctx, { username: 'otto' });
    await createUser(ctx, { username: 'gone', active: false });
    await addMember(ctx, org, v.id, 'viewer'); // left from a licensed period
    await addMember(ctx, org, a.id, 'admin');
    viewer = await login(ctx, 'vic', v.password);
    orgAdmin = await login(ctx, 'ada', a.password);
    outsider = await login(ctx, 'otto', o.password);
  });
  afterAll(async () => ctx.close());

  const call = (s: Session, method: 'GET' | 'POST', url: string, payload?: object) =>
    ctx.app.inject({
      method,
      url,
      headers: s.headers,
      ...(payload === undefined ? {} : { payload }),
    });

  it('lets a stored viewer read but not triage, one issue or in bulk', async () => {
    expect((await call(viewer, 'GET', `/api/v0/issues/${issueId}`)).statusCode).toBe(200);
    const one = await call(viewer, 'POST', `/api/v0/issues/${issueId}/transition`, {
      to: 'resolved',
    });
    expect(one.statusCode).toBe(403);
    expect(one.json()).toMatchObject({ code: 'FORBIDDEN' });
    // Refused before anything changed, not after.
    const after = await call(viewer, 'GET', `/api/v0/issues/${issueId}`);
    expect(after.json()).toMatchObject({ status: 'open' });
    const bulk = await call(viewer, 'POST', '/api/v0/issues/bulk-transition', {
      ids: [issueId],
      to: 'resolved',
    });
    expect(bulk.statusCode).toBe(200);
    expect(bulk.json()).toEqual({ succeeded: [], failed: [{ id: issueId, code: 'FORBIDDEN' }] });
    const outside = await call(outsider, 'POST', '/api/v0/issues/bulk-transition', {
      ids: [issueId],
      to: 'resolved',
    });
    expect(outside.json()).toEqual({ succeeded: [], failed: [{ id: issueId, code: 'NOT_FOUND' }] });
  });

  it("lists the viewer's projects, and nothing for an outsider", async () => {
    const projects = await call(viewer, 'GET', '/api/v0/projects');
    expect((projects.json() as { items: { id: string }[] }).items.map((p) => p.id)).toContain(
      projectId,
    );
    const orgs = await call(outsider, 'GET', '/api/v0/organizations');
    expect((orgs.json() as { items: unknown[] }).items).toEqual([]);
    const none = await call(outsider, 'GET', '/api/v0/projects');
    expect((none.json() as { items: unknown[] }).items).toEqual([]);
  });

  it('finds a user by exact name for an org admin only, and tells nothing more', async () => {
    const found = await call(orgAdmin, 'GET', '/api/v0/users/lookup?username=VIC');
    expect(found.statusCode).toBe(200);
    expect(found.json()).toMatchObject({ username: 'vic' });
    // No email, admin flag or active status: the lookup must not enumerate more than a name.
    expect(Object.keys(found.json() as object).sort()).toEqual(['displayName', 'id', 'username']);
    expect((await call(orgAdmin, 'GET', '/api/v0/users/lookup?username=vi')).statusCode).toBe(404);
    expect((await call(orgAdmin, 'GET', '/api/v0/users/lookup?username=gone')).statusCode).toBe(
      404,
    );
    expect((await call(viewer, 'GET', '/api/v0/users/lookup?username=ada')).statusCode).toBe(403);
    expect((await call(outsider, 'GET', '/api/v0/users/lookup?username=ada')).statusCode).toBe(403);
  });

  it('limits the lookup to 30 a minute per caller, not per address', async () => {
    const m = await createUser(ctx, { username: 'mia' });
    await addMember(ctx, org, m.id, 'admin');
    const mia = await login(ctx, 'mia', m.password);
    for (let n = 0; n < 30; n += 1) {
      expect((await call(mia, 'GET', '/api/v0/users/lookup?username=vic')).statusCode).toBe(200);
    }
    const limited = await call(mia, 'GET', '/api/v0/users/lookup?username=vic');
    expect(limited.statusCode).toBe(429);
    expect(limited.json()).toMatchObject({ code: 'RATE_LIMITED' });
    // Another org admin from the same address still has its own budget.
    expect((await call(orgAdmin, 'GET', '/api/v0/users/lookup?username=vic')).statusCode).toBe(200);
  });
});
