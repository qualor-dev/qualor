import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { VERSION } from '../index';
import {
  addMember,
  ADMIN_PASSWORD,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { adminHeaders, oidcConnection, ssoContext } from '../../test/sso';
import { memberships } from '../db/schema';

describe('organizations and members', () => {
  let ctx: TestContext;
  let admin: Session;
  let orgAdmin: Session;
  let member: Session;
  let outsider: Session;
  let teamId: string;
  let memberId: string;

  const call = (
    method: 'GET' | 'POST' | 'PUT' | 'DELETE',
    url: string,
    headers: Record<string, string>,
    payload?: object,
  ) => ctx.app.inject({ method, url: `/api/v0${url}`, headers, ...(payload ? { payload } : {}) });
  const paths = (res: { json(): { errors?: { path: string }[] } }) =>
    (res.json().errors ?? []).map((e) => e.path);

  beforeAll(async () => {
    ctx = await createTestContext();
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const created = await call('POST', '/organizations', admin.headers, {
      key: 'team-x',
      name: 'Team X',
    });
    teamId = created.json().id;
    const a = await createUser(ctx, { username: 'org-admin' });
    const m = await createUser(ctx, { username: 'org-member' });
    const o = await createUser(ctx, { username: 'outsider' });
    memberId = m.id;
    await addMember(ctx, teamId, a.id, 'admin');
    await addMember(ctx, teamId, m.id, 'member');
    orgAdmin = await login(ctx, a.username, a.password);
    member = await login(ctx, m.username, m.password);
    outsider = await login(ctx, o.username, o.password);
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('creates an organisation whose creator is its admin', async () => {
    const res = await call('GET', `/organizations/${teamId}/members`, admin.headers);
    expect(res.statusCode).toBe(200);
    expect(res.json().items).toContainEqual(
      expect.objectContaining({ username: 'admin', role: 'admin' }),
    );
  });

  it('validates POST /organizations (422) and rejects duplicate keys (409)', async () => {
    expect(
      paths(await call('POST', '/organizations', admin.headers, { key: 'Bad Key', name: 'x' })),
    ).toEqual(['body.key']);
    expect(paths(await call('POST', '/organizations', admin.headers, { key: 'ok-key' }))).toEqual([
      'body.name',
    ]);
    const dup = await call('POST', '/organizations', admin.headers, {
      key: 'team-x',
      name: 'Again',
    });
    expect([dup.statusCode, dup.json().code]).toEqual([409, 'ORG_KEY_TAKEN']);
  });

  it('lets only instance admins create organisations (401/403)', async () => {
    expect(
      (await call('POST', '/organizations', {}, { key: 'nope', name: 'Nope' })).statusCode,
    ).toBe(401);
    expect(
      (await call('POST', '/organizations', orgAdmin.headers, { key: 'nope', name: 'Nope' }))
        .statusCode,
    ).toBe(403);
  });

  it('a fourth and a fifth organisation can be created in the community edition', async () => {
    for (const key of ['third', 'fourth', 'fifth']) {
      expect(
        (await call('POST', '/organizations', admin.headers, { key, name: key })).statusCode,
      ).toBe(201);
    }
  });

  it('lists the organisations the caller can see (ruling R11)', async () => {
    const keys = async (s: Session) =>
      (await call('GET', '/organizations', s.headers))
        .json()
        .items.map((o: { key: string }) => o.key)
        .sort();
    expect(await keys(admin)).toEqual(['default', 'fifth', 'fourth', 'team-x', 'third']);
    expect(await keys(member)).toEqual(['team-x']);
    expect(await keys(outsider)).toEqual([]);
    expect((await call('GET', '/organizations', {})).statusCode).toBe(401);
    expect(paths(await call('GET', '/organizations?limit=501', admin.headers))).toEqual([
      'query.limit',
    ]);
  });

  it('lets org admins manage members; 403 for members, 404 for outsiders', async () => {
    expect(
      (await call('GET', `/organizations/${teamId}/members`, orgAdmin.headers)).statusCode,
    ).toBe(200);
    expect((await call('GET', `/organizations/${teamId}/members`, member.headers)).statusCode).toBe(
      403,
    );
    expect(
      (await call('GET', `/organizations/${teamId}/members`, outsider.headers)).statusCode,
    ).toBe(404);
    expect((await call('GET', `/organizations/${teamId}/members`, {})).statusCode).toBe(401);
    expect(paths(await call('GET', '/organizations/nope/members', orgAdmin.headers))).toEqual([
      'params.id',
    ]);
  });

  it('an org admin whose token lacks the admin scope gets 403 INSUFFICIENT_SCOPE, not FORBIDDEN', async () => {
    const pat = async (scopes: string[]) =>
      (
        await call('POST', '/tokens', orgAdmin.headers, { name: `s-${scopes.join('-')}`, scopes })
      ).json().token as string;
    const auth = (token: string) => ({ authorization: `Bearer ${token}` });
    const read = await call('GET', `/organizations/${teamId}/members`, auth(await pat(['read'])));
    expect([read.statusCode, read.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    const write = await call(
      'PUT',
      `/organizations/${teamId}/members/${memberId}`,
      auth(await pat(['write'])),
      { role: 'member' },
    );
    expect([write.statusCode, write.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    // A plain member lacks the role, whatever the token: that stays FORBIDDEN.
    expect(
      (await call('GET', `/organizations/${teamId}/members`, member.headers)).json().code,
    ).toBe('FORBIDDEN');
  });

  it('PUT sets a role; validates it; 404 for unknown users', async () => {
    const promote = await call(
      'PUT',
      `/organizations/${teamId}/members/${memberId}`,
      orgAdmin.headers,
      { role: 'admin' },
    );
    expect([promote.statusCode, promote.json().role]).toEqual([200, 'admin']);
    await call('PUT', `/organizations/${teamId}/members/${memberId}`, orgAdmin.headers, {
      role: 'member',
    });
    expect(
      paths(
        await call('PUT', `/organizations/${teamId}/members/${memberId}`, orgAdmin.headers, {
          role: 'owner',
        }),
      ),
    ).toEqual(['body.role']);
    const ghost = await call(
      'PUT',
      `/organizations/${teamId}/members/0190a0b0-0000-7000-8000-000000000000`,
      orgAdmin.headers,
      { role: 'member' },
    );
    expect(ghost.statusCode).toBe(404);
    expect(
      (
        await call('PUT', `/organizations/${teamId}/members/${memberId}`, member.headers, {
          role: 'admin',
        })
      ).statusCode,
    ).toBe(403);
    expect(
      (
        await call('PUT', `/organizations/${teamId}/members/${memberId}`, outsider.headers, {
          role: 'admin',
        })
      ).statusCode,
    ).toBe(404);
  });

  it('DELETE removes a membership once', async () => {
    const temp = await createUser(ctx, { username: 'temp-member' });
    await addMember(ctx, teamId, temp.id, 'member');
    expect(
      (await call('DELETE', `/organizations/${teamId}/members/${temp.id}`, member.headers))
        .statusCode,
    ).toBe(403);
    expect(
      (await call('DELETE', `/organizations/${teamId}/members/${temp.id}`, orgAdmin.headers))
        .statusCode,
    ).toBe(204);
    expect(
      (await call('DELETE', `/organizations/${teamId}/members/${temp.id}`, orgAdmin.headers))
        .statusCode,
    ).toBe(404);
  });

  it('never demotes or removes the last admin of an organisation (409 LAST_ADMIN)', async () => {
    const members = (await call('GET', `/organizations/${teamId}/members`, admin.headers)).json()
      .items as { userId: string; username: string }[];
    const idOf = (username: string) => members.find((m) => m.username === username)!.userId;
    const root = idOf('admin');
    const other = idOf('org-admin');
    const put = (userId: string, role: string, headers = admin.headers) =>
      call('PUT', `/organizations/${teamId}/members/${userId}`, headers, { role });
    const outcome = (res: Awaited<ReturnType<typeof call>>) =>
      res.statusCode === 409 ? `409 ${res.json().code as string}` : String(res.statusCode);

    // Two admins: either may go.
    expect(outcome(await put(root, 'member'))).toBe('200');
    // org-admin is now the last one; the instance admin does not count without the stored role.
    expect(outcome(await put(other, 'member', orgAdmin.headers))).toBe('409 LAST_ADMIN');
    expect(outcome(await put(other, 'member'))).toBe('409 LAST_ADMIN');
    expect(
      outcome(await call('DELETE', `/organizations/${teamId}/members/${other}`, admin.headers)),
    ).toBe('409 LAST_ADMIN');
    expect(outcome(await put(other, 'admin'))).toBe('200');
    // Two admins demoting each other at once: exactly one wins.
    expect(outcome(await put(root, 'admin'))).toBe('200');
    const raced = await Promise.all([
      put(root, 'member', orgAdmin.headers),
      put(other, 'member', admin.headers),
    ]);
    expect(raced.map(outcome).sort()).toEqual(['200', '409 LAST_ADMIN']);
    const roles = (await call('GET', `/organizations/${teamId}/members`, admin.headers)).json()
      .items as { username: string; role: string }[];
    expect(roles.filter((m) => m.role === 'admin')).toHaveLength(1);
    // Put both back for the tests that follow.
    expect(outcome(await put(root, 'admin'))).toBe('200');
    expect(outcome(await put(other, 'admin'))).toBe('200');
    // With two admins again, removing one works.
    const spare = await createUser(ctx, { username: 'spare-admin' });
    await addMember(ctx, teamId, spare.id, 'admin');
    expect(
      outcome(await call('DELETE', `/organizations/${teamId}/members/${spare.id}`, admin.headers)),
    ).toBe('204');
  });

  it('GET /system/info reports the edition and no organisation limit', async () => {
    const res = await call('GET', '/system/info', member.headers);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({
      version: VERSION,
      edition: 'community',
      features: [],
      extensions: [],
    });
    expect((await call('GET', '/system/info', {})).statusCode).toBe(401);
  });
});

describe('organisation creation over HTTP under concurrency (data-model.md §8 item 2)', () => {
  it('two creators racing for the same key get one 201 and one 409 ORG_KEY_TAKEN', async () => {
    const ctx = await createTestContext();
    try {
      const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
      const post = () =>
        ctx.app.inject({
          method: 'POST',
          url: '/api/v0/organizations',
          headers: admin.headers,
          payload: { key: 'race', name: 'Race' },
        });
      const results = await Promise.all([post(), post()]);
      expect(results.map((r) => r.statusCode).sort()).toEqual([201, 409]);
      expect(results.find((r) => r.statusCode === 409)!.json().code).toBe('ORG_KEY_TAKEN');
    } finally {
      await ctx.close();
    }
  });
});

describe('managed memberships (sso-scim.md §9.3, §16.2)', () => {
  it('shows a managed membership and takes it over on a hand change (sso-scim.md §9.3)', async () => {
    const ctx2 = await ssoContext({});
    try {
      const conn = await oidcConnection(ctx2, {});
      const org = await organizationId(ctx2, 'default');
      const u = await createUser(ctx2, { username: 'managed' });
      await ctx2.db
        .insert(memberships)
        .values({ organizationId: org, userId: u.id, role: 'member', managedByConnectionId: conn });
      const headers = await adminHeaders(ctx2);
      const list = await ctx2.app.inject({
        method: 'GET',
        url: `/api/v0/organizations/${org}/members`,
        headers,
      });
      const items = list.json().items as { userId: string; managedBy: unknown }[];
      expect(items.find((m) => m.userId === u.id)?.managedBy).toMatchObject({
        connectionId: conn,
        connectionName: expect.any(String),
      });
      const put = await ctx2.app.inject({
        method: 'PUT',
        url: `/api/v0/organizations/${org}/members/${u.id}`,
        headers,
        payload: { role: 'admin' },
      });
      expect(put.json()).toMatchObject({ role: 'admin', managedBy: null });
      const [row] = await ctx2.db
        .select()
        .from(memberships)
        .where(and(eq(memberships.organizationId, org), eq(memberships.userId, u.id)));
      expect(row).toMatchObject({ role: 'admin', managedByConnectionId: null });
    } finally {
      await ctx2.close();
    }
  });

  it('marks hand-made memberships null, takes over on a same-role PUT, and lets a managed one be removed', async () => {
    const ctx2 = await ssoContext({});
    try {
      const conn = await oidcConnection(ctx2, {});
      const org = await organizationId(ctx2, 'default');
      const same = await createUser(ctx2, { username: 'same-role' });
      const gone = await createUser(ctx2, { username: 'removed' });
      await ctx2.db.insert(memberships).values([
        { organizationId: org, userId: same.id, role: 'member', managedByConnectionId: conn },
        { organizationId: org, userId: gone.id, role: 'member', managedByConnectionId: conn },
      ]);
      const headers = await adminHeaders(ctx2);
      const list = await ctx2.app.inject({
        method: 'GET',
        url: `/api/v0/organizations/${org}/members`,
        headers,
      });
      const admin = (list.json().items as { username: string; managedBy: unknown }[]).find(
        (m) => m.username === 'admin',
      );
      expect(admin).toMatchObject({ managedBy: null });
      await ctx2.app.inject({
        method: 'PUT',
        url: `/api/v0/organizations/${org}/members/${same.id}`,
        headers,
        payload: { role: 'member' },
      });
      const del = await ctx2.app.inject({
        method: 'DELETE',
        url: `/api/v0/organizations/${org}/members/${gone.id}`,
        headers,
      });
      expect(del.statusCode).toBe(204);
      const rows = await ctx2.db
        .select()
        .from(memberships)
        .where(eq(memberships.organizationId, org));
      expect(rows.find((r) => r.userId === same.id)).toMatchObject({
        role: 'member',
        managedByConnectionId: null,
      });
      expect(rows.find((r) => r.userId === gone.id)).toBeUndefined();
    } finally {
      await ctx2.close();
    }
  });
});
