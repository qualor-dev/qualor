import { and, count, eq, inArray } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  bearer,
  createTestContext,
  createUser,
  login,
  type Session,
  type TestContext,
} from '../../test/app';
import { users } from '../db/schema';

describe('users (instance admin)', () => {
  let ctx: TestContext;
  let admin: Session;
  let member: Session;

  beforeAll(async () => {
    ctx = await createTestContext();
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const m = await createUser(ctx, { username: 'plain-member' });
    member = await login(ctx, m.username, m.password);
  });
  afterAll(async () => {
    await ctx.close();
  });

  const call = (
    method: 'GET' | 'POST' | 'PATCH',
    url: string,
    headers: Record<string, string>,
    payload?: object,
  ) => ctx.app.inject({ method, url: `/api/v0${url}`, headers, ...(payload ? { payload } : {}) });
  const paths = (res: { json(): { errors?: { path: string }[] } }) =>
    (res.json().errors ?? []).map((e) => e.path);

  it('lists users with keyset pagination', async () => {
    const first = await call('GET', '/users?limit=1', admin.headers);
    expect(first.statusCode).toBe(200);
    expect(first.json().items).toHaveLength(1);
    const second = await call(
      'GET',
      `/users?limit=1&cursor=${first.json().nextCursor}`,
      admin.headers,
    );
    expect(second.json().items[0].id).not.toBe(first.json().items[0].id);
    expect(paths(await call('GET', '/users?limit=0', admin.headers))).toEqual(['query.limit']);
    expect(paths(await call('GET', '/users?cursor=garbage', admin.headers))).toEqual([
      'query.cursor',
    ]);
  });

  it('creates a user who must change the password at first login', async () => {
    const res = await call('POST', '/users', admin.headers, {
      username: 'newbie',
      password: 'initial passphrase',
      email: 'newbie@example.com',
    });
    expect(res.statusCode).toBe(201);
    expect(res.json()).toMatchObject({
      username: 'newbie',
      passwordChangeRequired: true,
      isInstanceAdmin: false,
    });
    const newbie = await login(ctx, 'newbie', 'initial passphrase');
    const blocked = await call('GET', '/tokens', newbie.headers);
    expect([blocked.statusCode, blocked.json().code]).toEqual([403, 'PASSWORD_CHANGE_REQUIRED']);
  });

  it('rejects duplicate usernames case-insensitively and invalid bodies', async () => {
    const dup = await call('POST', '/users', admin.headers, {
      username: 'ADMIN',
      password: 'initial passphrase',
    });
    expect([dup.statusCode, dup.json().code]).toEqual([409, 'USERNAME_TAKEN']);
    expect(
      paths(
        await call('POST', '/users', admin.headers, { username: 'ok-name', password: 'short' }),
      ),
    ).toEqual(['body.password']);
    expect(
      paths(
        await call('POST', '/users', admin.headers, {
          username: 'bad name!',
          password: 'initial passphrase',
        }),
      ),
    ).toEqual(['body.username']);
    expect(
      paths(
        await call('POST', '/users', admin.headers, {
          username: 'x1',
          password: 'initial passphrase',
          role: 'god',
        }),
      ),
    ).toEqual(['body']);
  });

  it('updates a user; deactivating or resetting the password ends their sessions and revokes their tokens', async () => {
    const u = await createUser(ctx, { username: 'to-change' });
    const theirs = await login(ctx, u.username, u.password);
    const minted = await call('POST', '/tokens', theirs.headers, {
      name: 'pre-reset',
      scopes: ['read'],
    });
    const theirToken = minted.json().token as string;
    const renamed = await call('PATCH', `/users/${u.id}`, admin.headers, {
      displayName: 'Changed',
    });
    expect([renamed.statusCode, renamed.json().displayName]).toEqual([200, 'Changed']);
    const off = await call('PATCH', `/users/${u.id}`, admin.headers, { active: false });
    expect(off.json().active).toBe(false);
    expect((await call('GET', '/auth/me', theirs.headers)).statusCode).toBe(401);
    await call('PATCH', `/users/${u.id}`, admin.headers, {
      active: true,
      password: 'reset by the admin',
    });
    const again = await login(ctx, u.username, 'reset by the admin');
    expect((await call('GET', '/auth/me', again.headers)).json().user.passwordChangeRequired).toBe(
      true,
    );
    // The token pre-dates the reset and the user is active again, so only explicit revocation
    // (not the earlier deactivation, not the inactive-user check) explains this now being 401.
    const staleToken = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/auth/me',
      headers: bearer(theirToken),
    });
    expect(staleToken.statusCode).toBe(401);
  });

  it('validates PATCH input and 404s unknown users', async () => {
    expect(paths(await call('PATCH', `/users/${ctx.adminId}`, admin.headers, {}))).toEqual([
      'body',
    ]);
    expect(
      paths(await call('PATCH', '/users/not-a-uuid', admin.headers, { active: true })),
    ).toEqual(['params.id']);
    const missing = await call(
      'PATCH',
      '/users/0190a0b0-0000-7000-8000-000000000000',
      admin.headers,
      { active: true },
    );
    expect(missing.statusCode).toBe(404);
  });

  it('keeps at least one active instance admin', async () => {
    const res = await call('PATCH', `/users/${ctx.adminId}`, admin.headers, {
      isInstanceAdmin: false,
    });
    expect([res.statusCode, res.json().code]).toEqual([409, 'LAST_ADMIN']);
  });

  it('is instance-admin only: 401 anonymous, 403 for a member', async () => {
    for (const [method, url] of [
      ['GET', '/users'],
      ['POST', '/users'],
      ['PATCH', `/users/${ctx.adminId}`],
    ] as const) {
      const payload =
        method === 'GET'
          ? undefined
          : { displayName: 'x', username: 'someone', password: 'initial passphrase' };
      expect(
        (await call(method, url, {}, method === 'PATCH' ? { displayName: 'x' } : payload))
          .statusCode,
      ).toBe(401);
      const denied = await call(
        method,
        url,
        member.headers,
        method === 'PATCH' ? { displayName: 'x' } : payload,
      );
      expect(denied.statusCode, `${method} ${url}`).toBe(403);
    }
  });
});

describe('last-admin invariant under concurrency', () => {
  it('lets only one of two admins demote the other at the same moment', async () => {
    const ctx = await createTestContext();
    try {
      const other = await createUser(ctx, { username: 'second-admin', isInstanceAdmin: true });
      const a = await login(ctx, 'admin', ADMIN_PASSWORD);
      const b = await login(ctx, other.username, other.password);
      const [r1, r2] = await Promise.all([
        ctx.app.inject({
          method: 'PATCH',
          url: `/api/v0/users/${other.id}`,
          headers: a.headers,
          payload: { isInstanceAdmin: false },
        }),
        ctx.app.inject({
          method: 'PATCH',
          url: `/api/v0/users/${ctx.adminId}`,
          headers: b.headers,
          payload: { isInstanceAdmin: false },
        }),
      ]);
      const statuses = [r1.statusCode, r2.statusCode].sort((x, y) => x - y);
      // The advisory lock lets exactly one transaction run first; call it the winner. Since these
      // two accounts demote each other, the loser's own admin status is what the winner just
      // changed, so the loser's fresh re-check (taken under the same lock) ordinarily finds itself
      // no longer an admin — 403. If the loser were instead demoting some third account, it would
      // fail LAST_ADMIN's count check instead — 409. Either is a correct resolution of the race;
      // what actually matters is the invariant itself, so check that directly against the database
      // rather than pin down exactly which status the loser gets.
      expect([
        [200, 403],
        [200, 409],
      ]).toContainEqual(statuses);
      const rows = await ctx.db
        .select({ id: users.id, isInstanceAdmin: users.isInstanceAdmin, active: users.active })
        .from(users)
        .where(inArray(users.id, [ctx.adminId, other.id]));
      expect(rows.filter((u) => u.isInstanceAdmin && u.active)).toHaveLength(1);
      const [activeAdmins] = await ctx.db
        .select({ n: count() })
        .from(users)
        .where(and(eq(users.isInstanceAdmin, true), eq(users.active, true)));
      expect(activeAdmins?.n ?? 0).toBeGreaterThanOrEqual(1);
    } finally {
      await ctx.close();
    }
  });
});
