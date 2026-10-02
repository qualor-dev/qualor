import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addMember,
  createProject,
  createTestContext,
  createUser,
  login,
  nextIp,
  organizationId,
  ADMIN_PASSWORD,
  type CreatedUser,
  type TestContext,
} from '../../test/app';
import { DEMO_SESSION_MAX_HOURS } from '../auth/demo';
import { SESSION_COOKIE, sessionIdFor } from '../auth/sessions';
import { memberships, projectMemberships, sessions, users } from '../db/schema';

const demoRequest = (ctx: TestContext, cookies?: Record<string, string>) =>
  ctx.app.inject({
    method: 'POST',
    url: '/api/v0/auth/demo',
    remoteAddress: nextIp(),
    ...(cookies ? { cookies } : {}),
  });

const methods = async (ctx: TestContext): Promise<{ demo: boolean }> =>
  (
    await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/methods', remoteAddress: nextIp() })
  ).json();

/** Signs in to the demo; the cookie and CSRF header, as `login` gives them. */
async function demoSession(ctx: TestContext): Promise<Record<string, string>> {
  const res = await demoRequest(ctx);
  expect(res.statusCode, res.body).toBe(204);
  const cookie = res.cookies.find((c) => c.name === SESSION_COOKIE)!.value;
  const me = await ctx.app.inject({
    method: 'GET',
    url: '/api/v0/auth/me',
    cookies: { [SESSION_COOKIE]: cookie },
  });
  const csrf = (me.json() as { csrfToken: string }).csrfToken;
  return { cookie: `${SESSION_COOKIE}=${cookie}`, 'x-qualor-csrf': csrf };
}

describe('the demo sign-in (QUALOR_DEMO_USER)', () => {
  describe('without QUALOR_DEMO_USER', () => {
    let ctx: TestContext;
    beforeAll(async () => {
      ctx = await createTestContext();
      await createUser(ctx, { username: 'guest' });
    });
    afterAll(async () => {
      await ctx.close();
    });

    it('offers no demo and refuses the sign-in with 404', async () => {
      expect((await methods(ctx)).demo).toBe(false);
      const res = await demoRequest(ctx);
      expect(res.statusCode).toBe(404);
      expect(res.json()).toMatchObject({ code: 'DEMO_UNAVAILABLE' });
      expect(res.cookies.find((c) => c.name === SESSION_COOKIE)).toBeUndefined();
    });
  });

  describe('with QUALOR_DEMO_USER=guest', () => {
    let ctx: TestContext;
    let guest: CreatedUser;
    let org: string;
    beforeAll(async () => {
      ctx = await createTestContext({ config: { demoUser: 'guest' } });
      org = await organizationId(ctx, 'default');
    });
    afterAll(async () => {
      await ctx.close();
    });

    it('offers no demo while the account does not exist', async () => {
      expect((await methods(ctx)).demo).toBe(false);
      expect((await demoRequest(ctx)).statusCode).toBe(404);
    });

    it('signs a guest in without a password, for at most a day, and says so in /auth/me', async () => {
      guest = await createUser(ctx, { username: 'guest' });
      await addMember(ctx, org, guest.id, 'viewer');
      expect((await methods(ctx)).demo).toBe(true);
      const before = Date.now();
      const headers = await demoSession(ctx);
      const me = await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/me', headers });
      expect(me.json()).toMatchObject({ user: { username: 'guest' }, demo: true });
      const rows = await ctx.db.select().from(sessions).where(eq(sessions.userId, guest.id));
      expect(rows).toHaveLength(1);
      expect(rows[0]!.expiresAt.getTime()).toBeLessThanOrEqual(
        before + DEMO_SESSION_MAX_HOURS * 3_600_000 + 60_000,
      );
    });

    it('lets the guest read and sign out, and refuses every change with 403 DEMO_READ_ONLY', async () => {
      const headers = await demoSession(ctx);
      expect(
        (await ctx.app.inject({ method: 'GET', url: '/api/v0/projects', headers })).statusCode,
      ).toBe(200);
      const changes = [
        {
          method: 'PUT' as const,
          url: '/api/v0/auth/me/password',
          payload: { currentPassword: guest.password, newPassword: 'another fine passphrase' },
        },
        {
          method: 'POST' as const,
          url: '/api/v0/tokens',
          payload: { name: 't', scopes: ['read'] },
        },
      ];
      for (const change of changes) {
        const res = await ctx.app.inject({ ...change, headers });
        expect(res.statusCode, change.url).toBe(403);
        expect(res.json()).toMatchObject({ code: 'DEMO_READ_ONLY' });
      }
      const [stored] = await ctx.db.select().from(users).where(eq(users.id, guest.id));
      expect(stored!.passwordHash).toBeTruthy();
      const out = await ctx.app.inject({ method: 'POST', url: '/api/v0/auth/logout', headers });
      expect(out.statusCode).toBe(204);
    });

    it('refuses changes as the demo account whatever its role and however it signed in', async () => {
      await ctx.db
        .update(memberships)
        .set({ role: 'admin' })
        .where(eq(memberships.userId, guest.id));
      try {
        // An admin role takes the demo off the sign-in page...
        expect((await methods(ctx)).demo).toBe(false);
        expect((await demoRequest(ctx)).statusCode).toBe(404);
        // ...and a password sign-in as the account still changes nothing.
        const session = await login(ctx, 'guest', guest.password);
        const res = await ctx.app.inject({
          method: 'POST',
          url: '/api/v0/projects',
          headers: session.headers,
          payload: { organizationId: org, key: 'demo-made', name: 'demo-made' },
        });
        expect(res.statusCode).toBe(403);
        expect(res.json()).toMatchObject({ code: 'DEMO_READ_ONLY' });
      } finally {
        await ctx.db
          .update(memberships)
          .set({ role: 'viewer' })
          .where(eq(memberships.userId, guest.id));
      }
    });

    it('offers no demo while the account is more than a viewer anywhere, or not usable', async () => {
      const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
      const project = await createProject(ctx, admin, { organizationId: org, key: 'demo-grant' });
      const cases: { name: string; apply: () => Promise<unknown>; undo: () => Promise<unknown> }[] =
        [
          {
            name: 'a member project grant',
            apply: () =>
              ctx.db
                .insert(projectMemberships)
                .values({ projectId: project.id, userId: guest.id, role: 'member' }),
            undo: () =>
              ctx.db.delete(projectMemberships).where(eq(projectMemberships.userId, guest.id)),
          },
          ...(
            [
              ['an instance admin', { isInstanceAdmin: true }, { isInstanceAdmin: false }],
              ['an inactive account', { active: false }, { active: true }],
              [
                'a forced password change',
                { passwordChangeRequired: true },
                { passwordChangeRequired: false },
              ],
            ] as const
          ).map(([name, set, reset]) => ({
            name,
            apply: () => ctx.db.update(users).set(set).where(eq(users.id, guest.id)),
            undo: () => ctx.db.update(users).set(reset).where(eq(users.id, guest.id)),
          })),
        ];
      for (const c of cases) {
        await c.apply();
        try {
          expect((await methods(ctx)).demo, c.name).toBe(false);
          expect((await demoRequest(ctx)).statusCode, c.name).toBe(404);
        } finally {
          await c.undo();
        }
      }
      // A viewer grant is fine.
      await ctx.db
        .insert(projectMemberships)
        .values({ projectId: project.id, userId: guest.id, role: 'viewer' });
      expect((await methods(ctx)).demo).toBe(true);
    });

    it('drops the expired demo sessions and the one the client brought', async () => {
      const expired = Buffer.alloc(32, 7);
      await ctx.db
        .insert(sessions)
        .values({ id: expired, userId: guest.id, expiresAt: new Date(Date.now() - 1_000) });
      const brought = await demoSession(ctx);
      const broughtSecret = brought.cookie!.slice(SESSION_COOKIE.length + 1);
      await demoRequest(ctx, { [SESSION_COOKIE]: broughtSecret });
      const ids = (await ctx.db.select().from(sessions).where(eq(sessions.userId, guest.id))).map(
        (r) => r.id.toString('hex'),
      );
      expect(ids).not.toContain(expired.toString('hex'));
      expect(ids).not.toContain(sessionIdFor(broughtSecret).toString('hex'));
    });

    it('leaves everyone else alone', async () => {
      const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
      const me = await ctx.app.inject({
        method: 'GET',
        url: '/api/v0/auth/me',
        headers: admin.headers,
      });
      expect(me.json()).toMatchObject({ demo: false });
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: admin.headers,
        payload: { name: 'mine', scopes: ['read'] },
      });
      expect(res.statusCode).toBe(201);
    });
  });
});
