import { and, eq } from 'drizzle-orm';
import { describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  createUser,
  login,
  nextIp,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { oidcConnection, ssoContext } from '../../test/sso';
import { verifyAuditChain } from '../audit/verify';
import type { Config } from '../config';
import { auditEvents, identities, users } from '../db/schema';

/**
 * A licensed server (`audit-log`, so `user.updated` is recorded; `sso` and `scim`, for a SCIM
 * record) with the bootstrap admin signed in, for one test; `config` as createTestContext takes it.
 */
async function withServer(
  config: Partial<Config>,
  run: (ctx: TestContext, admin: Session) => Promise<void>,
): Promise<void> {
  const ctx = await ssoContext({ config });
  try {
    await run(ctx, await login(ctx, 'admin', ADMIN_PASSWORD));
  } finally {
    await ctx.close();
  }
}

const rename = (ctx: TestContext, headers: Record<string, string>, id: string, username: string) =>
  ctx.app.inject({ method: 'PATCH', url: `/api/v0/users/${id}`, headers, payload: { username } });

const signIn = (ctx: TestContext, username: string, password: string) =>
  ctx.app.inject({
    method: 'POST',
    url: '/api/v0/auth/login',
    payload: { username, password },
    remoteAddress: nextIp(),
  });

const problem = (res: { statusCode: number; json(): { code?: string } }) => [
  res.statusCode,
  res.json().code,
];

/** The stored spelling of the user's name. */
async function usernameOf(ctx: TestContext, id: string): Promise<string | undefined> {
  const [row] = await ctx.db
    .select({ username: users.username })
    .from(users)
    .where(eq(users.id, id));
  return row?.username;
}

describe('PATCH /users/{id} with username (0.16 issue #37)', () => {
  it('rename: the new name signs in and the old one does not, a session stays, one user.updated lists the change', async () => {
    await withServer({}, async (ctx, admin) => {
      const bob = await createUser(ctx, { username: 'bob' });
      const theirs = await login(ctx, 'bob', bob.password);
      const res = await rename(ctx, admin.headers, bob.id, 'carol');
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toMatchObject({ id: bob.id, username: 'carol' });
      expect((await signIn(ctx, 'carol', bob.password)).statusCode).toBe(204);
      expect(problem(await signIn(ctx, 'bob', bob.password))).toEqual([401, 'INVALID_CREDENTIALS']);
      const me = await ctx.app.inject({
        method: 'GET',
        url: '/api/v0/auth/me',
        headers: theirs.headers,
      });
      expect([me.statusCode, me.json().user.username]).toEqual([200, 'carol']);
      const events = await ctx.db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, 'user.updated'), eq(auditEvents.targetId, bob.id)));
      expect(events).toHaveLength(1);
      expect(events[0]).toMatchObject({
        targetLabel: 'carol',
        details: {
          changes: [{ field: 'username', from: 'bob', to: 'carol' }],
          passwordReset: false,
        },
      });
    });
  });

  it('case only: bob becomes Bob, stored in the new spelling', async () => {
    await withServer({}, async (ctx, admin) => {
      const bob = await createUser(ctx, { username: 'bob' });
      const res = await rename(ctx, admin.headers, bob.id, 'Bob');
      expect([res.statusCode, res.json().username]).toEqual([200, 'Bob']);
      expect(await usernameOf(ctx, bob.id)).toBe('Bob');
    });
  });

  it('taken in another case: alice cannot become BOB while bob exists (409 USERNAME_TAKEN)', async () => {
    await withServer({}, async (ctx, admin) => {
      const alice = await createUser(ctx, { username: 'alice' });
      await createUser(ctx, { username: 'bob' });
      expect(problem(await rename(ctx, admin.headers, alice.id, 'BOB'))).toEqual([
        409,
        'USERNAME_TAKEN',
      ]);
      expect(await usernameOf(ctx, alice.id)).toBe('alice');
    });
  });

  it('bad pattern: 422 VALIDATION_FAILED on body.username, nothing changes', async () => {
    await withServer({}, async (ctx, admin) => {
      const bob = await createUser(ctx, { username: 'bob' });
      const res = await rename(ctx, admin.headers, bob.id, 'a b');
      expect(problem(res)).toEqual([422, 'VALIDATION_FAILED']);
      expect((res.json().errors as { path: string }[]).map((e) => e.path)).toEqual([
        'body.username',
      ]);
      expect(await usernameOf(ctx, bob.id)).toBe('bob');
    });
  });

  it('demo user: neither the demo account nor the demo name changes hands (409 DEMO_USER); other renames work', async () => {
    await withServer({ demoUser: 'guest' }, async (ctx, admin) => {
      const guest = await createUser(ctx, { username: 'guest' });
      const bob = await createUser(ctx, { username: 'bob' });
      expect(problem(await rename(ctx, admin.headers, guest.id, 'visitor'))).toEqual([
        409,
        'DEMO_USER',
      ]);
      expect(problem(await rename(ctx, admin.headers, bob.id, 'GUEST'))).toEqual([
        409,
        'DEMO_USER',
      ]);
      expect(await usernameOf(ctx, guest.id)).toBe('guest');
      expect(await usernameOf(ctx, bob.id)).toBe('bob');
      // the demo account's name sent unchanged is no rename, alone or with a display name.
      const unchanged = await rename(ctx, admin.headers, guest.id, 'guest');
      expect([unchanged.statusCode, unchanged.json().username]).toEqual([200, 'guest']);
      const same = await ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/users/${guest.id}`,
        headers: admin.headers,
        payload: { username: 'guest', displayName: 'Guest' },
      });
      expect([same.statusCode, same.json().displayName]).toEqual([200, 'Guest']);
      const res = await rename(ctx, admin.headers, bob.id, 'carol');
      expect([res.statusCode, res.json().username]).toEqual([200, 'carol']);
    });
  });

  it('SCIM user: renamed, its SCIM userName unchanged', async () => {
    await withServer({}, async (ctx, admin) => {
      const connectionId = await oidcConnection(ctx);
      const [bob] = await ctx.db
        .insert(users)
        .values({ username: 'bob', passwordHash: null })
        .returning();
      await ctx.db
        .insert(identities)
        .values({ connectionId, userId: bob!.id, linkedBy: 'scim', scimUserName: 'bob' });
      const res = await rename(ctx, admin.headers, bob!.id, 'carol');
      expect([res.statusCode, res.json().username]).toEqual([200, 'carol']);
      const rows = await ctx.db
        .select({ scimUserName: identities.scimUserName })
        .from(identities)
        .where(eq(identities.userId, bob!.id));
      expect(rows).toEqual([{ scimUserName: 'bob' }]);
    });
  });

  it('history stays: an audit row made before the rename keeps the old name', async () => {
    await withServer({}, async (ctx, admin) => {
      const bob = await createUser(ctx, { username: 'bob' });
      await login(ctx, 'bob', bob.password);
      const signedIn = () =>
        ctx.db
          .select({
            actorUsername: auditEvents.actorUsername,
            targetLabel: auditEvents.targetLabel,
          })
          .from(auditEvents)
          .where(and(eq(auditEvents.action, 'auth.sign_in'), eq(auditEvents.actorUserId, bob.id)));
      expect(await signedIn()).toEqual([{ actorUsername: 'bob', targetLabel: 'bob' }]);
      expect((await rename(ctx, admin.headers, bob.id, 'carol')).statusCode).toBe(200);
      expect(await signedIn()).toEqual([{ actorUsername: 'bob', targetLabel: 'bob' }]);
      expect((await verifyAuditChain(ctx.db)).ok).toBe(true);
    });
  });

  it('not an instance admin: an organisation admin gets 403, nothing changes', async () => {
    await withServer({}, async (ctx) => {
      const bob = await createUser(ctx, { username: 'bob' });
      const orgAdmin = await createUser(ctx, { username: 'org-admin' });
      await addMember(ctx, await organizationId(ctx, 'default'), orgAdmin.id, 'admin');
      const theirs = await login(ctx, 'org-admin', orgAdmin.password);
      expect(problem(await rename(ctx, theirs.headers, bob.id, 'carol'))).toEqual([
        403,
        'FORBIDDEN',
      ]);
      expect(await usernameOf(ctx, bob.id)).toBe('bob');
    });
  });
});
