import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createUser, login, type TestContext } from '../../test/app';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';
import { auditRows, oidcConnection, ssoContext } from '../../test/sso';
import { createAuditRecorder } from '../audit/recorder';
import { SESSION_COOKIE } from '../auth/sessions';
import { createDatabase } from '../db/client';
import { identities, sessions, users } from '../db/schema';
import { SSO_COOKIE } from './binding';
import { failSsoFlow, SsoFailure } from './errors';
import { issueSsoSession } from './session';

/**
 * sso-scim.md §7.5 and §7.7 through two test routes: the flows of Tasks 13 and 14 call these two
 * helpers the same way.
 */
describe('SSO sessions and failures (sso-scim.md §7.5, §7.7)', () => {
  let ctx: TestContext;
  let connectionId: string;
  let userId: string;
  let failure: { connectionId: string; failure: SsoFailure } | undefined;
  let returnTo = '/projects/demo';
  beforeAll(async () => {
    ctx = await ssoContext({
      // Inside the test licence's validity (issued 2026-10-01), so audit-log is active.
      now: () => new Date('2027-01-01T00:00:00Z'),
      beforeReady: (app) => {
        const deps = () => ({
          db: ctx.db,
          config: ctx.config,
          audit: createAuditRecorder({
            isActive: () => ctx.edition?.isFeatureActive('audit-log') ?? false,
            log: QUIET_AUDIT_LOG,
          }),
          log: app.log,
        });
        app.get('/test/sso/issue', { config: { public: true } }, async (request, reply) => {
          const [user] = await ctx.db.select().from(users).where(eq(users.id, userId));
          // As the flows do (Tasks 13, 14): a failure of the session step ends the flow.
          try {
            return await issueSsoSession(deps(), request, reply, {
              user: user!,
              connectionId,
              protocol: 'oidc',
              returnTo,
            });
          } catch (err) {
            if (!(err instanceof SsoFailure)) throw err;
            return failSsoFlow(deps(), request, reply, {
              connectionId,
              protocol: 'oidc',
              failure: err,
            });
          }
        });
        app.get('/test/sso/fail', { config: { public: true } }, async (request, reply) =>
          failSsoFlow(deps(), request, reply, { ...failure!, protocol: 'saml' }),
        );
      },
    });
    connectionId = await oidcConnection(ctx, { enabled: true });
    userId = (await createUser(ctx, { username: 'sam' })).id;
    await ctx.db.insert(identities).values({ connectionId, userId, subject: 's', linkedBy: 'jit' });
  });
  afterAll(async () => ctx.close());

  it('issues a new session (dropping the presented one), records auth.sign_in and redirects', async () => {
    const first = await ctx.app.inject({ method: 'GET', url: '/test/sso/issue' });
    const old = first.cookies.find((c) => c.name === SESSION_COOKIE)!.value;
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/test/sso/issue',
      cookies: { [SESSION_COOKIE]: old, [SSO_COOKIE]: 'x' },
    });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/projects/demo');
    const cookie = res.cookies.find((c) => c.name === SESSION_COOKIE)!;
    expect(cookie).toMatchObject({ path: '/', httpOnly: true, sameSite: 'Lax' });
    expect(cookie.value).not.toBe(old);
    // The binding cookie is cleared.
    expect(res.cookies.find((c) => c.name === SSO_COOKIE)).toMatchObject({ value: '' });
    // Session fixation: only the new session is left.
    expect(await ctx.db.select().from(sessions).where(eq(sessions.userId, userId))).toHaveLength(1);
    const me = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/auth/me',
      cookies: { [SESSION_COOKIE]: cookie.value },
    });
    expect(me.json().user.username).toBe('sam');
    const [identity] = await ctx.db.select().from(identities).where(eq(identities.userId, userId));
    expect(identity!.lastSignInAt).toBeInstanceOf(Date);
    const [user] = await ctx.db.select().from(users).where(eq(users.id, userId));
    expect(user!.lastLoginAt).toBeInstanceOf(Date);
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'auth.sign_in',
      actorUserId: userId,
      targetId: userId,
      details: { method: 'oidc', connectionId },
    });
  });

  it('does not hold an SSO session up with a forced password change; a password session is', async () => {
    const forced = await createUser(ctx, { username: 'forced', passwordChangeRequired: true });
    await ctx.db
      .insert(identities)
      .values({ connectionId, userId: forced.id, subject: 'f', linkedBy: 'verified_email' });
    const sam = userId;
    userId = forced.id;
    try {
      const res = await ctx.app.inject({ method: 'GET', url: '/test/sso/issue' });
      const cookie = res.cookies.find((c) => c.name === SESSION_COOKIE)!.value;
      const viaSso = { [SESSION_COOKIE]: cookie };
      const me = await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/me', cookies: viaSso });
      expect(me.json().user).toMatchObject({ username: 'forced', passwordChangeRequired: false });
      const orgs = await ctx.app.inject({
        method: 'GET',
        url: '/api/v0/organizations',
        cookies: viaSso,
      });
      expect(orgs.statusCode).toBe(200);
      // The flag stays: the next password sign-in must still change the password first.
      const [row] = await ctx.db.select().from(users).where(eq(users.id, forced.id));
      expect(row!.passwordChangeRequired).toBe(true);
      const password = await login(ctx, forced.username, forced.password);
      const pwMe = await ctx.app.inject({
        method: 'GET',
        url: '/api/v0/auth/me',
        headers: password.headers,
      });
      expect(pwMe.json().user.passwordChangeRequired).toBe(true);
      const refused = await ctx.app.inject({
        method: 'GET',
        url: '/api/v0/organizations',
        headers: password.headers,
      });
      expect([refused.statusCode, refused.json().code]).toEqual([403, 'PASSWORD_CHANGE_REQUIRED']);
    } finally {
      userId = sam;
    }
  });

  it('fails a flow with a fixed code: 303 to /login, the event, a fixed log line', async () => {
    failure = {
      connectionId,
      failure: new SsoFailure('invalid_response', 'saml.recipient', userId),
    };
    const res = await ctx.app.inject({ method: 'GET', url: '/test/sso/fail' });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/login?sso_error=invalid_response');
    expect(res.body).toBe('');
    expect(res.cookies.find((c) => c.name === SSO_COOKIE)).toMatchObject({ value: '' });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.sign_in_failed',
      outcome: 'failure',
      actorType: 'anonymous',
      actorUserId: userId,
      targetId: userId,
      details: { connectionId, protocol: 'saml', reason: 'invalid_response' },
    });
    const line = ctx.logs.find((l) => l.includes('single sign-on failed'))!;
    expect(JSON.parse(line)).toMatchObject({
      component: 'sso',
      connectionId,
      reason: 'invalid_response',
      detail: 'saml.recipient',
    });
  });

  it('never logs a detail outside the fixed list, nor records a connection id that is not one', async () => {
    const before = (await auditRows(ctx)).length;
    const text = '<script>IdP says: user@example.com is not allowed</script>';
    failure = { connectionId: 'not-a-uuid', failure: new SsoFailure('unavailable', text) };
    const res = await ctx.app.inject({ method: 'GET', url: '/test/sso/fail' });
    expect(res.headers.location).toBe('/login?sso_error=unavailable');
    expect(await auditRows(ctx)).toHaveLength(before);
    expect(ctx.logs.join('\n')).not.toContain('IdP says');
    expect(ctx.logs.join('\n')).not.toContain('not-a-uuid');
    const lines = ctx.logs.filter((l) => l.includes('single sign-on failed'));
    expect(JSON.parse(lines.at(-1)!)).toMatchObject({
      msg: 'single sign-on failed for an unknown connection',
      connectionId: null,
      reason: 'unavailable',
      detail: 'other',
    });
  });

  it('records nothing for a UUID that names no connection: one fixed log line only', async () => {
    const before = (await auditRows(ctx)).length;
    const logged = ctx.logs.length;
    const unknown = '00000000-0000-4000-8000-00000000abcd';
    failure = { connectionId: unknown, failure: new SsoFailure('flow_expired', 'flow.expired') };
    const res = await ctx.app.inject({ method: 'GET', url: '/test/sso/fail' });
    expect([res.statusCode, res.headers.location]).toEqual([303, '/login?sso_error=flow_expired']);
    expect(await auditRows(ctx)).toHaveLength(before);
    const added = ctx.logs.slice(logged).filter((l) => l.includes('single sign-on failed'));
    expect(added.map((l) => JSON.parse(l) as Record<string, unknown>)).toEqual([
      expect.objectContaining({
        msg: 'single sign-on failed for an unknown connection',
        component: 'sso',
        connectionId: null,
        reason: 'flow_expired',
        detail: 'flow.expired',
      }),
    ]);
    expect(ctx.logs.slice(logged).join('\n')).not.toContain(unknown);
  });

  it('records a failure on a connection that exists, even a disabled one', async () => {
    const disabled = await oidcConnection(ctx, { enabled: false });
    failure = { connectionId: disabled, failure: new SsoFailure('unavailable', 'oidc.disabled') };
    const res = await ctx.app.inject({ method: 'GET', url: '/test/sso/fail' });
    expect(res.headers.location).toBe('/login?sso_error=unavailable');
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.sign_in_failed',
      targetId: null,
      details: { connectionId: disabled, protocol: 'saml', reason: 'unavailable' },
    });
  });

  it('makes returnTo safe again: an off-site target becomes /', async () => {
    for (const target of [
      '//evil.example/x',
      'https://evil.example/',
      '/\\evil.example',
      '/%2F%2Fevil',
    ]) {
      returnTo = target;
      const res = await ctx.app.inject({ method: 'GET', url: '/test/sso/issue' });
      expect([target, res.statusCode, res.headers.location]).toEqual([target, 303, '/']);
    }
    returnTo = '/projects/demo?tab=issues';
    const res = await ctx.app.inject({ method: 'GET', url: '/test/sso/issue' });
    expect(res.headers.location).toBe('/projects/demo?tab=issues');
    returnTo = '/projects/demo';
  });

  it('locks the identity before the user, as SCIM does: a concurrent SCIM write does not deadlock', async () => {
    returnTo = '/projects/demo';
    const other = createDatabase(ctx.database.url, { max: 1 });
    try {
      let lockUser!: () => void;
      const userTurn = new Promise<void>((resolve) => {
        lockUser = resolve;
      });
      let identityHeld!: () => void;
      const held = new Promise<void>((resolve) => {
        identityHeld = resolve;
      });
      // SCIM's order (scim/users.ts): the identity row, then the user row.
      const scim = other.db.transaction(async (tx) => {
        await tx.execute(
          sql`SELECT id FROM identities WHERE user_id = ${userId} AND connection_id = ${connectionId} FOR NO KEY UPDATE`,
        );
        identityHeld();
        await userTurn;
        await tx.execute(sql`SELECT id FROM users WHERE id = ${userId} FOR NO KEY UPDATE`);
      });
      await held;
      const signIn = ctx.app.inject({ method: 'GET', url: '/test/sso/issue' });
      await new Promise((resolve) => setTimeout(resolve, 300));
      lockUser();
      await scim;
      const res = await signIn;
      expect([res.statusCode, res.headers.location]).toEqual([303, '/projects/demo']);
    } finally {
      await other.close();
    }
  });

  it('gives a user deactivated after resolution no session: inactive_user', async () => {
    const before = await ctx.db.select().from(sessions).where(eq(sessions.userId, userId));
    const events = (await auditRows(ctx)).length;
    await ctx.db.update(users).set({ active: false }).where(eq(users.id, userId));
    try {
      const res = await ctx.app.inject({ method: 'GET', url: '/test/sso/issue' });
      expect(res.statusCode).toBe(303);
      expect(res.headers.location).toBe('/login?sso_error=inactive_user');
      expect(res.cookies.find((c) => c.name === SESSION_COOKIE)).toBeUndefined();
      expect(await ctx.db.select().from(sessions).where(eq(sessions.userId, userId))).toHaveLength(
        before.length,
      );
      const added = (await auditRows(ctx)).slice(events);
      expect(added.map((e) => e.action)).toEqual(['sso.sign_in_failed']);
      expect(added[0]).toMatchObject({ targetId: userId, details: { reason: 'inactive_user' } });
    } finally {
      await ctx.db.update(users).set({ active: true }).where(eq(users.id, userId));
    }
  });
});
