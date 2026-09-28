import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createTestContext,
  createUser,
  DEFAULT_TEST_PASSWORD,
  login,
  nextIp,
  type TestContext,
} from '../../test/app';
import { PASSWORD_MAX_LENGTH } from '../auth/password';
import { SESSION_COOKIE, sessionIdFor } from '../auth/sessions';
import { sessions } from '../db/schema';

describe('auth routes', () => {
  let ctx: TestContext;
  beforeAll(async () => {
    ctx = await createTestContext();
  });
  afterAll(async () => {
    await ctx.close();
  });

  const loginRequest = (
    username: string,
    password: string,
    extra: { remoteAddress?: string; cookies?: Record<string, string> } = {},
  ) =>
    ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/login',
      payload: { username, password },
      remoteAddress: extra.remoteAddress ?? nextIp(),
      ...(extra.cookies ? { cookies: extra.cookies } : {}),
    });
  const me = (headers: Record<string, string>) =>
    ctx.app.inject({ method: 'GET', url: '/api/v0/auth/me', headers });
  const errorPaths = (body: { errors?: { path: string }[] }) =>
    (body.errors ?? []).map((e) => e.path);

  it('logs in with an HttpOnly, SameSite=Lax cookie that is not Secure over plain http', async () => {
    await createUser(ctx, { username: 'cookie-user' });
    const res = await loginRequest('cookie-user', DEFAULT_TEST_PASSWORD);
    expect(res.statusCode).toBe(204);
    const cookie = res.cookies.find((c) => c.name === SESSION_COOKIE)!;
    expect(cookie).toMatchObject({ httpOnly: true, sameSite: 'Lax', path: '/' });
    expect(cookie.secure).toBeFalsy();
  });

  it('sets Secure behind a TLS-terminating proxy when QUALOR_TRUST_PROXY is on', async () => {
    const proxied = await createTestContext({ config: { trustProxy: 1 } });
    try {
      const res = await proxied.app.inject({
        method: 'POST',
        url: '/api/v0/auth/login',
        payload: { username: 'admin', password: ADMIN_PASSWORD },
        headers: { 'x-forwarded-proto': 'https' },
      });
      expect(res.cookies.find((c) => c.name === SESSION_COOKIE)?.secure).toBe(true);
    } finally {
      await proxied.close();
    }
  });

  it('rejects invalid login bodies with 422 and errors[].path', async () => {
    const missing = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/login',
      payload: { username: 'admin' },
      remoteAddress: nextIp(),
    });
    expect(missing.statusCode).toBe(422);
    expect(errorPaths(missing.json())).toContain('body.password');
    const extra = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/login',
      payload: { username: 'admin', password: 'x', admin: true },
      remoteAddress: nextIp(),
    });
    expect(errorPaths(extra.json())).toContain('body');
  });

  it('answers a wrong password, an unknown user and a deactivated user identically', async () => {
    await createUser(ctx, { username: 'dormant', active: false });
    for (const [username, password] of [
      ['admin', 'wrong password!!'],
      ['nobody-here', 'whatever password'],
      ['dormant', DEFAULT_TEST_PASSWORD],
    ] as const) {
      const res = await loginRequest(username, password);
      expect(res.statusCode, username).toBe(401);
      expect(res.json()).toMatchObject({
        code: 'INVALID_CREDENTIALS',
        title: 'Invalid username or password',
      });
    }
  });

  it('rejects an over-long password like a wrong one, not a validation error (S6)', async () => {
    const res = await loginRequest('admin', 'x'.repeat(PASSWORD_MAX_LENGTH + 1));
    expect(res.statusCode).toBe(401);
    expect(res.json()).toMatchObject({ code: 'INVALID_CREDENTIALS' });
  });

  it('allows 10 login attempts per minute per IP', async () => {
    const ip = nextIp();
    for (let i = 0; i < 10; i++) {
      expect(
        (await loginRequest(`ip-user-${i}`, 'wrong password!!', { remoteAddress: ip })).statusCode,
      ).toBe(401);
    }
    const blocked = await loginRequest('admin', ADMIN_PASSWORD, { remoteAddress: ip });
    expect([blocked.statusCode, blocked.json().code]).toEqual([429, 'RATE_LIMITED']);
    expect(blocked.headers['retry-after']).toBeDefined();
  });

  it('allows 10 login attempts per minute per username, across IPs and letter case', async () => {
    await createUser(ctx, { username: 'target' });
    for (let i = 0; i < 10; i++)
      expect((await loginRequest('TARGET', 'wrong password!!')).statusCode).toBe(401);
    const blocked = await loginRequest('target', DEFAULT_TEST_PASSWORD);
    expect([blocked.statusCode, blocked.json().code]).toEqual([429, 'RATE_LIMITED']);
  });

  it('issues a new session id at login and deletes the one the client brought (fixation)', async () => {
    await createUser(ctx, { username: 'fixation' });
    const planted = await login(ctx, 'fixation', DEFAULT_TEST_PASSWORD);
    const res = await loginRequest('fixation', DEFAULT_TEST_PASSWORD, {
      cookies: { [SESSION_COOKIE]: planted.cookie },
    });
    const fresh = res.cookies.find((c) => c.name === SESSION_COOKIE)!.value;
    expect(fresh).not.toBe(planted.cookie);
    expect((await me({ cookie: `${SESSION_COOKIE}=${planted.cookie}` })).statusCode).toBe(401);
    expect((await me({ cookie: `${SESSION_COOKIE}=${fresh}` })).statusCode).toBe(200);
  });

  it('requires X-Qualor-CSRF on cookie-authenticated mutations', async () => {
    await createUser(ctx, { username: 'csrf-user' });
    const s = await login(ctx, 'csrf-user', DEFAULT_TEST_PASSWORD);
    const cookieOnly = { cookie: s.headers.cookie! };
    const none = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/logout',
      headers: cookieOnly,
    });
    expect([none.statusCode, none.json().code]).toEqual([403, 'CSRF_FAILED']);
    const wrong = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/logout',
      headers: { ...cookieOnly, 'x-qualor-csrf': 'x'.repeat(43) },
    });
    expect(wrong.statusCode).toBe(403);
    const ok = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/logout',
      headers: s.headers,
    });
    expect(ok.statusCode).toBe(204);
    expect(ok.cookies.find((c) => c.name === SESSION_COOKIE)?.value).toBe('');
    expect((await me(cookieOnly)).statusCode).toBe(401);
  });

  it('GET /auth/me returns the user, memberships and CSRF token; 401 without credentials', async () => {
    const s = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await me(s.headers);
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      user: { username: 'admin', isInstanceAdmin: true, passwordChangeRequired: false },
      memberships: [{ organizationKey: 'default', role: 'admin' }],
      csrfToken: s.csrf,
    });
    expect(res.json().user).not.toHaveProperty('passwordHash');
    const anonymous = await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/me' });
    expect([anonymous.statusCode, anonymous.json().code]).toEqual([401, 'UNAUTHENTICATED']);
    expect(anonymous.headers['www-authenticate']).toBe('Bearer');
  });

  it('rejects an expired session', async () => {
    await createUser(ctx, { username: 'expiring' });
    const s = await login(ctx, 'expiring', DEFAULT_TEST_PASSWORD);
    await ctx.db
      .update(sessions)
      .set({ expiresAt: new Date(Date.now() - 1_000) })
      .where(eq(sessions.id, sessionIdFor(s.cookie)));
    expect((await me(s.headers)).statusCode).toBe(401);
  });

  it('answers unauthenticated requests with 401 before validating the body', async () => {
    const res = await ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/auth/me/password',
      payload: { nonsense: true },
    });
    expect(res.statusCode).toBe(401);
  });

  it('rejects POST /auth/logout with 401 when there is no session (S7)', async () => {
    const res = await ctx.app.inject({ method: 'POST', url: '/api/v0/auth/logout' });
    expect([res.statusCode, res.json().code]).toEqual([401, 'UNAUTHENTICATED']);
  });

  it('rejects PUT /auth/me/password with 401 when there is no session, even with a well-formed body (S7)', async () => {
    const res = await ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/auth/me/password',
      payload: { currentPassword: DEFAULT_TEST_PASSWORD, newPassword: 'a fine new passphrase' },
    });
    expect([res.statusCode, res.json().code]).toEqual([401, 'UNAUTHENTICATED']);
  });

  it('keeps health checks public and database-free', async () => {
    expect((await ctx.app.inject({ method: 'GET', url: '/healthz' })).statusCode).toBe(200);
  });

  describe('PUT /auth/me/password', () => {
    const change = (headers: Record<string, string>, payload: Record<string, unknown>) =>
      ctx.app.inject({ method: 'PUT', url: '/api/v0/auth/me/password', headers, payload });

    it('changes the password, keeps this session and ends the others', async () => {
      await createUser(ctx, { username: 'changer' });
      const current = await login(ctx, 'changer', DEFAULT_TEST_PASSWORD);
      const other = await login(ctx, 'changer', DEFAULT_TEST_PASSWORD);
      const res = await change(current.headers, {
        currentPassword: DEFAULT_TEST_PASSWORD,
        newPassword: 'a brand new passphrase',
      });
      expect(res.statusCode).toBe(204);
      expect((await me(current.headers)).statusCode).toBe(200);
      expect((await me(other.headers)).statusCode).toBe(401);
      expect((await loginRequest('changer', DEFAULT_TEST_PASSWORD)).statusCode).toBe(401);
      expect((await loginRequest('changer', 'a brand new passphrase')).statusCode).toBe(204);
    });

    it('rejects a short new password and a wrong current password with 422', async () => {
      await createUser(ctx, { username: 'validator' });
      const s = await login(ctx, 'validator', DEFAULT_TEST_PASSWORD);
      const short = await change(s.headers, {
        currentPassword: DEFAULT_TEST_PASSWORD,
        newPassword: 'short',
      });
      expect([short.statusCode, errorPaths(short.json())]).toEqual([422, ['body.newPassword']]);
      const wrong = await change(s.headers, {
        currentPassword: 'not my password',
        newPassword: 'long enough passphrase',
      });
      expect([wrong.statusCode, errorPaths(wrong.json())]).toEqual([422, ['body.currentPassword']]);
    });

    it('rejects an over-long current or new password with 422 (S6)', async () => {
      await createUser(ctx, { username: 'over-long' });
      const s = await login(ctx, 'over-long', DEFAULT_TEST_PASSWORD);
      const overLongCurrent = await change(s.headers, {
        currentPassword: 'x'.repeat(PASSWORD_MAX_LENGTH + 1),
        newPassword: 'a fine replacement passphrase',
      });
      expect([overLongCurrent.statusCode, errorPaths(overLongCurrent.json())]).toEqual([
        422,
        ['body.currentPassword'],
      ]);
      const overLongNew = await change(s.headers, {
        currentPassword: DEFAULT_TEST_PASSWORD,
        newPassword: 'x'.repeat(PASSWORD_MAX_LENGTH + 1),
      });
      expect([overLongNew.statusCode, errorPaths(overLongNew.json())]).toEqual([
        422,
        ['body.newPassword'],
      ]);
    });

    it('clears the must-change flag (ruling R7)', async () => {
      await createUser(ctx, { username: 'fresh', passwordChangeRequired: true });
      const s = await login(ctx, 'fresh', DEFAULT_TEST_PASSWORD);
      expect((await me(s.headers)).json().user.passwordChangeRequired).toBe(true);
      expect(
        (
          await change(s.headers, {
            currentPassword: DEFAULT_TEST_PASSWORD,
            newPassword: 'my own new passphrase',
          })
        ).statusCode,
      ).toBe(204);
      expect((await me(s.headers)).json().user.passwordChangeRequired).toBe(false);
    });
  });
});
