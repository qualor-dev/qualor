import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestContext, createUser, login, type TestContext } from '../../test/app';
import { users } from '../db/schema';

/**
 * Task 6 could not exercise these paths: they need a non-allow-listed route (GET /tokens,
 * GET /users) and a way to mint a bearer token, both of which only exist as of Task 7.
 */
describe('authentication hook: Bearer, CSRF and password-change interactions', () => {
  let ctx: TestContext;
  beforeAll(async () => {
    ctx = await createTestContext();
  });
  afterAll(async () => {
    await ctx.close();
  });

  const mintToken = async (
    headers: Record<string, string>,
    scopes: string[] = ['read'],
  ): Promise<string> => {
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/tokens',
      headers,
      payload: { name: 'mint', scopes },
    });
    return (res.json() as { token: string }).token;
  };

  it('picks the Bearer token over a session cookie when both are presented', async () => {
    const cookieUser = await createUser(ctx, { username: 'cookie-holder' });
    const tokenUser = await createUser(ctx, { username: 'token-holder' });
    const cookieSession = await login(ctx, cookieUser.username, cookieUser.password);
    const tokenSession = await login(ctx, tokenUser.username, tokenUser.password);
    const token = await mintToken(tokenSession.headers);

    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/auth/me',
      headers: { cookie: cookieSession.headers.cookie!, authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(200);
    expect(res.json().user.id).toBe(tokenUser.id);
  });

  it('accepts a Bearer-authenticated mutation with no CSRF header at all', async () => {
    const user = await createUser(ctx, { username: 'bearer-mutator' });
    const session = await login(ctx, user.username, user.password);
    const token = await mintToken(session.headers, ['admin']);

    const minted = await ctx.app.inject({
      method: 'DELETE',
      url: '/api/v0/tokens/00000000-0000-7000-8000-000000000000',
      headers: { authorization: `Bearer ${token}` },
    });
    // No CSRF_FAILED (403): the request reaches ordinary route logic (404, unknown token id).
    expect(minted.statusCode).toBe(404);
  });

  it('403s a non-allow-listed route for a session user who must change their password', async () => {
    const user = await createUser(ctx, {
      username: 'must-change-now',
      passwordChangeRequired: true,
    });
    const session = await login(ctx, user.username, user.password);
    const usersRes = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/users',
      headers: session.headers,
    });
    expect([usersRes.statusCode, usersRes.json().code]).toEqual([403, 'PASSWORD_CHANGE_REQUIRED']);
    const tokensRes = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/tokens',
      headers: session.headers,
    });
    expect([tokensRes.statusCode, tokensRes.json().code]).toEqual([
      403,
      'PASSWORD_CHANGE_REQUIRED',
    ]);
  });

  it('blocks a personal access token once its owner is later flagged for a password change (R7)', async () => {
    const user = await createUser(ctx, { username: 'flagged-after-minting' });
    const session = await login(ctx, user.username, user.password);
    const token = await mintToken(session.headers);
    // The token pre-dates the flag: minting it happened while it was still false.
    await ctx.db.update(users).set({ passwordChangeRequired: true }).where(eq(users.id, user.id));

    const blocked = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/tokens',
      headers: { authorization: `Bearer ${token}` },
    });
    expect([blocked.statusCode, blocked.json().code]).toEqual([403, 'PASSWORD_CHANGE_REQUIRED']);
    // The token itself remains otherwise valid: allow-listed routes still work with it.
    const allowed = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/auth/me',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(allowed.statusCode).toBe(200);
  });
});
