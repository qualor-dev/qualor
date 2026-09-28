import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  bearer,
  createTestContext,
  createUser,
  login,
  type Session,
  type TestContext,
} from '../../test/app';
import { hashToken, randomBase62 } from '../auth/tokens';
import { apiTokens, users } from '../db/schema';

describe('personal access tokens', () => {
  let ctx: TestContext;
  let alice: Session;
  let bob: Session;
  let aliceId: string;
  let bobId: string;

  beforeAll(async () => {
    ctx = await createTestContext();
    const a = await createUser(ctx, { username: 'alice' });
    const b = await createUser(ctx, { username: 'bob' });
    aliceId = a.id;
    bobId = b.id;
    alice = await login(ctx, a.username, a.password);
    bob = await login(ctx, b.username, b.password);
  });
  afterAll(async () => {
    await ctx.close();
  });

  const create = async (session: Session, payload: object) =>
    ctx.app.inject({ method: 'POST', url: '/api/v0/tokens', headers: session.headers, payload });
  const mint = async (
    session: Session,
    scopes: string[] = ['read'],
  ): Promise<{ id: string; token: string }> =>
    (await create(session, { name: `t-${randomBase62(6)}`, scopes })).json();
  const me = (headers: Record<string, string>) =>
    ctx.app.inject({ method: 'GET', url: '/api/v0/auth/me', headers });

  it('rejects U+0000 in a token name with 422 on body.name', async () => {
    const res = await create(alice, { name: 'a\u0000b', scopes: ['read'] });
    expect(res.statusCode).toBe(422);
    expect(res.json().errors.map((e: { path: string }) => e.path)).toEqual(['body.name']);
  });

  it('creates a token, shows it once and stores only its hash', async () => {
    const res = await create(alice, {
      name: 'ci',
      scopes: ['read', 'analysis:write'],
      expiresInDays: 30,
    });
    expect(res.statusCode).toBe(201);
    const body = res.json();
    expect(body.token).toMatch(/^qlr_pat_[0-9A-Za-z]{32}$/);
    expect(body).toMatchObject({
      name: 'ci',
      prefix: body.token.slice(0, 12),
      scopes: ['read', 'analysis:write'],
    });
    const [row] = await ctx.db.select().from(apiTokens).where(eq(apiTokens.id, body.id));
    expect(row!.secretHash).toEqual(hashToken(body.token));
    expect(JSON.stringify(row)).not.toContain(body.token.slice(12));
    const listed = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/tokens',
      headers: alice.headers,
    });
    expect(listed.json().items.find((t: { id: string }) => t.id === body.id)).not.toHaveProperty(
      'token',
    );
  });

  it('authenticates with Bearer, needs no CSRF header, and has no CSRF token', async () => {
    // 'write' scope: revoking is a mutation (see the INSUFFICIENT_SCOPE test below for 'read').
    const { token } = await mint(alice, ['write']);
    const res = await me(bearer(token));
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ user: { id: aliceId }, csrfToken: null });
    const victim = await mint(alice, ['read']);
    const del = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/tokens/${victim.id}`,
      headers: bearer(token),
    });
    expect(del.statusCode).toBe(204);
  });

  it('requires write scope to revoke a token: a read-only token gets 403 INSUFFICIENT_SCOPE', async () => {
    const readOnly = await mint(alice, ['read']);
    const victim = await mint(alice, ['read']);
    const res = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/tokens/${victim.id}`,
      headers: bearer(readOnly.token),
    });
    expect([res.statusCode, res.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
  });

  it('never lets a token mint a token or change the password (ruling R10)', async () => {
    const { token } = await mint(alice, ['admin']);
    const minted = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/tokens',
      headers: bearer(token),
      payload: { name: 'x', scopes: ['admin'] },
    });
    expect([minted.statusCode, minted.json().code]).toEqual([403, 'SESSION_REQUIRED']);
    const pw = await ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/auth/me/password',
      headers: bearer(token),
      payload: {
        currentPassword: 'a perfectly fine passphrase',
        newPassword: 'another fine passphrase',
      },
    });
    expect([pw.statusCode, pw.json().code]).toEqual([403, 'SESSION_REQUIRED']);
  });

  it('enforces scopes: an analysis:write-only token cannot read the API', async () => {
    const { token } = await mint(alice, ['analysis:write']);
    const res = await me(bearer(token));
    expect([res.statusCode, res.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
  });

  it('rejects revoked, expired, tampered and orphaned tokens with 401', async () => {
    const revoked = await mint(alice);
    await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/tokens/${revoked.id}`,
      headers: alice.headers,
    });
    expect((await me(bearer(revoked.token))).statusCode).toBe(401);
    const expired = await mint(alice);
    await ctx.db
      .update(apiTokens)
      .set({ expiresAt: new Date(Date.now() - 1_000) })
      .where(eq(apiTokens.id, expired.id));
    expect((await me(bearer(expired.token))).statusCode).toBe(401);
    const valid = await mint(alice);
    expect((await me(bearer(`${valid.token.slice(0, 12)}${randomBase62(28)}`))).statusCode).toBe(
      401,
    );
    expect((await me(bearer('qlr_pat_short'))).statusCode).toBe(401);
    const gone = await createUser(ctx, { username: 'soon-inactive' });
    const goneSession = await login(ctx, gone.username, gone.password);
    const goneToken = await mint(goneSession);
    await ctx.db.update(users).set({ active: false }).where(eq(users.id, gone.id));
    expect((await me(bearer(goneToken.token))).statusCode).toBe(401);
  });

  it('leaves lastUsedAt untouched when the presented token is rejected', async () => {
    const inactive = await createUser(ctx, { username: 'never-touches' });
    const inactiveSession = await login(ctx, inactive.username, inactive.password);
    const rejected = await mint(inactiveSession);
    await ctx.db.update(users).set({ active: false }).where(eq(users.id, inactive.id));
    const before = await ctx.db.select().from(apiTokens).where(eq(apiTokens.id, rejected.id));
    expect(before[0]!.lastUsedAt).toBeNull();
    expect((await me(bearer(rejected.token))).statusCode).toBe(401);
    const after = await ctx.db.select().from(apiTokens).where(eq(apiTokens.id, rejected.id));
    expect(after[0]!.lastUsedAt).toBeNull();
  });

  it('maintains updated_at on revoke (data-model.md §2: api_tokens is mutable)', async () => {
    const token = await mint(alice);
    const old = new Date('2000-01-01T00:00:00Z');
    await ctx.db.execute(sql`UPDATE api_tokens SET updated_at = ${old} WHERE id = ${token.id}`);
    const res = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/tokens/${token.id}`,
      headers: alice.headers,
    });
    expect(res.statusCode).toBe(204);
    const [row] = await ctx.db.select().from(apiTokens).where(eq(apiTokens.id, token.id));
    expect(row!.revokedAt).not.toBeNull();
    expect(row!.updatedAt.getTime()).toBeGreaterThan(old.getTime());
    expect(row!.updatedAt.getTime()).toBeGreaterThanOrEqual(row!.createdAt.getTime());
  });

  it('matches the full hash when two tokens share a 12-character prefix', async () => {
    const mine = await mint(alice);
    const twin = `${mine.token.slice(0, 12)}${randomBase62(28)}`;
    await ctx.db.insert(apiTokens).values({
      kind: 'personal',
      userId: bobId,
      name: 'twin',
      prefix: mine.token.slice(0, 12),
      secretHash: hashToken(twin),
      scopes: ['read'],
      createdBy: bobId,
    });
    expect((await me(bearer(mine.token))).json().user.id).toBe(aliceId);
    expect((await me(bearer(twin))).json().user.id).toBe(bobId);
  });

  it('still matches the live token when a revoked token shares its 12-character prefix', async () => {
    // Controller ruling S6: revoked/expired siblings must stay in the constant-time comparison set
    // (checked only after a match is found), not be filtered out of the SQL candidate lookup.
    const mine = await mint(alice);
    const revokedTwin = `${mine.token.slice(0, 12)}${randomBase62(28)}`;
    const [inserted] = await ctx.db
      .insert(apiTokens)
      .values({
        kind: 'personal',
        userId: bobId,
        name: 'revoked-twin',
        prefix: mine.token.slice(0, 12),
        secretHash: hashToken(revokedTwin),
        scopes: ['read'],
        createdBy: bobId,
        revokedAt: new Date(),
      })
      .returning();
    expect((await me(bearer(mine.token))).json().user.id).toBe(aliceId);
    expect((await me(bearer(revokedTwin))).statusCode).toBe(401);
    expect(inserted!.revokedAt).not.toBeNull();
  });

  it("lists only your own live tokens and 404s other people's", async () => {
    const bobs = await mint(bob);
    const list = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/tokens?limit=500',
      headers: alice.headers,
    });
    expect(list.json().items.map((t: { id: string }) => t.id)).not.toContain(bobs.id);
    const steal = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/tokens/${bobs.id}`,
      headers: alice.headers,
    });
    expect(steal.statusCode).toBe(404);
  });

  it('validates the body (422)', async () => {
    for (const [payload, path] of [
      [{ name: 'x', scopes: [] }, 'body.scopes'],
      [{ name: 'x', scopes: ['root'] }, 'body.scopes.0'],
      [{ name: 'x', scopes: ['read', 'read'] }, 'body.scopes'],
      [{ name: 'x', scopes: ['read'], expiresInDays: 0 }, 'body.expiresInDays'],
      [{ name: '', scopes: ['read'] }, 'body.name'],
    ] as const) {
      const res = await create(alice, payload);
      expect(res.statusCode, JSON.stringify(payload)).toBe(422);
      expect(res.json().errors.map((e: { path: string }) => e.path)).toContain(path);
    }
    const badId = await ctx.app.inject({
      method: 'DELETE',
      url: '/api/v0/tokens/nope',
      headers: alice.headers,
    });
    expect(badId.json().errors[0].path).toBe('params.id');
  });

  it('requires authentication (401)', async () => {
    for (const [method, url] of [
      ['GET', '/api/v0/tokens'],
      ['POST', '/api/v0/tokens'],
      ['DELETE', '/api/v0/tokens/0190a0b0-0000-7000-8000-000000000000'],
    ] as const) {
      expect((await ctx.app.inject({ method, url })).statusCode).toBe(401);
    }
  });
});
