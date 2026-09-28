import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';
import { createTestContext, type TestContext } from '../../test/app';
import { licensedEdition, SSO_FEATURES } from '../../test/sso';
import { createAuditRecorder, SYSTEM_ACTOR } from '../audit/recorder';
import { hashToken } from '../auth/tokens';
import { auditEvents, scimTokens } from '../db/schema';
import { createConnection, deleteConnection, type ConnectionDeps } from '../sso/connections';
import {
  createScimToken,
  generateScimToken,
  listScimTokens,
  MAX_SCIM_TOKENS,
  resolveScimToken,
  revokeScimToken,
  SCIM_TOKEN_PREFIX,
  type ScimTokenDeps,
} from './tokens';

describe('SCIM tokens (sso-scim.md §12.2)', () => {
  let ctx: TestContext;
  let deps: ScimTokenDeps;
  let connectionDeps: ConnectionDeps;
  let conn: string;
  let n = 0;
  const newConnection = async () => {
    n += 1;
    const view = await createConnection(connectionDeps, SYSTEM_ACTOR, {
      name: `SCIM ${n}`,
      protocol: 'oidc',
      oidc: { issuer: `https://idp${n}.example`, clientId: 'q', clientSecret: 's' },
    });
    return view.id;
  };

  beforeAll(async () => {
    ctx = await createTestContext();
    const audit = createAuditRecorder({ isActive: () => true, log: QUIET_AUDIT_LOG });
    deps = { db: ctx.db, audit };
    connectionDeps = {
      db: ctx.db,
      config: { secretKey: ctx.config.secretKey, publicUrl: null, ssoInternalHosts: new Set() },
      audit,
      edition: licensedEdition(SSO_FEATURES),
    };
    conn = await newConnection();
  });
  afterAll(async () => ctx.close());

  it('generates qlr_scim_ and 32 base62 characters, found by the first 12', () => {
    const { token, prefix, secretHash } = generateScimToken();
    expect(SCIM_TOKEN_PREFIX).toBe('qlr_scim_');
    expect(token).toMatch(/^qlr_scim_[0-9A-Za-z]{32}$/);
    expect(prefix).toBe(token.slice(0, 12));
    expect(secretHash.equals(hashToken(token))).toBe(true);
    expect(generateScimToken().token).not.toBe(token);
  });

  it('shows the token once, stores only its hash, and resolves it', async () => {
    const { view, token } = await createScimToken(deps, SYSTEM_ACTOR, {
      connectionId: conn,
      name: 'Entra',
      expiresAt: null,
    });
    expect(token).toMatch(/^qlr_scim_[0-9A-Za-z]{32}$/);
    expect(JSON.stringify(view)).not.toContain(token);
    expect(JSON.stringify(await ctx.db.select().from(scimTokens))).not.toContain(token.slice(9));
    expect(await resolveScimToken(ctx.db, token)).toMatchObject({
      connectionId: conn,
      tokenId: view.id,
    });
    expect(view).toMatchObject({
      connectionId: conn,
      name: 'Entra',
      prefix: token.slice(0, 12),
      expiresAt: null,
      revokedAt: null,
    });
    // The audit event names the token by its prefix, never by its secret.
    const events = await ctx.db.select().from(auditEvents).where(eq(auditEvents.targetId, view.id));
    expect(events.map((e) => e.action)).toEqual(['scim_token.created']);
    expect(events[0]?.details).toEqual({
      connectionId: conn,
      name: 'Entra',
      prefix: token.slice(0, 12),
      expiresAt: null,
    });
    expect(JSON.stringify(events)).not.toContain(token.slice(12));
  });

  it.each([
    ['a malformed token', () => 'qlr_scim_short'],
    ['a personal token', () => 'qlr_pat_' + 'a'.repeat(32)],
    ['an unknown token', () => 'qlr_scim_' + 'b'.repeat(32)],
    ['a token with a trailing newline', () => 'qlr_scim_' + 'b'.repeat(32) + '\n'],
    ['a token of 33 characters', () => 'qlr_scim_' + 'b'.repeat(33)],
    ['an empty string', () => ''],
    ['a huge string', () => 'qlr_scim_' + 'b'.repeat(1_000_000)],
  ])('does not resolve %s', async (_n, make) => {
    expect(await resolveScimToken(ctx.db, make())).toBeNull();
  });

  it('does not resolve a token that shares its prefix but not its secret', async () => {
    const { token } = await createScimToken(deps, SYSTEM_ACTOR, {
      connectionId: conn,
      name: 'twin',
      expiresAt: null,
    });
    const last = token.at(-1) === 'a' ? 'b' : 'a';
    const twin = token.slice(0, -1) + last;
    expect(await resolveScimToken(ctx.db, twin)).toBeNull();
    expect(await resolveScimToken(ctx.db, token)).not.toBeNull();
  });

  it('does not resolve a revoked or an expired token', async () => {
    const a = await createScimToken(deps, SYSTEM_ACTOR, {
      connectionId: conn,
      name: 'r',
      expiresAt: null,
    });
    await revokeScimToken(deps, SYSTEM_ACTOR, a.view.id);
    expect(await resolveScimToken(ctx.db, a.token)).toBeNull();
    // Another connection, so the limit test below counts exactly (this one expires in a second).
    const b = await createScimToken(deps, SYSTEM_ACTOR, {
      connectionId: await newConnection(),
      name: 'e',
      expiresAt: new Date(Date.now() + 1_000),
    });
    expect(await resolveScimToken(ctx.db, b.token, new Date(Date.now() + 5_000))).toBeNull();
    // Neither refusal counts as a use.
    const rows = await ctx.db.select().from(scimTokens).where(eq(scimTokens.id, b.view.id));
    expect(rows[0]?.lastUsedAt).toBeNull();
    const revoked = await ctx.db.select().from(scimTokens).where(eq(scimTokens.id, a.view.id));
    expect(revoked[0]?.lastUsedAt).toBeNull();
  });

  it('touches last_used_at at most once a minute', async () => {
    const { view, token } = await createScimToken(deps, SYSTEM_ACTOR, {
      connectionId: conn,
      name: 'touch',
      expiresAt: null,
    });
    const lastUsed = async () =>
      (await ctx.db.select().from(scimTokens).where(eq(scimTokens.id, view.id)))[0]?.lastUsedAt;
    const t0 = new Date(Date.now() + 60_000);
    await resolveScimToken(ctx.db, token, t0);
    expect((await lastUsed())?.getTime()).toBe(t0.getTime());
    await resolveScimToken(ctx.db, token, new Date(t0.getTime() + 59_000));
    expect((await lastUsed())?.getTime()).toBe(t0.getTime());
    const t1 = new Date(t0.getTime() + 60_000);
    await resolveScimToken(ctx.db, token, t1);
    expect((await lastUsed())?.getTime()).toBe(t1.getTime());
  });

  it('revokes idempotently, records one event, and 404s an unknown id', async () => {
    const { view } = await createScimToken(deps, SYSTEM_ACTOR, {
      connectionId: conn,
      name: 'twice',
      expiresAt: null,
    });
    const first = await revokeScimToken(deps, SYSTEM_ACTOR, view.id);
    expect(first.revokedAt).not.toBeNull();
    const second = await revokeScimToken(deps, SYSTEM_ACTOR, view.id);
    expect(second.revokedAt).toBe(first.revokedAt);
    const events = await ctx.db.select().from(auditEvents).where(eq(auditEvents.targetId, view.id));
    expect(events.map((e) => e.action)).toEqual(['scim_token.created', 'scim_token.revoked']);
    expect(events[1]?.details).toEqual({ connectionId: conn, name: 'twice', prefix: view.prefix });
    await expect(
      revokeScimToken(deps, SYSTEM_ACTOR, '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f'),
    ).rejects.toMatchObject({ status: 404 });
    await expect(revokeScimToken(deps, SYSTEM_ACTOR, 'not-a-uuid')).rejects.toMatchObject({
      status: 404,
    });
  });

  it('refuses a sixth active token on one connection', async () => {
    for (
      let i = (await listScimTokens(ctx.db, conn)).filter((t) => !t.revokedAt).length;
      i < 5;
      i += 1
    ) {
      await createScimToken(deps, SYSTEM_ACTOR, {
        connectionId: conn,
        name: `t${i}`,
        expiresAt: null,
      });
    }
    await expect(
      createScimToken(deps, SYSTEM_ACTOR, { connectionId: conn, name: 'six', expiresAt: null }),
    ).rejects.toMatchObject({ status: 409, code: 'SCIM_TOKEN_LIMIT_REACHED' });
  });

  it('counts only active tokens toward the limit, per connection', async () => {
    const other = await newConnection();
    const made = [];
    for (let i = 0; i < MAX_SCIM_TOKENS; i += 1) {
      made.push(
        await createScimToken(deps, SYSTEM_ACTOR, {
          connectionId: other,
          name: `o${i}`,
          expiresAt: null,
        }),
      );
    }
    await expect(
      createScimToken(deps, SYSTEM_ACTOR, { connectionId: other, name: 'x', expiresAt: null }),
    ).rejects.toMatchObject({ status: 409 });
    const revoked = made[0];
    if (!revoked) throw new Error('no token');
    await revokeScimToken(deps, SYSTEM_ACTOR, revoked.view.id);
    await expect(
      createScimToken(deps, SYSTEM_ACTOR, { connectionId: other, name: 'x', expiresAt: null }),
    ).resolves.toMatchObject({ view: { connectionId: other } });
    expect(await listScimTokens(ctx.db, other)).toHaveLength(MAX_SCIM_TOKENS + 1);
    const all = await listScimTokens(ctx.db);
    expect(all.some((t) => t.connectionId === conn)).toBe(true);
    expect(all.some((t) => t.connectionId === other)).toBe(true);
  });

  it('resolves no token once its connection is gone', async () => {
    const gone = await newConnection();
    const { token } = await createScimToken(deps, SYSTEM_ACTOR, {
      connectionId: gone,
      name: 'gone',
      expiresAt: null,
    });
    expect(await resolveScimToken(ctx.db, token)).not.toBeNull();
    await deleteConnection(connectionDeps, SYSTEM_ACTOR, gone);
    expect(await resolveScimToken(ctx.db, token)).toBeNull();
  });

  it('allows exactly one of six parallel creates past the limit on a fresh connection', async () => {
    const fresh = await newConnection();
    for (let i = 0; i < MAX_SCIM_TOKENS - 1; i += 1) {
      await createScimToken(deps, SYSTEM_ACTOR, {
        connectionId: fresh,
        name: `p${i}`,
        expiresAt: null,
      });
    }
    // The count is taken under the connections' lock: six racing creates on an empty connection
    // give five tokens and exactly one 409, and two racing for the last place give one token.
    const empty = await newConnection();
    const results = await Promise.allSettled(
      Array.from({ length: MAX_SCIM_TOKENS + 1 }, (_, i) =>
        createScimToken(deps, SYSTEM_ACTOR, {
          connectionId: empty,
          name: `race${i}`,
          expiresAt: null,
        }),
      ),
    );
    const refused = results.filter((r) => r.status === 'rejected');
    expect(results.filter((r) => r.status === 'fulfilled')).toHaveLength(MAX_SCIM_TOKENS);
    expect(refused).toHaveLength(1);
    expect(refused[0]).toMatchObject({
      reason: { status: 409, code: 'SCIM_TOKEN_LIMIT_REACHED' },
    });
    expect(await listScimTokens(ctx.db, empty)).toHaveLength(MAX_SCIM_TOKENS);
    const late = await Promise.allSettled(
      Array.from({ length: 2 }, (_, i) =>
        createScimToken(deps, SYSTEM_ACTOR, {
          connectionId: fresh,
          name: `late${i}`,
          expiresAt: null,
        }),
      ),
    );
    expect(late.filter((r) => r.status === 'fulfilled')).toHaveLength(1);
  });

  it('refuses an unknown connection, a bad name and a past expiry', async () => {
    await expect(
      createScimToken(deps, SYSTEM_ACTOR, {
        connectionId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f',
        name: 'x',
        expiresAt: null,
      }),
    ).rejects.toMatchObject({ status: 404 });
    await expect(
      createScimToken(deps, SYSTEM_ACTOR, { connectionId: 'nope', name: 'x', expiresAt: null }),
    ).rejects.toMatchObject({ status: 404 });
    const char = (code: number) => String.fromCharCode(code);
    for (const name of [
      '',
      'x'.repeat(101),
      'tab\there',
      `nul${char(0)}`,
      // Format characters (Cf): a right-to-left override, a zero-width space, a soft hyphen.
      `Entra${char(0x202e)}`,
      `En${char(0x200b)}tra`,
      `En${char(0xad)}tra`,
      `lone${char(0xd800)}`,
    ]) {
      await expect(
        createScimToken(deps, SYSTEM_ACTOR, { connectionId: conn, name, expiresAt: null }),
      ).rejects.toMatchObject({ status: 422 });
    }
    await expect(
      createScimToken(deps, SYSTEM_ACTOR, {
        connectionId: conn,
        name: 'past',
        expiresAt: new Date(Date.now() - 1_000),
      }),
    ).rejects.toMatchObject({ status: 422 });
  });
});
