import { sign } from 'node:crypto';
import { eq } from 'drizzle-orm';
import { afterEach, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  bearer,
  createTestContext,
  createUser,
  login,
  type Session,
  type TestContext,
} from '../../test/app';
import {
  signTest,
  T0,
  testPayload,
  testSigner,
  verifyWith,
  type TestSigner,
} from '../../test/license';
import { instanceSettings } from '../db/schema';
import { createEdition } from '../license/edition';
import type { BootLicense } from '../license/source';
import { keyHash } from '../license/token';
import { verifyLicenseKey } from '../license/verify';

const signer = testSigner();
/** Signs arbitrary payload bytes by hand, as a pre-5A key was signed: signLicenseKey drops `organizations`. */
function signBytes(s: TestSigner, body: Buffer): string {
  const input = `QLK1.${s.kid}.${body.toString('base64url')}`;
  return `${input}.${sign(null, Buffer.from(input), s.privateKey).toString('base64url')}`;
}

const none: BootLicense = { source: null, keyHash: null, verification: null };

async function context(boot: BootLicense = none): Promise<TestContext> {
  return createTestContext({
    edition: createEdition({
      boot,
      now: () => T0,
      verifyOptions: (now) => verifyWith(signer, now),
    }),
  });
}

async function storedRows(ctx: TestContext) {
  return ctx.db.select().from(instanceSettings).where(eq(instanceSettings.key, 'license'));
}

function put(ctx: TestContext, session: Session, key: unknown) {
  return ctx.app.inject({
    method: 'PUT',
    url: '/api/v0/license',
    headers: session.headers,
    payload: { key },
  });
}

describe('the licence API (enterprise.md §9)', () => {
  let ctx: TestContext;
  afterEach(async () => ctx.close());

  it('needs an instance admin', async () => {
    ctx = await context();
    expect((await ctx.app.inject({ method: 'GET', url: '/api/v0/license' })).statusCode).toBe(401);
    const user = await createUser(ctx, { username: 'dev' });
    const session = await login(ctx, user.username, user.password);
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/license',
      headers: session.headers,
    });
    expect(res.statusCode).toBe(403);
    const key = signTest(signer);
    expect((await put(ctx, session, key)).statusCode).toBe(403);
    const removed = await ctx.app.inject({
      method: 'DELETE',
      url: '/api/v0/license',
      headers: session.headers,
    });
    expect(removed.statusCode).toBe(403);
    expect(await storedRows(ctx)).toHaveLength(0);
  });

  it('lets an admin-scoped token of an instance admin in; a read/write token gets 403', async () => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const tokenOf = async (scopes: string[]) => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: admin.headers,
        payload: { name: `licence-${scopes.join('-')}`, scopes },
      });
      expect(res.statusCode, res.body).toBe(201);
      return bearer((res.json() as { token: string }).token);
    };
    const adminToken = await tokenOf(['admin']);
    const got = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/license',
      headers: adminToken,
    });
    expect(got.statusCode, got.body).toBe(200);
    const writeToken = await tokenOf(['read', 'write']);
    const refused = await ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/license',
      headers: writeToken,
      payload: { key: signTest(signer) },
    });
    expect(refused.statusCode).toBe(403);
    expect(await storedRows(ctx)).toHaveLength(0);
  });

  it('refuses a session PUT or DELETE without the CSRF header', async () => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const headers = { cookie: admin.headers.cookie! };
    const res = await ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/license',
      headers,
      payload: { key: signTest(signer) },
    });
    expect(res.statusCode).toBe(403);
    expect(res.json()).toMatchObject({ code: 'CSRF_FAILED' });
    const removed = await ctx.app.inject({ method: 'DELETE', url: '/api/v0/license', headers });
    expect(removed.statusCode).toBe(403);
    expect(await storedRows(ctx)).toHaveLength(0);
  });

  it('reports the community edition without a key', async () => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/license',
      headers: admin.headers,
    });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      edition: 'community',
      state: 'none',
      reason: null,
      source: null,
      license: null,
      expiresSoon: false,
      restartRequired: false,
      activeFeatures: [],
      plugins: [],
    });
  });

  it('stores a valid key, says restartRequired, and never returns or logs the key', async () => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const payload = testPayload();
    const key = signTest(signer, payload);
    const res = await put(ctx, admin, key);
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({
      restartRequired: true,
      state: 'none',
      edition: 'community',
    });
    const secretPart = key.split('.')[2]!;
    expect(res.body).not.toContain(secretPart);
    expect(res.body).not.toContain(keyHash(key));
    const [row] = await storedRows(ctx);
    expect(row?.value).toMatchObject({ key, savedBy: ctx.adminId });
    const logs = ctx.logs.join('\n');
    expect(logs).not.toContain(secretPart);
    expect(logs).not.toContain(keyHash(key));
    expect(logs).toContain('licence key saved');
    // A GET afterwards still says a restart is required and still returns no key.
    const again = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/license',
      headers: admin.headers,
    });
    expect(again.json()).toMatchObject({ restartRequired: true, license: null });
    expect(again.body).not.toContain(secretPart);
  });

  it('stores a key pasted with line breaks without its whitespace', async () => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const key = signTest(signer);
    const wrapped = `  ${key.slice(0, 40)}\r\n${key.slice(40, 90)}\n ${key.slice(90)}\n`;
    const res = await put(ctx, admin, wrapped);
    expect(res.statusCode, res.body).toBe(200);
    const [row] = await storedRows(ctx);
    expect(row?.value).toMatchObject({ key });
  });

  it.each([
    ['malformed', 'not a key'],
    ['unknown-key', signTest(testSigner('test-z'))],
  ])('refuses a %s key with 422 LICENSE_INVALID on body.key', async (reason, key) => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await put(ctx, admin, key);
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({
      code: 'LICENSE_INVALID',
      reason,
      errors: [{ path: 'body.key' }],
    });
    expect(await storedRows(ctx)).toHaveLength(0);
  });

  it('refuses a key issued more than 24 h ahead as not-yet-valid (enterprise.md §6)', async () => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const key = signTest(signer, testPayload({ issued: '2026-10-03T00:00:00Z' }));
    const res = await put(ctx, admin, key);
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ code: 'LICENSE_INVALID', reason: 'not-yet-valid' });
  });

  it('verifies an upload with the same keys as the boot: one seam (enterprise.md §9)', async () => {
    const key = signTest(signer);
    // The edition of a release build: the compiled keys only, which know no test- key.
    ctx = await createTestContext({ edition: createEdition({ boot: none, now: () => T0 }) });
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const refused = await put(ctx, admin, key);
    expect(refused.json()).toMatchObject({ code: 'LICENSE_INVALID', reason: 'unknown-key' });
    await ctx.close();
    ctx = await context();
    const session = await login(ctx, 'admin', ADMIN_PASSWORD);
    expect((await put(ctx, session, key)).statusCode).toBe(200);
  });

  it('refuses a revoked key and keeps the stored one', async () => {
    const payload = testPayload();
    ctx = await createTestContext({
      edition: createEdition({
        boot: none,
        now: () => T0,
        verifyOptions: (now) => ({ ...verifyWith(signer, now), revoked: [payload.id] }),
      }),
    });
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const good = signTest(signer);
    expect((await put(ctx, admin, good)).statusCode).toBe(200);
    const res = await put(ctx, admin, signTest(signer, payload));
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({
      code: 'LICENSE_INVALID',
      reason: 'revoked',
      errors: [{ path: 'body.key', message: 'This licence has been revoked' }],
    });
    const [row] = await storedRows(ctx);
    expect(row?.value).toMatchObject({ key: good });
  });

  it('refuses a key past its grace period with 422 LICENSE_EXPIRED', async () => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const key = signTest(
      signer,
      testPayload({ issued: '2024-01-01T00:00:00Z', expires: '2025-01-01T00:00:00Z' }),
    );
    const res = await put(ctx, admin, key);
    expect(res.statusCode).toBe(422);
    expect(res.json()).toMatchObject({ code: 'LICENSE_EXPIRED', errors: [{ path: 'body.key' }] });
    expect(await storedRows(ctx)).toHaveLength(0);
  });

  it('refuses a body over 16 KiB, and a much larger one with 413', async () => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await put(ctx, admin, 'A'.repeat(16 * 1024 + 1));
    expect(res.statusCode).toBe(422);
    const huge = await put(ctx, admin, 'A'.repeat(64 * 1024));
    expect(huge.statusCode).toBe(413);
    expect(await storedRows(ctx)).toHaveLength(0);
  });

  it('refuses a body that is not exactly { key: string }', async () => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    for (const payload of [{}, { key: 42 }, { key: '' }, { key: signTest(signer), extra: 1 }]) {
      const res = await ctx.app.inject({
        method: 'PUT',
        url: '/api/v0/license',
        headers: admin.headers,
        payload,
      });
      expect(res.statusCode, JSON.stringify(payload)).toBe(422);
    }
    expect(await storedRows(ctx)).toHaveLength(0);
  });

  it('refuses PUT and DELETE while the key comes from the environment or a file', async () => {
    const key = signTest(signer);
    for (const source of ['environment', 'file'] as const) {
      ctx = await context({
        source,
        keyHash: keyHash(key),
        verification: { ok: true, kid: signer.kid, license: testPayload() },
      });
      const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
      for (const method of ['PUT', 'DELETE'] as const) {
        const res = await ctx.app.inject({
          method,
          url: '/api/v0/license',
          headers: admin.headers,
          ...(method === 'PUT' ? { payload: { key } } : {}),
        });
        expect(res.statusCode).toBe(409);
        expect(res.json()).toMatchObject({ code: 'LICENSE_MANAGED_BY_ENVIRONMENT' });
      }
      const refusals = ctx.logs.filter((l) => l.includes('licence change refused'));
      expect(refusals).toHaveLength(2);
      for (const line of refusals) {
        expect(JSON.parse(line)).toMatchObject({ level: 40, userId: ctx.adminId, source });
        expect(line).not.toContain(key.split('.')[2]);
      }
      expect(await storedRows(ctx)).toHaveLength(0);
      const status = await ctx.app.inject({
        method: 'GET',
        url: '/api/v0/license',
        headers: admin.headers,
      });
      expect(status.json()).toMatchObject({ source, state: 'active', restartRequired: false });
      await ctx.close();
    }
    ctx = await context();
  });

  it('reports an uploaded boot key as active and says no restart is needed', async () => {
    const payload = testPayload();
    const key = signTest(signer, payload);
    ctx = await context({
      source: 'uploaded',
      keyHash: keyHash(key),
      verification: { ok: true, kid: signer.kid, license: payload },
    });
    await ctx.db
      .insert(instanceSettings)
      .values({ key: 'license', value: { key, savedAt: T0.toISOString(), savedBy: ctx.adminId } });
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/license',
      headers: admin.headers,
    });
    expect(res.json()).toMatchObject({
      edition: 'enterprise',
      state: 'active',
      source: 'uploaded',
      restartRequired: false,
      license: {
        id: payload.id,
        keyId: 'test-a',
        customer: payload.customer,
        issued: '2026-10-01T00:00:00.000Z',
        expires: '2027-10-01T00:00:00.000Z',
        graceEndsAt: '2027-10-15T00:00:00.000Z',
        features: ['llm.fix-quota'],
        test: true,
      },
    });
    expect(res.body).not.toContain(key.split('.')[2]);
    expect(res.body).not.toContain(keyHash(key));
    // Saving the boot key again changes nothing that needs a restart.
    const same = await put(ctx, admin, key);
    expect(same.statusCode, same.body).toBe(200);
    expect(same.json()).toMatchObject({ restartRequired: false });
    const removed = await ctx.app.inject({
      method: 'DELETE',
      url: '/api/v0/license',
      headers: admin.headers,
    });
    expect(removed.statusCode).toBe(200);
    expect(removed.json()).toMatchObject({ restartRequired: true, state: 'active' });
    expect(await storedRows(ctx)).toHaveLength(0);
    expect(ctx.logs.join('\n')).toContain('licence key removed');
  });

  it('PUT /license with a pre-5A key answers 200 and the status has no organizations', async () => {
    // Review Focus 2: a key signed before 5A carries `organizations`; it verifies and is dropped.
    const payload = testPayload();
    const key = signBytes(signer, Buffer.from(JSON.stringify({ ...payload, organizations: 10 })));
    const verification = verifyLicenseKey(key, verifyWith(signer));
    expect(verification).toEqual({ ok: true, kid: signer.kid, license: payload });
    ctx = await context({ source: 'uploaded', keyHash: keyHash(key), verification });
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await put(ctx, admin, key);
    expect(res.statusCode, res.body).toBe(200);
    const body = res.json() as { license: Record<string, unknown> | null } & Record<
      string,
      unknown
    >;
    expect(body).toMatchObject({ state: 'active', edition: 'enterprise', restartRequired: false });
    expect(body).not.toHaveProperty('organizations');
    expect(body.license).toMatchObject({ id: payload.id, customer: payload.customer });
    expect(body.license).not.toHaveProperty('organizations');
    const [row] = await storedRows(ctx);
    expect(row?.value).toMatchObject({ key });
  });

  it('PUT /license with a key listing rbac answers 200, and activeFeatures has no rbac (enterprise.md §1.4)', async () => {
    // Review Focus 3: a pre-5B key that lists rbac still verifies; rbac never becomes active.
    const payload = testPayload({ features: ['rbac', 'audit-log'] });
    const key = signTest(signer, payload);
    const verification = verifyLicenseKey(key, verifyWith(signer));
    ctx = await createTestContext({
      edition: createEdition({
        boot: { source: 'uploaded', keyHash: keyHash(key), verification },
        now: () => T0,
        verifyOptions: (now) => verifyWith(signer, now),
        // The real plugin no longer declares rbac (enterprise.md §7.1, §13).
        plugins: {
          reports: [],
          features: new Set(['audit-log']),
          limitOverrides: [],
          extensions: [],
        },
      }),
    });
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await put(ctx, admin, key);
    expect(res.statusCode, res.body).toBe(200);
    const body = res.json() as {
      activeFeatures: string[];
      license: { features: string[] } | null;
    };
    expect(body.license?.features).toEqual(['rbac', 'audit-log']);
    expect(body.activeFeatures).toEqual(['audit-log']);
    expect(body.activeFeatures).not.toContain('rbac');
  });

  it('shows the licence of a revoked boot key, but not of one whose signature failed', async () => {
    const payload = testPayload();
    ctx = await context({
      source: 'uploaded',
      keyHash: 'x',
      verification: { ok: false, reason: 'revoked', kid: signer.kid, license: payload },
    });
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/license',
      headers: admin.headers,
    });
    expect(res.json()).toMatchObject({
      edition: 'community',
      state: 'invalid',
      reason: 'revoked',
      license: { id: payload.id },
    });
    await ctx.close();
    ctx = await context({
      source: 'uploaded',
      keyHash: 'x',
      verification: { ok: false, reason: 'bad-signature' },
    });
    const admin2 = await login(ctx, 'admin', ADMIN_PASSWORD);
    const bad = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/license',
      headers: admin2.headers,
    });
    expect(bad.json()).toMatchObject({ state: 'invalid', reason: 'bad-signature', license: null });
  });

  it('accepts a key in its grace period and says so', async () => {
    ctx = await context();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    // The upload is checked against the edition's clock (T0): a key that expired a day before is in grace.
    const day = 24 * 60 * 60 * 1000;
    const key = signTest(
      signer,
      testPayload({
        issued: new Date(T0.getTime() - 400 * day).toISOString(),
        expires: new Date(T0.getTime() - day).toISOString(),
      }),
    );
    const res = await put(ctx, admin, key);
    expect(res.statusCode, res.body).toBe(200);
  });
});
