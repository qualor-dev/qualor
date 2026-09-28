import cookie from '@fastify/cookie';
import { eq } from 'drizzle-orm';
import Fastify, { type FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createUser,
  DEFAULT_TEST_PASSWORD,
  nextIp,
  type TestContext,
} from '../../test/app';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';
import { ENTERPRISE_FEATURES } from '../../test/license';
import { AFTER_GRACE } from '../../test/rbac';
import {
  adminHeaders,
  auditRows,
  licensedEdition,
  ONE_CONNECTION_FEATURES,
  oidcConnection,
  personalTokenFor,
  samlConnection,
  sessionHeaders,
  ssoContext,
} from '../../test/sso';
import { createAuditRecorder, SYSTEM_ACTOR } from '../audit/recorder';
import { identities, instanceSettings, users } from '../db/schema';
import { createSsoService } from '../sso/service';
import { updateSignInSettings } from '../sso/sign-in-policy';

/** Inside the test licence's validity (it is issued 2026-10-01): sso, scim, audit-log active. */
const LICENSED = () => new Date('2027-01-01T00:00:00Z');

const login = (ctx: TestContext, username: string, password: string) =>
  ctx.app.inject({
    method: 'POST',
    url: '/api/v0/auth/login',
    remoteAddress: nextIp(),
    payload: { username, password },
  });

describe('password sign-in with SSO (sso-scim.md §10–§11, §16)', () => {
  let now = new Date('2027-01-01T00:00:00Z');
  let ctx: TestContext;
  let adminId: string;
  let connectionId: string;
  beforeAll(async () => {
    ctx = await ssoContext({ now: () => now });
    adminId = ctx.adminId;
    connectionId = await oidcConnection(ctx, { name: 'Acme SSO', enabled: true });
  });
  afterAll(async () => ctx.close());

  it('GET /auth/methods lists the enabled providers and the policy, without credentials', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/methods' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({
      password: 'everyone',
      providers: [
        {
          name: 'Acme SSO',
          protocol: 'oidc',
          startUrl: expect.stringMatching(/^\/api\/v0\/ee\/sso\/[0-9a-f-]+\/start$/),
        },
      ],
    });
    // §16.1: it names no user and no setting beyond these.
    expect(Object.keys(res.json()).sort()).toEqual(['password', 'providers']);
    expect(Object.keys(res.json().providers[0]).sort()).toEqual([
      'id',
      'name',
      'protocol',
      'startUrl',
    ]);
  });

  it('refuses break_glass_only without a usable break-glass admin (422)', async () => {
    const audit = createAuditRecorder({ isActive: () => true, log: QUIET_AUDIT_LOG });
    await expect(
      updateSignInSettings({ db: ctx.db, audit }, SYSTEM_ACTOR, {
        passwordSignIn: 'break_glass_only',
        breakGlassUserIds: [],
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.breakGlassUserIds' }] });
    const plain = await createUser(ctx, { username: 'not-an-admin' });
    await expect(
      updateSignInSettings({ db: ctx.db, audit }, SYSTEM_ACTOR, {
        passwordSignIn: 'break_glass_only',
        breakGlassUserIds: [plain.id],
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.breakGlassUserIds' }] });
  });

  it('saves the setting through updateSignInSettings and records it', async () => {
    const audit = createAuditRecorder({ isActive: () => true, log: QUIET_AUDIT_LOG });
    const saved = await updateSignInSettings({ db: ctx.db, audit }, SYSTEM_ACTOR, {
      passwordSignIn: 'break_glass_only',
      breakGlassUserIds: [adminId],
    });
    expect(saved).toEqual({ passwordSignIn: 'break_glass_only', breakGlassUserIds: [adminId] });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.sign_in_settings_updated',
      targetType: 'sign_in_settings',
      details: { passwordSignIn: 'break_glass_only', breakGlassUserIds: [adminId] },
    });
    await updateSignInSettings({ db: ctx.db, audit }, SYSTEM_ACTOR, {
      passwordSignIn: 'everyone',
      breakGlassUserIds: [adminId],
    });
  });

  it('limits password sign-in to break-glass admins, with the wrong-password answer for others', async () => {
    await createUser(ctx, { username: 'dana' });
    const value = { passwordSignIn: 'break_glass_only', breakGlassUserIds: [adminId] };
    await ctx.db
      .insert(instanceSettings)
      .values({ key: 'sign-in', value })
      .onConflictDoUpdate({ target: instanceSettings.key, set: { value } });
    const refused = await login(ctx, 'dana', DEFAULT_TEST_PASSWORD);
    const wrong = await login(ctx, 'dana', 'not the password at all');
    const nobody = await login(ctx, 'nobody-at-all', DEFAULT_TEST_PASSWORD);
    expect(refused.statusCode).toBe(401);
    expect(refused.json()).toEqual(wrong.json());
    expect(refused.json()).toEqual(nobody.json());
    expect(refused.cookies).toEqual([]);
    expect((await login(ctx, 'admin', ADMIN_PASSWORD)).statusCode).toBe(204);
    const events = await auditRows(ctx);
    expect(
      events.filter((e) => e.action === 'auth.sign_in_failed').map((e) => e.details.reason),
    ).toEqual(expect.arrayContaining(['password_disabled', 'invalid_credentials']));
    expect(events.filter((e) => e.action === 'auth.sign_in').at(-1)?.details).toEqual({
      method: 'password',
    });
    expect(
      (await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/methods' })).json().password,
    ).toBe('break_glass_only');
  });

  it('keeps tokens working for a user who may not use a password', async () => {
    const token = await personalTokenFor(ctx, 'dana');
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/auth/me',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(res.statusCode).toBe(200);
  });

  it('refuses to demote or deactivate the last break-glass admin (409), while another instance admin exists', async () => {
    await createUser(ctx, { username: 'second-admin', isInstanceAdmin: true });
    const headers = await sessionHeaders(ctx, 'second-admin');
    for (const payload of [{ active: false }, { isInstanceAdmin: false }]) {
      const res = await ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/users/${adminId}`,
        headers,
        payload,
      });
      expect(res.statusCode).toBe(409);
      expect(res.json().code).toBe('LAST_BREAK_GLASS_ADMIN');
    }
    // Another listed, usable admin lets the first one go.
    const second = (await ctx.db.select().from(users)).find((u) => u.username === 'second-admin');
    const value = { passwordSignIn: 'break_glass_only', breakGlassUserIds: [adminId, second!.id] };
    await ctx.db.update(instanceSettings).set({ value }).where(eq(instanceSettings.key, 'sign-in'));
    const demoted = await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/users/${adminId}`,
      headers,
      payload: { isInstanceAdmin: false },
    });
    expect(demoted.statusCode).toBe(200);
    expect(demoted.json()).toMatchObject({
      isInstanceAdmin: false,
      hasPassword: true,
      sso: { identities: 0, scim: false },
    });
    const restored = await ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/users/${adminId}`,
      headers,
      payload: { isInstanceAdmin: true },
    });
    expect(restored.statusCode).toBe(200);
    await ctx.db
      .update(instanceSettings)
      .set({ value: { passwordSignIn: 'break_glass_only', breakGlassUserIds: [adminId] } })
      .where(eq(instanceSettings.key, 'sign-in'));
  });

  it('lists SSO-only users for an admin, with their identities, and after the lapse everyone with a password signs in', async () => {
    const [sso] = await ctx.db
      .insert(users)
      .values({ username: 'ssoonly', passwordHash: null })
      .returning();
    await ctx.db.insert(identities).values({
      connectionId,
      userId: sso!.id,
      subject: 'sub-1',
      linkedBy: 'jit',
      scimUserName: 'ssoonly@acme.example',
    });
    const list = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/users?signIn=no-password',
      headers: await adminHeaders(ctx),
    });
    expect(list.statusCode).toBe(200);
    const items = list.json().items as {
      username: string;
      hasPassword: boolean;
      sso: { identities: number; scim: boolean };
    }[];
    expect(items.map((u) => u.username)).toContain('ssoonly');
    expect(items.every((u) => !u.hasPassword)).toBe(true);
    expect(items.find((u) => u.username === 'ssoonly')?.sso).toEqual({ identities: 1, scim: true });
    const all = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/users',
      headers: await adminHeaders(ctx),
    });
    expect(all.json().items.map((u: { username: string }) => u.username)).toContain('dana');
    now = AFTER_GRACE;
    expect((await login(ctx, 'dana', DEFAULT_TEST_PASSWORD)).statusCode).toBe(204);
    expect((await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/methods' })).json()).toEqual({
      password: 'everyone',
      providers: [],
    });
    now = new Date('2027-01-01T00:00:00Z');
  });
});

describe('QUALOR_FORCE_PASSWORD_SIGN_IN (sso-scim.md §10.4)', () => {
  it('re-enables every user with a password and marks the sign-in forced', async () => {
    const ctx = await ssoContext({ now: LICENSED, config: { forcePasswordSignIn: true } });
    try {
      await oidcConnection(ctx, { enabled: true });
      await ctx.db.insert(instanceSettings).values({
        key: 'sign-in',
        value: { passwordSignIn: 'break_glass_only', breakGlassUserIds: [ctx.adminId] },
      });
      await createUser(ctx, { username: 'eve' });
      expect((await login(ctx, 'eve', DEFAULT_TEST_PASSWORD)).statusCode).toBe(204);
      const signIn = (await auditRows(ctx)).filter((e) => e.action === 'auth.sign_in').at(-1);
      expect(signIn?.details).toEqual({ method: 'password', forced: true });
      // The break-glass admin is allowed by the policy itself, so its sign-in is not marked.
      expect((await login(ctx, 'admin', ADMIN_PASSWORD)).statusCode).toBe(204);
      const admin = (await auditRows(ctx)).filter((e) => e.action === 'auth.sign_in').at(-1);
      expect(admin?.details).toEqual({ method: 'password' });
      expect(
        (await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/methods' })).json().password,
      ).toBe('everyone');
    } finally {
      await ctx.close();
    }
  });

  it('still keeps the last break-glass admin while the variable is set (the stored policy decides)', async () => {
    const ctx = await ssoContext({ now: LICENSED, config: { forcePasswordSignIn: true } });
    try {
      await oidcConnection(ctx, { enabled: true });
      await ctx.db.insert(instanceSettings).values({
        key: 'sign-in',
        value: { passwordSignIn: 'break_glass_only', breakGlassUserIds: [ctx.adminId] },
      });
      await createUser(ctx, { username: 'other-admin', isInstanceAdmin: true });
      const headers = await sessionHeaders(ctx, 'other-admin');
      for (const payload of [{ isInstanceAdmin: false }, { active: false }]) {
        const res = await ctx.app.inject({
          method: 'PATCH',
          url: `/api/v0/users/${ctx.adminId}`,
          headers,
          payload,
        });
        expect([res.statusCode, res.json().code]).toEqual([409, 'LAST_BREAK_GLASS_ADMIN']);
      }
      const [admin] = await ctx.db.select().from(users).where(eq(users.id, ctx.adminId));
      expect(admin).toMatchObject({ isInstanceAdmin: true, active: true });
    } finally {
      await ctx.close();
    }
  });

  it('keeps the last break-glass admin after the sso licence lapsed too', async () => {
    let now = LICENSED();
    const ctx = await ssoContext({ now: () => now });
    try {
      await oidcConnection(ctx, { enabled: true });
      await ctx.db.insert(instanceSettings).values({
        key: 'sign-in',
        value: { passwordSignIn: 'break_glass_only', breakGlassUserIds: [ctx.adminId] },
      });
      await createUser(ctx, { username: 'other-admin', isInstanceAdmin: true });
      const headers = await sessionHeaders(ctx, 'other-admin');
      now = AFTER_GRACE;
      const res = await ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/users/${ctx.adminId}`,
        headers,
        payload: { isInstanceAdmin: false },
      });
      expect([res.statusCode, res.json().code]).toEqual([409, 'LAST_BREAK_GLASS_ADMIN']);
      // Password sign-in is open to everyone meanwhile (§11): only the removal is refused.
      expect(
        (await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/methods' })).json().password,
      ).toBe('everyone');
    } finally {
      await ctx.close();
    }
  });
});

describe('without sso (community)', () => {
  it('ignores a stored break_glass_only and lists no provider', async () => {
    const ctx = await ssoContext({ now: LICENSED, features: ['audit-log'] });
    try {
      await ctx.db.insert(instanceSettings).values({
        key: 'sign-in',
        value: { passwordSignIn: 'break_glass_only', breakGlassUserIds: [ctx.adminId] },
      });
      await createUser(ctx, { username: 'frank' });
      expect((await login(ctx, 'frank', DEFAULT_TEST_PASSWORD)).statusCode).toBe(204);
      expect((await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/methods' })).json()).toEqual(
        { password: 'everyone', providers: [] },
      );
    } finally {
      await ctx.close();
    }
  });

  it('reads a malformed setting as everyone', async () => {
    const ctx = await ssoContext({ now: LICENSED });
    try {
      await ctx.db
        .insert(instanceSettings)
        .values({ key: 'sign-in', value: { passwordSignIn: 'nobody', breakGlassUserIds: 'x' } });
      await createUser(ctx, { username: 'gina' });
      expect((await login(ctx, 'gina', DEFAULT_TEST_PASSWORD)).statusCode).toBe(204);
    } finally {
      await ctx.close();
    }
  });
});

describe('one connection in effect without sso.multi (sso-scim.md §4.4, §16.1)', () => {
  let ctx: TestContext;
  let app: FastifyInstance;
  /** Kept from an Enterprise key: both enabled, `oldest` first, `newer` first by name. */
  let oldest: string;
  let newer: string;

  beforeAll(async () => {
    ctx = await ssoContext({ features: ONE_CONNECTION_FEATURES });
    const enterprise = licensedEdition(ENTERPRISE_FEATURES);
    oldest = await samlConnection(ctx, { name: 'Zeta SSO', enabled: true, edition: enterprise });
    newer = await oidcConnection(ctx, { name: 'Alpha SSO', enabled: true, edition: enterprise });
    // The start route as the plugin mounts it: core's service, under the context's edition.
    const service = createSsoService({
      db: ctx.db,
      config: ctx.config,
      edition: () => ctx.edition!,
      audit: createAuditRecorder({ isActive: () => true, log: QUIET_AUDIT_LOG }),
      log: ctx.app.log,
    });
    app = Fastify();
    await app.register(cookie);
    app.get<{ Params: { id: string } }>('/start/:id', (req, reply) =>
      service.start(req, reply, req.params.id),
    );
    await app.ready();
  });
  afterAll(async () => {
    await app.close();
    await ctx.close();
  });

  it('GET /auth/methods lists only the connection in effect', async () => {
    expect(ctx.edition?.isFeatureActive('sso.multi')).toBe(false);
    const res = await ctx.app.inject({ method: 'GET', url: '/api/v0/auth/methods' });
    expect(res.statusCode).toBe(200);
    expect(res.json().providers).toEqual([
      {
        id: oldest,
        name: 'Zeta SSO',
        protocol: 'saml',
        startUrl: `/api/v0/ee/sso/${oldest}/start`,
      },
    ]);
  });

  it('start of a connection not in effect ends in unavailable', async () => {
    const refused = await app.inject({ method: 'GET', url: `/start/${newer}` });
    expect(refused.statusCode).toBe(303);
    expect(refused.headers.location).toBe('/login?sso_error=unavailable');
    expect(refused.cookies.find((c) => c.name === 'qualor_sso')).toBeUndefined();
    // The connection in effect starts (SAML: no outbound call).
    const started = await app.inject({ method: 'GET', url: `/start/${oldest}` });
    expect(started.statusCode).toBe(302);
    expect(new URL(started.headers.location as string).origin).toBe('https://idp.test');
  });
});
