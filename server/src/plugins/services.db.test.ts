import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  createProject,
  createUser,
  login,
  type Session,
  type TestContext,
} from '../../test/app';
import { AFTER_GRACE, rbacContext } from '../../test/rbac';
import { startFakeOp, type FakeOp } from '../../test/fake-oidc';
import { TEST_IDP } from '../../test/saml';
import { auditRows, personalTokenFor, sessionHeaders, ssoContext } from '../../test/sso';
import { createAuditRecorder, SYSTEM_ACTOR } from '../audit/recorder';
import { AUDIT_CHAIN_KEY } from '../audit/settings';
import {
  identities,
  instanceSettings,
  memberships,
  organizations,
  scimGroupMembers,
  scimGroups,
  ssoConnections,
  ssoStates,
  users,
} from '../db/schema';
import { testConnection } from '../sso/connections';
import type { QualorPlugin } from './contract';
import { createPluginServices, type PluginServices } from './services';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';

const LICENSED = new Date('2027-01-01T00:00:00Z');

const fixture: QualorPlugin = {
  name: 'svc-fixture',
  apiVersion: 1,
  features: ['audit-log'],
  register(ctx) {
    ctx.routes('audit-log', async (app) => {
      // The checks a plugin route makes on a project's organisation, as core routes make them.
      app.put('/svc/projects/:id/check/:userId', async (request) => {
        const { id } = request.params as { id: string; userId: string };
        const project = await ctx.access.projectForUser(request, id, 'project.read');
        await ctx.access.requireOrganizationAccess(
          request,
          project.organizationId,
          'org.members.manage',
        );
        return { project: project.id, actor: ctx.access.actor(request).actor };
      });
      app.get('/svc/problem', async () => {
        throw ctx.access.problem(409, 'SVC_BUSY', 'The fixture is busy', 'Try later.');
      });
      app.get('/svc/audit/head', async (request) => {
        ctx.access.requireInstanceAdmin(request);
        return ctx.audit.head();
      });
    });
  },
};

describe('the plugin services (rbac-audit.md §15)', () => {
  let now = LICENSED;
  let ctx: TestContext;
  let root: Session;
  let orgAdmin: Session;
  let member: Session;
  let outsider: Session;
  let orgAdminId: string;
  let targetId: string;
  let project: { id: string; key: string };

  const put = (session: Session, userId = targetId) =>
    ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/ee/svc/projects/${project.id}/check/${userId}`,
      headers: session.headers,
    });
  const head = (session: Session) =>
    ctx.app.inject({ method: 'GET', url: '/api/v0/ee/svc/audit/head', headers: session.headers });

  beforeAll(async () => {
    ctx = await rbacContext({
      now: () => now,
      plugin: fixture,
    });
    expect(ctx.edition?.plugins()).toEqual([
      { name: 'svc-fixture', state: 'loaded', features: ['audit-log'], error: null },
    ]);
    root = await login(ctx, 'admin', ADMIN_PASSWORD);
    const created = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/organizations',
      headers: root.headers,
      payload: { key: 'second', name: 'Second' },
    });
    expect(created.statusCode).toBe(201);
    const org = (created.json() as { id: string }).id;
    project = await createProject(ctx, root, { organizationId: org, key: 'svc-app' });
    const admin = await createUser(ctx, { username: 'svc-orgadmin' });
    const plain = await createUser(ctx, { username: 'svc-member' });
    const stranger = await createUser(ctx, { username: 'svc-outsider' });
    targetId = (await createUser(ctx, { username: 'svc-target' })).id;
    orgAdminId = admin.id;
    await addMember(ctx, org, admin.id, 'admin');
    await addMember(ctx, org, plain.id, 'member');
    orgAdmin = await login(ctx, admin.username, admin.password);
    member = await login(ctx, plain.username, plain.password);
    outsider = await login(ctx, stranger.username, stranger.password);
  });
  afterAll(async () => ctx.close());

  it('lets an org admin through the access checks, with the actor core records', async () => {
    const res = await put(orgAdmin);
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toEqual({
      project: project.id,
      actor: { type: 'user', userId: orgAdminId, username: 'svc-orgadmin', tokenId: null },
    });
  });

  it('answers 403 FORBIDDEN to a member and 404 to an outsider, as core routes do', async () => {
    const forbidden = await put(member);
    expect(forbidden.statusCode).toBe(403);
    expect(forbidden.json()).toMatchObject({ code: 'FORBIDDEN' });
    const hidden = await put(outsider);
    expect(hidden.statusCode).toBe(404);
    expect(hidden.json()).toMatchObject({ code: 'NOT_FOUND' });
  });

  it('answers the chain head to an instance admin only', async () => {
    const ok = await head(root);
    expect(ok.statusCode).toBe(200);
    const body = ok.json() as { seq: string; hash: string; count: number };
    expect(body.seq).toMatch(/^\d+$/);
    expect(body.hash).toMatch(/^[0-9a-f]{64}$/);
    expect(body.count).toBeGreaterThan(0);
    const refused = await head(orgAdmin);
    expect(refused.statusCode).toBe(403);
    expect(refused.json()).toMatchObject({ code: 'FORBIDDEN' });
  });

  it('answers 409 AUDIT_CHAIN_ANCHOR_MALFORMED, not a 500, on a malformed anchor row', async () => {
    await ctx.db
      .insert(instanceSettings)
      .values({ key: AUDIT_CHAIN_KEY, value: { throughSeq: 'x', throughHash: 'y' } });
    try {
      const res = await head(root);
      expect(res.statusCode).toBe(409);
      expect(res.json()).toMatchObject({
        code: 'AUDIT_CHAIN_ANCHOR_MALFORMED',
        type: 'urn:qualor:problem:audit-chain-anchor-malformed',
      });
    } finally {
      await ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, AUDIT_CHAIN_KEY));
    }
  });

  it('turns ctx.access.problem into a core problem', async () => {
    const res = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/ee/svc/problem',
      headers: root.headers,
    });
    expect(res.statusCode).toBe(409);
    expect(res.headers['content-type']).toMatch(/^application\/problem\+json/);
    expect(res.json()).toEqual({
      type: 'urn:qualor:problem:svc-busy',
      title: 'The fixture is busy',
      status: 409,
      code: 'SVC_BUSY',
      detail: 'Try later.',
    });
  });

  it("switches the feature's routes off after the grace period", async () => {
    now = AFTER_GRACE;
    try {
      for (const res of [await put(orgAdmin), await head(root)]) {
        expect(res.statusCode).toBe(403);
        expect(res.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED' });
      }
    } finally {
      now = LICENSED;
    }
  });

  describe('createPluginServices', () => {
    const services = () =>
      createPluginServices({
        db: ctx.db,
        isFeatureActive: () => true,
        secretKey: ctx.config.secretKey,
        version: '0.0.0',
        recorder: createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true }),
      });

    it('is frozen, and hands out no database handle', () => {
      const s = services();
      expect(Object.isFrozen(s)).toBe(true);
      for (const service of [s.access, s.audit]) {
        expect(Object.isFrozen(service)).toBe(true);
        expect(Object.values(service).every((v) => typeof v === 'function')).toBe(true);
      }
      // Without config, edition and logger, sso and scim are the stand-ins that throw.
      // No rbac service since 5B: the grant routes are core routes (rbac-audit.md §15, §16).
      expect(Object.keys(s).sort()).toEqual(['access', 'audit', 'scim', 'sso']);
      expect(() => s.sso.listConnections()).toThrow(
        'the sso service is not available in this context',
      );
    });

    it('verifies a range given as seq strings, and refuses anything else with 422', async () => {
      const s = services();
      await expect(s.audit.verify({ fromSeq: '1' })).resolves.toMatchObject({ ok: true });
      await expect(s.audit.verify({ toSeq: '1.5' })).rejects.toMatchObject({
        status: 422,
        errors: [{ path: 'query.toSeq', message: 'Use a sequence number' }],
      });
    });

    it('refuses a problem that is not one', () => {
      const s = services();
      expect(() => s.access.problem(200, 'OK', 'Fine')).toThrow(/status is 400 to 599/);
      expect(() => s.access.problem(409, 'lower', 'Title')).toThrow(/UPPER_SNAKE_CASE/);
      expect(() => s.access.problem(409, 'CODE', ' ')).toThrow(/title/);
    });

    it('streamOnce sends nothing and updateSettings with a stream is 403 while audit-log.stream is inactive', async () => {
      // rbac-audit.md §14.4: core checks the feature again, whatever the plugin registered.
      const bodies: string[] = [];
      const receiver = createServer((req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', () => {
          bodies.push(Buffer.concat(chunks).toString());
          res.statusCode = 204;
          res.end();
        });
      });
      await new Promise<void>((resolve) => receiver.listen(0, '127.0.0.1', resolve));
      const url = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/siem`;
      const servicesWith = (on: readonly string[]) =>
        createPluginServices({
          db: ctx.db,
          isFeatureActive: (f) => on.includes(f),
          secretKey: ctx.config.secretKey,
          version: '0.0.0',
          recorder: createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true }),
        });
      const full = servicesWith(['audit-log', 'audit-log.stream']);
      const business = servicesWith(['audit-log']);
      const streamOnly = servicesWith(['audit-log.stream']);
      const signal = new AbortController().signal;
      const rows = async () =>
        (
          await ctx.db.execute<{ key: string; value: string }>(sql`
            SELECT key, value::text AS value FROM instance_settings
             WHERE key IN ('audit', 'audit-stream') ORDER BY key`)
        ).rows;
      const eventCount = async () =>
        (await ctx.db.execute<{ n: number }>(sql`SELECT count(*)::int AS n FROM audit_events`))
          .rows[0]!.n;
      await ctx.db.execute(sql`
        INSERT INTO instance_settings (key, value)
        VALUES ('webhooks', ${JSON.stringify({ allowHttp: true, allowInternalHosts: true })}::jsonb)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`);
      try {
        // Configured while licensed: the settings_updated event is pending (§14.2).
        await full.audit.updateSettings(SYSTEM_ACTOR, { stream: { url } });
        const kept = await rows();
        const events = await eventCount();
        expect(kept.map((r) => r.key)).toEqual(['audit', 'audit-stream']);

        for (const gated of [business, streamOnly]) {
          await gated.audit.streamOnce(signal);
          await expect(gated.audit.testStream()).resolves.toEqual({
            ok: false,
            status: null,
            excerpt: 'SIEM streaming is not licensed',
          });
        }
        const refusal = {
          status: 403,
          code: 'FEATURE_NOT_LICENSED',
          message: 'The enterprise feature "audit-log.stream" is not licensed',
        };
        // Refused before anything is read or written: an invalid URL is not even validated.
        for (const stream of [{ url }, { url: 'ftp://127.0.0.1/siem', active: false }]) {
          await expect(
            business.audit.updateSettings(SYSTEM_ACTOR, { retentionDays: 90, stream }),
          ).rejects.toMatchObject(refusal);
        }
        await expect(business.audit.regenerateStreamSecret(SYSTEM_ACTOR)).rejects.toMatchObject(
          refusal,
        );
        expect(bodies).toEqual([]);
        expect(await rows()).toEqual(kept);
        expect(await eventCount()).toBe(events);

        // Retention alone needs audit-log only, and keeps the stream as it is.
        const retention = await business.audit.updateSettings(SYSTEM_ACTOR, { retentionDays: 90 });
        expect(retention.view).toMatchObject({ retentionDays: 90, stream: { url, active: true } });

        // The positive control: the same configuration streams once the feature is active.
        await full.audit.streamOnce(signal);
        expect(bodies).toHaveLength(1);
        expect(JSON.parse(bodies[0]!)).toMatchObject({ stream: 'qualor-audit', test: false });

        // stream: null removes it with audit-log alone.
        const removed = await business.audit.updateSettings(SYSTEM_ACTOR, {
          retentionDays: 365,
          stream: null,
        });
        expect(removed.view).toEqual({ retentionDays: 365, stream: null });
      } finally {
        await ctx.db.execute(sql`DELETE FROM instance_settings WHERE key = 'webhooks'`);
        receiver.closeAllConnections();
        await new Promise<void>((resolve) => receiver.close(() => resolve()));
      }
    });
  });
});

describe('the 4D services (sso-scim.md §17.1)', () => {
  let ctx: TestContext;
  let op: FakeOp;
  let services: PluginServices;
  /** The same services over an edition where `sso` and `scim` are inactive (the lapse). */
  let lapsed: PluginServices;
  /** The same services without `sso.multi` (a Business key): one connection in effect. */
  let business: PluginServices;
  let defaultOrg: string;

  const build = (
    active: (feature: string) => boolean,
    config: TestContext['config'] = ctx.config,
  ): PluginServices =>
    createPluginServices({
      db: ctx.db,
      isFeatureActive: active,
      secretKey: ctx.config.secretKey,
      version: '0.0.0',
      recorder: createAuditRecorder({ isActive: () => active('audit-log'), log: QUIET_AUDIT_LOG }),
      config,
      edition: () => ({ ...ctx.edition!, isFeatureActive: active }),
      logger: ctx.app.log,
    });

  beforeAll(async () => {
    op = await startFakeOp();
    ctx = await ssoContext({
      // The test licence is issued 2026-10-01: the edition's clock is inside it.
      now: () => LICENSED,
      config: { ssoInternalHosts: new Set([new URL(op.issuer).host]) },
      beforeReady: (app) => {
        // The plugin's routes (Task 19) in miniature, over the services and over the lapsed ones.
        const open = { config: { public: true } };
        const idOf = (request: { params: unknown }) => (request.params as { id: string }).id;
        for (const [prefix, s] of [
          ['/test/svc', () => services],
          ['/test/lapsed', () => lapsed],
          ['/test/business', () => business],
        ] as const) {
          app.get(`${prefix}/sso/:id/start`, open, (request, reply) =>
            s().sso.start(request, reply, idOf(request)),
          );
          app.post(`${prefix}/sso/:id/link`, async (request, reply) =>
            s().sso.startLink(request, reply, idOf(request)),
          );
          app.get(`${prefix}/sso/oidc/:id/callback`, open, (request, reply) =>
            s().sso.oidcCallback(request, reply, idOf(request)),
          );
          app.post(`${prefix}/sso/saml/:id/acs`, open, (request, reply) =>
            s().sso.samlAcs(request, reply, idOf(request)),
          );
          app.get(`${prefix}/sso/finish`, open, (request, reply) => s().sso.finish(request, reply));
          app.all(`${prefix}/scim/v2/*`, open, (request, reply) => s().scim.handle(request, reply));
        }
      },
    });
    services = build((f) => ctx.edition!.isFeatureActive(f));
    lapsed = build((f) => f !== 'sso' && f !== 'scim' && ctx.edition!.isFeatureActive(f));
    business = build((f) => f !== 'sso.multi' && ctx.edition!.isFeatureActive(f));
    const [org] = await ctx.db
      .select({ id: organizations.id })
      .from(organizations)
      .where(eq(organizations.key, 'default'));
    defaultOrg = org!.id;
  });
  afterAll(async () => {
    await ctx.close();
    await op.close();
  });

  // At most 10 connections (spec §4): every test starts without any.
  beforeEach(async () => {
    await ctx.db.delete(ssoConnections);
  });

  const oidcInput = (name: string) => ({
    name,
    protocol: 'oidc' as const,
    oidc: { issuer: op.issuer, clientId: op.clientId, clientSecret: op.clientSecret },
  });

  it('create, read, update and delete a connection, recording each change', async () => {
    const { sso } = services;
    const view = await sso.createConnection(SYSTEM_ACTOR, {
      name: 'Plug',
      protocol: 'oidc',
      oidc: { issuer: 'https://idp.example', clientId: 'q', clientSecret: 's' },
    });
    expect((await sso.getConnection(view.id)).name).toBe('Plug');
    await sso.updateConnection(SYSTEM_ACTOR, view.id, { name: 'Plug 2' });
    await sso.deleteConnection(SYSTEM_ACTOR, view.id);
    const actions = (await auditRows(ctx)).map((e) => e.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        'sso.connection_created',
        'sso.connection_updated',
        'sso.connection_deleted',
      ]),
    );
  });

  it('answers a problem the plugin can throw for an unknown connection', async () => {
    await expect(
      services.sso.getConnection('0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f'),
    ).rejects.toMatchObject({ status: 404 });
  });

  it('creates a SCIM token once and lists it without the secret', async () => {
    const conn = (
      await services.sso.createConnection(SYSTEM_ACTOR, {
        name: 'S',
        protocol: 'oidc',
        oidc: { issuer: 'https://s.example', clientId: 'q', clientSecret: 's' },
      })
    ).id;
    const { token, view } = await services.scim.createToken(SYSTEM_ACTOR, {
      connectionId: conn,
      name: 'Entra',
      expiresAt: null,
    });
    expect(JSON.stringify(await services.scim.listTokens(conn))).not.toContain(token);
    expect(view.prefix).toBe(token.slice(0, 12));
    await services.scim.revokeToken(SYSTEM_ACTOR, view.id);
    const [listed] = await services.scim.listTokens(conn);
    expect(listed?.revokedAt).not.toBeNull();
  });

  it('takes an expiry as an ISO time, and refuses one that is not with 422', async () => {
    const conn = (await services.sso.createConnection(SYSTEM_ACTOR, oidcInput('Expiring'))).id;
    const { view } = await services.scim.createToken(SYSTEM_ACTOR, {
      connectionId: conn,
      name: 'Okta',
      expiresAt: '2099-01-01T00:00:00Z',
    });
    expect(view.expiresAt).toBe('2099-01-01T00:00:00.000Z');
    await expect(
      services.scim.createToken(SYSTEM_ACTOR, {
        connectionId: conn,
        name: 'Okta',
        expiresAt: 'next tuesday',
      }),
    ).rejects.toMatchObject({ status: 422, errors: [{ path: 'body.expiresAt' }] });
  });

  it('refuses every admin member with 403 FEATURE_NOT_LICENSED while the feature is off, writing nothing', async () => {
    const conn = (await services.sso.createConnection(SYSTEM_ACTOR, oidcInput('Lapsing'))).id;
    const settled = (await auditRows(ctx)).length;
    const calls: [string, () => Promise<unknown>][] = [
      ['listConnections', () => lapsed.sso.listConnections()],
      ['getConnection', () => lapsed.sso.getConnection(conn)],
      ['createConnection', () => lapsed.sso.createConnection(SYSTEM_ACTOR, oidcInput('Never'))],
      ['updateConnection', () => lapsed.sso.updateConnection(SYSTEM_ACTOR, conn, { name: 'X' })],
      ['deleteConnection', () => lapsed.sso.deleteConnection(SYSTEM_ACTOR, conn)],
      ['testConnection', () => lapsed.sso.testConnection(conn)],
      ['readSamlMetadata', () => lapsed.sso.readSamlMetadata(conn)],
      ['mappings', () => lapsed.sso.mappings(conn)],
      ['replaceMappings', () => lapsed.sso.replaceMappings(SYSTEM_ACTOR, conn, [])],
      ['signInSettings', () => lapsed.sso.signInSettings()],
      [
        'updateSignInSettings',
        () =>
          lapsed.sso.updateSignInSettings(SYSTEM_ACTOR, {
            passwordSignIn: 'everyone',
            breakGlassUserIds: [],
          }),
      ],
      ['userIdentities', () => lapsed.sso.userIdentities(ctx.adminId)],
      ['unlinkIdentity', () => lapsed.sso.unlinkIdentity(SYSTEM_ACTOR, ctx.adminId, conn, true)],
      ['spMetadata', () => lapsed.sso.spMetadata(conn)],
      ['listTokens', () => lapsed.scim.listTokens(conn)],
      [
        'createToken',
        () =>
          lapsed.scim.createToken(SYSTEM_ACTOR, { connectionId: conn, name: 'N', expiresAt: null }),
      ],
      ['revokeToken', () => lapsed.scim.revokeToken(SYSTEM_ACTOR, conn)],
    ];
    for (const [name, call] of calls) {
      await expect(call(), name).rejects.toMatchObject({
        status: 403,
        code: 'FEATURE_NOT_LICENSED',
      });
    }
    expect((await auditRows(ctx)).length).toBe(settled);
    expect((await services.sso.getConnection(conn)).name).toBe('Lapsing');
  });

  it('answers 403 on every flow and on SCIM while the features are off, starting nothing', async () => {
    const conn = (
      await services.sso.createConnection(SYSTEM_ACTOR, { ...oidcInput('Lapsed'), enabled: true })
    ).id;
    const { token } = await services.scim.createToken(SYSTEM_ACTOR, {
      connectionId: conn,
      name: 'Lapsed',
      expiresAt: null,
    });
    await createUser(ctx, { username: 'lapsed-linker' });
    const settled = (await auditRows(ctx)).length;
    const states = async () => (await ctx.db.select().from(ssoStates)).length;
    const before = await states();
    const flows = [
      { name: 'start', method: 'GET', url: `/test/lapsed/sso/${conn}/start` },
      {
        name: 'startLink',
        method: 'POST',
        url: `/test/lapsed/sso/${conn}/link`,
        headers: await sessionHeaders(ctx, 'lapsed-linker'),
      },
      {
        name: 'oidcCallback',
        method: 'GET',
        url: `/test/lapsed/sso/oidc/${conn}/callback?state=s&code=c`,
      },
      {
        name: 'samlAcs',
        method: 'POST',
        url: `/test/lapsed/sso/saml/${conn}/acs`,
        payload: { SAMLResponse: 'x', RelayState: 'y' },
      },
      { name: 'finish', method: 'GET', url: `/test/lapsed/sso/finish?code=${'a'.repeat(43)}` },
    ] as const;
    for (const { name, ...request } of flows) {
      const res = await ctx.app.inject(request);
      expect([res.statusCode, res.json().code], name).toEqual([403, 'FEATURE_NOT_LICENSED']);
      expect(res.headers['content-type'], name).toMatch(/^application\/problem\+json/);
      expect(
        res.cookies.map((c) => c.name),
        name,
      ).not.toContain('qualor_sso');
    }
    // SCIM answers in SCIM, even refusing (ruling SS7: handleScim's own check).
    const scim = await ctx.app.inject({
      method: 'GET',
      url: '/test/lapsed/scim/v2/Users',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(scim.statusCode).toBe(403);
    expect(scim.headers['content-type']).toMatch(/^application\/scim\+json/);
    expect(await states()).toBe(before);
    expect((await auditRows(ctx)).length).toBe(settled);
  });

  it('lists and replaces a connection’s mappings; 404 for an unknown connection', async () => {
    const conn = (await services.sso.createConnection(SYSTEM_ACTOR, oidcInput('Mapped'))).id;
    const replaced = await services.sso.replaceMappings(SYSTEM_ACTOR, conn, [
      { group: 'devs', organizationId: defaultOrg, projectId: null, role: 'member' },
    ]);
    expect(replaced).toMatchObject([{ group: 'devs', organizationKey: 'default' }]);
    expect(await services.sso.mappings(conn)).toEqual(replaced);
    for (const id of ['0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f', 'not-a-uuid']) {
      await expect(services.sso.mappings(id)).rejects.toMatchObject({ status: 404 });
    }
  });

  it('shows the sign-in settings with the variable and the break-glass admins', async () => {
    expect(await services.sso.signInSettings()).toEqual({
      passwordSignIn: 'everyone',
      breakGlassUserIds: [],
      forced: false,
      breakGlass: [],
    });
    await services.sso.createConnection(SYSTEM_ACTOR, { ...oidcInput('Glass'), enabled: true });
    try {
      const view = await services.sso.updateSignInSettings(SYSTEM_ACTOR, {
        passwordSignIn: 'break_glass_only',
        breakGlassUserIds: [ctx.adminId],
      });
      expect(view).toEqual({
        passwordSignIn: 'break_glass_only',
        breakGlassUserIds: [ctx.adminId],
        forced: false,
        breakGlass: [{ userId: ctx.adminId, username: 'admin', usable: true }],
      });
      expect(await services.sso.signInSettings()).toEqual(view);
    } finally {
      await services.sso.updateSignInSettings(SYSTEM_ACTOR, {
        passwordSignIn: 'everyone',
        breakGlassUserIds: [],
      });
    }
  });

  describe('identities', () => {
    let conn: string;
    let other: string;

    const link = async (connectionId: string, userId: string, subject: string) => {
      const [row] = await ctx.db
        .insert(identities)
        .values({ connectionId, userId, subject, linkedBy: 'user' })
        .returning({ id: identities.id });
      return row!.id;
    };
    const noPassword = async (userId: string) =>
      ctx.db.update(users).set({ passwordHash: null }).where(eq(users.id, userId));

    /** Enabled: only an identity on an enabled connection counts as a way to sign in. */
    const enabledInput = (name: string) => ({ ...oidcInput(name), enabled: true });

    beforeEach(async () => {
      conn = (await services.sso.createConnection(SYSTEM_ACTOR, enabledInput('Ids One'))).id;
      other = (await services.sso.createConnection(SYSTEM_ACTOR, enabledInput('Ids Two'))).id;
    });

    it('lists a user’s identities without the subject, and 404 for an unknown user', async () => {
      const user = await createUser(ctx, { username: 'ids-list' });
      const id = await link(conn, user.id, 'secret-subject');
      const list = await services.sso.userIdentities(user.id);
      expect(list).toEqual([
        {
          id,
          connectionId: conn,
          connectionName: 'Ids One',
          protocol: 'oidc',
          linkedBy: 'user',
          scim: false,
          createdAt: expect.any(String),
          lastSignInAt: null,
        },
      ]);
      expect(JSON.stringify(list)).not.toContain('secret-subject');
      for (const unknown of ['0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f', 'nope']) {
        await expect(services.sso.userIdentities(unknown)).rejects.toMatchObject({
          status: 404,
        });
      }
    });

    it('unlinks an identity of a user with a password, recording sso.identity_unlinked', async () => {
      const user = await createUser(ctx, { username: 'ids-unlink' });
      const id = await link(conn, user.id, 'ids-unlink-sub');
      await services.sso.unlinkIdentity(SYSTEM_ACTOR, user.id, id, true);
      expect(await services.sso.userIdentities(user.id)).toEqual([]);
      const [event] = (await auditRows(ctx)).filter(
        (e) => e.action === 'sso.identity_unlinked' && e.targetId === user.id,
      );
      expect(event).toMatchObject({ details: { connectionId: conn, byAdmin: true } });
    });

    it('refuses the last sign-in method of a user without a password with 409', async () => {
      const user = await createUser(ctx, { username: 'ids-last' });
      await noPassword(user.id);
      const first = await link(conn, user.id, 'ids-last-1');
      const second = await link(other, user.id, 'ids-last-2');
      await services.sso.unlinkIdentity(SYSTEM_ACTOR, user.id, first, false);
      await expect(
        services.sso.unlinkIdentity(SYSTEM_ACTOR, user.id, second, false),
      ).rejects.toMatchObject({ status: 409, code: 'LAST_SIGN_IN_METHOD' });
      expect((await services.sso.userIdentities(user.id)).map((i) => i.id)).toEqual([second]);
    });

    it('counts no identity on a disabled connection as a way to sign in', async () => {
      const disabled = (await services.sso.createConnection(SYSTEM_ACTOR, oidcInput('Ids Off'))).id;
      const user = await createUser(ctx, { username: 'ids-disabled' });
      await noPassword(user.id);
      const usable = await link(conn, user.id, 'ids-disabled-1');
      await link(disabled, user.id, 'ids-disabled-2');
      await expect(
        services.sso.unlinkIdentity(SYSTEM_ACTOR, user.id, usable, false),
      ).rejects.toMatchObject({ status: 409, code: 'LAST_SIGN_IN_METHOD' });
      expect(await services.sso.userIdentities(user.id)).toHaveLength(2);
    });

    it('counts no password the policy refuses (break-glass only, not listed)', async () => {
      const user = await createUser(ctx, { username: 'ids-policy' });
      const id = await link(conn, user.id, 'ids-policy-sub');
      await services.sso.updateSignInSettings(SYSTEM_ACTOR, {
        passwordSignIn: 'break_glass_only',
        breakGlassUserIds: [ctx.adminId],
      });
      try {
        await expect(
          services.sso.unlinkIdentity(SYSTEM_ACTOR, user.id, id, false),
        ).rejects.toMatchObject({ status: 409, code: 'LAST_SIGN_IN_METHOD' });
        expect(await services.sso.userIdentities(user.id)).toHaveLength(1);
      } finally {
        await services.sso.updateSignInSettings(SYSTEM_ACTOR, {
          passwordSignIn: 'everyone',
          breakGlassUserIds: [],
        });
      }
      // Under `everyone` the same password counts again.
      await services.sso.unlinkIdentity(SYSTEM_ACTOR, user.id, id, false);
      expect(await services.sso.userIdentities(user.id)).toEqual([]);
    });

    it('refuses a self-unlink of an identity SCIM linked (409 SCIM_MANAGED_IDENTITY); an admin may', async () => {
      const scimConn = (
        await services.sso.createConnection(SYSTEM_ACTOR, {
          ...enabledInput('Ids Scim Linked'),
          linkByEmail: true,
        })
      ).id;
      const user = await createUser(ctx, {
        username: 'ids-scimself',
        email: 'scimself@acme.example',
      });
      const { token } = await services.scim.createToken(SYSTEM_ACTOR, {
        connectionId: scimConn,
        name: 'Entra',
        expiresAt: null,
      });
      const created = await ctx.app.inject({
        method: 'POST',
        url: '/test/svc/scim/v2/Users',
        headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
        payload: {
          schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
          userName: 'scimself@acme.example',
          emails: [{ value: 'scimself@acme.example', primary: true }],
          active: true,
        },
      });
      expect(created.statusCode).toBe(201);
      const [identity] = await services.sso.userIdentities(user.id);
      expect(identity).toMatchObject({ connectionId: scimConn, scim: true });
      // The user has a password, so the last-method rule would not stop this: the SCIM rule does.
      await expect(
        services.sso.unlinkIdentity(SYSTEM_ACTOR, user.id, identity!.id, false),
      ).rejects.toMatchObject({ status: 409, code: 'SCIM_MANAGED_IDENTITY' });
      expect(await services.sso.userIdentities(user.id)).toEqual([identity]);
      await services.sso.unlinkIdentity(SYSTEM_ACTOR, user.id, identity!.id, true);
      expect(await services.sso.userIdentities(user.id)).toEqual([]);
    });

    it('answers 404 for an identity of another user, or an unknown one', async () => {
      const owner = await createUser(ctx, { username: 'ids-owner' });
      const stranger = await createUser(ctx, { username: 'ids-stranger' });
      const id = await link(conn, owner.id, 'ids-owner-sub');
      await expect(
        services.sso.unlinkIdentity(SYSTEM_ACTOR, stranger.id, id, true),
      ).rejects.toMatchObject({ status: 404 });
      await expect(
        services.sso.unlinkIdentity(SYSTEM_ACTOR, owner.id, 'nope', true),
      ).rejects.toMatchObject({ status: 404 });
      expect(await services.sso.userIdentities(owner.id)).toHaveLength(1);
    });

    it('removes the memberships SCIM group sync gave through the unlinked identity', async () => {
      const scimConn = (
        await services.sso.createConnection(SYSTEM_ACTOR, {
          ...oidcInput('Ids Scim'),
          groupSource: 'scim',
        })
      ).id;
      await services.sso.replaceMappings(SYSTEM_ACTOR, scimConn, [
        { group: 'devs', organizationId: defaultOrg, projectId: null, role: 'member' },
      ]);
      const user = await createUser(ctx, { username: 'ids-scim' });
      const id = await link(scimConn, user.id, 'ids-scim-sub');
      const [group] = await ctx.db
        .insert(scimGroups)
        .values({ connectionId: scimConn, displayName: 'devs' })
        .returning({ id: scimGroups.id });
      await ctx.db.insert(scimGroupMembers).values({ groupId: group!.id, identityId: id });
      await ctx.db.insert(memberships).values({
        organizationId: defaultOrg,
        userId: user.id,
        role: 'member',
        managedByConnectionId: scimConn,
      });
      await services.sso.unlinkIdentity(SYSTEM_ACTOR, user.id, id, true);
      const left = await ctx.db
        .select()
        .from(memberships)
        .where(and(eq(memberships.userId, user.id), eq(memberships.organizationId, defaultOrg)));
      expect(left).toEqual([]);
      expect(
        await ctx.db.select().from(scimGroupMembers).where(eq(scimGroupMembers.identityId, id)),
      ).toEqual([]);
    });
  });

  describe('testConnection', () => {
    it('runs discovery and reads the JWKS now, naming the endpoints', async () => {
      const conn = (await services.sso.createConnection(SYSTEM_ACTOR, oidcInput('Tested'))).id;
      expect(await services.sso.testConnection(conn)).toEqual({
        ok: true,
        problem: null,
        endpoints: {
          authorization: expect.stringContaining(op.issuer),
          token: `${op.issuer}/token`,
          jwks: expect.stringContaining(op.issuer),
          userinfo: expect.stringContaining(op.issuer),
        },
        certificates: null,
      });
    });

    it('fails with a fixed message when discovery names another issuer', async () => {
      const conn = (await services.sso.createConnection(SYSTEM_ACTOR, oidcInput('Mixed up'))).id;
      op.tweak({ issuerInDiscovery: `${op.issuer}/` });
      try {
        expect(await services.sso.testConnection(conn)).toEqual({
          ok: false,
          problem: {
            code: 'issuer_mismatch',
            message: 'The discovery document names another issuer',
          },
          endpoints: null,
          certificates: null,
        });
      } finally {
        op.tweak({ issuerInDiscovery: undefined });
      }
    });

    it('fails with the refusal when the issuer’s host is no longer listed', async () => {
      const conn = (await services.sso.createConnection(SYSTEM_ACTOR, oidcInput('Unlisted'))).id;
      const unlisted = build((f) => ctx.edition!.isFeatureActive(f), {
        ...ctx.config,
        ssoInternalHosts: new Set(),
      });
      expect(await unlisted.sso.testConnection(conn)).toEqual({
        ok: false,
        problem: {
          code: 'issuer_url',
          message:
            'The issuer URL: Use an https URL (http only for a host in QUALOR_SSO_INTERNAL_HOSTS)',
        },
        endpoints: null,
        certificates: null,
      });
    });

    it('names a refusal of ssoFetch with its fixed text, never sending the request', async () => {
      const conn = (await services.sso.createConnection(SYSTEM_ACTOR, oidcInput('Private'))).id;
      // Saved as https://idp.example (public by name); the name now resolves to a private address.
      await ctx.db
        .update(ssoConnections)
        .set({
          config: sql`jsonb_set(${ssoConnections.config}, '{issuer}', '"https://idp.example"')`,
        })
        .where(eq(ssoConnections.id, conn));
      const result = await testConnection(
        {
          db: ctx.db,
          config: ctx.config,
          audit: createAuditRecorder({ isActive: () => false, log: QUIET_AUDIT_LOG }),
          edition: ctx.edition!,
          resolve: async () => [{ address: '10.0.0.7', family: 4 }],
        },
        conn,
      );
      expect(result).toEqual({
        ok: false,
        problem: {
          code: 'fetch.not_public',
          message: 'The host is not public; list it in QUALOR_SSO_INTERNAL_HOSTS',
        },
        endpoints: null,
        certificates: null,
      });
    });

    it('shows a SAML connection’s certificates and whether its SSO URL is allowed', async () => {
      const conn = (
        await services.sso.createConnection(SYSTEM_ACTOR, {
          name: 'Saml tested',
          protocol: 'saml',
          saml: {
            idpEntityId: 'https://idp.test/saml',
            idpSsoUrl: 'https://idp.test/sso',
            idpCertificates: [TEST_IDP.certPem],
          },
        })
      ).id;
      expect(await services.sso.testConnection(conn)).toMatchObject({
        ok: true,
        problem: null,
        endpoints: null,
        certificates: [{ sha256: expect.stringMatching(/^[0-9A-F:]+$/), expired: false }],
      });
    });
  });

  describe('the browser flows', () => {
    it('redirects an unknown or disabled connection’s start to the login page', async () => {
      const disabled = (await services.sso.createConnection(SYSTEM_ACTOR, oidcInput('Off'))).id;
      for (const id of ['0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f', disabled]) {
        const res = await ctx.app.inject({ method: 'GET', url: `/test/svc/sso/${id}/start` });
        expect(res.statusCode).toBe(303);
        expect(res.headers.location).toBe('/login?sso_error=unavailable');
      }
    });

    it('starts an enabled OIDC connection at the IdP, with the binding cookie', async () => {
      const conn = (
        await services.sso.createConnection(SYSTEM_ACTOR, { ...oidcInput('On'), enabled: true })
      ).id;
      const res = await ctx.app.inject({
        method: 'GET',
        url: `/test/svc/sso/${conn}/start?returnTo=/projects`,
      });
      expect(res.statusCode).toBe(302);
      expect(res.headers.location).toMatch(new RegExp(`^${op.issuer}`));
      expect(res.cookies.map((c) => c.name)).toContain('qualor_sso');
    });

    it('starts a link from a browser session only (403 SESSION_REQUIRED with a token)', async () => {
      const conn = (
        await services.sso.createConnection(SYSTEM_ACTOR, { ...oidcInput('Link'), enabled: true })
      ).id;
      await createUser(ctx, { username: 'linker' });
      const ok = await ctx.app.inject({
        method: 'POST',
        url: `/test/svc/sso/${conn}/link`,
        headers: await sessionHeaders(ctx, 'linker'),
      });
      expect(ok.statusCode).toBe(200);
      expect((ok.json() as { url: string }).url).toMatch(new RegExp(`^${op.issuer}`));
      const token = await personalTokenFor(ctx, 'linker');
      const refused = await ctx.app.inject({
        method: 'POST',
        url: `/test/svc/sso/${conn}/link`,
        headers: { authorization: `Bearer ${token}` },
      });
      expect(refused.statusCode).toBe(403);
      expect(refused.json()).toMatchObject({ code: 'SESSION_REQUIRED' });
    });

    it('starts a link only on a connection in effect: 404 for one that is not (sso-scim.md §4.4)', async () => {
      // Both enabled under sso.multi; without it only the oldest, `first`, is in effect.
      const first = (
        await services.sso.createConnection(SYSTEM_ACTOR, { ...oidcInput('First'), enabled: true })
      ).id;
      const second = (
        await services.sso.createConnection(SYSTEM_ACTOR, { ...oidcInput('Second'), enabled: true })
      ).id;
      await createUser(ctx, { username: 'nie-linker' });
      const headers = await sessionHeaders(ctx, 'nie-linker');
      const refused = await ctx.app.inject({
        method: 'POST',
        url: `/test/business/sso/${second}/link`,
        headers,
      });
      expect(refused.statusCode).toBe(404);
      expect(refused.json()).toMatchObject({ code: 'NOT_FOUND' });
      expect(refused.cookies.map((c) => c.name)).not.toContain('qualor_sso');
      const start = await ctx.app.inject({
        method: 'GET',
        url: `/test/business/sso/${second}/start`,
      });
      expect(start.statusCode).toBe(303);
      expect(start.headers.location).toBe('/login?sso_error=unavailable');
      const ok = await ctx.app.inject({
        method: 'POST',
        url: `/test/business/sso/${first}/link`,
        headers,
      });
      expect(ok.statusCode).toBe(200);
      // With sso.multi, the second one links too.
      const multi = await ctx.app.inject({
        method: 'POST',
        url: `/test/svc/sso/${second}/link`,
        headers,
      });
      expect(multi.statusCode).toBe(200);
    });

    it('answers 503 SSO_UNAVAILABLE when the IdP’s discovery is down, logging fixed fields only', async () => {
      const conn = (
        await services.sso.createConnection(SYSTEM_ACTOR, { ...oidcInput('Down'), enabled: true })
      ).id;
      // The same (listed) host, a path where the fake OP has no discovery document: a 404.
      const issuer = `${op.issuer}/gone`;
      await ctx.db
        .update(ssoConnections)
        .set({
          config: sql`jsonb_set(${ssoConnections.config}, '{issuer}', ${JSON.stringify(issuer)}::jsonb)`,
        })
        .where(eq(ssoConnections.id, conn));
      await createUser(ctx, { username: 'down-linker' });
      const from = ctx.logs.length;
      const res = await ctx.app.inject({
        method: 'POST',
        url: `/test/svc/sso/${conn}/link`,
        headers: await sessionHeaders(ctx, 'down-linker'),
      });
      expect(res.statusCode).toBe(503);
      expect(res.headers['content-type']).toMatch(/^application\/problem\+json/);
      expect(res.json()).toMatchObject({ code: 'SSO_UNAVAILABLE' });
      expect(res.body).not.toContain(op.issuer);
      expect(res.cookies.map((c) => c.name)).not.toContain('qualor_sso');
      const lines = ctx.logs
        .slice(from)
        .map((l) => JSON.parse(l) as Record<string, unknown>)
        .filter((l) => l['msg'] === 'single sign-on linking could not start');
      expect(lines).toHaveLength(1);
      const { level, time, pid, hostname, msg, ...fields } = lines[0]!;
      expect([level, typeof time, msg]).toEqual([
        40,
        'number',
        'single sign-on linking could not start',
      ]);
      void pid;
      void hostname;
      expect(fields).toEqual({
        component: 'sso',
        connectionId: conn,
        reason: 'unavailable',
        detail: 'oidc.discovery',
      });
      expect(ctx.logs.slice(from).join('\n')).not.toContain('/gone');
    });
  });
});
