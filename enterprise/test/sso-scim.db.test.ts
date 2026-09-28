// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { fileURLToPath } from 'node:url';
import { eq, sql } from 'drizzle-orm';
import type { InjectOptions } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  createUser,
  login,
  organizationId,
  type TestContext,
  createTestContext,
} from '../../server/test/app';
import { testConfig } from '../../server/test/config';
import { createTestDatabase, type TestDatabase } from '../../server/test/db';
import {
  BUSINESS_FEATURES,
  ENTERPRISE_FEATURES,
  signTest,
  testPayload,
  testSigner,
  verifyWith,
  type TestSigner,
} from '../../server/test/license';
import { AFTER_GRACE, LICENSE_EXPIRES } from '../../server/test/rbac';
import { oidcConnection, samlConnection, SSO_PUBLIC_URL } from '../../server/test/sso';
import { buildApp } from '../../server/src/app';
import { bootstrap } from '../../server/src/auth/bootstrap';
import { createAuditRecorder } from '../../server/src/audit/recorder';
import { createSession, csrfTokenFor, SESSION_COOKIE } from '../../server/src/auth/sessions';
import { identities, users } from '../../server/src/db/schema';
import { createLogger } from '../../server/src/http/logger';
import { createEdition, type Edition } from '../../server/src/license/edition';
import { licenseState } from '../../server/src/license/state';
import { verifyLicenseKey } from '../../server/src/license/verify';
import { bootEnterprise } from '../../server/src/plugins/boot';
import { loadPlugins } from '../../server/src/plugins/loader';
import { dropPluginsThatFailToMount } from '../../server/src/plugins/mount';
import { createPluginServices } from '../../server/src/plugins/services';
import { buildEnterprise } from '../scripts/bundle';

// Under enterprise/, so the bundle resolves its external zod from enterprise/node_modules, as the
// image's /app/enterprise/plugin.js resolves it from /app/node_modules.
const OUT = fileURLToPath(new URL('../.tmp/sso-scim-test/plugin.js', import.meta.url));
/** Inside the throwaway test licence (issued 2026-10-01, expires 2027-10-01). */
const LICENSED = new Date('2027-01-01T00:00:00Z');
const FEATURES = ['sso', 'scim', 'audit-log'];
const USER_SCHEMA = 'urn:ietf:params:scim:schemas:core:2.0:User';
const SCIM_ERROR = 'urn:ietf:params:scim:api:messages:2.0:Error';
const SCIM_TYPE = 'application/scim+json; charset=utf-8';
const UNKNOWN = '00000000-0000-4000-8000-000000000000';

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

/**
 * The built plugin through the real loader, under a `test-` key listing the 4D features, with
 * the services bound as bootEnterprise binds them (the sso and scim ones included). The licence
 * and the recorder run on `clock`.
 */
async function bootSsoTest(clock: () => Date): Promise<TestContext> {
  const signer = testSigner();
  const verification = verifyLicenseKey(
    signTest(signer, testPayload({ features: FEATURES, expires: LICENSE_EXPIRES })),
    verifyWith(signer, clock()),
  );
  const boot = { source: 'environment' as const, keyHash: 'h', verification };
  return createTestContext({
    config: { publicUrl: SSO_PUBLIC_URL },
    pluginsFor: async (db, config, logger) => {
      let edition: Edition | undefined;
      const isFeatureActive = (f: string): boolean => edition?.isFeatureActive(f) ?? false;
      const audit = createAuditRecorder({
        isActive: () => isFeatureActive('audit-log'),
        now: clock,
        log: logger,
      });
      const services = createPluginServices({
        db,
        isFeatureActive,
        secretKey: config.secretKey,
        version: '0.0.0',
        recorder: audit,
        now: clock,
        config,
        edition: () => {
          if (!edition) throw new Error('the edition does not exist yet');
          return edition;
        },
        logger,
      });
      const plugins = await loadPlugins({
        paths: [OUT],
        state: licenseState(verification, clock()),
        base: { serverVersion: '0.0.0', db, logger: quietLogger(), services },
      });
      await dropPluginsThatFailToMount(plugins, quietLogger());
      return {
        plugins,
        edition: (frozen) => {
          edition = createEdition({ boot, plugins: frozen, now: clock });
          return edition;
        },
        audit,
      };
    },
  });
}

/** `SELECT count(*)` of each table. */
async function rowCounts(ctx: TestContext, tables: string[]): Promise<Record<string, number>> {
  const out: Record<string, number> = {};
  for (const table of tables) {
    const rows = await ctx.db.execute(sql`SELECT count(*)::int AS n FROM ${sql.identifier(table)}`);
    out[table] = (rows as unknown as { rows: { n: number }[] }).rows[0]!.n;
  }
  return out;
}

/** Session headers of a user inserted directly (with or without a password). */
async function sessionOf(ctx: TestContext, userId: string): Promise<Record<string, string>> {
  const { secret } = await createSession(ctx.db, {
    userId,
    ttlHours: 1,
    ip: null,
    userAgent: null,
  });
  return {
    cookie: `${SESSION_COOKIE}=${secret}`,
    'x-qualor-csrf': csrfTokenFor(ctx.config.secretKey, secret),
  };
}

beforeAll(async () => {
  await buildEnterprise({ outfile: OUT });
}, 60_000);

describe('the enterprise SSO and SCIM API (sso-scim.md §17)', () => {
  let now = LICENSED;
  let ctx: TestContext;
  let admin: Record<string, string>;
  let orgAdmin: Record<string, string>;
  let member: Record<string, string>;
  let disabledConn: string;
  let samlConn: string;
  let scimToken: string;

  beforeAll(async () => {
    ctx = await bootSsoTest(() => now);
    admin = (await login(ctx, 'admin', ADMIN_PASSWORD)).headers;
    const org = await organizationId(ctx, 'default');
    const oa = await createUser(ctx, { username: 'org-admin' });
    await addMember(ctx, org, oa.id, 'admin');
    orgAdmin = (await login(ctx, oa.username, oa.password)).headers;
    const m = await createUser(ctx, { username: 'member' });
    await addMember(ctx, org, m.id, 'member');
    member = (await login(ctx, m.username, m.password)).headers;
    disabledConn = await oidcConnection(ctx, { enabled: false });
    samlConn = await samlConnection(ctx, { enabled: true });
  }, 120_000);
  afterAll(async () => ctx?.close());

  const inject = (options: InjectOptions) => ctx.app.inject(options);

  it('loads with its six features and the four 4D settings entries', async () => {
    expect(ctx.edition!.plugins()).toEqual([
      {
        name: 'qualor-enterprise',
        state: 'loaded',
        features: ['llm.fix-quota', 'audit-log', 'audit-log.stream', 'sso', 'sso.multi', 'scim'],
        error: null,
      },
    ]);
    const info = (
      await inject({ method: 'GET', url: '/api/v0/system/info', headers: admin })
    ).json() as { extensions: { id: string }[] };
    expect(info.extensions.map((e) => e.id)).toEqual([
      'audit-log',
      'audit-settings',
      'sso',
      'sign-in',
      'linked-accounts',
      'scim',
    ]);
  });

  it('lets an instance admin create an OIDC connection and hides the secret', async () => {
    const res = await inject({
      method: 'POST',
      url: '/api/v0/ee/sso/connections',
      headers: admin,
      payload: {
        name: 'Acme',
        protocol: 'oidc',
        oidc: { issuer: 'https://idp.example', clientId: 'q', clientSecret: 'top-secret' },
      },
    });
    expect(res.statusCode).toBe(201);
    expect(res.body).not.toContain('top-secret');
    expect(res.json().oidc.clientSecretSet).toBe(true);
    const id = res.json().id as string;
    const read = await inject({
      method: 'GET',
      url: `/api/v0/ee/sso/connections/${id}`,
      headers: admin,
    });
    expect(read.statusCode).toBe(200);
    expect(read.body).not.toContain('top-secret');
    expect(read.json()).toMatchObject({ name: 'Acme', protocol: 'oidc', saml: null });
    const renamed = await inject({
      method: 'PATCH',
      url: `/api/v0/ee/sso/connections/${id}`,
      headers: admin,
      payload: { name: 'Acme Two', oidc: { clientSecret: 'other-secret' } },
    });
    expect(renamed.statusCode).toBe(200);
    expect(renamed.body).not.toContain('other-secret');
    expect(renamed.json().name).toBe('Acme Two');
    const list = await inject({ method: 'GET', url: '/api/v0/ee/sso/connections', headers: admin });
    expect(list.statusCode).toBe(200);
    expect((list.json() as { name: string }[]).map((c) => c.name)).toContain('Acme Two');
    const gone = await inject({
      method: 'DELETE',
      url: `/api/v0/ee/sso/connections/${id}`,
      headers: admin,
    });
    expect(gone.statusCode).toBe(204);
    expect(ctx.logs.join('\n')).not.toMatch(/top-secret|other-secret/);
  });

  it('refuses unknown body fields (422) and a JSON body of another type (415)', async () => {
    const extra = await inject({
      method: 'POST',
      url: '/api/v0/ee/sso/connections',
      headers: admin,
      payload: { name: 'X', protocol: 'oidc', oidc: { issuer: 'https://x.example' }, admin: true },
    });
    expect(extra.statusCode).toBe(422);
    const xml = await inject({
      method: 'PUT',
      url: '/api/v0/ee/sso/settings',
      headers: { ...admin, 'content-type': 'application/xml' },
      payload: '<settings/>',
    });
    expect(xml.statusCode).toBe(415);
    // text/plain is read as a string (Fastify's own parser, as on core routes): not an object.
    const text = await inject({
      method: 'PUT',
      url: '/api/v0/ee/sso/settings',
      headers: { ...admin, 'content-type': 'text/plain' },
      payload: 'passwordSignIn=everyone',
    });
    expect(text.statusCode).toBe(422);
  });

  it('refuses an org admin and a member (403) and an anonymous caller (401)', async () => {
    for (const headers of [orgAdmin, member]) {
      for (const url of [
        '/api/v0/ee/sso/connections',
        '/api/v0/ee/sso/settings',
        `/api/v0/ee/sso/users/${ctx.adminId}/identities`,
        '/api/v0/ee/scim/tokens',
      ]) {
        expect((await inject({ method: 'GET', url, headers })).statusCode, url).toBe(403);
      }
    }
    expect((await inject({ method: 'GET', url: '/api/v0/ee/sso/connections' })).statusCode).toBe(
      401,
    );
    expect((await inject({ method: 'GET', url: '/api/v0/ee/scim/tokens' })).statusCode).toBe(401);
    expect((await inject({ method: 'GET', url: '/api/v0/ee/sso/me/identities' })).statusCode).toBe(
      401,
    );
  });

  it('serves the sign-in settings, the mappings and a SAML test to an instance admin', async () => {
    const settings = await inject({
      method: 'GET',
      url: '/api/v0/ee/sso/settings',
      headers: admin,
    });
    expect(settings.statusCode).toBe(200);
    expect(settings.json()).toEqual({
      passwordSignIn: 'everyone',
      breakGlassUserIds: [],
      forced: false,
      breakGlass: [],
    });
    const saved = await inject({
      method: 'PUT',
      url: '/api/v0/ee/sso/settings',
      headers: admin,
      payload: { passwordSignIn: 'everyone', breakGlassUserIds: [ctx.adminId] },
    });
    expect(saved.statusCode).toBe(200);
    expect(saved.json().breakGlass).toEqual([
      { userId: ctx.adminId, username: 'admin', usable: true },
    ]);
    const org = await organizationId(ctx, 'default');
    const mappings = await inject({
      method: 'PUT',
      url: `/api/v0/ee/sso/connections/${samlConn}/mappings`,
      headers: admin,
      payload: [{ group: 'eng', organizationId: org, projectId: null, role: 'member' }],
    });
    expect(mappings.statusCode).toBe(200);
    expect(mappings.json()).toMatchObject([
      { group: 'eng', organizationId: org, organizationKey: 'default', projectId: null },
    ]);
    const listed = await inject({
      method: 'GET',
      url: `/api/v0/ee/sso/connections/${samlConn}/mappings`,
      headers: admin,
    });
    expect(listed.json()).toEqual(mappings.json());
    const test = await inject({
      method: 'POST',
      url: `/api/v0/ee/sso/connections/${samlConn}/test`,
      headers: admin,
    });
    expect(test.statusCode).toBe(200);
    expect(test.json()).toMatchObject({ ok: true, problem: null, endpoints: null });
    const unknown = await inject({
      method: 'GET',
      url: `/api/v0/ee/sso/connections/${UNKNOWN}`,
      headers: admin,
    });
    expect(unknown.statusCode).toBe(404);
  });

  it('serves the public flow routes without credentials', async () => {
    const start = await inject({ method: 'GET', url: `/api/v0/ee/sso/${disabledConn}/start` });
    expect(start.statusCode).toBe(303);
    expect(start.headers.location).toBe('/login?sso_error=unavailable');
    // A malformed id is an unknown connection, not a 422.
    const odd = await inject({ method: 'GET', url: '/api/v0/ee/sso/not-an-id/start' });
    expect([odd.statusCode, odd.headers.location]).toEqual([303, '/login?sso_error=unavailable']);
    const meta = await inject({
      method: 'GET',
      url: `/api/v0/ee/sso/saml/${samlConn}/metadata`,
    });
    expect(meta.statusCode).toBe(200);
    expect(meta.headers['content-type']).toMatch(/^application\/samlmetadata\+xml/);
    expect(meta.body).toMatch(/^<\?xml|<(md:)?EntityDescriptor/);
    const saml = await inject({ method: 'GET', url: `/api/v0/ee/sso/${samlConn}/start` });
    expect(saml.statusCode).toBe(302);
    expect(saml.headers.location).toMatch(/^https:\/\/idp\.test\/sso\?SAMLRequest=/);
    const finish = await inject({ method: 'GET', url: '/api/v0/ee/sso/finish?code=nothing' });
    expect(finish.statusCode).toBe(303);
    expect(finish.headers.location).toMatch(/^\/login\?sso_error=/);
  });

  it('never logs the query string of an SSO callback (§7.8)', async () => {
    const res = await inject({
      method: 'GET',
      url: `/api/v0/ee/sso/oidc/${disabledConn}/callback?code=code-4d-canary&state=state-4d-canary`,
    });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toMatch(/^\/login\?sso_error=/);
    expect(ctx.logs.join('\n')).toContain(`/api/v0/ee/sso/oidc/${disabledConn}/callback`);
    expect(ctx.logs.join('\n')).not.toMatch(/code-4d-canary|state-4d-canary/);
  });

  it('parses the ACS form with its own limits (415, 413)', async () => {
    expect(
      (
        await inject({
          method: 'POST',
          url: `/api/v0/ee/sso/saml/${samlConn}/acs`,
          headers: { 'content-type': 'application/json' },
          payload: '{}',
        })
      ).statusCode,
    ).toBe(415);
    expect(
      (
        await inject({
          method: 'POST',
          url: `/api/v0/ee/sso/saml/${samlConn}/acs`,
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          payload: 'SAMLResponse=' + 'A'.repeat(600_000),
        })
      ).statusCode,
    ).toBe(413);
    const junk = await inject({
      method: 'POST',
      url: `/api/v0/ee/sso/saml/${samlConn}/acs`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      payload: 'SAMLResponse=bm90IHhtbA&RelayState=x',
    });
    expect(junk.statusCode).toBe(303);
    expect(junk.headers.location).toMatch(/^\/login\?sso_error=/);
  });

  it('limits a start to 30 a minute per address, then redirects with rate_limited', async () => {
    const remoteAddress = '10.250.0.1';
    const start = () =>
      inject({ method: 'GET', url: `/api/v0/ee/sso/${disabledConn}/start`, remoteAddress });
    for (let i = 0; i < 30; i++) expect((await start()).headers.location).toContain('unavailable');
    const limited = await start();
    expect([limited.statusCode, limited.headers.location]).toEqual([
      303,
      '/login?sso_error=rate_limited',
    ]);
    // another address is not affected
    const other = await inject({
      method: 'GET',
      url: `/api/v0/ee/sso/${disabledConn}/start`,
      remoteAddress: '10.250.0.2',
    });
    expect(other.headers.location).toBe('/login?sso_error=unavailable');
  });

  it('limits the ACS and the finish step to 60 a minute per address', async () => {
    for (const [method, url] of [
      ['POST', `/api/v0/ee/sso/saml/${samlConn}/acs`],
      ['GET', '/api/v0/ee/sso/finish?code=x'],
    ] as const) {
      const remoteAddress = method === 'POST' ? '10.250.1.1' : '10.250.1.2';
      const call = () =>
        inject({
          method,
          url,
          remoteAddress,
          ...(method === 'POST'
            ? {
                headers: { 'content-type': 'application/x-www-form-urlencoded' },
                payload: 'SAMLResponse=eA',
              }
            : {}),
        });
      for (let i = 0; i < 60; i++) expect((await call()).statusCode, url).toBe(303);
      expect((await call()).headers.location, url).toBe('/login?sso_error=rate_limited');
    }
  });

  it('limits the OIDC callback to 60 a minute per address; an unknown connection records nothing', async () => {
    const failures = async () => {
      const rows = await ctx.db.execute(
        sql`SELECT count(*)::int AS n FROM audit_events WHERE action = 'sso.sign_in_failed'`,
      );
      return (rows as unknown as { rows: { n: number }[] }).rows[0]!.n;
    };
    const before = await failures();
    const remoteAddress = '10.250.2.1';
    const call = () =>
      inject({ method: 'GET', url: `/api/v0/ee/sso/oidc/${UNKNOWN}/callback`, remoteAddress });
    for (let i = 0; i < 60; i++) {
      expect((await call()).headers.location).toBe('/login?sso_error=flow_expired');
    }
    const limited = await call();
    expect([limited.statusCode, limited.headers.location]).toEqual([
      303,
      '/login?sso_error=rate_limited',
    ]);
    // No audit row for a connection that does not exist.
    expect(await failures()).toBe(before);
    // A connection that exists (disabled) is recorded.
    await inject({
      method: 'GET',
      url: `/api/v0/ee/sso/oidc/${disabledConn}/callback`,
      remoteAddress: '10.250.2.2',
    });
    expect(await failures()).toBe(before + 1);
  });

  it('limits linking to 10 a minute per user, and needs a browser session', async () => {
    const u = await createUser(ctx, { username: 'linker' });
    const headers = (await login(ctx, u.username, u.password)).headers;
    const link = (h: Record<string, string>) =>
      inject({ method: 'POST', url: `/api/v0/ee/sso/connections/${UNKNOWN}/link`, headers: h });
    for (let i = 0; i < 10; i++) expect((await link(headers)).statusCode).toBe(404);
    const limited = await link(headers);
    expect([limited.statusCode, limited.json().code]).toEqual([429, 'RATE_LIMITED']);
    // per user: another user is not affected
    expect((await link(member)).statusCode).toBe(404);
  });

  it('answers SCIM as SCIM, with application/scim+json bodies accepted', async () => {
    const created = await inject({
      method: 'POST',
      url: '/api/v0/ee/scim/tokens',
      headers: admin,
      payload: { connectionId: samlConn, name: 'Okta' },
    });
    expect(created.statusCode).toBe(201);
    scimToken = created.json().token as string;
    expect(scimToken).toMatch(/^qlr_scim_/);
    expect(created.json()).toMatchObject({ connectionId: samlConn, name: 'Okta', revokedAt: null });
    const res = await inject({
      method: 'POST',
      url: '/api/v0/ee/scim/v2/Users',
      headers: { authorization: `Bearer ${scimToken}`, 'content-type': 'application/scim+json' },
      payload: JSON.stringify({ schemas: [USER_SCHEMA], userName: 'x@acme.example' }),
    });
    expect(res.statusCode).toBe(201);
    expect(res.headers['content-type']).toBe(SCIM_TYPE);
    const listed = await inject({
      method: 'GET',
      url: `/api/v0/ee/scim/tokens?connectionId=${samlConn}`,
      headers: admin,
    });
    expect(listed.statusCode).toBe(200);
    expect(listed.body).not.toContain(scimToken);
    expect((listed.json() as { name: string }[]).map((t) => t.name)).toEqual(['Okta']);
    expect(ctx.logs.join('\n')).not.toContain(scimToken);
  });

  it('accepts application/json, an empty DELETE body, and answers body errors in SCIM', async () => {
    const scim = (
      method: 'POST' | 'DELETE',
      url: string,
      contentType: string | null,
      payload?: string,
    ) =>
      inject({
        method,
        url: `/api/v0/ee/scim/v2${url}`,
        headers: {
          authorization: `Bearer ${scimToken}`,
          ...(contentType === null ? {} : { 'content-type': contentType }),
        },
        ...(payload === undefined ? {} : { payload }),
      });
    const json = await scim(
      'POST',
      '/Users',
      'application/json',
      JSON.stringify({ schemas: [USER_SCHEMA], userName: 'y@acme.example' }),
    );
    expect(json.statusCode).toBe(201);
    const id = json.json().id as string;
    // Entra and Okta send a DELETE with a JSON content type and no body.
    const deleted = await scim('DELETE', `/Users/${id}`, 'application/scim+json', '');
    expect(deleted.statusCode).toBe(204);

    const refusals = [
      [await scim('POST', '/Users', 'text/plain', '{}'), 415, undefined],
      [await scim('POST', '/Users', 'application/scim+json', '{"schemas":'), 400, 'invalidSyntax'],
      [
        await scim('POST', '/Users', 'application/scim+json', '{"__proto__":{"admin":true}}'),
        400,
        'invalidSyntax',
      ],
      [
        await scim(
          'POST',
          '/Users',
          'application/scim+json',
          JSON.stringify({ schemas: [USER_SCHEMA], userName: 'z'.repeat(1_100_000) }),
        ),
        413,
        undefined,
      ],
    ] as const;
    for (const [res, status, scimType] of refusals) {
      expect(res.statusCode).toBe(status);
      expect(res.headers['content-type']).toBe(SCIM_TYPE);
      expect(res.json()).toMatchObject({ schemas: [SCIM_ERROR], status: String(status) });
      expect(res.json().scimType).toBe(scimType);
    }
    const anonymous = await inject({ method: 'GET', url: '/api/v0/ee/scim/v2/Users' });
    expect(anonymous.statusCode).toBe(401);
    expect(anonymous.headers['content-type']).toBe(SCIM_TYPE);
  });

  it('refuses a user unlinking their last sign-in method (409)', async () => {
    const [u] = await ctx.db
      .insert(users)
      .values({ username: 'only-sso', passwordHash: null })
      .returning();
    const [identity] = await ctx.db
      .insert(identities)
      .values({ connectionId: samlConn, userId: u!.id, subject: 'only-sso-sub', linkedBy: 'jit' })
      .returning();
    const headers = await sessionOf(ctx, u!.id);
    const mine = await inject({ method: 'GET', url: '/api/v0/ee/sso/me/identities', headers });
    expect(mine.statusCode).toBe(200);
    expect(mine.json()).toMatchObject([{ id: identity!.id, connectionId: samlConn, scim: false }]);
    expect(mine.body).not.toContain('only-sso-sub');
    const res = await inject({
      method: 'DELETE',
      url: `/api/v0/ee/sso/me/identities/${identity!.id}`,
      headers,
    });
    expect(res.statusCode).toBe(409);
    expect(res.json().code).toBe('LAST_SIGN_IN_METHOD');
  });

  it('refuses a user unlinking a SCIM identity (409 SCIM_MANAGED_IDENTITY); an admin may', async () => {
    const created = await inject({
      method: 'POST',
      url: '/api/v0/ee/scim/v2/Users',
      headers: { authorization: `Bearer ${scimToken}`, 'content-type': 'application/scim+json' },
      payload: JSON.stringify({ schemas: [USER_SCHEMA], userName: 'scim-person@acme.example' }),
    });
    const identityId = created.json().id as string;
    const [row] = await ctx.db
      .select({ userId: identities.userId })
      .from(identities)
      .where(eq(identities.id, identityId));
    const userId = row!.userId;
    await ctx.db.update(users).set({ passwordHash: 'x' }).where(eq(users.id, userId));
    const own = await inject({
      method: 'DELETE',
      url: `/api/v0/ee/sso/me/identities/${identityId}`,
      headers: await sessionOf(ctx, userId),
    });
    expect([own.statusCode, own.json().code]).toEqual([409, 'SCIM_MANAGED_IDENTITY']);
    const listed = await inject({
      method: 'GET',
      url: `/api/v0/ee/sso/users/${userId}/identities`,
      headers: admin,
    });
    expect(listed.json()).toMatchObject([{ id: identityId, scim: true }]);
    const byAdmin = await inject({
      method: 'DELETE',
      url: `/api/v0/ee/sso/users/${userId}/identities/${identityId}`,
      headers: admin,
    });
    expect(byAdmin.statusCode).toBe(204);
  });

  it('revokes a SCIM token (204), after which the token is refused (401)', async () => {
    const created = await inject({
      method: 'POST',
      url: '/api/v0/ee/scim/tokens',
      headers: admin,
      payload: { connectionId: samlConn, name: 'Entra', expiresAt: '2030-01-01T00:00:00Z' },
    });
    expect(created.statusCode).toBe(201);
    const { id, token } = created.json() as { id: string; token: string };
    const revoked = await inject({
      method: 'DELETE',
      url: `/api/v0/ee/scim/tokens/${id}`,
      headers: admin,
    });
    expect(revoked.statusCode).toBe(204);
    const refused = await inject({
      method: 'GET',
      url: '/api/v0/ee/scim/v2/Users',
      headers: { authorization: `Bearer ${token}` },
    });
    expect(refused.statusCode).toBe(401);
  });

  it('after the lapse: every /ee/sso and /ee/scim route is 403, and no row changed', async () => {
    const before = await rowCounts(ctx, [
      'sso_connections',
      'identities',
      'scim_tokens',
      'scim_groups',
      'sso_group_mappings',
      'memberships',
    ]);
    now = AFTER_GRACE;
    for (const [method, url] of [
      ['GET', '/api/v0/ee/sso/connections'],
      ['GET', `/api/v0/ee/sso/${samlConn}/start`],
      ['GET', `/api/v0/ee/sso/oidc/${disabledConn}/callback?code=x&state=y`],
      ['POST', `/api/v0/ee/sso/saml/${samlConn}/acs`],
      ['GET', '/api/v0/ee/sso/finish?code=x'],
      ['GET', `/api/v0/ee/sso/saml/${samlConn}/metadata`],
      ['GET', '/api/v0/ee/sso/me/identities'],
      ['GET', '/api/v0/ee/scim/v2/Users'],
      ['DELETE', `/api/v0/ee/scim/v2/Users/${UNKNOWN}`],
      ['GET', '/api/v0/ee/scim/tokens'],
    ] as const) {
      const res = await inject({ method, url, headers: admin });
      expect([url, res.statusCode, res.json().code]).toEqual([url, 403, 'FEATURE_NOT_LICENSED']);
      expect(res.headers['content-type']).toMatch(/^application\/problem\+json/);
    }
    expect(await rowCounts(ctx, Object.keys(before))).toEqual(before);
  });
});

/** A server on `database`, booted as main.ts boots it: bootEnterprise reads a real signed key. */
async function bootOn(
  database: TestDatabase,
  signer: TestSigner,
  features: readonly string[],
): Promise<TestContext> {
  const key = signTest(signer, testPayload({ features: [...features], expires: LICENSE_EXPIRES }));
  const config = testConfig({
    databaseUrl: database.url,
    license: { text: key, file: null },
    pluginPaths: [OUT],
    publicUrl: SSO_PUBLIC_URL,
  });
  const logs: string[] = [];
  const logger = createLogger('info', { write: (line: string) => void logs.push(line) });
  const booted = await bootEnterprise({
    config,
    db: database.db,
    logger,
    serverVersion: '0.0.0',
    verifyOptions: (at) => verifyWith(signer, at),
    now: () => LICENSED,
  });
  const app = await buildApp({
    config,
    db: database.db,
    logger,
    edition: booted.edition,
    plugins: booted.plugins,
    audit: booted.audit,
    checkReady: async () => true,
  });
  await app.ready();
  const [admin] = await database.db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.username, 'admin'));
  return {
    app,
    db: database.db,
    database,
    config,
    logs,
    adminId: admin!.id,
    plugins: booted.plugins,
    edition: booted.edition,
    // The database outlives the app: the next boot uses it.
    close: () => app.close(),
  };
}

describe('sso.multi: one connection in effect without it (sso-scim.md §4.4)', () => {
  const MULTI_DETAIL =
    'Your plan allows one enabled single sign-on connection. Disable the enabled one first, or keep this one disabled; several enabled connections need the Enterprise plan.';
  const signer = testSigner();
  let database: TestDatabase;
  let ctx: TestContext | undefined;
  let admin: Record<string, string>;

  const boot = async (features: readonly string[]) => {
    await ctx?.close();
    ctx = await bootOn(database, signer, features);
    admin = (await login(ctx, 'admin', ADMIN_PASSWORD)).headers;
    return ctx;
  };
  const call = (method: 'GET' | 'POST' | 'PUT' | 'PATCH', url: string, payload?: unknown) =>
    ctx!.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: admin,
      ...(payload === undefined ? {} : { payload: payload as never }),
    });
  const create = async (name: string, enabled?: boolean) =>
    call('POST', '/ee/sso/connections', {
      name,
      protocol: 'oidc',
      ...(enabled === undefined ? {} : { enabled }),
      oidc: { issuer: `https://${name.toLowerCase()}.example`, clientId: 'q', clientSecret: 's' },
    });
  const inEffect = async () =>
    Object.fromEntries(
      (
        (await call('GET', '/ee/sso/connections')).json() as { name: string; inEffect: boolean }[]
      ).map((c) => [c.name, c.inEffect]),
    );
  const providers = async () =>
    (
      (await call('GET', '/auth/methods')).json() as { providers: { name: string }[] }
    ).providers.map((p) => p.name);
  const TABLES = ['sso_connections', 'identities', 'scim_tokens', 'sso_group_mappings'];
  const enabledFlags = async () =>
    (await ctx!.db.execute(sql`SELECT name, enabled FROM sso_connections ORDER BY name`)).rows;

  beforeAll(async () => {
    database = await createTestDatabase();
    await bootstrap(database.db, { username: 'admin', password: ADMIN_PASSWORD });
  });
  afterAll(async () => {
    await ctx?.close();
    await database?.close();
  });

  it('keeps everything across Enterprise → Business → Enterprise; a Business admin switches provider', async () => {
    // Enterprise: three enabled connections, each in effect, with a mapping and a SCIM token.
    await boot(ENTERPRISE_FEATURES);
    const ids: Record<string, string> = {};
    for (const name of ['Oldest', 'Middle', 'Newest']) {
      const res = await create(name, true);
      expect(res.statusCode, res.body).toBe(201);
      expect(res.json()).toMatchObject({ enabled: true, inEffect: true });
      ids[name] = res.json().id as string;
    }
    const org = await organizationId(ctx!, 'default');
    for (const id of Object.values(ids)) {
      const mapped = await call('PUT', `/ee/sso/connections/${id}/mappings`, [
        { group: `g-${id}`, organizationId: org, projectId: null, role: 'member' },
      ]);
      expect(mapped.statusCode, mapped.body).toBe(200);
      const token = await call('POST', '/ee/scim/tokens', { connectionId: id, name: `t-${id}` });
      expect(token.statusCode, token.body).toBe(201);
    }
    await ctx!.db.insert(identities).values({
      connectionId: ids['Middle']!,
      userId: ctx!.adminId,
      subject: 'sub-admin',
      linkedBy: 'user',
    });
    expect(await inEffect()).toEqual({ Oldest: true, Middle: true, Newest: true });
    expect(await providers()).toEqual(['Middle', 'Newest', 'Oldest']);
    const counts = await rowCounts(ctx!, TABLES);
    const flags = await enabledFlags();

    // Business: nothing written; only the oldest enabled connection is in effect.
    await boot(BUSINESS_FEATURES);
    expect(ctx!.edition!.activeFeatures()).toEqual(['audit-log', 'llm.fix-quota', 'sso']);
    expect(await rowCounts(ctx!, TABLES)).toEqual(counts);
    expect(await enabledFlags()).toEqual(flags);
    expect(await inEffect()).toEqual({ Oldest: true, Middle: false, Newest: false });
    expect(await providers()).toEqual(['Oldest']);
    const single = await call('GET', `/ee/sso/connections/${ids['Middle']!}`);
    expect(single.json()).toMatchObject({ enabled: true, inEffect: false });
    const start = await ctx!.app.inject({
      method: 'GET',
      url: `/api/v0/ee/sso/${ids['Middle']!}/start`,
    });
    expect(start.statusCode).toBe(303);
    expect(start.headers.location).toBe('/login?sso_error=unavailable');

    // Review Focus 4: a new connection is prepared disabled; enabling it is 409 and saves nothing.
    const refused = await create('Replacement', true);
    expect(refused.statusCode).toBe(409);
    expect(refused.json()).toMatchObject({ code: 'SSO_MULTI_NOT_LICENSED', title: MULTI_DETAIL });
    expect(await rowCounts(ctx!, ['sso_connections'])).toEqual({
      sso_connections: counts['sso_connections'],
    });
    const prepared = await create('Replacement');
    expect(prepared.statusCode).toBe(201);
    expect(prepared.json()).toMatchObject({ enabled: false, inEffect: false });
    const replacement = prepared.json().id as string;
    const enable = await call('PATCH', `/ee/sso/connections/${replacement}`, {
      enabled: true,
      name: 'Renamed',
    });
    expect(enable.statusCode).toBe(409);
    expect(enable.json().code).toBe('SSO_MULTI_NOT_LICENSED');
    expect((await call('GET', `/ee/sso/connections/${replacement}`)).json()).toMatchObject({
      name: 'Replacement',
      enabled: false,
    });

    // Switch: disabling the one in effect hands over to the next oldest enabled one.
    const off = await call('PATCH', `/ee/sso/connections/${ids['Oldest']!}`, { enabled: false });
    expect(off.statusCode).toBe(200);
    expect(await providers()).toEqual(['Middle']);
    expect(await inEffect()).toMatchObject({ Oldest: false, Middle: true, Newest: false });

    // Enterprise again: every enabled connection is in effect at once, nothing lost.
    await boot(ENTERPRISE_FEATURES);
    expect(await inEffect()).toEqual({
      Oldest: false,
      Middle: true,
      Newest: true,
      Replacement: false,
    });
    expect(await providers()).toEqual(['Middle', 'Newest']);
    expect(await rowCounts(ctx!, ['identities', 'scim_tokens', 'sso_group_mappings'])).toEqual({
      identities: counts['identities'],
      scim_tokens: counts['scim_tokens'],
      sso_group_mappings: counts['sso_group_mappings'],
    });
    const again = await call('PATCH', `/ee/sso/connections/${replacement}`, { enabled: true });
    expect(again.statusCode).toBe(200);
    expect(again.json()).toMatchObject({ enabled: true, inEffect: true });
  });
});
