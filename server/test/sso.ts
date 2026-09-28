import { inflateRawSync } from 'node:zlib';
import cookie from '@fastify/cookie';
import { and, asc, count, eq, isNull } from 'drizzle-orm';
import Fastify, { type FastifyInstance, type LightMyRequestResponse } from 'fastify';
import { createAuditRecorder, SYSTEM_ACTOR } from '../src/audit/recorder';
import { generateToken } from '../src/auth/tokens';
import { createSession, csrfTokenFor, SESSION_COOKIE } from '../src/auth/sessions';
import type { Config } from '../src/config';
import {
  apiTokens,
  auditEvents,
  identities,
  memberships,
  organizations,
  sessions,
  users,
} from '../src/db/schema';
import { createEdition, NO_PLUGINS, type Edition } from '../src/license/edition';
import { verifyLicenseKey } from '../src/license/verify';
import { handleScim, type ScimDeps } from '../src/scim/handle';
import type { FlowDeps } from '../src/sso/complete';
import type { NAME_ID_FORMATS } from '../src/sso/connection-config';
import {
  createConnection,
  type ConnectionDeps,
  type SsoClaimsInput,
  loadConnection,
  type SsoConnectionInput,
} from '../src/sso/connections';
import { oidcCallback, startOidc } from '../src/sso/oidc';
import { finishSaml, registerSamlFormParser, samlAcs, startSaml } from '../src/sso/saml';
import { ADMIN_PASSWORD, createTestContext, login, type TestContext } from './app';
import { QUIET_AUDIT_LOG } from './audit-log';
import type { FakeOp } from './fake-oidc';
import { signTest, testPayload, testSigner, verifyWith } from './license';
import { RBAC_FIXTURE, rbacPlugins } from './rbac';
import { TEST_IDP } from './saml';
import { flowDeps } from './sso-flow';

/** The 4D features and `sso.multi` (5D), so several connections can be enabled and in effect. */
export const SSO_FEATURES = ['sso', 'sso.multi', 'scim', 'audit-log'];
/** The 4D features without `sso.multi` (5D): one connection in effect (sso-scim.md §4.4). */
export const ONE_CONNECTION_FEATURES = ['sso', 'scim', 'audit-log'];
export const SSO_PUBLIC_URL = 'https://q.example';
/**
 * The licence clock ssoContext runs on unless a test passes `now`: inside the throwaway test
 * licence (issued 2026-10-01, expires 2027-10-01) whatever the real date, so the features are
 * active today and stay active once the real clock passes the licence's expiry.
 */
export const SSO_LICENSED_NOW = new Date('2027-01-01T00:00:00Z');

/**
 * A licensed test server for plan 4D: the rbac fixture plugin (as `sso-fixture`) under a licence
 * listing `features` (default sso, scim, audit-log), `QUALOR_PUBLIC_URL` https://q.example.
 * The licence runs on `now` (default SSO_LICENSED_NOW); the audit recorder and the database on the
 * real clock.
 */
export async function ssoContext(
  options: {
    features?: string[];
    now?: () => Date;
    config?: Partial<Config>;
    /** Runs before the app is ready (a test's own routes). */
    beforeReady?: (app: FastifyInstance) => void;
  } = {},
): Promise<TestContext> {
  const features = options.features ?? SSO_FEATURES;
  return createTestContext({
    config: { publicUrl: SSO_PUBLIC_URL, ...options.config },
    pluginsFor: rbacPlugins({
      features,
      now: options.now ?? (() => SSO_LICENSED_NOW),
      plugin: { ...RBAC_FIXTURE, name: 'sso-fixture', features },
    }),
    ...(options.beforeReady ? { beforeReady: options.beforeReady } : {}),
  });
}

/**
 * An edition from a real signed `test-` key listing `features`, with a plugin implementing them,
 * on the clock `now` (default SSO_LICENSED_NOW): for calling core's functions directly under a
 * licence other than the context's (a Business key after an Enterprise one, on one database).
 */
export function licensedEdition(
  features: readonly string[],
  now: () => Date = () => SSO_LICENSED_NOW,
): Edition {
  const signer = testSigner();
  const verification = verifyLicenseKey(
    signTest(signer, testPayload({ features: [...features] })),
    verifyWith(signer, now()),
  );
  return createEdition({
    boot: { source: 'environment', keyHash: 'h', verification },
    plugins: { ...NO_PLUGINS, features: new Set(features) },
    now,
    verifyOptions: (at) => verifyWith(signer, at),
  });
}

/**
 * What createConnection needs, recording while the context's `audit-log` is active, under the
 * context's edition (or `edition`).
 */
export function connectionDeps(ctx: TestContext, edition?: Edition): ConnectionDeps {
  const active = edition ?? ctx.edition;
  if (!active) throw new Error('connectionDeps needs a context with an edition (ssoContext)');
  return {
    edition: active,
    db: ctx.db,
    config: {
      secretKey: ctx.config.secretKey,
      publicUrl: ctx.config.publicUrl,
      ssoInternalHosts: ctx.config.ssoInternalHosts,
    },
    audit: createAuditRecorder({
      isActive: () => ctx.edition?.isFeatureActive('audit-log') ?? false,
      log: QUIET_AUDIT_LOG,
    }),
  };
}

interface CommonOverrides {
  /** Create under this edition instead of the context's (an Enterprise key's, say). */
  edition?: Edition;
  name?: string;
  enabled?: boolean;
  jit?: boolean;
  linkByEmail?: boolean;
  groupSource?: 'none' | 'claims' | 'scim';
  requiredClaims?: { claim: string; value: string }[];
  claims?: SsoClaimsInput;
}

export interface OidcConnectionOverrides extends CommonOverrides {
  issuer?: string;
  clientId?: string;
  clientSecret?: string;
}

export interface SamlConnectionOverrides extends CommonOverrides {
  idpEntityId?: string;
  idpSsoUrl?: string;
  idpCertificates?: string[];
  emailVerified?: boolean;
  nameIdFormat?: (typeof NAME_ID_FORMATS)[number];
}

let counter = 0;

/** The common fields; `claims.groups` is `groups` (the fake OP's, the builder's, Keycloak's). */
function common(o: CommonOverrides): Omit<SsoConnectionInput, 'protocol'> {
  counter += 1;
  const claims = o.claims ?? (o.groupSource === 'claims' ? { groups: 'groups' } : undefined);
  return {
    name: o.name ?? `Acme ${counter}`,
    enabled: o.enabled ?? false,
    ...(o.jit === undefined ? {} : { jit: o.jit }),
    ...(o.linkByEmail === undefined ? {} : { linkByEmail: o.linkByEmail }),
    ...(o.groupSource === undefined ? {} : { groupSource: o.groupSource }),
    ...(o.requiredClaims === undefined ? {} : { requiredClaims: o.requiredClaims }),
    ...(claims === undefined ? {} : { claims }),
  };
}

/** An OIDC connection inserted through createConnection; its id. */
export async function oidcConnection(
  ctx: TestContext,
  overrides: OidcConnectionOverrides = {},
): Promise<string> {
  const view = await createConnection(connectionDeps(ctx, overrides.edition), SYSTEM_ACTOR, {
    ...common(overrides),
    protocol: 'oidc',
    oidc: {
      issuer: overrides.issuer ?? 'https://idp.example/realms/acme',
      clientId: overrides.clientId ?? 'qualor',
      clientSecret: overrides.clientSecret ?? 's3cret',
    },
  });
  return view.id;
}

/** A SAML connection inserted through createConnection, trusting TEST_IDP by default; its id. */
export async function samlConnection(
  ctx: TestContext,
  overrides: SamlConnectionOverrides = {},
): Promise<string> {
  const view = await createConnection(connectionDeps(ctx, overrides.edition), SYSTEM_ACTOR, {
    ...common(overrides),
    protocol: 'saml',
    saml: {
      idpEntityId: overrides.idpEntityId ?? 'https://idp.test/saml',
      idpSsoUrl: overrides.idpSsoUrl ?? 'https://idp.test/sso',
      idpCertificates: overrides.idpCertificates ?? [TEST_IDP.certPem],
      ...(overrides.emailVerified === undefined ? {} : { emailVerified: overrides.emailVerified }),
      ...(overrides.nameIdFormat === undefined ? {} : { nameIdFormat: overrides.nameIdFormat }),
    },
  });
  return view.id;
}

/** Every audit event, oldest first. */
export async function auditRows(ctx: TestContext) {
  return ctx.db.select().from(auditEvents).orderBy(asc(auditEvents.seq));
}

/** The bootstrap admin's session headers (`cookie`, `x-qualor-csrf`). */
export async function adminHeaders(ctx: TestContext): Promise<Record<string, string>> {
  return (await login(ctx, 'admin', ADMIN_PASSWORD)).headers;
}

async function userIdOf(ctx: TestContext, username: string): Promise<string> {
  const [user] = await ctx.db
    .select({ id: users.id })
    .from(users)
    .where(eq(users.username, username));
  if (!user) throw new Error(`no user ${username}`);
  return user.id;
}

/**
 * Session headers (`cookie`, `x-qualor-csrf`) for `username`, from a session inserted directly: a
 * password sign-in would be refused while the policy is `break_glass_only`.
 */
export async function sessionHeaders(
  ctx: TestContext,
  username: string,
): Promise<Record<string, string>> {
  const session = await createSession(ctx.db, {
    userId: await userIdOf(ctx, username),
    ttlHours: 1,
    ip: null,
    userAgent: null,
  });
  return {
    cookie: `${SESSION_COOKIE}=${session.secret}`,
    'x-qualor-csrf': csrfTokenFor(ctx.config.secretKey, session.secret),
  };
}

/** A personal token (scope `read`) of `username`, inserted directly; its plaintext. */
export async function personalTokenFor(ctx: TestContext, username: string): Promise<string> {
  const userId = await userIdOf(ctx, username);
  const generated = generateToken('personal');
  await ctx.db.insert(apiTokens).values({
    kind: 'personal',
    userId,
    name: 'test',
    prefix: generated.prefix,
    secretHash: generated.secretHash,
    scopes: ['read'],
    createdBy: userId,
  });
  return generated.token;
}

// ─── SCIM (Task 17) ─────────────────────────────────────────────────────────

/** What handleScim needs, against the context's database, edition and audit state. */
export function scimDeps(ctx: TestContext): ScimDeps {
  const edition = ctx.edition;
  if (!edition) throw new Error('scimDeps needs a licensed context (ssoContext)');
  return {
    db: ctx.db,
    secretKey: ctx.config.secretKey,
    config: {
      publicUrl: ctx.config.publicUrl,
      forcePasswordSignIn: ctx.config.forcePasswordSignIn,
    },
    edition,
    audit: createAuditRecorder({
      isActive: () => edition.isFeatureActive('audit-log'),
      log: QUIET_AUDIT_LOG,
    }),
    log: ctx.app.log,
  };
}

/** The user behind a SCIM User id (an identity id). */
export async function userIdOfIdentity(ctx: TestContext, identityId: string): Promise<string> {
  const [row] = await ctx.db
    .select({ userId: identities.userId })
    .from(identities)
    .where(eq(identities.id, identityId));
  if (!row) throw new Error(`no identity ${identityId}`);
  return row.userId;
}

/** A personal token of the user, inserted directly; its plaintext. */
export async function givePersonalToken(ctx: TestContext, userId: string): Promise<string> {
  const generated = generateToken('personal');
  await ctx.db.insert(apiTokens).values({
    kind: 'personal',
    userId,
    name: 'scim-test',
    prefix: generated.prefix,
    secretHash: generated.secretHash,
    scopes: ['read'],
    createdBy: userId,
  });
  return generated.token;
}

/** A session of the user; its secret. */
export async function giveSession(ctx: TestContext, userId: string): Promise<string> {
  return (await createSession(ctx.db, { userId, ttlHours: 1, ip: null, userAgent: null })).secret;
}

export async function activeSessions(ctx: TestContext, userId: string): Promise<number> {
  const [row] = await ctx.db
    .select({ n: count() })
    .from(sessions)
    .where(eq(sessions.userId, userId));
  return row?.n ?? 0;
}

/** Personal tokens of the user that are not revoked. */
export async function liveTokens(ctx: TestContext, userId: string): Promise<number> {
  const [row] = await ctx.db
    .select({ n: count() })
    .from(apiTokens)
    .where(and(eq(apiTokens.userId, userId), isNull(apiTokens.revokedAt)));
  return row?.n ?? 0;
}

/** The user's role in the `default` organisation, or null. */
export async function orgRoleOf(ctx: TestContext, userId: string): Promise<string | null> {
  const [row] = await ctx.db
    .select({ role: memberships.role })
    .from(memberships)
    .innerJoin(organizations, eq(organizations.id, memberships.organizationId))
    .where(and(eq(organizations.key, 'default'), eq(memberships.userId, userId)));
  return row?.role ?? null;
}

export async function userActive(ctx: TestContext, userId: string): Promise<boolean> {
  const [row] = await ctx.db
    .select({ active: users.active })
    .from(users)
    .where(eq(users.id, userId));
  if (!row) throw new Error(`no user ${userId}`);
  return row.active;
}

/** A SCIM record on `connectionId` for an existing user (the bootstrap admin by default); its id. */
export async function linkScimIdentityToAdmin(
  ctx: TestContext,
  connectionId: string,
  userId = ctx.adminId,
): Promise<string> {
  const [row] = await ctx.db
    .insert(identities)
    .values({ connectionId, userId, linkedBy: 'scim', scimUserName: `scim-${userId}` })
    .returning({ id: identities.id });
  if (!row) throw new Error('identity insert returned nothing');
  return row.id;
}

/** A small app with the wildcard route Task 19 mounts and the SCIM and JSON content-type parsers. */
export function scimApp(ctx: TestContext): FastifyInstance {
  const app = Fastify({ logger: false });
  // An empty body (a DELETE with a content type, as IdPs send it) is no body, not a 400.
  const parse = (
    _req: unknown,
    body: string | Buffer,
    done: (err: Error | null, value?: unknown) => void,
  ) => {
    const text = body.toString();
    if (text.trim() === '') return done(null, undefined);
    try {
      done(null, JSON.parse(text));
    } catch (err) {
      done(Object.assign(err as Error, { statusCode: 400 }));
    }
  };
  app.removeContentTypeParser('application/json');
  app.addContentTypeParser(
    ['application/json', 'application/scim+json'],
    { parseAs: 'string' },
    parse,
  );
  const deps = scimDeps(ctx);
  app.all('/scim/v2/*', (req, reply) => handleScim(deps, req, reply));
  return app;
}

// ─── Sign-in test apps (Tasks 13, 14, 15) ───────────────────────────────────

/** A started SAML flow: the AuthnRequest's id, the RelayState, the binding cookie. */
export interface SamlStarted {
  id: string;
  relay: string;
  sso: string;
  /** The inflated AuthnRequest XML. */
  request: string;
  url: URL;
}

export interface SamlTestApp {
  app: FastifyInstance;
  /** `GET /start/<connection><query>` (returnTo `/projects` unless the query names one). */
  start(connectionId: string, query?: string): Promise<SamlStarted>;
  /** The IdP's cross-site POST to the ACS. */
  post(b64: string, relay: string, connectionId: string): Promise<LightMyRequestResponse>;
  /** The browser's `GET` of the finish location, with its binding cookie (and `extra` cookies). */
  finish(
    location: string,
    sso?: string,
    extra?: Record<string, string>,
  ): Promise<LightMyRequestResponse>;
  close(): Promise<void>;
}

/**
 * A small app on `ctx` with the SAML routes as Task 19 mounts them (`/start/:id`, `/acs/:id` with
 * its form parser, `/finish`), for the flow tests and the attack corpus. Two of them on one
 * context are two replicas on one database.
 */
export async function samlTestApp(
  ctx: TestContext,
  options: { acsDeps?: () => FlowDeps | null } = {},
): Promise<SamlTestApp> {
  const app = Fastify();
  await app.register(cookie);
  app.get<{ Params: { id: string }; Querystring: { returnTo?: string; link?: string } }>(
    '/start/:id',
    async (req, reply) => {
      const loaded = await loadConnection(ctx.db, req.params.id, ctx.config.secretKey);
      if (!loaded) throw new Error(`no connection ${req.params.id}`);
      const url = await startSaml(flowDeps(ctx), req, reply, loaded, {
        returnTo: req.query.returnTo ?? '/projects',
        link: req.query.link ? { userId: req.query.link } : null,
      });
      return reply.code(302).header('location', url).send();
    },
  );
  await app.register((scope, _opts, done) => {
    registerSamlFormParser(scope);
    scope.post<{ Params: { id: string } }>('/acs/:id', (req, reply) =>
      samlAcs(options.acsDeps?.() ?? flowDeps(ctx), req, reply, req.params.id),
    );
    done();
  });
  app.get('/finish', (req, reply) => finishSaml(flowDeps(ctx), req, reply));
  await app.ready();

  return {
    app,
    async start(connectionId, query = '') {
      const res = await app.inject({ method: 'GET', url: `/start/${connectionId}${query}` });
      if (res.statusCode !== 302) throw new Error(`start answered ${String(res.statusCode)}`);
      const url = new URL(res.headers.location as string);
      const request = inflateRawSync(
        Buffer.from(url.searchParams.get('SAMLRequest') ?? '', 'base64'),
      ).toString('utf8');
      const id = /ID="([^"]+)"/.exec(request)?.[1];
      const relay = url.searchParams.get('RelayState');
      const sso = res.cookies.find((c) => c.name === 'qualor_sso')?.value;
      if (!id || !relay || !sso) throw new Error('start gave no request id, RelayState or cookie');
      return { id, relay, sso, request, url };
    },
    post: (b64, relay, connectionId) =>
      app.inject({
        method: 'POST',
        url: `/acs/${connectionId}`,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: new URLSearchParams({ SAMLResponse: b64, RelayState: relay }).toString(),
      }),
    finish: (location, sso, extra = {}) =>
      app.inject({
        method: 'GET',
        url: location.replace('/api/v0/ee/sso/finish', '/finish'),
        cookies: { ...(sso ? { qualor_sso: sso } : {}), ...extra },
      }),
    close: () => app.close(),
  };
}

/** A started OIDC flow: the start answer, its binding cookie, the callback URL the OP sent. */
export interface OidcFlow {
  start: LightMyRequestResponse;
  sso: string;
  callback: URL;
}

export interface OidcTestApp {
  app: FastifyInstance;
  /** Starts a flow on `connection` and lets the fake OP authorize `login`. */
  begin(
    login: string,
    options: { connection: string; returnTo?: string; link?: string },
  ): Promise<OidcFlow>;
  /** The browser's callback request (default: the flow's binding cookie). */
  finish(
    flow: OidcFlow,
    options: {
      connection: string;
      cookies?: Record<string, string>;
      headers?: Record<string, string>;
    },
  ): Promise<LightMyRequestResponse>;
  /** begin, `tamper` with the callback URL, finish with `cookie` (default: the flow's). */
  signIn(
    login: string,
    options: {
      connection: string;
      tamper?: (callback: URL) => void;
      cookie?: string;
      returnTo?: string;
    },
  ): Promise<LightMyRequestResponse>;
  close(): Promise<void>;
}

/**
 * A small app on `ctx` with the OIDC routes as Task 19 mounts them (`/start/:id`, `/callback/:id`)
 * against the fake OP `op`. `callbackDeps`, when it returns deps, replaces flowDeps(ctx) for the
 * callback (a test's edition or resolver).
 */
export async function oidcTestApp(
  ctx: TestContext,
  op: FakeOp,
  options: { callbackDeps?: () => FlowDeps | null } = {},
): Promise<OidcTestApp> {
  const app = Fastify();
  await app.register(cookie);
  app.get<{ Params: { id: string }; Querystring: { returnTo?: string; link?: string } }>(
    '/start/:id',
    async (req, reply) => {
      const loaded = await loadConnection(ctx.db, req.params.id, ctx.config.secretKey);
      if (!loaded) throw new Error(`no connection ${req.params.id}`);
      const url = await startOidc(flowDeps(ctx), req, reply, loaded, {
        returnTo: req.query.returnTo ?? '/projects',
        link: req.query.link ? { userId: req.query.link } : null,
      });
      return reply.code(302).header('location', url).send();
    },
  );
  app.get<{ Params: { id: string } }>('/callback/:id', (req, reply) =>
    oidcCallback(options.callbackDeps?.() ?? flowDeps(ctx), req, reply, req.params.id),
  );
  await app.ready();

  async function begin(
    login: string,
    o: { connection: string; returnTo?: string; link?: string },
  ): Promise<OidcFlow> {
    const query = new URLSearchParams();
    if (o.returnTo !== undefined) query.set('returnTo', o.returnTo);
    if (o.link !== undefined) query.set('link', o.link);
    const start = await app.inject({
      method: 'GET',
      url: `/start/${o.connection}?${query.toString()}`,
    });
    if (start.statusCode !== 302) throw new Error(`start answered ${String(start.statusCode)}`);
    const sso = start.cookies.find((c) => c.name === 'qualor_sso')?.value;
    if (!sso) throw new Error('start set no binding cookie');
    const callback = new URL(await op.authorize(start.headers.location as string, login));
    return { start, sso, callback };
  }

  function finish(
    flow: OidcFlow,
    o: { connection: string; cookies?: Record<string, string>; headers?: Record<string, string> },
  ): Promise<LightMyRequestResponse> {
    return app.inject({
      method: 'GET',
      url: `/callback/${o.connection}${flow.callback.search}`,
      cookies: o.cookies ?? { qualor_sso: flow.sso },
      ...(o.headers ? { headers: o.headers } : {}),
    });
  }

  return {
    app,
    begin,
    finish,
    async signIn(login, o) {
      const flow = await begin(login, {
        connection: o.connection,
        ...(o.returnTo === undefined ? {} : { returnTo: o.returnTo }),
      });
      o.tamper?.(flow.callback);
      return finish(flow, {
        connection: o.connection,
        cookies: o.cookie === '' ? {} : { qualor_sso: o.cookie ?? flow.sso },
      });
    },
    close: () => app.close(),
  };
}
