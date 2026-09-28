import { generateKeyPairSync, randomBytes, type KeyObject } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { and, eq } from 'drizzle-orm';
import type { LightMyRequestResponse } from 'fastify';
import { exportJWK, SignJWT } from 'jose';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createUser, type TestContext } from '../../test/app';
import { startFakeOp, type FakeOp } from '../../test/fake-oidc';
import {
  auditRows,
  connectionDeps,
  licensedEdition,
  ONE_CONNECTION_FEATURES,
  oidcConnection,
  oidcTestApp,
  samlConnection,
  sessionHeaders,
  ssoContext,
  type OidcFlow,
  type OidcTestApp,
} from '../../test/sso';
import { flowDeps } from '../../test/sso-flow';
import { SYSTEM_ACTOR } from '../audit/recorder';
import {
  identities,
  memberships,
  organizations,
  ssoConnections,
  ssoStates,
  users,
} from '../db/schema';
import type { FlowDeps } from './complete';
import { createConnection, loadConnection } from './connections';
import { SsoFailure } from './errors';
import { MAX_GROUP_VALUES, replaceMappings } from './groups';
import { startOidc } from './oidc';
import { forgetOidcConfiguration } from './oidc-config';
import { stateKey } from './states';

describe('OIDC sign-in (sso-scim.md §5, §7)', () => {
  let ctx: TestContext;
  let op: FakeOp;
  let oapp: OidcTestApp;
  /** jit, groups from the claim, qualor-admins → default org admin. */
  let conn: string;
  /** linkByEmail, no JIT. */
  let linking: string;
  /** requires `hd` = acme.example. */
  let strict: string;
  let defaultOrg: string;
  /** reads userinfo too. */
  let withUserinfo: string;
  /** The callback's deps for one test (default: flowDeps). */
  let callbackDeps: (() => FlowDeps) | null = null;

  beforeAll(async () => {
    op = await startFakeOp();
    ctx = await ssoContext({
      // The test licence is issued 2026-10-01: the edition's clock is inside it (the rest is real).
      now: () => new Date('2027-01-01T00:00:00Z'),
      config: { ssoInternalHosts: new Set([new URL(op.issuer).host]) },
    });
    const oidc = {
      enabled: true,
      issuer: op.issuer,
      clientId: op.clientId,
      clientSecret: op.clientSecret,
    };
    conn = await oidcConnection(ctx, { ...oidc, groupSource: 'claims' });
    linking = await oidcConnection(ctx, {
      ...oidc,
      name: 'Linking',
      jit: false,
      linkByEmail: true,
    });
    strict = await oidcConnection(ctx, {
      ...oidc,
      name: 'Strict',
      requiredClaims: [{ claim: 'hd', value: 'acme.example' }],
    });
    const [org] = await ctx.db
      .select({ id: organizations.id })
      .from(organizations)
      .where(eq(organizations.key, 'default'));
    defaultOrg = org!.id;
    await replaceMappings({ db: ctx.db, audit: flowDeps(ctx).audit }, SYSTEM_ACTOR, conn, [
      { group: 'qualor-admins', organizationId: defaultOrg, projectId: null, role: 'admin' },
    ]);
    const extra = (login: string, over: Record<string, unknown> = {}) =>
      op.users.set(login, {
        sub: `${login}-sub`,
        email: `${login}@acme.example`,
        email_verified: true,
        preferred_username: login,
        name: login,
        groups: [],
        ...over,
      });
    extra('dave');
    extra('greg', { groups: Array.from({ length: MAX_GROUP_VALUES + 1 }, (_, i) => `g${i}`) });
    extra('stringy', { email: 'stringy@acme.example', email_verified: 'true' });
    extra('verified', { email: 'verified@acme.example' });
    extra('hd', { hd: 'acme.example' });
    extra('linked');
    extra('nulsub', { sub: `nul${String.fromCharCode(0)}sub` });
    extra('nulname', { preferred_username: `nul${String.fromCharCode(0)}name` });
    extra('lonemail', { email: `lone${String.fromCharCode(0xd800)}@acme.example` });
    extra('uinfo');
    withUserinfo = (
      await createConnection(connectionDeps(ctx), SYSTEM_ACTOR, {
        name: 'Userinfo',
        enabled: true,
        protocol: 'oidc',
        oidc: {
          issuer: op.issuer,
          clientId: op.clientId,
          clientSecret: op.clientSecret,
          userinfo: true,
        },
      })
    ).id;

    oapp = await oidcTestApp(ctx, op, { callbackDeps: () => callbackDeps?.() ?? null });
  });
  afterAll(async () => {
    await oapp.close();
    await ctx.close();
    await op.close();
  });
  afterEach(() => {
    callbackDeps = null;
    op.tweak({
      nonce: undefined,
      idTokenAud: undefined,
      idTokenIss: undefined,
      issParam: undefined,
      advertiseIssParam: false,
      redirectFromToken: false,
    });
  });

  type Flow = OidcFlow;

  const begin = (
    login: string,
    options: { connection?: string; returnTo?: string; link?: string } = {},
  ): Promise<Flow> => oapp.begin(login, { ...options, connection: options.connection ?? conn });

  const finish = (
    flow: Flow,
    options: {
      connection?: string;
      cookies?: Record<string, string>;
      headers?: Record<string, string>;
    } = {},
  ) => oapp.finish(flow, { ...options, connection: options.connection ?? conn });

  const signIn = (
    login: string,
    options: { connection?: string; tamper?: (callback: URL) => void; cookie?: string } = {},
  ) => oapp.signIn(login, { ...options, connection: options.connection ?? conn });

  const sessionOf = (res: LightMyRequestResponse) =>
    res.cookies.find((c) => c.name === 'qualor_session');

  /** The last `single sign-on failed` line's reason and detail. */
  function lastFailure(): { reason: string; detail: string } {
    const line = ctx.logs.filter((l) => l.includes('single sign-on failed')).at(-1);
    const parsed = JSON.parse(line ?? '{}') as { reason?: string; detail?: string };
    return { reason: parsed.reason ?? '', detail: parsed.detail ?? '' };
  }

  async function userNamed(username: string) {
    const [user] = await ctx.db.select().from(users).where(eq(users.username, username));
    return user;
  }

  it('sends S256 PKCE, state and nonce, and signs alice in with a session, a 303 and the audit rows', async () => {
    const before = (await auditRows(ctx)).length;
    const start = await oapp.app.inject({ method: 'GET', url: `/start/${conn}` });
    const url = new URL(start.headers.location as string);
    expect(url.origin + url.pathname).toBe(`${op.issuer}/auth`);
    expect(url.searchParams.get('code_challenge_method')).toBe('S256');
    expect(url.searchParams.get('code_challenge')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(url.searchParams.get('state')).toMatch(/.{20,}/);
    expect(url.searchParams.get('nonce')).toMatch(/.{20,}/);
    expect(url.searchParams.get('redirect_uri')).toBe(
      `https://q.example/api/v0/ee/sso/oidc/${conn}/callback`,
    );
    expect(url.searchParams.get('scope')).toBe('openid email profile');
    const binding = start.cookies.find((c) => c.name === 'qualor_sso')!;
    expect(binding).toMatchObject({ path: '/api/v0/ee/sso', httpOnly: true, sameSite: 'Lax' });
    // The flow row holds the hash of state, never the state.
    const [row] = await ctx.db
      .select()
      .from(ssoStates)
      .where(eq(ssoStates.key, stateKey('oidc', url.searchParams.get('state')!)));
    expect(row).toMatchObject({ kind: 'oidc', connectionId: conn });
    expect(JSON.stringify(row!.payload)).not.toContain(binding.value);

    const res = await signIn('alice');
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/projects');
    expect(sessionOf(res)?.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(op.lastTokenRequest()?.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
    // The binding cookie is cleared.
    expect(res.cookies.find((c) => c.name === 'qualor_sso')?.value).toBe('');

    const alice = (await userNamed('alice'))!;
    expect(alice).toMatchObject({
      email: 'alice@acme.example',
      displayName: 'Alice A',
      passwordHash: null,
      isInstanceAdmin: false,
    });
    const [identity] = await ctx.db
      .select()
      .from(identities)
      .where(and(eq(identities.connectionId, conn), eq(identities.userId, alice.id)));
    expect(identity).toMatchObject({ subject: 'alice-sub', linkedBy: 'jit' });
    expect(identity!.lastSignInAt).toBeInstanceOf(Date);
    const [membership] = await ctx.db
      .select()
      .from(memberships)
      .where(and(eq(memberships.userId, alice.id), eq(memberships.organizationId, defaultOrg)));
    expect(membership).toMatchObject({ role: 'admin', managedByConnectionId: conn });

    const rows = (await auditRows(ctx)).slice(before);
    expect(rows.map((r) => r.action)).toEqual([
      'sso.user_provisioned',
      'member.added',
      'auth.sign_in',
    ]);
    expect(rows[0]).toMatchObject({
      targetId: alice.id,
      details: { connectionId: conn, emailSet: true },
    });
    expect(rows[1]).toMatchObject({ organizationId: defaultOrg, details: { managedBy: conn } });
    expect(rows[2]).toMatchObject({
      actorType: 'user',
      actorUserId: alice.id,
      details: { method: 'oidc', connectionId: conn },
    });

    // Signing in again finds the identity: no new user, no new membership.
    const again = await signIn('alice');
    expect(again.statusCode).toBe(303);
    expect((await auditRows(ctx)).at(-1)).toMatchObject({ action: 'auth.sign_in' });
  });

  it('works once: the same callback URL a second time is flow_expired', async () => {
    const flow = await begin('alice');
    expect((await finish(flow)).statusCode).toBe(303);
    const again = await finish(flow);
    expect(again.headers.location).toBe('/login?sso_error=flow_expired');
    expect(sessionOf(again)).toBeUndefined();
    expect(lastFailure()).toEqual({ reason: 'flow_expired', detail: 'oidc.state_unknown' });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.sign_in_failed',
      outcome: 'failure',
      details: { connectionId: conn, protocol: 'oidc', reason: 'flow_expired' },
    });
  });

  it('refuses another browser (flow_mismatch), and the flow is burnt', async () => {
    const flow = await begin('alice');
    const res = await finish(flow, { cookies: { qualor_sso: 'A'.repeat(43) } });
    expect(res.headers.location).toBe('/login?sso_error=flow_mismatch');
    expect(sessionOf(res)).toBeUndefined();
    expect(lastFailure()).toEqual({ reason: 'flow_mismatch', detail: 'oidc.binding' });
    // The row was taken before the check: the right browser cannot use it afterwards either.
    const retry = await finish(flow);
    expect(retry.headers.location).toBe('/login?sso_error=flow_expired');
  });

  it('refuses a callback without the binding cookie (flow_mismatch)', async () => {
    const flow = await begin('alice');
    const res = await finish(flow, { cookies: {} });
    expect(res.headers.location).toBe('/login?sso_error=flow_mismatch');
  });

  it('refuses a callback without state, or with a flow of another connection', async () => {
    const res = await signIn('alice', { tamper: (cb) => cb.searchParams.delete('state') });
    expect(res.headers.location).toBe('/login?sso_error=flow_expired');
    expect(lastFailure().detail).toBe('oidc.state_missing');
    const flow = await begin('alice');
    const other = await finish(flow, { connection: linking });
    expect(other.headers.location).toBe('/login?sso_error=flow_expired');
    expect(lastFailure().detail).toBe('oidc.state_unknown');
  });

  it('refuses an expired flow (flow_expired)', async () => {
    const flow = await begin('alice');
    const state = new URL(flow.start.headers.location as string).searchParams.get('state')!;
    await ctx.db
      .update(ssoStates)
      .set({ expiresAt: new Date(Date.now() - 1_000) })
      .where(eq(ssoStates.key, stateKey('oidc', state)));
    const res = await finish(flow);
    expect(res.headers.location).toBe('/login?sso_error=flow_expired');
    expect(op.lastTokenRequest()?.get('code')).not.toBe(flow.callback.searchParams.get('code'));
  });

  it('passes the IdP error through as idp_error, never its description', async () => {
    const res = await signIn('alice', {
      tamper: (cb) => {
        cb.search = `?error=access_denied&error_description=${encodeURIComponent('<b>evil</b>')}&state=${cb.searchParams.get('state')}`;
      },
    });
    expect(res.headers.location).toBe('/login?sso_error=idp_error');
    expect(lastFailure()).toEqual({ reason: 'idp_error', detail: 'oidc.idp.access_denied' });
    expect(ctx.logs.join('\n')).not.toContain('<b>evil</b>');
    expect(ctx.logs.join('\n')).not.toContain('evil');
  });

  it('refuses an ID token with another nonce (invalid_response, oidc.id_token.nonce)', async () => {
    op.tweak({ nonce: 'someone-elses-nonce-000000000000' });
    const res = await signIn('alice');
    expect(res.headers.location).toBe('/login?sso_error=invalid_response');
    expect(sessionOf(res)).toBeUndefined();
    expect(lastFailure().detail).toBe('oidc.id_token.nonce');
  });

  it('refuses a wrong aud (oidc.id_token.aud) and a wrong iss in the ID token (oidc.id_token.iss)', async () => {
    op.tweak({ idTokenAud: 'another-client' });
    const aud = await signIn('alice');
    expect(aud.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('oidc.id_token.aud');
    op.tweak({ idTokenAud: undefined, idTokenIss: 'https://evil.example' });
    const iss = await signIn('alice');
    expect(iss.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('oidc.id_token.iss');
  });

  it('refuses an iss response parameter of another issuer (mix-up) before the code is redeemed', async () => {
    const before = op.lastTokenRequest();
    const res = await signIn('alice', {
      tamper: (cb) => cb.searchParams.set('iss', 'https://evil.example'),
    });
    expect(res.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('oidc.iss_param');
    expect(op.lastTokenRequest()).toBe(before);
  });

  it('requires the iss parameter when the IdP advertises it (RFC 9207)', async () => {
    op.tweak({ advertiseIssParam: true });
    forgetOidcConfiguration(conn);
    try {
      const ok = await signIn('alice');
      expect(ok.statusCode).toBe(303);
      expect(ok.headers.location).toBe('/projects');
      const missing = await signIn('alice', { tamper: (cb) => cb.searchParams.delete('iss') });
      expect(missing.headers.location).toBe('/login?sso_error=invalid_response');
      expect(lastFailure().detail).toBe('oidc.iss_param');
    } finally {
      op.tweak({ advertiseIssParam: false });
      forgetOidcConfiguration(conn);
    }
  });

  it('refuses a token endpoint that answers 302 (oidc.token_endpoint), following nothing', async () => {
    op.tweak({ redirectFromToken: true });
    const res = await signIn('alice');
    expect(res.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('oidc.token_endpoint');
  });

  it('rebuilds the redirect URI from QUALOR_PUBLIC_URL, never the Host header', async () => {
    const flow = await begin('alice');
    const res = await finish(flow, { headers: { host: 'evil.example' } });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/projects');
    expect(op.lastTokenRequest()?.get('redirect_uri')).toBe(
      `https://q.example/api/v0/ee/sso/oidc/${conn}/callback`,
    );
  });

  it('keeps returnTo on this origin: anything else becomes /', async () => {
    const flow = await begin('alice', { returnTo: '//evil.example/x' });
    const res = await finish(flow);
    expect(res.headers.location).toBe('/');
    const kept = await finish(await begin('alice', { returnTo: '/projects/p1?tab=issues' }));
    expect(kept.headers.location).toBe('/projects/p1?tab=issues');
  });

  it('refuses a disabled connection (unavailable), at the start and at the callback', async () => {
    const flow = await begin('alice');
    await ctx.db.update(ssoConnections).set({ enabled: false }).where(eq(ssoConnections.id, conn));
    try {
      const res = await finish(flow);
      expect(res.headers.location).toBe('/login?sso_error=unavailable');
      expect(lastFailure()).toEqual({ reason: 'unavailable', detail: 'oidc.disabled' });
      const loaded = (await loadConnection(ctx.db, conn, ctx.config.secretKey))!;
      const reply = { setCookie: () => reply } as never;
      await expect(
        startOidc(flowDeps(ctx), { protocol: 'https' } as never, reply, loaded, {
          returnTo: '/',
          link: null,
        }),
      ).rejects.toMatchObject({ code: 'unavailable', detail: 'oidc.disabled' });
    } finally {
      await ctx.db.update(ssoConnections).set({ enabled: true }).where(eq(ssoConnections.id, conn));
    }
  });

  it('refuses a connection not in effect (unavailable, oidc.not_in_effect), at the start and at the callback', async () => {
    // A key without sso.multi (sso-scim.md §4.4): only the oldest enabled connection, `conn`,
    // is in effect. A flow started before the licence changed fails at its callback.
    const business = licensedEdition(ONE_CONNECTION_FEATURES);
    const businessDeps = (): FlowDeps => ({ ...flowDeps(ctx), edition: business });
    const flow = await begin('alice', { connection: linking });
    callbackDeps = businessDeps;
    const tokenRequest = op.lastTokenRequest();
    const res = await finish(flow, { connection: linking });
    expect(res.headers.location).toBe('/login?sso_error=unavailable');
    expect(sessionOf(res)).toBeUndefined();
    expect(lastFailure()).toEqual({ reason: 'unavailable', detail: 'oidc.not_in_effect' });
    // Nothing went to the IdP.
    expect(op.lastTokenRequest()).toBe(tokenRequest);
    const loaded = (await loadConnection(ctx.db, linking, ctx.config.secretKey))!;
    const reply = { setCookie: () => reply } as never;
    await expect(
      startOidc(businessDeps(), { protocol: 'https' } as never, reply, loaded, {
        returnTo: '/',
        link: null,
      }),
    ).rejects.toMatchObject({ code: 'unavailable', detail: 'oidc.not_in_effect' });
    // The connection in effect still signs people in under the same key.
    const ok = await finish(await begin('alice'));
    expect(ok.statusCode).toBe(303);
    expect(ok.headers.location).toBe('/projects');
  });

  it('refuses a deactivated user (inactive_user), with the user in the audit row', async () => {
    expect((await signIn('dave')).statusCode).toBe(303);
    const dave = (await userNamed('dave'))!;
    await ctx.db.update(users).set({ active: false }).where(eq(users.id, dave.id));
    const res = await signIn('dave');
    expect(res.headers.location).toBe('/login?sso_error=inactive_user');
    expect(sessionOf(res)).toBeUndefined();
    expect(lastFailure()).toEqual({ reason: 'inactive_user', detail: 'account.inactive_user' });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.sign_in_failed',
      actorType: 'anonymous',
      actorUserId: dave.id,
      targetId: dave.id,
      details: { reason: 'inactive_user' },
    });
  });

  it('never links by an unverified email, nor by the string "true"; links by a verified one', async () => {
    const robert = await createUser(ctx, { username: 'robert', email: 'bob@acme.example' });
    const bob = await signIn('bob', { connection: linking });
    expect(bob.headers.location).toBe('/login?sso_error=no_account');
    const stringy = await createUser(ctx, {
      username: 'stringy-local',
      email: 'stringy@acme.example',
    });
    const res = await signIn('stringy', { connection: linking });
    expect(res.headers.location).toBe('/login?sso_error=no_account');
    const linked = await ctx.db
      .select()
      .from(identities)
      .where(eq(identities.connectionId, linking));
    expect(linked.map((i) => i.userId)).not.toContain(robert.id);
    expect(linked.map((i) => i.userId)).not.toContain(stringy.id);

    const verified = await createUser(ctx, {
      username: 'verified-local',
      email: 'verified@acme.example',
    });
    const ok = await signIn('verified', { connection: linking });
    expect(ok.statusCode).toBe(303);
    const rows = await auditRows(ctx);
    expect(rows.at(-2)).toMatchObject({
      action: 'sso.identity_linked',
      targetId: verified.id,
      details: { connectionId: linking, method: 'verified_email' },
    });
    expect(rows.at(-1)).toMatchObject({ action: 'auth.sign_in', actorUserId: verified.id });
  });

  it('refuses more groups than the bound (invalid_response, groups.too_many) before any account', async () => {
    const res = await signIn('greg');
    expect(res.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('groups.too_many');
    expect(await userNamed('greg')).toBeUndefined();
  });

  it('enforces the required claims before any account (required_claim)', async () => {
    const res = await signIn('dave', { connection: strict });
    expect(res.headers.location).toBe('/login?sso_error=required_claim');
    expect(lastFailure().detail).toBe('oidc.required_claim');
    const [identity] = await ctx.db
      .select()
      .from(identities)
      .where(and(eq(identities.connectionId, strict), eq(identities.subject, 'dave-sub')));
    expect(identity).toBeUndefined();
    const ok = await signIn('hd', { connection: strict });
    expect(ok.statusCode).toBe(303);
  });

  it('links the signed-in user (intent link) in the session they have, and only that user', async () => {
    const local = await createUser(ctx, { username: 'linker' });
    const headers = await sessionHeaders(ctx, 'linker');
    const session = headers.cookie!.split('=')[1]!;
    const flow = await begin('linked', { link: local.id, returnTo: '/settings/account' });
    // Another user's session (the admin's) cannot finish it.
    const wrong = await finish(flow, {
      cookies: {
        qualor_sso: flow.sso,
        qualor_session: (await sessionHeaders(ctx, 'admin')).cookie!.split('=')[1]!,
      },
    });
    expect(wrong.headers.location).toBe('/login?sso_error=flow_mismatch');
    expect(lastFailure().detail).toBe('link.session');

    const again = await begin('linked', { link: local.id, returnTo: '/settings/account' });
    const res = await finish(again, {
      cookies: { qualor_sso: again.sso, qualor_session: session },
    });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/settings/account');
    expect(sessionOf(res)).toBeUndefined();
    const [identity] = await ctx.db
      .select()
      .from(identities)
      .where(and(eq(identities.connectionId, conn), eq(identities.userId, local.id)));
    expect(identity).toMatchObject({ subject: 'linked-sub', linkedBy: 'user' });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.identity_linked',
      actorUserId: local.id,
      details: { connectionId: conn, method: 'user' },
    });

    // alice's subject is alice's: linking it to linker is identity_in_use.
    const taken = await begin('alice', { link: local.id });
    const refused = await finish(taken, {
      cookies: { qualor_sso: taken.sso, qualor_session: session },
    });
    expect(refused.headers.location).toBe('/login?sso_error=identity_in_use');
  });

  it('never logs a secret of the flow', () => {
    const logs = ctx.logs.join('\n');
    expect(logs).not.toContain(op.clientSecret);
    const verifier = op.lastTokenRequest()?.get('code_verifier');
    if (verifier) expect(logs).not.toContain(verifier);
    expect(logs).not.toMatch(/"(state|nonce|code|id_token|access_token)":/);
  });

  it('startOidc refuses a SAML connection or a missing public URL (unavailable)', async () => {
    const reply = { setCookie: () => reply } as never;
    const request = { protocol: 'https' } as never;
    const loaded = (await loadConnection(ctx.db, conn, ctx.config.secretKey))!;
    const noPublicUrl = { ...flowDeps(ctx), config: { ...ctx.config, publicUrl: null } };
    const noUrl = startOidc(noPublicUrl, request, reply, loaded, { returnTo: '/', link: null });
    await expect(noUrl).rejects.toBeInstanceOf(SsoFailure);
    await expect(noUrl).rejects.toMatchObject({
      code: 'unavailable',
      detail: 'oidc.not_configured',
    });
    const saml = (await loadConnection(
      ctx.db,
      await samlConnection(ctx, { name: 'A SAML one', enabled: true }),
      ctx.config.secretKey,
    ))!;
    const refused = startOidc(flowDeps(ctx), request, reply, saml, { returnTo: '/', link: null });
    await expect(refused).rejects.toBeInstanceOf(SsoFailure);
    await expect(refused).rejects.toMatchObject({
      code: 'unavailable',
      detail: 'oidc.not_configured',
    });
  });

  it('refuses at the callback when sso is no longer active (unavailable, oidc.inactive)', async () => {
    const flow = await begin('alice');
    callbackDeps = () => {
      const deps = flowDeps(ctx);
      const real = deps.edition;
      return {
        ...deps,
        edition: {
          ...real,
          isFeatureActive: (f: string) => f !== 'sso' && real.isFeatureActive(f),
        },
      };
    };
    const tokenRequest = op.lastTokenRequest();
    const res = await finish(flow);
    expect(res.headers.location).toBe('/login?sso_error=unavailable');
    expect(sessionOf(res)).toBeUndefined();
    expect(lastFailure()).toEqual({ reason: 'unavailable', detail: 'oidc.inactive' });
    // Nothing went to the IdP.
    expect(op.lastTokenRequest()).toBe(tokenRequest);
  });

  it('ends any other error on the login page as invalid_response, logging only its class', async () => {
    const flow = await begin('alice');
    callbackDeps = () => {
      const deps = flowDeps(ctx);
      return {
        ...deps,
        edition: {
          ...deps.edition,
          isFeatureActive: () => {
            throw new TypeError('boom <b>idp text</b>');
          },
        },
      };
    };
    const res = await finish(flow);
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure()).toEqual({ reason: 'invalid_response', detail: 'oidc.other' });
    const logs = ctx.logs.join(' ');
    expect(logs).toContain('"errorClass":"TypeError"');
    expect(logs).not.toContain('idp text');
  });

  it('refuses a sub holding U+0000 (invalid_response, oidc.claims), never a 500', async () => {
    const res = await signIn('nulsub');
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('oidc.claims');
  });

  it('counts a username with U+0000 or an email with a lone surrogate as absent', async () => {
    const nulname = await signIn('nulname');
    expect(nulname.statusCode).toBe(303);
    expect(nulname.headers.location).toBe('/projects');
    // The username came from the email's local part instead.
    expect(await userNamed('nulname')).toMatchObject({ email: 'nulname@acme.example' });
    const lonemail = await signIn('lonemail');
    expect(lonemail.statusCode).toBe(303);
    expect(lonemail.headers.location).toBe('/projects');
    expect(await userNamed('lonemail')).toMatchObject({ email: null });
  });

  it('signs in with userinfo on, its email verified by the same source', async () => {
    const res = await signIn('uinfo', { connection: withUserinfo });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/projects');
    expect(await userNamed('uinfo')).toMatchObject({ email: 'uinfo@acme.example' });
  });
});

/**
 * A minimal OP whose JWKS rotates: keys are published by kid, the ID token is signed by the kid
 * `signWith` names, and every JWKS request is counted (the fake OP of Task 6 has one fixed kid).
 */
async function startRotatingOp() {
  const clientId = 'rotating';
  const clientSecret = `rot-${randomBytes(8).toString('hex')}`;
  const keys = new Map<string, { key: KeyObject; jwk: Record<string, unknown> }>();
  const codes = new Map<string, { nonce: string | null }>();
  const state = { signWith: 'k1', jwksHits: 0, jwksUri: '' };
  async function publish(kid: string): Promise<void> {
    const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    keys.set(kid, {
      key: pair.privateKey,
      jwk: { ...(await exportJWK(pair.publicKey)), kid, alg: 'RS256', use: 'sig' },
    });
  }
  await publish('k1');
  let issuer = '';
  const json = (res: ServerResponse, status: number, body: unknown) => {
    res.writeHead(status, { 'content-type': 'application/json' });
    res.end(JSON.stringify(body));
  };
  async function token(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(chunk as Buffer);
    const value = new URLSearchParams(Buffer.concat(chunks).toString('utf8')).get('code') ?? '';
    const code = codes.get(value);
    codes.delete(value);
    const signer = keys.get(state.signWith);
    if (!code || !signer) {
      json(res, 400, { error: 'invalid_grant' });
      return;
    }
    const now = Math.floor(Date.now() / 1000);
    const idToken = await new SignJWT({
      sub: 'rot-sub',
      preferred_username: 'rotator',
      email: 'rotator@acme.example',
      email_verified: true,
      ...(code.nonce ? { nonce: code.nonce } : {}),
    })
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: state.signWith })
      .setIssuer(issuer)
      .setAudience(clientId)
      .setIssuedAt(now)
      .setExpirationTime(now + 300)
      .sign(signer.key);
    json(res, 200, {
      access_token: randomBytes(16).toString('hex'),
      token_type: 'Bearer',
      id_token: idToken,
    });
  }
  const server: Server = createServer((req, res) => {
    const path = new URL(req.url ?? '/', 'http://op').pathname;
    if (path === '/.well-known/openid-configuration') {
      json(res, 200, {
        issuer,
        authorization_endpoint: `${issuer}/auth`,
        token_endpoint: `${issuer}/token`,
        jwks_uri: state.jwksUri || `${issuer}/jwks`,
        response_types_supported: ['code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: ['RS256'],
      });
    } else if (path === '/jwks') {
      state.jwksHits += 1;
      json(res, 200, { keys: [...keys.values()].map((k) => k.jwk) });
    } else if (path === '/token' && req.method === 'POST') {
      token(req, res).catch(() => {
        if (!res.headersSent) json(res, 500, { error: 'server_error' });
      });
    } else {
      json(res, 404, { error: 'not_found' });
    }
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  issuer = `http://127.0.0.1:${String((server.address() as AddressInfo).port)}`;
  return {
    issuer,
    clientId,
    clientSecret,
    state,
    publish,
    /** The IdP's side of the browser round trip, as FakeOp.authorize. */
    authorize(authorizationUrl: string): Promise<string> {
      const url = new URL(authorizationUrl);
      const code = randomBytes(16).toString('base64url');
      codes.set(code, { nonce: url.searchParams.get('nonce') });
      const callback = new URL(url.searchParams.get('redirect_uri') ?? '');
      callback.searchParams.set('code', code);
      callback.searchParams.set('state', url.searchParams.get('state') ?? '');
      return Promise.resolve(callback.href);
    },
    close: () =>
      new Promise<void>((resolve) => {
        server.closeAllConnections();
        server.close(() => {
          resolve();
        });
      }),
  };
}

describe('the ID token signature and the JWKS (sso-scim.md §3.2, §14)', () => {
  let ctx: TestContext;
  let op: Awaited<ReturnType<typeof startRotatingOp>>;
  let oapp: OidcTestApp;
  let conn: string;

  beforeAll(async () => {
    op = await startRotatingOp();
    ctx = await ssoContext({
      now: () => new Date('2027-01-01T00:00:00Z'),
      config: { ssoInternalHosts: new Set([new URL(op.issuer).host]) },
    });
    conn = await oidcConnection(ctx, {
      enabled: true,
      issuer: op.issuer,
      clientId: op.clientId,
      clientSecret: op.clientSecret,
    });
    // oidcTestApp plays the browser through the OP's `authorize` only.
    oapp = await oidcTestApp(ctx, op as unknown as FakeOp);
  });
  afterAll(async () => {
    vi.useRealTimers();
    await oapp.close();
    await ctx.close();
    await op.close();
  });
  afterEach(() => {
    vi.useRealTimers();
  });

  const signIn = () => oapp.signIn('rotator', { connection: conn });
  function lastDetail(): string | undefined {
    const line = ctx.logs.filter((l) => l.includes('single sign-on failed')).at(-1);
    return (JSON.parse(line ?? '{}') as { detail?: string }).detail;
  }

  it('fetches the JWKS once and caches it', async () => {
    forgetOidcConfiguration(conn);
    const before = op.state.jwksHits;
    expect((await signIn()).headers.location).toBe('/projects');
    expect((await signIn()).headers.location).toBe('/projects');
    expect(op.state.jwksHits).toBe(before + 1);
  });

  it('takes a rotated key (a new kid) with one refetch once the cached JWKS is 60 s old', async () => {
    forgetOidcConfiguration(conn);
    op.state.signWith = 'k1';
    expect((await signIn()).headers.location).toBe('/projects');
    const before = op.state.jwksHits;
    await op.publish('k2');
    op.state.signWith = 'k2';
    vi.useFakeTimers({ toFake: ['Date'], now: Date.now() + 61_000 });
    const res = await signIn();
    expect(res.headers.location).toBe('/projects');
    expect(op.state.jwksHits).toBe(before + 1);
  });

  it('refuses a kid the fresh JWKS lacks without refetching, then starts the next flow from a fresh JWKS', async () => {
    forgetOidcConfiguration(conn);
    // Its own signing key, so the test does not depend on the rotation test before it (-t).
    await op.publish('k2');
    op.state.signWith = 'k2';
    expect((await signIn()).headers.location).toBe('/projects');
    const before = op.state.jwksHits;
    await op.publish('k3');
    op.state.signWith = 'k3';
    // The cached JWKS is seconds old: no refetch (a kid in a token cannot make Qualor hammer the
    // IdP's JWKS), and the sign-in is refused.
    const refused = await signIn();
    expect(refused.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastDetail()).toBe('oidc.key_selection');
    expect(op.state.jwksHits).toBe(before);
    // The configuration was dropped: the next flow rediscovers and fetches the JWKS once.
    expect((await signIn()).headers.location).toBe('/projects');
    expect(op.state.jwksHits).toBe(before + 1);
  });

  it('fetches the JWKS through ssoFetch: a jwks_uri on a private address not listed is refused', async () => {
    op.state.jwksUri = 'http://10.0.0.7/jwks';
    forgetOidcConfiguration(conn);
    try {
      const res = await signIn();
      expect(res.headers.location).toBe('/login?sso_error=invalid_response');
      expect(lastDetail()).toBe('oidc.fetch.not_public');
    } finally {
      op.state.jwksUri = '';
      forgetOidcConfiguration(conn);
    }
  });
});
