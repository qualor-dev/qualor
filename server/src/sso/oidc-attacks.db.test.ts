import { and, count, eq } from 'drizzle-orm';
import type { LightMyRequestResponse } from 'fastify';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createUser, type TestContext } from '../../test/app';
import { startFakeOp, type FakeOp, type FakeOpTweaks } from '../../test/fake-oidc';
import { oidcConnection, oidcTestApp, ssoContext, type OidcTestApp } from '../../test/sso';
import { flowDeps } from '../../test/sso-flow';
import { identities, sessions, users } from '../db/schema';
import type { FlowDeps } from './complete';
import { loadConnection } from './connections';
import { startOidc } from './oidc';
import { forgetOidcConfiguration } from './oidc-config';

/** Every tweak a row may set, back at its default. */
const RESET: Partial<FakeOpTweaks> = {
  issuerInDiscovery: undefined,
  idTokenIss: undefined,
  idTokenAud: undefined,
  idTokenAzp: undefined,
  nonce: undefined,
  alg: undefined,
  hsKey: undefined,
  rsaBits: undefined,
  kid: undefined,
  foreignKey: undefined,
  expOffsetSeconds: undefined,
  iatOffsetSeconds: undefined,
  issParam: undefined,
  advertiseIssParam: undefined,
  signingAlgs: undefined,
  omitJwksUri: undefined,
  tokenEndpoint: undefined,
  checkVerifier: undefined,
  expectVerifier: undefined,
  redirectFromToken: undefined,
  emailVerified: undefined,
};

/**
 * sso-scim.md §19.3, the OIDC half of the security corpus, against the fake OP (§19.2). Every row
 * runs a real flow (start, the OP's authorization, the callback) and expects the refusal code, the
 * fixed detail in the `component: "sso"` log line, and no session.
 */
describe('the OIDC attack corpus (sso-scim.md §19.3)', () => {
  let ctx: TestContext;
  let op: FakeOp;
  let oapp: OidcTestApp;
  /** jit, groups from the claim. */
  let conn: string;
  /** The callback's deps for one row (default: flowDeps). */
  let callbackDeps: (() => FlowDeps) | null = null;

  beforeAll(async () => {
    op = await startFakeOp();
    ctx = await ssoContext({
      // The test licence is issued 2026-10-01: the edition's clock is inside it. Token times are
      // real (Date.now() when the OP signs), so openid-client's clock agrees.
      now: () => new Date('2027-01-01T00:00:00Z'),
      config: { ssoInternalHosts: new Set([new URL(op.issuer).host]) },
    });
    conn = await oidcConnection(ctx, {
      enabled: true,
      issuer: op.issuer,
      clientId: op.clientId,
      clientSecret: op.clientSecret,
      groupSource: 'claims',
    });
    oapp = await oidcTestApp(ctx, op, { callbackDeps: () => callbackDeps?.() ?? null });
  });
  afterAll(async () => {
    await oapp.close();
    await ctx.close();
    await op.close();
  });
  afterEach(() => {
    callbackDeps = null;
    op.tweak(RESET);
    forgetOidcConfiguration(conn);
  });

  const signIn = (
    login: string,
    options: { tamper?: (callback: URL) => void; cookie?: string; returnTo?: string } = {},
  ) => oapp.signIn(login, { ...options, connection: conn });

  const sessionOf = (res: LightMyRequestResponse) =>
    res.cookies.find((c) => c.name === 'qualor_session');

  /** The last `single sign-on failed` line's reason and detail. */
  function lastFailure(): { reason: string; detail: string } {
    const line = ctx.logs.filter((l) => l.includes('single sign-on failed')).at(-1);
    const parsed = JSON.parse(line ?? '{}') as {
      component?: string;
      reason?: string;
      detail?: string;
    };
    expect(parsed.component).toBe('sso');
    return { reason: parsed.reason ?? '', detail: parsed.detail ?? '' };
  }

  const sessionCount = async () => {
    const [row] = await ctx.db.select({ n: count() }).from(sessions);
    return row!.n;
  };

  /** Runs `act` (one callback) and expects it refused with `code` and `detail`, and no session. */
  async function refused(
    act: () => Promise<LightMyRequestResponse>,
    code: string,
    detail: string,
  ): Promise<void> {
    const before = await sessionCount();
    const res = await act();
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`/login?sso_error=${code}`);
    expect(sessionOf(res)).toBeUndefined();
    expect(lastFailure()).toEqual({ reason: code, detail });
    expect(await sessionCount()).toBe(before);
  }

  it('accepts the control flow: S256 in the authorization URL, the verifier in the token request', async () => {
    const flow = await oapp.begin('alice', { connection: conn });
    const authorization = new URL(flow.start.headers.location as string);
    expect(authorization.searchParams.get('code_challenge_method')).toBe('S256');
    const res = await oapp.finish(flow, { connection: conn });
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe('/projects');
    expect(sessionOf(res)).toBeDefined();
    expect(op.lastTokenRequest()?.get('code_verifier')).toMatch(/^[A-Za-z0-9_-]{43,128}$/);
  });

  describe('state and the browser binding', () => {
    it('refuses a missing state (flow_expired, oidc.state_missing)', async () => {
      await refused(
        () => signIn('alice', { tamper: (u) => u.searchParams.delete('state') }),
        'flow_expired',
        'oidc.state_missing',
      );
    });

    it('refuses a changed state (flow_expired, oidc.state_unknown)', async () => {
      await refused(
        () => signIn('alice', { tamper: (u) => u.searchParams.set('state', 'x'.repeat(43)) }),
        'flow_expired',
        'oidc.state_unknown',
      );
    });

    it('refuses a state used twice (flow_expired, oidc.state_unknown)', async () => {
      const flow = await oapp.begin('alice', { connection: conn });
      expect(sessionOf(await oapp.finish(flow, { connection: conn }))).toBeDefined();
      await refused(
        () => oapp.finish(flow, { connection: conn }),
        'flow_expired',
        'oidc.state_unknown',
      );
    });

    it('refuses a callback without the qualor_sso cookie (flow_mismatch, oidc.binding)', async () => {
      await refused(() => signIn('alice', { cookie: '' }), 'flow_mismatch', 'oidc.binding');
    });

    it('refuses a state from another browser: the victim’s callback with the attacker’s cookie', async () => {
      const victim = await oapp.begin('alice', { connection: conn });
      const attacker = await oapp.begin('bob', { connection: conn });
      await refused(
        () => oapp.finish(victim, { connection: conn, cookies: { qualor_sso: attacker.sso } }),
        'flow_mismatch',
        'oidc.binding',
      );
    });
  });

  describe('the code and PKCE', () => {
    it('fails PKCE when the OP checks the verifier and gets another one (invalid_response)', async () => {
      op.tweak({ expectVerifier: 'not-the-verifier-of-this-flow-0000000000000' });
      await refused(() => signIn('alice'), 'invalid_response', 'oidc.token_endpoint');
    });

    it('refuses a replayed code: a redeemed code under a new flow (invalid_response)', async () => {
      const first = await oapp.begin('alice', { connection: conn });
      expect(sessionOf(await oapp.finish(first, { connection: conn }))).toBeDefined();
      await refused(
        () =>
          signIn('alice', {
            tamper: (u) => u.searchParams.set('code', first.callback.searchParams.get('code')!),
          }),
        'invalid_response',
        'oidc.token_endpoint',
      );
    });

    it('refuses an injected code: another flow’s unredeemed code under this flow’s state (PKCE)', async () => {
      const victims = await oapp.begin('alice', { connection: conn });
      await refused(
        () =>
          signIn('bob', {
            tamper: (u) => u.searchParams.set('code', victims.callback.searchParams.get('code')!),
          }),
        'invalid_response',
        'oidc.token_endpoint',
      );
    });
  });

  describe('the ID token', () => {
    // Offsets are relative to the moment the OP signs, taken when the row runs.
    it.each<[string, Partial<FakeOpTweaks>, string]>([
      ['a wrong nonce', { nonce: 'someone-elses-nonce-000000000000' }, 'oidc.id_token.nonce'],
      // oauth4webapi reports a missing required claim as a malformed response, not a comparison.
      ['a missing nonce', { nonce: null }, 'oidc.invalid_response'],
      ['a wrong iss claim', { idTokenIss: 'https://evil.example' }, 'oidc.id_token.iss'],
      ['a wrong aud', { idTokenAud: 'other-client' }, 'oidc.id_token.aud'],
      ['an expired token (61 s past)', { expOffsetSeconds: -361 }, 'oidc.id_token.exp'],
      // The JWS algorithm is checked against the expected RS256 before anything else.
      ['alg none', { alg: 'none' }, 'oidc.invalid_response'],
      ['HS256 signed with the client secret', { alg: 'HS256' }, 'oidc.invalid_response'],
      [
        'HS256 signed with the RSA public key (key confusion)',
        { alg: 'HS256', hsKey: 'publicKeyPem' },
        'oidc.invalid_response',
      ],
    ])('refuses %s (invalid_response, %s)', async (_name, tweak, detail) => {
      op.tweak(tweak);
      await refused(() => signIn('alice'), 'invalid_response', detail);
    });

    it('refuses two audiences without azp (invalid_response, oidc.id_token.aud)', async () => {
      op.tweak({ idTokenAud: [op.clientId, 'other-client'] });
      await refused(() => signIn('alice'), 'invalid_response', 'oidc.id_token.aud');
    });

    it('refuses two audiences with an azp of another client (invalid_response, oidc.id_token.azp)', async () => {
      op.tweak({ idTokenAud: [op.clientId, 'other-client'], idTokenAzp: 'other-client' });
      await refused(() => signIn('alice'), 'invalid_response', 'oidc.id_token.azp');
    });

    // Fixed in Task 13 fix round 2: oidc-config.ts enables openid-client's non-repudiation checks
    // (the JWS signature, the kid, the key size), and oidcCallback checks what oauth4webapi does
    // not: an `iat` over 60 s ahead, and a present `azp` with a single `aud`.
    it.each<[string, Partial<FakeOpTweaks>, string]>([
      ['an unknown kid', { kid: 'nope' }, 'oidc.key_selection'],
      ['a JWKS with an RSA key of 1024 bits', { rsaBits: 1024 }, 'oidc.unsupported_alg'],
      [
        'RS256 signed by a key the JWKS does not hold (a forged signature)',
        { foreignKey: true },
        'oidc.id_token.signature',
      ],
      ['iat 62 s in the future', { iatOffsetSeconds: 62 }, 'oidc.id_token.iat'],
      ['one aud and an azp of another client', { idTokenAzp: 'other-client' }, 'oidc.id_token.azp'],
    ])('refuses %s (invalid_response, %s)', async (_name, tweak, detail) => {
      op.tweak(tweak);
      await refused(() => signIn('alice'), 'invalid_response', detail);
    });

    // An IdP that advertises HS256 (and none): the metadata check lets the header through, and
    // the asymmetric-only key selection behind it must refuse.
    it.each<[string, Partial<FakeOpTweaks>, string]>([
      ['HS256 signed with the client secret', { alg: 'HS256' }, 'oidc.unsupported_alg'],
      [
        'HS256 keyed with the RSA public key PEM (key confusion)',
        { alg: 'HS256', hsKey: 'publicKeyPem' },
        'oidc.unsupported_alg',
      ],
      ['alg none', { alg: 'none' }, 'oidc.unsupported_alg'],
    ])(
      'refuses %s from an OP advertising RS256, HS256 and none (invalid_response, %s)',
      async (_name, tweak, detail) => {
        op.tweak({ signingAlgs: ['RS256', 'HS256', 'none'], ...tweak });
        forgetOidcConfiguration(conn);
        await refused(() => signIn('alice'), 'invalid_response', detail);
      },
    );

    it.each<[string, Partial<FakeOpTweaks>]>([
      ['exp 50 s past', { expOffsetSeconds: -350 }],
      ['iat 50 s ahead', { iatOffsetSeconds: 50 }],
      // The boundary of the 60 s the product allows: iat = now + 60 at signing, never later.
      ['iat 60 s ahead', { iatOffsetSeconds: 60 }],
    ])('accepts %s (60 s of tolerance)', async (_name, tweak) => {
      op.tweak(tweak);
      const res = await signIn('alice');
      expect(res.headers.location).toBe('/projects');
      expect(sessionOf(res)).toBeDefined();
    });
  });

  describe('the issuer (mix-up) and the endpoints', () => {
    it('refuses an iss parameter of another issuer while advertised (invalid_response, oidc.iss_param)', async () => {
      op.tweak({ advertiseIssParam: true, issParam: 'https://evil.example' });
      await refused(() => signIn('alice'), 'invalid_response', 'oidc.iss_param');
    });

    it('refuses a missing iss parameter while advertised (invalid_response, oidc.iss_param)', async () => {
      op.tweak({ advertiseIssParam: true });
      await refused(
        () => signIn('alice', { tamper: (u) => u.searchParams.delete('iss') }),
        'invalid_response',
        'oidc.iss_param',
      );
    });

    it('refuses a discovery document naming another issuer: the start and a pending callback are unavailable', async () => {
      const pending = await oapp.begin('alice', { connection: conn });
      op.tweak({ issuerInDiscovery: 'https://evil.example' });
      forgetOidcConfiguration(conn);
      const loaded = (await loadConnection(ctx.db, conn, ctx.config.secretKey))!;
      const reply = { setCookie: () => reply } as never;
      await expect(
        startOidc(flowDeps(ctx), { protocol: 'https' } as never, reply, loaded, {
          returnTo: '/',
          link: null,
        }),
      ).rejects.toMatchObject({ code: 'unavailable', detail: 'oidc.discovery' });
      await refused(
        () => oapp.finish(pending, { connection: conn }),
        'unavailable',
        'oidc.discovery',
      );
    });

    it('refuses a discovery document without jwks_uri: the start is unavailable (oidc.discovery)', async () => {
      op.tweak({ omitJwksUri: true });
      forgetOidcConfiguration(conn);
      const loaded = (await loadConnection(ctx.db, conn, ctx.config.secretKey))!;
      const reply = { setCookie: () => reply } as never;
      await expect(
        startOidc(flowDeps(ctx), { protocol: 'https' } as never, reply, loaded, {
          returnTo: '/',
          link: null,
        }),
      ).rejects.toMatchObject({ code: 'unavailable', detail: 'oidc.discovery' });
    });

    it('refuses a token endpoint on a private address, sending nothing (oidc.fetch.not_public)', async () => {
      op.tweak({ tokenEndpoint: 'http://10.0.0.7/token' });
      const before = op.lastTokenRequest();
      await refused(() => signIn('alice'), 'invalid_response', 'oidc.fetch.not_public');
      expect(op.lastTokenRequest()).toBe(before);
    });

    it('refuses a token endpoint whose name resolves to a private address (oidc.fetch.not_public)', async () => {
      op.tweak({ tokenEndpoint: 'https://idp-internal.example/token' });
      const resolved: string[] = [];
      callbackDeps = () => ({
        ...flowDeps(ctx),
        // The fake OP's own address stays itself; the token endpoint's name is the private one.
        resolve: (hostname: string) => {
          resolved.push(hostname);
          const address = hostname === '127.0.0.1' ? '127.0.0.1' : '10.0.0.7';
          return Promise.resolve([{ address, family: 4 }]);
        },
      });
      const before = op.lastTokenRequest();
      // The start cached a discovery without the resolver: drop it, so that the callback's own
      // (with the resolver) is the one that meets the token endpoint. No real DNS query is made.
      await refused(
        () => signIn('alice', { tamper: () => forgetOidcConfiguration(conn) }),
        'invalid_response',
        'oidc.fetch.not_public',
      );
      expect(resolved).toContain('idp-internal.example');
      expect(op.lastTokenRequest()).toBe(before);
    });

    it('refuses a 302 from the token endpoint, following nothing (oidc.token_endpoint)', async () => {
      op.tweak({ redirectFromToken: true });
      await refused(() => signIn('alice'), 'invalid_response', 'oidc.token_endpoint');
    });
  });

  describe('linking and returnTo', () => {
    it('does not link on email_verified "true" (a string) with linkByEmail on: JIT without the email', async () => {
      const linking = await oidcConnection(ctx, {
        name: 'Linking',
        enabled: true,
        issuer: op.issuer,
        clientId: op.clientId,
        clientSecret: op.clientSecret,
        linkByEmail: true,
      });
      const carol = await createUser(ctx, { username: 'carol-local', email: 'carol@acme.example' });
      op.users.set('carol', {
        sub: 'carol-sub',
        email: 'carol@acme.example',
        email_verified: 'true',
        preferred_username: 'carol',
        name: 'Carol C',
        groups: [],
      });
      const res = await oapp.signIn('carol', { connection: linking });
      expect(res.statusCode).toBe(303);
      expect(res.headers.location).toBe('/projects');
      expect(await ctx.db.select().from(identities).where(eq(identities.userId, carol.id))).toEqual(
        [],
      );
      const [made] = await ctx.db
        .select({ id: users.id, email: users.email })
        .from(identities)
        .innerJoin(users, eq(users.id, identities.userId))
        .where(and(eq(identities.connectionId, linking), eq(identities.subject, 'carol-sub')));
      expect(made!.id).not.toBe(carol.id);
      expect(made!.email).toBeNull();
    });

    it.each(['//evil.example', 'https://evil.example', '/\\evil.example'])(
      'sends returnTo=%s to /',
      async (returnTo) => {
        const res = await signIn('alice', { returnTo });
        expect(res.statusCode).toBe(303);
        expect(res.headers.location).toBe('/');
      },
    );
  });
});
