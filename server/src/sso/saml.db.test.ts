import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { and, eq, sql } from 'drizzle-orm';
import type { LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createUser, type TestContext } from '../../test/app';
import {
  buildResponse,
  encryptAssertion,
  STRANGER,
  TEST_IDP,
  TEST_SP,
  type SamlResponseOptions,
} from '../../test/saml';
import {
  auditRows,
  connectionDeps,
  licensedEdition,
  ONE_CONNECTION_FEATURES,
  samlConnection,
  samlTestApp,
  sessionHeaders,
  ssoContext,
  type SamlStarted,
  type SamlTestApp,
} from '../../test/sso';
import { flowDeps } from '../../test/sso-flow';
import type { FlowDeps } from './complete';
import { SYSTEM_ACTOR } from '../audit/recorder';
import {
  identities,
  memberships,
  organizations,
  ssoConnections,
  ssoStates,
  users,
} from '../db/schema';
import { createConnection, loadConnection } from './connections';
import { replaceMappings } from './groups';
import {
  FINISH_MAX_BYTES,
  jsonbTextBytes,
  readSamlMetadata,
  type FinishPayload,
  spMetadata,
  startSaml,
} from './saml';
import { stateKey } from './states';
import { ssoUrls } from './urls';

const PUBLIC_URL = 'https://q.example';
const RSA_SHA1 = 'http://www.w3.org/2000/09/xmldsig#rsa-sha1';
const RESPONDER = 'urn:oasis:names:tc:SAML:2.0:status:Responder';
const GOOGLE_SSO = 'https://accounts.google.com/o/saml2/idp?idpid=C01abc234';

/** The base64 body of a PEM certificate. */
const certBody = (pem: string) => pem.replace(/-----[A-Z ]+-----/g, '').replace(/\s+/g, '');

function metadataXml(certs: string[], comment = true): string {
  const keys = certs
    .map(
      (c, i) =>
        `<md:KeyDescriptor${i === 0 ? ' use="signing"' : ''}><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${certBody(c)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>`,
    )
    .join('');
  return (
    `<?xml version="1.0" encoding="UTF-8"?>` +
    (comment ? '<!-- Shibboleth writes comments: > < " -->' : '') +
    `<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.meta/saml">` +
    `<md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
    keys +
    `<md:KeyDescriptor use="encryption"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>${certBody(TEST_SP.certPem)}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>` +
    `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://idp.meta/post"/>` +
    `<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.meta/sso?appid=a1"/>` +
    `</md:IDPSSODescriptor></md:EntityDescriptor>`
  );
}

describe('SAML sign-in (sso-scim.md §6, §7)', () => {
  let ctx: TestContext;
  let sapp: SamlTestApp;
  let metadataServer: Server;
  let metadataBase: string;
  /** jit, groups from the `groups` attribute, qualor-admins → default org admin, verified email. */
  let conn: string;
  /** An SP key pair: signed requests, encrypted assertions. */
  let keyed: string;
  /** Google's SSO URL, with its `?idpid=` query. */
  let google: string;
  /** requires `department` = eng. */
  let strict: string;
  /** Reads its metadata from the local server. */
  let withMetadata: string;
  let tooMany: string;
  let defaultOrg: string;
  let acsUrl: string;
  let entityId: string;
  /** When set, replaces flowDeps(ctx) at the ACS (a test's edition). */
  let acsDeps: (() => FlowDeps) | null = null;

  beforeAll(async () => {
    metadataServer = createServer((req, res) => {
      res
        .writeHead(200, { 'content-type': 'application/samlmetadata+xml' })
        .end(metadataXml([TEST_IDP.certPem, STRANGER.certPem]));
    });
    await new Promise<void>((resolve) => metadataServer.listen(0, '127.0.0.1', resolve));
    const { port } = metadataServer.address() as AddressInfo;
    metadataBase = `http://127.0.0.1:${String(port)}`;

    ctx = await ssoContext({
      // The test licence is issued 2026-10-01: the edition's clock is inside it (the rest is real).
      now: () => new Date('2027-01-01T00:00:00Z'),
      config: { ssoInternalHosts: new Set([`127.0.0.1:${String(port)}`]) },
    });
    conn = await samlConnection(ctx, {
      enabled: true,
      groupSource: 'claims',
      emailVerified: true,
    });
    google = await samlConnection(ctx, { enabled: true, name: 'Google', idpSsoUrl: GOOGLE_SSO });
    strict = await samlConnection(ctx, {
      enabled: true,
      name: 'Strict',
      requiredClaims: [{ claim: 'department', value: 'eng' }],
    });
    tooMany = await samlConnection(ctx, { enabled: true, name: 'Groups', groupSource: 'claims' });
    const deps = connectionDeps(ctx);
    keyed = (
      await createConnection(deps, SYSTEM_ACTOR, {
        name: 'Keyed',
        protocol: 'saml',
        enabled: true,
        saml: {
          idpEntityId: 'https://idp.test/saml',
          idpSsoUrl: 'https://idp.test/sso',
          idpCertificates: [TEST_IDP.certPem],
          emailVerified: true,
          spKey: TEST_SP.keyPem,
          spCertificate: TEST_SP.certPem,
        },
      })
    ).id;
    withMetadata = (
      await createConnection(deps, SYSTEM_ACTOR, {
        name: 'Metadata',
        protocol: 'saml',
        saml: {
          idpEntityId: 'https://idp.test/saml',
          idpSsoUrl: 'https://idp.test/sso',
          idpCertificates: [TEST_IDP.certPem],
          metadataUrl: `${metadataBase}/metadata`,
        },
      })
    ).id;
    ({ acsUrl, entityId } = ssoUrls(PUBLIC_URL, conn));
    const [org] = await ctx.db
      .select({ id: organizations.id })
      .from(organizations)
      .where(eq(organizations.key, 'default'));
    defaultOrg = org!.id;
    await replaceMappings({ db: ctx.db, audit: flowDeps(ctx).audit }, SYSTEM_ACTOR, conn, [
      { group: 'qualor-admins', organizationId: defaultOrg, projectId: null, role: 'admin' },
    ]);

    sapp = await samlTestApp(ctx, { acsDeps: () => acsDeps?.() ?? null });
  });
  afterAll(async () => {
    await sapp.close();
    await ctx.close();
    await new Promise<void>((resolve) => metadataServer.close(() => resolve()));
  });

  type Started = SamlStarted;

  const start = (connection = conn, query = ''): Promise<Started> => sapp.start(connection, query);
  const post = (b64: string, relay: string, connection = conn) => sapp.post(b64, relay, connection);
  const finish = (location: string, sso?: string, extra: Record<string, string> = {}) =>
    sapp.finish(location, sso, extra);
  /** A correct response to `s` for `connection`, with `over` changed. */
  const respond = (s: Started, over: SamlResponseOptions = {}, connection = conn) => {
    const urls = ssoUrls(PUBLIC_URL, connection);
    return buildResponse({
      inResponseTo: s.id,
      audience: urls.entityId,
      recipient: urls.acsUrl,
      destination: urls.acsUrl,
      ...over,
    });
  };
  /** Start, post a response built with `over`, and return both. */
  async function acsWith(over: SamlResponseOptions = {}, connection = conn) {
    const s = await start(connection);
    const acs = await post(respond(s, over, connection), s.relay, connection);
    return { s, acs };
  }
  /** The whole flow; the finish answer. */
  async function signIn(over: SamlResponseOptions = {}, connection = conn) {
    const { s, acs } = await acsWith(over, connection);
    expect(acs.statusCode).toBe(303);
    const location = acs.headers.location as string;
    if (!location.startsWith('/api/v0/ee/sso/finish')) return acs;
    return finish(location, s.sso);
  }

  const sessionOf = (res: LightMyRequestResponse) =>
    res.cookies.find((c) => c.name === 'qualor_session');

  /** The last `single sign-on failed` line's reason and detail. */
  function lastFailure(): { reason: string; detail: string } {
    const line = ctx.logs.filter((l) => l.includes('single sign-on failed')).at(-1);
    const parsed = JSON.parse(line ?? '{}') as { reason?: string; detail?: string };
    return { reason: parsed.reason ?? '', detail: parsed.detail ?? '' };
  }

  async function identityOf(connection: string, subject: string) {
    const [row] = await ctx.db
      .select()
      .from(identities)
      .where(and(eq(identities.connectionId, connection), eq(identities.subject, subject)));
    return row;
  }

  const person = (login: string, over: SamlResponseOptions = {}): SamlResponseOptions => ({
    nameId: `${login}-id`,
    attributes: { email: [`${login}@acme.example`], displayName: [login], groups: [] },
    ...over,
  });

  it('sends an unsigned AuthnRequest to the SSO URL with the ACS URL and the NameID format', async () => {
    const { request, url, id, relay, sso } = await start();
    expect(request).toContain(`AssertionConsumerServiceURL="${acsUrl}"`);
    expect(request).toContain('Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"');
    expect(request).toContain(
      `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">${entityId}</saml:Issuer>`,
    );
    expect(request).toContain('Destination="https://idp.test/sso"');
    expect(request).not.toContain('RequestedAuthnContext');
    expect(id).toMatch(/^_[0-9a-f]{64}$/);
    expect(url.origin + url.pathname).toBe('https://idp.test/sso');
    expect(url.searchParams.get('SigAlg')).toBeNull();
    expect(url.searchParams.get('Signature')).toBeNull();
    // RelayState is an opaque 32-byte reference, never a URL.
    expect(relay).toMatch(/^[A-Za-z0-9_-]{43}$/);
    const [row] = await ctx.db
      .select()
      .from(ssoStates)
      .where(eq(ssoStates.key, stateKey('saml-request', id)));
    expect(row).toMatchObject({ kind: 'saml-request', connectionId: conn });
    expect(row!.payload).toMatchObject({ relay, intent: 'sign_in', returnTo: '/projects' });
    expect(JSON.stringify(row!.payload)).not.toContain(sso);
  });

  it('keeps the query of a Google-style SSO URL when it adds SAMLRequest and RelayState', async () => {
    const { url, request } = await start(google);
    expect(url.origin + url.pathname).toBe('https://accounts.google.com/o/saml2/idp');
    expect(url.searchParams.get('idpid')).toBe('C01abc234');
    expect(url.searchParams.get('SAMLRequest')).toBeTruthy();
    expect(url.searchParams.get('RelayState')).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect([...url.searchParams.keys()]).toEqual(['idpid', 'SAMLRequest', 'RelayState']);
    expect(request).toContain(`Destination="${GOOGLE_SSO.replace('&', '&amp;')}"`);
  });

  it('signs the AuthnRequest (rsa-sha256) when the connection has an SP key', async () => {
    const { url } = await start(keyed);
    expect(url.searchParams.get('SigAlg')).toBe(
      'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    );
    expect(url.searchParams.get('Signature')).toMatch(/^[A-Za-z0-9+/]+=*$/);
  });

  it('signs alice in: ACS → finish → session, with the account, the membership and the audit rows', async () => {
    const before = (await auditRows(ctx)).length;
    const s = await start();
    const acs = await post(
      buildResponse({
        inResponseTo: s.id,
        audience: entityId,
        recipient: acsUrl,
        destination: acsUrl,
      }),
      s.relay,
    );
    expect(acs.statusCode).toBe(303);
    expect(acs.headers.location).toMatch(/^\/api\/v0\/ee\/sso\/finish\?code=[A-Za-z0-9_-]{43}$/);
    // Nothing is resolved at the ACS: the cross-site POST carries no binding cookie (§6.4).
    expect(await identityOf(conn, 'alice-persistent-id')).toBeUndefined();
    const done = await finish(acs.headers.location as string, s.sso);
    expect(done.statusCode).toBe(303);
    expect(done.headers.location).toBe('/projects');
    expect(sessionOf(done)?.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(done.cookies.find((c) => c.name === 'qualor_sso')?.value).toBe('');

    const identity = (await identityOf(conn, 'alice-persistent-id'))!;
    expect(identity.linkedBy).toBe('jit');
    const [alice] = await ctx.db.select().from(users).where(eq(users.id, identity.userId));
    expect(alice).toMatchObject({
      email: 'alice@acme.example',
      displayName: 'Alice A',
      passwordHash: null,
    });
    const [membership] = await ctx.db
      .select()
      .from(memberships)
      .where(and(eq(memberships.userId, alice!.id), eq(memberships.organizationId, defaultOrg)));
    expect(membership).toMatchObject({ role: 'admin', managedByConnectionId: conn });
    const rows = (await auditRows(ctx)).slice(before);
    expect(rows.map((r) => r.action)).toEqual([
      'sso.user_provisioned',
      'member.added',
      'auth.sign_in',
    ]);
    expect(rows[2]).toMatchObject({
      actorUserId: alice!.id,
      details: { method: 'saml', connectionId: conn },
    });
    // The finish row carried the NameID (SignInClaims.nameId).
    expect(identity.subject).toBe('alice-persistent-id');
  });

  it('refuses the same response twice', async () => {
    const s = await start();
    const body = buildResponse({
      inResponseTo: s.id,
      audience: entityId,
      recipient: acsUrl,
      destination: acsUrl,
    });
    await post(body, s.relay);
    expect((await post(body, s.relay)).headers.location).toBe('/login?sso_error=flow_expired');
  });

  it('refuses a replayed assertion under a new request (replayed)', async () => {
    const first = await acsWith({ assertionId: '_replayed-assertion-1' });
    expect(first.acs.headers.location).toMatch(/^\/api\/v0\/ee\/sso\/finish/);
    const again = await acsWith({ assertionId: '_replayed-assertion-1' });
    expect(again.acs.headers.location).toBe('/login?sso_error=replayed');
    expect(lastFailure()).toEqual({ reason: 'replayed', detail: 'saml.replayed' });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.sign_in_failed',
      details: { connectionId: conn, protocol: 'saml', reason: 'replayed' },
    });
  });

  it('refuses the finish code in another browser, and a second use', async () => {
    const s = await start();
    const acs = await post(
      buildResponse({
        inResponseTo: s.id,
        audience: entityId,
        recipient: acsUrl,
        destination: acsUrl,
      }),
      s.relay,
    );
    expect((await finish(acs.headers.location as string)).headers.location).toBe(
      '/login?sso_error=flow_mismatch',
    );
    expect(lastFailure()).toEqual({ reason: 'flow_mismatch', detail: 'flow.binding' });
    expect((await finish(acs.headers.location as string, s.sso)).headers.location).toBe(
      '/login?sso_error=flow_expired',
    );
    // An unknown code names no connection: logged and redirected, not recorded.
    const rowsBefore = (await auditRows(ctx)).length;
    const unknown = await finish(`/api/v0/ee/sso/finish?code=${'A'.repeat(43)}`, s.sso);
    expect(unknown.headers.location).toBe('/login?sso_error=flow_expired');
    expect((await auditRows(ctx)).length).toBe(rowsBefore);
  });

  it('refuses a RelayState that differs from the flow (flow_mismatch), and the flow is burnt', async () => {
    const s = await start();
    const body = respond(s);
    const wrong = await post(body, 'B'.repeat(43));
    expect(wrong.headers.location).toBe('/login?sso_error=flow_mismatch');
    expect(lastFailure().detail).toBe('saml.relay');
    expect((await post(body, s.relay)).headers.location).toBe('/login?sso_error=flow_expired');
  });

  it('refuses a wrong InResponseTo, none (IdP-initiated), and a request of another connection', async () => {
    const s = await start();
    const unknown = await post(respond(s, { inResponseTo: '_not-a-request' }), s.relay);
    expect(unknown.headers.location).toBe('/login?sso_error=flow_expired');
    expect(lastFailure().detail).toBe('saml.request_unknown');

    const idp = await post(respond(s, { inResponseTo: null }), s.relay);
    expect(idp.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('saml.in_response_to');

    // The subject confirmation answering another request than the response does.
    const mixed = await post(respond(s, { subjectInResponseTo: '_other' }), s.relay);
    expect(mixed.headers.location).toBe('/login?sso_error=invalid_response');

    const other = await start(google);
    const cross = await post(respond(other), other.relay);
    expect(cross.headers.location).toBe('/login?sso_error=flow_expired');
    expect(lastFailure().detail).toBe('saml.request_unknown');
  });

  it.each<[string, SamlResponseOptions, string]>([
    ['a wrong Audience', { audience: 'https://evil.example/sp' }, 'saml.validate'],
    [
      'a wrong Recipient',
      { recipient: 'https://evil.example/acs', destination: undefined },
      'saml.recipient',
    ],
    ['a wrong Destination', { destination: 'https://evil.example/acs' }, 'saml.destination'],
    [
      'a wrong assertion Issuer (signed by the pinned key; node-saml does not check it)',
      { issuer: 'https://evil.example/idp', responseIssuer: 'https://idp.test/saml' },
      'saml.issuer',
    ],
    ['a wrong response Issuer', { responseIssuer: 'https://evil.example/idp' }, 'saml.issuer'],
    ['an unsigned assertion', { signAssertion: false }, 'saml.validate'],
    [
      'a signed response with an unsigned assertion',
      { signAssertion: false, signResponse: true },
      'saml.validate',
    ],
    [
      'another key with its certificate in KeyInfo',
      { key: STRANGER.keyPem, cert: STRANGER.certPem },
      'saml.validate',
    ],
    [
      'the pinned certificate in KeyInfo, another key',
      { key: STRANGER.keyPem, keyInfoCert: TEST_IDP.certPem },
      'saml.validate',
    ],
    ['no AuthnStatement', { authnStatement: false }, 'saml.authn_statement'],
    [
      'a holder-of-key confirmation only',
      { confirmationMethod: 'urn:oasis:names:tc:SAML:2.0:cm:holder-of-key' },
      'saml.subject_confirmation',
    ],
    [
      'another NameID format',
      { nameIdFormat: 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress' },
      'saml.name_id_format',
    ],
    ['a NameID over 255 characters', { nameId: 'n'.repeat(256) }, 'saml.name_id'],
  ])('refuses %s (invalid_response, %s)', async (_name, over, detail) => {
    const { acs } = await acsWith(over);
    expect(acs.headers.location).toBe('/login?sso_error=invalid_response');
    expect(sessionOf(acs)).toBeUndefined();
    expect(lastFailure()).toEqual({ reason: 'invalid_response', detail });
  });

  it('accepts a response signed as a whole besides its signed assertion', async () => {
    const both = await signIn({ signResponse: true });
    expect(both.statusCode).toBe(303);
    expect(sessionOf(both)).toBeDefined();
  });

  // §19.3: 60 s of skew. The times are taken when each response is built, never at collection.
  it.each<[string, () => SamlResponseOptions]>([
    ['NotOnOrAfter 61 s past', () => ({ notOnOrAfter: new Date(Date.now() - 61_000) })],
    ['NotBefore 61 s ahead', () => ({ notBefore: new Date(Date.now() + 61_000) })],
  ])('refuses %s (invalid_response)', async (_name, over) => {
    const { acs } = await acsWith(over());
    expect(acs.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure()).toEqual({ reason: 'invalid_response', detail: 'saml.validate' });
  });

  it.each<[string, () => SamlResponseOptions]>([
    ['NotOnOrAfter 59 s past', () => ({ notOnOrAfter: new Date(Date.now() - 59_000) })],
    ['NotBefore 59 s ahead', () => ({ notBefore: new Date(Date.now() + 59_000) })],
  ])('accepts %s', async (_name, over) => {
    expect(sessionOf(await signIn(over()))).toBeDefined();
  });

  const precheckCases: [string, SamlResponseOptions, string][] = [
    [
      'a DOCTYPE',
      { transform: (x) => `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>${x}` },
      'doctype',
    ],
    [
      'a processing instruction',
      { transform: (x) => x.replace('<samlp:Status>', '<?evil x?><samlp:Status>') },
      'processing_instruction',
    ],
    [
      'a comment inside the NameID',
      { transform: (x) => x.replace('alice-persistent-id', 'alice<!---->-persistent-id') },
      'comment',
    ],
    ['a CDATA section', { transform: (x) => x.replace('Alice A', '<![CDATA[Alice A]]>') }, 'cdata'],
    [
      'a malformed document',
      { transform: (x) => x.replace('</samlp:Response>', '</samlp:Respons>') },
      'malformed',
    ],
    [
      'another root element',
      { transform: (x) => x.replaceAll('samlp:Response', 'samlp:ArtifactResponse') },
      'not_response',
    ],
    [
      'nesting of 40',
      { transform: (x) => x.replace('Alice A', `${'<x>'.repeat(40)}${'</x>'.repeat(40)}`) },
      'too_complex',
    ],
    [
      'a second assertion',
      {
        transform: (x) =>
          x.replace('</samlp:Response>', '<saml:Assertion ID="_second"/></samlp:Response>'),
      },
      'assertion_count',
    ],
    ['an rsa-sha1 signature', { signatureAlgorithm: RSA_SHA1 }, 'signature_shape'],
    [
      'a __proto__ element',
      { transform: (x) => x.replace('<samlp:Status>', '<__proto__/><samlp:Status>') },
      'forbidden_name',
    ],
    [
      'a duplicate ID',
      {
        assertionId: '_dup-id',
        transform: (x) => x.replace('<saml:Subject>', '<saml:Subject ID="_dup-id">'),
      },
      'duplicate_id',
    ],
    [
      'an EncryptedAssertion without an SP key',
      { encryptFor: TEST_SP.certPem },
      'encrypted_without_key',
    ],
    ['a NUL in the NameID', { nameId: `alice${String.fromCharCode(0)}x` }, 'malformed'],
    [
      'a lone surrogate in the email',
      { transform: (x) => x.replace('alice@acme.example', 'alice&#xD800;@acme.example') },
      'malformed',
    ],
  ];
  it.each(precheckCases)(
    'refuses %s at the pre-check (invalid_response, saml.precheck.%s)',
    async (_name, over, code) => {
      const { acs } = await acsWith(over);
      expect(acs.headers.location).toBe('/login?sso_error=invalid_response');
      expect(lastFailure()).toEqual({
        reason: 'invalid_response',
        detail: `saml.precheck.${code}`,
      });
    },
  );

  it('refuses a body that is not strict base64, and one over the size bound, at the pre-check', async () => {
    const s = await start();
    expect((await post('%%%not base64', s.relay)).headers.location).toBe(
      '/login?sso_error=invalid_response',
    );
    expect(lastFailure().detail).toBe('saml.precheck.base64');
    expect((await post('A'.repeat(360_000), s.relay)).headers.location).toBe(
      '/login?sso_error=invalid_response',
    );
    expect(lastFailure().detail).toBe('saml.precheck.too_large');
  });

  it('refuses a form without SAMLResponse or RelayState, or with either twice (saml.form)', async () => {
    const s = await start();
    const body = respond(s);
    for (const payload of [
      new URLSearchParams({ SAMLResponse: body }).toString(),
      new URLSearchParams({ RelayState: s.relay }).toString(),
      `SAMLResponse=${encodeURIComponent(body)}&SAMLResponse=x&RelayState=${s.relay}`,
    ]) {
      const res = await sapp.app.inject({
        method: 'POST',
        url: `/acs/${conn}`,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload,
      });
      expect(res.headers.location).toBe('/login?sso_error=invalid_response');
      expect(lastFailure().detail).toBe('saml.form');
    }
  });

  it('passes an IdP refusal through as idp_error, with or without an assertion', async () => {
    const bare = await acsWith({
      status: RESPONDER,
      transform: (x) => x.replace(/<saml:Assertion[\s\S]*<\/saml:Assertion>/, ''),
    });
    expect(bare.acs.headers.location).toBe('/login?sso_error=idp_error');
    expect(lastFailure()).toEqual({ reason: 'idp_error', detail: 'saml.status' });
    const withAssertion = await acsWith({ status: RESPONDER });
    expect(withAssertion.acs.headers.location).toBe('/login?sso_error=idp_error');
  });

  it('accepts an EncryptedAssertion on a connection with an SP key, and refuses RSA PKCS#1 v1.5', async () => {
    const res = await signIn(person('enc', { encryptFor: TEST_SP.certPem }), keyed);
    expect(res.statusCode).toBe(303);
    expect(sessionOf(res)).toBeDefined();
    expect(await identityOf(keyed, 'enc-id')).toBeDefined();

    const weak = await acsWith(
      person('enc', {
        encryptFor: TEST_SP.certPem,
        transform: (x) =>
          x.replace(
            'http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p',
            'http://www.w3.org/2001/04/xmlenc#rsa-1_5',
          ),
      }),
      keyed,
    );
    expect(weak.acs.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('saml.encryption');

    // Encrypted for another key: nothing decrypts.
    const other = await acsWith(person('enc', { encryptFor: TEST_IDP.certPem }), keyed);
    expect(other.acs.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('saml.decrypt');

    // An unsigned assertion inside the encryption is still unsigned.
    const unsigned = await acsWith(
      person('enc', { encryptFor: TEST_SP.certPem, signAssertion: false }),
      keyed,
    );
    expect(unsigned.acs.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('saml.validate');
  });

  it('pre-checks the decrypted assertion before node-saml reads it', async () => {
    // A signed assertion with a comment put into its NameID, then encrypted: the outer document
    // passes the pre-check, the plaintext must not.
    const s = await start(keyed);
    const plain = Buffer.from(
      respond(s, person('enc', { assertionId: '_encc' }), keyed),
      'base64',
    ).toString('utf8');
    const assertion = /<saml:Assertion[\s\S]*<\/saml:Assertion>/
      .exec(plain)![0]
      .replace('enc-id', 'enc<!---->-id');
    const xml = plain.replace(
      /<saml:Assertion[\s\S]*<\/saml:Assertion>/,
      encryptAssertion(assertion, TEST_SP.certPem),
    );
    const acs = await post(Buffer.from(xml).toString('base64'), s.relay, keyed);
    expect(acs.headers.location).toBe('/login?sso_error=invalid_response');
    // The same detail as a failed decryption: no padding or format oracle (AES-CBC).
    expect(lastFailure().detail).toBe('saml.decrypt');
  });

  const FOREIGN = 'urn:example:not-xmlenc';
  it.each<[string, (xml: string) => string]>([
    [
      'a foreign-namespace rsa-1_5 EncryptionMethod first in EncryptedKey',
      (x) =>
        x.replace(
          '<xenc:EncryptedKey>',
          `<xenc:EncryptedKey><f:EncryptionMethod xmlns:f="${FOREIGN}" Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>`,
        ),
    ],
    [
      'a foreign-namespace tripledes-cbc EncryptionMethod first in EncryptedData',
      (x) =>
        x.replace(
          '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>',
          `<f:EncryptionMethod xmlns:f="${FOREIGN}" Algorithm="http://www.w3.org/2001/04/xmlenc#tripledes-cbc"/><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>`,
        ),
    ],
    [
      'a foreign-namespace RetrievalMethod',
      (x) =>
        x.replace(
          '<xenc:EncryptedKey>',
          `<f:RetrievalMethod xmlns:f="${FOREIGN}" URI="#k"/><xenc:EncryptedKey>`,
        ),
    ],
    [
      'a foreign-namespace CipherValue before the key',
      (x) =>
        x.replace(
          '<xenc:EncryptedKey>',
          `<xenc:EncryptedKey><f:CipherValue xmlns:f="${FOREIGN}">AAAA</f:CipherValue>`,
        ),
    ],
    [
      'an xmldsig RetrievalMethod',
      (x) => x.replace('<xenc:EncryptedKey>', '<ds:RetrievalMethod URI="#k"/><xenc:EncryptedKey>'),
    ],
    [
      'a second EncryptedKey',
      (x) => {
        const key = /<xenc:EncryptedKey>[\s\S]*<\/xenc:EncryptedKey>/.exec(x)![0];
        return x.replace(key, key + key);
      },
    ],
  ])('refuses %s before decrypting (saml.encryption)', async (_name, transform) => {
    const { acs } = await acsWith(person('enc', { encryptFor: TEST_SP.certPem, transform }), keyed);
    expect(acs.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure()).toEqual({ reason: 'invalid_response', detail: 'saml.encryption' });
  });

  it('bounds the finish row as the database measures it (octet_length of the jsonb text)', async () => {
    const nameId = 'hugo-id';
    const email = 'hugo@acme.example';
    const displayName = 'Hugo';
    // What the ACS will store, with values of the same lengths (relay 43, binding 64 characters).
    const payloadFor = (groups: string[]): FinishPayload => ({
      claims: {
        subject: nameId,
        username: nameId,
        email,
        emailVerified: false,
        displayName,
        groups,
        nameId,
      },
      flow: {
        connectionId: tooMany,
        returnTo: '/projects',
        intent: 'sign_in',
        linkUserId: null,
        binding: 'b'.repeat(64),
        relay: 'r'.repeat(43),
      },
    });
    const groupsOf = (target: number): string[] => {
      const groups: string[] = [];
      const next = () => `group-${String(groups.length).padStart(4, '0')}-${'x'.repeat(50)}`;
      while (jsonbTextBytes(payloadFor([...groups, next()])) <= target) groups.push(next());
      const last = groups.length - 1;
      groups[last] += 'y'.repeat(target - jsonbTextBytes(payloadFor(groups)));
      expect(jsonbTextBytes(payloadFor(groups))).toBe(target);
      return groups;
    };
    const attributes = (groups: string[]) => ({
      email: [email],
      displayName: [displayName],
      groups,
    });

    const under = await acsWith(
      { nameId, attributes: attributes(groupsOf(FINISH_MAX_BYTES)) },
      tooMany,
    );
    const location = under.acs.headers.location as string;
    expect(location).toMatch(/^\/api\/v0\/ee\/sso\/finish\?code=/);
    const code = new URL(location, 'https://q.example').searchParams.get('code')!;
    const result = await ctx.db.execute(
      sql`SELECT octet_length(payload::text) AS n FROM sso_states WHERE key = ${stateKey('finish', code)}`,
    );
    expect(Number((result.rows[0] as { n: unknown }).n)).toBe(FINISH_MAX_BYTES);

    const over = await acsWith(
      { nameId, attributes: attributes(groupsOf(FINISH_MAX_BYTES + 1)) },
      tooMany,
    );
    expect(over.acs.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure()).toEqual({
      reason: 'invalid_response',
      detail: 'saml.claims_too_large',
    });
  });

  it('refuses a disabled connection (unavailable), at the start and at the ACS', async () => {
    const s = await start();
    await ctx.db.update(ssoConnections).set({ enabled: false }).where(eq(ssoConnections.id, conn));
    try {
      const acs = await post(respond(s), s.relay);
      expect(acs.headers.location).toBe('/login?sso_error=unavailable');
      expect(lastFailure()).toEqual({ reason: 'unavailable', detail: 'saml.disabled' });
      const loaded = (await loadConnection(ctx.db, conn, ctx.config.secretKey))!;
      const reply = { setCookie: () => reply } as never;
      await expect(
        startSaml(flowDeps(ctx), { protocol: 'https' } as never, reply, loaded, {
          returnTo: '/',
          link: null,
        }),
      ).rejects.toMatchObject({ code: 'unavailable', detail: 'saml.disabled' });
    } finally {
      await ctx.db.update(ssoConnections).set({ enabled: true }).where(eq(ssoConnections.id, conn));
    }
  });

  it('refuses a connection not in effect (unavailable, saml.not_in_effect), at the start and at the ACS', async () => {
    // A key without sso.multi (sso-scim.md §4.4): only the oldest enabled connection, `conn`,
    // is in effect, so `google` is not. A flow started before the licence changed fails at the ACS.
    const business = licensedEdition(
      ONE_CONNECTION_FEATURES,
      () => new Date('2027-01-01T00:00:00Z'),
    );
    const businessDeps = (): FlowDeps => ({ ...flowDeps(ctx), edition: business });
    const s = await start(google);
    acsDeps = businessDeps;
    try {
      const acs = await post(respond(s, {}, google), s.relay, google);
      expect(acs.headers.location).toBe('/login?sso_error=unavailable');
      expect(sessionOf(acs)).toBeUndefined();
      expect(lastFailure()).toEqual({ reason: 'unavailable', detail: 'saml.not_in_effect' });
      const loaded = (await loadConnection(ctx.db, google, ctx.config.secretKey))!;
      const reply = { setCookie: () => reply } as never;
      await expect(
        startSaml(businessDeps(), { protocol: 'https' } as never, reply, loaded, {
          returnTo: '/',
          link: null,
        }),
      ).rejects.toMatchObject({ code: 'unavailable', detail: 'saml.not_in_effect' });
      // The connection in effect still signs people in under the same key.
      const done = await signIn(person('nie-alice'));
      expect(done.statusCode).toBe(303);
      expect(sessionOf(done)).toBeDefined();
    } finally {
      acsDeps = null;
    }
  });

  it('refuses a disabled connection at the finish step too', async () => {
    const { s, acs } = await acsWith();
    await ctx.db.update(ssoConnections).set({ enabled: false }).where(eq(ssoConnections.id, conn));
    try {
      const done = await finish(acs.headers.location as string, s.sso);
      expect(done.headers.location).toBe('/login?sso_error=unavailable');
      expect(sessionOf(done)).toBeUndefined();
    } finally {
      await ctx.db.update(ssoConnections).set({ enabled: true }).where(eq(ssoConnections.id, conn));
    }
  });

  it('refuses a deactivated user (inactive_user), with the user in the audit row', async () => {
    expect(sessionOf(await signIn(person('dave')))).toBeDefined();
    const dave = (await identityOf(conn, 'dave-id'))!;
    await ctx.db.update(users).set({ active: false }).where(eq(users.id, dave.userId));
    const res = await signIn(person('dave'));
    expect(res.headers.location).toBe('/login?sso_error=inactive_user');
    expect(sessionOf(res)).toBeUndefined();
    expect(lastFailure()).toEqual({ reason: 'inactive_user', detail: 'account.inactive_user' });
    expect((await auditRows(ctx)).at(-1)).toMatchObject({
      action: 'sso.sign_in_failed',
      actorUserId: dave.userId,
      details: { connectionId: conn, protocol: 'saml', reason: 'inactive_user' },
    });
  });

  it('enforces the required claims before any account (required_claim)', async () => {
    const refused = await signIn(person('erin'), strict);
    expect(refused.headers.location).toBe('/login?sso_error=required_claim');
    expect(lastFailure().detail).toBe('saml.required_claim');
    expect(await identityOf(strict, 'erin-id')).toBeUndefined();
    const ok = await signIn(
      person('erin', {
        attributes: { email: ['erin@acme.example'], department: ['eng'] },
      }),
      strict,
    );
    expect(sessionOf(ok)).toBeDefined();
  });

  it('refuses more groups than the bound before any account (groups.too_many)', async () => {
    const res = await signIn(
      person('greg', {
        attributes: {
          email: ['greg@acme.example'],
          groups: Array.from({ length: 1_001 }, (_, i) => `g${String(i)}`),
        },
      }),
      tooMany,
    );
    expect(res.headers.location).toBe('/login?sso_error=invalid_response');
    expect(lastFailure().detail).toBe('groups.too_many');
    expect(await identityOf(tooMany, 'greg-id')).toBeUndefined();
  });

  it('links an existing account only by an email the connection says is verified', async () => {
    const google2 = await samlConnection(ctx, {
      enabled: true,
      name: 'Unverified linking',
      linkByEmail: true,
      jit: false,
    });
    const local = await createUser(ctx, { username: 'frank-local', email: 'frank@acme.example' });
    const res = await signIn(person('frank'), google2);
    // emailVerified is off on this connection: no link, and no JIT.
    expect(res.headers.location).toBe('/login?sso_error=no_account');
    const [linked] = await ctx.db
      .select()
      .from(identities)
      .where(and(eq(identities.connectionId, google2), eq(identities.userId, local.id)));
    expect(linked).toBeUndefined();
  });

  it('links the signed-in user (intent link) in the session they have', async () => {
    const local = await createUser(ctx, { username: 'linker-saml' });
    const session = (await sessionHeaders(ctx, 'linker-saml')).cookie!.split('=')[1]!;
    const s = await start(conn, `?link=${local.id}&returnTo=/settings/account`);
    const acs = await post(respond(s, person('linked')), s.relay);
    const done = await finish(acs.headers.location as string, s.sso, { qualor_session: session });
    expect(done.statusCode).toBe(303);
    expect(done.headers.location).toBe('/settings/account');
    expect(sessionOf(done)).toBeUndefined();
    expect(await identityOf(conn, 'linked-id')).toMatchObject({
      userId: local.id,
      linkedBy: 'user',
    });
  });

  it('never logs the response, the NameID or an attribute', () => {
    const logs = ctx.logs.join('\n');
    expect(logs).not.toContain('alice-persistent-id');
    expect(logs).not.toContain('alice@acme.example');
    expect(logs).not.toContain('PHNhbWxwOlJlc3BvbnNl'); // base64 of "<samlp:Response"
    expect(logs).not.toMatch(/SAMLResponse|RelayState/);
  });

  it('serves SP metadata with the entity id and the ACS URL, and no key without an SP key', async () => {
    const xml = spMetadata((await loadConnection(ctx.db, conn, ctx.config.secretKey))!, PUBLIC_URL);
    expect(xml).toContain(`entityID="${entityId}"`);
    expect(xml).toContain(`Location="${acsUrl}"`);
    expect(xml).not.toContain('KeyDescriptor');
    const withKey = spMetadata(
      (await loadConnection(ctx.db, keyed, ctx.config.secretKey))!,
      PUBLIC_URL,
    );
    expect(withKey).toContain('use="signing"');
    expect(withKey).toContain('use="encryption"');
    expect(withKey).toContain(certBody(TEST_SP.certPem).slice(0, 64));
    expect(withKey).not.toContain('PRIVATE KEY');
  });

  it('refuses a form body that is not urlencoded (415), and a body over 512 KiB (413)', async () => {
    expect(
      (
        await sapp.app.inject({
          method: 'POST',
          url: `/acs/${conn}`,
          headers: { 'content-type': 'application/json' },
          payload: '{}',
        })
      ).statusCode,
    ).toBe(415);
    expect(
      (
        await sapp.app.inject({
          method: 'POST',
          url: `/acs/${conn}`,
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          payload: 'SAMLResponse=' + 'A'.repeat(600_000),
        })
      ).statusCode,
    ).toBe(413);
  });

  it('reads IdP metadata (comments allowed): entity id, the HTTP-Redirect SSO URL, signing certificates', async () => {
    const loaded = (await loadConnection(ctx.db, withMetadata, ctx.config.secretKey))!;
    const preview = await readSamlMetadata(loaded, flowDeps(ctx));
    expect(preview.idpEntityId).toBe('https://idp.meta/saml');
    expect(preview.idpSsoUrl).toBe('https://idp.meta/sso?appid=a1');
    // The `use="encryption"` key is left out; `use` absent counts as signing.
    expect(preview.certificates).toHaveLength(2);
    expect(preview.certificates.map((c) => c.pem.replace(/\s+/g, ''))).toEqual([
      TEST_IDP.certPem.replace(/\s+/g, ''),
      STRANGER.certPem.replace(/\s+/g, ''),
    ]);
    expect(preview.certificates[0]!.sha256).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
    // Nothing was saved.
    const after = (await loadConnection(ctx.db, withMetadata, ctx.config.secretKey))!;
    expect(after.parsed.config).toMatchObject({ idpEntityId: 'https://idp.test/saml' });
  });

  it('refuses metadata without a URL or from a URL it may not read (422)', async () => {
    const loaded = (await loadConnection(ctx.db, conn, ctx.config.secretKey))!;
    await expect(readSamlMetadata(loaded, flowDeps(ctx))).rejects.toMatchObject({ status: 422 });
    const blocked = (await loadConnection(ctx.db, withMetadata, ctx.config.secretKey))!;
    const noInternal = {
      ...flowDeps(ctx),
      config: { ...ctx.config, ssoInternalHosts: new Set<string>() },
    };
    await expect(readSamlMetadata(blocked, noInternal)).rejects.toMatchObject({
      status: 422,
      errors: [{ path: 'saml.metadataUrl', message: 'The metadata URL could not be read' }],
    });
  });
});
