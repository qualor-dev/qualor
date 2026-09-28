import { and, count, eq } from 'drizzle-orm';
import type { LightMyRequestResponse } from 'fastify';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import type { TestContext } from '../../test/app';
import {
  buildResponse,
  EVIL_NAME_ID,
  signedAssertionOf,
  STRANGER,
  TEST_IDP,
  TEST_SP,
  XSW_VARIANTS,
  type SamlResponseOptions,
} from '../../test/saml';
import {
  connectionDeps,
  samlConnection,
  samlTestApp,
  ssoContext,
  type SamlStarted,
  type SamlTestApp,
} from '../../test/sso';
import { SYSTEM_ACTOR } from '../audit/recorder';
import { identities, sessions, ssoStates } from '../db/schema';
import { createConnection } from './connections';
import { ssoUrls } from './urls';

/**
 * sso-scim.md §19.3, the SAML half of the security corpus. Every row starts a real flow on a
 * licensed test server, posts a crafted response to the ACS and expects the refusal code in the
 * redirect, the fixed detail in the `component: "sso"` log line, and nothing of a sign-in: no
 * session cookie, no finish row, no session row, no identity for the attacker's NameID.
 */
describe('the SAML attack corpus (sso-scim.md §19.3)', () => {
  const PUBLIC_URL = 'https://q.example';
  const XMLENC = 'http://www.w3.org/2001/04/xmlenc#';
  const FOREIGN = 'urn:example:not-xmlenc';
  let ctx: TestContext;
  let sapp: SamlTestApp;
  /** A second app on the same database: another replica. */
  let replica: SamlTestApp;
  /** jit, groups from the `groups` attribute, verified email. */
  let conn: string;
  /** Another connection trusting the same IdP. */
  let other: string;
  /** With an SP key pair: encrypted assertions are allowed. */
  let keyed: string;

  beforeAll(async () => {
    ctx = await ssoContext({
      // The test licence is issued 2026-10-01: the edition's clock is inside it. Assertion times
      // are real (Date.now() when each response is built), so node-saml's clock agrees.
      now: () => new Date('2027-01-01T00:00:00Z'),
    });
    conn = await samlConnection(ctx, { enabled: true, groupSource: 'claims', emailVerified: true });
    other = await samlConnection(ctx, { enabled: true, name: 'Other' });
    keyed = (
      await createConnection(connectionDeps(ctx), SYSTEM_ACTOR, {
        name: 'Keyed',
        protocol: 'saml',
        enabled: true,
        saml: {
          idpEntityId: 'https://idp.test/saml',
          idpSsoUrl: 'https://idp.test/sso',
          idpCertificates: [TEST_IDP.certPem],
          spKey: TEST_SP.keyPem,
          spCertificate: TEST_SP.certPem,
        },
      })
    ).id;
    sapp = await samlTestApp(ctx);
    replica = await samlTestApp(ctx);
  });
  afterAll(async () => {
    await replica.close();
    await sapp.close();
    await ctx.close();
  });

  const start = (connection = conn): Promise<SamlStarted> => sapp.start(connection);
  const post = (b64: string, relay: string, connection = conn) => sapp.post(b64, relay, connection);

  /** A correct response to `s` for `connection` (default conn), with `over` changed. */
  function good(
    s: SamlStarted,
    over: SamlResponseOptions = {},
    connection = conn,
  ): SamlResponseOptions {
    const urls = ssoUrls(PUBLIC_URL, connection);
    return {
      inResponseTo: s.id,
      audience: urls.entityId,
      recipient: urls.acsUrl,
      destination: urls.acsUrl,
      ...over,
    };
  }

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

  async function counts(): Promise<{ finish: number; sessions: number; evil: number }> {
    const [finish] = await ctx.db
      .select({ n: count() })
      .from(ssoStates)
      .where(eq(ssoStates.kind, 'finish'));
    const [session] = await ctx.db.select({ n: count() }).from(sessions);
    const [evil] = await ctx.db
      .select({ n: count() })
      .from(identities)
      .where(eq(identities.subject, EVIL_NAME_ID));
    return { finish: finish!.n, sessions: session!.n, evil: evil!.n };
  }

  /**
   * Runs `act` (one post to the ACS) and expects it refused with `code` and the log's `detail`,
   * leaving no finish row, no session and no identity for the attacker's NameID.
   */
  async function refused(
    act: () => Promise<LightMyRequestResponse>,
    code: string,
    detail: string,
  ): Promise<void> {
    const before = await counts();
    const res = await act();
    expect(res.statusCode).toBe(303);
    expect(res.headers.location).toBe(`/login?sso_error=${code}`);
    expect(sessionOf(res)).toBeUndefined();
    expect(lastFailure()).toEqual({ reason: code, detail });
    expect(await counts()).toEqual({ ...before, evil: 0 });
  }

  /** Starts a flow and posts the response `over` builds for it. */
  const attack =
    (over: SamlResponseOptions, connection = conn) =>
    async () => {
      const s = await start(connection);
      return post(buildResponse(good(s, over, connection)), s.relay, connection);
    };

  /** The whole flow for a response built with `over`; the finish answer. */
  async function signIn(over: SamlResponseOptions = {}, connection = conn) {
    const s = await start(connection);
    const acs = await post(buildResponse(good(s, over, connection)), s.relay, connection);
    expect(acs.statusCode).toBe(303);
    expect(acs.headers.location).toMatch(/^\/api\/v0\/ee\/sso\/finish\?code=[A-Za-z0-9_-]{43}$/);
    return sapp.finish(acs.headers.location as string, s.sso);
  }

  it('accepts the control response: one finish code, then one session', async () => {
    const done = await signIn();
    expect(done.statusCode).toBe(303);
    expect(done.headers.location).toBe('/projects');
    expect(sessionOf(done)?.value).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  describe('signatures', () => {
    it('refuses no signature at all (saml.validate)', async () => {
      await refused(attack({ signAssertion: false }), 'invalid_response', 'saml.validate');
    });

    it('refuses a signed assertion with its Signature element stripped (saml.validate)', async () => {
      await refused(
        attack({ transform: (x) => x.replace(/<Signature xmlns[\s\S]*?<\/Signature>/, '') }),
        'invalid_response',
        'saml.validate',
      );
    });

    it('refuses a signed response around an unsigned assertion (saml.validate)', async () => {
      await refused(
        attack({ signAssertion: false, signResponse: true }),
        'invalid_response',
        'saml.validate',
      );
    });

    it('refuses a stranger’s signature with its certificate in KeyInfo, CVE-2024-32962 (saml.validate)', async () => {
      await refused(
        attack({ key: STRANGER.keyPem, cert: STRANGER.certPem }),
        'invalid_response',
        'saml.validate',
      );
    });

    it('refuses KeyInfo substitution: the pinned certificate in KeyInfo, a stranger’s key (saml.validate)', async () => {
      await refused(
        attack({ key: STRANGER.keyPem, keyInfoCert: TEST_IDP.certPem }),
        'invalid_response',
        'saml.validate',
      );
    });

    it('refuses an edited NameID inside a signed assertion, CVE-2025-54419 (saml.validate)', async () => {
      await refused(
        attack({ transform: (x) => x.replace('alice-persistent-id', EVIL_NAME_ID) }),
        'invalid_response',
        'saml.validate',
      );
    });

    it('refuses an edited attribute inside a signed assertion (saml.validate)', async () => {
      await refused(
        attack({ transform: (x) => x.replace('qualor-admins', 'qualor-owners') }),
        'invalid_response',
        'saml.validate',
      );
    });

    // spec §3.1: "the security corpus edits every text node of a signed assertion". The signed
    // content is everything of the assertion but its Signature.
    it('refuses an edit of any text node of the signed assertion (saml.validate)', async () => {
      const sample = Buffer.from(
        buildResponse({ inResponseTo: '_sample', signAssertion: true }),
        'base64',
      ).toString('utf8');
      const signedContent = signedAssertionOf(Buffer.from(sample).toString('base64')).replace(
        /<Signature xmlns[\s\S]*?<\/Signature>/,
        '',
      );
      const nodes = [...signedContent.matchAll(/>([^<]+)</g)].length;
      expect(nodes).toBeGreaterThanOrEqual(7);
      for (let index = 0; index < nodes; index += 1) {
        const editNode = (xml: string): string => {
          const at = xml.indexOf('<saml:Assertion');
          const head = xml.slice(0, at);
          const assertion = xml.slice(at);
          // Text nodes outside the Signature, in document order; the index-th gets a character.
          let seen = -1;
          const signature = /<Signature xmlns[\s\S]*?<\/Signature>/.exec(assertion)!;
          const sigStart = signature.index;
          const sigEnd = sigStart + signature[0].length;
          return (
            head +
            assertion.replace(/>([^<]+)</g, (match: string, text: string, offset: number) => {
              if (offset >= sigStart && offset < sigEnd) return match;
              seen += 1;
              return seen === index ? `>${text}x<` : match;
            })
          );
        };
        await refused(attack({ transform: editNode }), 'invalid_response', 'saml.validate');
      }
    });

    it.each<[string, string, string]>([
      [
        'rsa-sha1',
        '<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>',
        '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/>',
      ],
      [
        'hmac-sha1',
        '<SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/>',
        '<SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#hmac-sha1"/>',
      ],
      [
        'a sha1 digest',
        '<DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>',
        '<DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/>',
      ],
    ])('refuses %s (saml.precheck.signature_shape)', async (_name, from, to) => {
      await refused(
        attack({ transform: (x) => x.replace(from, to) }),
        'invalid_response',
        'saml.precheck.signature_shape',
      );
    });

    it('refuses a response actually signed with rsa-sha1 and a sha1 digest (saml.precheck.signature_shape)', async () => {
      await refused(
        attack({
          signatureAlgorithm: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1',
          digestAlgorithm: 'http://www.w3.org/2000/09/xmldsig#sha1',
        }),
        'invalid_response',
        'saml.precheck.signature_shape',
      );
    });

    it('refuses two SignedInfo in one Signature, CVE-2025-29774 (saml.precheck.signature_shape)', async () => {
      await refused(
        attack({
          transform: (x) => x.replace(/(<SignedInfo>[\s\S]*?<\/SignedInfo>)/, '$1$1'),
        }),
        'invalid_response',
        'saml.precheck.signature_shape',
      );
    });
  });

  describe('signature wrapping (XSW1–XSW8, SAML Raider)', () => {
    /** Where each variant is refused; each is a wrapping the pre-check or node-saml catches. */
    const expected: Record<string, string> = {
      XSW1: 'saml.precheck.assertion_count',
      XSW2: 'saml.precheck.assertion_count',
      XSW3: 'saml.precheck.assertion_count',
      XSW4: 'saml.precheck.assertion_count',
      XSW5: 'saml.precheck.assertion_count',
      XSW6: 'saml.precheck.assertion_count',
      XSW7: 'saml.precheck.assertion_count',
      XSW8: 'saml.precheck.assertion_count',
    };

    it('has eight variants', () => {
      expect(XSW_VARIANTS.map((v) => v.name.slice(0, 4))).toEqual(Object.keys(expected));
    });

    it.each(XSW_VARIANTS.map((v) => [v.name, v] as const))('refuses %s', async (_name, v) => {
      await refused(
        attack({ signResponse: v.signResponse, transform: v.wrap }),
        'invalid_response',
        expected[v.name.slice(0, 4)]!,
      );
    });

    it('refuses a second assertion beside the signed one, signed or not (saml.precheck.assertion_count)', async () => {
      const second = signedAssertionOf(
        buildResponse({ inResponseTo: '_x', nameId: EVIL_NAME_ID, assertionId: '_second' }),
      );
      await refused(
        attack({ transform: (x) => x.replace('</samlp:Response>', `${second}</samlp:Response>`) }),
        'invalid_response',
        'saml.precheck.assertion_count',
      );
      const unsigned = second.replace(/<Signature xmlns[\s\S]*?<\/Signature>/, '');
      await refused(
        attack({
          transform: (x) => x.replace('</samlp:Response>', `${unsigned}</samlp:Response>`),
        }),
        'invalid_response',
        'saml.precheck.assertion_count',
      );
    });
  });

  describe('the pre-check', () => {
    it.each<[string, (x: string) => string, string]>([
      [
        'a comment inside the NameID',
        (x) => x.replace('alice-persistent-id', 'alice<!---->-persistent-id'),
        'comment',
      ],
      [
        'a comment inside an attribute value',
        (x) => x.replace('alice@acme.example', 'alice@acme.example<!---->.evil.example'),
        'comment',
      ],
      [
        'a comment inside DigestValue (CVE-2025-29775)',
        (x) => x.replace('<DigestValue>', '<DigestValue><!--x-->'),
        'comment',
      ],
      [
        'an XXE DOCTYPE',
        (x) => `<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>${x}`,
        'doctype',
      ],
      [
        'a billion-laughs entity',
        (x) =>
          `<!DOCTYPE r [<!ENTITY a "aaaaaaaaaa"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">]>${x.replace('Alice A', '&b;')}`,
        'doctype',
      ],
      [
        'a processing instruction',
        (x) => x.replace('<samlp:Status>', '<?pi x?><samlp:Status>'),
        'processing_instruction',
      ],
      ['a CDATA section', (x) => x.replace('Alice A', '<![CDATA[Alice A]]>'), 'cdata'],
      [
        'two root elements',
        (x) => `${x}<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`,
        'not_response',
      ],
      [
        'a __proto__ element',
        (x) => x.replace('<samlp:Status>', '<__proto__/><samlp:Status>'),
        'forbidden_name',
      ],
      [
        // Response 1 > Assertion 2 > AttributeStatement 3 > Attribute 4 > AttributeValue 5.
        'nesting of 33',
        (x) => x.replace('Alice A', `${'<x>'.repeat(28)}${'</x>'.repeat(28)}`),
        'too_complex',
      ],
    ])('refuses %s (saml.precheck.%s)', async (_name, transform, code) => {
      await refused(attack({ transform }), 'invalid_response', `saml.precheck.${code}`);
    });

    // The unsigned part of the response: Response 1 > samlp:Extensions 2 > x 3 … so n elements
    // under Extensions reach a depth of 2 + n. 32 is the bound (spec §6.2).
    const nested = (depth: number) => (x: string) =>
      x.replace(
        '<samlp:Status>',
        `<samlp:Extensions>${'<x>'.repeat(depth - 2)}${'</x>'.repeat(depth - 2)}</samlp:Extensions><samlp:Status>`,
      );

    it('accepts nesting of exactly 32 (in samlp:Extensions)', async () => {
      const done = await signIn({ transform: nested(32) });
      expect(done.headers.location).toBe('/projects');
      expect(sessionOf(done)).toBeDefined();
    });

    it('refuses nesting of 33 in samlp:Extensions (saml.precheck.too_complex)', async () => {
      await refused(
        attack({ transform: nested(33) }),
        'invalid_response',
        'saml.precheck.too_complex',
      );
    });

    it('refuses over 256 KiB decoded (saml.precheck.too_large), and a body over 512 KiB (413)', async () => {
      const s = await start();
      // 262 200 bytes is 349 600 base64 characters: under the character bound, over the byte one.
      const big = Buffer.from(`<a>${'x'.repeat(262_200 - 7)}</a>`).toString('base64');
      expect(big.length).toBeLessThan(350_000);
      await refused(() => post(big, s.relay), 'invalid_response', 'saml.precheck.too_large');
      const tooLarge = await sapp.app.inject({
        method: 'POST',
        url: `/acs/${conn}`,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        payload: `SAMLResponse=${'A'.repeat(600_000)}&RelayState=${s.relay}`,
      });
      expect(tooLarge.statusCode).toBe(413);
    });

    it('refuses an EncryptedAssertion on a connection without an SP key (saml.precheck.encrypted_without_key)', async () => {
      await refused(
        attack({ encryptFor: TEST_SP.certPem }),
        'invalid_response',
        'saml.precheck.encrypted_without_key',
      );
    });
  });

  describe('replay and the flow', () => {
    it('refuses the same response posted twice (flow_expired)', async () => {
      const s = await start();
      const body = buildResponse(good(s));
      expect((await post(body, s.relay)).headers.location).toMatch(/finish\?code=/);
      await refused(() => post(body, s.relay), 'flow_expired', 'saml.request_unknown');
    });

    it('refuses the same assertion under a new request (replayed)', async () => {
      const assertionId = `_replay-${String(Date.now())}`;
      const s1 = await start();
      expect(
        (await post(buildResponse(good(s1, { assertionId })), s1.relay)).headers.location,
      ).toMatch(/finish\?code=/);
      const s2 = await start();
      await refused(
        () => post(buildResponse(good(s2, { assertionId })), s2.relay),
        'replayed',
        'saml.replayed',
      );
    });

    it('refuses the captured response with only its unsigned InResponseTo forged for a new request', async () => {
      const s1 = await start();
      const captured = Buffer.from(buildResponse(good(s1)), 'base64').toString('utf8');
      // The captured response is never used: the attacker replays it under their own request.
      const s2 = await start();
      const forged = captured.replace(
        /(<samlp:Response[^>]*InResponseTo=")[^"]+"/,
        (_m, head: string) => `${head}${s2.id}"`,
      );
      await refused(
        () => post(Buffer.from(forged).toString('base64'), s2.relay),
        'invalid_response',
        // node-saml compares the signed SubjectConfirmationData's InResponseTo with the request.
        'saml.validate',
      );
    });

    it('gives exactly one finish code and one session when two replicas take the same response at once', async () => {
      const s = await start();
      const body = buildResponse(good(s));
      const results = await Promise.all([
        sapp.post(body, s.relay, conn),
        replica.post(body, s.relay, conn),
      ]);
      const won = results.filter((r) => /finish\?code=/.test(r.headers.location as string));
      expect(won).toHaveLength(1);
      const lost = results.find((r) => r !== won[0])!;
      expect(lost.headers.location).toBe('/login?sso_error=flow_expired');
      const location = won[0]!.headers.location as string;
      const finishes = await Promise.all([
        sapp.finish(location, s.sso),
        replica.finish(location, s.sso),
      ]);
      expect(finishes.filter((r) => sessionOf(r) !== undefined)).toHaveLength(1);
      expect(finishes.map((r) => r.headers.location).sort()).toEqual([
        '/login?sso_error=flow_expired',
        '/projects',
      ]);
    });

    it('refuses no InResponseTo (IdP-initiated), an unknown one, and one of another connection', async () => {
      await refused(attack({ inResponseTo: null }), 'invalid_response', 'saml.in_response_to');
      await refused(attack({ inResponseTo: '_unknown' }), 'flow_expired', 'saml.request_unknown');
      const theirs = await start(other);
      await refused(
        async () => {
          const s = await start();
          return post(buildResponse(good(s, { inResponseTo: theirs.id })), s.relay);
        },
        'flow_expired',
        'saml.request_unknown',
      );
    });

    it('refuses a response made for another connection, posted to this one', async () => {
      // Signed by the same IdP for the other connection's audience, recipient and destination.
      await refused(
        async () => {
          const s = await start();
          const theirs = ssoUrls(PUBLIC_URL, other);
          return post(
            buildResponse(
              good(s, {
                audience: theirs.entityId,
                recipient: theirs.acsUrl,
                destination: theirs.acsUrl,
              }),
            ),
            s.relay,
          );
        },
        'invalid_response',
        'saml.validate',
      );
      // Its own request, posted to another connection's ACS.
      await refused(
        async () => {
          const s = await start();
          return post(buildResponse(good(s)), s.relay, other);
        },
        'flow_expired',
        'saml.request_unknown',
      );
    });

    it('refuses a finish code replayed after it signed in (flow_expired), with no second session', async () => {
      const s = await start();
      const acs = await post(buildResponse(good(s)), s.relay);
      const location = acs.headers.location as string;
      const first = await sapp.finish(location, s.sso);
      expect(first.headers.location).toBe('/projects');
      expect(sessionOf(first)).toBeDefined();
      const before = await counts();
      const replayed = await sapp.finish(location, s.sso);
      expect(replayed.statusCode).toBe(303);
      expect(replayed.headers.location).toBe('/login?sso_error=flow_expired');
      expect(sessionOf(replayed)).toBeUndefined();
      expect(lastFailure()).toEqual({ reason: 'flow_expired', detail: 'flow.expired' });
      expect(await counts()).toEqual(before);
    });

    it('refuses a finish code used twice (flow_expired) or in another browser (flow_mismatch)', async () => {
      const s = await start();
      const acs = await post(buildResponse(good(s)), s.relay);
      const location = acs.headers.location as string;
      const intruder = await start();
      const other = await sapp.finish(location, intruder.sso);
      expect(other.headers.location).toBe('/login?sso_error=flow_mismatch');
      expect(sessionOf(other)).toBeUndefined();
      expect(lastFailure()).toEqual({ reason: 'flow_mismatch', detail: 'flow.binding' });
      const again = await sapp.finish(location, s.sso);
      expect(again.headers.location).toBe('/login?sso_error=flow_expired');
      expect(sessionOf(again)).toBeUndefined();

      const s2 = await start();
      const acs2 = await post(buildResponse(good(s2)), s2.relay);
      const none = await sapp.finish(acs2.headers.location as string);
      expect(none.headers.location).toBe('/login?sso_error=flow_mismatch');
      expect(sessionOf(none)).toBeUndefined();
    });
  });

  describe('recipient, audience, destination, issuer and time', () => {
    it.each<[string, SamlResponseOptions, string]>([
      ['the wrong Audience', { audience: 'https://other.example' }, 'saml.validate'],
      [
        'the wrong Recipient',
        { recipient: 'https://other.example/acs', destination: undefined },
        'saml.recipient',
      ],
      ['the wrong Destination', { destination: 'https://other.example/acs' }, 'saml.destination'],
      [
        'the wrong assertion Issuer',
        { issuer: 'https://evil.example/saml', responseIssuer: 'https://idp.test/saml' },
        'saml.issuer',
      ],
      ['the wrong response Issuer', { responseIssuer: 'https://evil.example/saml' }, 'saml.issuer'],
    ])('refuses %s (%s)', async (_name, over, detail) => {
      // `destination: undefined` keeps the response's Destination at the real ACS URL.
      const fixed = async () => {
        const s = await start();
        const opts = good(s, over);
        if ('destination' in over && over.destination === undefined) {
          opts.destination = ssoUrls(PUBLIC_URL, conn).acsUrl;
        }
        return post(buildResponse(opts), s.relay);
      };
      await refused(fixed, 'invalid_response', detail);
    });

    // The times are taken when the row runs, never when the table is collected.
    it.each<[string, () => SamlResponseOptions]>([
      ['NotOnOrAfter 61 s past', () => ({ notOnOrAfter: new Date(Date.now() - 61_000) })],
      ['NotBefore 61 s ahead', () => ({ notBefore: new Date(Date.now() + 61_000) })],
    ])('refuses %s (saml.validate)', async (_name, over) => {
      await refused(() => attack(over())(), 'invalid_response', 'saml.validate');
    });

    it.each<[string, () => SamlResponseOptions]>([
      ['NotOnOrAfter 59 s past', () => ({ notOnOrAfter: new Date(Date.now() - 59_000) })],
      ['NotBefore 59 s ahead', () => ({ notBefore: new Date(Date.now() + 59_000) })],
    ])('accepts %s', async (_name, over) => {
      const done = await signIn(over());
      expect(done.headers.location).toBe('/projects');
      expect(sessionOf(done)).toBeDefined();
    });
  });

  describe('encrypted assertions (a connection with an SP key)', () => {
    const encrypted = (transform?: (x: string) => string): SamlResponseOptions => ({
      nameId: 'enc-id',
      encryptFor: TEST_SP.certPem,
      ...(transform ? { transform } : {}),
    });

    it('accepts the control: RSA-OAEP and AES-256-GCM', async () => {
      const done = await signIn(encrypted(), keyed);
      expect(sessionOf(done)).toBeDefined();
      const [identity] = await ctx.db
        .select()
        .from(identities)
        .where(and(eq(identities.connectionId, keyed), eq(identities.subject, 'enc-id')));
      expect(identity).toBeDefined();
    });

    it.each<[string, (x: string) => string]>([
      [
        'the key sent with RSA PKCS#1 v1.5',
        (x) => x.replace(`${XMLENC}rsa-oaep-mgf1p`, `${XMLENC}rsa-1_5`),
      ],
      [
        'the content encrypted with 3DES',
        (x) => x.replace('http://www.w3.org/2009/xmlenc11#aes256-gcm', `${XMLENC}tripledes-cbc`),
      ],
      [
        'a foreign-namespace rsa-1_5 EncryptionMethod first in EncryptedKey',
        (x) =>
          x.replace(
            '<xenc:EncryptedKey>',
            `<xenc:EncryptedKey><f:EncryptionMethod xmlns:f="${FOREIGN}" Algorithm="${XMLENC}rsa-1_5"/>`,
          ),
      ],
      [
        'a foreign-namespace tripledes-cbc EncryptionMethod first in EncryptedData',
        (x) =>
          x.replace(
            '<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>',
            `<f:EncryptionMethod xmlns:f="${FOREIGN}" Algorithm="${XMLENC}tripledes-cbc"/><xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>`,
          ),
      ],
    ])('refuses %s before decrypting (saml.encryption)', async (_name, transform) => {
      await refused(attack(encrypted(transform), keyed), 'invalid_response', 'saml.encryption');
    });
  });
});
