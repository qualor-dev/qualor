import { describe, expect, it } from 'vitest';
import { SAML_MAX_BYTES, decodeSamlResponse, samlAssertionCheck, samlPreCheck } from './saml-guard';

const P = 'urn:oasis:names:tc:SAML:2.0:protocol';
const A = 'urn:oasis:names:tc:SAML:2.0:assertion';
const MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const EXC = 'http://www.w3.org/2001/10/xml-exc-c14n#';
const BOM = String.fromCharCode(0xfeff);

function sig(opts: { signedInfo?: number; refs?: number; method?: string; digest?: string } = {}) {
  const method = opts.method ?? 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
  const digest = opts.digest ?? 'http://www.w3.org/2001/04/xmlenc#sha256';
  const ref = `<ds:Reference URI="#a1"><ds:DigestMethod Algorithm="${digest}"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference>`;
  const si = `<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="${EXC}"/><ds:SignatureMethod Algorithm="${method}"/>${ref.repeat(opts.refs ?? 1)}</ds:SignedInfo>`;
  return `<ds:Signature xmlns:ds="${DS}">${si.repeat(opts.signedInfo ?? 1)}<ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>`;
}

function response(
  inner = `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig()}<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>`,
  attrs = 'ID="r1" InResponseTo="_req" Destination="https://q/acs"',
) {
  return `<?xml version="1.0" encoding="UTF-8"?><samlp:Response xmlns:samlp="${P}" ${attrs}>${inner}</samlp:Response>`;
}

const assertion = (body: string, open = `<saml:Assertion xmlns:saml="${A}" ID="a1">`) =>
  response(`${open}${body}</saml:Assertion>`);

const check = (xml: string, hasSpKey = false) => samlPreCheck(xml, { root: 'Response', hasSpKey });

/**
 * The time bounds of the pre-check (§6.2). On an idle machine each of these inputs takes a few
 * milliseconds; the bound is there to catch super-linear work (a quadratic scan over 290 KiB takes
 * seconds), not to benchmark. 250 ms, and the fastest of three runs (after one warm-up), so that a
 * loaded test machine (the whole suite, Docker, other workers) cannot fail it by scheduling alone,
 * while any regression to quadratic behaviour still does.
 */
const TIME_BOUND_MS = 250;
function fastest<T>(run: () => T, runs = 3): { result: T; ms: number } {
  let ms = Number.POSITIVE_INFINITY;
  let result = run();
  for (let i = 0; i < runs; i += 1) {
    const started = performance.now();
    result = run();
    ms = Math.min(ms, performance.now() - started);
  }
  return { result, ms };
}

describe('samlPreCheck (sso-scim.md §6.2)', () => {
  it('accepts the minimal shape and reads InResponseTo and Destination', () => {
    expect(check(response())).toMatchObject({
      ok: true,
      inResponseTo: '_req',
      destination: 'https://q/acs',
    });
  });

  it.each([
    [
      'a DOCTYPE',
      response().replace(
        '<samlp:Response',
        '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><samlp:Response',
      ),
      'doctype',
    ],
    [
      'a billion-laughs entity',
      `<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;">]>` + response(),
      'doctype',
    ],
    [
      'a processing instruction',
      response().replace('<samlp:Response', '<?evil x?><samlp:Response'),
      'processing_instruction',
    ],
    [
      'a comment in the NameID',
      response().replace('alice', 'admin@corp.com<!---->.evil.com'),
      'comment',
    ],
    [
      'a comment in DigestValue',
      response().replace('<ds:DigestValue>AA==', '<ds:DigestValue><!--x-->AA=='),
      'comment',
    ],
    ['CDATA', response().replace('alice', '<![CDATA[alice]]>'), 'cdata'],
    ['malformed XML', response().replace('</samlp:Response>', ''), 'malformed'],
    ['another root', `<x xmlns="urn:x"/>`, 'not_response'],
    ['a Response in the wrong namespace', response().replaceAll(P, 'urn:evil'), 'not_response'],
    [
      'two assertions',
      response(
        `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig()}</saml:Assertion><saml:Assertion xmlns:saml="${A}" ID="a2"/>`,
      ),
      'assertion_count',
    ],
    [
      'an assertion hidden in the signature (XSW)',
      response(
        `<saml:Assertion xmlns:saml="${A}" ID="a1"><ds:Signature xmlns:ds="${DS}"><ds:Object><saml:Assertion ID="a1"/></ds:Object></ds:Signature></saml:Assertion>`,
      ),
      'assertion_count',
    ],
    ['no assertion', response(''), 'assertion_count'],
    [
      'an encrypted assertion without an SP key',
      response(`<saml:EncryptedAssertion xmlns:saml="${A}"/>`),
      'encrypted_without_key',
    ],
    [
      'two SignedInfo (CVE-2025-29774)',
      response(
        `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig({ signedInfo: 2 })}</saml:Assertion>`,
      ),
      'signature_shape',
    ],
    [
      'two references',
      response(`<saml:Assertion xmlns:saml="${A}" ID="a1">${sig({ refs: 2 })}</saml:Assertion>`),
      'signature_shape',
    ],
    [
      'rsa-sha1',
      response(
        `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig({ method: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' })}</saml:Assertion>`,
      ),
      'signature_shape',
    ],
    [
      'hmac-sha1',
      response(
        `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig({ method: 'http://www.w3.org/2000/09/xmldsig#hmac-sha1' })}</saml:Assertion>`,
      ),
      'signature_shape',
    ],
    [
      'a sha1 digest',
      response(
        `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig({ digest: 'http://www.w3.org/2000/09/xmldsig#sha1' })}</saml:Assertion>`,
      ),
      'signature_shape',
    ],
    [
      'a __proto__ element',
      response().replace('<saml:Subject>', '<saml:Subject><__proto__/>'),
      'forbidden_name',
    ],
    [
      'a constructor attribute',
      response().replace('ID="a1"', 'ID="a1" constructor="x"'),
      'forbidden_name',
    ],
    [
      'two elements with one ID',
      response(
        `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig()}<saml:Subject ID="a1"/></saml:Assertion>`,
      ),
      'duplicate_id',
    ],
    [
      'nesting of 33',
      response(
        `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig()}${'<x>'.repeat(33)}${'</x>'.repeat(33)}</saml:Assertion>`,
      ),
      'too_complex',
    ],
  ])('refuses %s', (_what, xml, code) => {
    expect(check(xml)).toEqual({ ok: false, code });
  });

  it('accepts an encrypted assertion when the connection has an SP key', () => {
    expect(check(response(`<saml:EncryptedAssertion xmlns:saml="${A}"/>`), true)).toMatchObject({
      ok: true,
    });
  });

  describe('namespace prefixes', () => {
    it('accepts saml2:, no prefix at all, and swapped prefixes, since only namespaces count', () => {
      const saml2 = `<saml2p:Response xmlns:saml2p="${P}" ID="r1"><saml2:Assertion xmlns:saml2="${A}" ID="a1">${sig()}<saml2:Subject><saml2:NameID>alice</saml2:NameID></saml2:Subject></saml2:Assertion></saml2p:Response>`;
      const bare = `<Response xmlns="${P}" ID="r1"><Assertion xmlns="${A}" ID="a1"><Signature xmlns="${DS}"><SignedInfo><CanonicalizationMethod Algorithm="${EXC}"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#a1"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AA==</DigestValue></Reference></SignedInfo><SignatureValue>AA==</SignatureValue></Signature><Subject><NameID>alice</NameID></Subject></Assertion></Response>`;
      const swapped = `<saml:Response xmlns:saml="${P}" ID="r1"><samlp:Assertion xmlns:samlp="${A}" ID="a1">${sig()}</samlp:Assertion></saml:Response>`;
      for (const xml of [saml2, bare, swapped]) expect(check(xml)).toMatchObject({ ok: true });
    });

    it('refuses a SHA-1 signature whatever prefix names the xmldsig namespace', () => {
      const dsig = sig({ method: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' })
        .replaceAll('ds:', 'dsig:')
        .replace('xmlns:ds=', 'xmlns:dsig=');
      expect(check(assertion(dsig))).toEqual({ ok: false, code: 'signature_shape' });
      const bare = `<Signature xmlns="${DS}"><SignedInfo><CanonicalizationMethod Algorithm="${EXC}"/><SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><Reference URI="#a1"><DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><DigestValue>AA==</DigestValue></Reference></SignedInfo><SignatureValue>AA==</SignatureValue></Signature>`;
      expect(check(assertion(bare))).toEqual({ ok: false, code: 'signature_shape' });
    });

    it('refuses a root whose samlp prefix is rebound to another namespace', () => {
      const rebound = response().replace(
        `xmlns:samlp="${P}"`,
        `xmlns:samlp="urn:evil" xmlns:p="${P}"`,
      );
      expect(check(rebound)).toEqual({ ok: false, code: 'not_response' });
    });

    it('refuses an assertion whose saml prefix is rebound away from the assertion namespace', () => {
      // A prefix-based check would count one saml:Assertion; node-saml's XPath matches on local-name().
      const rebound = response(
        `<saml:Assertion xmlns:saml="urn:evil" ID="a1">${sig()}</saml:Assertion>`,
      );
      expect(check(rebound)).toEqual({ ok: false, code: 'assertion_count' });
      const second = response(
        `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig()}</saml:Assertion><saml:Assertion xmlns:saml="urn:evil" ID="a2"/>`,
      );
      expect(check(second)).toEqual({ ok: false, code: 'assertion_count' });
    });

    it('refuses a prefix rebound inside the assertion to smuggle a second assertion', () => {
      const inner = `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig()}<saml:Subject xmlns:saml="urn:x"><y:Assertion xmlns:y="${A}" ID="a2"/></saml:Subject></saml:Assertion>`;
      expect(check(response(inner))).toEqual({ ok: false, code: 'assertion_count' });
    });

    it('refuses a Signature element outside the xmldsig namespace', () => {
      const fake = sig().replace(`xmlns:ds="${DS}"`, 'xmlns:ds="urn:evil"');
      expect(check(assertion(fake))).toEqual({ ok: false, code: 'signature_shape' });
    });

    it('refuses an unbound prefix and an empty prefix binding (not namespace-well-formed)', () => {
      expect(check(response().replace('<saml:Subject>', '<saml:Subject><zz:x/>'))).toEqual({
        ok: false,
        code: 'malformed',
      });
      expect(
        check(response().replace('<saml:Subject>', '<saml:Subject><zz:x xmlns:zz=""/>')),
      ).toEqual({ ok: false, code: 'malformed' });
    });

    it('refuses forbidden names used as prefixes or namespace declarations', () => {
      expect(
        check(
          response().replace(
            '<saml:Subject>',
            '<saml:Subject><__proto__:x xmlns:__proto__="urn:x"/>',
          ),
        ),
      ).toEqual({ ok: false, code: 'forbidden_name' });
      expect(check(response().replace('ID="a1"', 'ID="a1" xmlns:prototype="urn:x"'))).toEqual({
        ok: false,
        code: 'forbidden_name',
      });
    });
  });

  describe('text-level tricks', () => {
    it.each([
      [
        'a DOCTYPE after a byte-order mark',
        BOM + response().replace('<samlp:Response', '<!DOCTYPE r><samlp:Response'),
        'doctype',
      ],
      [
        'a lower-case doctype',
        response().replace('<samlp:Response', '<!doctype r><samlp:Response'),
        'doctype',
      ],
      [
        'a doctype split by a newline',
        response().replace('<samlp:Response', '<!\nDOCTYPE r><samlp:Response'),
        'doctype',
      ],
      ['an ENTITY without a DOCTYPE', response().replace('alice', '<!ENTITY x "y">'), 'doctype'],
      ['an ELEMENT declaration', response().replace('alice', '<!ELEMENT x ANY>'), 'doctype'],
      [
        'a comment with spaces in the NameID',
        response().replace('alice', 'admin@corp.com<!-- x -->.evil.com'),
        'comment',
      ],
      [
        'a comment in an attribute value',
        response().replace('ID="a1"', 'ID="a1<!--x-->"'),
        'comment',
      ],
      ['a comment after the root', response() + '<!---->', 'comment'],
      [
        'a comment with whitespace inside the opener',
        response().replace('alice', 'a< !-- x -->b'),
        'malformed',
      ],
      ['a PI with spaces', response().replace('alice', '<? evil ?>'), 'processing_instruction'],
      [
        'a PI named like the declaration',
        response().replace('<samlp:Response', '<?xml-stylesheet href="x"?><samlp:Response'),
        'processing_instruction',
      ],
      ['a declaration not at the start', ' ' + response(), 'processing_instruction'],
      [
        'a second declaration',
        response().replace('<samlp:Response', '<?xml version="1.0"?><samlp:Response'),
        'processing_instruction',
      ],
      [
        'a declaration in another encoding',
        response().replace('encoding="UTF-8"', 'encoding="ISO-8859-1"'),
        'malformed',
      ],
      [
        'a CDATA section in lower case',
        response().replace('alice', '<![cdata[alice]]>'),
        'doctype',
      ],
      ['a byte-order mark before a valid response', BOM + response(), 'malformed'],
      [
        'a NUL character',
        response().replace('alice', 'al' + String.fromCharCode(0) + 'ice'),
        'malformed',
      ],
      [
        'a control character',
        response().replace('alice', 'al' + String.fromCharCode(1) + 'ice'),
        'malformed',
      ],
      [
        'a lone surrogate',
        response().replace('alice', 'al' + String.fromCharCode(0xd800) + 'ice'),
        'malformed',
      ],
      [
        'U+FFFE',
        response().replace('alice', 'al' + String.fromCharCode(0xfffe) + 'ice'),
        'malformed',
      ],
      ['an undeclared entity', response().replace('alice', '&xxe;'), 'malformed'],
      ['a duplicated attribute', response().replace('ID="a1"', 'ID="a1" ID="a2"'), 'malformed'],
      [
        'two root elements',
        response() + `<samlp:Response xmlns:samlp="${P}" ID="r2"/>`,
        'not_response',
      ],
      ['text after the root', response() + 'x', 'not_response'],
    ])('refuses %s', (_what, xml, code) => {
      expect(check(xml)).toEqual({ ok: false, code });
    });

    it('accepts a response without a declaration, with whitespace around the root and character references', () => {
      const xml =
        response()
          .replace('<?xml version="1.0" encoding="UTF-8"?>', '')
          .replace('alice', 'al&#105;ce &amp; co') + '\n';
      expect(check(xml)).toMatchObject({ ok: true });
      expect(
        check(response().replace('encoding="UTF-8"', "encoding='utf-8' standalone='no'")),
      ).toMatchObject({ ok: true });
    });
  });

  describe('the signature shape', () => {
    it.each([
      ['hmac-sha256', sig({ method: 'http://www.w3.org/2001/04/xmldsig-more#hmac-sha256' })],
      [
        'a padded algorithm URI',
        sig({ method: ' http://www.w3.org/2001/04/xmldsig-more#rsa-sha256' }),
      ],
      ['a sha224 digest', sig({ digest: 'http://www.w3.org/2001/04/xmldsig-more#sha224' })],
      [
        'a ds:Object in the signature',
        sig().replace('</ds:Signature>', '<ds:Object/></ds:Signature>'),
      ],
      ['no SignatureValue', sig().replace('<ds:SignatureValue>AA==</ds:SignatureValue>', '')],
      [
        'two SignatureMethods',
        sig().replace(
          '<ds:SignatureMethod',
          '<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><ds:SignatureMethod',
        ),
      ],
      [
        'a Reference in a foreign namespace beside the real one',
        sig().replace('</ds:SignedInfo>', '<x:Reference xmlns:x="urn:x"/></ds:SignedInfo>'),
      ],
      [
        'two DigestMethods',
        sig().replace(
          '<ds:DigestValue>',
          '<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>',
        ),
      ],
      ['a stray SignedInfo outside a Signature', `<ds:SignedInfo xmlns:ds="${DS}"/>${sig()}`],
      // xml-crypto's loadSignature takes the first `.//*[local-name()='SignatureMethod']` (and
      // CanonicalizationMethod, SignatureValue, KeyInfo) in any namespace: none may hide.
      [
        'an rsa-sha1 SignatureMethod in a foreign namespace inside CanonicalizationMethod',
        sig().replace(
          `<ds:CanonicalizationMethod Algorithm="${EXC}"/>`,
          `<ds:CanonicalizationMethod Algorithm="${EXC}"><x:SignatureMethod xmlns:x="urn:x" Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/></ds:CanonicalizationMethod>`,
        ),
      ],
      [
        'an rsa-sha1 ds:SignatureMethod whose ds prefix is rebound, inside CanonicalizationMethod',
        sig().replace(
          `<ds:CanonicalizationMethod Algorithm="${EXC}"/>`,
          `<ds:CanonicalizationMethod Algorithm="${EXC}"><ds:SignatureMethod xmlns:ds="urn:x" Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/></ds:CanonicalizationMethod>`,
        ),
      ],
      [
        'an rsa-sha1 SignatureMethod inside a Transform, with the Reference before the real one',
        `<ds:Signature xmlns:ds="${DS}"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="${EXC}"/><ds:Reference URI="#a1"><ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"><x:SignatureMethod xmlns:x="urn:x" Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/></ds:Transform></ds:Transforms><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>`,
      ],
      [
        'a c14n#WithComments CanonicalizationMethod inside SignatureMethod, before the real one',
        `<ds:Signature xmlns:ds="${DS}"><ds:SignedInfo><ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"><x:CanonicalizationMethod xmlns:x="urn:x" Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#WithComments"/></ds:SignatureMethod><ds:CanonicalizationMethod Algorithm="${EXC}"/><ds:Reference URI="#a1"><ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><ds:DigestValue>AA==</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>AA==</ds:SignatureValue></ds:Signature>`,
      ],
      [
        'a SignatureValue hidden in CanonicalizationMethod',
        sig().replace(
          `<ds:CanonicalizationMethod Algorithm="${EXC}"/>`,
          `<ds:CanonicalizationMethod Algorithm="${EXC}"><x:SignatureValue xmlns:x="urn:x">ZZZZ</x:SignatureValue></ds:CanonicalizationMethod>`,
        ),
      ],
      [
        'a KeyInfo hidden in CanonicalizationMethod',
        sig().replace(
          `<ds:CanonicalizationMethod Algorithm="${EXC}"/>`,
          `<ds:CanonicalizationMethod Algorithm="${EXC}"><x:KeyInfo xmlns:x="urn:x"/></ds:CanonicalizationMethod>`,
        ),
      ],
      [
        'a SignatureMethod hidden in KeyInfo',
        sig().replace(
          '</ds:Signature>',
          '<ds:KeyInfo><x:SignatureMethod xmlns:x="urn:x" Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/></ds:KeyInfo></ds:Signature>',
        ),
      ],
      [
        'the Reference before the SignatureMethod',
        sig().replace(/(<ds:SignatureMethod [^>]*\/>)(<ds:Reference.*<\/ds:Reference>)/, '$2$1'),
      ],
      [
        'no CanonicalizationMethod',
        sig().replace(`<ds:CanonicalizationMethod Algorithm="${EXC}"/>`, ''),
      ],
      [
        'KeyInfo before SignatureValue',
        sig().replace(
          '<ds:SignatureValue>AA==</ds:SignatureValue>',
          '<ds:KeyInfo/><ds:SignatureValue>AA==</ds:SignatureValue>',
        ),
      ],
      [
        'the DigestValue before the DigestMethod',
        sig().replace(
          /(<ds:DigestMethod [^>]*\/>)(<ds:DigestValue>AA==<\/ds:DigestValue>)/,
          '$2$1',
        ),
      ],
      [
        'an element inside DigestValue',
        sig().replace('<ds:DigestValue>AA==', '<ds:DigestValue><x:y xmlns:x="urn:x"/>AA=='),
      ],
      [
        'an element inside SignatureValue',
        sig().replace('<ds:SignatureValue>AA==', '<ds:SignatureValue><x:y xmlns:x="urn:x"/>AA=='),
      ],
      [
        'a foreign element in a Transform',
        sig().replace(
          '<ds:DigestMethod',
          '<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"><x:y xmlns:x="urn:x"/></ds:Transform></ds:Transforms><ds:DigestMethod',
        ),
      ],
      [
        'three Transforms',
        sig().replace(
          '<ds:DigestMethod',
          `<ds:Transforms>${'<ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/>'.repeat(3)}</ds:Transforms><ds:DigestMethod`,
        ),
      ],
      [
        'an empty Transforms',
        sig().replace('<ds:DigestMethod', '<ds:Transforms/><ds:DigestMethod'),
      ],
    ])('refuses %s', (_what, signature) => {
      expect(check(assertion(signature))).toEqual({ ok: false, code: 'signature_shape' });
    });

    it('accepts the other allowed algorithms, transforms, a canonicalization method and KeyInfo', () => {
      for (const [method, digest] of [
        [
          'http://www.w3.org/2001/04/xmldsig-more#rsa-sha512',
          'http://www.w3.org/2001/04/xmlenc#sha512',
        ],
        [
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256',
          'http://www.w3.org/2001/04/xmlenc#sha256',
        ],
        [
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384',
          'http://www.w3.org/2001/04/xmlenc#sha256',
        ],
        [
          'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512',
          'http://www.w3.org/2001/04/xmlenc#sha512',
        ],
      ] as const) {
        const full = sig({ method, digest })
          .replace(
            '<ds:DigestMethod',
            '<ds:Transforms><ds:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><ds:Transform Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:Transforms><ds:DigestMethod',
          )
          .replace(
            '</ds:Signature>',
            '<ds:KeyInfo><ds:X509Data><ds:X509Certificate>AA==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature>',
          );
        expect(check(assertion(full))).toMatchObject({ ok: true });
      }
    });

    describe('the shapes real identity providers send', () => {
      const RSA256 = 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256';
      const SHA256 = 'http://www.w3.org/2001/04/xmlenc#sha256';
      const ENVELOPED = 'http://www.w3.org/2000/09/xmldsig#enveloped-signature';
      /** SignedInfo as the IdPs write it: exclusive c14n, rsa-sha256, enveloped + exc-c14n transforms. */
      const signedInfo = (p: string, uri: string, inclusive = '') =>
        `<${p}SignedInfo><${p}CanonicalizationMethod Algorithm="${EXC}"/><${p}SignatureMethod Algorithm="${RSA256}"/><${p}Reference URI="#${uri}"><${p}Transforms><${p}Transform Algorithm="${ENVELOPED}"/><${p}Transform Algorithm="${EXC}">${inclusive}</${p}Transform></${p}Transforms><${p}DigestMethod Algorithm="${SHA256}"/><${p}DigestValue>AAAA</${p}DigestValue></${p}Reference></${p}SignedInfo>`;
      const x509 = (p: string) =>
        `<${p}KeyInfo><${p}X509Data><${p}X509Certificate>MIIB\nAAAA</${p}X509Certificate></${p}X509Data></${p}KeyInfo>`;
      const status = `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`;

      it.each([
        [
          'Keycloak (dsig: prefix, response and assertion signed, KeyName and KeyValue, a key id in Extensions)',
          `<samlp:Response xmlns:samlp="${P}" xmlns:saml="${A}" Destination="https://q/acs" ID="ID_r" InResponseTo="_req" IssueInstant="2026-01-01T00:00:00Z" Version="2.0"><saml:Issuer>https://kc/realms/x</saml:Issuer><dsig:Signature xmlns:dsig="${DS}">${signedInfo('dsig:', 'ID_r')}<dsig:SignatureValue>AAAA</dsig:SignatureValue><dsig:KeyInfo><dsig:KeyName>k</dsig:KeyName><dsig:X509Data><dsig:X509Certificate>AAAA</dsig:X509Certificate></dsig:X509Data><dsig:KeyValue><dsig:RSAKeyValue><dsig:Modulus>AAAA</dsig:Modulus><dsig:Exponent>AQAB</dsig:Exponent></dsig:RSAKeyValue></dsig:KeyValue></dsig:KeyInfo></dsig:Signature><samlp:Extensions><kckey:KeyInfo xmlns:kckey="urn:keycloak:ext:key:1.0" MessageSigningKeyId="abc"/></samlp:Extensions>${status}<saml:Assertion xmlns="${A}" ID="ID_a" IssueInstant="2026-01-01T00:00:00Z" Version="2.0"><saml:Issuer>https://kc/realms/x</saml:Issuer><dsig:Signature xmlns:dsig="${DS}">${signedInfo('dsig:', 'ID_a')}<dsig:SignatureValue>AAAA</dsig:SignatureValue></dsig:Signature><saml:Subject><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">G-1</saml:NameID></saml:Subject></saml:Assertion></samlp:Response>`,
        ],
        [
          'Entra ID (no prefixes, the Signature in the default namespace)',
          `<samlp:Response ID="_r" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://q/acs" InResponseTo="_req" xmlns:samlp="${P}"><Issuer xmlns="${A}">https://sts.windows.net/t/</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><Assertion ID="_a" IssueInstant="2026-01-01T00:00:00Z" Version="2.0" xmlns="${A}"><Issuer>https://sts.windows.net/t/</Issuer><Signature xmlns="${DS}">${signedInfo('', '_a')}<SignatureValue>AAAA</SignatureValue>${x509('')}</Signature><Subject><NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">a@b.c</NameID></Subject><AttributeStatement><Attribute Name="http://schemas.microsoft.com/ws/2008/06/identity/claims/groups"><AttributeValue>g</AttributeValue></Attribute></AttributeStatement></Assertion></samlp:Response>`,
        ],
        [
          'Okta (saml2: prefixes, ds: signature, InclusiveNamespaces in the exc-c14n Transform)',
          `<?xml version="1.0" encoding="UTF-8"?><saml2p:Response xmlns:saml2p="${P}" Destination="https://q/acs" ID="id1" InResponseTo="_req" IssueInstant="2026-01-01T00:00:00Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer xmlns:saml2="${A}" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/x</saml2:Issuer><saml2p:Status xmlns:saml2p="${P}"><saml2p:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></saml2p:Status><saml2:Assertion xmlns:saml2="${A}" ID="id2" IssueInstant="2026-01-01T00:00:00Z" Version="2.0" xmlns:xs="http://www.w3.org/2001/XMLSchema"><saml2:Issuer Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity">http://www.okta.com/x</saml2:Issuer><ds:Signature xmlns:ds="${DS}">${signedInfo('ds:', 'id2', `<ec:InclusiveNamespaces xmlns:ec="${EXC}" PrefixList="xs"/>`)}<ds:SignatureValue>AAAA</ds:SignatureValue>${x509('ds:')}</ds:Signature><saml2:Subject><saml2:NameID Format="urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified">a@b.c</saml2:NameID></saml2:Subject><saml2:AttributeStatement><saml2:Attribute Name="groups"><saml2:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">g</saml2:AttributeValue></saml2:Attribute></saml2:AttributeStatement></saml2:Assertion></saml2p:Response>`,
        ],
        [
          'AD FS (default-namespace assertion, ds: signature with a default-namespace KeyInfo)',
          `<samlp:Response ID="_r" Version="2.0" IssueInstant="2026-01-01T00:00:00Z" Destination="https://q/acs" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified" InResponseTo="_req" xmlns:samlp="${P}"><Issuer xmlns="${A}">http://adfs/adfs/services/trust</Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success" /></samlp:Status><Assertion ID="_a" IssueInstant="2026-01-01T00:00:00Z" Version="2.0" xmlns="${A}"><Issuer>http://adfs/adfs/services/trust</Issuer><ds:Signature xmlns:ds="${DS}">${signedInfo('ds:', '_a')}<ds:SignatureValue>AAAA</ds:SignatureValue><KeyInfo xmlns="${DS}"><ds:X509Data><ds:X509Certificate>AAAA</ds:X509Certificate></ds:X509Data></KeyInfo></ds:Signature><Subject><NameID>u</NameID></Subject></Assertion></samlp:Response>`,
        ],
      ])('accepts %s', (_idp, xml) => {
        expect(check(xml)).toMatchObject({ ok: true });
      });
    });

    it('checks a signature on the response as well as on the assertion', () => {
      const xml = response().replace(
        'Destination="https://q/acs">',
        `Destination="https://q/acs">${sig({ method: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' }).replaceAll('#a1', '#r1')}`,
      );
      expect(check(xml)).toEqual({ ok: false, code: 'signature_shape' });
    });

    it('does not judge the RSA-OAEP digest inside an encrypted assertion', () => {
      const enc = `<saml:EncryptedAssertion xmlns:saml="${A}"><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes256-cbc"/><ds:KeyInfo xmlns:ds="${DS}"><xenc:EncryptedKey><xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/></xenc:EncryptionMethod><xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedKey></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>AA==</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></saml:EncryptedAssertion>`;
      expect(check(response(enc), true)).toMatchObject({ ok: true });
    });
  });

  describe('structure and bounds', () => {
    it.each([
      [
        'a Response nested in the assertion',
        assertion(`${sig()}<samlp:Response xmlns:samlp="${P}" ID="r9"/>`),
        'assertion_count',
      ],
      [
        'a Response in a foreign namespace in the assertion',
        assertion(`${sig()}<x:Response xmlns:x="urn:x"/>`),
        'assertion_count',
      ],
      [
        'an assertion in an Extensions element',
        response(
          `<samlp:Extensions><saml:Assertion xmlns:saml="${A}" ID="a2"/></samlp:Extensions><saml:Assertion xmlns:saml="${A}" ID="a1">${sig()}</saml:Assertion>`,
        ),
        'assertion_count',
      ],
      [
        'an assertion and an encrypted assertion',
        response(
          `<saml:Assertion xmlns:saml="${A}" ID="a1">${sig()}</saml:Assertion><saml:EncryptedAssertion xmlns:saml="${A}"/>`,
        ),
        'assertion_count',
      ],
      [
        'an ID and an Id with the same value',
        assertion(`${sig()}<saml:Subject Id="a1"/>`),
        'duplicate_id',
      ],
      [
        'a namespaced ID repeating another',
        assertion(`${sig()}<saml:Subject xmlns:x="urn:x" x:ID="r1"/>`),
        'duplicate_id',
      ],
      ['5 001 elements', assertion(`${sig()}${'<x/>'.repeat(5_001)}`), 'too_complex'],
      [
        'an attribute value over 64 KiB',
        response().replace('ID="a1"', `ID="a1" x="${'a'.repeat(65_537)}"`),
        'too_complex',
      ],
      [
        'a document over 256 KiB',
        assertion(`${sig()}<x>${'a'.repeat(SAML_MAX_BYTES)}</x>`),
        'too_complex',
      ],
    ])('refuses %s', (_what, xml, code) => {
      expect(check(xml)).toEqual({ ok: false, code });
    });

    it.each([
      ['a NUL character reference in text', '&#0;'],
      ['a control character reference in text', '&#x1;'],
      ['a lone surrogate reference in text', '&#xD800;'],
      ['a U+FFFE reference in text', '&#xFFFE;'],
      ['a reference beyond U+10FFFF', '&#x110000;'],
    ])('refuses %s', (_what, ref) => {
      expect(check(response().replace('alice', `al${ref}ice`))).toEqual({
        ok: false,
        code: 'malformed',
      });
    });

    it.each([['&#0;'], ['&#x1;'], ['&#xD800;'], ['&#xFFFE;']])(
      'refuses the character reference %s in an attribute value',
      (ref) => {
        const xml = response().replace('<saml:NameID>', `<saml:NameID Format="x${ref}y">`);
        expect(check(xml)).toEqual({ ok: false, code: 'malformed' });
      },
    );

    it('accepts ordinary character references in text and attributes', () => {
      const xml = response().replace(
        '<saml:NameID>alice',
        '<saml:NameID Format="a&#x9;b&#13;">al&#xE9;ice&#10;',
      );
      expect(check(xml)).toMatchObject({ ok: true });
    });

    it('refuses more than 64 attributes on one element before parsing', () => {
      const attrs = (n: number) => Array.from({ length: n }, (_, i) => ` a${i}="v"`).join('');
      expect(
        check(response().replace('<saml:Subject>', `<saml:Subject${attrs(64)}>`)),
      ).toMatchObject({ ok: true });
      expect(check(response().replace('<saml:Subject>', `<saml:Subject${attrs(65)}>`))).toEqual({
        ok: false,
        code: 'too_complex',
      });
    });

    it('does not count `=`, `>` or `/` inside attribute values as markup', () => {
      const xml = response().replace(
        '<saml:NameID>',
        `<saml:NameID Format="a=b>c/" SPNameQualifier='x="/>'>`,
      );
      expect(check(xml)).toMatchObject({ ok: true });
    });

    const wrap = (inner: string, attrs = '') =>
      `<samlp:Response xmlns:samlp="${P}" ID="r1"${attrs}>${inner}</samlp:Response>`;
    const many = (n: number, f: (i: number) => string) =>
      Array.from({ length: n }, (_, i) => f(i)).join('');

    it.each([
      [
        '13 500 nested levels, each declaring a namespace',
        wrap('<a xmlns:q="u">'.repeat(13_500) + '</a>'.repeat(13_500)),
      ],
      [
        '7 000 nested levels, each declaring two namespaces',
        wrap('<a xmlns:q="u" xmlns:r="u">'.repeat(7_000) + '</a>'.repeat(7_000)),
      ],
      [
        '12 000 namespace declarations on the root',
        wrap(
          '',
          many(12_000, (i) => ` xmlns:p${i}="u"`),
        ),
      ],
      [
        '5 000 declarations on the root and 3 000 children',
        wrap(
          '<a/>'.repeat(3_000),
          many(5_000, (i) => ` xmlns:p${i}="u"`),
        ),
      ],
      [
        '33 nested levels, each declaring two namespaces',
        wrap('<a xmlns:q="u" xmlns:r="u">'.repeat(32) + '</a>'.repeat(32)),
      ],
      ['36 000 nested levels', wrap('<a>'.repeat(36_000) + '</a>'.repeat(36_000))],
      ['60 000 flat elements', wrap('<a/>'.repeat(60_000))],
      [
        '23 000 attributes on the root',
        wrap(
          '',
          many(23_000, (i) => ` a${i}="v"`),
        ),
      ],
      ['10 001 start-tag characters', wrap('<'.repeat(10_001))],
    ])(`refuses %s as too_complex, before parsing, in under ${TIME_BOUND_MS} ms`, (_what, xml) => {
      const { result, ms } = fastest(() => check(xml));
      expect(result).toEqual({ ok: false, code: 'too_complex' });
      expect(ms).toBeLessThan(TIME_BOUND_MS);
    });

    describe('many namespace declarations (Keycloak, Okta, Google: xs and xsi on every value)', () => {
      const info = (uri: string) =>
        `<dsig:SignedInfo><dsig:CanonicalizationMethod Algorithm="${EXC}"/><dsig:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><dsig:Reference URI="#${uri}"><dsig:Transforms><dsig:Transform Algorithm="http://www.w3.org/2000/09/xmldsig#enveloped-signature"/><dsig:Transform Algorithm="${EXC}"/></dsig:Transforms><dsig:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/><dsig:DigestValue>AAAA</dsig:DigestValue></dsig:Reference></dsig:SignedInfo>`;
      const value = (v: string) =>
        `<saml:AttributeValue xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:type="xs:string">${v}</saml:AttributeValue>`;
      /** A Keycloak-shaped response, both signed, with `groups` values each declaring xs and xsi. */
      const keycloak = (groups: number) =>
        `<samlp:Response xmlns:samlp="${P}" xmlns:saml="${A}" Destination="https://q/acs" ID="ID_r" InResponseTo="_req" IssueInstant="2026-01-01T00:00:00Z" Version="2.0"><saml:Issuer>https://kc/realms/x</saml:Issuer><dsig:Signature xmlns:dsig="${DS}">${info('ID_r')}<dsig:SignatureValue>AAAA</dsig:SignatureValue></dsig:Signature><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status><saml:Assertion xmlns="${A}" ID="ID_a" IssueInstant="2026-01-01T00:00:00Z" Version="2.0"><saml:Issuer>https://kc/realms/x</saml:Issuer><dsig:Signature xmlns:dsig="${DS}">${info('ID_a')}<dsig:SignatureValue>AAAA</dsig:SignatureValue></dsig:Signature><saml:Subject><saml:NameID>G-1</saml:NameID></saml:Subject><saml:AttributeStatement><saml:Attribute Name="email">${value('a@b')}</saml:Attribute><saml:Attribute Name="groups">${many(groups, (i) => value(`/g${i}`))}</saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>`;

      it('accepts 150 group values, each declaring xmlns:xs and xmlns:xsi, with both signatures', () => {
        expect(check(keycloak(150))).toMatchObject({ ok: true, inResponseTo: '_req' });
      });

      it(`finishes the worst case (2 400 values, two declarations each, over 290 KiB) in under ${TIME_BOUND_MS} ms, whatever its code`, () => {
        const xml = keycloak(2_400);
        expect(Buffer.byteLength(xml) / 1024).toBeGreaterThan(290);
        expect(fastest(() => check(xml)).ms).toBeLessThan(TIME_BOUND_MS);
      });

      it(`accepts the largest such response under the size bound (1 500 values) in under ${TIME_BOUND_MS} ms`, () => {
        const xml = keycloak(1_500);
        expect(Buffer.byteLength(xml)).toBeLessThanOrEqual(SAML_MAX_BYTES);
        const { result, ms } = fastest(() => check(xml));
        expect(ms).toBeLessThan(TIME_BOUND_MS);
        expect(result).toMatchObject({ ok: true });
      });
    });

    it('counts raw depth from the tag stream (33 levels refused before parsing)', () => {
      const deep = (n: number) => wrap('<a>'.repeat(n - 1) + '</a>'.repeat(n - 1));
      expect(check(deep(32))).toEqual({ ok: false, code: 'assertion_count' });
      expect(check(deep(33))).toEqual({ ok: false, code: 'too_complex' });
    });

    it('accepts nesting of exactly 32', () => {
      // Response (1) > Assertion (2) > 30 x.
      expect(check(assertion(`${sig()}${'<x>'.repeat(30)}${'</x>'.repeat(30)}`))).toMatchObject({
        ok: true,
      });
      expect(check(assertion(`${sig()}${'<x>'.repeat(31)}${'</x>'.repeat(31)}`))).toEqual({
        ok: false,
        code: 'too_complex',
      });
    });

    it('returns null for an absent InResponseTo or Destination', () => {
      expect(check(response(undefined, 'ID="r1"'))).toMatchObject({
        ok: true,
        inResponseTo: null,
        destination: null,
      });
    });

    it('checks metadata as an EntityDescriptor, up to 1 MiB', () => {
      const md = (inner = '') =>
        `<md:EntityDescriptor xmlns:md="${MD}" entityID="https://idp">${inner}<md:IDPSSODescriptor/></md:EntityDescriptor>`;
      const meta = (xml: string) =>
        samlPreCheck(xml, { root: 'EntityDescriptor', hasSpKey: false });
      expect(meta(md())).toMatchObject({ ok: true, inResponseTo: null, destination: null });
      expect(meta(md(sig()))).toMatchObject({ ok: true });
      expect(meta(md(`<x>${'a'.repeat(SAML_MAX_BYTES)}</x>`))).toMatchObject({ ok: true });
      expect(meta(md(`<x>${'a'.repeat(1_048_576)}</x>`))).toEqual({
        ok: false,
        code: 'too_complex',
      });
      // Ruling M-3: metadata may carry comments (Shibboleth writes them); nothing else relaxes.
      expect(meta(md('<!---->'))).toMatchObject({ ok: true });
      expect(meta(`<!-- generated -->${md('<!-- a > b <x/> "q -->')}<!-- end -->`)).toMatchObject({
        ok: true,
      });
      expect(meta(md('<!-- <!DOCTYPE x> -->'))).toEqual({ ok: false, code: 'doctype' });
      expect(meta(md('<!-- x --><?pi x?>'))).toEqual({ ok: false, code: 'processing_instruction' });
      expect(meta(md('<!-- <?pi x?> -->'))).toEqual({
        ok: false,
        code: 'processing_instruction',
      });
      expect(meta(md('<![CDATA[x]]>'))).toEqual({ ok: false, code: 'cdata' });
      expect(meta(md(`<!-- ${'<x>'.repeat(40)} -->`))).toMatchObject({ ok: true });
      expect(meta(md(sig({ method: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' })))).toEqual({
        ok: false,
        code: 'signature_shape',
      });
      expect(meta(md(`<saml:Assertion xmlns:saml="${A}"/>`))).toEqual({
        ok: false,
        code: 'assertion_count',
      });
      expect(meta(response())).toEqual({ ok: false, code: 'not_response' });
      expect(check(md())).toEqual({ ok: false, code: 'not_response' });
    });

    it('reports an IdP refusal without an assertion as idp_status, and keeps Success as assertion_count', () => {
      const status = (value: string) =>
        response(`<samlp:Status><samlp:StatusCode Value="${value}"/></samlp:Status>`);
      expect(check(status('urn:oasis:names:tc:SAML:2.0:status:Responder'))).toEqual({
        ok: false,
        code: 'idp_status',
      });
      expect(check(status('urn:oasis:names:tc:SAML:2.0:status:Success'))).toEqual({
        ok: false,
        code: 'assertion_count',
      });
      // Only the response's own Status counts; with a malformed signature it is never idp_status.
      expect(
        check(
          response(
            `<x:Status xmlns:x="urn:other"><x:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/></x:Status>`,
          ),
        ),
      ).toEqual({ ok: false, code: 'assertion_count' });
      expect(
        check(
          response(
            `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"/></samlp:Status>${sig({ refs: 2 })}`,
          ),
        ),
      ).toEqual({ ok: false, code: 'assertion_count' });
    });
  });
});

describe('samlAssertionCheck (sso-scim.md §6.3)', () => {
  const assertionDoc = (body = '<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject>') =>
    `<saml:Assertion xmlns:saml="${A}" ID="a1">${body}</saml:Assertion>`;

  it('accepts one Assertion as the document element and returns it', () => {
    const r = samlAssertionCheck(assertionDoc());
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.assertion.localName).toBe('Assertion');
    expect(samlAssertionCheck(assertionDoc(sig()))).toMatchObject({ ok: true });
  });

  it.each([
    [
      'a comment',
      assertionDoc('<saml:Subject><saml:NameID>a<!---->b</saml:NameID></saml:Subject>'),
      'comment',
    ],
    ['a DOCTYPE', `<!DOCTYPE a []>${assertionDoc()}`, 'doctype'],
    ['a PI', assertionDoc('<?x y?>'), 'processing_instruction'],
    ['CDATA', assertionDoc('<![CDATA[x]]>'), 'cdata'],
    ['a Response root', response(), 'not_response'],
    ['an Assertion in another namespace', `<Assertion xmlns="urn:x" ID="a1"/>`, 'not_response'],
    ['a nested Assertion', assertionDoc(`<saml:Assertion ID="a2"/>`), 'assertion_count'],
    ['a nested Response', assertionDoc(`<samlp:Response xmlns:samlp="${P}"/>`), 'assertion_count'],
    ['a duplicate ID', assertionDoc(`<saml:Subject ID="a1"/>`), 'duplicate_id'],
    [
      'a SHA-1 signature',
      assertionDoc(sig({ method: 'http://www.w3.org/2000/09/xmldsig#rsa-sha1' })),
      'signature_shape',
    ],
    ['a second root', `${assertionDoc()}${assertionDoc()}`, 'not_response'],
    ['a __proto__ element', assertionDoc('<__proto__/>'), 'forbidden_name'],
    [
      'a NUL reference',
      assertionDoc('<saml:Subject><saml:NameID>a&#0;</saml:NameID></saml:Subject>'),
      'malformed',
    ],
  ])('refuses %s', (_name, xml, code) => {
    expect(samlAssertionCheck(xml)).toEqual({ ok: false, code });
  });
});

describe('decodeSamlResponse', () => {
  it('decodes strict base64 only, up to 256 KiB', () => {
    expect(decodeSamlResponse(Buffer.from('<a/>').toString('base64'))).toEqual({
      ok: true,
      xml: '<a/>',
    });
    expect(decodeSamlResponse('%%%')).toEqual({ ok: false, code: 'base64' });
    expect(decodeSamlResponse(Buffer.from(BOM + '<a/>').toString('base64'))).toEqual({
      ok: false,
      code: 'base64',
    });
    expect(decodeSamlResponse(Buffer.alloc(262_145, 'a').toString('base64'))).toEqual({
      ok: false,
      code: 'too_large',
    });
  });

  it('accepts exactly 256 KiB and line-wrapped input', () => {
    const b64 = Buffer.alloc(SAML_MAX_BYTES, 'a').toString('base64');
    expect(decodeSamlResponse(b64)).toMatchObject({ ok: true });
    const wrapped = Buffer.from('<a>hello</a>')
      .toString('base64')
      .replace(/(.{4})/g, '$1\r\n\t ');
    expect(decodeSamlResponse(wrapped)).toEqual({ ok: true, xml: '<a>hello</a>' });
  });

  it.each([
    ['empty input', ''],
    ['only whitespace', ' \r\n'],
    ['the url-safe alphabet', Buffer.from([0xfb, 0xff, 0xbf]).toString('base64url')],
    ['missing padding', 'PGEvPg'],
    ['padding in the middle', 'PA==PGEvPg=='],
    ['three padding characters', 'PGE==='],
    ['non-canonical trailing bits', 'PGF='],
    ['a form feed', 'PGEv\fPg=='],
    ['a non-breaking space', 'PGEv' + String.fromCharCode(0xa0) + 'Pg=='],
    ['invalid UTF-8', Buffer.from([0x3c, 0x61, 0xc3, 0x28, 0x2f, 0x3e]).toString('base64')],
    [
      'an overlong UTF-8 encoding',
      Buffer.from([0x3c, 0xc0, 0xbc, 0x61, 0x2f, 0x3e]).toString('base64'),
    ],
    ['UTF-8 of a surrogate', Buffer.from([0x3c, 0xed, 0xa0, 0x80, 0x3e]).toString('base64')],
    [
      'UTF-16 with its byte-order mark',
      Buffer.from([0xff, 0xfe, 0x3c, 0x00, 0x61, 0x00]).toString('base64'),
    ],
  ])('refuses %s', (_what, b64) => {
    expect(decodeSamlResponse(b64)).toEqual({ ok: false, code: 'base64' });
  });

  it('refuses a byte-order mark before a DOCTYPE without decoding further', () => {
    const b64 = Buffer.from(BOM + '<!DOCTYPE r><r/>').toString('base64');
    expect(decodeSamlResponse(b64)).toEqual({ ok: false, code: 'base64' });
  });

  it('refuses an oversized input before decoding it', () => {
    expect(decodeSamlResponse('A'.repeat(4 * Math.ceil(SAML_MAX_BYTES / 3) + 4))).toEqual({
      ok: false,
      code: 'too_large',
    });
  });
});
