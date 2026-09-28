import {
  constants,
  createCipheriv,
  publicEncrypt,
  randomBytes,
  X509Certificate,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { SignedXml } from 'xml-crypto';

/**
 * The SAML tests' throwaway RSA 2048 key pairs (sso-scim.md §19.3). Node cannot mint X.509
 * certificates, so they are committed fixtures (server/test/fixtures/saml, made once with
 * `openssl req -x509 -newkey rsa:2048 -nodes -days 36500 -sha256`), each key pinned by path and
 * hash in tools/license/license-tool.ts and .gitleaks.toml. They protect nothing.
 */
export interface TestKeyPair {
  keyPem: string;
  certPem: string;
}

const FIXTURES = path.join(path.dirname(fileURLToPath(import.meta.url)), 'fixtures', 'saml');

function pair(name: string): TestKeyPair {
  return Object.freeze({
    keyPem: readFileSync(path.join(FIXTURES, `${name}.key.pem`), 'utf8'),
    certPem: readFileSync(path.join(FIXTURES, `${name}.cert.pem`), 'utf8'),
  });
}

/** The identity provider the tests' connections trust. */
export const TEST_IDP: TestKeyPair = pair('idp');
/** A key the connection does not pin: its signatures must be refused (CVE-2024-32962). */
export const STRANGER: TestKeyPair = pair('stranger');
/** A service provider key pair (`spKey`, `spCertificate`: signed requests, encryption). */
export const TEST_SP: TestKeyPair = pair('sp');

const P = 'urn:oasis:names:tc:SAML:2.0:protocol';
const A = 'urn:oasis:names:tc:SAML:2.0:assertion';
const XENC = 'http://www.w3.org/2001/04/xmlenc#';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
export const SAML_SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
export const PERSISTENT = 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent';
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';

/** What `buildResponse` writes; every field has a default that a correct response uses. */
export interface SamlResponseOptions {
  /** The response's `InResponseTo`; null leaves it out (IdP-initiated). */
  inResponseTo?: string | null;
  /** The SubjectConfirmationData's `InResponseTo` (default: `inResponseTo`); null leaves it out. */
  subjectInResponseTo?: string | null;
  audience?: string;
  recipient?: string;
  /** The response's `Destination` (default: `recipient`); null leaves it out. */
  destination?: string | null;
  /** The assertion's `Issuer` (default `https://idp.test/saml`). */
  issuer?: string;
  /** The response's `Issuer` (default: `issuer`); null leaves it out. */
  responseIssuer?: string | null;
  nameId?: string;
  /** Default persistent; null leaves the Format out. */
  nameIdFormat?: string | null;
  attributes?: Record<string, string[]>;
  /** Default: now − 10 s. */
  notBefore?: Date;
  /** Default: now + 5 minutes (the conditions' and the subject confirmation's). */
  notOnOrAfter?: Date;
  /** The response's top-level status (default Success). */
  status?: string;
  signAssertion?: boolean;
  signResponse?: boolean;
  /** The signing key and certificate (default TEST_IDP). */
  key?: string;
  cert?: string;
  /** The certificate put into `KeyInfo` (default: `cert`). */
  keyInfoCert?: string;
  signatureAlgorithm?: string;
  digestAlgorithm?: string;
  assertionId?: string;
  /** Default true. */
  authnStatement?: boolean;
  /** Default bearer. */
  confirmationMethod?: string;
  /** An SP certificate: the signed assertion is sent as an `EncryptedAssertion` for it. */
  encryptFor?: string;
  /** Applied to the finished XML, after signing and encryption. */
  transform?: (xml: string) => string;
}

const esc = (s: string): string =>
  s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const newId = (): string => `_${randomBytes(16).toString('hex')}`;

function sign(
  xml: string,
  xpath: string,
  key: string,
  cert: string,
  opts: { signatureAlgorithm?: string; digestAlgorithm?: string; keyInfoCert?: string },
): string {
  const sig = new SignedXml({
    privateKey: key,
    publicCert: opts.keyInfoCert ?? cert,
    signatureAlgorithm:
      opts.signatureAlgorithm ?? 'http://www.w3.org/2001/04/xmldsig-more#rsa-sha256',
    canonicalizationAlgorithm: 'http://www.w3.org/2001/10/xml-exc-c14n#',
  });
  sig.addReference({
    xpath,
    transforms: [
      'http://www.w3.org/2000/09/xmldsig#enveloped-signature',
      'http://www.w3.org/2001/10/xml-exc-c14n#',
    ],
    digestAlgorithm: opts.digestAlgorithm ?? 'http://www.w3.org/2001/04/xmlenc#sha256',
  });
  sig.computeSignature(xml, {
    location: { reference: `${xpath}/*[local-name(.)='Issuer']`, action: 'after' },
  });
  return sig.getSignedXml();
}

/**
 * XML Encryption of `plaintext` for the certificate's RSA key: AES-256-GCM content, the key sent
 * with RSA-OAEP (MGF1, SHA-1), as Entra ID and Okta write it.
 */
export function encryptAssertion(plaintext: string, certPem: string): string {
  const aesKey = randomBytes(32);
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', aesKey, iv);
  const body = Buffer.concat([
    cipher.update(plaintext, 'utf8'),
    cipher.final(),
    cipher.getAuthTag(),
  ]);
  const wrapped = publicEncrypt(
    {
      key: new X509Certificate(certPem).publicKey,
      padding: constants.RSA_PKCS1_OAEP_PADDING,
      oaepHash: 'sha1',
    },
    aesKey,
  );
  return (
    `<saml:EncryptedAssertion xmlns:saml="${A}">` +
    `<xenc:EncryptedData xmlns:xenc="${XENC}" Type="${XENC}Element">` +
    `<xenc:EncryptionMethod Algorithm="http://www.w3.org/2009/xmlenc11#aes256-gcm"/>` +
    `<ds:KeyInfo xmlns:ds="${DS}"><xenc:EncryptedKey>` +
    `<xenc:EncryptionMethod Algorithm="${XENC}rsa-oaep-mgf1p"><ds:DigestMethod Algorithm="${DS}sha1"/></xenc:EncryptionMethod>` +
    `<xenc:CipherData><xenc:CipherValue>${wrapped.toString('base64')}</xenc:CipherValue></xenc:CipherData>` +
    `</xenc:EncryptedKey></ds:KeyInfo>` +
    `<xenc:CipherData><xenc:CipherValue>${Buffer.concat([iv, body]).toString('base64')}</xenc:CipherValue></xenc:CipherData>` +
    `</xenc:EncryptedData></saml:EncryptedAssertion>`
  );
}

/**
 * A SAML 2.0 Response (sso-scim.md §19.3's template), its assertion signed with xml-crypto (the
 * library node-saml verifies with), and optionally the response too; base64, as an IdP posts it.
 */
export function buildResponse(options: SamlResponseOptions = {}): string {
  const now = Date.now();
  const iso = (d: Date) => d.toISOString();
  const inResponseTo = options.inResponseTo === undefined ? null : options.inResponseTo;
  const subjectInResponseTo =
    options.subjectInResponseTo === undefined ? inResponseTo : options.subjectInResponseTo;
  const recipient = options.recipient ?? 'https://sp.invalid/acs';
  const destination = options.destination === undefined ? recipient : options.destination;
  const issuer = options.issuer ?? 'https://idp.test/saml';
  const responseIssuer = options.responseIssuer === undefined ? issuer : options.responseIssuer;
  const nameIdFormat = options.nameIdFormat === undefined ? PERSISTENT : options.nameIdFormat;
  const notBefore = options.notBefore ?? new Date(now - 10_000);
  const notOnOrAfter = options.notOnOrAfter ?? new Date(now + 300_000);
  const assertionId = options.assertionId ?? newId();
  const attributes = options.attributes ?? {
    email: ['alice@acme.example'],
    displayName: ['Alice A'],
    groups: ['qualor-admins'],
  };
  const key = options.key ?? TEST_IDP.keyPem;
  const cert = options.cert ?? TEST_IDP.certPem;
  const signOpts = {
    ...(options.signatureAlgorithm ? { signatureAlgorithm: options.signatureAlgorithm } : {}),
    ...(options.digestAlgorithm ? { digestAlgorithm: options.digestAlgorithm } : {}),
    ...(options.keyInfoCert ? { keyInfoCert: options.keyInfoCert } : {}),
  };

  const attributeXml = Object.entries(attributes)
    .map(
      ([name, values]) =>
        `<saml:Attribute Name="${esc(name)}">${values
          .map((v) => `<saml:AttributeValue>${esc(v)}</saml:AttributeValue>`)
          .join('')}</saml:Attribute>`,
    )
    .join('');
  const irt = (value: string | null) => (value === null ? '' : ` InResponseTo="${esc(value)}"`);
  let assertion =
    `<saml:Assertion xmlns:saml="${A}" ID="${assertionId}" Version="2.0" IssueInstant="${iso(new Date(now))}">` +
    `<saml:Issuer>${esc(issuer)}</saml:Issuer>` +
    `<saml:Subject><saml:NameID${nameIdFormat === null ? '' : ` Format="${esc(nameIdFormat)}"`}>${esc(options.nameId ?? 'alice-persistent-id')}</saml:NameID>` +
    `<saml:SubjectConfirmation Method="${esc(options.confirmationMethod ?? BEARER)}">` +
    `<saml:SubjectConfirmationData${irt(subjectInResponseTo)} NotOnOrAfter="${iso(notOnOrAfter)}" Recipient="${esc(recipient)}"/>` +
    `</saml:SubjectConfirmation></saml:Subject>` +
    `<saml:Conditions NotBefore="${iso(notBefore)}" NotOnOrAfter="${iso(notOnOrAfter)}">` +
    `<saml:AudienceRestriction><saml:Audience>${esc(options.audience ?? 'https://sp.invalid')}</saml:Audience></saml:AudienceRestriction>` +
    `</saml:Conditions>` +
    (options.authnStatement === false
      ? ''
      : `<saml:AuthnStatement AuthnInstant="${iso(new Date(now))}" SessionIndex="${newId()}"><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>`) +
    (attributeXml ? `<saml:AttributeStatement>${attributeXml}</saml:AttributeStatement>` : '') +
    `</saml:Assertion>`;
  if (options.signAssertion !== false) {
    assertion = sign(assertion, "/*[local-name(.)='Assertion']", key, cert, signOpts);
  }
  if (options.encryptFor) assertion = encryptAssertion(assertion, options.encryptFor);

  let xml =
    `<samlp:Response xmlns:samlp="${P}" xmlns:saml="${A}" ID="${newId()}" Version="2.0" IssueInstant="${iso(new Date(now))}"` +
    `${destination === null ? '' : ` Destination="${esc(destination)}"`}${irt(inResponseTo)}>` +
    (responseIssuer === null ? '' : `<saml:Issuer>${esc(responseIssuer)}</saml:Issuer>`) +
    `<samlp:Status><samlp:StatusCode Value="${esc(options.status ?? SAML_SUCCESS)}"/></samlp:Status>` +
    assertion +
    `</samlp:Response>`;
  if (options.signResponse) {
    xml = sign(xml, "/*[local-name(.)='Response']", key, cert, signOpts);
  }
  if (options.transform) xml = options.transform(xml);
  return Buffer.from(xml, 'utf8').toString('base64');
}

// ─── Signature wrapping (sso-scim.md §19.3: XSW1–XSW8) ──────────────────────

/** The one assertion of a response `buildResponse` wrote (before any wrapping). */
const ASSERTION = /<saml:Assertion\b[\s\S]*<\/saml:Assertion>/;
/** xml-crypto writes its Signature with the default namespace; none nests another. */
const SIGNATURE =
  /<Signature xmlns="http:\/\/www\.w3\.org\/2000\/09\/xmldsig#">[\s\S]*?<\/Signature>/;
/** The NameID every wrapped (evil) assertion claims. */
export const EVIL_NAME_ID = 'admin-persistent-id';

function only(re: RegExp, xml: string): string {
  const m = re.exec(xml);
  if (!m) throw new Error(`no match for ${String(re)}`);
  return m[0];
}
/** `xml` with the first `from` replaced by `to`, literally (no `$` patterns). */
const put = (xml: string, from: string, to: string): string => {
  const at = xml.indexOf(from);
  if (at < 0) throw new Error('nothing to replace');
  return xml.slice(0, at) + to + xml.slice(at + from.length);
};
/** The assertion's NameID changed to EVIL_NAME_ID. */
const evilOf = (assertion: string): string =>
  assertion.replace(/(<saml:NameID\b[^>]*>)[^<]*(<\/saml:NameID>)/, `$1${EVIL_NAME_ID}$2`);
/** Inserts `child` just before the element's last closing tag `close`. */
const beforeClose = (element: string, close: string, child: string): string => {
  const at = element.lastIndexOf(close);
  return element.slice(0, at) + child + element.slice(at);
};

export interface XswVariant {
  name: string;
  /** Whether the response itself must be signed (XSW1 and XSW2 wrap the response's signature). */
  signResponse: boolean;
  /** Takes the signed response XML, gives the wrapped one. */
  wrap: (xml: string) => string;
}

/**
 * The eight signature-wrapping variants of the SAML Raider taxonomy. Each keeps a validly signed
 * element somewhere in the document for a verifier that looks the signed ID up anywhere, and puts
 * an unsigned or edited copy with NameID EVIL_NAME_ID where a naive reader takes the assertion.
 */
export const XSW_VARIANTS: readonly XswVariant[] = [
  {
    name: 'XSW1: an evil response wrapping the signed original inside its Signature',
    signResponse: true,
    wrap: (xml) => {
      const signature = only(SIGNATURE, xml);
      const evil = put(
        xml,
        only(ASSERTION, xml),
        evilOf(only(ASSERTION, xml).replace(SIGNATURE, '')),
      ).replace(/ ID="[^"]+"/, ' ID="_evil-response"');
      return put(evil, signature, beforeClose(signature, '</Signature>', xml));
    },
  },
  {
    name: 'XSW2: an evil response with the signed original detached before its Signature',
    signResponse: true,
    wrap: (xml) => {
      const signature = only(SIGNATURE, xml);
      const evil = put(
        xml,
        only(ASSERTION, xml),
        evilOf(only(ASSERTION, xml).replace(SIGNATURE, '')),
      ).replace(/ ID="[^"]+"/, ' ID="_evil-response"');
      return put(evil, signature, xml + signature);
    },
  },
  {
    name: 'XSW3: an unsigned evil assertion with the same ID before the signed one',
    signResponse: false,
    wrap: (xml) => {
      const signed = only(ASSERTION, xml);
      return put(xml, signed, evilOf(signed.replace(SIGNATURE, '')) + signed);
    },
  },
  {
    name: 'XSW4: the signed assertion moved inside an unsigned evil assertion',
    signResponse: false,
    wrap: (xml) => {
      const signed = only(ASSERTION, xml);
      const evil = evilOf(signed.replace(SIGNATURE, ''));
      return put(xml, signed, beforeClose(evil, '</saml:Assertion>', signed));
    },
  },
  {
    name: 'XSW5: the signed assertion edited in place, the original minus its Signature appended',
    signResponse: false,
    wrap: (xml) => {
      const signed = only(ASSERTION, xml);
      return put(xml, signed, evilOf(signed) + signed.replace(SIGNATURE, ''));
    },
  },
  {
    name: 'XSW6: the original minus its Signature inside the edited assertion’s Signature',
    signResponse: false,
    wrap: (xml) => {
      const signed = only(ASSERTION, xml);
      const evil = evilOf(signed);
      const signature = only(SIGNATURE, evil);
      const original = signed.replace(SIGNATURE, '');
      return put(
        xml,
        signed,
        put(evil, signature, beforeClose(signature, '</Signature>', original)),
      );
    },
  },
  {
    name: 'XSW7: an unsigned evil assertion in samlp:Extensions beside the signed one',
    signResponse: false,
    wrap: (xml) => {
      const signed = only(ASSERTION, xml);
      const evil = evilOf(signed.replace(SIGNATURE, ''));
      return put(
        xml,
        '<samlp:Status>',
        `<samlp:Extensions>${evil}</samlp:Extensions><samlp:Status>`,
      );
    },
  },
  {
    name: 'XSW8: the unsigned original inside ds:Object in the edited assertion’s Signature',
    signResponse: false,
    wrap: (xml) => {
      const signed = only(ASSERTION, xml);
      const evil = evilOf(signed);
      const signature = only(SIGNATURE, evil);
      const original = signed.replace(SIGNATURE, '');
      return put(
        xml,
        signed,
        put(
          evil,
          signature,
          beforeClose(signature, '</Signature>', `<Object>${original}</Object>`),
        ),
      );
    },
  },
];

/** The signed assertion of a response `buildResponse` wrote (base64), for splicing into another. */
export function signedAssertionOf(b64: string): string {
  return only(ASSERTION, Buffer.from(b64, 'base64').toString('utf8'));
}
