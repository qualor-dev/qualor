import { randomBytes, timingSafeEqual } from 'node:crypto';
import {
  SAML,
  SamlStatusError,
  ValidateInResponseTo,
  type CacheProvider,
  type Profile,
} from '@node-saml/node-saml';
// The decryption node-saml itself runs, so the plaintext pre-checked here is the plaintext it reads.
import { decryptXml } from '@node-saml/node-saml/lib/xml.js';
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { isStorableText } from '../audit/canonical';
import { validationFailed } from '../http/problem';
import type { SignInClaims } from './accounts';
import { bindingMatches, newBinding, setBindingCookie, SSO_COOKIE } from './binding';
import { requiredClaimsMet } from './claims';
import { completeSignIn, type FlowDeps } from './complete';
import type { SamlConfig } from './connection-config';
import {
  certificateInfo,
  isConnectionInEffect,
  loadConnection,
  UNDECRYPTABLE_SP_KEY,
  type LoadedConnection,
  type SsoCertificateView,
} from './connections';
import { failSsoFlow, SsoFailure } from './errors';
import { createSsoFetch } from './fetch';
import { MAX_GROUP_VALUES } from './groups';
import { safeReturnTo } from './return-to';
import {
  decodeSamlResponse,
  SAML_METADATA_MAX_BYTES,
  samlAssertionCheck,
  samlPreCheck,
  topStatus,
  type XmlElement,
} from './saml-guard';
import {
  FINISH_TTL_MS,
  putState,
  samlCacheProvider,
  StateExists,
  stateKey,
  takeState,
} from './states';
import { idpUrlProblem, normalIdpUrl, ssoUrls } from './urls';

/** sso-scim.md §6.2: the ACS body bound (Task 19 mounts the route with it). */
export const SAML_ACS_BODY_LIMIT = 524_288;

/** sso-scim.md §6.1: the flow row of a SAML sign-in or link (node-saml adds `issueInstant`). */
export interface SamlFlowPayload {
  connectionId: string;
  returnTo: string;
  intent: 'sign_in' | 'link';
  linkUserId: string | null;
  /** The SHA-256 (hex) of the `qualor_sso` cookie. */
  binding: string;
  /** The RelayState: an opaque 32-byte reference (base64url), never a URL. */
  relay: string;
}

/** sso-scim.md §6.4, §7.4: what the ACS hands to the finish step. */
export interface FinishPayload {
  claims: SignInClaims;
  flow: SamlFlowPayload;
}

const A = 'urn:oasis:names:tc:SAML:2.0:assertion';
const MD = 'urn:oasis:names:tc:SAML:2.0:metadata';
const DS = 'http://www.w3.org/2000/09/xmldsig#';
const XENC = 'http://www.w3.org/2001/04/xmlenc#';
const SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success';
const BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer';
const UNSPECIFIED = 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified';
const REDIRECT_BINDING = 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect';
/** spec §3.2: 60 s of clock skew. */
const SKEW_MS = 60_000;
/** spec §6.4: an assertion id is remembered at most this long. */
const REPLAY_MAX_MS = 86_400_000;
/** spec §6.3: the NameID is 1–255 characters. */
const NAME_ID_MAX = 255;
/** A claim read from an attribute (as OIDC's, spec §5 step 4). */
const CLAIM_MAX = 1_024;
/** spec §6.4 and the `sso_states_payload_size` check: a finish row's JSON. */
export const FINISH_MAX_BYTES = 16_384;

/**
 * The bytes of `value::text` once stored as jsonb, which is what the `sso_states_payload_size`
 * CHECK measures (`octet_length(payload::text)`): JSON with a space after every `:` and after
 * every `,` between members and elements. jsonb escapes strings as JSON.stringify does (quote,
 * backslash, the short control escapes, other controls as six-character escapes, everything else
 * as UTF-8), and key order does not change the length. Undefined members are left out.
 */
export function jsonbTextBytes(value: unknown): number {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') {
    return Buffer.byteLength(JSON.stringify(value), 'utf8');
  }
  if (typeof value === 'number') {
    // jsonb prints numbers as numeric; the payloads here hold none, so refuse to guess.
    throw new TypeError('numbers are not measured');
  }
  if (Array.isArray(value)) {
    const items = value.map((v: unknown) => jsonbTextBytes(v === undefined ? null : v));
    return 2 + items.reduce((a, b) => a + b, 0) + 2 * Math.max(items.length - 1, 0);
  }
  if (typeof value === 'object') {
    const members = Object.entries(value as Record<string, unknown>).filter(
      ([, v]) => v !== undefined,
    );
    const sizes = members.map(([k, v]) => jsonbTextBytes(k) + 2 + jsonbTextBytes(v));
    return 2 + sizes.reduce((a, b) => a + b, 0) + 2 * Math.max(sizes.length - 1, 0);
  }
  throw new TypeError('not JSON');
}

const RELAY_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const CODE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
/**
 * What an `EncryptedAssertion` may use (the set node-saml's SP metadata offers): AES-GCM or
 * AES-CBC content, the key sent with RSA-OAEP. RSA PKCS#1 v1.5 and 3DES are refused.
 */
const DATA_ENCRYPTION = new Set([
  'http://www.w3.org/2009/xmlenc11#aes256-gcm',
  'http://www.w3.org/2009/xmlenc11#aes128-gcm',
  `${XENC}aes256-cbc`,
  `${XENC}aes128-cbc`,
]);
const KEY_TRANSPORT = `${XENC}rsa-oaep-mgf1p`;

/** node-saml's cache where no request is saved (metadata). */
const NO_CACHE: CacheProvider = {
  saveAsync: () => Promise.resolve(null),
  getAsync: () => Promise.resolve(null),
  removeAsync: () => Promise.resolve(null),
};

/**
 * node-saml's cache while validating one response: the request row was taken already (SS3), so
 * it answers for exactly that request id, with the issue instant the row held.
 */
function takenRequestCache(requestId: string, issueInstant: string): CacheProvider {
  return {
    saveAsync: () => Promise.resolve(null),
    getAsync: (key) => Promise.resolve(key === requestId ? issueInstant : null),
    removeAsync: () => Promise.resolve(null),
  };
}

/** sso-scim.md §3.2: a node-saml instance with exactly the options the spec lists. */
export function samlFor(
  connection: LoadedConnection,
  publicUrl: string,
  cacheProvider: CacheProvider,
): SAML {
  if (connection.parsed.protocol !== 'saml') throw new Error('not a SAML connection');
  const cfg = connection.parsed.config;
  const urls = ssoUrls(publicUrl, connection.row.id);
  return new SAML({
    callbackUrl: urls.acsUrl,
    entryPoint: cfg.idpSsoUrl,
    issuer: urls.entityId,
    audience: urls.entityId,
    idpIssuer: cfg.idpEntityId,
    idpCert: cfg.idpCertificates,
    identifierFormat: cfg.nameIdFormat,
    wantAssertionsSigned: true, // fixed (Global Constraints)
    wantAuthnResponseSigned: cfg.wantResponseSigned,
    validateInResponseTo: ValidateInResponseTo.always,
    requestIdExpirationPeriodMs: 600_000,
    acceptedClockSkewMs: SKEW_MS,
    maxAssertionAgeMs: 0,
    signatureAlgorithm: 'sha256',
    digestAlgorithm: 'sha256',
    disableRequestedAuthnContext: true,
    // spec §6.1: `_` + 32 random bytes in hex.
    generateUniqueId: () => `_${randomBytes(32).toString('hex')}`,
    cacheProvider,
    ...(connection.spKey ? { privateKey: connection.spKey, decryptionPvk: connection.spKey } : {}),
  });
}

/**
 * The connection, if it may run a flow now: SAML with a public URL (else `saml.not_configured`),
 * `sso` active (`saml.inactive`), enabled (`saml.disabled`), in effect (`saml.not_in_effect`,
 * sso-scim.md §4.4), and an SP key that decrypts when one is stored (`saml.sp_key`); each
 * `unavailable`.
 */
async function usable(
  deps: FlowDeps,
  connection: LoadedConnection | null,
): Promise<{ connection: LoadedConnection; cfg: SamlConfig; publicUrl: string }> {
  if (!connection || connection.parsed.protocol !== 'saml' || !deps.config.publicUrl) {
    throw new SsoFailure('unavailable', 'saml.not_configured');
  }
  if (!deps.edition.isFeatureActive('sso')) throw new SsoFailure('unavailable', 'saml.inactive');
  if (!connection.row.enabled) throw new SsoFailure('unavailable', 'saml.disabled');
  if (!(await isConnectionInEffect(deps.db, deps.edition, connection.row.id))) {
    throw new SsoFailure('unavailable', 'saml.not_in_effect');
  }
  if (connection.row.spKeyEnc !== null && connection.spKey === null) {
    deps.log.error({ component: 'sso', connectionId: connection.row.id }, UNDECRYPTABLE_SP_KEY);
    throw new SsoFailure('unavailable', 'saml.sp_key');
  }
  return { connection, cfg: connection.parsed.config, publicUrl: deps.config.publicUrl };
}

/**
 * sso-scim.md §6.1, §7.2, §7.3: stores the flow under the AuthnRequest's id (through node-saml's
 * cache, SS3), sets the binding cookie, and returns the IdP's URL: the HTTP-Redirect binding, the
 * request signed with `rsa-sha256` when the connection has an SP key, the IdP URL's own query
 * (Google's `?idpid=`) kept, and a RelayState that is an opaque 32-byte reference. Throws
 * `SsoFailure('unavailable')` for a connection that cannot run.
 */
export async function startSaml(
  deps: FlowDeps,
  request: FastifyRequest,
  reply: FastifyReply,
  connection: LoadedConnection,
  intent: { returnTo: string; link: { userId: string } | null },
): Promise<string> {
  const { publicUrl } = await usable(deps, connection);
  const binding = newBinding();
  const relay = randomBytes(32).toString('base64url');
  const payload: SamlFlowPayload = {
    connectionId: connection.row.id,
    returnTo: safeReturnTo(intent.returnTo),
    intent: intent.link ? 'link' : 'sign_in',
    linkUserId: intent.link?.userId ?? null,
    binding: binding.hash,
    relay,
  };
  const saml = samlFor(
    connection,
    publicUrl,
    samlCacheProvider(deps.db, { connectionId: connection.row.id, payload }),
  );
  const url = await saml.getAuthorizeUrlAsync(relay, undefined, {});
  setBindingCookie(reply, request, binding.cookie);
  return url;
}

/**
 * The ACS body: `application/x-www-form-urlencoded` read with URLSearchParams, keeping only
 * `SAMLResponse` and `RelayState`, each only when it appears once (a repeated field is dropped, so
 * the ACS refuses the form).
 */
export function parseSamlForm(body: string): Record<string, string> {
  const params = new URLSearchParams(body);
  const out: Record<string, string> = {};
  for (const name of ['SAMLResponse', 'RelayState']) {
    const values = params.getAll(name);
    if (values.length === 1 && values[0] !== undefined) out[name] = values[0];
  }
  return out;
}

/**
 * The ACS route's body handling, for an encapsulated scope (Task 19): every other parser removed
 * (415 for JSON or anything else), the form parser at SAML_ACS_BODY_LIMIT (413 beyond).
 */
export function registerSamlFormParser(app: FastifyInstance): void {
  app.removeAllContentTypeParsers();
  app.addContentTypeParser(
    'application/x-www-form-urlencoded',
    { parseAs: 'string', bodyLimit: SAML_ACS_BODY_LIMIT },
    (request, body, done) => {
      done(null, parseSamlForm(typeof body === 'string' ? body : body.toString('utf8')));
    },
  );
}

const sameText = (a: string, b: string): boolean => {
  const x = Buffer.from(a, 'utf8');
  const y = Buffer.from(b, 'utf8');
  return x.length === y.length && timingSafeEqual(x, y);
};

function childElements(e: XmlElement): XmlElement[] {
  const out: XmlElement[] = [];
  for (let c = e.firstChild; c; c = c.nextSibling) if (c.nodeType === 1) out.push(c as XmlElement);
  return out;
}

/** The children of `e` named `local` in namespace `ns`. */
const kids = (e: XmlElement, ns: string, local: string): XmlElement[] =>
  childElements(e).filter((c) => c.namespaceURI === ns && c.localName === local);

const timeOf = (value: string | null): number | null => {
  if (value === null) return null;
  const t = Date.parse(value);
  return Number.isNaN(t) ? null : t;
};

/** What the ACS reads from the verified assertion itself (§6.3's checks beyond the library). */
interface AssertionFacts {
  assertionId: string;
  nameId: string;
  /** When the assertion stops being acceptable anywhere (the latest NotOnOrAfter), ms. */
  validUntil: number;
}

/**
 * sso-scim.md §6.3: the checks node-saml 5.1.0 does not make, on the assertion it verified. The
 * assertion's `Issuer` is the IdP's entity id (node-saml checks it only on logout messages); a
 * bearer `SubjectConfirmation` whose data names the ACS as `Recipient`, this request as
 * `InResponseTo` and a `NotOnOrAfter` still ahead (with the skew); an `AuthnStatement`; one
 * `NameID` of the connection's format (any for `unspecified`), 1–255 storable characters, equal to
 * what node-saml read; an `ID`.
 */
function assertionFacts(
  assertion: XmlElement,
  expected: { issuer: string; acsUrl: string; inResponseTo: string; nameIdFormat: string },
  profileNameId: unknown,
  now: number,
): AssertionFacts {
  const issuers = kids(assertion, A, 'Issuer');
  if (issuers.length !== 1 || issuers[0]?.textContent !== expected.issuer) {
    throw new SsoFailure('invalid_response', 'saml.issuer');
  }
  const assertionId = assertion.getAttribute('ID') ?? '';
  if (assertionId === '' || !isStorableText(assertionId)) {
    throw new SsoFailure('invalid_response', 'saml.assertion_id');
  }
  const subjects = kids(assertion, A, 'Subject');
  const subject = subjects.length === 1 ? subjects[0] : undefined;
  if (!subject) throw new SsoFailure('invalid_response', 'saml.name_id');

  const bearers = kids(subject, A, 'SubjectConfirmation')
    .filter((c) => c.getAttribute('Method') === BEARER)
    .flatMap((c) => kids(c, A, 'SubjectConfirmationData'));
  if (bearers.length === 0) throw new SsoFailure('invalid_response', 'saml.subject_confirmation');
  const toAcs = bearers.filter((d) => d.getAttribute('Recipient') === expected.acsUrl);
  if (toAcs.length === 0) throw new SsoFailure('invalid_response', 'saml.recipient');
  const answering = toAcs.filter((d) => d.getAttribute('InResponseTo') === expected.inResponseTo);
  if (answering.length === 0) throw new SsoFailure('invalid_response', 'saml.in_response_to');
  const current = answering
    .map((d) => ({
      notBefore: timeOf(d.getAttribute('NotBefore')),
      notOnOrAfter: timeOf(d.getAttribute('NotOnOrAfter')),
    }))
    .filter(
      (t) =>
        t.notOnOrAfter !== null &&
        now - SKEW_MS < t.notOnOrAfter &&
        (t.notBefore === null || now + SKEW_MS >= t.notBefore),
    );
  if (current.length === 0) throw new SsoFailure('invalid_response', 'saml.subject_confirmation');

  if (kids(assertion, A, 'AuthnStatement').length === 0) {
    throw new SsoFailure('invalid_response', 'saml.authn_statement');
  }

  const nameIds = kids(subject, A, 'NameID');
  const nameIdElement = nameIds.length === 1 ? nameIds[0] : undefined;
  if (!nameIdElement) throw new SsoFailure('invalid_response', 'saml.name_id');
  if (expected.nameIdFormat !== UNSPECIFIED) {
    if (nameIdElement.getAttribute('Format') !== expected.nameIdFormat) {
      throw new SsoFailure('invalid_response', 'saml.name_id_format');
    }
  }
  const nameId = nameIdElement.textContent ?? '';
  if (
    nameId.length === 0 ||
    nameId.length > NAME_ID_MAX ||
    !isStorableText(nameId) ||
    nameId !== profileNameId
  ) {
    throw new SsoFailure('invalid_response', 'saml.name_id');
  }

  const conditions = kids(assertion, A, 'Conditions').map((c) =>
    timeOf(c.getAttribute('NotOnOrAfter')),
  );
  const ends = [...current.map((t) => t.notOnOrAfter), ...conditions].filter(
    (t): t is number => t !== null,
  );
  return { assertionId, nameId, validUntil: Math.max(...ends) };
}

/**
 * A single-valued attribute: a string, or an array of exactly one string; else absent. A value
 * PostgreSQL cannot store (U+0000, a lone surrogate) is refused, never stored or dropped quietly.
 */
function single(value: unknown): string | null {
  const raw = Array.isArray(value) && value.length === 1 ? (value[0] as unknown) : value;
  if (typeof raw !== 'string') return null;
  if (!isStorableText(raw)) throw new SsoFailure('invalid_response', 'saml.claims');
  return raw.length <= CLAIM_MAX && raw.trim().length > 0 ? raw : null;
}

/**
 * sso-scim.md §6.3, §8.3, §9.1: the sign-in's claims from node-saml's profile (the signed
 * assertion's attributes; own properties only). The subject is the NameID; the username the
 * configured attribute, or the NameID when none is configured; `emailVerified` is the connection's
 * word (SAML has no flag). Groups are a string or an array of strings (anything else is refused as
 * `saml.claims`, never dropped quietly); more
 * than MAX_GROUP_VALUES is `groups.too_many`. A value that cannot be stored is `saml.claims`.
 */
export function samlClaims(
  attributes: Record<string, unknown>,
  nameId: string,
  cfg: SamlConfig,
): SignInClaims {
  if (!isStorableText(nameId) || nameId.length === 0 || nameId.length > NAME_ID_MAX) {
    throw new SsoFailure('invalid_response', 'saml.name_id');
  }
  const read = (name: string | null): unknown =>
    name !== null && Object.hasOwn(attributes, name) ? attributes[name] : undefined;
  let groups: string[] = [];
  const rawGroups = read(cfg.claims.groups);
  if (Array.isArray(rawGroups)) {
    if (rawGroups.length > MAX_GROUP_VALUES) {
      throw new SsoFailure('invalid_response', 'groups.too_many');
    }
    if (!rawGroups.every((g): g is string => typeof g === 'string')) {
      throw new SsoFailure('invalid_response', 'saml.claims');
    }
    groups = rawGroups;
  } else if (typeof rawGroups === 'string') {
    groups = [rawGroups];
  } else if (rawGroups !== undefined) {
    throw new SsoFailure('invalid_response', 'saml.claims');
  }
  if (!groups.every(isStorableText)) throw new SsoFailure('invalid_response', 'saml.claims');
  const email = single(read(cfg.claims.email));
  return {
    subject: nameId,
    username: cfg.claims.username === null ? nameId : single(read(cfg.claims.username)),
    email,
    emailVerified: cfg.emailVerified && email !== null,
    displayName: single(read(cfg.claims.displayName)),
    groups,
    nameId,
  };
}

/**
 * The local names xml-encryption 3.1.0 selects by (`local-name()`, first match in document order,
 * whatever the namespace), each with the only namespace Qualor accepts for it.
 */
const ENCRYPTION_NAMES: Record<string, string> = {
  EncryptedData: XENC,
  EncryptedKey: XENC,
  EncryptionMethod: XENC,
  CipherData: XENC,
  CipherValue: XENC,
  KeyInfo: DS,
  DigestMethod: DS,
  RetrievalMethod: DS,
};
/** The OAEP digests xml-encryption reads (it treats any other as SHA-1). */
const OAEP_DIGESTS = new Set([`${DS}sha1`, `${DS}sha256`, `${DS}sha512`]);

/** The element children of `e`, as `namespace local` names in order. */
const shape = (e: XmlElement): string[] =>
  childElements(e).map((c) => `${c.namespaceURI ?? ''} ${c.localName}`);
const named = (ns: string, local: string): string => `${ns} ${local}`;

/**
 * The shape and algorithms of an `EncryptedAssertion` before anything decrypts it
 * (`saml.encryption`). xml-encryption picks every part by local name and takes the first match,
 * so every element with one of those names must be in its own namespace (a foreign
 * `x:EncryptionMethod` placed first would otherwise choose the algorithm), the counts are exact
 * (one EncryptedData, one EncryptedKey, two EncryptionMethod, two CipherData, two CipherValue, no
 * RetrievalMethod, at most one DigestMethod), and the tree is exactly
 * EncryptedAssertion/EncryptedData[EncryptionMethod, KeyInfo[EncryptedKey[EncryptionMethod,
 * KeyInfo?, CipherData]], CipherData], so the first CipherValue in document order is the key's.
 */
function encryptionAllowed(encrypted: XmlElement): boolean {
  const counts = new Map<string, number>();
  const stack: XmlElement[] = [encrypted];
  for (let e = stack.pop(); e; e = stack.pop()) {
    const expected = Object.hasOwn(ENCRYPTION_NAMES, e.localName)
      ? ENCRYPTION_NAMES[e.localName]
      : undefined;
    if (expected !== undefined) {
      if (e.namespaceURI !== expected) return false;
      counts.set(e.localName, (counts.get(e.localName) ?? 0) + 1);
    }
    stack.push(...childElements(e));
  }
  const n = (local: string) => counts.get(local) ?? 0;
  if (
    n('EncryptedData') !== 1 ||
    n('EncryptedKey') !== 1 ||
    n('EncryptionMethod') !== 2 ||
    n('CipherData') !== 2 ||
    n('CipherValue') !== 2 ||
    n('RetrievalMethod') !== 0 ||
    n('DigestMethod') > 1
  ) {
    return false;
  }
  const [data] = childElements(encrypted);
  if (!data || shape(encrypted).join('|') !== named(XENC, 'EncryptedData')) return false;
  const [dataMethod, outerInfo, dataCipher] = childElements(data);
  const dataShape = [
    named(XENC, 'EncryptionMethod'),
    named(DS, 'KeyInfo'),
    named(XENC, 'CipherData'),
  ].join('|');
  if (!dataMethod || !outerInfo || !dataCipher || shape(data).join('|') !== dataShape) {
    return false;
  }
  if (shape(outerInfo).join('|') !== named(XENC, 'EncryptedKey')) return false;
  const [key] = childElements(outerInfo);
  if (!key) return false;
  const keyShape = shape(key).join('|');
  const keyChildren = childElements(key);
  const keyMethod = keyChildren[0];
  const keyOk =
    keyShape === [named(XENC, 'EncryptionMethod'), named(XENC, 'CipherData')].join('|') ||
    keyShape ===
      [named(XENC, 'EncryptionMethod'), named(DS, 'KeyInfo'), named(XENC, 'CipherData')].join('|');
  if (!keyOk || !keyMethod) return false;
  for (const cipher of [dataCipher, keyChildren[keyChildren.length - 1]]) {
    if (!cipher || shape(cipher).join('|') !== named(XENC, 'CipherValue')) return false;
  }
  if (childElements(dataMethod).length !== 0) return false;
  const digests = childElements(keyMethod);
  if (
    digests.length > 1 ||
    (digests[0] !== undefined &&
      (named(digests[0].namespaceURI ?? '', digests[0].localName) !== named(DS, 'DigestMethod') ||
        !OAEP_DIGESTS.has(digests[0].getAttribute('Algorithm') ?? '')))
  ) {
    return false;
  }
  return (
    keyMethod.getAttribute('Algorithm') === KEY_TRANSPORT &&
    DATA_ENCRYPTION.has(dataMethod.getAttribute('Algorithm') ?? '')
  );
}

/** The class name of a thrown value, never its message. */
const className = (err: unknown): string =>
  err instanceof Error ? err.constructor.name : typeof err;

/**
 * sso-scim.md §6.2–§6.4: the Assertion Consumer Service. In order:
 *
 * 1. the form holds one `SAMLResponse` and one `RelayState` (`saml.form`);
 * 2. the connection can run (`unavailable`);
 * 3. the pre-check (SS2), before any other parser sees the document (`saml.precheck.<code>`; an
 *    IdP refusal without an assertion is `idp_error`); a response without `InResponseTo`
 *    (IdP-initiated) is refused;
 * 4. the pending request row is taken (SS3: this burns it, whatever follows): unknown, expired or
 *    another connection's is `flow_expired`; the RelayState must equal the flow's (constant time,
 *    `flow_mismatch`);
 * 5. the response's status, and an `EncryptedAssertion`'s algorithms and plaintext (pre-checked
 *    before node-saml decrypts the same ciphertext);
 * 6. node-saml validates (signatures against the pinned certificates, audience, times, the
 *    request id); its assertion (the signed bytes) is pre-checked again and read for what the
 *    library does not check; the response's `Destination` and `Issuer`;
 * 7. the claims from the profile (the signed assertion), the required claims (`required_claim`);
 * 8. in one transaction, the assertion id is remembered until it expires (`replayed`) and a
 *    finish row written; the answer is 303 to `/api/v0/ee/sso/finish?code=`.
 *
 * Every failure is a 303 to `/login?sso_error=<code>` with a fixed detail in the log; the
 * response itself, its attributes and library messages are never logged.
 */
export async function samlAcs(
  deps: FlowDeps,
  request: FastifyRequest,
  reply: FastifyReply,
  connectionId: string,
): Promise<FastifyReply> {
  try {
    const body = request.body as Record<string, unknown> | null | undefined;
    const samlResponse = body && typeof body === 'object' ? body.SAMLResponse : undefined;
    const relayState = body && typeof body === 'object' ? body.RelayState : undefined;
    if (typeof samlResponse !== 'string' || typeof relayState !== 'string') {
      throw new SsoFailure('invalid_response', 'saml.form');
    }

    const { connection, cfg, publicUrl } = await usable(
      deps,
      await loadConnection(deps.db, connectionId, deps.config.secretKey),
    );
    const urls = ssoUrls(publicUrl, connection.row.id);

    const decoded = decodeSamlResponse(samlResponse);
    if (!decoded.ok) throw new SsoFailure('invalid_response', `saml.precheck.${decoded.code}`);
    const pre = samlPreCheck(decoded.xml, {
      root: 'Response',
      hasSpKey: connection.spKey !== null,
    });
    if (!pre.ok) {
      if (pre.code === 'idp_status') throw new SsoFailure('idp_error', 'saml.status');
      throw new SsoFailure('invalid_response', `saml.precheck.${pre.code}`);
    }
    if (pre.inResponseTo === null) throw new SsoFailure('invalid_response', 'saml.in_response_to');

    const flow = await takeState<SamlFlowPayload & { issueInstant?: unknown }>(
      deps.db,
      stateKey('saml-request', pre.inResponseTo),
    );
    if (!flow || flow.connectionId !== connection.row.id) {
      throw new SsoFailure('flow_expired', 'saml.request_unknown');
    }
    const { issueInstant, ...flowPayload } = flow.payload;
    if (
      !RELAY_PATTERN.test(relayState) ||
      typeof flowPayload.relay !== 'string' ||
      !sameText(relayState, flowPayload.relay)
    ) {
      throw new SsoFailure('flow_mismatch', 'saml.relay');
    }
    if (typeof issueInstant !== 'string') {
      throw new SsoFailure('flow_expired', 'saml.request_unknown');
    }

    const root = pre.doc.documentElement;
    if (!root) throw new SsoFailure('invalid_response', 'saml.precheck.not_response');
    const status = topStatus(root);
    if (status !== SUCCESS) {
      throw new SsoFailure(status === null ? 'invalid_response' : 'idp_error', 'saml.status');
    }
    const encrypted = kids(root, A, 'EncryptedAssertion')[0];
    if (encrypted && connection.spKey) {
      if (!encryptionAllowed(encrypted))
        throw new SsoFailure('invalid_response', 'saml.encryption');
      let plaintext: string;
      try {
        plaintext = await decryptXml(
          (encrypted as XmlElement & { toString(): string }).toString(),
          connection.spKey,
        );
      } catch {
        throw new SsoFailure('invalid_response', 'saml.decrypt');
      }
      // One detail for a failed decryption and for a plaintext the pre-check refuses: no padding
      // or format oracle in the log or the audit chain (AES-CBC).
      if (!samlAssertionCheck(plaintext).ok) {
        throw new SsoFailure('invalid_response', 'saml.decrypt');
      }
    }

    const saml = samlFor(connection, publicUrl, takenRequestCache(pre.inResponseTo, issueInstant));
    let profile: Profile | null;
    try {
      // The bytes the pre-check read, re-encoded canonically: node-saml decodes the same document.
      ({ profile } = await saml.validatePostResponseAsync({
        SAMLResponse: Buffer.from(decoded.xml, 'utf8').toString('base64'),
      }));
    } catch (err) {
      if (err instanceof SamlStatusError) throw new SsoFailure('idp_error', 'saml.status');
      throw new SsoFailure('invalid_response', 'saml.validate');
    }
    if (!profile) throw new SsoFailure('invalid_response', 'saml.no_profile');
    const assertionXml = profile.getAssertionXml?.();
    if (typeof assertionXml !== 'string')
      throw new SsoFailure('invalid_response', 'saml.no_profile');
    const signed = samlAssertionCheck(assertionXml);
    if (!signed.ok) throw new SsoFailure('invalid_response', `saml.precheck.${signed.code}`);

    const now = Date.now();
    const facts = assertionFacts(
      signed.assertion,
      {
        issuer: cfg.idpEntityId,
        acsUrl: urls.acsUrl,
        inResponseTo: pre.inResponseTo,
        nameIdFormat: cfg.nameIdFormat,
      },
      profile.nameID,
      now,
    );
    // The response's own Destination and Issuer, when present (Destination required when signed).
    if (
      (pre.destination !== null && pre.destination !== urls.acsUrl) ||
      (pre.destination === null && cfg.wantResponseSigned)
    ) {
      throw new SsoFailure('invalid_response', 'saml.destination');
    }
    const responseIssuers = kids(root, A, 'Issuer');
    if (
      responseIssuers.length > 1 ||
      (responseIssuers[0] !== undefined && responseIssuers[0].textContent !== cfg.idpEntityId)
    ) {
      throw new SsoFailure('invalid_response', 'saml.issuer');
    }

    const rawAttributes = profile.attributes;
    const attributes: Record<string, unknown> =
      rawAttributes !== null && typeof rawAttributes === 'object' && !Array.isArray(rawAttributes)
        ? (rawAttributes as Record<string, unknown>)
        : {};
    const claims = samlClaims(attributes, facts.nameId, cfg);
    if (!requiredClaimsMet(cfg.requiredClaims, attributes)) {
      throw new SsoFailure('required_claim', 'saml.required_claim');
    }

    const code = randomBytes(32).toString('base64url');
    const finish: FinishPayload = { claims, flow: flowPayload };
    if (jsonbTextBytes(finish) > FINISH_MAX_BYTES) {
      throw new SsoFailure('invalid_response', 'saml.claims_too_large');
    }
    const replayTtl = Math.min(Math.max(facts.validUntil + SKEW_MS - now, 1_000), REPLAY_MAX_MS);
    await deps.db.transaction(async (tx) => {
      try {
        await putState(tx, {
          key: stateKey('saml-assertion', facts.assertionId, connection.row.id),
          kind: 'saml-assertion',
          connectionId: connection.row.id,
          payload: {},
          ttlMs: replayTtl,
        });
      } catch (err) {
        if (err instanceof StateExists) throw new SsoFailure('replayed', 'saml.replayed');
        throw err;
      }
      await putState(tx, {
        key: stateKey('finish', code),
        kind: 'finish',
        connectionId: connection.row.id,
        payload: finish,
        ttlMs: FINISH_TTL_MS,
      });
    });
    return await reply.code(303).header('location', `/api/v0/ee/sso/finish?code=${code}`).send();
  } catch (err) {
    return failed(deps, request, reply, connectionId, err);
  }
}

/** Ends a flow: an SsoFailure as it is, anything else `invalid_response` with its class logged. */
function failed(
  deps: FlowDeps,
  request: FastifyRequest,
  reply: FastifyReply,
  connectionId: string,
  err: unknown,
): Promise<FastifyReply> {
  if (err instanceof SsoFailure) {
    return failSsoFlow(deps, request, reply, { connectionId, protocol: 'saml', failure: err });
  }
  deps.log.error(
    { component: 'sso', errorClass: className(err) },
    'single sign-on failed unexpectedly',
  );
  return failSsoFlow(deps, request, reply, {
    connectionId,
    protocol: 'saml',
    failure: new SsoFailure('invalid_response', 'saml.other'),
  });
}

/**
 * sso-scim.md §7.4: `GET /api/v0/ee/sso/finish?code=`. The finish row is taken first (SS3: a code
 * works once), then the browser binding checked (SS4: `flow_mismatch`), then the connection must
 * still run, and the account, groups and session follow (Task 13's completeSignIn). An unknown code
 * names no connection, so its failure is logged and redirected but not recorded (the catalogue's
 * `sso.sign_in_failed` needs one).
 */
export async function finishSaml(
  deps: FlowDeps,
  request: FastifyRequest,
  reply: FastifyReply,
): Promise<FastifyReply> {
  let connectionId = '';
  try {
    const query = request.query as Record<string, unknown> | undefined;
    const code = query?.code;
    if (typeof code !== 'string' || !CODE_PATTERN.test(code)) {
      throw new SsoFailure('flow_expired', 'flow.expired');
    }
    const row = await takeState<FinishPayload>(deps.db, stateKey('finish', code));
    if (!row) throw new SsoFailure('flow_expired', 'flow.expired');
    connectionId = row.connectionId;
    const { claims, flow } = row.payload;
    if (!bindingMatches(request.cookies[SSO_COOKIE], flow.binding)) {
      throw new SsoFailure('flow_mismatch', 'flow.binding');
    }
    const { connection } = await usable(
      deps,
      await loadConnection(deps.db, row.connectionId, deps.config.secretKey),
    );
    return await completeSignIn(deps, request, reply, {
      connection,
      protocol: 'saml',
      claims,
      flow,
    });
  } catch (err) {
    return failed(deps, request, reply, connectionId, err);
  }
}

/**
 * sso-scim.md §4.3, §17.2: the SP metadata (entity id, ACS, NameID format), served as
 * `application/samlmetadata+xml`. With an SP key, its certificate is offered for signing and for
 * encryption; without one the metadata has no `KeyDescriptor`.
 */
export function spMetadata(connection: LoadedConnection, publicUrl: string): string {
  if (connection.parsed.protocol !== 'saml') throw new Error('not a SAML connection');
  const cert = connection.spKey ? connection.parsed.config.spCertificate : null;
  const forMetadata: LoadedConnection = cert ? connection : { ...connection, spKey: null };
  return samlFor(forMetadata, publicUrl, NO_CACHE).generateServiceProviderMetadata(cert, cert);
}

/** A base64 certificate body as PEM, 64 characters a line. */
function pemOf(body: string): string {
  const lines = body.match(/.{1,64}/g) ?? [];
  return `-----BEGIN CERTIFICATE-----\n${lines.join('\n')}\n-----END CERTIFICATE-----\n`;
}

const METADATA_PATH = 'saml.metadataUrl';
const metadataProblem = (message: string) => validationFailed([{ path: METADATA_PATH, message }]);

/**
 * sso-scim.md §4.3: reads the connection's metadata URL (only when an admin asks) through ssoFetch
 * (that URL only, at most 1 MiB), pre-checks it as an `EntityDescriptor` (comments allowed,
 * Ruling M-3), and returns the IdP's entity id, its HTTP-Redirect SingleSignOnService and its
 * signing certificates (`use="signing"` or unspecified, at most 3) for the admin to review.
 * Nothing is saved. Every problem is a 422 on `saml.metadataUrl`.
 */
export async function readSamlMetadata(
  connection: LoadedConnection,
  deps: Pick<FlowDeps, 'config' | 'resolve'>,
): Promise<{ idpEntityId: string; idpSsoUrl: string; certificates: SsoCertificateView[] }> {
  if (connection.parsed.protocol !== 'saml') throw metadataProblem('Not a SAML connection');
  const url = connection.parsed.config.metadataUrl;
  if (!url) throw metadataProblem('Set a metadata URL first');
  const fetchMetadata = createSsoFetch({
    internalHosts: deps.config.ssoInternalHosts,
    allowed: new Set([url]),
    maxResponseBytes: SAML_METADATA_MAX_BYTES,
    ...(deps.resolve ? { resolve: deps.resolve } : {}),
  });
  let text: string;
  try {
    const res = await fetchMetadata(url, {
      method: 'GET',
      headers: { accept: 'application/samlmetadata+xml, application/xml, text/xml' },
      body: undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(10_000),
    });
    if (res.status !== 200) throw new Error('status');
    text = new TextDecoder('utf-8', { fatal: true }).decode(await res.arrayBuffer());
  } catch {
    throw metadataProblem('The metadata URL could not be read');
  }
  const pre = samlPreCheck(text, { root: 'EntityDescriptor', hasSpKey: false });
  if (!pre.ok) throw metadataProblem(`The metadata was refused (${pre.code})`);
  const root = pre.doc.documentElement;
  const idpEntityId = root?.getAttribute('entityID') ?? '';
  if (!root || idpEntityId === '' || idpEntityId.length > 1_024) {
    throw metadataProblem('The metadata has no entityID');
  }
  const idp = kids(root, MD, 'IDPSSODescriptor')[0];
  if (!idp) throw metadataProblem('The metadata has no IDPSSODescriptor');
  const sso = kids(idp, MD, 'SingleSignOnService').find(
    (s) => s.getAttribute('Binding') === REDIRECT_BINDING,
  );
  const idpSsoUrl = sso?.getAttribute('Location') ?? '';
  if (idpSsoUrl === '') {
    throw metadataProblem('The metadata has no HTTP-Redirect SingleSignOnService');
  }
  const urlProblem = idpUrlProblem(idpSsoUrl, deps.config.ssoInternalHosts);
  if (urlProblem) throw metadataProblem(`The SingleSignOnService URL: ${urlProblem}`);

  const bodies: string[] = [];
  for (const key of kids(idp, MD, 'KeyDescriptor')) {
    const use = key.getAttribute('use');
    if (use !== null && use !== '' && use !== 'signing') continue;
    for (const info of kids(key, DS, 'KeyInfo')) {
      for (const data of kids(info, DS, 'X509Data')) {
        for (const cert of kids(data, DS, 'X509Certificate')) {
          const body = (cert.textContent ?? '').replace(/\s+/g, '');
          if (body !== '' && !bodies.includes(body)) bodies.push(body);
        }
      }
    }
  }
  if (bodies.length === 0) throw metadataProblem('The metadata lists no signing certificate');
  if (bodies.length > 3)
    throw metadataProblem('The metadata lists more than 3 signing certificates');
  return {
    idpEntityId,
    idpSsoUrl: normalIdpUrl(idpSsoUrl),
    certificates: bodies.map((body, i) =>
      certificateInfo(pemOf(body), `saml.idpCertificates.${String(i)}`),
    ),
  };
}
