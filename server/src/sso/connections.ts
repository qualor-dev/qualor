import { createPrivateKey, X509Certificate, type KeyObject } from 'node:crypto';
import { and, asc, count, eq, ne, sql } from 'drizzle-orm';
import { z } from 'zod';
import { SSO_CONNECTION_CHANGED_FIELDS } from '../audit/catalogue';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import type { Config } from '../config';
import { decryptSecret, encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Db, Executor } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgConstraint, pgErrorCode } from '../db/errors';
import { LOCKS } from '../db/locks';
import { first } from '../db/rows';
import {
  memberships,
  projectMemberships,
  identities,
  SSO_PROTOCOLS,
  ssoConnections,
  type EncryptedValue,
  type SsoConnectionRow,
  type SsoProtocol,
} from '../db/schema';
import type { Resolver } from '../http/outbound';
import { conflict, notFound, validationFailed, type FieldError } from '../http/problem';
import { noNul } from '../http/schemas';
import type { Edition } from '../license/edition';
import {
  MAX_SSO_CONNECTIONS,
  type NAME_ID_FORMATS,
  OIDC_CONFIG,
  parseStoredConfig,
  SAML_CONFIG,
  SECRET_AAD,
  SP_KEY_AAD,
  type ConnectionConfig,
  type OidcConfig,
  type SamlConfig,
} from './connection-config';
import { SsoFetchRefused } from './fetch';
import { assertSsoConnectionKept } from './sign-in-policy';
import {
  forgetOidcConfiguration,
  ISSUER_MISMATCH,
  oidcConfiguration,
  type OidcConfiguration,
} from './oidc-config';
import {
  idpUrlProblem,
  issuerProblem,
  normalIdpUrl,
  normalIssuer,
  ssoUrls,
  type SsoUrls,
} from './urls';

export interface ConnectionDeps {
  db: Db;
  config: Pick<Config, 'secretKey' | 'publicUrl' | 'ssoInternalHosts'>;
  audit: AuditRecorder;
  /** `sso` and `sso.multi` decide which connections are in effect (spec §4.4). */
  edition: Pick<Edition, 'isFeatureActive'>;
}

// ─── The API's shapes (sso-scim.md §4, §17.2) ───────────────────────────────

export interface SsoClaimsInput {
  username?: string | null;
  email?: string | null;
  displayName?: string | null;
  groups?: string | null;
}

export interface SsoOidcInput {
  issuer: string;
  clientId: string;
  /** Write-only: required on create, and again when `issuer` changes. */
  clientSecret?: string;
  clientAuth?: 'client_secret_basic' | 'client_secret_post';
  scopes?: string[];
  userinfo?: boolean;
}

export interface SsoSamlInput {
  idpEntityId: string;
  idpSsoUrl: string;
  idpCertificates: string[];
  metadataUrl?: string | null;
  nameIdFormat?: (typeof NAME_ID_FORMATS)[number];
  emailVerified?: boolean;
  wantResponseSigned?: boolean;
  /** Write-only: a PKCS#8 PEM RSA key of 2048–4096 bits; needs `spCertificate`. */
  spKey?: string;
  /** `null` on a PATCH removes the SP key pair. */
  spCertificate?: string | null;
}

/** The create body (spec §4): the common fields at the top, the protocol's under its name. */
export interface SsoConnectionInput {
  name: string;
  protocol: SsoProtocol;
  enabled?: boolean;
  jit?: boolean;
  linkByEmail?: boolean;
  groupSource?: 'none' | 'claims' | 'scim';
  requiredClaims?: { claim: string; value: string }[];
  claims?: SsoClaimsInput;
  oidc?: SsoOidcInput;
  saml?: SsoSamlInput;
}

/** A PATCH: any field but `protocol` (fixed at creation); the protocol's fields merge. */
export type SsoConnectionPatch = Partial<Omit<SsoConnectionInput, 'protocol' | 'oidc' | 'saml'>> & {
  oidc?: Partial<SsoOidcInput>;
  saml?: Partial<SsoSamlInput>;
};

export interface SsoCertificateView {
  pem: string;
  /** SHA-256 of the DER, `AB:CD:…` (what an IdP's page shows). */
  sha256: string;
  notAfter: string;
  /** Accepted, with a warning on the page (spec §4.3). */
  expired: boolean;
}

export interface SsoConnectionView {
  id: string;
  name: string;
  protocol: SsoProtocol;
  enabled: boolean;
  /**
   * Enabled, `sso` active, and either `sso.multi` active or the oldest enabled connection
   * (spec §4.4): only a connection in effect signs anyone in.
   */
  inEffect: boolean;
  /** False when the stored `config` no longer parses: the connection is unusable (spec §13). */
  configValid: boolean;
  jit: boolean;
  linkByEmail: boolean;
  groupSource: 'none' | 'claims' | 'scim';
  requiredClaims: { claim: string; value: string }[];
  claims: {
    username: string | null;
    email: string | null;
    displayName: string | null;
    groups: string | null;
  };
  oidc: {
    issuer: string;
    clientId: string;
    clientAuth: 'client_secret_basic' | 'client_secret_post';
    scopes: string[];
    userinfo: boolean;
    clientSecretSet: boolean;
  } | null;
  saml: {
    idpEntityId: string;
    idpSsoUrl: string;
    idpCertificates: SsoCertificateView[];
    metadataUrl: string | null;
    nameIdFormat: (typeof NAME_ID_FORMATS)[number];
    emailVerified: boolean;
    wantResponseSigned: boolean;
    spCertificate: string | null;
    spKeySet: boolean;
  } | null;
  /** What to copy into the IdP; null while QUALOR_PUBLIC_URL is unset. */
  urls: SsoUrls | null;
  createdAt: string;
  updatedAt: string;
}

/** What the flows need: the row, its parsed config and the decrypted secret or key. */
export interface LoadedConnection {
  row: SsoConnectionRow;
  parsed: ConnectionConfig;
  /**
   * OIDC: the client secret, or null when it cannot be decrypted (`QUALOR_SECRET_KEY` changed):
   * the flow then fails `unavailable` and logs UNDECRYPTABLE_CLIENT_SECRET.
   */
  clientSecret: string | null;
  /** SAML: the SP key; null without one, or (with `row.spKeyEnc` set) when it cannot be decrypted. */
  spKey: string | null;
}

export const UNDECRYPTABLE_CLIENT_SECRET =
  'the stored client secret cannot be decrypted (QUALOR_SECRET_KEY changed?)';
export const UNDECRYPTABLE_SP_KEY =
  'the stored SP key cannot be decrypted (QUALOR_SECRET_KEY changed?)';

// ─── Validation ─────────────────────────────────────────────────────────────

/** Collects the field errors of one request, then throws them together (422). */
class Problems {
  readonly errors: FieldError[] = [];
  add(path: string, message: string): void {
    this.errors.push({ path, message });
  }
  throwIfAny(): void {
    if (this.errors.length > 0) throw validationFailed(this.errors);
  }
}

const EC_CURVES: ReadonlySet<string> = new Set(['prime256v1', 'secp384r1', 'secp521r1']);

function certificateOrProblem(
  pemText: string,
): { cert: X509Certificate; info: SsoCertificateView } | { problem: string } {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pemText);
  } catch {
    return { problem: 'Not a PEM X.509 certificate' };
  }
  const key = cert.publicKey;
  const details = key.asymmetricKeyDetails ?? {};
  const ok =
    (key.asymmetricKeyType === 'rsa' && (details.modulusLength ?? 0) >= 2048) ||
    (key.asymmetricKeyType === 'ec' && EC_CURVES.has(details.namedCurve ?? ''));
  if (!ok) {
    return {
      problem: 'Use an RSA key of at least 2048 bits or an EC P-256, P-384 or P-521 key',
    };
  }
  const notAfter = cert.validToDate;
  return {
    cert,
    info: {
      pem: cert.toString(),
      sha256: cert.fingerprint256,
      notAfter: notAfter.toISOString(),
      expired: notAfter.getTime() < Date.now(),
    },
  };
}

/** spec §4.3: X.509, RSA ≥ 2048 or EC P-256/384/521; the view shows the SHA-256 fingerprint. */
export function certificateInfo(pemText: string, path: string): SsoCertificateView {
  const r = certificateOrProblem(pemText);
  if ('problem' in r) throw validationFailed([{ path, message: r.problem }]);
  return r.info;
}

const PKCS8_BEGIN = /^-----BEGIN PRIVATE KEY-----\r?\n/;

/** spec §4.3: an unencrypted PKCS#8 PEM RSA key of 2048–4096 bits. */
function spKeyOrProblem(pemText: string): KeyObject | string {
  if (!PKCS8_BEGIN.test(pemText.trimStart())) return 'Use an unencrypted PKCS#8 PEM RSA key';
  let key: KeyObject;
  try {
    key = createPrivateKey(pemText);
  } catch {
    return 'Use an unencrypted PKCS#8 PEM RSA key';
  }
  const bits = key.asymmetricKeyDetails?.modulusLength ?? 0;
  if (key.asymmetricKeyType !== 'rsa' || bits < 2048 || bits > 4096) {
    return 'Use an RSA key of 2048 to 4096 bits';
  }
  return key;
}

/** Type-checked later by the config schemas, whose errors map back onto the body. */
const loose = z.unknown().optional();
/**
 * spec §4.1: a name is the sign-in button's text, trimmed (uniqueness compares the trimmed,
 * lower-cased name); control, format (bidi) characters and lone surrogates are refused.
 */
const NAME = z
  .string()
  .trim()
  .min(1)
  .max(64)
  .regex(/^[^\p{Cc}\p{Cf}\p{Cs}]*$/u, 'No control, format or bidi characters');

const CLAIMS_BODY = z.strictObject({
  username: loose,
  email: loose,
  displayName: loose,
  groups: loose,
});
const COMMON_BODY = {
  enabled: z.boolean().optional(),
  jit: loose,
  linkByEmail: loose,
  groupSource: loose,
  requiredClaims: loose,
  claims: CLAIMS_BODY.optional(),
};
const OIDC_BODY = z.strictObject({
  issuer: loose,
  clientId: loose,
  clientSecret: noNul(z.string().min(1).max(1_024)).optional(),
  clientAuth: loose,
  scopes: loose,
  userinfo: loose,
});
const SAML_BODY = z.strictObject({
  idpEntityId: loose,
  idpSsoUrl: loose,
  idpCertificates: loose,
  metadataUrl: loose,
  nameIdFormat: loose,
  emailVerified: loose,
  wantResponseSigned: loose,
  spKey: noNul(z.string().min(1).max(16_384)).optional(),
  spCertificate: loose,
});
const CREATE_BODY = z.strictObject({
  name: NAME,
  protocol: z.enum(SSO_PROTOCOLS),
  ...COMMON_BODY,
  oidc: OIDC_BODY.optional(),
  saml: SAML_BODY.optional(),
});
const PATCH_BODY = z.strictObject({
  name: NAME.optional(),
  ...COMMON_BODY,
  oidc: OIDC_BODY.optional(),
  saml: SAML_BODY.optional(),
});

/** The config keys that sit at the top of the body; the others are under `oidc` or `saml`. */
const COMMON_KEYS: ReadonlySet<string> = new Set([
  'jit',
  'linkByEmail',
  'groupSource',
  'requiredClaims',
  'claims',
]);

function issuePath(issue: z.ZodError['issues'][number]): PropertyKey[] {
  if (issue.code === 'unrecognized_keys' && issue.keys[0] !== undefined) {
    return [...issue.path, issue.keys[0]];
  }
  return issue.path;
}

function zodErrors(error: z.ZodError, prefix: (first: PropertyKey | undefined) => string[]) {
  return error.issues.map((issue) => {
    const path = issuePath(issue);
    return {
      path: ['body', ...prefix(path[0]), ...path.map(String)].join('.'),
      message: issue.message,
    };
  });
}

function parseBody<T>(schema: z.ZodType<T>, input: unknown): T {
  const r = schema.safeParse(input);
  if (!r.success) throw validationFailed(zodErrors(r.error, () => []));
  return r.data;
}

/** Keeps the keys whose value is given (`null` is a value: it clears a field). */
function given(fields: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(Object.entries(fields).filter(([, v]) => v !== undefined));
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

type ProtocolBody = z.infer<typeof OIDC_BODY> | z.infer<typeof SAML_BODY>;

/** The protocol's config from a base (stored or empty) and the body's fields, not yet checked. */
function mergeRaw(
  protocol: SsoProtocol,
  base: Record<string, unknown>,
  common: z.infer<typeof PATCH_BODY>,
  own: ProtocolBody | undefined,
): Record<string, unknown> {
  // The write-only secret is not config: it is encrypted into its own column.
  const secretField = protocol === 'oidc' ? 'clientSecret' : 'spKey';
  const ownFields = Object.fromEntries(
    Object.entries(own ?? {}).filter(([k, v]) => k !== secretField && v !== undefined),
  );
  const baseClaims = isRecord(base['claims']) ? base['claims'] : {};
  const raw: Record<string, unknown> = {
    ...base,
    ...given({
      jit: common.jit,
      linkByEmail: common.linkByEmail,
      groupSource: common.groupSource,
      requiredClaims: common.requiredClaims,
    }),
    ...ownFields,
  };
  if (common.claims !== undefined) raw['claims'] = { ...baseClaims, ...given(common.claims) };
  // spec §4.2: an OIDC `groups` claim defaults to `groups` once group sync reads claims.
  const claims = isRecord(raw['claims']) ? raw['claims'] : {};
  if (
    protocol === 'oidc' &&
    common.groupSource === 'claims' &&
    common.claims?.groups === undefined &&
    (claims['groups'] ?? null) === null
  ) {
    raw['claims'] = { ...claims, groups: 'groups' };
  }
  return raw;
}

/** Parses the merged config, mapping each zod issue back onto the body's path. */
function parseConfig(protocol: SsoProtocol, raw: Record<string, unknown>): ConnectionConfig {
  const prefix = (key: PropertyKey | undefined) =>
    typeof key === 'string' && COMMON_KEYS.has(key) ? [] : [protocol];
  if (protocol === 'oidc') {
    const r = OIDC_CONFIG.safeParse(raw);
    if (!r.success) throw validationFailed(zodErrors(r.error, prefix));
    return { protocol, config: r.data };
  }
  const r = SAML_CONFIG.safeParse(raw);
  if (!r.success) throw validationFailed(zodErrors(r.error, prefix));
  return { protocol, config: r.data };
}

interface SecretChange {
  /** Undefined: keep the stored one. */
  secretEnc?: EncryptedValue | null;
  spKeyEnc?: EncryptedValue | null;
}

/**
 * The URL, certificate and key rules of spec §4.2–§4.3 on a parsed config (URLs and
 * certificates normalised in place), and the secrets to store. `storedSpKey` is the decrypted
 * key of an update (undefined: none stored; null: stored but not decryptable). An update that
 * gives neither `spKey` nor `spCertificate` keeps the stored pair unchecked, so a key that no
 * longer decrypts never blocks an unrelated change.
 */
function checkConfig(
  parsed: ConnectionConfig,
  own: ProtocolBody | undefined,
  deps: ConnectionDeps,
  storedSpKey: string | null | undefined,
  secretRequired: boolean,
): { parsed: ConnectionConfig; secrets: SecretChange } {
  const hosts = deps.config.ssoInternalHosts;
  const key = encryptionKey(deps.config.secretKey);
  const problems = new Problems();
  if (parsed.protocol === 'oidc') {
    const config: OidcConfig = { ...parsed.config };
    const problem = issuerProblem(config.issuer, hosts);
    if (problem) problems.add('body.oidc.issuer', problem);
    else config.issuer = normalIssuer(config.issuer);
    const clientSecret = own && 'clientSecret' in own ? own.clientSecret : undefined;
    if (clientSecret === undefined && secretRequired) {
      problems.add('body.oidc.clientSecret', 'Give the client secret');
    }
    problems.throwIfAny();
    return {
      parsed: { protocol: 'oidc', config },
      secrets:
        clientSecret === undefined
          ? {}
          : { secretEnc: encryptSecret(key, clientSecret, SECRET_AAD) },
    };
  }
  const config: SamlConfig = { ...parsed.config };
  for (const [field, value] of [
    ['idpSsoUrl', config.idpSsoUrl],
    ['metadataUrl', config.metadataUrl],
  ] as const) {
    if (value === null) continue;
    const problem = idpUrlProblem(value, hosts);
    if (problem) problems.add(`body.saml.${field}`, problem);
    else config[field] = normalIdpUrl(value);
  }
  config.idpCertificates = config.idpCertificates.map((pemText, i) => {
    const r = certificateOrProblem(pemText);
    if ('problem' in r) {
      problems.add(`body.saml.idpCertificates.${i}`, r.problem);
      return pemText;
    }
    return r.info.pem;
  });
  let spCert: X509Certificate | null = null;
  if (config.spCertificate !== null) {
    const r = certificateOrProblem(config.spCertificate);
    if ('problem' in r) problems.add('body.saml.spCertificate', r.problem);
    else {
      spCert = r.cert;
      config.spCertificate = r.info.pem;
    }
  }
  const newKey = own && 'spKey' in own ? own.spKey : undefined;
  const secrets: SecretChange = {};
  const signingTouched =
    storedSpKey === undefined ||
    newKey !== undefined ||
    (own !== undefined && 'spCertificate' in own && own.spCertificate !== undefined);
  if (!signingTouched) {
    problems.throwIfAny();
    return { parsed: { protocol: 'saml', config }, secrets };
  }
  let keyObject: KeyObject | null = null;
  if (newKey !== undefined) {
    const r = spKeyOrProblem(newKey);
    if (typeof r === 'string') problems.add('body.saml.spKey', r);
    else {
      keyObject = r;
      secrets.spKeyEnc = encryptSecret(
        key,
        String(r.export({ type: 'pkcs8', format: 'pem' })),
        SP_KEY_AAD,
      );
    }
  } else if (config.spCertificate === null) {
    // No certificate any more: the key goes with it.
    if (storedSpKey !== undefined) secrets.spKeyEnc = null;
  } else if (storedSpKey === null) {
    problems.add('body.saml.spKey', `${UNDECRYPTABLE_SP_KEY}; give it again`);
  } else if (storedSpKey !== undefined) {
    const r = spKeyOrProblem(storedSpKey);
    if (typeof r !== 'string') keyObject = r;
  }
  const hasKey = newKey !== undefined || (storedSpKey !== undefined && secrets.spKeyEnc !== null);
  if (hasKey && config.spCertificate === null) {
    problems.add('body.saml.spCertificate', 'Give the certificate of the SP key');
  } else if (!hasKey && config.spCertificate !== null) {
    problems.add('body.saml.spKey', 'Give the SP key of the certificate');
  } else if (keyObject && spCert && !spCert.checkPrivateKey(keyObject)) {
    problems.add('body.saml.spCertificate', 'The certificate does not belong to the SP key');
  }
  problems.throwIfAny();
  return { parsed: { protocol: 'saml', config }, secrets };
}

/** The host an audit event names (spec §15): the issuer's, or the SSO URL's. */
function hostOf(parsed: ConnectionConfig): string {
  return new URL(parsed.protocol === 'oidc' ? parsed.config.issuer : parsed.config.idpSsoUrl).host;
}

function requirePublicUrl(deps: ConnectionDeps): void {
  if (deps.config.publicUrl === null) {
    throw conflict('PUBLIC_URL_REQUIRED', 'Set QUALOR_PUBLIC_URL before enabling single sign-on');
  }
}

/** spec §4.4: the refusal of a second enabled connection without `sso.multi`. */
const SSO_MULTI_NOT_LICENSED_TEXT =
  'Your plan allows one enabled single sign-on connection. Disable the enabled one first, or keep this one disabled; several enabled connections need the Enterprise plan.';

/**
 * spec §4.4: without `sso.multi`, no connection may become enabled while another is
 * stored enabled. Runs in the transaction that holds `LOCKS.ssoConnections`, which every write of
 * `enabled` takes, so two concurrent enables see each other. Counts only enabled rows: a
 * disabled connection can always be created (up to the bound of 10) and prepared.
 */
async function assertOneEnabled(
  tx: Executor,
  edition: Pick<Edition, 'isFeatureActive'>,
  except: string | null,
): Promise<void> {
  if (edition.isFeatureActive('sso.multi')) return;
  const [{ n } = { n: 0 }] = await tx
    .select({ n: count() })
    .from(ssoConnections)
    .where(
      except === null
        ? eq(ssoConnections.enabled, true)
        : and(eq(ssoConnections.enabled, true), ne(ssoConnections.id, except)),
    );
  if (n > 0) throw conflict('SSO_MULTI_NOT_LICENSED', SSO_MULTI_NOT_LICENSED_TEXT);
}

function nameTaken(err: unknown): boolean {
  return (
    pgErrorCode(err) === PG_UNIQUE_VIOLATION && pgConstraint(err) === 'sso_connections_name_key'
  );
}

// ─── Views ──────────────────────────────────────────────────────────────────

function toView(
  row: SsoConnectionRow,
  publicUrl: string | null,
  inEffect: ReadonlySet<string>,
): SsoConnectionView {
  const parsed = parseStoredConfig(row.protocol, row.config);
  const base = {
    id: row.id,
    name: row.name,
    protocol: row.protocol,
    enabled: row.enabled,
    inEffect: inEffect.has(row.id),
    urls: publicUrl === null ? null : ssoUrls(publicUrl, row.id),
    createdAt: row.createdAt.toISOString(),
    updatedAt: row.updatedAt.toISOString(),
  };
  if (parsed === null) {
    return {
      ...base,
      configValid: false,
      jit: false,
      linkByEmail: false,
      groupSource: 'none',
      requiredClaims: [],
      claims: { username: null, email: null, displayName: null, groups: null },
      oidc: null,
      saml: null,
    };
  }
  const c = parsed.config;
  const common = {
    ...base,
    configValid: true,
    jit: c.jit,
    linkByEmail: c.linkByEmail,
    groupSource: c.groupSource,
    requiredClaims: c.requiredClaims,
    claims: c.claims,
  };
  if (parsed.protocol === 'oidc') {
    const o = parsed.config;
    return {
      ...common,
      oidc: {
        issuer: o.issuer,
        clientId: o.clientId,
        clientAuth: o.clientAuth,
        scopes: o.scopes,
        userinfo: o.userinfo,
        clientSecretSet: row.secretEnc !== null,
      },
      saml: null,
    };
  }
  const s = parsed.config;
  const certificates: SsoCertificateView[] = [];
  for (const pemText of s.idpCertificates) {
    const r = certificateOrProblem(pemText);
    if (!('problem' in r)) certificates.push(r.info);
  }
  return {
    ...common,
    oidc: null,
    saml: {
      idpEntityId: s.idpEntityId,
      idpSsoUrl: s.idpSsoUrl,
      idpCertificates: certificates,
      metadataUrl: s.metadataUrl,
      nameIdFormat: s.nameIdFormat,
      emailVerified: s.emailVerified,
      wantResponseSigned: s.wantResponseSigned,
      spCertificate: s.spCertificate,
      spKeySet: row.spKeyEnc !== null,
    },
  };
}

async function rowFor(db: Executor, id: string, lock = false): Promise<SsoConnectionRow | null> {
  const query = db.select().from(ssoConnections).where(eq(ssoConnections.id, id));
  const [row] = await (lock ? query.for('update') : query);
  return row ?? null;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ─── CRUD ───────────────────────────────────────────────────────────────────

export async function listConnections(deps: ConnectionDeps): Promise<SsoConnectionView[]> {
  const rows = await deps.db
    .select()
    .from(ssoConnections)
    .orderBy(asc(sql`lower(${ssoConnections.name})`), asc(ssoConnections.id));
  const inEffect = await inEffectConnectionIds(deps.db, deps.edition);
  return rows.map((row) => toView(row, deps.config.publicUrl, inEffect));
}

export async function getConnection(deps: ConnectionDeps, id: string): Promise<SsoConnectionView> {
  const row = UUID.test(id) ? await rowFor(deps.db, id) : null;
  if (!row) throw notFound('SSO connection');
  return toView(row, deps.config.publicUrl, await inEffectConnectionIds(deps.db, deps.edition));
}

export async function createConnection(
  deps: ConnectionDeps,
  actor: AuditActorContext,
  input: SsoConnectionInput,
): Promise<SsoConnectionView> {
  const body = parseBody(CREATE_BODY, input);
  const own = body.protocol === 'oidc' ? body.oidc : body.saml;
  const other = body.protocol === 'oidc' ? 'saml' : 'oidc';
  const problems = new Problems();
  if (body[other] !== undefined) {
    problems.add(`body.${other}`, `Only for a ${other.toUpperCase()} connection`);
  }
  if (own === undefined) {
    problems.add(
      `body.${body.protocol}`,
      `Required for a ${body.protocol.toUpperCase()} connection`,
    );
  }
  problems.throwIfAny();
  const raw = mergeRaw(body.protocol, {}, body, own);
  const { parsed, secrets } = checkConfig(
    parseConfig(body.protocol, raw),
    own,
    deps,
    undefined,
    body.protocol === 'oidc',
  );
  const enabled = body.enabled ?? false;
  if (enabled) requirePublicUrl(deps);
  const createdBy = actor.actor.type === 'system' ? null : actor.actor.userId;
  try {
    const row = await deps.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.ssoConnections})`);
      const [{ n } = { n: 0 }] = await tx.select({ n: count() }).from(ssoConnections);
      if (n >= MAX_SSO_CONNECTIONS) {
        throw conflict(
          'SSO_CONNECTION_LIMIT_REACHED',
          `At most ${MAX_SSO_CONNECTIONS} single sign-on connections`,
        );
      }
      if (enabled) await assertOneEnabled(tx, deps.edition, null);
      const inserted = first(
        await tx
          .insert(ssoConnections)
          .values({
            name: body.name,
            protocol: body.protocol,
            enabled,
            config: parsed.config,
            secretEnc: secrets.secretEnc ?? null,
            spKeyEnc: secrets.spKeyEnc ?? null,
            createdBy,
          })
          .returning(),
      );
      await deps.audit.record(tx, actor, [
        {
          action: 'sso.connection_created',
          target: { type: 'sso_connection', id: inserted.id, label: inserted.name },
          details: { name: inserted.name, protocol: inserted.protocol, host: hostOf(parsed) },
        },
      ]);
      return { row: inserted, inEffect: await inEffectConnectionIds(tx, deps.edition) };
    });
    return toView(row.row, deps.config.publicUrl, row.inEffect);
  } catch (err) {
    if (nameTaken(err)) {
      throw conflict('SSO_CONNECTION_NAME_TAKEN', 'A connection with that name exists');
    }
    throw err;
  }
}

type ChangedField = (typeof SSO_CONNECTION_CHANGED_FIELDS)[number];

/** The config fields whose value differs, by name (spec §15). */
function changedFields(before: unknown, after: Record<string, unknown>): Set<ChangedField> {
  const old = isRecord(before) ? before : {};
  const changed = new Set<ChangedField>();
  for (const field of SSO_CONNECTION_CHANGED_FIELDS) {
    if (!(field in after)) continue;
    if (JSON.stringify(old[field]) !== JSON.stringify(after[field])) changed.add(field);
  }
  return changed;
}

export async function updateConnection(
  deps: ConnectionDeps,
  actor: AuditActorContext,
  id: string,
  patch: SsoConnectionPatch,
): Promise<SsoConnectionView> {
  const body = parseBody(PATCH_BODY, patch);
  if (!UUID.test(id)) throw notFound('SSO connection');
  if (body.enabled === true) requirePublicUrl(deps);
  try {
    const row = await deps.db.transaction(async (tx) => {
      // Disabling may need the last-connection check: the instance-admin lock first.
      if (body.enabled === false) await assertSsoConnectionKept(tx, id);
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.ssoConnections})`);
      const current = await rowFor(tx, id, true);
      if (!current) throw notFound('SSO connection');
      // spec §4.4: without sso.multi, enabling needs every other connection disabled.
      if (body.enabled === true && !current.enabled) await assertOneEnabled(tx, deps.edition, id);
      const protocol = current.protocol;
      const other = protocol === 'oidc' ? 'saml' : 'oidc';
      if (body[other] !== undefined) {
        throw validationFailed([
          { path: `body.${other}`, message: `Only for a ${other.toUpperCase()} connection` },
        ]);
      }
      const own = protocol === 'oidc' ? body.oidc : body.saml;
      const stored = parseStoredConfig(protocol, current.config);
      // A row that no longer parses can be repaired: the patch applies over what is stored.
      const base: Record<string, unknown> = stored
        ? { ...stored.config }
        : isRecord(current.config)
          ? { ...current.config }
          : {};
      const merged = parseConfig(protocol, mergeRaw(protocol, base, body, own));
      const key = encryptionKey(deps.config.secretKey);
      const storedSpKey =
        current.spKeyEnc === null ? undefined : decryptSecret(key, current.spKeyEnc, SP_KEY_AAD);
      const issuerChanged =
        protocol === 'oidc' &&
        merged.protocol === 'oidc' &&
        issuerProblem(merged.config.issuer, deps.config.ssoInternalHosts) === null &&
        normalIssuer(merged.config.issuer) !== base['issuer'];
      const { parsed, secrets } = checkConfig(
        merged,
        own,
        deps,
        storedSpKey,
        issuerChanged || current.secretEnc === null,
      );
      const changed = changedFields(base, parsed.config);
      if (body.name !== undefined && body.name !== current.name) changed.add('name');
      if (body.enabled !== undefined && body.enabled !== current.enabled) changed.add('enabled');
      if (secrets.secretEnc) changed.add('clientSecret');
      if (secrets.spKeyEnc !== undefined) changed.add('spKey');
      const updated = first(
        await tx
          .update(ssoConnections)
          .set({
            ...given({ name: body.name, enabled: body.enabled }),
            config: parsed.config,
            ...given({ secretEnc: secrets.secretEnc, spKeyEnc: secrets.spKeyEnc }),
          })
          .where(eq(ssoConnections.id, id))
          .returning(),
      );
      await deps.audit.record(tx, actor, [
        {
          action: 'sso.connection_updated',
          target: { type: 'sso_connection', id, label: updated.name },
          details: { changed: SSO_CONNECTION_CHANGED_FIELDS.filter((f) => changed.has(f)) },
        },
      ]);
      return { row: updated, inEffect: await inEffectConnectionIds(tx, deps.edition) };
    });
    return toView(row.row, deps.config.publicUrl, row.inEffect);
  } catch (err) {
    if (nameTaken(err)) {
      throw conflict('SSO_CONNECTION_NAME_TAKEN', 'A connection with that name exists');
    }
    throw err;
  }
}

/**
 * spec §15: deleting a connection removes its identities, SCIM tokens, groups and mappings
 * (cascade) and leaves the memberships it managed as manual ones (`SET NULL`). Access-removing
 * (rbac-audit.md §10.2.1): a malformed anchor skips the event, not the deletion.
 */
export async function deleteConnection(
  deps: ConnectionDeps,
  actor: AuditActorContext,
  id: string,
): Promise<void> {
  if (!UUID.test(id)) throw notFound('SSO connection');
  await deps.db.transaction(async (tx) => {
    // the instance-admin lock first, then the connections' lock.
    await assertSsoConnectionKept(tx, id);
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.ssoConnections})`);
    const current = await rowFor(tx, id, true);
    if (!current) throw notFound('SSO connection');
    const [linked = { n: 0 }] = await tx
      .select({ n: count() })
      .from(identities)
      .where(eq(identities.connectionId, id));
    const [orgManaged = { n: 0 }] = await tx
      .select({ n: count() })
      .from(memberships)
      .where(eq(memberships.managedByConnectionId, id));
    const [projectManaged = { n: 0 }] = await tx
      .select({ n: count() })
      .from(projectMemberships)
      .where(eq(projectMemberships.managedByConnectionId, id));
    await tx.delete(ssoConnections).where(eq(ssoConnections.id, id));
    await deps.audit.recordOrSkipWhenAnchorMalformed(tx, actor, [
      {
        action: 'sso.connection_deleted',
        target: { type: 'sso_connection', id, label: current.name },
        details: {
          name: current.name,
          protocol: current.protocol,
          identities: linked.n,
          managedMemberships: orgManaged.n + projectManaged.n,
        },
      },
    ]);
  });
}

// ─── For the flows and the sign-in page ─────────────────────────────────────

/**
 * The connection with its config and decrypted secret, for the flows; null when unknown or when
 * the stored config no longer parses (spec §13: unusable, never a 500).
 */
export async function loadConnection(
  db: Executor,
  id: string,
  secretKey: string,
): Promise<LoadedConnection | null> {
  if (!UUID.test(id)) return null;
  const row = await rowFor(db, id);
  if (!row) return null;
  const parsed = parseStoredConfig(row.protocol, row.config);
  if (!parsed) return null;
  const key = encryptionKey(secretKey);
  return {
    row,
    parsed,
    clientSecret: row.secretEnc === null ? null : decryptSecret(key, row.secretEnc, SECRET_AAD),
    spKey: row.spKeyEnc === null ? null : decryptSecret(key, row.spKeyEnc, SP_KEY_AAD),
  };
}

// ─── The admin's Test (spec §4.2, §17.2) ────────────────────────────────────

/** `POST /ee/sso/connections/{id}/test`: what the admin sees; every message is a fixed text. */
export interface SsoTestResult {
  ok: boolean;
  problem: { code: SsoTestProblemCode; message: string } | null;
  /** OIDC, once discovery answered: the hosts Qualor will contact (spec §14); else null. */
  endpoints: {
    authorization: string | null;
    token: string | null;
    jwks: string | null;
    userinfo: string | null;
  } | null;
  /** SAML: the pinned IdP certificates, their fingerprints and expiry; else null. */
  certificates: SsoCertificateView[] | null;
}

/** A fixed text for each refusal of ssoFetch (never a library's or the IdP's message). */
const FETCH_REFUSALS: Record<SsoFetchRefused['reason'], string> = {
  not_allowed: 'The URL is not one the discovery document named',
  method: 'The request method is not allowed',
  status: 'The identity provider answered with an error status',
  invalid_url: 'The URL is not valid',
  not_public: 'The host is not public; list it in QUALOR_SSO_INTERNAL_HOSTS',
  refused_address: 'The host resolves to an address that is never allowed',
  unresolved: 'The host name could not be resolved',
  timeout: 'The identity provider did not answer in time',
  connect_timeout: 'The identity provider could not be reached in time',
  request: 'The request to the identity provider failed',
  connection: 'The connection to the identity provider failed',
  too_large: 'The answer of the identity provider is too large',
};

/** A refusal of ssoFetch as the **Test** reports it: `fetch.<reason>`. */
type FetchProblemCode = `fetch.${SsoFetchRefused['reason']}`;

/**
 * Every `problem.code` the admin's **Test** answers with (spec §4.2, §4.3). The UI keeps a text for
 * each (ui/src/app/settings/sso-settings-text.ts; tools/sso-codes.test.ts keeps the two equal).
 */
export const SSO_TEST_PROBLEM_CODES = [
  'issuer_mismatch',
  'client_secret',
  'issuer_url',
  'discovery',
  'jwks',
  'sso_url',
  'certificates_expired',
  'sp_key',
  'config_invalid',
  ...(Object.keys(FETCH_REFUSALS) as SsoFetchRefused['reason'][]).map(
    (reason): FetchProblemCode => `fetch.${reason}`,
  ),
] as const;

export type SsoTestProblemCode = (typeof SSO_TEST_PROBLEM_CODES)[number];

type TestProblem = { code: SsoTestProblemCode; message: string };

const TEST_TIMEOUT_MS = 10_000;

/** What a thrown discovery or JWKS error is, as a fixed code and text; `fallback` otherwise. */
function testProblem(err: unknown, fallback: TestProblem): TestProblem {
  let current: unknown = err;
  for (let depth = 0; depth < 5 && current !== null && typeof current === 'object'; depth++) {
    if (current instanceof SsoFetchRefused) {
      return { code: `fetch.${current.reason}`, message: FETCH_REFUSALS[current.reason] };
    }
    const fields = current as { message?: unknown; code?: unknown; cause?: unknown };
    if (
      fields.message === ISSUER_MISMATCH ||
      fields.code === 'OAUTH_JSON_ATTRIBUTE_COMPARISON_FAILED'
    ) {
      return {
        code: 'issuer_mismatch',
        message: 'The discovery document names another issuer',
      };
    }
    current = fields.cause;
  }
  return fallback;
}

const failedTest = (
  problem: TestProblem,
  certificates: SsoCertificateView[] | null = null,
): SsoTestResult => ({ ok: false, problem, endpoints: null, certificates });

async function testOidc(
  connection: LoadedConnection,
  deps: ConnectionDeps & { resolve?: Resolver },
): Promise<SsoTestResult> {
  if (connection.clientSecret === null) {
    return failedTest({
      code: 'client_secret',
      message: 'The stored client secret cannot be decrypted; give it again',
    });
  }
  if (connection.parsed.protocol !== 'oidc') throw new Error('not an OIDC connection');
  // The rules of saving, again: QUALOR_SSO_INTERNAL_HOSTS may have changed since.
  const issuer = issuerProblem(connection.parsed.config.issuer, deps.config.ssoInternalHosts);
  if (issuer) return failedTest({ code: 'issuer_url', message: `The issuer URL: ${issuer}` });
  // The admin asked now: never an answer from the cache.
  forgetOidcConfiguration(connection.row.id);
  let discovered: OidcConfiguration;
  try {
    discovered = await oidcConfiguration(connection, {
      internalHosts: deps.config.ssoInternalHosts,
      ...(deps.resolve ? { resolve: deps.resolve } : {}),
    });
  } catch (err) {
    return failedTest(
      testProblem(err, {
        code: 'discovery',
        message: "The issuer's discovery document could not be read",
      }),
    );
  }
  const meta = discovered.config.serverMetadata();
  const text = (value: unknown): string | null => (typeof value === 'string' ? value : null);
  const endpoints = {
    authorization: text(meta.authorization_endpoint),
    token: text(meta.token_endpoint),
    jwks: text(meta.jwks_uri),
    userinfo: text(meta.userinfo_endpoint),
  };
  const jwksFailed: TestProblem = { code: 'jwks', message: 'The JWKS could not be read' };
  if (endpoints.jwks === null) return { ...failedTest(jwksFailed), endpoints };
  try {
    const res = await discovered.fetch(endpoints.jwks, {
      method: 'GET',
      headers: { accept: 'application/json' },
      body: undefined,
      redirect: 'manual',
      signal: AbortSignal.timeout(TEST_TIMEOUT_MS),
    });
    if (res.status !== 200) throw new SsoFetchRefused('status');
    const body: unknown = JSON.parse(await res.text());
    if (!isRecord(body) || !Array.isArray(body['keys'])) {
      return { ...failedTest(jwksFailed), endpoints };
    }
  } catch (err) {
    return { ...failedTest(testProblem(err, jwksFailed)), endpoints };
  }
  return { ok: true, problem: null, endpoints, certificates: null };
}

function testSaml(connection: LoadedConnection, deps: ConnectionDeps): SsoTestResult {
  if (connection.parsed.protocol !== 'saml') throw new Error('not a SAML connection');
  const cfg = connection.parsed.config;
  const certificates: SsoCertificateView[] = [];
  for (const pemText of cfg.idpCertificates) {
    const r = certificateOrProblem(pemText);
    if (!('problem' in r)) certificates.push(r.info);
  }
  const urlProblem = idpUrlProblem(cfg.idpSsoUrl, deps.config.ssoInternalHosts);
  if (urlProblem) {
    return failedTest({ code: 'sso_url', message: `The SSO URL: ${urlProblem}` }, certificates);
  }
  if (certificates.length === 0 || certificates.every((c) => c.expired)) {
    return failedTest(
      { code: 'certificates_expired', message: 'No IdP certificate is valid now' },
      certificates,
    );
  }
  if (connection.row.spKeyEnc !== null && connection.spKey === null) {
    return failedTest(
      { code: 'sp_key', message: 'The stored SP key cannot be decrypted; give it again' },
      certificates,
    );
  }
  return { ok: true, problem: null, endpoints: null, certificates };
}

/**
 * spec §4.2, §17.2: the admin's **Test**. OIDC: discovery runs now (the cache is dropped first)
 * and the JWKS is fetched once, both through ssoFetch; the answer names the endpoints Qualor will
 * contact. SAML: nothing is fetched; the pinned certificates' fingerprints and expiry, and whether
 * the SSO URL is allowed. 404 for an unknown connection; a stored config that no longer parses is
 * a failed test, not an error. Nothing is written or recorded.
 */
export async function testConnection(
  deps: ConnectionDeps & { resolve?: Resolver },
  id: string,
): Promise<SsoTestResult> {
  const row = UUID.test(id) ? await rowFor(deps.db, id) : null;
  if (!row) throw notFound('SSO connection');
  const connection = await loadConnection(deps.db, id, deps.config.secretKey);
  if (!connection) {
    return failedTest({
      code: 'config_invalid',
      message: 'The stored configuration is not valid; save the connection again',
    });
  }
  return connection.parsed.protocol === 'oidc'
    ? testOidc(connection, deps)
    : testSaml(connection, deps);
}

/**
 * spec §4.4: the connections in effect. None without `sso`; every enabled one with `sso.multi`;
 * else the oldest enabled one, the first in `(created_at, id)` order. Computed on every call
 * (nothing is cached or stored), so a change of licence takes effect on the next request.
 */
export async function inEffectConnectionIds(
  db: Executor,
  edition: Pick<Edition, 'isFeatureActive'>,
): Promise<Set<string>> {
  if (!edition.isFeatureActive('sso')) return new Set();
  const query = db
    .select({ id: ssoConnections.id })
    .from(ssoConnections)
    .where(eq(ssoConnections.enabled, true))
    .orderBy(asc(ssoConnections.createdAt), asc(ssoConnections.id));
  const rows = edition.isFeatureActive('sso.multi') ? await query : await query.limit(1);
  return new Set(rows.map((r) => r.id));
}

/** Whether one connection is in effect now (spec §4.4): what the flows check. */
export async function isConnectionInEffect(
  db: Executor,
  edition: Pick<Edition, 'isFeatureActive'>,
  id: string,
): Promise<boolean> {
  return (await inEffectConnectionIds(db, edition)).has(id);
}

/** The sign-in page's buttons (`GET /auth/methods`, spec §16.1): connections in effect by name. */
export async function connectionsInEffect(
  db: Executor,
  edition: Pick<Edition, 'isFeatureActive'>,
): Promise<{ id: string; name: string; protocol: SsoProtocol }[]> {
  const inEffect = await inEffectConnectionIds(db, edition);
  if (inEffect.size === 0) return [];
  const rows = await db
    .select({ id: ssoConnections.id, name: ssoConnections.name, protocol: ssoConnections.protocol })
    .from(ssoConnections)
    .where(eq(ssoConnections.enabled, true))
    .orderBy(asc(sql`lower(${ssoConnections.name})`), asc(ssoConnections.id));
  return rows.filter((r) => inEffect.has(r.id));
}
