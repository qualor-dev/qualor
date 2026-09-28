import { execFileSync } from 'node:child_process';
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomUUID,
  type KeyObject,
} from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import path from 'node:path';
import { prerequisiteOf } from '../../server/src/license/edition';
import {
  LICENSE_PUBLIC_KEYS,
  PRODUCTION_KEYS,
  REVOKED_LICENSE_IDS,
} from '../../server/src/license/public-keys';
import { licenseState, type LicenseState } from '../../server/src/license/state';
import {
  KID_PATTERN,
  RETIRED_FEATURES,
  signLicenseKey,
  type LicensePayload,
} from '../../server/src/license/token';
import {
  productionVerifyOptions,
  verifyLicenseKey,
  type VerifyOptions,
} from '../../server/src/license/verify';

/**
 * enterprise.md §15: the maintainer's offline licence tool (dev only, never shipped). It reuses the
 * server's own token, verification and state code, so a key it signs or inspects is judged exactly
 * as the server judges it. It never prints a private key and never writes one into a repository.
 */

export const PASSPHRASE_VARIABLE = 'QUALOR_LICENSE_SIGNING_PASSPHRASE';
const MIN_PASSPHRASE = 16;

function requirePassphrase(passphrase: string | undefined): string {
  if (passphrase === undefined || passphrase === '') {
    throw new Error(`set ${PASSPHRASE_VARIABLE} to the private key's passphrase`);
  }
  if (passphrase.length < MIN_PASSPHRASE) {
    throw new Error(`the passphrase must have at least ${MIN_PASSPHRASE} characters`);
  }
  return passphrase;
}

/**
 * enterprise.md §1.4, §3.1, §15: `pnpm license:sign --features` refuses a retired name, before any
 * key file is read (`cli.ts`, beside the `--organizations` refusal). Throws the usage error the
 * CLI prints on standard error; signs nothing.
 */
export function refuseRetiredFeatures(features: readonly string[]): void {
  const retired = features.find((f) => RETIRED_FEATURES.includes(f));
  if (retired !== undefined) {
    throw new Error(
      `${retired} is retired: roles and project access are in the community edition since Qualor 5B; leave it out`,
    );
  }
}

/**
 * enterprise.md §7.1, §15: `pnpm license:sign --features` refuses a feature listed without its
 * prerequisite (`audit-log.stream` without `audit-log`, `sso.multi` without `sso`), before any
 * key file is read (`cli.ts`, beside `refuseRetiredFeatures`). Throws the usage error the CLI
 * prints on standard error; signs nothing.
 */
export function refuseMissingPrerequisites(features: readonly string[]): void {
  for (const f of features) {
    const needs = prerequisiteOf(f);
    if (needs !== undefined && !features.includes(needs)) {
      throw new Error(`${f} needs ${needs} in --features (enterprise.md §7.1)`);
    }
  }
}

/** The nearest existing directory at or above `dir`, with symbolic links resolved. */
function nearestExisting(dir: string): string {
  let probe = path.resolve(dir);
  while (!existsSync(probe)) {
    const parent = path.dirname(probe);
    if (parent === probe) break;
    probe = parent;
  }
  try {
    return realpathSync.native(probe);
  } catch {
    return probe;
  }
}

/**
 * True when `dir` (or its nearest existing parent) is inside any git repository, its `.git`
 * directory included. Two checks, either suffices: a `.git` entry in the directory or a parent
 * (works without git), and `git rev-parse --git-dir` (sees what git sees), run without the
 * GIT_DIR and GIT_WORK_TREE of the caller's environment.
 */
export function insideGitWorkTree(dir: string): boolean {
  const probe = nearestExisting(dir);
  for (let p = probe; ; p = path.dirname(p)) {
    if (path.basename(p) === '.git' || existsSync(path.join(p, '.git'))) return true;
    if (path.dirname(p) === p) break;
  }
  try {
    execFileSync('git', ['-C', probe, 'rev-parse', '--git-dir'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'ignore'],
      env: gitEnvironment(),
    });
    return true;
  } catch {
    return false;
  }
}

/**
 * The environment of the tool's git child: without the caller's GIT_DIR and GIT_WORK_TREE, and
 * without the signing passphrase (Task 10 review M-7), which git and its hooks never need.
 */
export function gitEnvironment(env: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const dropped = new Set(['GIT_DIR', 'GIT_WORK_TREE', PASSPHRASE_VARIABLE]);
  return Object.fromEntries(Object.entries(env).filter(([name]) => !dropped.has(name)));
}

/**
 * Windows ignores the file mode: the private key file's ACL is cut down to the current user
 * (icacls, inheritance removed). Returns a warning when that fails, for the caller to print
 * (enterprise.md §15). Elsewhere mode 0600 does it, and this returns null.
 */
export function restrictToOwner(
  file: string,
  platform: NodeJS.Platform = process.platform,
): string | null {
  if (platform !== 'win32') return null;
  try {
    execFileSync('icacls', [file, '/inheritance:r', '/grant:r', `${userInfo().username}:F`], {
      stdio: 'ignore',
      env: gitEnvironment(),
    });
    return null;
  } catch {
    return `could not restrict ${file} to your user; set its permissions by hand (only you may read it)`;
  }
}

function publicX(key: KeyObject): string {
  const { x } = (key.type === 'public' ? key : createPublicKey(key)).export({ format: 'jwk' });
  if (typeof x !== 'string') throw new Error('not an Ed25519 key');
  return x;
}

/** enterprise.md §15: an Ed25519 key pair; the private half encrypted, never in a repository. */
export function keygen(options: { kid: string; outDir: string; passphrase: string | undefined }): {
  privateKeyPath: string;
  x: string;
  line: string;
  /** Things the maintainer must fix by hand (a Windows ACL that could not be restricted). */
  warnings: string[];
} {
  if (!KID_PATTERN.test(options.kid)) {
    throw new Error(`invalid kid "${options.kid}" (${String(KID_PATTERN)})`);
  }
  const passphrase = requirePassphrase(options.passphrase);
  const outDir = path.resolve(options.outDir);
  if (insideGitWorkTree(outDir)) {
    throw new Error(
      `${outDir} is inside a git repository; keep the private key outside any repository`,
    );
  }
  mkdirSync(outDir, { recursive: true });
  const privateKeyPath = path.join(outDir, `${options.kid}.private.pem`);
  if (existsSync(privateKeyPath)) throw new Error(`${privateKeyPath} exists; choose another kid`);
  const { publicKey, privateKey } = generateKeyPairSync('ed25519', {
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase },
  });
  writeFileSync(privateKeyPath, privateKey, { mode: 0o600, flag: 'wx' });
  const warning = restrictToOwner(privateKeyPath);
  const x = publicX(createPublicKey(publicKey));
  return {
    privateKeyPath,
    x,
    line: `  '${options.kid}': '${x}',`,
    warnings: warning ? [warning] : [],
  };
}

const ENCRYPTED_HEADER = '-----BEGIN ENCRYPTED PRIVATE KEY-----';
const ENCRYPTED_FOOTER = '-----END ENCRYPTED PRIVATE KEY-----';

/**
 * The file must hold exactly one PEM block, the encrypted one. Checking only that the header text
 * appears is not enough: Node reads the first valid block, so an unencrypted key followed by a
 * stray encrypted header would be used with any passphrase.
 */
function isSingleEncryptedPemBlock(pem: string): boolean {
  const trimmed = pem.trim();
  if (!trimmed.startsWith(ENCRYPTED_HEADER) || !trimmed.endsWith(ENCRYPTED_FOOTER)) return false;
  return (trimmed.match(/-----BEGIN /g) ?? []).length === 1;
}

const DATE_ONLY = /^\d{4}-\d{2}-\d{2}$/;
/** As documented (enterprise.md §15, the usage text): whole seconds, no milliseconds. */
const FULL_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/;
/** Test key ids; any other kid must be one of the compiled production keys (Task 10 review I-2). */
const TEST_KID = /^test-/;

/**
 * `YYYY-MM-DD` is 00:00 UTC; a full UTC timestamp is kept as written. Nothing is rolled over:
 * the server's schema then refuses a date such as 2027-02-30.
 */
function timestamp(value: string): string {
  if (DATE_ONLY.test(value)) return `${value}T00:00:00Z`;
  if (FULL_UTC.test(value)) return value;
  throw new Error(`not a date: "${value}" (use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SSZ)`);
}

export function signKey(options: {
  keyFile: string;
  passphrase: string | undefined;
  kid: string;
  customer: string;
  expires: string;
  features: string[];
  issued?: string;
  id?: string;
  /** The compiled public keys; a kid in it must match the private key. */
  knownKeys?: Readonly<Record<string, string>>;
  /** A kid that does not start with `test-` must be one of these (default PRODUCTION_KEYS). */
  productionKeys?: Readonly<Record<string, string>>;
  /** Told about a key that is already expired or not valid yet (the CLI prints it). */
  onWarning?: (message: string) => void;
  /** The clock of those warnings (tests); the key itself is checked as of its issue date. */
  now?: Date;
}): string {
  const productionKeys = options.productionKeys ?? PRODUCTION_KEYS;
  // Task 10 review I-2: a real licence is signed only with a key a release accepts.
  if (!TEST_KID.test(options.kid) && !Object.hasOwn(productionKeys, options.kid)) {
    throw new Error(
      `kid "${options.kid}" is not in PRODUCTION_KEYS (server/src/license/public-keys.ts): ` +
        'release its public key first, or use a test- kid for a test key',
    );
  }
  const pem = readFileSync(options.keyFile, 'utf8');
  if (!isSingleEncryptedPemBlock(pem)) {
    throw new Error(`${options.keyFile} is not an encrypted private key (pnpm license:keygen)`);
  }
  let privateKey: KeyObject;
  try {
    privateKey = createPrivateKey({ key: pem, passphrase: requirePassphrase(options.passphrase) });
  } catch (err) {
    if (err instanceof Error && err.message.includes(PASSPHRASE_VARIABLE)) throw err;
    throw new Error(`cannot decrypt ${options.keyFile}: wrong passphrase or not a key`, {
      cause: err,
    });
  }
  const x = publicX(privateKey);
  const known =
    options.knownKeys ?? (TEST_KID.test(options.kid) ? LICENSE_PUBLIC_KEYS : productionKeys);
  if (Object.hasOwn(known, options.kid) && known[options.kid] !== x) {
    throw new Error(
      `this is not the private key of kid "${options.kid}" in the compiled public keys`,
    );
  }
  const issued = timestamp(options.issued ?? new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'));
  const payload: LicensePayload = {
    v: 1,
    id: options.id ?? randomUUID(),
    customer: options.customer,
    issued,
    expires: timestamp(options.expires),
    features: options.features,
  };
  const key = signLicenseKey(payload, options.kid, privateKey);
  // The server's own verifier, as of the issue date: the key must come back unchanged.
  const check = verifyLicenseKey(key, {
    publicKeys: { [options.kid]: x },
    revoked: REVOKED_LICENSE_IDS,
    now: new Date(Date.parse(issued)),
  });
  if (!check.ok) throw new Error(`the server would reject this key: ${check.reason}`);
  // Task 10 review M-6: a key that a server would not run with today is signed, but said so.
  const now = options.now ?? new Date();
  const today = licenseState(
    verifyLicenseKey(key, { publicKeys: { [options.kid]: x }, revoked: REVOKED_LICENSE_IDS, now }),
    now,
  );
  if (today.state === 'expired') {
    options.onWarning?.(`this key expired on ${payload.expires} and is past its grace period`);
  } else if (today.state === 'grace') {
    options.onWarning?.(
      `this key expired on ${payload.expires}; it is in its grace period until ${today.graceEndsAt?.toISOString() ?? ''}`,
    );
  } else if (today.reason === 'not-yet-valid') {
    options.onWarning?.(
      `this key is not valid before ${issued}: a server started earlier rejects it until it is restarted after that date`,
    );
  }
  return key;
}

/**
 * The server's verify options with the compiled keys, plus keys the caller names for this run
 * only (a compiled kid always wins, so a local key cannot mask the real one).
 */
export function inspectVerifyOptions(
  now: Date,
  extraKeys: Readonly<Record<string, string>> | undefined,
): VerifyOptions {
  const base = productionVerifyOptions(now);
  return { ...base, publicKeys: { ...extraKeys, ...base.publicKeys } };
}

/**
 * The state the server would compute for this key text at `now`: the same parser, verifier and
 * state function as readBootLicense and the edition (the parity test holds them equal).
 */
export function inspectLicense(
  text: string,
  options: { extraKeys?: Record<string, string>; now?: Date } = {},
): LicenseState {
  const now = options.now ?? new Date();
  return licenseState(verifyLicenseKey(text, inspectVerifyOptions(now, options.extraKeys)), now);
}

/** A readable report; never the key text. */
export function inspectKey(
  text: string,
  options: { extraKeys?: Record<string, string>; now?: Date } = {},
): string {
  const state = inspectLicense(text, options);
  const lines = [`state: ${state.state}`];
  if (state.reason) lines.push(`reason: ${state.reason}`);
  if (state.kid) {
    lines.push(`kid: ${state.kid}${state.kid.startsWith('test-') ? ' (a test key)' : ''}`);
  }
  if (state.license) lines.push(JSON.stringify(state.license, null, 2));
  if (state.graceEndsAt) lines.push(`grace ends: ${state.graceEndsAt.toISOString()}`);
  if (state.expiresSoon) lines.push('expires within 30 days');
  return lines.join('\n');
}
// ---------------------------------------------------------------------------------------------
// The private-key scan (enterprise.md §15): no tracked file may hold a private key.

export interface FoundKey {
  kind: 'pem' | 'ed25519-pkcs8' | 'ed25519-pkcs8-hex' | 'ed25519-pkcs8-der' | 'jwk' | 'putty';
  /** SHA-256 of the key material (the PEM body without whitespace), for the allow list. */
  fingerprint: string;
  /** The matched text (for a PEM block, from BEGIN to END). */
  text: string;
}

/** A key committed on purpose: test data that protects nothing. Never an Ed25519 key (a test). */
export interface AllowedKey {
  path: string;
  fingerprint: string;
  reason: string;
}

export const ALLOWED_TEST_KEYS: readonly AllowedKey[] = Object.freeze([
  {
    path: 'cli/test/tls.ts',
    fingerprint: 'f9a3dfba632efa0330a41cde3ba798334920684c5ac8b0be83115a12541bf11f',
    reason: "the EC P-256 key of the CLI tests' 127.0.0.1 TLS server certificate",
  },
  {
    path: 'server/test/fixtures/saml/idp.key.pem',
    fingerprint: 'd9ab89029c94d9f245b335f2ea84318e64bdb77193657165d72b037ea1ea80ec',
    reason: "the RSA 2048 key of the SAML tests' identity provider (plan 4D Task 5)",
  },
  {
    path: 'server/test/fixtures/saml/stranger.key.pem',
    fingerprint: '2369debcf1a6b7e0862018eafbead449b1b806161109fb888e388bfa0769f281',
    reason: "the RSA 2048 key of the SAML tests' stranger, whose signatures must be refused",
  },
  {
    path: 'server/test/fixtures/saml/sp.key.pem',
    fingerprint: 'b2f387fb3194a2845b164eeeb5d346619a5ef5a3f8decde1c13ae1bedaf0cbde',
    reason: "the RSA 2048 key of the SAML tests' service provider (signed requests)",
  },
]);

/**
 * Task 10 review M-1: tracked files larger than this are not read by the scan. None may exist
 * unless it is listed in LARGE_FILES_NOT_SCANNED with a reason; the scan's test fails otherwise.
 */
export const SCAN_SIZE_LIMIT = 2 * 1024 * 1024;
export const LARGE_FILES_NOT_SCANNED: readonly { path: string; reason: string }[] = Object.freeze(
  [],
);

/**
 * Task 10 review M-3: file names that hold private keys by convention. No tracked file may have
 * one, whatever it contains (a binary PKCS#12 or DER key has no text to find).
 */
export const PRIVATE_KEY_FILE_NAME =
  /(\.(p8|key|p12|pfx|der|ppk|jks|keystore|private\.pem)|(^|\/)id_(rsa|dsa|ecdsa|ed25519))$/i;

export function privateKeyFileNames(paths: readonly string[]): string[] {
  return paths.filter((p) => PRIVATE_KEY_FILE_NAME.test(p));
}

const sha256 = (text: string): string => createHash('sha256').update(text, 'latin1').digest('hex');

/** PEM and SSH2 (`---- BEGIN SSH2 ENCRYPTED PRIVATE KEY ----`) private key lines, any case. */
const PEM_BEGIN = /-{4,5} ?BEGIN ([A-Z0-9 ]*?)PRIVATE KEY(?: BLOCK)? ?-{4,5}[ \t]*\r?\n/gi;
const PEM_HEADER_LINE = /^[A-Za-z][A-Za-z0-9-]*:/;
const BASE64_RUN = /^[A-Za-z0-9+/=]+/;
const PEM_END = /^-{4,5} ?END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)? ?-{4,5}/i;
/** The raw text: any block with a body. */
const MIN_PEM_BODY = 16;
/** The normalised copy: a real key's body, not a short example in prose (Task 10 review I-1). */
const MIN_NORMALISED_PEM_BODY = 64;

/** PEM private key blocks with a body: PKCS#8, encrypted, PKCS#1, SEC1, OpenSSH, traditional. */
function pemKeys(text: string, minBody: number): FoundKey[] {
  const found: FoundKey[] = [];
  for (const match of text.matchAll(PEM_BEGIN)) {
    let at = match.index + match[0].length;
    let body = '';
    let inHeaders = true;
    while (at < text.length) {
      const eol = text.indexOf('\n', at);
      const next = eol === -1 ? text.length : eol + 1;
      const line = text
        .slice(at, eol === -1 ? text.length : eol)
        .replace(/\r$/, '')
        .trim();
      if (inHeaders && PEM_HEADER_LINE.test(line)) {
        at = next;
        continue;
      }
      if (inHeaders && line === '' && body === '') {
        inHeaders = false;
        at = next;
        continue;
      }
      inHeaders = false;
      // A line may end in something else ("MC4C..." in a document): its base64 start counts.
      const run = BASE64_RUN.exec(line)?.[0] ?? '';
      if (run !== '') {
        body += run;
        at = next;
        if (run.length === line.length) continue;
        break;
      }
      if (PEM_END.test(line)) at = next;
      break;
    }
    if (body.length >= minBody) {
      found.push({
        kind: 'pem',
        fingerprint: sha256(body),
        text: text.slice(match.index, at),
      });
    }
  }
  return found;
}

/**
 * Leading comment, quote and concatenation marks of a line: `//`, `#`, `>`, `*`, quotes, and a
 * `+` before a space or a quote (a base64 line may itself start with `+`).
 */
const LINE_PREFIX = /^[ \t]*(?:(?:\/\/|[#>*'"`]|\+(?=[ \t'"`]))[ \t]*)+/gm;

/**
 * Task 10 review I-1: the text as a key would read once unescaped: `\n` and `\r\n` escapes (a key
 * in a JSON or JavaScript string, such as a cloud service account file) and carriage returns
 * become line breaks, and each line loses its leading comment, quote and `+` marks (a key
 * commented out or concatenated line by line).
 */
export function normaliseForScan(text: string): string {
  return text
    .replace(/\\r\\n|\\n|\\r/g, '\n')
    .replace(/\r\n?/g, '\n')
    .replace(LINE_PREFIX, '');
}

/** Ed25519 PKCS#8 (v1, and v2 with the public key) in base64 or base64url, outside PEM too. */
const ED25519_BASE64 = /(?:MC4CAQAwBQYDK2VwBCIEI|MFECAQEwBQYDK2VwBCIEI)[A-Za-z0-9+/_-]{40,}/g;
const ED25519_HEX = /(?:302e020100|3051020101)300506032b657004220420[0-9a-f]{64}/gi;
const ED25519_DER = ['302e020100300506032b657004220420', '3051020101300506032b657004220420'].map(
  (hex) => Buffer.from(hex, 'hex').toString('latin1'),
);
/**
 * A JWK private member `d` (Ed25519 and P-256: 43 characters; RSA and larger curves: more), in
 * JSON, YAML or a JavaScript object: the name and the value quoted either way, or not at all
 * (Task 10 review M-2). Only in a text that also names `kty`.
 */
const JWK_D = /(?:^|[\s{,])["']?d["']?[ \t]*:[ \t]*["']?([A-Za-z0-9_-]{32,})/gm;
const JWK_KTY = /(?:^|[\s{,])["']?kty["']?[ \t]*:/m;
const PUTTY = /^PuTTY-User-Key-File-\d+:.*$/gm;

/** Every private key in `text` (read as latin1, so binary DER is seen too). */
export function findPrivateKeys(text: string): FoundKey[] {
  const found = pemKeys(text, MIN_PEM_BODY);
  // The same blocks in a JSON string, a comment or a concatenation; one key counts once.
  const seen = new Set(found.map((k) => k.fingerprint));
  for (const key of pemKeys(normaliseForScan(text), MIN_NORMALISED_PEM_BODY)) {
    if (!seen.has(key.fingerprint)) found.push(key);
    seen.add(key.fingerprint);
  }
  for (const m of text.matchAll(ED25519_BASE64)) {
    found.push({ kind: 'ed25519-pkcs8', fingerprint: sha256(m[0]), text: m[0] });
  }
  for (const m of text.matchAll(ED25519_HEX)) {
    found.push({
      kind: 'ed25519-pkcs8-hex',
      fingerprint: sha256(m[0].toLowerCase()),
      text: m[0],
    });
  }
  for (const prefix of ED25519_DER) {
    for (let at = text.indexOf(prefix); at !== -1; at = text.indexOf(prefix, at + 1)) {
      const der = text.slice(at, at + prefix.length + 32);
      if (der.length === prefix.length + 32) {
        found.push({ kind: 'ed25519-pkcs8-der', fingerprint: sha256(der), text: der });
      }
    }
  }
  if (JWK_KTY.test(text)) {
    for (const m of text.matchAll(JWK_D)) {
      found.push({ kind: 'jwk', fingerprint: sha256(m[1] ?? ''), text: m[0] });
    }
  }
  for (const m of text.matchAll(PUTTY)) {
    found.push({ kind: 'putty', fingerprint: sha256(m[0]), text: m[0] });
  }
  return found;
}

/** Tracked files that hold a private key, except the listed test keys in their own files. */
export function trackedPrivateKeys(
  files: { path: string; text: string }[],
  allowed: readonly AllowedKey[] = ALLOWED_TEST_KEYS,
): string[] {
  return files
    .filter((f) =>
      findPrivateKeys(f.text).some(
        (k) => !allowed.some((a) => a.path === f.path && a.fingerprint === k.fingerprint),
      ),
    )
    .map((f) => f.path);
}
