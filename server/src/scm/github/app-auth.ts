import {
  createHash,
  createHmac,
  createPrivateKey,
  sign,
  timingSafeEqual,
  type KeyObject,
} from 'node:crypto';

/** github.md §2.2: a private key PEM is at most this long ... */
export const MAX_PRIVATE_KEY_BYTES = 16 * 1024;
/** ... and an RSA key of at least this many bits. */
export const MIN_RSA_BITS = 2048;
/**
 * github.md §2.2: a positive integer without leading zeros that fits a JavaScript safe integer
 * (GitHub answers it as a JSON number). The database CHECK (`^[0-9]{1,20}$`) is broader; the API
 * and the client hold this one. Use {@link isGitHubAppId}, which also checks the safe range.
 */
export const GITHUB_APP_ID = /^[1-9][0-9]{0,15}$/;

export function isGitHubAppId(value: string): boolean {
  return GITHUB_APP_ID.test(value) && Number.isSafeInteger(Number(value));
}
/** github.md §2.2: 16–256 printable ASCII characters without spaces. */
export const WEBHOOK_SECRET_PATTERN = /^[\x21-\x7e]{16,256}$/;
/** github.md §4: GitHub accepts a clock up to 60 s behind and a JWT valid up to 10 minutes. */
export const JWT_BACKDATE_SECONDS = 60;
export const JWT_LIFETIME_SECONDS = 540;
/** github.md §4: a cached installation token is reused while more than this remains. */
export const TOKEN_REUSE_MARGIN_MS = 5 * 60_000;
export const MAX_CACHED_TOKENS = 1_000;
/** github.md §5.3: mutations of one installation at least this far apart. */
export const MUTATION_SPACING_MS = 1_000;

export type PrivateKeyProblem = 'too_large' | 'not_pem' | 'encrypted' | 'not_rsa' | 'too_short';

/** The 422 texts of `body.privateKey` (github.md §2.2). */
export const PRIVATE_KEY_PROBLEM_TEXT: Record<PrivateKeyProblem, string> = {
  too_large: 'The private key is larger than 16 KiB',
  not_pem: 'Use the private key GitHub generated for the App (a PEM file)',
  encrypted: 'Use the unencrypted key GitHub generated',
  not_rsa: 'The private key must be an RSA key',
  too_short: 'The private key must be an RSA key of at least 2048 bits',
};

const PEM = /^-----BEGIN (RSA )?PRIVATE KEY-----\n[A-Za-z0-9+/=\n]+\n-----END \1PRIVATE KEY-----$/;

/**
 * github.md §2.2 (ruling GH4): the App's private key, checked with `createPrivateKey` and kept as
 * its canonical PKCS#8 PEM export. Line ends and surrounding white space are normalised first (a
 * key pasted from Windows is the same key). Never returns or logs the input.
 */
export function parseAppPrivateKey(
  pem: string,
): { key: KeyObject; pkcs8: string } | { problem: PrivateKeyProblem } {
  if (Buffer.byteLength(pem, 'utf8') > MAX_PRIVATE_KEY_BYTES) return { problem: 'too_large' };
  const text = pem.replace(/\r\n?/g, '\n').trim();
  // Only the header lines say so; the base64 key material may spell anything.
  if (/^(?:-----BEGIN ENCRYPTED PRIVATE KEY-----|Proc-Type: 4,ENCRYPTED)$/m.test(text)) {
    return { problem: 'encrypted' };
  }
  if (!PEM.test(text)) return { problem: 'not_pem' };
  let key: KeyObject;
  try {
    key = createPrivateKey({ key: text, format: 'pem' });
  } catch {
    return { problem: 'not_pem' };
  }
  if (key.asymmetricKeyType !== 'rsa') return { problem: 'not_rsa' };
  if ((key.asymmetricKeyDetails?.modulusLength ?? 0) < MIN_RSA_BITS) {
    return { problem: 'too_short' };
  }
  return { key, pkcs8: key.export({ type: 'pkcs8', format: 'pem' }).toString() };
}

const base64url = (value: Buffer | string): string => Buffer.from(value).toString('base64url');

/**
 * github.md §4: the App's JWT, RS256 (`RSASSA-PKCS1-v1_5` with SHA-256, the default padding of
 * `sign` for an RSA key), `iat` back-dated 60 s, `exp` 9 minutes on, `iss` the App id.
 */
export function appJwt(appId: string, key: KeyObject, nowSeconds: number): string {
  if (!isGitHubAppId(appId)) throw new Error('not a GitHub App id');
  if (!Number.isSafeInteger(nowSeconds)) throw new Error('not a time in whole seconds');
  const header = base64url(JSON.stringify({ alg: 'RS256', typ: 'JWT' }));
  const payload = base64url(
    JSON.stringify({
      iat: nowSeconds - JWT_BACKDATE_SECONDS,
      exp: nowSeconds + JWT_LIFETIME_SECONDS,
      iss: appId,
    }),
  );
  const signature = sign('sha256', Buffer.from(`${header}.${payload}`), key);
  return `${header}.${payload}.${base64url(signature)}`;
}

const SIGNATURE = /^sha256=([0-9a-f]{64})$/;

/**
 * github.md §9: `X-Hub-Signature-256` is `sha256=` and the lower-case hex HMAC-SHA256 of the raw
 * body under the webhook secret, compared in constant time. Anything else is false.
 */
export function verifyWebhookSignature(
  secret: string,
  body: Buffer,
  header: string | undefined,
): boolean {
  if (typeof header !== 'string') return false;
  const match = SIGNATURE.exec(header);
  if (!match?.[1]) return false;
  const expected = createHmac('sha256', secret).update(body).digest();
  return timingSafeEqual(expected, Buffer.from(match[1], 'hex'));
}

/** A short hash of the credentials (github.md §4): tells a replaced key apart, reveals nothing. */
export function credentialsId(appId: string, privateKey: string): string {
  return createHash('sha256').update(`${appId}\0${privateKey}`, 'utf8').digest('hex').slice(0, 16);
}

/**
 * The token cache's key. It holds no secret (the credentials are a hash), but it names the
 * connection, installation and repository: never log it, nor put it in an error or a response.
 */
export function tokenCacheKey(parts: {
  connectionId: string;
  credentials: string;
  installationId: number;
  repo: string;
}): string {
  return `${parts.connectionId}|${parts.credentials}|${parts.installationId}|${parts.repo.toLowerCase()}`;
}

/**
 * github.md §4: installation tokens in this process's memory, never in the database; reused
 * while more than {@link TOKEN_REUSE_MARGIN_MS} remain; at most {@link MAX_CACHED_TOKENS}, the
 * oldest dropped first. A true private field keeps the tokens out of any serialisation.
 */
export class InstallationTokenCache {
  readonly #entries = new Map<string, { token: string; expiresAt: number }>();

  constructor(private readonly now: () => number = Date.now) {}

  get size(): number {
    return this.#entries.size;
  }

  get(key: string): string | null {
    const entry = this.#entries.get(key);
    if (!entry) return null;
    if (entry.expiresAt - this.now() <= TOKEN_REUSE_MARGIN_MS) {
      this.#entries.delete(key);
      return null;
    }
    return entry.token;
  }

  set(key: string, token: string, expiresAt: number): void {
    // A NaN expiry would compare false against the margin and keep the token forever.
    if (!Number.isFinite(expiresAt)) throw new Error('not a token expiry');
    this.#entries.delete(key);
    while (this.#entries.size >= MAX_CACHED_TOKENS) {
      const oldest = this.#entries.keys().next().value;
      if (oldest === undefined) break;
      this.#entries.delete(oldest);
    }
    this.#entries.set(key, { token, expiresAt });
  }

  drop(key: string): void {
    this.#entries.delete(key);
  }

  toJSON(): { size: number } {
    return { size: this.#entries.size };
  }
}

/**
 * github.md §5.3: GitHub asks for at least one second between mutations. Per process and per
 * installation, a mutation waits until {@link MUTATION_SPACING_MS} have passed since the last one
 * started; waiters that wake together check again, so they go one per second.
 */
export class MutationPacer {
  readonly #last = new Map<string, number>();

  constructor(
    private readonly now: () => number = Date.now,
    private readonly sleep: (ms: number) => Promise<void> = (ms) =>
      new Promise((resolve) => setTimeout(resolve, ms)),
  ) {}

  async wait(key: string): Promise<void> {
    for (;;) {
      const last = this.#last.get(key);
      const due = last === undefined ? 0 : last + MUTATION_SPACING_MS - this.now();
      if (due <= 0) {
        if (this.#last.size > 1_000) this.prune();
        this.#last.set(key, this.now());
        return;
      }
      await this.sleep(due);
    }
  }

  private prune(): void {
    const cutoff = this.now() - MUTATION_SPACING_MS;
    for (const [key, at] of this.#last) if (at < cutoff) this.#last.delete(key);
  }
}
