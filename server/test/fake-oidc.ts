import {
  createHash,
  generateKeyPairSync,
  randomBytes,
  sign as rsaSign,
  type KeyObject,
} from 'node:crypto';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { exportJWK, SignJWT } from 'jose';

/**
 * A fake OpenID Provider for the OIDC tests (sso-scim.md §5, §19.3): discovery, JWKS, the token
 * endpoint (authorization code with PKCE), userinfo, and a programmatic `authorize` that plays the
 * browser's part. Every field the attack corpus breaks is a tweak.
 */
export interface FakeOpTweaks {
  /** The `issuer` the discovery document states (default: the real one). */
  issuerInDiscovery: string | undefined;
  idTokenIss: string | undefined;
  idTokenAud: string | string[] | undefined;
  idTokenAzp: string | undefined;
  /** The ID token's `nonce` (default: the one the authorization request carried); null leaves it out. */
  nonce: string | null | undefined;
  alg: 'RS256' | 'none' | 'HS256';
  /**
   * The HS256 key: the client secret, or the bytes of the RSA public key's PEM (the key-confusion
   * attack, where a verifier takes the published RSA key as an HMAC secret).
   */
  hsKey: 'clientSecret' | 'publicKeyPem';
  /** The RSA key's size; a change makes a new key. */
  rsaBits: number;
  /** The `kid` in the ID token's header (the JWKS key is always `k1`). */
  kid: string;
  /** RS256 signed by a key the JWKS does not hold, under the JWKS key's `kid` (a forgery). */
  foreignKey: boolean;
  expOffsetSeconds: number;
  iatOffsetSeconds: number;
  /** The `iss` authorization response parameter (RFC 9207); default: the issuer when advertised. */
  issParam: string | undefined;
  advertiseIssParam: boolean;
  /**
   * `id_token_signing_alg_values_supported` in discovery (default `['RS256']`). A real IdP that
   * also offers HS256 lets a forged token past openid-client's metadata check, to the
   * asymmetric-only check behind it.
   */
  signingAlgs: string[];
  /** Discovery names no `jwks_uri`. */
  omitJwksUri: boolean;
  /** The `token_endpoint` discovery names (default: `<issuer>/token`). */
  tokenEndpoint: string | undefined;
  /** Whether the token endpoint checks the PKCE verifier (default true). */
  checkVerifier: boolean;
  /** The token endpoint expects this verifier instead of the one the challenge was made from. */
  expectVerifier: string | undefined;
  /** The token endpoint answers 302 instead of tokens. */
  redirectFromToken: boolean;
  /** Overrides the user's `email_verified` in the ID token. */
  emailVerified: boolean | undefined;
}

export interface FakeOpOptions {
  clientId?: string;
  clientSecret?: string;
  tweaks?: Partial<FakeOpTweaks>;
}

export interface FakeOp {
  issuer: string;
  clientId: string;
  clientSecret: string;
  port: number;
  users: Map<string, Record<string, unknown>>;
  tweak(t: Partial<FakeOpTweaks>): void;
  /** The IdP's side of the browser round trip: the callback URL the browser would be sent to. */
  authorize(authorizationUrl: string, login: string): Promise<string>;
  lastTokenRequest(): URLSearchParams | null;
  close(): Promise<void>;
}

const DEFAULT_TWEAKS: FakeOpTweaks = {
  issuerInDiscovery: undefined,
  idTokenIss: undefined,
  idTokenAud: undefined,
  idTokenAzp: undefined,
  nonce: undefined,
  alg: 'RS256',
  hsKey: 'clientSecret',
  rsaBits: 2048,
  kid: 'k1',
  foreignKey: false,
  expOffsetSeconds: 0,
  iatOffsetSeconds: 0,
  issParam: undefined,
  advertiseIssParam: false,
  signingAlgs: ['RS256'],
  omitJwksUri: false,
  tokenEndpoint: undefined,
  checkVerifier: true,
  expectVerifier: undefined,
  redirectFromToken: false,
  emailVerified: undefined,
};

interface PendingCode {
  login: string;
  nonce: string | null;
  codeChallenge: string | null;
  redirectUri: string;
  clientId: string;
}

const MAX_BODY = 64 * 1024;
const b64url = (data: Buffer | string): string => Buffer.from(data).toString('base64url');

function seedUsers(): Map<string, Record<string, unknown>> {
  return new Map<string, Record<string, unknown>>([
    [
      'alice',
      {
        sub: 'alice-sub',
        email: 'alice@acme.example',
        email_verified: true,
        preferred_username: 'alice',
        name: 'Alice A',
        groups: ['qualor-admins'],
      },
    ],
    [
      'bob',
      {
        sub: 'bob-sub',
        email: 'bob@acme.example',
        email_verified: false,
        preferred_username: 'bob',
        name: 'Bob B',
        groups: ['qualor-devs'],
      },
    ],
  ]);
}

function readBody(req: IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    const chunks: Buffer[] = [];
    let size = 0;
    req.on('data', (chunk: Buffer) => {
      size += chunk.length;
      if (size > MAX_BODY) {
        reject(new Error('body too large'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}

function json(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { 'content-type': 'application/json', 'cache-control': 'no-store' });
  res.end(JSON.stringify(body));
}

/** `application/x-www-form-urlencoded` decoding of one Basic credential half (RFC 6749 §2.3.1). */
const formDecode = (s: string): string => decodeURIComponent(s.replace(/\+/g, ' '));

export async function startFakeOp(options: FakeOpOptions = {}): Promise<FakeOp> {
  const clientId = options.clientId ?? 'qualor-test';
  const clientSecret = options.clientSecret ?? `fake-op-${randomBytes(12).toString('hex')}`;
  const users = seedUsers();
  const tweaks: FakeOpTweaks = { ...DEFAULT_TWEAKS, ...options.tweaks };
  const codes = new Map<string, PendingCode>();
  const accessTokens = new Map<string, string>();
  let lastToken: URLSearchParams | null = null;
  let keyBits = 0;
  let privateKey: KeyObject | undefined;
  let publicJwk: Record<string, unknown> = {};
  let publicPem = '';

  async function ensureKey(): Promise<KeyObject> {
    if (privateKey && keyBits === tweaks.rsaBits) return privateKey;
    const pair = generateKeyPairSync('rsa', { modulusLength: tweaks.rsaBits });
    privateKey = pair.privateKey;
    publicPem = pair.publicKey.export({ type: 'spki', format: 'pem' }).toString();
    keyBits = tweaks.rsaBits;
    publicJwk = { ...(await exportJWK(pair.publicKey)), kid: 'k1', alg: 'RS256', use: 'sig' };
    return privateKey;
  }
  await ensureKey();

  let issuer = '';

  async function idToken(code: PendingCode, user: Record<string, unknown>): Promise<string> {
    const now = Math.floor(Date.now() / 1000);
    const payload: Record<string, unknown> = {
      ...user,
      iss: tweaks.idTokenIss ?? issuer,
      aud: tweaks.idTokenAud ?? clientId,
      nonce: tweaks.nonce === null ? undefined : (tweaks.nonce ?? code.nonce ?? undefined),
      iat: now + tweaks.iatOffsetSeconds,
      exp: now + 300 + tweaks.expOffsetSeconds,
      email_verified: tweaks.emailVerified ?? user.email_verified,
    };
    if (tweaks.idTokenAzp !== undefined) payload.azp = tweaks.idTokenAzp;
    if (tweaks.alg === 'none') {
      return `${b64url(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${b64url(JSON.stringify(payload))}.`;
    }
    if (tweaks.alg === 'HS256') {
      return new SignJWT(payload)
        .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
        .sign(new TextEncoder().encode(tweaks.hsKey === 'publicKeyPem' ? publicPem : clientSecret));
    }
    const own = await ensureKey();
    const key = tweaks.foreignKey
      ? generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey
      : own;
    if (keyBits < 2048) {
      // jose refuses to sign RS256 with a key under 2048 bits; an OP with such a key signs anyway.
      const input = `${b64url(JSON.stringify({ alg: 'RS256', typ: 'JWT', kid: tweaks.kid }))}.${b64url(JSON.stringify(payload))}`;
      return `${input}.${b64url(rsaSign('sha256', Buffer.from(input), key))}`;
    }
    return new SignJWT(payload)
      .setProtectedHeader({ alg: 'RS256', typ: 'JWT', kid: tweaks.kid })
      .sign(key);
  }

  /** The client's credentials, by Basic or in the body; true when they are this client's. */
  function clientAuthenticated(req: IncomingMessage, form: URLSearchParams): boolean {
    const header = req.headers.authorization;
    if (header?.startsWith('Basic ')) {
      const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
      const colon = decoded.indexOf(':');
      if (colon < 0) return false;
      return (
        formDecode(decoded.slice(0, colon)) === clientId &&
        formDecode(decoded.slice(colon + 1)) === clientSecret
      );
    }
    return form.get('client_id') === clientId && form.get('client_secret') === clientSecret;
  }

  async function token(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const form = new URLSearchParams(await readBody(req));
    lastToken = form;
    if (tweaks.redirectFromToken) {
      res.writeHead(302, { location: `${issuer}/elsewhere` });
      res.end();
      return;
    }
    if (!clientAuthenticated(req, form)) {
      json(res, 401, { error: 'invalid_client' });
      return;
    }
    if (form.get('grant_type') !== 'authorization_code') {
      json(res, 400, { error: 'unsupported_grant_type' });
      return;
    }
    const codeValue = form.get('code') ?? '';
    const code = codes.get(codeValue);
    codes.delete(codeValue);
    if (!code || code.redirectUri !== form.get('redirect_uri') || code.clientId !== clientId) {
      json(res, 400, { error: 'invalid_grant' });
      return;
    }
    if (tweaks.checkVerifier) {
      const verifier = form.get('code_verifier');
      const challenge =
        verifier === null ? null : createHash('sha256').update(verifier).digest('base64url');
      const expected =
        tweaks.expectVerifier === undefined
          ? code.codeChallenge
          : createHash('sha256').update(tweaks.expectVerifier).digest('base64url');
      if (expected === null || challenge !== expected) {
        json(res, 400, { error: 'invalid_grant' });
        return;
      }
    }
    const user = users.get(code.login);
    if (!user) {
      json(res, 400, { error: 'invalid_grant' });
      return;
    }
    const accessToken = randomBytes(24).toString('base64url');
    accessTokens.set(accessToken, code.login);
    json(res, 200, {
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 300,
      id_token: await idToken(code, user),
    });
  }

  const server = createServer((req, res) => {
    const url = new URL(req.url ?? '/', 'http://fake-op');
    void (async () => {
      if (req.method === 'GET' && url.pathname === '/.well-known/openid-configuration') {
        json(res, 200, {
          issuer: tweaks.issuerInDiscovery ?? issuer,
          authorization_endpoint: `${issuer}/auth`,
          token_endpoint: tweaks.tokenEndpoint ?? `${issuer}/token`,
          ...(tweaks.omitJwksUri ? {} : { jwks_uri: `${issuer}/jwks` }),
          userinfo_endpoint: `${issuer}/userinfo`,
          response_types_supported: ['code'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: tweaks.signingAlgs,
          code_challenge_methods_supported: ['S256'],
          token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post'],
          authorization_response_iss_parameter_supported: tweaks.advertiseIssParam,
        });
      } else if (req.method === 'GET' && url.pathname === '/jwks') {
        await ensureKey();
        json(res, 200, { keys: [publicJwk] });
      } else if (req.method === 'POST' && url.pathname === '/token') {
        await token(req, res);
      } else if (url.pathname === '/userinfo') {
        const header = req.headers.authorization ?? '';
        const login = header.startsWith('Bearer ') ? accessTokens.get(header.slice(7)) : undefined;
        const user = login === undefined ? undefined : users.get(login);
        if (!user) {
          res.writeHead(401, { 'www-authenticate': 'Bearer error="invalid_token"' });
          res.end();
        } else json(res, 200, user);
      } else {
        json(res, 404, { error: 'not_found' });
      }
    })().catch(() => {
      if (!res.headersSent) json(res, 500, { error: 'server_error' });
      else res.destroy();
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as AddressInfo).port;
  issuer = `http://127.0.0.1:${port}`;

  return {
    issuer,
    clientId,
    clientSecret,
    port,
    users,
    tweak(t) {
      Object.assign(tweaks, t);
      for (const [name, value] of Object.entries(t)) {
        const key = name as keyof FakeOpTweaks;
        if (value === undefined) Object.assign(tweaks, { [key]: DEFAULT_TWEAKS[key] });
      }
    },
    authorize(authorizationUrl, login) {
      const url = new URL(authorizationUrl);
      const redirectUri = url.searchParams.get('redirect_uri');
      if (redirectUri === null) return Promise.reject(new Error('no redirect_uri'));
      if (!users.has(login)) return Promise.reject(new Error(`unknown user ${login}`));
      const code = randomBytes(24).toString('base64url');
      codes.set(code, {
        login,
        nonce: url.searchParams.get('nonce'),
        codeChallenge: url.searchParams.get('code_challenge'),
        redirectUri,
        clientId: url.searchParams.get('client_id') ?? '',
      });
      const callback = new URL(redirectUri);
      callback.searchParams.set('code', code);
      const state = url.searchParams.get('state');
      if (state !== null) callback.searchParams.set('state', state);
      const iss = tweaks.issParam ?? (tweaks.advertiseIssParam ? issuer : undefined);
      if (iss !== undefined) callback.searchParams.set('iss', iss);
      return Promise.resolve(callback.href);
    },
    lastTokenRequest: () => lastToken,
    close: () =>
      new Promise<void>((resolve, reject) => {
        server.closeAllConnections();
        server.close((err) => (err ? reject(err) : resolve()));
      }),
  };
}
