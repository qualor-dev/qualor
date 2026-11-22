import { createHash, verify, X509Certificate } from 'node:crypto';
import type { IncomingHttpHeaders } from 'node:http';
import { createServer, type Server } from 'node:https';
import type { AddressInfo } from 'node:net';
import { inspect } from 'node:util';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { TEST_IDP, TEST_SP } from '../../../test/saml';
import { TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM, trustTestCa } from '../../../test/tls';
import { VERSION } from '../../index';
import { ScmError } from '../provider';
import { parseAzureCertificate, type ParsedCertificate } from './certificate';
import {
  ENTRA_TEXT,
  entraCacheKey,
  entraToken,
  entraTokenUrl,
  MAX_ENTRA_RESPONSE_BYTES,
  type EntraCredential,
  type EntraOptions,
} from './entra';

const TENANT = '0f1e2d3c-4b5a-4987-a6b5-c4d3e2f1a0b9';
const CLIENT = '6c1d2e3f-4a5b-4c6d-8e7f-90a1b2c3d4e5';
// Joined so no scanner takes the test values for real ones.
const SECRET = ['entra-test-', 'client-secret'].join('');
const ACCESS_TOKEN = ['entra-test-', 'access-token'].join('');
/** Azure DevOps' resource id; the scope Entra was asked for in the probe (2026-11-22). */
const SCOPE = '499b84ac-1321-427f-aa17-267ca6975798/.default';
/** A time with milliseconds: the assertion's seconds are rounded down. */
const NOW = 1_800_000_000_750;
const NOW_SECONDS = 1_800_000_000;

function certificateOf(pair: { certPem: string; keyPem: string }): ParsedCertificate {
  const parsed = parseAzureCertificate(`${pair.certPem}${pair.keyPem}`);
  if ('problem' in parsed) throw new Error(parsed.problem);
  return parsed;
}

const SECRET_CREDENTIAL: EntraCredential = {
  kind: 'secret',
  tenantId: TENANT,
  clientId: CLIENT,
  secret: SECRET,
};
const CERTIFICATE_CREDENTIAL: EntraCredential = {
  kind: 'certificate',
  tenantId: TENANT,
  clientId: CLIENT,
  certificate: certificateOf(TEST_IDP),
};

/** The token answer Microsoft documents for the client credentials grant. */
const TOKEN_ANSWER = JSON.stringify({
  token_type: 'Bearer',
  expires_in: 3599,
  ext_expires_in: 3599,
  access_token: ACCESS_TOKEN,
});

/**
 * Entra's error answer as Microsoft documents it (AADSTS7000215, an invalid client secret), with a
 * marker that must never reach an error.
 */
const MARKER = 'entra-body-marker-6f2c';
const REFUSAL = JSON.stringify({
  error: 'invalid_client',
  error_description: `AADSTS7000215: Invalid client secret provided. ${MARKER} Trace ID: 0000 Correlation ID: 1111 Timestamp: 2026-11-22 10:00:00Z`,
  error_codes: [7000215],
  timestamp: '2026-11-22 10:00:00Z',
  trace_id: '00000000-0000-0000-0000-000000000000',
  correlation_id: '11111111-1111-1111-1111-111111111111',
  error_uri: 'https://login.microsoftonline.com/error?code=7000215',
});

interface Seen {
  method: string;
  path: string;
  headers: IncomingHttpHeaders;
  body: string;
}

type Answer = { status: number; headers?: Record<string, string>; body: string } | 'hang';

let server: Server;
let base: string;
let untrust: () => void;
let answer: Answer;
const seen: Seen[] = [];

beforeAll(async () => {
  untrust = trustTestCa();
  server = createServer({ cert: TEST_SERVER_CERT_PEM, key: TEST_SERVER_KEY_PEM }, (req, res) => {
    const chunks: Buffer[] = [];
    req.on('data', (chunk: Buffer) => chunks.push(chunk));
    req.on('end', () => {
      seen.push({
        method: req.method ?? '',
        path: req.url ?? '',
        headers: req.headers,
        body: Buffer.concat(chunks).toString('utf8'),
      });
      if (answer === 'hang') return;
      res.writeHead(answer.status, {
        'content-type': 'application/json; charset=utf-8',
        ...answer.headers,
      });
      res.end(answer.body);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  base = `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterAll(async () => {
  server.closeAllConnections();
  await new Promise((resolve) => server.close(resolve));
  untrust();
});

beforeEach(() => {
  seen.length = 0;
  answer = { status: 200, body: TOKEN_ANSWER };
});

const tokenUrlOf = (tenantId: string) => `${base}/${tenantId}/oauth2/v2.0/token`;
const options = (more: EntraOptions = {}): EntraOptions => ({
  tokenUrl: tokenUrlOf,
  allowInternalHosts: true,
  now: () => NOW,
  ...more,
});

async function failure(promise: Promise<unknown>): Promise<ScmError> {
  try {
    await promise;
  } catch (err) {
    if (err instanceof ScmError) return err;
    throw err;
  }
  throw new Error('no error');
}

/** Every way the error could be written down: none may carry the body or a credential. */
function written(err: ScmError): string {
  return [err.message, String(err), err.stack ?? '', JSON.stringify(err), inspect(err)].join('\n');
}

const formOf = (body: string) => new URLSearchParams(body);
const decoded = (part: string): unknown => JSON.parse(Buffer.from(part, 'base64url').toString());

describe('entraToken with a client secret (Azure DevOps design §7.1)', () => {
  it('posts exactly the client credentials form to the tenant token endpoint', async () => {
    const issued = await entraToken(SECRET_CREDENTIAL, options());
    expect(issued).toEqual({ token: ACCESS_TOKEN, expiresAt: NOW + 3599_000 });
    expect(seen).toHaveLength(1);
    const [request] = seen;
    expect(request?.method).toBe('POST');
    expect(request?.path).toBe(`/${TENANT}/oauth2/v2.0/token`);
    expect(request?.headers['content-type']).toBe('application/x-www-form-urlencoded');
    expect(request?.headers.accept).toBe('application/json');
    expect(request?.headers['user-agent']).toBe(`Qualor/${VERSION}`);
    expect(request?.headers.authorization).toBeUndefined();
    const form = formOf(request?.body ?? '');
    expect([...form.keys()]).toHaveLength(4);
    expect(Object.fromEntries(form)).toEqual({
      grant_type: 'client_credentials',
      client_id: CLIENT,
      scope: SCOPE,
      client_secret: SECRET,
    });
  });

  it('takes expires_in as a numeric string and a lower-case token type', async () => {
    answer = {
      status: 200,
      body: JSON.stringify({
        token_type: 'bearer',
        expires_in: '3600',
        access_token: ACCESS_TOKEN,
      }),
    };
    expect(await entraToken(SECRET_CREDENTIAL, options())).toEqual({
      token: ACCESS_TOKEN,
      expiresAt: NOW + 3600_000,
    });
  });
});

describe('entraToken with a certificate (Azure DevOps design §7.1)', () => {
  const idp = new X509Certificate(TEST_IDP.certPem);

  async function assertion(): Promise<{ form: URLSearchParams; parts: string[] }> {
    seen.length = 0;
    await entraToken(CERTIFICATE_CREDENTIAL, options());
    const form = formOf(seen[0]?.body ?? '');
    return { form, parts: (form.get('client_assertion') ?? '').split('.') };
  }

  it('posts a client assertion in place of a secret', async () => {
    const { form } = await assertion();
    expect([...form.keys()].sort()).toEqual([
      'client_assertion',
      'client_assertion_type',
      'client_id',
      'grant_type',
      'scope',
    ]);
    expect(Object.fromEntries(form)).toMatchObject({
      grant_type: 'client_credentials',
      client_id: CLIENT,
      scope: SCOPE,
      client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
    });
  });

  it('signs an RS256 JWT that names the certificate and verifies with its public key', async () => {
    const { parts } = await assertion();
    expect(parts).toHaveLength(3);
    const [header, claims, signature] = parts as [string, string, string];
    expect(decoded(header)).toEqual({
      alg: 'RS256',
      typ: 'JWT',
      x5t: createHash('sha1').update(idp.raw).digest('base64url'),
    });
    expect(decoded(claims)).toEqual({
      aud: tokenUrlOf(TENANT),
      iss: CLIENT,
      sub: CLIENT,
      jti: expect.stringMatching(
        /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/,
      ),
      nbf: NOW_SECONDS,
      exp: NOW_SECONDS + 600,
    });
    const signed = Buffer.from(`${header}.${claims}`);
    expect(verify('sha256', signed, idp.publicKey, Buffer.from(signature, 'base64url'))).toBe(true);
    const stranger = new X509Certificate(TEST_SP.certPem).publicKey;
    expect(verify('sha256', signed, stranger, Buffer.from(signature, 'base64url'))).toBe(false);
  });

  it('gives every assertion its own jti', async () => {
    const first = decoded((await assertion()).parts[1] ?? '') as { jti: string };
    const second = decoded((await assertion()).parts[1] ?? '') as { jti: string };
    expect(first.jti).not.toBe(second.jti);
  });
});

describe('entraToken refusals and failures', () => {
  it.each([400, 401])(
    'answers a %i as the fixed refusal, never with what Entra said',
    async (status) => {
      answer = { status, body: REFUSAL };
      const err = await failure(entraToken(SECRET_CREDENTIAL, options()));
      expect(err).toMatchObject({ kind: 'auth', reason: 'token_endpoint', status });
      expect(err.message).toBe('Microsoft Entra refused the service principal');
      expect(err.message).toBe(ENTRA_TEXT.refused);
      expect(err.providerMessage).toBeNull();
      const text = written(err);
      for (const leak of [MARKER, 'AADSTS', 'invalid_client', SECRET]) {
        expect(text).not.toContain(leak);
      }
    },
  );

  it('never writes the assertion or the key into an error', async () => {
    answer = { status: 401, body: REFUSAL };
    const err = await failure(entraToken(CERTIFICATE_CREDENTIAL, options()));
    const sent = formOf(seen[0]?.body ?? '').get('client_assertion') ?? '';
    expect(sent).not.toBe('');
    const text = written(err);
    for (const part of sent.split('.')) expect(text).not.toContain(part);
    const keyLine = TEST_IDP.keyPem.split(/\r?\n/)[1] ?? '';
    expect(keyLine).not.toBe('');
    expect(text).not.toContain(keyLine);
  });

  it.each([
    ['not JSON', 'not json'],
    ['an HTML page', '<html><body>Sign in</body></html>'],
    ['null', 'null'],
    ['an array', '[]'],
    ['no access token', JSON.stringify({ token_type: 'Bearer', expires_in: 3599 })],
    [
      'an empty access token',
      JSON.stringify({ token_type: 'Bearer', expires_in: 3599, access_token: '' }),
    ],
    [
      'another token type',
      JSON.stringify({ token_type: 'mac', expires_in: 3599, access_token: ACCESS_TOKEN }),
    ],
    ['no expiry', JSON.stringify({ token_type: 'Bearer', access_token: ACCESS_TOKEN })],
    [
      'a word for the expiry',
      JSON.stringify({ token_type: 'Bearer', expires_in: 'soon', access_token: ACCESS_TOKEN }),
    ],
    [
      'a zero expiry',
      JSON.stringify({ token_type: 'Bearer', expires_in: 0, access_token: ACCESS_TOKEN }),
    ],
    [
      'a negative expiry',
      JSON.stringify({ token_type: 'Bearer', expires_in: -60, access_token: ACCESS_TOKEN }),
    ],
    [
      'a fractional expiry',
      JSON.stringify({ token_type: 'Bearer', expires_in: 1.5, access_token: ACCESS_TOKEN }),
    ],
    ['an infinite expiry', `{"token_type":"Bearer","expires_in":1e400,"access_token":"x"}`],
  ])('answers a 200 with %s as a token endpoint failure, not a crash', async (_, body) => {
    answer = { status: 200, body };
    const err = await failure(entraToken(SECRET_CREDENTIAL, options()));
    expect(err).toMatchObject({ kind: 'auth', reason: 'token_endpoint', status: 200 });
    expect(err.message).toBe(ENTRA_TEXT.badAnswer);
  });

  it('does not echo a malformed answer', async () => {
    answer = { status: 200, body: `{"access_token": 42, "note": "${MARKER}"}` };
    const err = await failure(entraToken(SECRET_CREDENTIAL, options()));
    expect(err.reason).toBe('token_endpoint');
    expect(written(err)).not.toContain(MARKER);
  });

  it('follows no redirect: a 302 is a refusal and nothing else is asked', async () => {
    answer = { status: 302, headers: { location: `${base}/elsewhere` }, body: '' };
    const err = await failure(entraToken(SECRET_CREDENTIAL, options()));
    expect(err).toMatchObject({ kind: 'auth', reason: 'token_endpoint', status: 302 });
    expect(seen.map((s) => s.path)).toEqual([`/${TENANT}/oauth2/v2.0/token`]);
  });

  it('answers a 429 as a rate limit with its Retry-After', async () => {
    answer = { status: 429, headers: { 'retry-after': '30' }, body: REFUSAL };
    const err = await failure(entraToken(SECRET_CREDENTIAL, options()));
    expect(err).toMatchObject({ kind: 'rate_limited', status: 429, retryAfterSeconds: 30 });
    expect(written(err)).not.toContain(MARKER);
  });

  it('answers a 5xx as transient', async () => {
    answer = { status: 503, body: REFUSAL };
    const err = await failure(entraToken(SECRET_CREDENTIAL, options()));
    expect(err).toMatchObject({ kind: 'transient', reason: 'http', status: 503 });
    expect(written(err)).not.toContain(MARKER);
  });

  it('reads at most 1 MiB of an answer', async () => {
    expect(MAX_ENTRA_RESPONSE_BYTES).toBe(1024 * 1024);
    answer = {
      status: 200,
      body: JSON.stringify({
        token_type: 'Bearer',
        expires_in: 3599,
        access_token: 'a'.repeat(MAX_ENTRA_RESPONSE_BYTES),
      }),
    };
    const err = await failure(entraToken(SECRET_CREDENTIAL, options()));
    expect(err).toMatchObject({ kind: 'auth', reason: 'token_endpoint' });
  });

  it('answers a hanging endpoint as a transient timeout', async () => {
    answer = 'hang';
    const err = await failure(entraToken(SECRET_CREDENTIAL, options({ timeoutMs: 300 })));
    expect(err).toMatchObject({ kind: 'transient', reason: 'timeout', status: null });
  });

  it('answers a closed port as transient and unreachable', async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise((resolve) => closed.close(resolve));
    const err = await failure(
      entraToken(
        SECRET_CREDENTIAL,
        options({ tokenUrl: (tenant) => `https://127.0.0.1:${port}/${tenant}/oauth2/v2.0/token` }),
      ),
    );
    expect(err).toMatchObject({ kind: 'transient', reason: 'unreachable', status: null });
  });

  it('refuses a non-public address unless internal hosts are allowed (only tests allow them)', async () => {
    const err = await failure(
      entraToken(SECRET_CREDENTIAL, { tokenUrl: tokenUrlOf, now: () => NOW }),
    );
    expect(err).toMatchObject({ kind: 'refused', reason: 'not_public', status: null });
    expect(seen).toEqual([]);
  });

  it('asks login.microsoftonline.com by default, and checks its addresses', async () => {
    expect(entraTokenUrl(TENANT)).toBe(
      `https://login.microsoftonline.com/${TENANT}/oauth2/v2.0/token`,
    );
    const asked: string[] = [];
    const err = await failure(
      entraToken(SECRET_CREDENTIAL, {
        resolve: async (host) => {
          asked.push(host);
          return [{ address: '10.0.0.7', family: 4 }];
        },
      }),
    );
    expect(asked).toEqual(['login.microsoftonline.com']);
    expect(err).toMatchObject({ kind: 'refused', reason: 'not_public' });
  });

  it('refuses a tenant id that is not a GUID before any request', async () => {
    for (const tenantId of ['common', '../x', `${TENANT}/x`, '']) {
      const err = await failure(entraToken({ ...SECRET_CREDENTIAL, tenantId }, options()));
      expect(err).toMatchObject({ kind: 'refused', reason: 'invalid_input' });
    }
    expect(seen).toEqual([]);
  });
});

describe('entraCacheKey', () => {
  const key = entraCacheKey('connection-1', SECRET_CREDENTIAL);

  it('is the same for the same connection and credential', () => {
    expect(entraCacheKey('connection-1', { ...SECRET_CREDENTIAL })).toBe(key);
    expect(entraCacheKey('connection-1', CERTIFICATE_CREDENTIAL)).toBe(
      entraCacheKey('connection-1', { ...CERTIFICATE_CREDENTIAL }),
    );
  });

  it('changes with the connection, the ids, the secret or the certificate', () => {
    const others = [
      entraCacheKey('connection-2', SECRET_CREDENTIAL),
      entraCacheKey('connection-1', { ...SECRET_CREDENTIAL, secret: `${SECRET}2` }),
      entraCacheKey('connection-1', { ...SECRET_CREDENTIAL, clientId: TENANT }),
      entraCacheKey('connection-1', { ...SECRET_CREDENTIAL, tenantId: CLIENT }),
      entraCacheKey('connection-1', CERTIFICATE_CREDENTIAL),
      entraCacheKey('connection-1', {
        ...CERTIFICATE_CREDENTIAL,
        certificate: certificateOf(TEST_SP),
      }),
    ];
    expect(new Set([key, ...others]).size).toBe(others.length + 1);
  });

  it('holds no secret', () => {
    expect(key).not.toContain(SECRET);
    expect(key.startsWith('connection-1|')).toBe(true);
  });
});
