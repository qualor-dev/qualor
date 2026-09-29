import { createServer, type Server } from 'node:http';
import { createServer as createHttpsServer } from 'node:https';
import { createServer as createTcpServer } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { TEST_SP } from '../../test/saml';
import { createSsoFetch, isTlsErrorCode, SsoFetchRefused, ssoFetchRefusal } from './fetch';

let server: Server;
let base: string;
beforeAll(async () => {
  server = createServer((req, res) => {
    if (req.url === '/redirect') {
      res.writeHead(302, { location: '/x' });
      res.end();
      return;
    }
    if (req.url === '/big') {
      res.end('x'.repeat(600 * 1024));
      return;
    }
    if (req.url === '/slow') {
      setTimeout(() => res.end('late'), 1_500).unref();
      return;
    }
    res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify({ ok: true, method: req.method }));
  });
  await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
  base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterAll(() => new Promise<void>((r) => server.close(() => r())));

const listed = () => new Set([new URL(base).host]);
const opts = (method = 'GET') => ({
  method,
  headers: {},
  body: undefined,
  redirect: 'manual' as const,
});

describe('ssoFetch (sso-scim.md §14)', () => {
  it('answers an allowed URL on a listed internal host', async () => {
    const f = createSsoFetch({ internalHosts: listed(), allowed: new Set([`${base}/ok`]) });
    const res = await f(`${base}/ok`, opts());
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ ok: true, method: 'GET' });
  });

  it('refuses a URL discovery did not name, before any request', async () => {
    const f = createSsoFetch({ internalHosts: listed(), allowed: new Set([`${base}/ok`]) });
    await expect(f(`${base}/other`, opts())).rejects.toBeInstanceOf(SsoFetchRefused);
  });

  it('refuses the internal host when it is not listed', async () => {
    const f = createSsoFetch({ internalHosts: new Set(), allowed: new Set([`${base}/ok`]) });
    await expect(f(`${base}/ok`, opts())).rejects.toMatchObject({ reason: 'not_public' });
  });

  it('does not follow a redirect: the 302 is the answer', async () => {
    const f = createSsoFetch({ internalHosts: listed(), allowed: new Set([`${base}/redirect`]) });
    expect((await f(`${base}/redirect`, opts())).status).toBe(302);
  });

  it('refuses a body over the limit', async () => {
    const f = createSsoFetch({ internalHosts: listed(), allowed: new Set([`${base}/big`]) });
    await expect(f(`${base}/big`, opts())).rejects.toMatchObject({ reason: 'too_large' });
  });

  it('refuses methods other than GET and POST', async () => {
    const f = createSsoFetch({ internalHosts: listed(), allowed: new Set([`${base}/ok`]) });
    await expect(f(`${base}/ok`, opts('DELETE'))).rejects.toMatchObject({ reason: 'method' });
  });

  it('refuses a link-local address even when listed', async () => {
    const f = createSsoFetch({
      internalHosts: new Set(['169.254.169.254']),
      allowed: new Set(['http://169.254.169.254/latest']),
    });
    await expect(f('http://169.254.169.254/latest', opts())).rejects.toBeInstanceOf(
      SsoFetchRefused,
    );
  });

  it('refuses plain http to a host that is not listed, before any lookup', async () => {
    let looked = 0;
    const f = createSsoFetch({
      internalHosts: new Set(),
      allowed: new Set(['http://idp.example/token']),
      resolve: () => {
        looked += 1;
        return Promise.resolve([{ address: '93.184.216.34', family: 4 }]);
      },
    });
    await expect(f('http://idp.example/token', opts('POST'))).rejects.toMatchObject({
      reason: 'not_public',
    });
    expect(looked).toBe(0);
  });

  it('refuses an https name that resolves to a private address when it is not listed', async () => {
    const f = createSsoFetch({
      internalHosts: new Set(),
      allowed: new Set(['https://idp.example/jwks']),
      resolve: () => Promise.resolve([{ address: '10.0.0.5', family: 4 }]),
    });
    await expect(f('https://idp.example/jwks', opts())).rejects.toMatchObject({
      reason: 'not_public',
    });
  });

  it('matches allowed URLs without their query, and allow() adds one', async () => {
    const f = createSsoFetch({ internalHosts: listed(), allowed: new Set() });
    await expect(f(`${base}/ok?x=1`, opts())).rejects.toMatchObject({ reason: 'not_allowed' });
    f.allow(`${base}/ok?y=2`);
    const res = await f(`${base}/ok?x=1`, opts('POST'));
    expect(await res.json()).toEqual({ ok: true, method: 'POST' });
  });

  it('normalises the initial allowed entries as it normalises lookups', async () => {
    const f = createSsoFetch({ internalHosts: listed(), allowed: new Set([`${base}/ok?x=1#f`]) });
    expect((await f(`${base}/ok`, opts())).status).toBe(200);
  });

  it('gives up when openid-client aborts, without waiting for the answer', async () => {
    const f = createSsoFetch({ internalHosts: listed(), allowed: new Set([`${base}/slow`]) });
    const controller = new AbortController();
    setTimeout(() => controller.abort(), 50);
    const started = Date.now();
    await expect(f(`${base}/slow`, { ...opts(), signal: controller.signal })).rejects.toMatchObject(
      { reason: 'timeout' },
    );
    expect(Date.now() - started).toBeLessThan(1_000);
  });

  it('refuses a status a Response cannot carry, instead of throwing a RangeError', async () => {
    const odd = createTcpServer((socket) => {
      socket.on('data', () => {
        socket.end('HTTP/1.1 999 Odd\r\ncontent-length: 0\r\nconnection: close\r\n\r\n');
      });
    });
    await new Promise<void>((r) => odd.listen(0, '127.0.0.1', r));
    const port = (odd.address() as { port: number }).port;
    try {
      const f = createSsoFetch({
        internalHosts: new Set([`127.0.0.1:${port}`]),
        allowed: new Set([`http://127.0.0.1:${port}/x`]),
      });
      const failure = await f(`http://127.0.0.1:${port}/x`, opts()).catch((e: unknown) => e);
      expect(failure).toBeInstanceOf(SsoFetchRefused);
      // The status is kept for the log.
      expect(failure).toMatchObject({ reason: 'status', status: 999 });
    } finally {
      await new Promise<void>((r) => odd.close(() => r()));
    }
  });

  it('says tls, with the system code, when the certificate is not trusted', async () => {
    // A self-signed certificate for another name: never trusted, whatever the host is called.
    const tls = createHttpsServer({ key: TEST_SP.keyPem, cert: TEST_SP.certPem }, (_req, res) => {
      res.end('{}');
    });
    await new Promise<void>((r) => tls.listen(0, '127.0.0.1', r));
    const port = (tls.address() as { port: number }).port;
    try {
      const url = `https://127.0.0.1:${port}/x`;
      const f = createSsoFetch({
        internalHosts: new Set([`127.0.0.1:${port}`]),
        allowed: new Set([url]),
      });
      const failure = await f(url, opts()).catch((e: unknown) => e);
      expect(failure).toMatchObject({ reason: 'tls', status: null });
      expect(isTlsErrorCode((failure as SsoFetchRefused).code)).toBe(true);
    } finally {
      await new Promise<void>((r) => tls.close(() => r()));
    }
  });

  it('finds a refusal however deep a library wrapped it', () => {
    const refused = new SsoFetchRefused('unresolved', 'ENOTFOUND');
    const wrapped = new Error('outer', { cause: new Error('inner', { cause: refused }) });
    expect(ssoFetchRefusal(wrapped)).toBe(refused);
    expect(ssoFetchRefusal(new Error('other'))).toBeNull();
    expect(isTlsErrorCode('ECONNREFUSED')).toBe(false);
    expect(isTlsErrorCode(null)).toBe(false);
  });
});
