import { createServer as createHttp, type IncomingMessage, type ServerResponse } from 'node:http';
import { createServer as createHttps } from 'node:https';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { TEST_CA_PEM, TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM } from '../../cli/test/tls.js';
import { AzureClient, AzureProbeError } from './client.js';

type Handler = (req: IncomingMessage, res: ServerResponse, n: number) => void;
type Closable = {
  close: () => unknown;
  listen: (...a: never[]) => unknown;
  address: () => unknown;
};
let server: Closable | undefined;
afterEach(() => {
  server?.close();
});

async function serve(
  handler: Handler,
  tls = false,
): Promise<{ base: string; seen: IncomingMessage[] }> {
  const seen: IncomingMessage[] = [];
  const h = (req: IncomingMessage, res: ServerResponse): void => {
    seen.push(req);
    handler(req, res, seen.length);
  };
  const s = tls
    ? createHttps({ key: TEST_SERVER_KEY_PEM, cert: TEST_SERVER_CERT_PEM }, h)
    : createHttp(h);
  server?.close();
  server = s as unknown as Closable;
  await new Promise<void>((r) => s.listen(0, '127.0.0.1', r));
  const port = (s.address() as AddressInfo).port;
  return { base: `${tls ? 'https' : 'http'}://127.0.0.1:${port}`, seen };
}

const json = (res: ServerResponse, status = 200, extra: Record<string, string> = {}): void => {
  res.writeHead(status, { 'content-type': 'application/json', ...extra });
  res.end('{"ok":true}');
};

const PAT = { kind: 'pat', pat: 'abc' } as const;

describe('AzureClient', () => {
  it('sends a PAT as basic auth with an empty user', async () => {
    const { base, seen } = await serve((_q, res) => json(res));
    const r = await new AzureClient(base, PAT).request('GET', '/org/_apis/projects');
    expect(seen[0]!.headers.authorization).toBe(`Basic ${Buffer.from(':abc').toString('base64')}`);
    expect(r.status).toBe(200);
    expect(r.json).toEqual({ ok: true });
  });

  it('adds api-version=7.0 unless told otherwise', async () => {
    const { base, seen } = await serve((_q, res) => json(res));
    const c = new AzureClient(base, PAT);
    await c.request('GET', '/a?x=1');
    await c.request('GET', '/b', undefined, { apiVersion: '7.1-preview.1' });
    expect(seen[0]!.url).toBe('/a?x=1&api-version=7.0');
    expect(seen[1]!.url).toBe('/b?api-version=7.1-preview.1');
  });

  it('turns a 203 or 200 HTML answer into html_answer', async () => {
    for (const status of [200, 203]) {
      const { base } = await serve((_q, res) => {
        res.writeHead(status, { 'content-type': 'text/html; charset=utf-8' });
        res.end('<html>sign in</html>');
      });
      const err = await new AzureClient(base, PAT).request('GET', '/x').catch((e: unknown) => e);
      expect(err).toBeInstanceOf(AzureProbeError);
      expect((err as AzureProbeError).code).toBe('html_answer');
    }
  });

  it('retries a 429 once after Retry-After', async () => {
    const { base, seen } = await serve((_q, res, n) =>
      n === 1 ? json(res, 429, { 'retry-after': '1' }) : json(res),
    );
    const t0 = Date.now();
    const r = await new AzureClient(base, PAT).request('GET', '/x');
    expect(Date.now() - t0).toBeGreaterThanOrEqual(950);
    expect(seen).toHaveLength(2);
    expect(r.status).toBe(200);
  });

  it('returns a 200 with Retry-After at once and delays the next request', async () => {
    const { base, seen } = await serve((_q, res, n) =>
      n === 1 ? json(res, 200, { 'retry-after': '1' }) : json(res),
    );
    const realSetTimeout = setTimeout;
    const realWait = (ms: number) => new Promise((r) => realSetTimeout(r, ms));
    // Only the client's own waits are faked; the sockets run on real time.
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'Date'] });
    try {
      const c = new AzureClient(base, PAT);
      // No fake time passes: a wait on Retry-After here would never end.
      const first = await c.request('POST', '/x', { a: 1 });
      expect(first.status).toBe(200);
      expect(seen).toHaveLength(1);
      const second = c.request('GET', '/y');
      await vi.advanceTimersByTimeAsync(999);
      // Real time for a request sent too early to arrive (none is sent until the fake second ends).
      await realWait(100);
      expect(seen).toHaveLength(1);
      await vi.advanceTimersByTimeAsync(1);
      expect((await second).status).toBe(200);
      expect(seen).toHaveLength(2);
    } finally {
      vi.useRealTimers();
    }
  });

  it('rejects with timeout when the server never answers', async () => {
    const { base } = await serve(() => undefined);
    const err = await new AzureClient(base, PAT, { timeoutMs: 200 })
      .request('GET', '/x')
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(AzureProbeError);
    expect((err as AzureProbeError).code).toBe('timeout');
  });

  it('writes a JSON body with its content type', async () => {
    let body = '';
    const { base, seen } = await serve((q, res) => {
      q.on('data', (d) => (body += d));
      q.on('end', () => json(res));
    });
    await new AzureClient(base, PAT).request('POST', '/x', { a: 1 });
    expect(seen[0]!.headers['content-type']).toContain('application/json');
    expect(body).toBe('{"a":1}');
  });

  it('trusts a private CA given as caPem and refuses an unknown certificate without it', async () => {
    const { base } = await serve((_q, res) => json(res), true);
    const ok = await new AzureClient(base, PAT, { caPem: TEST_CA_PEM }).request('GET', '/x');
    expect(ok.status).toBe(200);
    await expect(new AzureClient(base, PAT).request('GET', '/x')).rejects.toThrow();
  });

  it('fetches a bearer token once and caches it', async () => {
    const { base, seen } = await serve((_q, res) => json(res));
    let calls = 0;
    const fetchFn = (async () => {
      calls++;
      return new Response(JSON.stringify({ access_token: 'tok', expires_in: 3599 }), {
        headers: { 'content-type': 'application/json' },
      });
    }) as unknown as typeof fetch;
    const c = new AzureClient(
      base,
      { kind: 'secret', tenantId: 't', clientId: 'c', secret: 's' },
      { fetch: fetchFn },
    );
    await c.request('GET', '/a');
    await c.request('GET', '/b');
    expect(calls).toBe(1);
    expect(seen[1]!.headers.authorization).toBe('Bearer tok');
  });
});
