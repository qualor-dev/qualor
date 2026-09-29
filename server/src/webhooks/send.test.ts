import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createTcpServer, type AddressInfo, type Socket } from 'node:net';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  CONNECT_TIMEOUT_MS,
  excerptOf,
  MAX_EXCERPT_BYTES,
  pinnedLookup,
  sendWebhook,
  type SendOptions,
} from './send';

interface Received {
  headers: IncomingMessage['headers'];
  body: string;
  url: string | undefined;
}

describe('sendWebhook (ruling W3)', () => {
  let server: Server;
  let port: number;
  let received: Received[];
  let respond: (req: IncomingMessage, res: ServerResponse) => void;
  const open = { allowInternalHosts: true, timeoutMs: 2_000 };
  const post = (url: string, options: SendOptions = open) =>
    sendWebhook({ url, body: '{"a":1}', headers: { 'content-type': 'application/json' } }, options);

  beforeAll(async () => {
    server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        received.push({
          headers: req.headers,
          body: Buffer.concat(chunks).toString(),
          url: req.url,
        });
        respond(req, res);
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });
  beforeEach(() => {
    received = [];
    respond = (_req, res) => res.writeHead(200).end('thanks');
  });

  it('POSTs the body and headers and reports a 2xx as success', async () => {
    const outcome = await post(`http://127.0.0.1:${port}/hook?x=1`);
    expect(outcome).toEqual({ ok: true, status: 200, excerpt: 'thanks' });
    expect(received).toEqual([expect.objectContaining({ body: '{"a":1}', url: '/hook?x=1' })]);
    expect(received[0]!.headers['content-length']).toBe('7');
  });

  it('refuses a non-public address before connecting, unless internal hosts are allowed', async () => {
    const strict = { ...open, allowInternalHosts: false };
    const outcome = await post(`http://127.0.0.1:${port}/hook`, strict);
    expect(outcome).toMatchObject({ ok: false, status: null });
    expect(outcome.excerpt).toMatch(/non-public/);
    // Every resolved address is checked, not only the first.
    const mixed = await sendWebhook(
      { url: `http://hooks.test:${port}/`, body: '{}', headers: {} },
      {
        ...strict,
        resolve: async () => [
          { address: '93.184.215.14', family: 4 },
          { address: '10.0.0.7', family: 4 },
        ],
      },
    );
    expect(mixed.excerpt).toMatch(/non-public/);
    expect(received).toEqual([]);
  });

  it('connects to the address it resolved and checked (pinned), with the original Host', async () => {
    let lookups = 0;
    const outcome = await sendWebhook(
      { url: `http://hooks.test:${port}/pinned`, body: '{}', headers: {} },
      {
        ...open,
        resolve: async () => {
          lookups += 1;
          return [{ address: '127.0.0.1', family: 4 }];
        },
      },
    );
    expect(outcome.ok).toBe(true);
    expect(lookups).toBe(1);
    expect(received[0]!.headers.host).toBe(`hooks.test:${port}`);
  });

  it('reports a failed lookup without throwing', async () => {
    const outcome = await sendWebhook(
      { url: 'https://nowhere.test/', body: '{}', headers: {} },
      {
        ...open,
        resolve: async () => {
          throw new Error('ENOTFOUND');
        },
      },
    );
    expect(outcome).toEqual({
      ok: false,
      status: null,
      excerpt: 'The webhook host could not be resolved',
    });
  });

  it('does not follow redirects: a 3xx is a failure', async () => {
    respond = (_req, res) => res.writeHead(302, { location: 'http://169.254.169.254/' }).end();
    const outcome = await post(`http://127.0.0.1:${port}/moved`);
    expect(outcome).toEqual({ ok: false, status: 302, excerpt: null });
    expect(received).toHaveLength(1);
  });

  it('gives up at the deadline when the receiver never answers', async () => {
    respond = () => undefined;
    const started = Date.now();
    const outcome = await post(`http://127.0.0.1:${port}/slow`, { ...open, timeoutMs: 300 });
    expect(outcome).toMatchObject({ ok: false, status: null });
    expect(outcome.excerpt).toMatch(/^No response within/);
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it('reads at most 1 KiB of a huge response, then closes it', async () => {
    respond = (_req, res) => {
      res.writeHead(500);
      const chunk = Buffer.alloc(64 * 1024, 'x');
      for (let i = 0; i < 80; i++) res.write(chunk);
      res.end();
    };
    const outcome = await post(`http://127.0.0.1:${port}/huge`);
    expect(outcome.status).toBe(500);
    expect(outcome.ok).toBe(false);
    expect(Buffer.byteLength(outcome.excerpt!, 'utf8')).toBe(MAX_EXCERPT_BYTES);
  });

  it('cuts an excerpt to 1 KiB of valid UTF-8 without NUL', () => {
    expect(excerptOf(Buffer.alloc(0))).toBeNull();
    expect(excerptOf(Buffer.from('a\u0000b'))).toBe('ab');
    // C0 controls other than tab and line feed are stripped (terminal escapes, bells, CR).
    expect(excerptOf(Buffer.from('a\u001b[31mred\u0007\r\n\tb\u007f'))).toBe('a[31mred\n\tb\u007f');
    expect(excerptOf(Buffer.from('\u0001\u0002'))).toBeNull();
    const euros = excerptOf(Buffer.from('€'.repeat(1_000)))!;
    expect(Buffer.byteLength(euros, 'utf8')).toBeLessThanOrEqual(MAX_EXCERPT_BYTES);
    expect(euros).not.toContain('�');
    const shifted = excerptOf(Buffer.from(`x${'€'.repeat(1_000)}`))!;
    expect(Buffer.byteLength(shifted, 'utf8')).toBeLessThanOrEqual(MAX_EXCERPT_BYTES);
  });
  it('refuses every resolved address form that is not public: mapped, NAT64, zone ids, garbage', async () => {
    const strict = { ...open, allowInternalHosts: false };
    for (const address of [
      '::ffff:10.0.0.7',
      '64:ff9b::a9fe:a9fe',
      'fe80::1%eth0',
      '::1',
      'nonsense',
    ]) {
      const outcome = await sendWebhook(
        { url: `http://hooks.test:${port}/`, body: '{}', headers: {} },
        { ...strict, resolve: async () => [{ address, family: address.includes(':') ? 6 : 4 }] },
      );
      expect(outcome.ok, address).toBe(false);
      expect(outcome.excerpt, address).toMatch(/non-public|could not be resolved/);
    }
    // Literal hosts are judged without any lookup.
    let lookups = 0;
    const literal = await sendWebhook(
      { url: `http://[::ffff:127.0.0.1]:${port}/`, body: '{}', headers: {} },
      {
        ...strict,
        resolve: async () => {
          lookups += 1;
          return [{ address: '93.184.215.14', family: 4 }];
        },
      },
    );
    expect(literal.excerpt).toMatch(/non-public/);
    expect(lookups).toBe(0);
    expect(received).toEqual([]);
  });

  it('counts a lookup that never answers against the same deadline, as an unresolved host', async () => {
    const started = Date.now();
    const outcome = await sendWebhook(
      { url: 'https://slow-dns.test/', body: '{}', headers: {} },
      { ...open, timeoutMs: 300, resolve: () => new Promise(() => undefined) },
    );
    expect(outcome).toMatchObject({ ok: false, status: null });
    expect(outcome.excerpt).toBe('The webhook host could not be resolved within 300 ms');
    expect(Date.now() - started).toBeLessThan(2_000);
  });

  it('keeps the status when the body stalls past the deadline', async () => {
    respond = (_req, res) => {
      res.writeHead(202);
      res.write('partial');
    };
    const outcome = await post(`http://127.0.0.1:${port}/stall`, { ...open, timeoutMs: 300 });
    expect(outcome).toEqual({ ok: true, status: 202, excerpt: 'partial' });
  });

  it('reports a refused connection with its error code only', async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const closedPort = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const outcome = await post(`http://127.0.0.1:${closedPort}/`);
    expect(outcome).toEqual({
      ok: false,
      status: null,
      excerpt: 'The connection to the webhook failed (ECONNREFUSED)',
    });
  });

  it('ignores proxy environment variables', async () => {
    const saved = { http: process.env.HTTP_PROXY, https: process.env.HTTPS_PROXY };
    process.env.HTTP_PROXY = 'http://127.0.0.1:9';
    process.env.HTTPS_PROXY = 'http://127.0.0.1:9';
    try {
      expect((await post(`http://127.0.0.1:${port}/direct`)).ok).toBe(true);
      expect(received.map((r) => r.url)).toEqual(['/direct']);
    } finally {
      if (saved.http === undefined) delete process.env.HTTP_PROXY;
      else process.env.HTTP_PROXY = saved.http;
      if (saved.https === undefined) delete process.env.HTTPS_PROXY;
      else process.env.HTTPS_PROXY = saved.https;
    }
  });

  it('opens a fresh connection per request (agent: false)', async () => {
    const sockets = new Set<unknown>();
    const previous = respond;
    respond = (req, res) => {
      sockets.add(req.socket);
      previous(req, res);
    };
    await post(`http://127.0.0.1:${port}/one`);
    await post(`http://127.0.0.1:${port}/two`);
    expect(sockets.size).toBe(2);
  });

  it('gives up when no connection is established within the connect timeout (X7)', async () => {
    // A TCP server that accepts and never speaks: an https handshake to it never completes.
    const sockets: Socket[] = [];
    const blackhole = createTcpServer((socket) => void sockets.push(socket));
    await new Promise<void>((resolve) => blackhole.listen(0, '127.0.0.1', resolve));
    const blackholePort = (blackhole.address() as AddressInfo).port;
    try {
      const outcome = await post(`https://127.0.0.1:${blackholePort}/`, {
        ...open,
        timeoutMs: 30_000,
        connectTimeoutMs: 200,
      });
      // The connect timeout decided, not the 30 s deadline (the test would time out first).
      expect(outcome).toEqual({ ok: false, status: null, excerpt: 'No connection within 200 ms' });
      expect(sockets).toHaveLength(1);
      // A lookup that never answers counts against the connect timeout too, as a host that does
      // not resolve.
      const dns = await sendWebhook(
        { url: 'https://slow-dns.test/', body: '{}', headers: {} },
        {
          ...open,
          timeoutMs: 30_000,
          connectTimeoutMs: 200,
          resolve: () => new Promise(() => undefined),
        },
      );
      expect(dns.excerpt).toBe('The webhook host could not be resolved within 200 ms');
    } finally {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => blackhole.close(() => resolve()));
    }
    expect(CONNECT_TIMEOUT_MS).toBe(3_000);
  });

  it('keeps the connect timeout for the connection only: a slow answer on an open one still counts', async () => {
    let release: (() => void) | undefined;
    const answered = new Promise<void>((resolve) => {
      release = resolve;
    });
    respond = (_req, res) => {
      // Answers only after the connect timeout would have fired, had it not been cleared.
      setTimeout(() => {
        res.writeHead(200).end('late');
        release?.();
      }, 150);
    };
    const outcome = await post(`http://127.0.0.1:${port}/late`, {
      ...open,
      connectTimeoutMs: 50,
    });
    await answered;
    expect(outcome).toEqual({ ok: true, status: 200, excerpt: 'late' });
  });

  it('reports a request that throws synchronously instead of throwing', async () => {
    const outcome = await sendWebhook(
      { url: `http://127.0.0.1:${port}/`, body: '{}', headers: { 'x-bad': 'a\nb' } },
      open,
    );
    expect(outcome).toMatchObject({ ok: false, status: null });
    expect(outcome.excerpt).toMatch(/^The request to the webhook could not be made/);
    expect(received).toEqual([]);
  });

  it('pins every lookup to the checked addresses, all of them when asked for all', () => {
    const lookup = pinnedLookup([
      { address: '93.184.215.14', family: 4 },
      { address: '2606:2800:21f:cb07:6820:80da:af6b:8b2c', family: 6 },
    ]);
    const all: unknown[] = [];
    lookup('example.test', { all: true }, (...args: unknown[]) => void all.push(args));
    expect(all).toEqual([
      [
        null,
        [
          { address: '93.184.215.14', family: 4 },
          { address: '2606:2800:21f:cb07:6820:80da:af6b:8b2c', family: 6 },
        ],
      ],
    ]);
    const one: unknown[] = [];
    lookup('example.test', {}, (...args: unknown[]) => void one.push(args));
    expect(one).toEqual([[null, '93.184.215.14', 4]]);
  });
});
