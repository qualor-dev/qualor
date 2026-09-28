import net from 'node:net';
import { Readable } from 'node:stream';
import { afterEach, describe, expect, it } from 'vitest';
import { json, useTestServers } from '../../test/http';
import { startConnectProxy, type ConnectProxy } from '../../test/proxy';
import { CliError } from '../errors';
import { request, type ServerEndpoint } from './http';
import { noProxyMatches, proxyFor, RawHttpError } from './raw-http';

const serve = useTestServers();
const TOKEN = 'qlr_prj_raw_http_token';

const proxies: ConnectProxy[] = [];
const rawServers: net.Server[] = [];
afterEach(() => {
  for (const p of proxies.splice(0)) p.close();
  for (const s of rawServers.splice(0)) s.close();
});
async function proxy(o: Parameters<typeof startConnectProxy>[0] = {}): Promise<ConnectProxy> {
  const p = await startConnectProxy(o);
  proxies.push(p);
  return p;
}

/** A raw server: `answer(socket)` runs once the request head has arrived. */
async function rawServer(answer: (socket: net.Socket) => void): Promise<string> {
  const server = net.createServer((socket) => {
    let text = '';
    let answered = false;
    socket.on('error', () => undefined);
    socket.on('data', (d: Buffer) => {
      text += d.toString('latin1');
      if (!answered && text.includes('\r\n\r\n')) {
        answered = true;
        answer(socket);
      }
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  rawServers.push(server);
  return `http://127.0.0.1:${(server.address() as net.AddressInfo).port}`;
}

const upload = (ep: ServerEndpoint) =>
  request(ep, {
    method: 'POST',
    path: 'api/v0/analyses',
    body: { stream: () => Readable.from([Buffer.from('hello')]), contentLength: 5 },
  });

async function failure(p: Promise<unknown>, ...secrets: string[]): Promise<CliError> {
  const err: unknown = await p.catch((e: unknown) => e);
  if (!(err instanceof CliError)) throw new Error(`expected a CliError, got ${String(err)}`);
  expect(err.exitCode).toBe(4);
  for (const s of [TOKEN, ...secrets]) expect(err.message).not.toContain(s);
  return err;
}

describe('proxyFor and NO_PROXY (ruling V9)', () => {
  const https = new URL('https://qualor.acme.test/x');
  const http = new URL('http://qualor.acme.test:8080/x');

  it('picks https_proxy/HTTPS_PROXY for https (then http_proxy), http_proxy for http', () => {
    expect(proxyFor(https, {})).toBeNull();
    expect(proxyFor(https, { HTTPS_PROXY: 'http://p1:3128' })?.host).toBe('p1:3128');
    expect(proxyFor(https, { https_proxy: 'http://low:1', HTTPS_PROXY: 'http://up:2' })?.host).toBe(
      'low:1',
    );
    expect(proxyFor(https, { HTTP_PROXY: 'http://p2:3128' })?.host).toBe('p2:3128');
    expect(proxyFor(http, { HTTPS_PROXY: 'http://p1:3128' })).toBeNull();
    expect(proxyFor(http, { http_proxy: 'p3:3128' })?.href).toBe('http://p3:3128/');
    expect(proxyFor(http, { HTTP_PROXY: '  ' })).toBeNull();
  });

  it('refuses a proxy that is not http:// or not a URL, without showing it', () => {
    expect(() => proxyFor(https, { HTTPS_PROXY: 'https://u:secretpw@p:1' })).toThrow(
      /HTTPS_PROXY must be an http:\/\/ proxy/,
    );
    expect(() => proxyFor(https, { HTTPS_PROXY: 'socks5://p:1' })).toThrow(RawHttpError);
    let message = '';
    try {
      proxyFor(https, { HTTPS_PROXY: 'http://u:secretpw@[bad' });
    } catch (e) {
      message = (e as Error).message;
    }
    expect(message).toContain('HTTPS_PROXY is not a valid URL');
    expect(message).not.toContain('secretpw');
  });

  it.each([
    ['*', true],
    ['qualor.acme.test', true],
    ['acme.test', true],
    ['.acme.test', true],
    ['*.acme.test', true],
    ['QUALOR.ACME.TEST', true],
    ['other.test, acme.test', true],
    ['other.test acme.test', true],
    ['qualor.acme.test:443', true],
    ['qualor.acme.test:8443', false],
    ['cme.test', false],
    ['qualor.acme.test.evil', false],
    ['', false],
  ])('NO_PROXY=%j exempts https://qualor.acme.test: %s', (value, expected) => {
    expect(noProxyMatches(https, value)).toBe(expected);
    expect(proxyFor(https, { HTTPS_PROXY: 'http://p:1', NO_PROXY: value }) === null).toBe(expected);
  });

  it('matches IP addresses and bracketed IPv6 entries', () => {
    expect(noProxyMatches(new URL('http://127.0.0.1:9/'), '127.0.0.1')).toBe(true);
    expect(noProxyMatches(new URL('http://127.0.0.1:9/'), '127.0.0.1:9')).toBe(true);
    expect(noProxyMatches(new URL('http://127.0.0.2:9/'), '127.0.0.1')).toBe(false);
    expect(noProxyMatches(new URL('http://[::1]:9/'), '[::1]:9')).toBe(true);
    expect(noProxyMatches(new URL('http://[::1]:9/'), '[::1]')).toBe(true);
  });
});

describe('the upload through a CONNECT proxy (ruling V9)', () => {
  it('tunnels to the origin by name, for http too, and never sends the token to the proxy', async () => {
    const origin = await serve((_req, res) => json(res, 202, { ok: true }));
    const p = await proxy();
    const port = new URL(origin.url).port;
    // The name does not resolve: only the proxy can reach it (it maps every tunnel to 127.0.0.1).
    const res = await upload({
      url: `http://upload.invalid:${port}`,
      token: TOKEN,
      timeoutMs: 5_000,
      env: { HTTP_PROXY: p.url },
    });
    expect(res.status).toBe(202);
    expect(p.heads).toHaveLength(1);
    expect(p.heads[0]?.split('\r\n')[0]).toBe(`CONNECT upload.invalid:${port} HTTP/1.1`);
    expect(p.heads[0]).not.toContain(TOKEN);
    expect(p.heads[0]?.toLowerCase()).not.toMatch(/^authorization:/m);
    // `Expect` went end to end: the origin itself saw it.
    expect(origin.requests[0]?.headers).toMatchObject({
      expect: '100-continue',
      authorization: `Bearer ${TOKEN}`,
    });
    expect(origin.requests[0]?.body.toString()).toBe('hello');
  });

  it('sends the proxy URL credentials as Proxy-Authorization, and 407 fails without them', async () => {
    const origin = await serve((_req, res) => json(res, 202, { ok: true }));
    const port = new URL(origin.url).port;
    const p = await proxy({ credentials: 'alice:p@ss:w0rd' });
    const ok = await upload({
      url: `http://upload.invalid:${port}`,
      token: TOKEN,
      timeoutMs: 5_000,
      env: { HTTP_PROXY: p.url },
    });
    expect(ok.status).toBe(202);
    const wrong = new URL(p.url);
    wrong.password = 'nope-secret';
    const err = await failure(
      upload({
        url: `http://upload.invalid:${port}`,
        token: TOKEN,
        timeoutMs: 5_000,
        env: { HTTP_PROXY: wrong.href },
      }),
      'nope-secret',
      'alice',
      'p@ss',
      'p%40ss',
    );
    expect(err.message).toContain('the proxy requires authentication (407)');
    expect(origin.requests).toHaveLength(1);
  });

  it('goes direct when NO_PROXY names the origin (a trailing dot included)', async () => {
    const p = await proxy();
    for (const noProxy of ['upload.invalid', 'upload.invalid.', '.invalid']) {
      // Direct, the name does not resolve: the failure proves the proxy was skipped.
      await failure(
        upload({
          url: 'http://upload.invalid.:9',
          token: TOKEN,
          timeoutMs: 5_000,
          env: { HTTP_PROXY: p.url, NO_PROXY: noProxy },
        }),
      );
    }
    expect(p.connections()).toBe(0);
  });

  it('never proxies a loopback origin (localhost, 127.0.0.0/8, ::1), as Go does', async () => {
    const origin = await serve((_req, res) => json(res, 202, { ok: true }));
    const p = await proxy();
    const res = await upload({
      url: origin.url,
      token: TOKEN,
      timeoutMs: 5_000,
      env: { HTTP_PROXY: p.url },
    });
    expect(res.status).toBe(202);
    expect(p.connections()).toBe(0);
    for (const url of [
      'http://localhost/',
      'http://127.1.2.3/',
      'http://[::1]/',
      'http://localhost./',
    ]) {
      expect(proxyFor(new URL(url), { HTTP_PROXY: p.url }), url).toBeNull();
    }
    expect(proxyFor(new URL('http://128.0.0.1/'), { HTTP_PROXY: p.url })).not.toBeNull();
  });

  it('skips 1xx answers before the tunnel, and refuses a bare-LF answer clearly', async () => {
    const origin = await serve((_req, res) => json(res, 202, { ok: true }));
    const port = new URL(origin.url).port;
    // A proxy that says 100 before its 200, then relays to the origin.
    const early = net.createServer((client) => {
      client.on('error', () => undefined);
      client.once('data', () => {
        const upstream = net.connect({ host: '127.0.0.1', port: Number(port) }, () => {
          client.write('HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\n\r\n');
          client.pipe(upstream);
          upstream.pipe(client);
        });
        upstream.on('error', () => client.destroy());
      });
    });
    await new Promise<void>((resolve) => early.listen(0, '127.0.0.1', resolve));
    rawServers.push(early);
    const via = `http://127.0.0.1:${(early.address() as net.AddressInfo).port}`;
    const res = await upload({
      url: `http://upload.invalid:${port}`,
      token: TOKEN,
      timeoutMs: 5_000,
      env: { HTTP_PROXY: via },
    });
    expect(res.status).toBe(202);
    const bareLf = await rawServer((s) => s.write('HTTP/1.1 200 OK\n\n'));
    const err = await failure(
      upload({
        url: 'http://upload.invalid:9',
        token: TOKEN,
        timeoutMs: 2_000,
        env: { HTTP_PROXY: bareLf },
      }),
    );
    expect(err.message).toContain('bare LF');
  });

  it.each(['never', 'trickle'] as const)(
    'fails in bounded time when the proxy %s answers the CONNECT',
    async (answer) => {
      const p = await proxy({ answer });
      const started = Date.now();
      const err = await failure(
        upload({
          url: 'http://upload.invalid:9',
          token: TOKEN,
          timeoutMs: 1_000,
          env: { HTTP_PROXY: p.url },
        }),
      );
      expect(err.message).toContain('the proxy did not open a tunnel within 1 s');
      expect(Date.now() - started).toBeLessThan(4_000);
    },
  );

  it('fails with exit 4 when the proxy is down, or refuses the tunnel', async () => {
    const down = await failure(
      upload({
        url: 'http://upload.invalid:9',
        token: TOKEN,
        timeoutMs: 2_000,
        env: { HTTP_PROXY: 'http://127.0.0.1:9' },
      }),
    );
    expect(down.message).toMatch(/proxy: (ECONNREFUSED|the connection closed)/);
    const refusing = await rawServer((s) =>
      s.end('HTTP/1.1 403 Forbidden\r\ncontent-length: 0\r\n\r\n'),
    );
    const refused = await failure(
      upload({
        url: 'http://upload.invalid:9',
        token: TOKEN,
        timeoutMs: 2_000,
        env: { HTTP_PROXY: refusing },
      }),
    );
    expect(refused.message).toContain('the proxy refused the tunnel (403)');
  });
});

describe('the answer is bounded (fix round 1)', () => {
  const ep = (url: string, timeoutMs = 1_000): ServerEndpoint => ({
    url,
    token: TOKEN,
    timeoutMs,
    env: {},
  });

  it('fails a flood of informational (1xx) answers', async () => {
    const url = await rawServer((s) => {
      const t = setInterval(() => {
        if (s.destroyed) clearInterval(t);
        else s.write(`HTTP/1.1 103 Early Hints\r\nlink: ${'x'.repeat(1_000)}\r\n\r\n`);
      }, 20);
    });
    const err = await failure(upload(ep(url, 5_000)));
    expect(err.message).toContain('too many informational (1xx) answers');
  });

  it('counts chunk lines and extensions toward the response bound', async () => {
    const url = await rawServer((s) => {
      s.write('HTTP/1.1 401 X\r\ntransfer-encoding: chunked\r\n\r\n');
      const piece = `1;${'e'.repeat(1_000)}\r\nx\r\n`;
      const t = setInterval(() => {
        if (s.destroyed) clearInterval(t);
        else s.write(piece.repeat(20));
      }, 20);
    });
    const started = Date.now();
    const err = await failure(
      request(ep(url, 5_000), {
        method: 'POST',
        path: 'x',
        body: { stream: () => Readable.from([Buffer.from('hello')]), contentLength: 5 },
        maxResponseBytes: 4_096,
      }),
    );
    expect(err.message).toContain('larger than 4096 bytes');
    expect(Date.now() - started).toBeLessThan(4_000);
  });

  it('fails an answer that trickles after its head, within the timeout', async () => {
    const url = await rawServer((s) => {
      s.write('HTTP/1.1 401 X\r\ncontent-length: 1000\r\n\r\n');
      const t = setInterval(() => (s.destroyed ? clearInterval(t) : s.write('a')), 300);
    });
    const started = Date.now();
    const err = await failure(upload(ep(url)));
    expect(err.message).toContain('no complete response within 1 s');
    expect(Date.now() - started).toBeLessThan(3_000);
  });

  it('fails a head that never ends once the body has been handed over', async () => {
    const url = await rawServer((s) => {
      s.write('HTTP/1.1 401 X\r\n');
      const t = setInterval(() => (s.destroyed ? clearInterval(t) : s.write('x-a: b\r\n')), 20);
    });
    const started = Date.now();
    const err = await failure(upload(ep(url)));
    expect(err.message).toMatch(/no complete response( head)? within 1 s/);
    expect(Date.now() - started).toBeLessThan(4_000);
  });

  it.each([true, false])(
    'fails a server that stops reading the body and trickles a head (100 Continue first: %s)',
    async (continueFirst) => {
      const url = await rawServer((s) => {
        s.pause(); // never reads the body
        if (continueFirst) s.write('HTTP/1.1 100 Continue\r\n\r\n');
        const head = `HTTP/1.1 401 X\r\nx-pad: ${'a'.repeat(60_000)}`;
        let i = 0;
        const t = setInterval(
          () => (s.destroyed ? clearInterval(t) : s.write(head[i++] ?? 'a')),
          300,
        );
      });
      const big = 256 * 1024 * 1024;
      const started = Date.now();
      const err = await failure(
        request(ep(url), {
          method: 'POST',
          path: 'x',
          body: {
            stream: () =>
              Readable.from(
                (function* () {
                  for (let n = 0; n < big; n += 65_536) yield Buffer.alloc(65_536);
                })(),
              ),
            contentLength: big,
          },
        }),
      );
      expect(err.message).toContain('no complete response head within 1 s');
      expect(Date.now() - started).toBeLessThan(4_000);
    },
  );

  it(
    'still lets a slow but steady reader finish (4 MiB/s, far past the timeout)',
    { timeout: 30_000 },
    async () => {
      const size = 24 * 1024 * 1024;
      const rate = 4 * 1024 * 1024;
      const server = net.createServer((s) => {
        s.on('error', () => undefined);
        let got = -1;
        const t0 = Date.now();
        s.on('data', (d: Buffer) => {
          if (got < 0) {
            got = 0;
            s.write('HTTP/1.1 100 Continue\r\n\r\n');
            return;
          }
          got += d.length;
          if (got >= size) {
            s.end('HTTP/1.1 202 Accepted\r\ncontent-length: 2\r\n\r\nok');
            return;
          }
          const wait = t0 + (got / rate) * 1000 - Date.now();
          if (wait > 0) {
            s.pause();
            setTimeout(() => s.resume(), wait);
          }
        });
      });
      await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
      rawServers.push(server);
      const started = Date.now();
      const port = (server.address() as net.AddressInfo).port;
      const res = await request(ep(`http://127.0.0.1:${port}`, 2_000), {
        method: 'POST',
        path: 'x',
        body: {
          stream: () =>
            Readable.from(
              (function* () {
                for (let n = 0; n < size; n += 65_536) yield Buffer.alloc(65_536);
              })(),
            ),
          contentLength: size,
        },
      });
      expect(res.status).toBe(202);
      expect(Date.now() - started).toBeGreaterThan(4_000);
    },
  );

  it('enforces the 64 KiB head limit also when the head arrives in one read', async () => {
    const url = await rawServer((s) =>
      s.end(`HTTP/1.1 401 X\r\nx-big: ${'a'.repeat(100 * 1024)}\r\ncontent-length: 0\r\n\r\n`),
    );
    const err = await failure(upload(ep(url, 5_000)));
    expect(err.message).toContain('the response head is too large');
  });

  it('keeps headers in a prototype-free object, trims only SP/HTAB and refuses control characters', async () => {
    const url = await rawServer((s) =>
      s.end(
        'HTTP/1.1 401 X\r\n__proto__: x\r\nconstructor: y\r\nx-ws: \t v \t\r\ncontent-length: 0\r\n\r\n',
      ),
    );
    const res = await upload(ep(url, 5_000));
    expect(Object.getPrototypeOf(res.headers)).toBeNull();
    expect(res.headers['__proto__']).toBe('x');
    expect(res.headers['constructor']).toBe('y');
    expect(res.headers['x-ws']).toBe('v');
    for (const bad of [0x00, 0x01, 0x0b, 0x7f]) {
      const nul = await rawServer((s) =>
        s.end(`HTTP/1.1 401 X\r\nx-a: a${String.fromCharCode(bad)}b\r\ncontent-length: 0\r\n\r\n`),
      );
      const err = await failure(upload(ep(nul, 5_000)));
      expect(err.message, String(bad)).toContain('invalid response header');
    }
  });

  it('treats a close-delimited answer cut by a reset as an error', async () => {
    const url = await rawServer((s) => {
      s.write('HTTP/1.1 401 X\r\n\r\npartial');
      setTimeout(() => s.resetAndDestroy(), 50);
    });
    const err = await failure(upload(ep(url, 5_000)));
    expect(err.message).toMatch(/ECONNRESET|before the response was complete/);
  });
});
