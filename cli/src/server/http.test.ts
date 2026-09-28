import http from 'node:http';
import net from 'node:net';
import { Readable } from 'node:stream';
import tls from 'node:tls';
import { describe, expect, it, vi } from 'vitest';
import { json, problem, useTestServers } from '../../test/http';
import { CliError, EXIT } from '../errors';
import { httpBaselineClient } from './baseline-client';
import {
  caBundle,
  clean,
  describeFailure,
  pathSegment,
  request,
  retryAfterMs,
  type ServerEndpoint,
  targetUrl,
  UnreachableError,
} from './http';

const serve = useTestServers();
const TOKEN = 'qlr_prj_0123456789abcdef';
// Assembled at run time, so the repository's own Gitleaks check finds no fake secret here (.gitleaks.toml).
const TOK = ['tok_', '0123456789'].join('');

async function rejection(p: Promise<unknown>): Promise<CliError> {
  const err: unknown = await p.catch((e: unknown) => e);
  if (!(err instanceof CliError)) throw new Error(`expected a CliError, got ${String(err)}`);
  expect(err.message).not.toContain(TOKEN);
  return err;
}

describe('targetUrl', () => {
  it('keeps the base path prefix and encodes the query', () => {
    expect(targetUrl('https://q.test/qualor', 'api/v0/x', { a: 'b/c', skip: undefined }).href).toBe(
      'https://q.test/qualor/api/v0/x?a=b%2Fc',
    );
    expect(targetUrl('https://q.test/qualor/', 'api/v0/x').href).toBe(
      'https://q.test/qualor/api/v0/x',
    );
  });

  it.each([
    '//evil.test/x',
    '/api/v0/x',
    'https://evil.test/x',
    'http:evil',
    '../x',
    'api/../../x',
    'api/%2e%2e/x',
    'api\\x',
    'api/v0/x?y=1',
    'api/v0/x#f',
    '',
  ])('refuses a path that could leave the base URL: %j', (p) => {
    expect(() => targetUrl('https://q.test/qualor', p)).toThrow(CliError);
  });
});

describe('request', () => {
  it('never follows a redirect, so the token never reaches the redirect target', async () => {
    const other = await serve((_req, res) => json(res, 200, { revision: null }));
    const { url } = await serve((_req, res) => {
      res.writeHead(302, { location: `${other.url}/api/v0/projects/new-code-baseline` }).end();
    });
    const res = await request(
      { url, token: TOKEN, timeoutMs: 5_000 },
      { method: 'GET', path: 'x' },
    );
    expect(res.status).toBe(302);
    const err = await rejection(
      httpBaselineClient({ url, token: TOKEN, timeoutMs: 5_000 }).fetchBaseline({
        projectKey: 'acme/app',
        branch: 'main',
      }),
    );
    expect(err.exitCode).toBe(4);
    expect(err.message).toContain('redirect');
    expect(other.requests).toHaveLength(0);
  });

  it('fails a server that never answers after the inactivity timeout', async () => {
    const { url } = await serve(() => {
      // never answers
    });
    const started = Date.now();
    const err = await rejection(
      request({ url, token: TOKEN, timeoutMs: 300 }, { method: 'GET', path: 'x' }),
    );
    expect(err.exitCode).toBe(4);
    expect(err.message).toContain('no response within');
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it('fails a response body that stalls halfway', async () => {
    const { url } = await serve((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': '100' });
      res.write('{"revision":');
    });
    const err = await rejection(
      request({ url, token: TOKEN, timeoutMs: 300 }, { method: 'GET', path: 'x' }),
    );
    expect(err.exitCode).toBe(4);
  });

  it('fails a JSON exchange that trickles past the deadline, even though bytes keep coming', async () => {
    const { url } = await serve((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      const timer = setInterval(() => res.write(' '), 50);
      res.on('close', () => clearInterval(timer));
    });
    const started = Date.now();
    const err = await rejection(
      request({ url, token: TOKEN, timeoutMs: 500 }, { method: 'GET', path: 'x' }),
    );
    expect(err.message).toContain('no response within 0.5 s');
    expect(Date.now() - started).toBeLessThan(3_000);
  });

  it(
    'honours timeoutMs while connecting, not the 5 s of the global agent',
    { timeout: 30_000 },
    async () => {
      // A socket that never connects, set up the way net.createConnection sets up a real one.
      const spy = vi
        .spyOn(http.Agent.prototype, 'createConnection')
        .mockImplementation((options: { timeout?: number }) => {
          // `connecting` as while a SYN is unanswered: writes queue until a `connect` that never comes.
          const socket = Object.assign(new net.Socket(), { connecting: true });
          if (options.timeout !== undefined) socket.setTimeout(options.timeout);
          return socket;
        });
      try {
        const started = Date.now();
        const err = await rejection(
          request(
            { url: 'http://127.0.0.1:9', token: TOKEN, timeoutMs: 6_000 },
            { method: 'GET', path: 'x' },
          ),
        );
        expect(Date.now() - started).toBeGreaterThanOrEqual(5_900);
        expect(err.message).toContain('no response within 6 s');
        expect(spy).toHaveBeenCalled();
      } finally {
        spy.mockRestore();
      }
    },
  );

  it('fails a connection closed in the middle of the body', async () => {
    const { url } = await serve((req, res) => {
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': '100' });
      res.write('{"revision":', () => req.socket.destroy());
    });
    const err = await rejection(
      request({ url, token: TOKEN, timeoutMs: 5_000 }, { method: 'GET', path: 'x' }),
    );
    expect(err.exitCode).toBe(4);
  });

  it('refuses a declared oversized body without reading it', async () => {
    const { url } = await serve((_req, res) => {
      res.writeHead(200, { 'content-length': String(10 * 1024 * 1024) });
      res.write('x');
    });
    const err = await rejection(
      request(
        { url, token: TOKEN, timeoutMs: 5_000 },
        { method: 'GET', path: 'x', maxResponseBytes: 1024 },
      ),
    );
    expect(err.message).toContain('larger than 1024 bytes');
  });

  it('never repeats the token when the server echoes it back', async () => {
    const { url } = await serve((req, res) =>
      problem(res, 500, 'INTERNAL_ERROR', `bad header ${req.headers.authorization ?? ''}`),
    );
    const res = await request(
      { url, token: TOKEN, timeoutMs: 5_000 },
      { method: 'GET', path: 'x' },
    );
    expect(res.body).not.toContain(TOKEN);
    const err = await rejection(
      httpBaselineClient({ url, token: TOKEN, timeoutMs: 5_000 }).fetchBaseline({
        projectKey: 'acme/app',
        branch: 'main',
      }),
    );
    expect(err.message).toContain('500 INTERNAL_ERROR');
  });

  it('turns a header value Node refuses into a CliError that does not show it', async () => {
    const { url, requests } = await serve((_req, res) => json(res, 200, {}));
    const err = await rejection(
      request({ url, token: `${TOKEN}\r\nx: y`, timeoutMs: 5_000 }, { method: 'GET', path: 'x' }),
    );
    expect(err.exitCode).toBe(4);
    expect(requests).toHaveLength(0);
  });
});

describe('describeFailure', () => {
  it('shows the status, the code and a cleaned, bounded problem text', () => {
    const body = JSON.stringify({ code: 'X', detail: `a\u001b[31mb\r\nc${'d'.repeat(1_000)}` });
    const text = describeFailure({ status: 500, headers: {}, body });
    expect(text).toMatch(/^500 X: ab c/);
    expect(text).not.toContain('\u001b');
    expect(text.length).toBeLessThan(520);
    expect(describeFailure({ status: 502, headers: {}, body: '<html>bad gateway</html>' })).toBe(
      '502',
    );
    expect(
      describeFailure({ status: 307, headers: { location: 'https://x' }, body: '' }),
    ).toContain('redirects are not followed');
  });
});

describe('clean', () => {
  it('removes whole escape sequences, not only their ESC and BEL bytes', () => {
    // OSC (title, hyperlink) ended by BEL or by ST, and one left unterminated.
    expect(clean('a\u001b]0;evil title\u0007b')).toBe('ab');
    expect(clean('a\u001b]8;;https://evil.test\u001b\\link\u001b]8;;\u001b\\b')).toBe('alinkb');
    expect(clean('a\u001b]0;never ends')).toBe('a');
    expect(clean('a\u001b]0;cut short\u001b[31mb')).toBe('ab');
    // DCS/SOS/PM/APC strings, C1 CSI and OSC, two-byte and intermediate ESC sequences.
    expect(clean('a\u001bPq#0;2;0;0;0\u001b\\b')).toBe('ab');
    expect(clean('a\u001b_payload\u001b\\b\u001bXsos\u001b\\c\u001b^pm\u001b\\d')).toBe('abcd');
    expect(clean('a\u009b31mb\u009d0;t\u0007c')).toBe('abc');
    expect(clean('a\u001bcb\u001b7c\u001b(Bd\u001b#8e')).toBe('abcde');
    expect(clean('a\u001b[38;2;255;0;0mb\u001b[?25lc')).toBe('abc');
  });

  it('removes bidi overrides and isolates and zero-width characters', () => {
    expect(clean('pass\u202eliaf\u202c')).toBe('passliaf');
    for (const c of ['\u202a', '\u202b', '\u202d', '\u2066', '\u2067', '\u2068', '\u2069']) {
      expect(clean(`a${c}b`)).toBe('ab');
    }
    expect(clean('n\u200bew\u200c_\u200dissues\ufeff')).toBe('new_issues');
  });

  it('replaces other control characters with a space and bounds the text', () => {
    expect(clean(' a\r\n\tb\u0000c ')).toBe('a b c');
    expect(clean('x'.repeat(2_000))).toHaveLength(500);
  });
});

describe('retryAfterMs', () => {
  it('reads delta-seconds only, clamped', () => {
    expect(retryAfterMs({ 'retry-after': '3' }, 1_000, 10_000)).toBe(3_000);
    expect(retryAfterMs({ 'retry-after': '999' }, 1_000, 10_000)).toBe(10_000);
    expect(retryAfterMs({ 'retry-after': 'Wed, 21 Oct 2015 07:28:00 GMT' }, 1_000, 10_000)).toBe(
      null,
    );
    expect(retryAfterMs({}, 1_000, 10_000)).toBeNull();
  });
});

describe('caBundle', () => {
  it('adds server.caFile to the default trust store instead of replacing it', () => {
    const extra = '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n';
    const bundle = caBundle(extra);
    expect(bundle).toContain(extra);
    expect(bundle).toEqual(expect.arrayContaining([...tls.rootCertificates]));
  });
});

describe('plan 3A additions', () => {
  const serve = useTestServers();
  const ep = (url: string, over: Partial<ServerEndpoint> = {}): ServerEndpoint => ({
    url,
    token: TOK,
    timeoutMs: 5000,
    ...over,
  });

  it('sends basic authentication with the token as user name, or none at all', async () => {
    const s = await serve((_req, res) => json(res, 200, {}));
    await request(ep(s.url, { auth: 'basic' }), { method: 'GET', path: 'api/x' });
    await request(ep(s.url, { auth: 'none' }), { method: 'GET', path: 'api/x' });
    expect(s.requests[0]?.headers.authorization).toBe(
      `Basic ${Buffer.from(`${TOK}:`).toString('base64')}`,
    );
    expect(s.requests[1]?.headers.authorization).toBeUndefined();
  });

  it.each(['PUT', 'PATCH', 'DELETE', 'POST'] as const)(
    'sends %s with a JSON body',
    async (method) => {
      const s = await serve((_req, res) => json(res, 200, { ok: true }));
      const res = await request(ep(s.url), { method, path: 'api/v0/x', json: { a: 1 } });
      expect(res.status).toBe(200);
      expect(s.requests[0]).toMatchObject({ method });
      expect(s.requests[0]?.headers['content-type']).toBe('application/json');
      expect(s.requests[0]?.body.toString()).toBe('{"a":1}');
    },
  );

  it('refuses a JSON body over 1 MiB before connecting', async () => {
    const s = await serve((_req, res) => json(res, 200, {}));
    await expect(
      request(ep(s.url), { method: 'PUT', path: 'api/v0/x', json: { a: 'x'.repeat(1024 * 1024) } }),
    ).rejects.toThrow(/1 MiB/);
    expect(s.requests).toHaveLength(0);
  });

  it('encodes a rule key as one path segment', () => {
    expect(pathSegment('eslint:@typescript-eslint/no-unused-vars')).toBe(
      'eslint%3A%40typescript-eslint%2Fno-unused-vars',
    );
    expect(targetUrl('https://q.test', `api/v0/r/${pathSegment('a/b')}`).pathname).toBe(
      '/api/v0/r/a%2Fb',
    );
    for (const bad of ['.', '..', '']) expect(() => pathSegment(bad)).toThrow(CliError);
  });

  it.each(['api/%2E%2E/x', 'api/%2e/x', 'api/%2E/x', 'api/%zz/x'])('still refuses %j', (p) => {
    expect(() => targetUrl('https://q.test/qualor', p)).toThrow(CliError);
  });

  // Beyond the brief: the security requirements of the task.

  it('keeps sending the bearer token by default', async () => {
    const s = await serve((_req, res) => json(res, 200, {}));
    await request(ep(s.url), { method: 'GET', path: 'api/x' });
    await request(ep(s.url, { auth: 'bearer' }), { method: 'GET', path: 'api/x' });
    expect(s.requests.map((r) => r.headers.authorization)).toEqual([
      `Bearer ${TOK}`,
      `Bearer ${TOK}`,
    ]);
    expect(s.requests[0]?.headers['content-type']).toBeUndefined();
    expect(s.requests[0]?.body).toHaveLength(0);
  });

  it('masks the basic credential when the server echoes it back', async () => {
    const s = await serve((req, res) =>
      problem(res, 500, 'INTERNAL_ERROR', `bad header ${req.headers.authorization ?? ''}`),
    );
    const res = await request(ep(s.url, { auth: 'basic' }), { method: 'GET', path: 'api/x' });
    expect(res.body).not.toContain(Buffer.from(`${TOK}:`).toString('base64'));
    expect(res.body).not.toContain(TOK);
  });

  it('refuses basic authentication for a token with a colon, without showing it', async () => {
    const s = await serve((_req, res) => json(res, 200, {}));
    const token = 'tok_01234:56789';
    const err: unknown = await request(ep(s.url, { auth: 'basic', token }), {
      method: 'GET',
      path: 'api/x',
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    expect((err as CliError).message).not.toContain(token);
    expect(s.requests).toHaveLength(0);
  });

  it('refuses a JSON body it cannot serialise, or one sent with a stream body', async () => {
    const s = await serve((_req, res) => json(res, 200, {}));
    await expect(
      request(ep(s.url), { method: 'POST', path: 'api/x', json: { n: 1n } }),
    ).rejects.toThrow(CliError);
    await expect(
      request(ep(s.url), { method: 'POST', path: 'api/x', json: () => 1 }),
    ).rejects.toThrow(CliError);
    await expect(
      request(ep(s.url), {
        method: 'POST',
        path: 'api/x',
        json: {},
        body: { stream: () => Readable.from([]), contentLength: 0 },
      }),
    ).rejects.toThrow(/either a body or JSON/);
    expect(s.requests).toHaveLength(0);
  });

  it('encodes a leading dot or tilde instead of refusing it, and never produces a dot segment', () => {
    expect(pathSegment('.eslintrc')).toBe('%2Eeslintrc');
    expect(pathSegment('~x')).toBe('%7Ex');
    expect(pathSegment('a.b~c')).toBe('a.b~c');
    expect(pathSegment("it's(*)!")).toBe('it%27s%28%2A%29%21');
    expect(targetUrl('https://q.test', `r/${pathSegment('.eslintrc')}`).pathname).toBe(
      '/r/%2Eeslintrc',
    );
    for (const bad of ['%2E', '%2E%2E', '%2e.']) {
      expect(() => targetUrl('https://q.test', `r/${pathSegment(bad)}`)).not.toThrow();
      expect(targetUrl('https://q.test', `r/${pathSegment(bad)}`).pathname).toMatch(/^\/r\/%25/);
    }
  });
});

describe('fix 8a', () => {
  const serve = useTestServers();
  const ep = (url: string, over: Partial<ServerEndpoint> = {}): ServerEndpoint => ({
    url,
    token: TOK,
    timeoutMs: 5000,
    ...over,
  });
  const caught = async (p: Promise<unknown>): Promise<unknown> => p.catch((e: unknown) => e);

  it.each(['a/../b', 'a/./b', '../b', 'a/..', './a', 'a\\..\\b', 'a\\.', '..\\a', 'x/y/..'])(
    'pathSegment refuses a value with a dot part: %j',
    (value) => {
      expect(() => pathSegment(value)).toThrow(CliError);
    },
  );

  it('pathSegment keeps values whose parts only contain dots among other characters', () => {
    expect(pathSegment('a/.b/c.')).toBe('a%2F.b%2Fc.');
    expect(pathSegment('a/.../b')).toBe('a%2F...%2Fb');
  });

  it.each([
    'r/a%2F..%2Fb',
    'r/a%2f..%2fb',
    'r/a%5C..%5Cb',
    'r/a%5c%2E%5cb',
    'r/..%2Fb',
    'r/a%2F%2E',
    'r/%2E%2E%5Cx',
  ])('targetUrl refuses a segment with a dot part once escaped slashes are decoded: %s', (p) => {
    expect(() => targetUrl('https://q.test', p)).toThrow(CliError);
  });

  it('targetUrl keeps a segment whose encoded slashes hold no dot part', () => {
    expect(targetUrl('https://q.test', 'r/a%2F.b%2Fc').pathname).toBe('/r/a%2F.b%2Fc');
  });

  it.each(['\ud800', 'a\udfffb', 'x/\ud83d'])(
    'pathSegment gives a CliError, not a URIError, for a lone surrogate: %j',
    (value) => {
      let err: unknown;
      try {
        pathSegment(value);
      } catch (e) {
        err = e;
      }
      expect(err).toBeInstanceOf(CliError);
      expect(err).not.toBeInstanceOf(URIError);
    },
  );

  it('refuses before any I/O with a plain CliError, never an UnreachableError', async () => {
    const s = await serve((_req, res) => json(res, 200, {}));
    const refusals = [
      caught(
        request(ep(s.url, { auth: 'basic', token: 'tok_0123:456789' }), {
          method: 'GET',
          path: 'api/x',
        }),
      ),
      caught(
        request(ep(s.url), {
          method: 'POST',
          path: 'api/x',
          json: {},
          body: { stream: () => Readable.from([]), contentLength: 0 },
        }),
      ),
      caught(request(ep(s.url), { method: 'POST', path: 'api/x', json: { n: 1n } })),
      caught(request(ep(s.url), { method: 'POST', path: 'api/x', json: () => 1 })),
      caught(
        request(ep(s.url), {
          method: 'PUT',
          path: 'api/x',
          json: { a: 'x'.repeat(1024 * 1024) },
        }),
      ),
    ];
    for (const err of await Promise.all(refusals)) {
      expect(err).toBeInstanceOf(CliError);
      expect(err).not.toBeInstanceOf(UnreachableError);
      expect((err as CliError).exitCode).toBe(EXIT.SERVER);
      expect((err as CliError).message).not.toContain('tok_0123');
    }
    expect(s.requests).toHaveLength(0);
  });

  it('still reports a refused connection as an UnreachableError', async () => {
    const s = await serve((_req, res) => json(res, 200, {}));
    const url = s.url;
    s.server.closeAllConnections();
    await new Promise<void>((resolve) => s.server.close(() => resolve()));
    const err = await caught(request(ep(url), { method: 'GET', path: 'api/x' }));
    expect(err).toBeInstanceOf(UnreachableError);
  });

  it.each(['t', 'tok', 'tok_0', 'tok_01', 'tok_012', TOK, 'tok_01234567890'])(
    'masks the basic credential, padded or not, whatever the token length: %j',
    async (token) => {
      const padded = Buffer.from(`${token}:`).toString('base64');
      const unpadded = padded.replace(/=+$/, '');
      const s = await serve((_req, res) =>
        json(res, 200, { padded: `<${padded}>`, unpadded: `<${unpadded}>` }),
      );
      const res = await request(ep(s.url, { auth: 'basic', token }), {
        method: 'GET',
        path: 'api/x',
      });
      const body = JSON.parse(res.body) as { padded: string; unpadded: string };
      expect(body.padded).not.toContain(unpadded);
      expect(body.unpadded).not.toContain(unpadded);
      expect(body.padded).toMatch(/^<[^=]*>$/);
    },
  );
});
