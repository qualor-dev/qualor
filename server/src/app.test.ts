import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { connect } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import type { FastifyInstance } from 'fastify';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import { testConfig } from '../test/config';
import { buildApp } from './app';
import type { Config } from './config';
import { createDatabase, type Database } from './db/client';
import { createLogger } from './http/logger';
import { loadUiAssets, type UiAssets } from './http/ui';

describe('buildApp', () => {
  let database: Database;
  const apps: FastifyInstance[] = [];

  beforeAll(() => {
    // A pool that never connects: these routes must not touch the database.
    database = createDatabase('postgres://unused@127.0.0.1:1/unused', { max: 1 });
  });
  afterAll(async () => {
    await Promise.all(apps.map((a) => a.close()));
    await database.close();
  });

  async function app(
    checkReady: () => Promise<boolean> = async () => true,
    config: Partial<Config> = {},
    ui?: UiAssets,
  ): Promise<FastifyInstance> {
    const instance = await buildApp({
      config: testConfig(config),
      db: database.db,
      logger: createLogger('silent'),
      checkReady,
      ui,
    });
    apps.push(instance);
    return instance;
  }

  it('computes the dummy argon2 hash at startup, so the first unknown-user login is not slower', async () => {
    vi.resetModules(); // a fresh password module, whose dummy hash has not been computed yet
    const password = await import('./auth/password');
    const fresh = await import('./app');
    expect(password.dummyHashIsWarm()).toBe(false);
    const instance = await fresh.buildApp({
      config: testConfig(),
      db: database.db,
      logger: createLogger('silent'),
      checkReady: async () => true,
    });
    apps.push(instance);
    expect(password.dummyHashIsWarm()).toBe(true);
  });

  it('answers /healthz with security headers and no database access', async () => {
    const res = await (
      await app(async () => {
        throw new Error('must not be called');
      })
    ).inject({ method: 'GET', url: '/healthz' });
    expect(res.statusCode).toBe(200);
    expect(res.json()).toEqual({ status: 'ok' });
    expect(res.headers['x-content-type-options']).toBe('nosniff');
  });

  it('answers /readyz from the readiness check', async () => {
    expect(
      (await (await app(async () => true)).inject({ method: 'GET', url: '/readyz' })).statusCode,
    ).toBe(200);
    const notReady = await (await app(async () => false)).inject({ method: 'GET', url: '/readyz' });
    expect([notReady.statusCode, notReady.json().code]).toEqual([503, 'NOT_READY']);
    const failing = await (
      await app(async () => {
        throw new Error('connect ECONNREFUSED');
      })
    ).inject({ method: 'GET', url: '/readyz' });
    expect(failing.statusCode).toBe(503);
  });

  it('answers /readyz with 503 when the readiness check hangs past its timeout', async () => {
    const instance = await buildApp({
      config: testConfig(),
      db: database.db,
      logger: createLogger('silent'),
      // An unresponsive PostgreSQL: the check never settles.
      checkReady: () => new Promise<boolean>(() => undefined),
      readyTimeoutMs: 50,
    });
    apps.push(instance);
    const started = Date.now();
    const res = await instance.inject({ method: 'GET', url: '/readyz' });
    expect([res.statusCode, res.json().code]).toEqual([503, 'NOT_READY']);
    expect(Date.now() - started).toBeLessThan(5_000);
  });

  it('serves the OpenAPI 3.1 document', async () => {
    const res = await (await app()).inject({ method: 'GET', url: '/api/v0/openapi.json' });
    expect(res.statusCode).toBe(200);
    expect(res.json().openapi).toBe('3.1.0');
    expect(Object.keys(res.json().paths)).toEqual(expect.arrayContaining(['/healthz', '/readyz']));
  });

  it('derives request.ip from X-Forwarded-For only as far as the configured hop count', async () => {
    const whoami = async (trustProxy: Config['trustProxy']) => {
      const instance = await app(undefined, { trustProxy });
      instance.get('/whoami', { config: { public: true } }, async (request) => ({
        ip: request.ip,
      }));
      const res = await instance.inject({
        method: 'GET',
        url: '/whoami',
        remoteAddress: '10.0.0.2',
        headers: { 'x-forwarded-for': '198.51.100.9, 203.0.113.7' },
      });
      return (res.json() as { ip: string }).ip;
    };
    expect(await whoami(false)).toBe('10.0.0.2');
    // One trusted hop (the reverse proxy at 10.0.0.2): the client is the address it appended; the
    // left-most entry is whatever the client claimed and is ignored.
    expect(await whoami(1)).toBe('203.0.113.7');
    expect(await whoami(2)).toBe('198.51.100.9');
    expect(await whoami(['10.0.0.0/8'])).toBe('203.0.113.7');
    expect(await whoami(['192.168.0.0/16'])).toBe('10.0.0.2');
  });

  it('answers unknown routes with a problem', async () => {
    const res = await (await app()).inject({ method: 'GET', url: '/api/v0/nope' });
    expect([res.statusCode, res.json().code]).toEqual([404, 'NOT_FOUND']);
  });

  it('sends the strict CSP, DENY framing and no referrer on API responses', async () => {
    const res = await (await app()).inject({ method: 'GET', url: '/healthz' });
    const csp = res.headers['content-security-policy'];
    expect(csp).toContain("default-src 'self'");
    expect(csp).toContain("script-src 'self';");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("style-src 'self'");
    expect(csp).not.toMatch(/unsafe-inline|unsafe-eval|nonce-|upgrade-insecure-requests/);
    expect(res.headers['x-frame-options']).toBe('DENY');
    expect(res.headers['referrer-policy']).toBe('no-referrer');
  });

  describe('serving the web UI (plan 1F ruling Y2)', () => {
    const script = 'export const x = 1;'.repeat(200);
    let dir: string;
    let ui: UiAssets;

    beforeAll(async () => {
      dir = await mkdtemp(join(tmpdir(), 'qualor-app-ui-'));
      await writeFile(
        join(dir, 'index.html'),
        '<!doctype html><app-root ngCspNonce="__QUALOR_CSP_NONCE__"></app-root>',
      );
      await writeFile(join(dir, 'main-4BUTXKQY.js'), script);
      await writeFile(join(dir, 'favicon.ico'), 'icon');
      ui = await loadUiAssets(dir);
    });
    afterAll(async () => {
      await rm(dir, { recursive: true, force: true });
    });

    it('serves index.html for client routes with a fresh nonce in body and CSP', async () => {
      const instance = await app(undefined, {}, ui);
      const nonces: string[] = [];
      for (const url of ['/', '/projects/0190a6c2-0000-7000-8000-000000000000/issues?q=a.b']) {
        const res = await instance.inject({ method: 'GET', url });
        expect(res.statusCode).toBe(200);
        expect(res.headers['content-type']).toBe('text/html; charset=utf-8');
        expect(res.headers['cache-control']).toBe('no-store');
        expect(res.headers['x-content-type-options']).toBe('nosniff');
        const nonce = /ngCspNonce="([^"]+)"/.exec(res.body)?.[1] ?? '';
        expect(nonce).toMatch(/^[A-Za-z0-9+/]{22}==$/);
        // One policy only: the page's own replaces helmet's, it is not added next to it.
        const csp = res.headers['content-security-policy'];
        expect(typeof csp).toBe('string');
        expect(csp).toContain(`style-src 'self' 'nonce-${nonce}'`);
        expect(csp).toContain(`script-src 'self' 'nonce-${nonce}';`);
        expect(csp).toContain("frame-ancestors 'none'");
        nonces.push(nonce);
      }
      expect(nonces[0]).not.toBe(nonces[1]);
    });

    it('serves hashed files immutable and compressed, others revalidated, and answers 304', async () => {
      const instance = await app(undefined, {}, ui);
      const main = await instance.inject({
        method: 'GET',
        url: '/main-4BUTXKQY.js',
        headers: { 'accept-encoding': 'gzip, br' },
      });
      expect(main.statusCode).toBe(200);
      expect(main.headers['cache-control']).toBe('public, max-age=31536000, immutable');
      expect(main.headers['content-type']).toBe('text/javascript; charset=utf-8');
      expect(main.headers['content-encoding']).toBe('br');
      expect(main.headers['vary']).toBe('accept-encoding');
      const plain = await instance.inject({ method: 'GET', url: '/main-4BUTXKQY.js' });
      expect([plain.headers['content-encoding'], plain.body]).toEqual([undefined, script]);
      const icon = await instance.inject({ method: 'GET', url: '/favicon.ico' });
      expect(icon.headers['cache-control']).toBe('public, no-cache');
      const again = await instance.inject({
        method: 'GET',
        url: '/favicon.ico',
        headers: { 'if-none-match': String(icon.headers['etag']) },
      });
      expect([again.statusCode, again.body]).toEqual([304, '']);
      const head = await instance.inject({ method: 'HEAD', url: '/settings' });
      expect([head.statusCode, head.body]).toEqual([200, '']);
    });

    it('sends gzip only when br is refused, a distinct ETag per encoding, and nosniff on files', async () => {
      const instance = await app(undefined, {}, ui);
      const get = (headers: Record<string, string>) =>
        instance.inject({ method: 'GET', url: '/main-4BUTXKQY.js', headers });
      const gzip = await get({ 'accept-encoding': 'br;q=0, gzip' });
      expect([gzip.headers['content-encoding'], gzip.headers['vary']]).toEqual([
        'gzip',
        'accept-encoding',
      ]);
      const none = await get({ 'accept-encoding': 'br;q=0, gzip;q=0' });
      expect([none.headers['content-encoding'], none.body]).toEqual([undefined, script]);
      expect(none.headers['x-content-type-options']).toBe('nosniff');
      const br = await get({ 'accept-encoding': 'br' });
      expect(new Set([br, gzip, none].map((r) => r.headers['etag'])).size).toBe(3);
      // A validator of one encoding does not answer 304 for another.
      const stale = await get({ 'if-none-match': String(br.headers['etag']) });
      expect([stale.statusCode, stale.body]).toEqual([200, script]);
      const fresh = await get({
        'accept-encoding': 'br',
        'if-none-match': `"other", ${String(br.headers['etag'])}`,
      });
      expect(fresh.statusCode).toBe(304);
      const head = await instance.inject({
        method: 'HEAD',
        url: '/main-4BUTXKQY.js',
        headers: { 'accept-encoding': 'br' },
      });
      expect([head.statusCode, head.body, head.headers['content-encoding']]).toEqual([
        200,
        '',
        'br',
      ]);
    });

    it('never shadows the API, and 404s a missing file instead of sending index.html', async () => {
      const instance = await app(undefined, {}, ui);
      for (const url of ['/api/v0/nope', '/api', '/api/', '/api/v1/projects']) {
        const res = await instance.inject({ method: 'GET', url });
        expect([url, res.statusCode, res.headers['content-type']]).toEqual([
          url,
          404,
          'application/problem+json; charset=utf-8',
        ]);
      }
      const me = await instance.inject({ method: 'GET', url: '/api/v0/auth/me' });
      expect([me.statusCode, me.json().code]).toEqual([401, 'UNAUTHENTICATED']);
      const health = await instance.inject({ method: 'GET', url: '/healthz' });
      expect(health.json()).toEqual({ status: 'ok' });
      const missing = await instance.inject({ method: 'GET', url: '/chunk-AAAAAAAA.js' });
      expect([missing.statusCode, missing.json().code]).toEqual([404, 'NOT_FOUND']);
      // Fastify rejects a malformed percent-encoding before routing (400 FST_ERR_BAD_URL).
      const malformed = await instance.inject({ method: 'GET', url: '/%E0%A4%A' });
      expect([malformed.statusCode, malformed.headers['content-type']]).toEqual([
        400,
        'application/json',
      ]);
      expect((await instance.inject({ method: 'POST', url: '/projects' })).statusCode).toBe(404);
    });

    it('never answers an API-looking path with the page (encoded, doubled slash, any case)', async () => {
      const instance = await app(undefined, {}, ui);
      for (const url of ['/%61pi/v0/nope', '//api/v0/nope', '/API/v0/nope', '/Api', '/api?x=1']) {
        const res = await instance.inject({ method: 'GET', url });
        expect([url, res.statusCode, res.headers['content-type']]).toEqual([
          url,
          404,
          'application/problem+json; charset=utf-8',
        ]);
      }
    });

    it('never escapes QUALOR_UI_DIR: traversal, backslashes, NUL and long paths', async () => {
      const instance = await app(undefined, {}, ui);
      const misses = [
        '/../package.json',
        '/%2e%2e/%2e%2e/package.json',
        '/..%2f..%2fpackage.json',
        '/%2e%2e%5c%2e%2e%5cpackage.json',
        '/..\\..\\package.json',
        '/main-4BUTXKQY.js%00.html',
        '/favicon.ico%00.txt',
        '/x/..%2ffavicon.ico',
        `/${'a/'.repeat(4000)}x.js`,
      ];
      for (const url of misses) {
        const res = await instance.inject({ method: 'GET', url });
        expect([url, res.statusCode]).toEqual([url, 404]);
        expect(res.body).not.toContain('export const x');
      }
      // Literal dot segments are resolved like a browser does, and only inside the directory.
      const inside = await instance.inject({ method: 'GET', url: '/x/../../favicon.ico' });
      expect([inside.statusCode, inside.body]).toEqual([200, 'icon']);
      // A path without a dot in its last segment is a client route: the page, never a file.
      for (const url of ['/%2e%2e/%2e%2e/etc/passwd', '/x%00y', `/${'a'.repeat(8000)}`]) {
        const res = await instance.inject({ method: 'GET', url });
        expect([url, res.statusCode, res.headers['content-type']]).toEqual([
          url,
          200,
          'text/html; charset=utf-8',
        ]);
        expect(res.body).toContain('<app-root');
      }
    });

    it('routes an absolute-form request target by its path, over a real socket', async () => {
      // inject() normalises the URL, so this needs a listener and raw HTTP/1.1 (RFC 9112 §3.2.2).
      const instance = await app(undefined, {}, ui);
      await instance.listen({ host: '127.0.0.1', port: 0 });
      const { port } = instance.server.address() as { port: number };
      const send = (target: string) =>
        new Promise<{ status: number; type: string; body: string }>((resolve, reject) => {
          const socket = connect(port, '127.0.0.1', () => {
            socket.write(`GET ${target} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n`);
          });
          let raw = '';
          socket.on('data', (chunk: Buffer) => (raw += chunk.toString('latin1')));
          socket.on('error', reject);
          socket.on('end', () => {
            const [head = '', body = ''] = raw.split('\r\n\r\n');
            resolve({
              status: Number(head.split(' ')[1]),
              type: /^content-type: (.*)$/im.exec(head)?.[1] ?? '',
              body,
            });
          });
        });
      const origin = `http://127.0.0.1:${port}`;
      for (const target of [
        `${origin}/api/v0/nope`,
        `${origin}/api`,
        `HTTP://other/%61pi/v0/nope`,
        `${origin}/chunk-AAAAAAAA.js`,
        '*',
      ]) {
        const res = await send(target);
        expect([target, res.status, res.type]).toEqual([
          target,
          404,
          'application/problem+json; charset=utf-8',
        ]);
      }
      const icon = await send(`${origin}/favicon.ico`);
      expect([icon.status, icon.body]).toEqual([200, 'icon']);
      const page = await send(`${origin}/projects/x`);
      expect([page.status, page.type]).toEqual([200, 'text/html; charset=utf-8']);
      const origin404 = await send('/api/v0/nope');
      expect(origin404.status).toBe(404);
    });

    it('serves nothing but the API without QUALOR_UI_DIR', async () => {
      const res = await (await app()).inject({ method: 'GET', url: '/projects' });
      expect([res.statusCode, res.json().code]).toEqual([404, 'NOT_FOUND']);
    });
  });
});
