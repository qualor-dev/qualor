import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer } from 'node:https';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import { Readable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { describeWithTools } from '../../test/analyzers';
import { startConnectProxy } from '../../test/proxy';
import { settingsFor } from '../../test/git';
import { useTempDirs, writeTree } from '../../test/tmp';
import { resolveBinary } from '../analyzers/binary';
import { loadSettings, type Settings } from '../config/settings';
import { CliError } from '../errors';
import { createLogger } from '../log';
import { serverEndpoint } from './endpoint';
import { request } from './http';

const tmp = useTempDirs();

function withServer(
  root: string,
  source: Settings['serverUrlSource'],
  server: { caFile?: string } = {},
  caFileSource: Settings['caFileSource'] = server.caFile === undefined ? null : 'env',
): Settings {
  return {
    ...settingsFor(root, { server: { url: 'https://q.example.test', ...server } }),
    token: 'qlr_prj_token',
    serverUrlSource: source,
    caFileSource,
  };
}

describe('serverEndpoint', () => {
  it('uses a URL from the command line or QUALOR_URL', () => {
    const root = tmp();
    for (const source of ['flag', 'env'] as const) {
      expect(
        serverEndpoint(withServer(root, source), {
          upload: true,
          log: createLogger('error', () => {}),
        }),
      ).toEqual({ url: 'https://q.example.test', token: 'qlr_prj_token', timeoutMs: 30_000 });
    }
  });

  it('refuses an upload to a URL that only qualor.yml names, and warns under --dry-run', () => {
    const root = tmp();
    const lines: string[] = [];
    const log = createLogger('warn', (t) => lines.push(t));
    const err: unknown = (() => {
      try {
        return serverEndpoint(withServer(root, 'file'), { upload: true, log });
      } catch (e) {
        return e;
      }
    })();
    expect(err).toBeInstanceOf(CliError);
    expect((err as CliError).exitCode).toBe(2);
    expect((err as CliError).message).toContain('or pass --server-url');
    expect(serverEndpoint(withServer(root, 'file'), { upload: false, log })).toBeNull();
    expect(lines.join('')).toContain('QUALOR_URL');
  });

  it('has no endpoint without a URL or a token', () => {
    const root = tmp();
    const log = createLogger('error', () => {});
    expect(serverEndpoint(settingsFor(root), { upload: false, log })).toBeNull();
    expect(
      serverEndpoint({ ...withServer(root, 'env'), token: null }, { upload: false, log }),
    ).toBeNull();
  });

  it('reads server.caFile relative to the repo, and rejects a missing or non-PEM file with exit 2', () => {
    const root = tmp();
    writeTree(root, {
      'certs/ca.pem': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
      'certs/not.pem': 'hello',
    });
    const log = createLogger('error', () => {});
    expect(
      serverEndpoint(withServer(root, 'env', { caFile: 'certs/ca.pem' }), { upload: true, log })
        ?.ca,
    ).toContain('BEGIN CERTIFICATE');
    for (const caFile of ['certs/missing.pem', 'certs/not.pem']) {
      expect(() =>
        serverEndpoint(withServer(root, 'env', { caFile }), { upload: true, log }),
      ).toThrow(expect.objectContaining({ exitCode: 2 }));
    }
  });
});

describe('serverEndpoint: the URL, the token and the CA file', () => {
  const log = createLogger('error', () => {});
  const endpoint = (root: string, url: string, token = 'qlr_prj_token') =>
    serverEndpoint(
      {
        ...settingsFor(root, { server: { url } }),
        token,
        serverUrlSource: 'env',
      },
      { upload: true, log },
    );

  it.each([
    'https://user:hunter2secret@q.example.test',
    'https://hunter2secret@q.example.test',
    'https://q.example.test/?token=hunter2secret',
    'https://q.example.test/#hunter2secret',
  ])('refuses %s with exit 2 and never repeats it', (url) => {
    const err: unknown = (() => {
      try {
        return endpoint(tmp(), url);
      } catch (e) {
        return e;
      }
    })();
    expect(err).toMatchObject({ exitCode: 2 });
    expect((err as CliError).message).not.toContain('hunter2secret');
  });

  it('refuses a token that cannot be sent in an HTTP header, without showing it', () => {
    const err: unknown = (() => {
      try {
        return endpoint(tmp(), 'https://q.example.test', 'qlr_\nsecret');
      } catch (e) {
        return e;
      }
    })();
    expect(err).toMatchObject({ exitCode: 2 });
    expect((err as CliError).message).not.toContain('secret');
  });

  it('warns when the token would travel over plain http to another host', () => {
    const root = tmp();
    const lines: string[] = [];
    const warn = createLogger('warn', (t) => lines.push(t));
    const at = (url: string) =>
      serverEndpoint(
        { ...settingsFor(root, { server: { url } }), token: 't', serverUrlSource: 'flag' },
        { upload: true, log: warn },
      );
    for (const url of ['http://127.0.0.1:8080', 'http://localhost:8080', 'http://[::1]:8080']) {
      expect(at(url)?.url).toBe(url);
    }
    expect(lines).toEqual([]);
    expect(at('http://qualor.acme.internal')?.url).toBe('http://qualor.acme.internal');
    expect(lines.join('')).toContain('unencrypted');
  });

  it('warns that NODE_TLS_REJECT_UNAUTHORIZED=0 is ignored', () => {
    const lines: string[] = [];
    serverEndpoint(
      {
        ...settingsFor(tmp(), { server: { url: 'https://q.example.test' } }),
        token: 't',
        serverUrlSource: 'env',
      },
      {
        upload: true,
        log: createLogger('warn', (t) => lines.push(t)),
        env: { NODE_TLS_REJECT_UNAUTHORIZED: '0' },
      },
    );
    expect(lines.join('')).toContain('NODE_TLS_REJECT_UNAUTHORIZED=0 is ignored');
  });

  it('rejects a missing CA file, a directory, or one over 1 MiB', () => {
    const root = tmp();
    writeTree(root, {
      'certs/big.pem':
        '-----BEGIN CERTIFICATE-----\n' + 'A'.repeat(1024 * 1024) + '\n-----END CERTIFICATE-----\n',
      'certs/dir/x': '',
    });
    for (const caFile of ['../missing-outside.pem', 'certs/dir', 'certs/big.pem']) {
      expect(() =>
        serverEndpoint(withServer(root, 'env', { caFile }), { upload: true, log }),
      ).toThrow(expect.objectContaining({ exitCode: 2 }));
    }
  });
});

describe('serverEndpoint: the CA file follows (ruling V8)', () => {
  it('refuses an upload with a caFile only qualor.yml names, before reading it', () => {
    const root = tmp();
    const err: unknown = (() => {
      try {
        return serverEndpoint(withServer(root, 'env', { caFile: 'missing.pem' }, 'file'), {
          upload: true,
          log: createLogger('error', () => {}),
        });
      } catch (e) {
        return e;
      }
    })();
    expect(err).toMatchObject({ exitCode: 2 });
    expect((err as CliError).message).toContain('QUALOR_CA_FILE');
    expect((err as CliError).message).not.toContain('ENOENT');
  });

  it('ignores it with a warning under --dry-run, so the default store is used', () => {
    const root = tmp();
    const lines: string[] = [];
    const ep = serverEndpoint(withServer(root, 'env', { caFile: 'missing.pem' }, 'file'), {
      upload: false,
      log: createLogger('warn', (t) => lines.push(t)),
    });
    expect(ep).toEqual({
      url: 'https://q.example.test',
      token: 'qlr_prj_token',
      timeoutMs: 30_000,
    });
    expect(lines.join('')).toContain('QUALOR_CA_FILE');
  });

  it('reads it from --ca-file or QUALOR_CA_FILE, wherever the file is', () => {
    const outside = tmp();
    writeTree(outside, {
      'ca.pem': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
    });
    const root = tmp();
    for (const source of ['flag', 'env'] as const) {
      const caFile = path.join(outside, 'ca.pem');
      const lines: string[] = [];
      expect(
        serverEndpoint(withServer(root, 'env', { caFile }, source), {
          upload: true,
          log: createLogger('warn', (t) => lines.push(t)),
        })?.ca,
      ).toContain('BEGIN CERTIFICATE');
      expect(lines).toEqual([]);
    }
  });

  it('warns when a CI-supplied CA file lies inside the checkout, which the repository controls', () => {
    const root = tmp();
    writeTree(root, {
      'certs/ca.pem': '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n',
    });
    const lines: string[] = [];
    expect(
      serverEndpoint(withServer(root, 'env', { caFile: 'certs/ca.pem' }, 'env'), {
        upload: true,
        log: createLogger('warn', (t) => lines.push(t)),
      })?.ca,
    ).toContain('BEGIN CERTIFICATE');
    expect(lines.join('')).toContain('certs/ca.pem is inside the repository');
  });
});

describe.runIf(process.platform !== 'win32')('server.caFile that is a FIFO', () => {
  it('is refused with exit 2 instead of blocking the CLI', () => {
    const root = tmp();
    expect(spawnSync('mkfifo', [path.join(root, 'ca.pem')]).status).toBe(0);
    expect(() =>
      serverEndpoint(withServer(root, 'env', { caFile: 'ca.pem' }), {
        upload: true,
        log: createLogger('error', () => {}),
      }),
    ).toThrow(expect.objectContaining({ exitCode: 2 }));
  });
});

describeWithTools(['openssl'])('server.caFile over real TLS', () => {
  it('trusts a private CA only when it is given', { timeout: 60_000 }, async () => {
    const dir = tmp();
    const openssl = resolveBinary('openssl', { root: dir, env: process.env }) ?? 'openssl';
    const gen = spawnSync(
      openssl,
      [
        'req',
        '-x509',
        '-newkey',
        'rsa:2048',
        '-nodes',
        '-keyout',
        path.join(dir, 'key.pem'),
        '-out',
        path.join(dir, 'cert.pem'),
        '-days',
        '1',
        '-subj',
        '/CN=127.0.0.1',
        '-addext',
        'subjectAltName=IP:127.0.0.1,DNS:qualor.test',
      ],
      { encoding: 'utf8' },
    );
    expect(gen.status, gen.stderr).toBe(0);
    const cert = readFileSync(path.join(dir, 'cert.pem'), 'utf8');
    const server = createServer(
      { key: readFileSync(path.join(dir, 'key.pem')), cert },
      (_req, res) => res.end('{"ok":true}'),
    );
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      const { port } = server.address() as AddressInfo;
      const ep = { url: `https://127.0.0.1:${port}`, token: 't', timeoutMs: 5_000 };
      const trusted = await request({ ...ep, ca: cert }, { method: 'GET', path: 'x' });
      expect(trusted).toMatchObject({ status: 200, body: '{"ok":true}' });
      // The upload goes over its own TLS socket (raw-http.ts), with the same trust rules.
      const upload = (e: typeof ep & { ca?: string; env?: Record<string, string> }) =>
        request(e, {
          method: 'POST',
          path: 'x',
          body: { stream: () => Readable.from([Buffer.from('hello')]), contentLength: 5 },
        });
      expect(await upload({ ...ep, ca: cert })).toMatchObject({ status: 200, body: '{"ok":true}' });
      const untrustedUpload: unknown = await upload(ep).catch((e: unknown) => e);
      expect(untrustedUpload).toMatchObject({ exitCode: 4 });
      expect((untrustedUpload as Error).message).toMatch(/SELF_SIGNED|UNABLE_TO_VERIFY|CERT/);
      // Ruling V9: through a CONNECT proxy, TLS runs inside the tunnel and is checked against
      // the origin's name (the proxy maps `qualor.test`, which does not resolve, to 127.0.0.1).
      const proxy = await startConnectProxy();
      try {
        const viaProxy = {
          ...ep,
          url: `https://qualor.test:${port}`,
          env: { HTTPS_PROXY: proxy.url },
        };
        expect(await upload({ ...viaProxy, ca: cert })).toMatchObject({ status: 200 });
        expect(proxy.heads[0]?.split('\r\n')[0]).toBe(`CONNECT qualor.test:${port} HTTP/1.1`);
        const untrustedTunnel: unknown = await upload(viaProxy).catch((e: unknown) => e);
        expect(untrustedTunnel).toMatchObject({ exitCode: 4 });
      } finally {
        proxy.close();
      }
      const untrusted: unknown = await request(ep, { method: 'GET', path: 'x' }).catch(
        (e: unknown) => e,
      );
      expect(untrusted).toMatchObject({ exitCode: 4 });
      // The escape hatch Node honours by default is never honoured here.
      const saved = process.env['NODE_TLS_REJECT_UNAUTHORIZED'];
      process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = '0';
      try {
        const bypass: unknown = await request(ep, { method: 'GET', path: 'x' }).catch(
          (e: unknown) => e,
        );
        expect(bypass).toMatchObject({ exitCode: 4 });
        const bypassUpload: unknown = await upload(ep).catch((e: unknown) => e);
        expect(bypassUpload).toMatchObject({ exitCode: 4 });
      } finally {
        if (saved === undefined) delete process.env['NODE_TLS_REJECT_UNAUTHORIZED'];
        else process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = saved;
      }

      // Ruling V8, end to end through loadSettings: --ca-file and QUALOR_CA_FILE are trusted, a
      // caFile only qualor.yml names is ignored under --dry-run (default store: untrusted).
      const repo = tmp();
      writeTree(repo, {
        'qualor.yml': 'version: 1\nserver:\n  caFile: ca.pem\n',
        'ca.pem': cert,
      });
      const env = { QUALOR_URL: ep.url, QUALOR_TOKEN: 'qlr_prj_token' };
      const log = createLogger('error', () => {});
      const via = (settings: Settings) => {
        const endpoint = serverEndpoint(settings, { upload: false, log });
        if (endpoint === null) throw new Error('no endpoint');
        return request(endpoint, { method: 'GET', path: 'x' }).catch((e: unknown) => e);
      };
      const load = (e: Record<string, string>, flags: { caFile?: string } = {}) =>
        loadSettings({ cwd: repo, env: { ...env, ...e }, flags, log });
      expect(await via(load({}, { caFile: path.join(dir, 'cert.pem') }))).toMatchObject({
        status: 200,
      });
      expect(await via(load({ QUALOR_CA_FILE: path.join(dir, 'cert.pem') }))).toMatchObject({
        status: 200,
      });
      expect(await via(load({}))).toMatchObject({ exitCode: 4 });
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});
