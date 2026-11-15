import { createHash } from 'node:crypto';
import {
  createWriteStream,
  existsSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  statSync,
} from 'node:fs';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import type { ServerResponse } from 'node:http';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { json, problem, useTestServers } from '../../test/http';
import { TEST_CA_PEM, TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM } from '../../test/tls';
import { useTempDirs } from '../../test/tmp';
import type * as Runner from '../analyzers/runner';
import { trackWorkDir, untrackWorkDir } from '../analyzers/runner';
import { silentLogger } from '../log';
import type { ServerEndpoint } from './http';
import { downloadServerVulndb, fetchServerVulndb } from './vulndb';

// The real signal-cleanup registry, watched: which paths the download leaves for a Ctrl+C.
vi.mock('../analyzers/runner', async (importOriginal) => {
  const real = await importOriginal<typeof Runner>();
  return {
    ...real,
    trackWorkDir: vi.fn(real.trackWorkDir),
    untrackWorkDir: vi.fn(real.untrackWorkDir),
  };
});
beforeEach(() => {
  vi.mocked(trackWorkDir).mockClear();
  vi.mocked(untrackWorkDir).mockClear();
});

const serve = useTestServers();
const tmp = useTempDirs();
const TOKEN = 'qlr_sca_download_token_1234';

const payload = Buffer.from('trivy-db-bytes-'.repeat(1000));
const hex = createHash('sha256').update(payload).digest('hex');
const digest = `sha256:${hex}`;

const endpoint = (url: string, extra: Partial<ServerEndpoint> = {}): ServerEndpoint => ({
  url,
  token: TOKEN,
  timeoutMs: 5000,
  ...extra,
});

describe('fetchServerVulndb', () => {
  const meta = {
    serve: true,
    policy: 'daily',
    current: { digest, sizeBytes: payload.length, builtAt: '2026-10-31T00:00:00.000Z' },
    accepted: [digest],
  };

  it('parses the metadata and sends the token', async () => {
    const s = await serve((_req, res) => json(res, 200, meta));
    const got = await fetchServerVulndb(endpoint(s.url), silentLogger);
    expect(got).toEqual(meta);
    expect(s.requests[0]?.url).toBe('/api/v0/scanner/vulnerability-db');
    expect(s.requests[0]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it('accepts serve false with no current database', async () => {
    const body = { serve: false, policy: 'every', current: null, accepted: [] };
    const s = await serve((_req, res) => json(res, 200, body));
    expect(await fetchServerVulndb(endpoint(s.url), silentLogger)).toEqual(body);
  });

  it('answers unsupported for a server without the route', async () => {
    const s = await serve((_req, res) => problem(res, 404, 'NOT_FOUND'));
    expect(await fetchServerVulndb(endpoint(s.url), silentLogger)).toBe('unsupported');
  });

  it.each([
    [401, 'server answered 401'],
    [500, 'server answered 500'],
  ])('fails on %i', async (status, reason) => {
    const s = await serve((_req, res) => problem(res, status, 'X'));
    expect(await fetchServerVulndb(endpoint(s.url), silentLogger)).toEqual({ failed: reason });
  });

  it('fails on a malformed body', async () => {
    const s = await serve((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/json' });
      res.end('not json');
    });
    expect(await fetchServerVulndb(endpoint(s.url), silentLogger)).toEqual({
      failed: 'unexpected response',
    });
  });

  it('fails on a digest without the sha256 prefix', async () => {
    const bad = { ...meta, current: { ...meta.current, digest: hex } };
    const s = await serve((_req, res) => json(res, 200, bad));
    expect(await fetchServerVulndb(endpoint(s.url), silentLogger)).toEqual({
      failed: 'unexpected response',
    });
  });

  it('fails on an oversized or unknown-policy answer', async () => {
    const s = await serve((_req, res) => json(res, 200, { ...meta, policy: 'weekly' }));
    expect(await fetchServerVulndb(endpoint(s.url), silentLogger)).toEqual({
      failed: 'unexpected response',
    });
  });

  it('fails on metadata over 16 KiB', async () => {
    const s = await serve((_req, res) => {
      const body = Buffer.alloc(16 * 1024 + 1, 0x20);
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': body.length });
      res.end(body);
    });
    expect(await fetchServerVulndb(endpoint(s.url), silentLogger)).toEqual({
      failed: expect.stringContaining('larger than 16384'),
    });
  });

  it('fails when nobody listens, without the token in the reason', async () => {
    const s = await serve((_req, res) => json(res, 200, meta));
    const url = s.url;
    await new Promise<void>((r) => s.server.close(() => r()));
    const got = await fetchServerVulndb(endpoint(url), silentLogger);
    expect(got).toEqual({ failed: expect.stringContaining('connection failed') });
    expect(JSON.stringify(got)).not.toContain(TOKEN);
  });
});

describe('downloadServerVulndb', () => {
  const leftovers = (dir: string) => readdirSync(dir);

  const send = (res: ServerResponse, body: Buffer, status = 200) => {
    res.writeHead(status, {
      'content-type': 'application/gzip',
      'content-length': String(body.length),
      etag: `"${digest}"`,
    });
    res.end(body);
  };

  it('downloads, verifies and renames', async () => {
    const dir = tmp();
    const dest = path.join(dir, 'db.tar.gz');
    const s = await serve((_req, res) => send(res, payload));
    const got = await downloadServerVulndb(endpoint(s.url), digest, payload.length, dest);
    expect(got).toEqual({ ok: true });
    expect(readFileSync(dest).equals(payload)).toBe(true);
    expect(leftovers(dir)).toEqual(['db.tar.gz']);
    expect(s.requests[0]?.url).toBe(`/api/v0/scanner/vulnerability-db/${hex}`);
    expect(s.requests[0]?.headers.authorization).toBe(`Bearer ${TOKEN}`);
  });

  it('writes the archive readable by all (0644): a CI cache step that runs as another user saves it', async () => {
    const dir = tmp();
    const dest = path.join(dir, 'db.tar.gz');
    const s = await serve((_req, res) => send(res, payload));
    const modes: number[] = [];
    const got = await downloadServerVulndb(endpoint(s.url), digest, payload.length, dest, {
      createStream: (file, o) => {
        modes.push(o.mode);
        return createWriteStream(file, o);
      },
    });
    expect(got).toEqual({ ok: true });
    expect(modes).toEqual([0o644]);
    if (process.platform !== 'win32') expect(statSync(dest).mode & 0o777).toBe(0o644);
  });

  const expectFailed = async (
    handler: Parameters<typeof serve>[0],
    opts?: Parameters<typeof downloadServerVulndb>[4],
    size = payload.length,
  ) => {
    const dir = tmp();
    const dest = path.join(dir, 'db.tar.gz');
    const s = await serve(handler);
    const got = await downloadServerVulndb(endpoint(s.url), digest, size, dest, opts);
    expect(got.ok).toBe(false);
    expect(existsSync(dest)).toBe(false);
    expect(leftovers(dir)).toEqual([]);
    return { got, s };
  };

  it('refuses a wrong sha256', async () => {
    const wrong = Buffer.from(payload);
    wrong[0] = wrong[0]! ^ 0xff;
    const { got } = await expectFailed((_req, res) => send(res, wrong));
    expect(got).toEqual({ ok: false, reason: 'checksum mismatch' });
  });

  it('refuses extra bytes', async () => {
    const more = Buffer.concat([payload, Buffer.from('extra')]);
    const { got } = await expectFailed((_req, res) => send(res, more));
    expect(got).toEqual({ ok: false, reason: 'size mismatch' });
  });

  it('refuses extra bytes in a chunked body', async () => {
    const { got } = await expectFailed((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/gzip' });
      res.end(Buffer.concat([payload, Buffer.from('extra')]));
    });
    expect(got).toEqual({ ok: false, reason: 'size mismatch' });
  });

  it('writes nothing after a refused chunk', async () => {
    // A late chunk can already be queued when the first refusal destroys the response; the
    // handler must not write it. The window cannot be forced, so this also holds without the guard.
    const writes: number[] = [];
    const third = Math.ceil(payload.length / 3);
    const { got } = await expectFailed(
      (_req, res) => {
        res.writeHead(200, { 'content-type': 'application/gzip' });
        for (let at = 0; at < payload.length; at += third)
          res.write(payload.subarray(at, at + third));
        for (let i = 0; i < 5; i++) res.write(Buffer.alloc(100, 0x78));
        res.end();
      },
      {
        createStream: (file, o) => {
          const stream = createWriteStream(file, o);
          const write = stream.write.bind(stream) as (chunk: Buffer) => boolean;
          stream.write = ((chunk: Buffer) => {
            writes.push(chunk.length);
            return write(chunk);
          }) as typeof stream.write;
          return stream;
        },
      },
    );
    expect(got).toEqual({ ok: false, reason: 'size mismatch' });
    const total = writes.reduce((a, b) => a + b, 0);
    expect(total).toBeLessThanOrEqual(payload.length);
    const count = writes.length;
    await new Promise((r) => setTimeout(r, 100));
    expect(writes).toHaveLength(count);
  });

  it('refuses a short body', async () => {
    const short = payload.subarray(0, payload.length - 10);
    const { got } = await expectFailed((_req, res) => {
      res.writeHead(200, { 'content-type': 'application/gzip' });
      res.end(short);
    });
    expect(got).toEqual({ ok: false, reason: 'size mismatch' });
  });

  it('refuses a digest without its sha256: prefix', async () => {
    const dir = tmp();
    const s = await serve((_req, res) => send(res, payload));
    const got = await downloadServerVulndb(
      endpoint(s.url),
      hex,
      payload.length,
      path.join(dir, 'db.tar.gz'),
    );
    expect(got).toEqual({ ok: false, reason: 'unexpected response' });
    expect(s.requests).toEqual([]);
  });

  it('refuses a connection closed mid-body', async () => {
    await expectFailed((req, res) => {
      res.writeHead(200, {
        'content-type': 'application/gzip',
        'content-length': String(payload.length),
      });
      res.write(payload.subarray(0, 100));
      setTimeout(() => req.socket.destroy(), 20);
    });
  });

  it('aborts on an idle stall', async () => {
    const { got } = await expectFailed(
      (_req, res) => {
        res.writeHead(200, {
          'content-type': 'application/gzip',
          'content-length': String(payload.length),
        });
        res.write(payload.subarray(0, 100));
      },
      { idleMs: 150 },
    );
    expect(got).toEqual({ ok: false, reason: 'timed out' });
  });

  it('aborts at the total time limit', async () => {
    const { got } = await expectFailed(
      (_req, res) => {
        res.writeHead(200, {
          'content-type': 'application/gzip',
          'content-length': String(payload.length),
        });
        const t = setInterval(() => res.write('x'), 20);
        res.on('close', () => clearInterval(t));
      },
      { idleMs: 5000, totalMs: 200 },
    );
    expect(got).toEqual({ ok: false, reason: 'timed out' });
  });

  it('does not follow a redirect', async () => {
    let followed = 0;
    const other = await serve((_req, res) => {
      followed += 1;
      send(res, payload);
    });
    const { got } = await expectFailed((_req, res) => {
      res.writeHead(302, { location: `${other.url}/x` });
      res.end();
    });
    expect(got).toEqual({ ok: false, reason: 'server answered 302' });
    expect(followed).toBe(0);
  });

  it('fails on a 404', async () => {
    const { got } = await expectFailed((_req, res) => problem(res, 404, 'NOT_FOUND'));
    expect(got).toEqual({ ok: false, reason: 'server answered 404' });
    expect(JSON.stringify(got)).not.toContain(TOKEN);
  });

  it('fails without the token in the reason when nobody listens', async () => {
    const s = await serve((_req, res) => send(res, payload));
    const url = s.url;
    await new Promise<void>((r) => s.server.close(() => r()));
    const got = await downloadServerVulndb(
      endpoint(url),
      digest,
      payload.length,
      path.join(tmp(), 'db.tar.gz'),
    );
    expect(got).toEqual({ ok: false, reason: expect.stringContaining('connection failed') });
    expect(JSON.stringify(got)).not.toContain(TOKEN);
  });

  it('fails before reading when content-length differs from sizeBytes', async () => {
    const opened: string[] = [];
    const { got } = await expectFailed(
      (_req, res) => send(res, payload),
      {
        createStream: (file, o) => {
          opened.push(file);
          return createWriteStream(file, o);
        },
      },
      payload.length - 1,
    );
    expect(got).toEqual({ ok: false, reason: 'size mismatch' });
    expect(opened).toEqual([]);
  });

  it('retries once on 503 with a short retry-after', async () => {
    const dir = tmp();
    const dest = path.join(dir, 'db.tar.gz');
    let n = 0;
    const s = await serve((_req, res) => {
      n += 1;
      if (n === 1) {
        res.writeHead(503, { 'retry-after': '1', 'content-length': '0' });
        res.end();
      } else send(res, payload);
    });
    const got = await downloadServerVulndb(endpoint(s.url), digest, payload.length, dest);
    expect(got).toEqual({ ok: true });
    expect(s.requests).toHaveLength(2);
    expect(readFileSync(dest).equals(payload)).toBe(true);
  });

  it('does not retry when retry-after is above the cap', async () => {
    const dir = tmp();
    const dest = path.join(dir, 'db.tar.gz');
    const s = await serve((_req, res) => {
      res.writeHead(503, { 'retry-after': '30', 'content-length': '0' });
      res.end();
    });
    const got = await downloadServerVulndb(endpoint(s.url), digest, payload.length, dest);
    expect(got.ok).toBe(false);
    expect(s.requests).toHaveLength(1);
    expect(leftovers(dir)).toEqual([]);
  });

  it('fails after a second 503', async () => {
    const dir = tmp();
    const dest = path.join(dir, 'db.tar.gz');
    const s = await serve((_req, res) => {
      res.writeHead(503, { 'retry-after': '0', 'content-length': '0' });
      res.end();
    });
    const got = await downloadServerVulndb(endpoint(s.url), digest, payload.length, dest);
    expect(got.ok).toBe(false);
    expect(s.requests).toHaveLength(2);
  });

  it('fails when the partial file cannot be opened', async () => {
    const dir = tmp();
    const dest = path.join(dir, 'missing', 'db.tar.gz');
    const s = await serve((_req, res) => send(res, payload));
    const got = await downloadServerVulndb(endpoint(s.url), digest, payload.length, dest);
    expect(got.ok).toBe(false);
    expect(leftovers(dir)).toEqual([]);
  });

  it('fails when the final write fails, leaving no dest and no partial', async () => {
    const dir = tmp();
    const dest = path.join(dir, 'db.tar.gz');
    const s = await serve((_req, res) => send(res, payload));
    const got = await downloadServerVulndb(endpoint(s.url), digest, payload.length, dest, {
      createStream: (file, o) => {
        const stream = createWriteStream(file, o);
        stream._final = (cb) => cb(Object.assign(new Error('no space'), { code: 'ENOSPC' }));
        return stream;
      },
    });
    expect(got).toEqual({ ok: false, reason: 'cannot write the database file' });
    expect(leftovers(dir)).toEqual([]);
  });

  it('tracks the partial file for the signal cleanup while it downloads', async () => {
    const paths = (fn: typeof trackWorkDir) => vi.mocked(fn).mock.calls.map(([p]) => p);
    const download = async (body: Buffer) => {
      const dest = path.join(tmp(), 'db.tar.gz');
      const s = await serve((_req, res) => send(res, body));
      const opened: { file: string; tracked: string[]; untracked: string[] }[] = [];
      const got = await downloadServerVulndb(endpoint(s.url), digest, payload.length, dest, {
        createStream: (file, o) => {
          // Before the first byte reaches the file.
          opened.push({ file, tracked: paths(trackWorkDir), untracked: paths(untrackWorkDir) });
          return createWriteStream(file, o);
        },
      });
      expect(opened).toHaveLength(1);
      const { file, tracked, untracked } = opened[0]!;
      expect(file.slice(0, dest.length)).toBe(dest);
      expect(file.slice(dest.length)).toMatch(/^\.[0-9a-f]{12}\.partial$/);
      expect(tracked).toEqual([file]);
      expect(untracked).toEqual([]);
      expect(paths(untrackWorkDir)).toEqual([file]);
      vi.mocked(trackWorkDir).mockClear();
      vi.mocked(untrackWorkDir).mockClear();
      return got;
    };
    expect(await download(payload)).toEqual({ ok: true });
    const wrong = Buffer.from(payload);
    wrong[0] = wrong[0]! ^ 0xff;
    expect(await download(wrong)).toEqual({ ok: false, reason: 'checksum mismatch' });
  });

  describe('TLS', () => {
    const closers: Array<() => void> = [];
    afterEach(() => {
      for (const c of closers.splice(0)) c();
    });
    const tlsServer = async () => {
      const server = https.createServer(
        { cert: TEST_SERVER_CERT_PEM, key: TEST_SERVER_KEY_PEM },
        (_req, res) => {
          res.writeHead(200, { 'content-length': String(payload.length) });
          res.end(payload);
        },
      );
      await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
      closers.push(() => {
        server.closeAllConnections();
        server.close();
      });
      return `https://127.0.0.1:${(server.address() as AddressInfo).port}`;
    };

    it('trusts the configured CA', async () => {
      const dir = mkdtempSync(path.join(tmp(), 'tls-'));
      const dest = path.join(dir, 'db.tar.gz');
      const url = await tlsServer();
      const got = await downloadServerVulndb(
        endpoint(url, { ca: TEST_CA_PEM }),
        digest,
        payload.length,
        dest,
      );
      expect(got).toEqual({ ok: true });
    });

    it('fails without the CA and leaves nothing', async () => {
      const dir = mkdtempSync(path.join(tmp(), 'tls-'));
      const dest = path.join(dir, 'db.tar.gz');
      const url = await tlsServer();
      const got = await downloadServerVulndb(endpoint(url), digest, payload.length, dest);
      expect(got.ok).toBe(false);
      expect(readdirSync(dir)).toEqual([]);
    });
  });
});
