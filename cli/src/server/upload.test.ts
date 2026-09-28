import { randomBytes } from 'node:crypto';
import { rmSync, writeFileSync } from 'node:fs';
import type { IncomingMessage } from 'node:http';
import net from 'node:net';
import path from 'node:path';
import { Readable } from 'node:stream';
import { gzipSync } from 'node:zlib';
import { afterEach, describe, expect, it } from 'vitest';
import { json, problem, useTestServers } from '../../test/http';
import { useTempDirs } from '../../test/tmp';
import { CliError } from '../errors';
import { silentLogger } from '../log';
import { request } from './http';
import {
  MAX_UPLOAD_ATTEMPTS,
  MAX_UPLOAD_RETRY_WAIT_MS,
  REPORT_CONTENT_TYPE,
  uploadReport,
} from './upload';

const tmp = useTempDirs();
const serve = useTestServers();
const ID = '0192a4c6-1c2e-7a3b-9f00-0000000000aa';
const TOKEN = 'qlr_prj_secret';

function gzFile(): { file: string; size: number; bytes: Buffer } {
  const bytes = gzipSync(
    Buffer.from(JSON.stringify({ schemaVersion: 1, pad: 'x'.repeat(200_000) })),
  );
  const file = path.join(tmp(), 'report.json.gz');
  writeFileSync(file, bytes);
  return { file, size: bytes.length, bytes };
}

/** An incompressible file, large enough that socket buffers cannot swallow it at once. */
function bigFile(bytes: number): { file: string; size: number } {
  const file = path.join(tmp(), 'big.json.gz');
  writeFileSync(file, randomBytes(bytes));
  return { file, size: bytes };
}

const ep = (url: string, timeoutMs = 5_000) => ({ url, token: TOKEN, timeoutMs });

async function uploadError(p: Promise<unknown>): Promise<CliError> {
  const err: unknown = await p.catch((e: unknown) => e);
  if (!(err instanceof CliError)) throw new Error(`expected a CliError, got ${String(err)}`);
  expect(err.message).not.toContain(TOKEN);
  return err;
}

/** Counts the request body bytes that ever reach the server, on every request. */
function countBody(req: IncomingMessage, counter: { bytes: number }): void {
  req.on('data', (c: Buffer) => (counter.bytes += c.length));
}

const accepted = { analysisId: ID, status: 'queued', statusUrl: `/api/v0/analyses/${ID}` };

describe('uploadReport', () => {
  it('streams the gzip file with Expect: 100-continue, Content-Length and ?projectKey=', async () => {
    const { file, size, bytes } = gzFile();
    const { url, requests } = await serve((_req, res) => json(res, 202, accepted));
    expect(
      await uploadReport(ep(url), { projectKey: 'acme/app', file, size }, { log: silentLogger }),
    ).toEqual({ analysisId: ID });
    const r = requests[0];
    expect(r?.method).toBe('POST');
    expect(r?.url).toBe('/api/v0/analyses?projectKey=acme%2Fapp');
    expect(r?.headers).toMatchObject({
      expect: '100-continue',
      'content-length': String(size),
      'content-type': REPORT_CONTENT_TYPE,
      'content-encoding': 'gzip',
      authorization: `Bearer ${TOKEN}`,
    });
    expect(Buffer.compare(r?.body ?? Buffer.alloc(0), bytes)).toBe(0);
  });

  it('never sends the body when the server refuses before 100 Continue', async () => {
    const { file, size } = gzFile();
    let received = 0;
    const { url } = await serve(
      (req, res) => {
        req.on('data', (c: Buffer) => (received += c.length));
        problem(res, 401, 'UNAUTHENTICATED');
      },
      { readBody: false },
    );
    const err: unknown = await uploadReport(
      ep(url),
      { projectKey: 'acme/app', file, size },
      { log: silentLogger },
    ).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CliError);
    expect((err as CliError).exitCode).toBe(5);
    expect((err as CliError).message).not.toContain('qlr_prj_secret');
    await new Promise((r) => setTimeout(r, 200));
    expect(received).toBe(0);
  });

  it.each([
    [401, 'UNAUTHENTICATED', 5],
    [403, 'TOKEN_NOT_ALLOWED', 5],
    [404, 'PROJECT_NOT_FOUND', 4],
    [413, 'REPORT_TOO_LARGE', 4],
    [503, 'UPLOADS_BUSY', 4],
  ])(
    'never sends a byte of the body after an early %i %s, even while it lingers',
    async (status, code, exitCode) => {
      // Like the Qualor server (S15): it refuses before 100 Continue, then keeps reading.
      const counter = { bytes: 0 };
      const { url, requests } = await serve(
        (req, res) => {
          countBody(req, counter);
          problem(res, status, code);
        },
        { readBody: false },
      );
      const { file, size } = bigFile(2 * 1024 * 1024);
      const err = await uploadError(
        uploadReport(
          ep(url),
          { projectKey: 'acme/app', file, size },
          { log: silentLogger, wait: () => Promise.resolve() },
        ),
      );
      expect(err.exitCode).toBe(exitCode);
      await new Promise((r) => setTimeout(r, 300));
      expect(counter.bytes).toBe(0);
      expect(requests.length).toBe(status === 503 ? MAX_UPLOAD_ATTEMPTS : 1);
    },
  );

  it.each([
    [404, 'PROJECT_NOT_FOUND', 4, 'project acme/app does not exist on the server'],
    [404, 'NOT_FOUND', 4, 'no report upload endpoint'],
    [413, 'REPORT_TOO_LARGE', 4, 'larger than the server accepts'],
    [415, 'UNSUPPORTED_ENCODING', 4, '415 UNSUPPORTED_ENCODING'],
    [422, 'REPORT_INVALID', 4, '422 REPORT_INVALID'],
    [403, 'TOKEN_NOT_ALLOWED', 5, '403 TOKEN_NOT_ALLOWED'],
    [500, 'INTERNAL_ERROR', 4, '500 INTERNAL_ERROR'],
  ])('maps %i %s to exit %i', async (status, code, exitCode, text) => {
    const { file, size } = gzFile();
    const { url } = await serve((_req, res) => problem(res, status, code), { readBody: false });
    const err: unknown = await uploadReport(
      ep(url),
      { projectKey: 'acme/app', file, size },
      { log: silentLogger },
    ).catch((e: unknown) => e);
    expect(err).toMatchObject({ exitCode });
    expect((err as Error).message).toContain(text);
  });

  it('never shows the token, even when the server echoes it', async () => {
    const { file, size } = gzFile();
    const { url } = await serve(
      (_req, res) => problem(res, 422, 'REPORT_INVALID', `bad token ${TOKEN} in the report`),
      { readBody: false },
    );
    const err = await uploadError(
      uploadReport(ep(url), { projectKey: 'a/b', file, size }, { log: silentLogger }),
    );
    expect(err.message).toContain('422 REPORT_INVALID');
  });

  it('fails with exit 4 on a 202 that is not an upload answer', async () => {
    const { file, size } = gzFile();
    const { url } = await serve((_req, res) => json(res, 202, { analysisId: 'nope' }));
    const err = await uploadError(
      uploadReport(ep(url), { projectKey: 'a/b', file, size }, { log: silentLogger }),
    );
    expect(err.exitCode).toBe(4);
  });

  it('retries 503 UPLOADS_BUSY after Retry-After, a bounded number of times', async () => {
    const { file, size } = gzFile();
    let calls = 0;
    const { url } = await serve(
      (_req, res) => {
        calls += 1;
        if (calls < 3) {
          problem(res, 503, 'UPLOADS_BUSY');
          return;
        }
        res.writeContinue();
        json(res, 202, { analysisId: ID, status: 'queued', statusUrl: `/api/v0/analyses/${ID}` });
      },
      { readBody: false },
    );
    const waits: number[] = [];
    const wait = (ms: number) => {
      waits.push(ms);
      return Promise.resolve();
    };
    expect(
      await uploadReport(ep(url), { projectKey: 'a/b', file, size }, { log: silentLogger, wait }),
    ).toEqual({ analysisId: ID });
    expect(waits).toEqual([2_000, 2_000]);

    calls = -100;
    const err: unknown = await uploadReport(
      ep(url),
      { projectKey: 'a/b', file, size },
      { log: silentLogger, wait },
    ).catch((e: unknown) => e);
    expect(err).toMatchObject({ exitCode: 4 });
    expect((err as Error).message).toContain('503 UPLOADS_BUSY');
  });

  it('honours Retry-After within [1 s, 30 s] and bounds the total wait', async () => {
    const { file, size } = gzFile();
    const retryAfter = ['7', '0', '999', '999', '999'];
    let calls = 0;
    const { url } = await serve(
      (_req, res) => {
        const value = retryAfter[calls] ?? '1';
        calls += 1;
        res.writeHead(503, {
          'content-type': 'application/problem+json',
          'retry-after': value,
          connection: 'close',
        });
        res.end(JSON.stringify({ status: 503, code: 'UPLOADS_BUSY', title: 'busy' }));
      },
      { readBody: false },
    );
    const waits: number[] = [];
    const err = await uploadError(
      uploadReport(
        ep(url),
        { projectKey: 'a/b', file, size },
        {
          log: silentLogger,
          wait: (ms) => {
            waits.push(ms);
            return Promise.resolve();
          },
        },
      ),
    );
    expect(err.exitCode).toBe(4);
    expect(err.message).toContain('503 UPLOADS_BUSY');
    // 7 s, then the 1 s floor, then 30 s caps until the total budget is spent.
    expect(waits).toEqual([7_000, 1_000, 30_000, MAX_UPLOAD_RETRY_WAIT_MS - 38_000]);
    expect(waits.reduce((a, b) => a + b, 0)).toBeLessThanOrEqual(MAX_UPLOAD_RETRY_WAIT_MS);
    expect(calls).toBe(MAX_UPLOAD_ATTEMPTS);
  });

  it('does not retry a 503 that is not UPLOADS_BUSY', async () => {
    const { file, size } = gzFile();
    const { url, requests } = await serve((_req, res) => problem(res, 503, 'MAINTENANCE'), {
      readBody: false,
    });
    const err = await uploadError(
      uploadReport(
        ep(url),
        { projectKey: 'a/b', file, size },
        { log: silentLogger, wait: () => Promise.resolve() },
      ),
    );
    expect(err.exitCode).toBe(4);
    expect(requests).toHaveLength(1);
  });

  it('fails with exit 4, and releases the file, when the server resets the connection mid-body', async () => {
    const { file, size } = bigFile(8 * 1024 * 1024);
    const { url } = await serve(
      (req, res) => {
        res.writeContinue();
        let got = 0;
        req.on('data', (c: Buffer) => {
          got += c.length;
          if (got > 256 * 1024) req.socket.resetAndDestroy();
        });
      },
      { readBody: false },
    );
    const err = await uploadError(
      uploadReport(ep(url), { projectKey: 'a/b', file, size }, { log: silentLogger }),
    );
    expect(err.exitCode).toBe(4);
    expect(err.message).toMatch(/cannot reach/);
    // The read stream is closed: on Windows an open handle would make this fail with EBUSY.
    rmSync(file);
  });

  it(
    'keeps uploading to a server that reads slowly, past the timeout, as long as it progresses',
    { timeout: 30_000 },
    async () => {
      // The server pauses 300 ms after every 4 MiB of the first 24 MiB (about 13 MiB/s): 1.8 s
      // in all, far over the 1 s timeout. Progress shows when the socket takes more bytes, and
      // loopback buffers hold several MiB (about 0.4 s at this rate), so the timeout exceeds that.
      // The rest is read at full speed: once the client has handed over its last byte, it cannot
      // see the server work through what the socket buffers still hold.
      const { file, size } = bigFile(32 * 1024 * 1024);
      const step = 4 * 1024 * 1024;
      let got = 0;
      let pauses = 0;
      const { url, requests } = await serve(
        (req, res) => {
          res.writeContinue();
          req.on('data', (c: Buffer) => {
            const before = got;
            got += c.length;
            if (Math.floor(got / step) > Math.floor(before / step) && before < (size * 3) / 4) {
              pauses += 1;
              req.pause();
              setTimeout(() => req.resume(), 300);
            }
          });
          req.on('end', () => json(res, 202, accepted));
        },
        { readBody: false },
      );
      const started = Date.now();
      expect(
        await uploadReport(
          ep(url, 1_000),
          { projectKey: 'a/b', file, size },
          { log: silentLogger },
        ),
      ).toEqual({ analysisId: ID });
      expect(requests).toHaveLength(1);
      expect(got).toBe(size);
      expect(pauses).toBe(6);
      // The upload outlasted the (inactivity) timeout: only progress kept it alive.
      expect(Date.now() - started).toBeGreaterThan(1_500);
      rmSync(file);
    },
  );

  it('fails a server that stops reading the body after the inactivity timeout', async () => {
    const { file, size } = bigFile(32 * 1024 * 1024);
    const { url } = await serve(
      (req, res) => {
        res.writeContinue();
        req.pause(); // never reads: the socket buffers fill, then nothing moves
      },
      { readBody: false },
    );
    const started = Date.now();
    const err = await uploadError(
      uploadReport(ep(url, 500), { projectKey: 'a/b', file, size }, { log: silentLogger }),
    );
    expect(err.exitCode).toBe(4);
    expect(err.message).toContain('no response within');
    expect(Date.now() - started).toBeLessThan(10_000);
    rmSync(file);
  });

  it('stops sending the body once the server has answered mid-body', async () => {
    const { file, size } = bigFile(24 * 1024 * 1024);
    const counter = { bytes: 0 };
    const { url } = await serve(
      (req, res) => {
        res.writeContinue();
        let answered = false;
        req.on('data', (c: Buffer) => {
          counter.bytes += c.length;
          if (!answered && counter.bytes > 256 * 1024) {
            answered = true;
            // Lingers like the Qualor server (S15): keeps draining the body instead of closing
            // the socket at once (which would reset it), so the client reads this answer.
            const socket = req.socket;
            const close = socket.destroySoon.bind(socket);
            socket.destroySoon = () => void req.once('end', close);
            problem(res, 413, 'REPORT_TOO_LARGE');
          }
        });
      },
      { readBody: false },
    );
    const err = await uploadError(
      uploadReport(ep(url), { projectKey: 'a/b', file, size }, { log: silentLogger }),
    );
    expect(err.exitCode).toBe(4);
    expect(err.message).toContain('413');
    await new Promise((r) => setTimeout(r, 500));
    expect(counter.bytes).toBeLessThan(size);
    rmSync(file);
  });
});

describe('request with a body', () => {
  it('sends the body anyway when no 100 Continue comes (a proxy that ignores Expect)', async () => {
    const { url, requests } = await serve(
      (req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', () => json(res, 200, { got: Buffer.concat(chunks).toString() }));
      },
      { readBody: false },
    );
    const res = await request(ep(url), {
      method: 'POST',
      path: 'x',
      body: { stream: () => Readable.from([Buffer.from('hello')]), contentLength: 5 },
      continueTimeoutMs: 100,
    });
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ got: 'hello' });
    expect(requests[0]?.headers.expect).toBe('100-continue');
  });

  it('never waits for 100 Continue longer than the inactivity timeout allows', async () => {
    // A proxy that ignores Expect, with server.timeoutSeconds shorter than the 10 s default wait.
    const { url } = await serve(
      (req, res) => {
        const chunks: Buffer[] = [];
        req.on('data', (c: Buffer) => chunks.push(c));
        req.on('end', () => json(res, 200, { got: Buffer.concat(chunks).toString() }));
      },
      { readBody: false },
    );
    const res = await request(ep(url, 600), {
      method: 'POST',
      path: 'x',
      body: { stream: () => Readable.from([Buffer.from('hello')]), contentLength: 5 },
    });
    expect(JSON.parse(res.body)).toEqual({ got: 'hello' });
  });

  it('closes the body stream after an answer mid-body and after a connection reset', async () => {
    const declared = 64 * 1024 * 1024;
    const body = () => {
      let sent = 0;
      return new Readable({
        read() {
          if (sent >= declared) {
            this.push(null);
            return;
          }
          sent += 64 * 1024;
          this.push(Buffer.alloc(64 * 1024, 1));
        },
      });
    };
    const lingering = await serve(
      (req, res) => {
        res.writeContinue();
        req.once('data', () => {
          const socket = req.socket;
          const close = socket.destroySoon.bind(socket);
          socket.destroySoon = () => void req.once('end', close);
          problem(res, 413, 'REPORT_TOO_LARGE');
        });
      },
      { readBody: false },
    );
    let stream: Readable | undefined;
    const res = await request(ep(lingering.url), {
      method: 'POST',
      path: 'x',
      body: {
        stream: () => (stream = body()),
        contentLength: declared,
      },
    });
    expect(res.status).toBe(413);
    expect(stream?.destroyed).toBe(true);

    const resetting = await serve(
      (req, res) => {
        res.writeContinue();
        req.once('data', () => req.socket.resetAndDestroy());
      },
      { readBody: false },
    );
    const err = await uploadError(
      request(ep(resetting.url), {
        method: 'POST',
        path: 'x',
        body: { stream: () => (stream = body()), contentLength: declared },
      }),
    );
    expect(err.exitCode).toBe(4);
    expect(stream?.destroyed).toBe(true);
  });

  it('fails with exit 4 when the body cannot be read', async () => {
    const { url } = await serve((_req, res) => json(res, 200, {}));
    const err: unknown = await request(ep(url), {
      method: 'POST',
      path: 'x',
      body: {
        stream: () =>
          new Readable({
            read() {
              this.destroy(new Error('disk gone'));
            },
          }),
        contentLength: 5,
      },
    }).catch((e: unknown) => e);
    expect(err).toMatchObject({ exitCode: 4 });
  });
});

describe('request with a body: the HTTP/1.1 exchange', () => {
  /** A raw server: `answer(head, socket)` runs once the request head has arrived. */
  async function rawServer(
    answer: (head: string, socket: net.Socket) => void,
  ): Promise<{ url: string; connections: () => number }> {
    let connections = 0;
    const server = net.createServer((socket) => {
      connections += 1;
      let text = '';
      let answered = false;
      socket.on('error', () => undefined);
      socket.on('data', (d: Buffer) => {
        text += d.toString('latin1');
        if (!answered && text.includes('\r\n\r\n')) {
          answered = true;
          answer(text.slice(0, text.indexOf('\r\n\r\n')), socket);
        }
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    rawServers.push(server);
    const { port } = server.address() as net.AddressInfo;
    return { url: `http://127.0.0.1:${port}`, connections: () => connections };
  }
  const rawServers: net.Server[] = [];
  afterEach(() => {
    for (const s of rawServers.splice(0)) s.close();
  });
  const post = (url: string, extra: Partial<Parameters<typeof request>[1]> = {}) =>
    request(ep(url), {
      method: 'POST',
      path: 'x',
      body: { stream: () => Readable.from([Buffer.from('hello')]), contentLength: 5 },
      ...extra,
    });

  it('writes one well-formed head: path, query, Host, Content-Length, Expect, Connection', async () => {
    let seen = '';
    const { url } = await rawServer((head, socket) => {
      seen = head;
      socket.end('HTTP/1.1 204 No Content\r\n\r\n');
    });
    const res = await request(ep(`${url}/base`), {
      method: 'POST',
      path: 'api/v0/analyses',
      query: { projectKey: 'acme/app' },
      body: { stream: () => Readable.from([Buffer.from('hello')]), contentLength: 5 },
    });
    expect(res.status).toBe(204);
    const [line, ...headers] = seen.split('\r\n');
    expect(line).toBe('POST /base/api/v0/analyses?projectKey=acme%2Fapp HTTP/1.1');
    expect(headers).toEqual(
      expect.arrayContaining([
        `host: ${new URL(url).host}`,
        'content-length: 5',
        'expect: 100-continue',
        'connection: close',
        `authorization: Bearer ${TOKEN}`,
      ]),
    );
  });

  it.each([
    [401, 'UNAUTHENTICATED', 5],
    [403, 'TOKEN_NOT_ALLOWED', 5],
    [413, 'REPORT_TOO_LARGE', 4],
    [503, 'UPLOADS_BUSY', 4],
  ])(
    'sends no body byte before an answer, nor after an early %i (socket-level count)',
    async (status, code, exitCode) => {
      // The refusal comes 300 ms after the head: an eager client would have sent bytes by then.
      let afterHead = 0;
      const { url } = await rawServer((_head, socket) => {
        socket.on('data', (d: Buffer) => (afterHead += d.length));
        setTimeout(() => {
          const body = JSON.stringify({ status, code });
          socket.write(
            `HTTP/1.1 ${status} X\r\ncontent-length: ${body.length}\r\nconnection: close\r\n\r\n${body}`,
          );
        }, 300);
      });
      const { file, size } = bigFile(2 * 1024 * 1024);
      const err = await uploadError(
        uploadReport(
          ep(url),
          { projectKey: 'a/b', file, size },
          { log: silentLogger, wait: () => Promise.resolve() },
        ),
      );
      expect(err.exitCode).toBe(exitCode);
      await new Promise((r) => setTimeout(r, 300));
      expect(afterHead).toBe(0);
    },
  );

  it('refuses a header value that could split the request, before connecting', async () => {
    const { url, connections } = await rawServer((_head, socket) => socket.destroy());
    const err = await uploadError(post(url, { headers: { 'x-evil': 'a\r\nx-injected: 1' } }));
    expect(err.exitCode).toBe(4);
    expect(err.message).toContain('ERR_INVALID_CHAR');
    expect(err.message).not.toContain('injected');
    expect(connections()).toBe(0);
  });

  it('reads chunked, close-delimited and informational (1xx) answers', async () => {
    const chunked = await rawServer((_head, socket) => {
      socket.write('HTTP/1.1 100 Continue\r\n\r\n');
      setTimeout(() => {
        socket.write('HTTP/1.1 202 Accepted\r\nTransfer-Encoding: chunked\r\n\r\n');
        socket.write('3\r\n{"a\r\n');
        socket.end('4;ext=1\r\n":1}\r\n0\r\nx-trailer: y\r\n\r\n');
      }, 50);
    });
    expect(await post(chunked.url)).toMatchObject({ status: 202, body: '{"a":1}' });

    const closeDelimited = await rawServer((_head, socket) => {
      socket.end(
        'HTTP/1.1 103 Early Hints\r\nlink: </x>\r\n\r\nHTTP/1.1 401 Unauthorized\r\n\r\n{"code":"X"}',
      );
    });
    expect(await post(closeDelimited.url)).toMatchObject({ status: 401, body: '{"code":"X"}' });
  });

  it.each([
    ['not HTTP', 'SSH-2.0-OpenSSH\r\n\r\n', 'did not answer with HTTP/1.1'],
    ['a bad header', 'HTTP/1.1 200 OK\r\nno colon here\r\n\r\n', 'invalid response header'],
    ['a bad Content-Length', 'HTTP/1.1 200 OK\r\ncontent-length: 5, 6\r\n\r\n', 'Content-Length'],
    ['a bad chunk', 'HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\nzz\r\n', 'chunked'],
    [
      'a declared oversized body',
      'HTTP/1.1 200 OK\r\ncontent-length: 2000000\r\n\r\n',
      'larger than',
    ],
    ['an endless head', `HTTP/1.1 200 OK\r\n${'x-pad: 1\r\n'.repeat(8_000)}`, 'head is too large'],
    [
      'a truncated body',
      'HTTP/1.1 200 OK\r\ncontent-length: 10\r\n\r\nabc',
      'before the response was complete',
    ],
  ])('fails with exit 4 on %s', async (_name, answer, text) => {
    const { url } = await rawServer((_head, socket) => socket.end(answer));
    const err = await uploadError(post(url));
    expect(err.exitCode).toBe(4);
    expect(err.message).toContain(text);
  });

  it('fails an oversized chunked or close-delimited answer', async () => {
    const big = 'x'.repeat(64 * 1024);
    const chunkedBig = await rawServer((_head, socket) => {
      socket.write('HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n');
      for (let i = 0; i < 20; i++) socket.write(`${big.length.toString(16)}\r\n${big}\r\n`);
    });
    const e1 = await uploadError(post(chunkedBig.url, { maxResponseBytes: 512 * 1024 }));
    expect(e1.message).toContain('larger than');
    const closeBig = await rawServer((_head, socket) => {
      socket.write('HTTP/1.1 200 OK\r\n\r\n');
      for (let i = 0; i < 20; i++) socket.write(big);
    });
    const e2 = await uploadError(post(closeBig.url, { maxResponseBytes: 512 * 1024 }));
    expect(e2.message).toContain('larger than');
  });

  it('fails a body stream that is shorter or longer than its Content-Length', async () => {
    for (const [data, text] of [
      ['hell', 'shorter than declared'],
      ['hello!', 'longer than declared'],
    ] as const) {
      const { url } = await rawServer((_head, socket) => {
        socket.write('HTTP/1.1 100 Continue\r\n\r\n');
      });
      const err = await uploadError(
        request(ep(url), {
          method: 'POST',
          path: 'x',
          body: { stream: () => Readable.from([Buffer.from(data)]), contentLength: 5 },
        }),
      );
      expect(err.message, data).toContain(text);
    }
  });

  it('fails with exit 4 when nothing listens', async () => {
    const { url } = await rawServer(() => undefined);
    const port = new URL(url).port;
    rawServers.splice(0).forEach((s) => s.close());
    await new Promise((r) => setTimeout(r, 50));
    const err = await uploadError(post(`http://127.0.0.1:${port}`));
    expect(err.message).toMatch(/ECONNREFUSED|closed without a response/);
  });
});
