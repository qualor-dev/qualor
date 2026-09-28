import { Readable } from 'node:stream';
import net from 'node:net';
import type { AddressInfo } from 'node:net';
import { gzipSync } from 'node:zlib';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  login,
  organizationId,
  type TestContext,
} from '../../test/app';
import { gzipJson, REPORT_CONTENT_TYPE, sampleReport } from '../../test/reports';
import { LINGER_EXTRA_BYTES_MARGIN, LINGER_TOTAL_MS } from '../http/lingering-close';

const MiB = 1024 * 1024;
const DEFAULT_MAX_COMPRESSED_BYTES = 50 * MiB; // testConfig()'s default upload.maxCompressedBytes

/** Resolves once a server-side socket has fully closed (its bytesRead is then final). */
function serverSocketClosed(socket: net.Socket): Promise<void> {
  if (socket.closed) return Promise.resolve();
  return new Promise((resolve) => socket.once('close', () => resolve()));
}

/**
 * Sends `head` over a raw socket and collects the server's bytes. `onData` may write more (e.g. a
 * body after `100 Continue`); the exchange ends when the server closes the connection, or when
 * `done(text)` returns true (the client then closes its side).
 */
function rawExchange(
  port: number,
  head: string,
  options: {
    onData?: (text: string, socket: net.Socket) => void;
    done?: (text: string) => boolean;
  } = {},
): Promise<string> {
  return new Promise((resolve) => {
    let text = '';
    let finished = false;
    const socket = net.createConnection({ host: '127.0.0.1', port }, () => socket.write(head));
    const finish = (): void => {
      if (finished) return;
      finished = true;
      socket.destroy();
      resolve(text);
    };
    socket.on('data', (d: Buffer) => {
      text += d.toString('utf8');
      options.onData?.(text, socket);
      if (options.done?.(text)) finish();
    });
    socket.on('error', () => {});
    socket.on('close', finish);
  });
}

/**
 * S11/S12 (Important, Review, three rounds): a rejection that never fully reads `request.body`
 * must still close the connection (round 1: without `Connection: close`, Node treats the socket
 * as keep-alive-reusable and drains/discards the *entire* declared Content-Length before it can
 * parse the next request off it), but an immediate close is its own bug (round 2: destroying the
 * socket while the client is still mid-write, with unread bytes still queued in the kernel, sends
 * a TCP RST instead of a clean close, and the client never sees the response). Round 3 (S12) fixed
 * a further gap: measuring drain progress via the request stream's own 'data' events works for a
 * stream the route had paused mid-read, but never fires at all for one Node's own `_dump()` had
 * already detached (an early rejection) — the byte cap silently never triggered there, letting the
 * (much longer) deadline read hundreds of MiB in the meantime; and for a mid-read rejection, a
 * small 'data'-based cap raced past the *socket*'s still-queued bytes and destroyed with data still
 * unread, RSTing anyway.
 *
 * `app.inject()` cannot observe any of this: light-my-request never opens a real socket. These
 * tests do, following the exact scenarios from the S12 re-review: early rejection, mid-read
 * invalid-gzip, mid-read gzip-bomb, a client that never stops, and a body that's already fully
 * arrived.
 */
describe('POST /analyses over a real socket (S11/S12)', () => {
  let ctx: TestContext;
  let token: string;
  let port: number;
  const serverSockets: net.Socket[] = [];
  // A second app with a 1 MiB decompressed limit, for the gzip-bomb case (c).
  let small: TestContext;
  let smallToken: string;
  let smallPort: number;

  beforeAll(async () => {
    ctx = await createTestContext();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const project = await createProject(ctx, admin, {
      organizationId: await organizationId(ctx, 'default'),
      key: 'acme/real-socket',
    });
    // A project token is scoped to its own project: any other ?projectKey= is invisible to it,
    // i.e. exactly "a project the caller can't see".
    token = await createProjectToken(ctx, admin, project.id);
    ctx.app.server.on('connection', (s) => serverSockets.push(s));
    await ctx.app.listen({ port: 0, host: '127.0.0.1' });
    port = (ctx.app.server.address() as AddressInfo).port;

    small = await createTestContext({
      config: {
        upload: { maxCompressedBytes: DEFAULT_MAX_COMPRESSED_BYTES, maxDecompressedBytes: MiB },
      },
    });
    const smallAdmin = await login(small, 'admin', ADMIN_PASSWORD);
    const smallProject = await createProject(small, smallAdmin, {
      organizationId: await organizationId(small, 'default'),
      key: 'acme/small-limits',
    });
    smallToken = await createProjectToken(small, smallAdmin, smallProject.id);
    await small.app.listen({ port: 0, host: '127.0.0.1' });
    smallPort = (small.app.server.address() as AddressInfo).port;
  });

  afterAll(async () => {
    await ctx.close();
    await small.close();
  });

  /** A stream of exactly `totalLength` bytes: `prefix` first, then repeating filler. */
  function paddedStream(prefix: Buffer, totalLength: number, chunkSize = 256 * 1024): Readable {
    let sent = 0;
    let sentPrefix = false;
    return new Readable({
      read() {
        if (!sentPrefix) {
          sentPrefix = true;
          if (prefix.length > 0) {
            sent += prefix.length;
            this.push(prefix);
            return;
          }
        }
        if (sent >= totalLength) {
          this.push(null);
          return;
        }
        const size = Math.min(chunkSize, totalLength - sent);
        sent += size;
        this.push(Buffer.alloc(size, 7));
      },
    });
  }

  interface StreamedResult {
    status: number;
    body: string;
    socket: net.Socket | undefined;
  }

  /** Posts a streamed (chunked, no Content-Length negotiation surprises) body via fetch/undici. */
  async function postStreamed(
    headers: Record<string, string>,
    projectKey: string,
    body: Readable,
    targetPort = port,
  ): Promise<StreamedResult> {
    const before = serverSockets.length;
    const url = `http://127.0.0.1:${targetPort}/api/v0/analyses?projectKey=${encodeURIComponent(projectKey)}`;
    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: Readable.toWeb(body) as ReadableStream<Uint8Array>,
      duplex: 'half',
    });
    const text = await res.text();
    return { status: res.status, body: text, socket: serverSockets[before] };
  }

  it('(a) early 404 with a streamed 45 MiB body (under the cap): delivered, no ECONNRESET, drained gracefully', async () => {
    const bodyLen = 45 * MiB;
    const { status, body, socket } = await postStreamed(
      { ...bearer(token), 'content-type': REPORT_CONTENT_TYPE, 'content-encoding': 'gzip' },
      'acme/not-this-tokens-project',
      paddedStream(Buffer.alloc(0), bodyLen),
    );
    expect(status).toBe(404);
    expect(JSON.parse(body)).toMatchObject({ code: 'PROJECT_NOT_FOUND' });
    // No byte bound here: a 45 MiB body is under the 51 MiB cap, so such an assertion could never
    // fail (and fetch stops sending once it sees the final response anyway). The cap is asserted
    // in (d), with a body that never ends. What this test pins down is delivery: the server
    // socket closes cleanly and the client still read the whole 404.
    expect(socket).toBeDefined();
    await serverSocketClosed(socket!);
  }, 30_000);

  it('(b) mid-read 422 (invalid gzip) with a streamed 40 MiB body: delivered, no ECONNRESET', async () => {
    const bodyLen = 40 * MiB;
    const { status, body } = await postStreamed(
      { ...bearer(token), 'content-type': REPORT_CONTENT_TYPE, 'content-encoding': 'gzip' },
      'acme/real-socket',
      paddedStream(Buffer.alloc(0), bodyLen), // all filler, not valid gzip
    );
    expect(status).toBe(422);
    expect(JSON.parse(body)).toMatchObject({ code: 'REPORT_INVALID' });
  }, 30_000);

  it('(c) mid-read 413 (gzip bomb) with a streamed 40 MiB body: delivered, no ECONNRESET', async () => {
    // Against an app whose decompressed limit is 1 MiB, an 8 MiB run of zeros (~8 KiB gzipped) is
    // already a bomb: no 600 MiB buffer needed to get past the default 500 MiB.
    const bomb = gzipSync(Buffer.alloc(8 * MiB));
    const bodyLen = 40 * MiB;
    const { status, body } = await postStreamed(
      { ...bearer(smallToken), 'content-type': REPORT_CONTENT_TYPE, 'content-encoding': 'gzip' },
      'acme/small-limits',
      paddedStream(bomb, bodyLen),
      smallPort,
    );
    expect(status).toBe(413);
    expect(JSON.parse(body)).toMatchObject({ code: 'REPORT_TOO_LARGE' });
  }, 30_000);

  it('(d) a raw client that never stops writing is cut off by the byte cap, well before the deadline', async () => {
    const startedAt = Date.now();
    const before = serverSockets.length;
    await new Promise<void>((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
        socket.write(
          `POST /api/v0/analyses?projectKey=${encodeURIComponent('acme/not-this-tokens-project')} HTTP/1.1\r\n` +
            `Host: 127.0.0.1\r\nAuthorization: Bearer ${token}\r\nContent-Type: ${REPORT_CONTENT_TYPE}\r\n` +
            // Declared far larger than anything that could naturally finish within this test's
            // timeout, so completion can only come from the byte cap or the total deadline, never
            // from the request simply running out of declared body.
            `Content-Encoding: gzip\r\nContent-Length: ${100 * 1024 * MiB}\r\n\r\n`,
        );
        const chunk = Buffer.alloc(64 * 1024);
        const pump = (): void => {
          while (!socket.destroyed) {
            if (!socket.write(chunk)) {
              socket.once('drain', pump);
              return;
            }
          }
        };
        pump();
      });
      let responseText = '';
      socket.on('data', (d: Buffer) => {
        responseText += d.toString('utf8');
      });
      socket.on('error', () => {}); // the client's own writes error once the server closes — expected
      socket.on('close', () => {
        try {
          expect(responseText).toContain(' 404 ');
          resolve();
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
    });
    // The declared length (100 GiB) is far too large to ever finish naturally within any
    // reasonable test time, so this proves the byte cap is what actually stops it — not the
    // (much longer) total deadline, which this asserts against explicitly: a regression back to
    // measuring by the request stream's 'data' events (which never fire for this early-rejection,
    // dumped-by-Node case, see lingering-close.ts) would fall through to LINGER_TOTAL_MS instead.
    expect(Date.now() - startedAt).toBeLessThan(LINGER_TOTAL_MS / 2);
    // And the cap bounds what the server read: its compressed-body limit plus the linger margin,
    // plus slack for the headers and whatever arrives within one poll interval. The body never
    // ends, so without a working cap this would be whatever arrives in LINGER_TOTAL_MS: gigabytes
    // on loopback.
    const serverSocket = serverSockets[before];
    expect(serverSocket).toBeDefined();
    await serverSocketClosed(serverSocket!);
    expect(serverSocket!.bytesRead).toBeGreaterThan(DEFAULT_MAX_COMPRESSED_BYTES);
    expect(serverSocket!.bytesRead).toBeLessThanOrEqual(
      DEFAULT_MAX_COMPRESSED_BYTES + LINGER_EXTRA_BYTES_MARGIN + 64 * MiB,
    );
  }, 30_000);

  it('(e) an already-fully-arrived body closes promptly (well under 1 s)', async () => {
    const startedAt = Date.now();
    await new Promise<void>((resolve, reject) => {
      const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
        const body = 'not-gzip';
        socket.write(
          `POST /api/v0/analyses?projectKey=${encodeURIComponent('acme/not-this-tokens-project')} HTTP/1.1\r\n` +
            `Host: 127.0.0.1\r\nAuthorization: Bearer ${token}\r\nContent-Type: ${REPORT_CONTENT_TYPE}\r\n` +
            `Content-Encoding: gzip\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n${body}`,
        );
      });
      let responseText = '';
      socket.on('data', (d: Buffer) => {
        responseText += d.toString('utf8');
      });
      socket.on('error', () => {});
      socket.on('close', () => {
        try {
          expect(responseText).toContain(' 404 ');
          resolve();
        } catch (err) {
          reject(err instanceof Error ? err : new Error(String(err)));
        }
      });
    });
    expect(Date.now() - startedAt).toBeLessThan(1_000);
  });

  describe('Expect: 100-continue (RFC 9110 §10.1.1)', () => {
    const uploadHead = (projectKey: string, authorization: string, length: number): string =>
      `POST /api/v0/analyses?projectKey=${encodeURIComponent(projectKey)} HTTP/1.1\r\n` +
      `Host: 127.0.0.1\r\nAuthorization: ${authorization}\r\n` +
      `Content-Type: ${REPORT_CONTENT_TYPE}\r\nContent-Encoding: gzip\r\n` +
      `Content-Length: ${length}\r\nExpect: 100-continue\r\n\r\n`;

    it('rejects an upload for an invisible project, or without credentials, with no 100 Continue', async () => {
      const cases = [
        [`Bearer ${token}`, 404, 'PROJECT_NOT_FOUND'],
        ['Bearer qlr_prj_00000000000000000000000000000000', 401, 'UNAUTHENTICATED'],
      ] as const;
      for (const [authorization, status, code] of cases) {
        // The client holds its (declared 40 MiB) body back until told to continue; the server
        // answers with the final status straight away and closes the connection.
        const text = await rawExchange(
          port,
          uploadHead('acme/not-this-tokens-project', authorization, 40 * MiB),
        );
        expect(text).not.toContain('100 Continue');
        expect(text.startsWith(`HTTP/1.1 ${status} `)).toBe(true);
        expect(text).toContain(`"code":"${code}"`);
      }
    });

    it('sends 100 Continue for a valid upload only after its checks, then accepts the body (202)', async () => {
      const gz = gzipJson(sampleReport({ projectKey: 'acme/real-socket' }));
      let sentBody = false;
      const text = await rawExchange(
        port,
        uploadHead('acme/real-socket', `Bearer ${token}`, gz.length),
        {
          onData: (received, socket) => {
            if (!sentBody && received.includes('\r\n\r\n')) {
              sentBody = true;
              socket.write(gz);
            }
          },
          done: (received) => received.includes('"statusUrl"'),
        },
      );
      expect(sentBody).toBe(true);
      expect(text).toMatch(/^HTTP\/1\.1 100 Continue\r\n\r\nHTTP\/1\.1 202 /);
    });

    it('S15: recognises every Expect value Node treats as 100-continue', async () => {
      for (const expect100 of ['100-Continue', '100-continue, x-trace']) {
        const gz = gzipJson(sampleReport({ projectKey: 'acme/real-socket' }));
        let sentBody = false;
        const head = uploadHead('acme/real-socket', `Bearer ${token}`, gz.length).replace(
          'Expect: 100-continue',
          `Expect: ${expect100}`,
        );
        const text = await rawExchange(port, head, {
          onData: (received, socket) => {
            if (!sentBody && received.includes('\r\n\r\n')) {
              sentBody = true;
              socket.write(gz);
            }
          },
          done: (received) => received.includes('"statusUrl"'),
        });
        expect(text, expect100).toMatch(/^HTTP\/1\.1 100 Continue\r\n\r\nHTTP\/1\.1 202 /);
      }
    });

    it('S15: still delivers the rejection to a client that sends the body without waiting for 100 Continue', async () => {
      // RFC 9110 lets a client stop waiting; the CLI does after 10 s. The body is then already
      // on its way when the server refuses, and closing at once would reset the connection.
      const bodyLen = 20 * MiB;
      const text = await new Promise<string>((resolve) => {
        let received = '';
        const socket = net.createConnection({ host: '127.0.0.1', port }, () => {
          socket.write(uploadHead('acme/not-this-tokens-project', `Bearer ${token}`, bodyLen));
          paddedStream(Buffer.alloc(0), bodyLen).pipe(socket);
        });
        socket.on('data', (d: Buffer) => {
          received += d.toString('utf8');
        });
        socket.on('error', () => resolve(`ERROR ${received}`));
        socket.on('close', () => resolve(received));
      });
      expect(text.startsWith('HTTP/1.1 404 ')).toBe(true);
      expect(text).toContain('"code":"PROJECT_NOT_FOUND"');
    }, 30_000);

    it('sends 100 Continue for other body-carrying routes only once authentication has passed', async () => {
      const body = JSON.stringify({ username: 'admin', password: 'wrong password, sorry' });
      let sentBody = false;
      const text = await rawExchange(
        port,
        'POST /api/v0/auth/login HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n' +
          `Content-Length: ${Buffer.byteLength(body)}\r\nExpect: 100-continue\r\n\r\n`,
        {
          onData: (received, socket) => {
            if (!sentBody && received.includes('\r\n\r\n')) {
              sentBody = true;
              socket.write(body);
            }
          },
          done: (received) => received.includes('"code"'),
        },
      );
      expect(text).toMatch(/^HTTP\/1\.1 100 Continue\r\n\r\nHTTP\/1\.1 401 /);
      const unauthenticated = await rawExchange(
        port,
        'PUT /api/v0/auth/me/password HTTP/1.1\r\nHost: 127.0.0.1\r\n' +
          'Content-Type: application/json\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n',
        { done: (received) => received.includes('"code"') },
      );
      expect(unauthenticated).not.toContain('100 Continue');
      expect(unauthenticated.startsWith('HTTP/1.1 401 ')).toBe(true);
    });
  });
});
