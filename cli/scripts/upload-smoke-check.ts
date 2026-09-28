import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync, statSync, writeFileSync } from 'node:fs';
import net, { type AddressInfo } from 'node:net';
import tls from 'node:tls';
import os from 'node:os';
import path from 'node:path';
import { Readable } from 'node:stream';
import type { Report } from '@qualor/shared';
import { CliError } from '../src/errors';
import { silentLogger } from '../src/log';
import { withPrivateReportFile } from '../src/scan/report';
import { request } from '../src/server/http';
import { uploadReport } from '../src/server/upload';
import { startConnectProxy } from '../test/proxy';
import { TEST_CA_PEM, TEST_SERVER_CERT_PEM, TEST_SERVER_KEY_PEM } from '../test/tls';

const TOKEN = 'qlr_prj_upload_smoke_token';
const ID = '0192a4c6-1c2e-7a3b-9f00-0000000000aa';
const ACCEPTED = JSON.stringify({ analysisId: ID, status: 'queued', statusUrl: `/x/${ID}` });

interface Exchange {
  /** Everything before the blank line, lower-cased header names. */
  head: { line: string; headers: Map<string, string> };
  socket: net.Socket;
  /** Body bytes received so far (also after the handler answered). */
  body: () => number;
  /** Resolves with the body once `n` bytes have arrived. */
  readBody: (n: number) => Promise<Buffer>;
  /** Pauses reading for `ms` after every `bytes` received, up to `until` (a slow reader). */
  trickle: (bytes: number, ms: number, until: number) => void;
}

function response(status: string, body: string, extra = ''): string {
  return (
    `HTTP/1.1 ${status}\r\ncontent-type: application/json\r\n` +
    `content-length: ${Buffer.byteLength(body)}\r\nconnection: close\r\n${extra}\r\n${body}`
  );
}

/**
 * A raw HTTP/1.1 server on 127.0.0.1 (`node:net`, so it behaves the same under Node and Bun,
 * whose `node:http` servers differ): the test decides byte by byte what the client sees.
 */
async function rawServer(
  handle: (x: Exchange) => void,
): Promise<{ url: string; close: () => void; exchanges: Exchange[] }> {
  const exchanges: Exchange[] = [];
  const server = net.createServer((socket) => {
    let buffer = Buffer.alloc(0);
    let exchange: Exchange | undefined;
    let bodyBytes = 0;
    let trickle = { bytes: 0, ms: 0, until: 0 };
    let waiter: { n: number; resolve: (b: Buffer) => void } | undefined;
    const bodyChunks: Buffer[] = [];
    const deliver = () => {
      if (waiter !== undefined && bodyBytes >= waiter.n) {
        const w = waiter;
        waiter = undefined;
        w.resolve(Buffer.concat(bodyChunks).subarray(0, w.n));
      }
    };
    socket.on('error', () => undefined);
    socket.on('data', (d: Buffer) => {
      if (exchange !== undefined) {
        const before = bodyBytes;
        bodyBytes += d.length;
        bodyChunks.push(d);
        deliver();
        if (
          trickle.bytes > 0 &&
          before < trickle.until &&
          Math.floor(bodyBytes / trickle.bytes) > Math.floor(before / trickle.bytes)
        ) {
          socket.pause();
          setTimeout(() => socket.resume(), trickle.ms);
        }
        return;
      }
      buffer = Buffer.concat([buffer, d]);
      const end = buffer.indexOf('\r\n\r\n');
      if (end < 0) return;
      const [line = '', ...rest] = buffer.subarray(0, end).toString('latin1').split('\r\n');
      const headers = new Map<string, string>();
      for (const h of rest) {
        const i = h.indexOf(':');
        headers.set(h.slice(0, i).trim().toLowerCase(), h.slice(i + 1).trim());
      }
      const early = buffer.subarray(end + 4);
      bodyBytes = early.length;
      if (early.length > 0) bodyChunks.push(early);
      exchange = {
        head: { line, headers },
        socket,
        body: () => bodyBytes,
        readBody: (n) =>
          new Promise((resolve) => {
            waiter = { n, resolve };
            deliver();
          }),
        trickle: (bytes, ms, until) => {
          trickle = { bytes, ms, until };
        },
      };
      exchanges.push(exchange);
      handle(exchange);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const { port } = server.address() as AddressInfo;
  return {
    url: `http://127.0.0.1:${port}`,
    exchanges,
    close: () => {
      for (const x of exchanges) x.socket.destroy();
      server.close();
    },
  };
}

type Check = (file: string, bytes: Buffer) => Promise<string | null>;

/**
 * A server on 127.0.0.1 that hands every accepted socket to `handle`: plain TCP, or TLS with the
 * test certificate. `node:net`/`node:tls` behave the same under Node and Bun.
 */
async function socketServer(
  handle: (socket: net.Socket) => void,
  o: { tls?: boolean } = {},
): Promise<{ port: number; close: () => void }> {
  const sockets: net.Socket[] = [];
  const onSocket = (socket: net.Socket) => {
    sockets.push(socket);
    socket.on('error', () => undefined);
    handle(socket);
  };
  const server =
    o.tls === true
      ? tls.createServer({ cert: TEST_SERVER_CERT_PEM, key: TEST_SERVER_KEY_PEM }, onSocket)
      : net.createServer(onSocket);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return {
    port: (server.address() as AddressInfo).port,
    close: () => {
      for (const socket of sockets) socket.destroy();
      server.close();
    },
  };
}

/** Answers the first request head on `socket` with a small JSON body. */
function answerJson(socket: net.Socket): void {
  let head = '';
  socket.on('data', (d: Buffer) => {
    head += d.toString('latin1');
    if (head.includes('\r\n\r\n')) socket.end(response('200 OK', '{"ok":true}'));
  });
}

/** A JSON exchange that must fail with exit 4, "no response within 1 s", in bounded time. */
async function expectDeadline(url: string): Promise<string | null> {
  const started = Date.now();
  const err: unknown = await request(
    { url, token: TOKEN, timeoutMs: 1_000 },
    { method: 'GET', path: 'api/v0/x' },
  ).then(
    () => null,
    (e: unknown) => e,
  );
  const took = Date.now() - started;
  if (!(err instanceof CliError) || err.exitCode !== 4)
    return `expected exit 4, got ${String(err)}`;
  if (!err.message.includes('no response within 1 s')) return `unexpected message: ${err.message}`;
  return took < 3_000 ? null : `the request failed only after ${took} ms`;
}

/**
 * The JSON exchanges (the new-code baseline, the gate polling) on this runtime: TLS with a CA file,
 * the total deadline and the connect timeout (ruling E1). The shipped binary's runtime is Bun,
 * whose `node:http` differs from Node's.
 */
const jsonChecks: Record<string, () => Promise<string | null>> = {
  'JSON over TLS trusts the CA file, and refuses the server without it': async () => {
    const s = await socketServer(answerJson, { tls: true });
    try {
      const url = `https://127.0.0.1:${s.port}`;
      const res = await request(
        { url, token: TOKEN, timeoutMs: 5_000, ca: TEST_CA_PEM },
        { method: 'GET', path: 'api/v0/x' },
      );
      if (res.status !== 200 || res.body !== '{"ok":true}') {
        return `unexpected answer ${res.status} ${res.body}`;
      }
      return await expectCliError(
        request({ url, token: TOKEN, timeoutMs: 5_000 }, { method: 'GET', path: 'api/v0/x' }),
        4,
      );
    } finally {
      s.close();
    }
  },

  'JSON fails at the total deadline when the server never answers': async () => {
    const s = await socketServer(() => undefined);
    try {
      return await expectDeadline(`http://127.0.0.1:${s.port}`);
    } finally {
      s.close();
    }
  },

  'JSON fails at the total deadline when the answer trickles': async () => {
    const s = await socketServer((socket) => {
      socket.once('data', () => {
        socket.write('HTTP/1.1 200 OK\r\ncontent-length: 1000\r\n\r\n');
        const t = setInterval(() => (socket.destroyed ? clearInterval(t) : socket.write('a')), 200);
      });
    });
    try {
      return await expectDeadline(`http://127.0.0.1:${s.port}`);
    } finally {
      s.close();
    }
  },

  'JSON fails at the connect timeout when the TLS handshake never completes': async () => {
    // Accepts the connection and never answers the ClientHello.
    const s = await socketServer(() => undefined);
    try {
      return await expectDeadline(`https://127.0.0.1:${s.port}`);
    } finally {
      s.close();
    }
  },
};

/**
 * Bun linger (fixed in CLI step 13): after a JSON exchange with a long timeout, nothing may keep
 * the process alive. Run as a process of its own (`--linger-probe`); the caller checks that it
 * exits promptly, far below the 30 s timeout.
 */
export async function lingerProbe(): Promise<void> {
  const s = await socketServer(answerJson, { tls: true });
  try {
    await request(
      { url: `https://127.0.0.1:${s.port}`, token: TOKEN, timeoutMs: 30_000, ca: TEST_CA_PEM },
      { method: 'GET', path: 'api/v0/x' },
    );
  } finally {
    s.close();
  }
}

const ep = (url: string, timeoutMs = 5_000) => ({ url, token: TOKEN, timeoutMs });

async function expectCliError(p: Promise<unknown>, exitCode: number): Promise<string | null> {
  const err: unknown = await p.then(
    () => null,
    (e: unknown) => e,
  );
  if (!(err instanceof CliError)) return `expected a CliError, got ${String(err)}`;
  if (err.message.includes(TOKEN)) return 'the token appears in the error message';
  if (err.exitCode !== exitCode) return `expected exit ${exitCode}, got ${err.exitCode}`;
  return null;
}

const checks: Record<string, Check> = {
  'sends the report after 100 Continue, with Content-Length and Expect': async (file, bytes) => {
    let problemText: string | null = null;
    const s = await rawServer((x) => {
      const h = x.head.headers;
      if (h.get('expect') !== '100-continue') problemText = `Expect was ${h.get('expect')}`;
      else if (h.get('content-length') !== String(bytes.length)) {
        problemText = `Content-Length was ${h.get('content-length')}`;
      } else if (x.body() !== 0) problemText = 'the body came before 100 Continue';
      x.socket.write('HTTP/1.1 100 Continue\r\n\r\n');
      void x.readBody(bytes.length).then((got) => {
        if (!got.equals(bytes)) problemText = 'the body differs from the file';
        x.socket.end(response('202 Accepted', ACCEPTED));
      });
    });
    try {
      const r = await uploadReport(
        ep(s.url),
        { projectKey: 'a/b', file, size: bytes.length },
        { log: silentLogger },
      );
      if (r.analysisId !== ID) return `unexpected analysis id ${r.analysisId}`;
      return problemText;
    } finally {
      s.close();
    }
  },

  'never sends the body after a refusal before 100 Continue': async (file, bytes) => {
    const s = await rawServer((x) => {
      // Refuses after 300 ms (an eager client would have sent bytes by then), then keeps the
      // connection open and reading, like the lingering Qualor server.
      setTimeout(
        () => x.socket.write(response('401 Unauthorized', '{"code":"UNAUTHENTICATED"}')),
        300,
      );
    });
    try {
      const failure = await expectCliError(
        uploadReport(
          ep(s.url),
          { projectKey: 'a/b', file, size: bytes.length },
          { log: silentLogger },
        ),
        5,
      );
      if (failure !== null) return failure;
      await new Promise((r) => setTimeout(r, 300));
      const sent = s.exchanges[0]?.body() ?? -1;
      return sent === 0 ? null : `${sent} body bytes were sent after the refusal`;
    } finally {
      s.close();
    }
  },

  'sends the body anyway when no 100 Continue comes': async () => {
    const s = await rawServer((x) => {
      void x
        .readBody(5)
        .then((got) => x.socket.end(response('200 OK', JSON.stringify({ got: got.toString() }))));
    });
    try {
      const res = await request(ep(s.url), {
        method: 'POST',
        path: 'x',
        body: { stream: () => Readable.from([Buffer.from('hello')]), contentLength: 5 },
        continueTimeoutMs: 200,
      });
      return res.body === '{"got":"hello"}' ? null : `unexpected answer ${res.status} ${res.body}`;
    } finally {
      s.close();
    }
  },

  'fails with exit 4 when the connection is reset mid-body': async (file, bytes) => {
    const s = await rawServer((x) => {
      x.socket.write('HTTP/1.1 100 Continue\r\n\r\n');
      void x.readBody(64 * 1024).then(() => x.socket.resetAndDestroy());
    });
    try {
      return await expectCliError(
        uploadReport(
          ep(s.url),
          { projectKey: 'a/b', file, size: bytes.length },
          { log: silentLogger },
        ),
        4,
      );
    } finally {
      s.close();
    }
  },

  'keeps uploading to a server that trickles, past the inactivity timeout': async (file, bytes) => {
    const s = await rawServer((x) => {
      // About 13 MiB/s: 300 ms pauses after every 4 MiB of the first three quarters, 3.6 s in
      // all, far over the 2 s timeout. Progress is only seen when the socket takes more bytes,
      // and Bun keeps up to ~16 MiB in flight on Linux loopback (about 1.2 s at this rate), so
      // the timeout must exceed that. The last quarter is read at full speed: once the client has
      // handed over its last byte it cannot see the server read what the buffers still hold.
      x.trickle(4 * 1024 * 1024, 300, (bytes.length * 3) / 4);
      x.socket.write('HTTP/1.1 100 Continue\r\n\r\n');
      void x.readBody(bytes.length).then(() => x.socket.end(response('202 Accepted', ACCEPTED)));
    });
    const started = Date.now();
    try {
      await uploadReport(
        ep(s.url, 2_000),
        { projectKey: 'a/b', file, size: bytes.length },
        { log: silentLogger },
      );
      const took = Date.now() - started;
      return took > 3_000 ? null : `the upload took only ${took} ms; the server did not trickle`;
    } finally {
      s.close();
    }
  },

  'fails with exit 4, in bounded time, when the server stops reading': async () => {
    // 1 MiB: under Bun the answer is awaited `timeoutMs` + 8 s once the body is handed over.
    const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-upload-smoke-stall-'));
    const file = path.join(dir, 'report.json.gz');
    writeFileSync(file, randomBytes(1024 * 1024));
    const s = await rawServer((x) => {
      x.socket.write('HTTP/1.1 100 Continue\r\n\r\n');
      x.socket.pause(); // never reads again, never answers
    });
    const started = Date.now();
    try {
      const failure = await expectCliError(
        uploadReport(
          ep(s.url, 500),
          { projectKey: 'a/b', file, size: 1024 * 1024 },
          { log: silentLogger },
        ),
        4,
      );
      const took = Date.now() - started;
      return failure ?? (took < 20_000 ? null : `the upload failed only after ${took} ms`);
    } finally {
      s.close();
      rmSync(dir, { recursive: true, force: true });
    }
  },

  'uploads through a CONNECT proxy (V9), and never sends the token to it': async (file, bytes) => {
    const s = await rawServer((x) => {
      x.socket.write('HTTP/1.1 100 Continue\r\n\r\n');
      void x.readBody(bytes.length).then(() => x.socket.end(response('202 Accepted', ACCEPTED)));
    });
    const proxy = await startConnectProxy({ credentials: 'smoke:pa ss' });
    try {
      const port = new URL(s.url).port;
      // The origin name does not resolve: only the proxy can reach it.
      await uploadReport(
        { ...ep(`http://upload.invalid:${port}`), env: { HTTP_PROXY: proxy.url } },
        { projectKey: 'a/b', file, size: bytes.length },
        { log: silentLogger },
      );
      const head = proxy.heads[0] ?? '';
      if (!head.startsWith(`CONNECT upload.invalid:${port} HTTP/1.1`)) return `proxy saw ${head}`;
      if (head.includes(TOKEN)) return 'the token was sent to the proxy';
      if (s.exchanges[0]?.head.headers.get('authorization') !== `Bearer ${TOKEN}`) {
        return 'the origin did not get the token';
      }
      const wrong = new URL(proxy.url);
      wrong.password = 'wrong-secret';
      const failure = await expectCliError(
        uploadReport(
          { ...ep(`http://upload.invalid:${port}`), env: { HTTP_PROXY: wrong.href } },
          { projectKey: 'a/b', file, size: bytes.length },
          { log: silentLogger },
        ),
        4,
      );
      return failure;
    } finally {
      proxy.close();
      s.close();
    }
  },

  'fails an answer that trickles after its head, within the timeout': async (file, bytes) => {
    const s = await rawServer((x) => {
      x.socket.write('HTTP/1.1 401 Unauthorized\r\ncontent-length: 1000\r\n\r\n');
      const t = setInterval(
        () => (x.socket.destroyed ? clearInterval(t) : x.socket.write('a')),
        300,
      );
    });
    const started = Date.now();
    try {
      const failure = await expectCliError(
        uploadReport(
          ep(s.url, 1_000),
          { projectKey: 'a/b', file, size: bytes.length },
          { log: silentLogger },
        ),
        4,
      );
      const took = Date.now() - started;
      return failure ?? (took < 3_000 ? null : `the answer held the client for ${took} ms`);
    } finally {
      s.close();
    }
  },

  'retries 503 UPLOADS_BUSY after Retry-After': async (file, bytes) => {
    let calls = 0;
    const s = await rawServer((x) => {
      calls += 1;
      if (calls < 3) {
        x.socket.write(
          response('503 Service Unavailable', '{"code":"UPLOADS_BUSY"}', 'retry-after: 1\r\n'),
        );
        return;
      }
      x.socket.write('HTTP/1.1 100 Continue\r\n\r\n');
      void x.readBody(bytes.length).then(() => x.socket.end(response('202 Accepted', ACCEPTED)));
    });
    const waits: number[] = [];
    try {
      await uploadReport(
        ep(s.url),
        { projectKey: 'a/b', file, size: bytes.length },
        {
          log: silentLogger,
          wait: (ms) => {
            waits.push(ms);
            return Promise.resolve();
          },
        },
      );
      return waits.join(',') === '1000,1000' ? null : `unexpected waits ${waits.join(',')}`;
    } finally {
      s.close();
    }
  },
};

/**
 * The upload path (ruling E5) and the JSON exchanges (ruling E1) against real local servers, on whatever runtime runs it: under
 * Node by `upload-smoke.test.ts`, and under Bun (the shipped binary's runtime) by
 * `upload-smoke.ts`. Returns one line per failed check, empty when all pass.
 */
export async function checkUploadPath(): Promise<{ passed: string[]; failed: string[] }> {
  const passed: string[] = [];
  const failed: string[] = [];
  const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-upload-smoke-'));
  try {
    // The report file is written the way the CLI writes it: privately, then removed.
    let privateFile = '';
    await withPrivateReportFile(
      { schemaVersion: 1, pad: randomBytes(64).toString('hex') } as unknown as Report,
      ({ file }) => {
        privateFile = file;
        if (process.platform !== 'win32' && (statSync(file).mode & 0o777) !== 0o600) {
          failed.push('the private report file is not mode 0600');
        }
        return Promise.resolve();
      },
    );
    try {
      statSync(privateFile);
      failed.push('the private report file was not removed');
    } catch {
      passed.push('writes the report to a private temporary file and removes it');
    }

    const bytes = randomBytes(64 * 1024 * 1024);
    const file = path.join(dir, 'report.json.gz');
    writeFileSync(file, bytes);
    for (const [name, check] of Object.entries(checks)) {
      const failure = await check(file, bytes).catch((e: unknown) => `threw ${String(e)}`);
      if (failure === null) passed.push(name);
      else failed.push(`${name}: ${failure}`);
    }
    for (const [name, check] of Object.entries(jsonChecks)) {
      const failure = await check().catch((e: unknown) => `threw ${String(e)}`);
      if (failure === null) passed.push(name);
      else failed.push(`${name}: ${failure}`);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
  return { passed, failed };
}
