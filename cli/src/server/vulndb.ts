import { createHash, randomBytes } from 'node:crypto';
import { createWriteStream, rmSync, renameSync, type WriteStream } from 'node:fs';
import http, { type IncomingMessage } from 'node:http';
import https from 'node:https';
import { z } from 'zod';
import { VERSION } from '../index';
import type { Logger } from '../log';
import { isMissingEndpoint } from './baseline-client';
import {
  agentFor,
  authorization,
  caBundle,
  request,
  retryAfterMs,
  targetUrl,
  type ServerEndpoint,
} from './http';

/** What `GET api/v0/scanner/vulnerability-db` tells a scanner (Trivy database from the server). */
export type ServerVulndb = {
  serve: boolean;
  policy: 'daily' | 'every';
  current: { digest: string; sizeBytes: number; builtAt: string | null } | null;
  accepted: string[];
};

const MAX_DB_BYTES = 2 * 1024 ** 3;
const MAX_METADATA_BYTES = 16 * 1024;
const MAX_ACCEPTED = 64;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

const metadata = z.object({
  serve: z.boolean(),
  policy: z.enum(['daily', 'every']),
  current: z
    .object({
      digest: z.string().regex(DIGEST),
      sizeBytes: z.number().int().positive().max(MAX_DB_BYTES),
      builtAt: z.string().max(64).nullable(),
    })
    .nullable(),
  accepted: z.array(z.string().regex(DIGEST)).max(MAX_ACCEPTED),
});

/** The text after the last `): ` of an UnreachableError (the part without URL and path). */
function transportReason(err: unknown): string {
  const text = err instanceof Error ? err.message : String(err);
  const why = /\): ([^\n]{1,100})$/.exec(text)?.[1];
  return `connection failed: ${why ?? 'error'}`;
}

/**
 * Asks the server for its current vulnerability database. Never throws: `'unsupported'` for a
 * server without the route, `{failed}` (a short reason without the token) for anything else.
 */
export async function fetchServerVulndb(
  ep: ServerEndpoint,
  log: Logger,
): Promise<ServerVulndb | 'unsupported' | { failed: string }> {
  try {
    const res = await request(ep, {
      method: 'GET',
      path: 'api/v0/scanner/vulnerability-db',
      maxResponseBytes: MAX_METADATA_BYTES,
    });
    if (isMissingEndpoint(res)) return 'unsupported';
    if (res.status !== 200) return { failed: `server answered ${res.status}` };
    let parsed: z.ZodSafeParseResult<ServerVulndb>;
    try {
      parsed = metadata.safeParse(JSON.parse(res.body));
    } catch {
      return { failed: 'unexpected response' };
    }
    return parsed.success ? parsed.data : { failed: 'unexpected response' };
  } catch (err) {
    log.debug(
      `vulnerability database metadata failed (${err instanceof Error ? err.message : String(err)})`,
    );
    return { failed: transportReason(err) };
  }
}

export type DownloadOptions = {
  /** No byte for this long aborts (default 60 s). */
  idleMs?: number;
  /** The whole download takes at most this long (default 15 min). */
  totalMs?: number;
  /** A 503 is retried once when its `retry-after` is at most this (default 10 s). */
  retryAfterCapMs?: number;
  /** Test seam: opens the partial file (default `fs.createWriteStream`). */
  createStream?: (file: string, o: { flags: string; mode: number }) => WriteStream;
};

type Attempt = { ok: true } | { ok: false; reason: string; busyAfterMs?: number | null };

function unlinkQuietly(file: string): void {
  try {
    rmSync(file, { force: true, maxRetries: 5, retryDelay: 50 });
  } catch {
    // A partial file we cannot remove stays in the cache directory; nothing more to do.
  }
}

function attempt(
  ep: ServerEndpoint,
  hex: string,
  sizeBytes: number,
  dest: string,
  idleMs: number,
  totalMs: number,
  opts: DownloadOptions,
): Promise<Attempt> {
  let url: URL;
  try {
    url = targetUrl(ep.url, `api/v0/scanner/vulnerability-db/${hex}`);
  } catch {
    return Promise.resolve({ ok: false, reason: 'unexpected response' });
  }
  const isHttps = url.protocol === 'https:';
  const lib = isHttps ? https : http;
  const partial = `${dest}.${randomBytes(6).toString('hex')}.partial`;
  const hash = createHash('sha256');

  return new Promise((resolve) => {
    let settled = false;
    let req: http.ClientRequest | undefined;
    let res: IncomingMessage | undefined;
    let out: WriteStream | undefined;
    let idle: NodeJS.Timeout | undefined;
    let received = 0;

    const finish = (result: Attempt) => {
      if (settled) return;
      settled = true;
      clearTimeout(idle);
      clearTimeout(total);
      res?.destroy();
      req?.destroy();
      const stream = out;
      const cleanup = () => {
        if (!result.ok) unlinkQuietly(partial);
        resolve(result);
      };
      if (stream === undefined) cleanup();
      else if (result.ok) cleanup();
      else if (stream.closed) cleanup();
      else {
        stream.once('close', cleanup);
        stream.destroy();
      }
    };
    const fail = (reason: string, busyAfterMs?: number | null) =>
      finish({ ok: false, reason, ...(busyAfterMs !== undefined && { busyAfterMs }) });
    const total = setTimeout(() => fail('timed out'), totalMs);
    const armIdle = () => {
      clearTimeout(idle);
      idle = setTimeout(() => fail('timed out'), idleMs);
    };

    try {
      req = lib.request(url, {
        method: 'GET',
        headers: {
          ...authorization(ep),
          accept: 'application/gzip, application/json, application/problem+json',
          'user-agent': `qualor-cli/${VERSION}`,
        },
        agent: agentFor(isHttps, ep),
        ...(isHttps && {
          rejectUnauthorized: true,
          ...(ep.ca !== undefined && { ca: caBundle(ep.ca) }),
        }),
      });
    } catch {
      fail('unexpected response');
      return;
    }
    armIdle();
    req.on('error', (err: NodeJS.ErrnoException) =>
      fail(`connection failed: ${err.code ?? 'error'}`),
    );
    req.on('response', (r: IncomingMessage) => {
      res = r;
      armIdle();
      const status = r.statusCode ?? 0;
      if (status === 503) {
        fail('server busy', retryAfterMs(r.headers, 0, Number.MAX_SAFE_INTEGER));
        return;
      }
      if (status !== 200) {
        fail(`server answered ${status}`);
        return;
      }
      const declared = r.headers['content-length'];
      if (declared !== undefined && Number(declared) !== sizeBytes) {
        fail('unexpected response');
        return;
      }
      // Readable by all, like server.json: the archive is public advisory data, and a CI cache
      // step that runs as another user (actions/cache after the scan-action) must read it.
      const stream = (opts.createStream ?? createWriteStream)(partial, {
        flags: 'wx',
        mode: 0o644,
      });
      out = stream;
      stream.on('error', () => fail('cannot write the database file'));
      const resume = () => r.resume();
      /** Renames the partial file once its descriptor is closed and every byte reached it. */
      const commit = () => {
        if (settled) return;
        if (stream.bytesWritten !== sizeBytes) {
          fail('cannot write the database file');
          return;
        }
        try {
          renameSync(partial, dest);
        } catch {
          fail('cannot write the database file');
          return;
        }
        finish({ ok: true });
      };
      const ended = (err?: Error | null) => {
        if (err) fail('cannot write the database file');
      };
      r.on('data', (chunk: Buffer) => {
        armIdle();
        received += chunk.length;
        if (received > sizeBytes) {
          fail('unexpected response');
          return;
        }
        hash.update(chunk);
        if (!stream.write(chunk)) {
          r.pause();
          stream.once('drain', resume);
        }
      });
      r.on('error', (err: NodeJS.ErrnoException) =>
        fail(`connection failed: ${err.code ?? 'error'}`),
      );
      r.on('close', () => {
        if (!r.complete) fail('connection failed: closed early');
      });
      r.on('end', () => {
        if (settled) return;
        if (received !== sizeBytes || hash.digest('hex') !== hex) {
          fail('unexpected response');
          return;
        }
        clearTimeout(idle);
        // Rename only once the descriptor is closed and every byte reached the file.
        stream.once('close', commit);
        stream.end(ended);
      });
    });
    req.end();
  });
}

const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

/**
 * Streams the database `digest` (`sha256:<hex>`) to `dest`. The bytes go to a `.partial` file next
 * to it and are renamed only when their count and sha256 match; every failure removes the partial
 * file. Never throws; the reason is short and holds no token. No redirect is followed.
 */
export async function downloadServerVulndb(
  ep: ServerEndpoint,
  digest: string,
  sizeBytes: number,
  dest: string,
  opts: DownloadOptions = {},
): Promise<{ ok: true } | { ok: false; reason: string }> {
  const hex = /^(?:sha256:)?([0-9a-f]{64})$/.exec(digest)?.[1];
  if (
    hex === undefined ||
    !Number.isInteger(sizeBytes) ||
    sizeBytes <= 0 ||
    sizeBytes > MAX_DB_BYTES
  ) {
    return { ok: false, reason: 'unexpected response' };
  }
  const idleMs = opts.idleMs ?? 60_000;
  const totalMs = opts.totalMs ?? 15 * 60_000;
  const cap = opts.retryAfterCapMs ?? 10_000;
  const started = Date.now();
  let result = await attempt(ep, hex, sizeBytes, dest, idleMs, totalMs, opts);
  if (
    !result.ok &&
    result.busyAfterMs !== undefined &&
    result.busyAfterMs !== null &&
    result.busyAfterMs <= cap
  ) {
    await sleep(result.busyAfterMs);
    const left = Math.max(1, totalMs - (Date.now() - started));
    result = await attempt(ep, hex, sizeBytes, dest, idleMs, left, opts);
  }
  return result.ok ? { ok: true } : { ok: false, reason: result.reason };
}
