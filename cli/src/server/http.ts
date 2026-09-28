import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import http, { type IncomingHttpHeaders, type IncomingMessage } from 'node:http';
import https from 'node:https';
import type { Readable } from 'node:stream';
import tls from 'node:tls';
import { z } from 'zod';
import { REDACTED_VALUE } from '../config/render';
import { CliError, EXIT } from '../errors';
import { VERSION } from '../index';
import { rawRequestWithBody } from './raw-http';

/** Where and how the CLI talks to the Qualor server (config.md §3 `server`). */
export interface ServerEndpoint {
  /** Base URL, e.g. `https://qualor.acme.internal` (a path prefix is kept). */
  url: string;
  token: string;
  /** No progress on the connection for this long fails the request (`server.timeoutSeconds`). */
  timeoutMs: number;
  /** `server.caFile`: extra CA certificates (PEM), trusted on top of the default store. */
  ca?: string | undefined;
  /** Where the upload reads `HTTP(S)_PROXY`/`NO_PROXY` (ruling V9); `process.env` by default. */
  env?: Readonly<Record<string, string | undefined>> | undefined;
  /** `bearer` (default), `basic` (`<token>:`, SonarQube before 10.0), or `none` (public requests). */
  auth?: 'bearer' | 'basic' | 'none' | undefined;
}

const MAX_CA_FILE_BYTES = 1024 * 1024;

/**
 * Reads `server.caFile` (config.md §3), already resolved against the repo root. Only a regular
 * file is read (a FIFO or a device would block or never end), at most 1 MiB, and it must hold a
 * PEM certificate; anything else is a config error. The content is never shown.
 */
export function readCaFile(file: string, configured: string): string {
  let fd: number | undefined;
  try {
    // O_NONBLOCK: opening a FIFO for reading must not wait for a writer (not defined on Windows).
    fd = openSync(file, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
    const stat = fstatSync(fd);
    if (!stat.isFile()) throw new Error('not a regular file');
    if (stat.size > MAX_CA_FILE_BYTES) throw new Error('larger than 1 MiB');
    const buf = Buffer.alloc(stat.size);
    let read = 0;
    while (read < buf.length) {
      const n = readSync(fd, buf, read, buf.length - read, null);
      if (n === 0) break;
      read += n;
    }
    const pem = buf.subarray(0, read).toString('utf8');
    if (!pem.includes('-----BEGIN CERTIFICATE-----')) throw new Error('no PEM certificate in it');
    return pem;
  } catch (err) {
    const why =
      err instanceof Error && 'code' in err && typeof err.code === 'string'
        ? err.code
        : err instanceof Error
          ? err.message
          : String(err);
    throw new CliError(EXIT.USAGE, `cannot use server.caFile ${configured}: ${why}`);
  } finally {
    if (fd !== undefined) closeSync(fd);
  }
}

/**
 * The CAs a request trusts with `server.caFile`: Node's default store (its bundled roots plus
 * `NODE_EXTRA_CA_CERTS`, and the system store under `--use-system-ca`) and then the file. Passing
 * `ca` to Node replaces the default store, so the defaults are listed explicitly (config.md §3:
 * the file adds CAs, it never narrows the trust).
 */
export function caBundle(extra: string): string[] {
  const defaults =
    typeof tls.getCACertificates === 'function'
      ? tls.getCACertificates('default')
      : [...tls.rootCertificates];
  return [...defaults, extra];
}

/**
 * No usable HTTP answer (connection refused or reset, TLS, DNS, a timeout, an oversized or broken
 * response): exit 4 like any server problem, but worth retrying (gate polling, ruling E6).
 */
export class UnreachableError extends CliError {
  override name = 'UnreachableError';
  constructor(message: string) {
    super(EXIT.SERVER, message);
  }
}

export interface HttpResponse {
  status: number;
  headers: IncomingHttpHeaders;
  /** The response body as UTF-8 text, at most `maxResponseBytes`; the token is masked in it. */
  body: string;
}

export interface RequestOptions {
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  /** Relative to the base URL, without a leading slash (`api/v0/analyses`). */
  path: string;
  query?: Readonly<Record<string, string | undefined>>;
  headers?: Readonly<Record<string, string>>;
  /** Streamed request body; with `contentLength` it is sent with `Expect: 100-continue`. */
  body?: { stream: () => Readable; contentLength: number };
  /** The response body is refused past this size (a misbehaving proxy cannot flood the CLI). */
  maxResponseBytes?: number;
  /** How long to wait for `100 Continue` before sending the body anyway (RFC 9110 §10.1.1);
   * never more than half of `timeoutMs`, so the idle connection cannot time out meanwhile. */
  continueTimeoutMs?: number;
  /** A small JSON body (at most 1 MiB), sent with `Content-Length`; never together with `body`. */
  json?: unknown;
}

const DEFAULT_MAX_RESPONSE_BYTES = 1024 * 1024;
/** A Qualor server answers `100 Continue` (or a final status) as soon as its checks pass. */
const DEFAULT_CONTINUE_TIMEOUT_MS = 10_000;

/** The largest JSON body `request` sends: the server refuses a larger one (413 BODY_TOO_LARGE). */
export const MAX_JSON_BODY_BYTES = 1024 * 1024;

/**
 * A path segment below the base URL: unreserved characters or upper-case percent escapes, never
 * a dot segment, spelled out or escaped (the URL parser reads `%2E%2E` as `..`).
 */
const SEGMENT = /^(?:[A-Za-z0-9_-]|%[0-9A-F]{2})(?:[A-Za-z0-9._~-]|%[0-9A-F]{2}){0,1023}$/;

/** Splits on `/` and `\`: a server or a proxy may read either as a path separator. */
const SEPARATOR = /[/\\]/;
const hasDotPart = (s: string) => s.split(SEPARATOR).some((part) => part === '.' || part === '..');

function segmentAllowed(s: string): boolean {
  if (!SEGMENT.test(s)) return false;
  // A server or a proxy that decodes `%2F`, `%5C` or `%2E` before routing must not see a dot
  // segment either.
  return !hasDotPart(s.replace(/%2E/gi, '.').replace(/%2F/gi, '/').replace(/%5C/gi, '\\'));
}

/**
 * `value` as one path segment (a rule key with `:` `@` `/` included), or a CliError. Every
 * reserved character is escaped, `!'()*` included, and so is a leading `.` or `~`, so a value
 * such as `.eslintrc` stays usable while `.` and `..` are refused, and so is a value with a `.` or
 * `..` part between slashes or backslashes (`a/../b`). A lone surrogate cannot be encoded.
 */
export function pathSegment(value: string): string {
  const refuse = () =>
    new CliError(EXIT.SERVER, 'internal error: refusing a path segment it cannot encode safely');
  if (value === '' || hasDotPart(value)) throw refuse();
  let encoded: string;
  try {
    encoded = encodeURIComponent(value);
  } catch {
    throw refuse();
  }
  encoded = encoded
    .replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`)
    .replace(/^[.~]/, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
  if (!segmentAllowed(encoded)) throw refuse();
  return encoded;
}

/** The credential sent for basic authentication: the token as user name, no password. */
function basicCredential(token: string): string {
  return Buffer.from(`${token}:`, 'utf8').toString('base64');
}

function authorization(ep: ServerEndpoint): Record<string, string> {
  switch (ep.auth ?? 'bearer') {
    case 'bearer':
      return { authorization: `Bearer ${ep.token}` };
    case 'basic':
      return { authorization: `Basic ${basicCredential(ep.token)}` };
    case 'none':
      return {};
  }
}

/**
 * The request URL: `p` below the base URL's path, the query encoded. `p` is a fixed API path or
 * one built from ids a server sent, so it is checked: only plain segments, never a scheme, an
 * authority (`//host`), a dot segment or an escape, and the result must stay on the base URL's
 * origin and below its path. The token can therefore only ever go to the configured server.
 */
export function targetUrl(base: string, p: string, query: RequestOptions['query'] = {}): URL {
  const refuse = () =>
    new CliError(EXIT.SERVER, `internal error: refusing the request path ${JSON.stringify(p)}`);
  const segments = p.split('/');
  if (!segments.every(segmentAllowed)) throw refuse();
  const root = new URL(base);
  root.search = '';
  root.hash = '';
  const prefix = root.pathname.endsWith('/') ? root.pathname : `${root.pathname}/`;
  const url = new URL(root.href);
  url.pathname = `${prefix}${segments.join('/')}`;
  if (url.origin !== root.origin || !url.pathname.startsWith(prefix)) throw refuse();
  for (const [k, v] of Object.entries(query)) if (v !== undefined) url.searchParams.set(k, v);
  return url;
}

/** Below this length a token is not masked in response bodies (it would mask unrelated text). */
const MIN_MASKED_TOKEN_LENGTH = 8;

/** Timers may fire this much before their nominal time. */
const TIMER_SLACK_MS = 20;

/**
 * Masks the token, and the basic credential made from it, in text a server sent. The credential
 * is masked padded and unpadded, whatever the token's length: it is never shorter than 3
 * characters of base64, which unrelated text rarely holds, and it is the secret itself.
 */
function masker(token: string): (text: string) => string {
  const basic = basicCredential(token);
  const unpadded = basic.replace(/=+$/, '');
  const maskToken = token.length >= MIN_MASKED_TOKEN_LENGTH;
  return (text) => {
    const masked = text.replaceAll(basic, REDACTED_VALUE).replaceAll(unpadded, REDACTED_VALUE);
    return maskToken ? masked.replaceAll(token, REDACTED_VALUE) : masked;
  };
}

/**
 * One HTTP request (ruling E1). Never follows redirects (a 3xx is returned like any other status,
 * so `Authorization` never reaches another URL), never retries, always verifies the TLS
 * certificate (`NODE_TLS_REJECT_UNAUTHORIZED` is overridden), and never puts the token in an
 * error message or a returned body. The promise always settles.
 *
 * - Without a body (the small JSON exchanges): `node:http`/`node:https`, answered completely
 *   within `timeoutMs`, connecting included, so a server that trickles bytes cannot hold the CLI.
 *   Each request has its own agent with that timeout: the global agent's own socket timeout (5 s
 *   since Node 19) would otherwise cut the connect phase short.
 * - With a body (the upload, ruling E5): `rawRequestWithBody` on a plain socket, with
 *   `Content-Length` and `Expect: 100-continue`; the body goes only after `100 Continue` or after
 *   the continue wait without any answer, never after a final answer, and the request fails after
 *   `timeoutMs` without progress in either direction. The continue wait is at most half of
 *   `timeoutMs`, so the idle connection cannot time out meanwhile. It honours `HTTP(S)_PROXY`
 *   and `NO_PROXY` from `ep.env` (default `process.env`) through a `CONNECT` tunnel (ruling V9).
 */
export function request(ep: ServerEndpoint, o: RequestOptions): Promise<HttpResponse> {
  const mask = masker(ep.token);
  let url: URL;
  try {
    url = targetUrl(ep.url, o.path, o.query);
  } catch (err) {
    return Promise.reject(err instanceof Error ? err : new Error(String(err)));
  }
  const isHttps = url.protocol === 'https:';
  const maxBytes = o.maxResponseBytes ?? DEFAULT_MAX_RESPONSE_BYTES;
  const headers: Record<string, string> = {
    ...authorization(ep),
    accept: 'application/json, application/problem+json',
    'user-agent': `qualor-cli/${VERSION}`,
    ...o.headers,
  };
  const fail = (why: string) =>
    new UnreachableError(mask(`cannot reach ${url.origin} (${o.method} /${o.path}): ${why}`));
  // A request refused before any I/O: a plain CliError, never retried like an UnreachableError.
  const refuse = (why: string) =>
    Promise.reject(
      new CliError(EXIT.SERVER, mask(`refusing to send ${o.method} /${o.path}: ${why}`)),
    );
  // RFC 7617: the user name of basic authentication cannot hold a colon.
  if (ep.auth === 'basic' && ep.token.includes(':')) {
    return refuse('a token for basic authentication cannot contain ":"');
  }
  let payload: Buffer | undefined;
  if (o.json !== undefined) {
    if (o.body !== undefined) return refuse('a request has either a body or JSON');
    let text: string | undefined;
    try {
      text = JSON.stringify(o.json) as string | undefined;
    } catch {
      text = undefined;
    }
    if (text === undefined) return refuse('the JSON body cannot be serialised');
    payload = Buffer.from(text, 'utf8');
    if (payload.length > MAX_JSON_BODY_BYTES) return refuse('the JSON body is larger than 1 MiB');
    headers['content-type'] = 'application/json';
    headers['content-length'] = String(payload.length);
  }
  if (o.body !== undefined) {
    if (o.method !== 'POST') return refuse('a request body needs POST');
    return rawRequestWithBody({
      url,
      method: o.method,
      headers,
      body: o.body,
      ca: isHttps && ep.ca !== undefined ? caBundle(ep.ca) : undefined,
      timeoutMs: ep.timeoutMs,
      continueWaitMs: Math.min(
        o.continueTimeoutMs ?? DEFAULT_CONTINUE_TIMEOUT_MS,
        Math.floor(ep.timeoutMs / 2),
      ),
      maxResponseBytes: maxBytes,
      env: ep.env,
    }).then(
      (res) => ({
        status: res.status,
        headers: res.headers,
        body: mask(res.body.toString('utf8')),
      }),
      (err: unknown) => {
        throw fail(err instanceof Error ? err.message : String(err));
      },
    );
  }
  const lib = isHttps ? https : http;
  const idle = `no response within ${ep.timeoutMs / 1000} s`;
  const started = performance.now();
  // Under Bun the request's own `timeout` closes the connection (without a 'timeout' event) just
  // before the deadline timer below fires. A close that late is the timeout, so it gets its words.
  const closed = (why: string) =>
    fail(performance.now() - started >= ep.timeoutMs - TIMER_SLACK_MS ? idle : why);
  return new Promise((resolve, reject) => {
    let settled = false;
    let answered = false;
    let req: http.ClientRequest;
    const done = (err: CliError | null, res?: HttpResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      if (err !== null) {
        reject(err);
        req.destroy();
      } else if (res !== undefined) resolve(res);
    };
    try {
      req = lib.request(url, {
        method: o.method,
        headers,
        timeout: ep.timeoutMs,
        agent: new (isHttps ? https.Agent : http.Agent)({
          keepAlive: false,
          timeout: ep.timeoutMs,
        }),
        ...(isHttps && {
          // Explicit, so NODE_TLS_REJECT_UNAUTHORIZED=0 in the environment cannot switch it off.
          rejectUnauthorized: true,
          ...(ep.ca !== undefined && { ca: caBundle(ep.ca) }),
        }),
      });
    } catch (err) {
      // e.g. ERR_INVALID_CHAR for a header value; Node's message names the header, not the value.
      const code = err instanceof Error && 'code' in err ? String(err.code) : 'invalid request';
      reject(fail(code));
      return;
    }
    const onIdle = () => done(fail(idle));
    req.setTimeout(ep.timeoutMs, onIdle);
    const deadline = setTimeout(onIdle, ep.timeoutMs);
    req.on('response', (res: IncomingMessage) => {
      answered = true;
      // No `res.setTimeout`: the deadline above already bounds the whole exchange, and under Bun
      // a response timeout outlives the response and keeps the process alive for `timeoutMs`.
      const tooLarge = () => fail(`the response is larger than ${maxBytes} bytes`);
      const declared = Number(res.headers['content-length']);
      if (Number.isFinite(declared) && declared > maxBytes) {
        res.destroy();
        done(tooLarge());
        return;
      }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > maxBytes) {
          res.destroy();
          done(tooLarge());
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => {
        done(null, {
          status: res.statusCode ?? 0,
          headers: res.headers,
          body: mask(Buffer.concat(chunks).toString('utf8')),
        });
      });
      res.on('error', (err) => done(fail(err.message)));
      res.on('close', () => {
        if (!res.complete) done(closed('the connection closed before the response was complete'));
      });
    });
    req.on('error', (err: NodeJS.ErrnoException) => done(fail(err.code ?? err.message)));
    req.on('close', () => {
      if (!answered) done(closed('the connection closed without a response'));
    });
    req.end(payload);
  });
}

/** RFC 9457 problem details (api.md §1): only the fields the CLI shows or branches on. */
const problemSchema = z.looseObject({
  code: z.string().optional(),
  title: z.string().optional(),
  detail: z.string().optional(),
  errors: z.array(z.looseObject({ path: z.string(), message: z.string() })).optional(),
});
export type Problem = z.infer<typeof problemSchema>;

export function parseProblem(body: string): Problem | null {
  try {
    const parsed = problemSchema.safeParse(JSON.parse(body));
    return parsed.success ? parsed.data : null;
  } catch {
    return null;
  }
}

/* eslint-disable no-control-regex -- terminal escape sequences and control characters are what is removed */
/**
 * Control strings, removed whole with their payload: OSC (`ESC ]`, C1 `0x9d`: titles,
 * hyperlinks), DCS (`ESC P`, `0x90`), SOS (`ESC X`, `0x98`), PM (`ESC ^`, `0x9e`) and APC
 * (`ESC _`, `0x9f`), ended by BEL or ST (`ESC \`, `0x9c`), or by the end of the text.
 */
const CONTROL_STRING =
  /(?:\u001b[\]PX^_]|[\u009d\u0090\u0098\u009e\u009f])[^\u0007\u001b\u009c]*(?:\u0007|\u001b\\|\u009c|(?=\u001b)|$)/g;
/** CSI (`ESC [` or C1 `0x9b`), with parameters and intermediates. */
const CSI = /(?:\u001b\[|\u009b)[0-?]*[ -/]*[@-~]/g;
/** Every other escape sequence: `ESC`, intermediates (`ESC ( B`, `ESC # 8`), a final byte. */
const OTHER_ESCAPE = /\u001b[ -/]*[0-~]?/g;
/** Bidi embeddings, overrides and isolates, and zero-width characters: they reorder or hide text. */
const INVISIBLE = /[\u202a-\u202e\u2066-\u2069\u200b-\u200d\ufeff]/g;
const CONTROL = /[\u0000-\u001f\u007f-\u009f]+/g;
/* eslint-enable no-control-regex */
const PROBLEM_CODE = /^[A-Z][A-Z0-9_]{0,63}$/;
const MAX_PROBLEM_TEXT = 500;
const MAX_ERROR_PATHS = 3;

/** Server text for a terminal: no escape sequences or control characters, bounded. */
export function clean(text: string): string {
  return text
    .replace(CONTROL_STRING, '')
    .replace(CSI, '')
    .replace(OTHER_ESCAPE, '')
    .replace(INVISIBLE, '')
    .replace(CONTROL, ' ')
    .trim()
    .slice(0, MAX_PROBLEM_TEXT);
}

/**
 * `"401 UNAUTHENTICATED: …"` for messages; never the raw body (it may echo request data, or be
 * an HTML page from a proxy), only a problem's code and title/detail, cleaned and bounded.
 */
export function describeFailure(res: HttpResponse): string {
  const p = parseProblem(res.body);
  const code = p?.code !== undefined && PROBLEM_CODE.test(p.code) ? ` ${p.code}` : '';
  const raw = p?.detail ?? p?.title;
  const text = raw === undefined ? '' : clean(raw);
  const redirect =
    res.status >= 300 && res.status < 400
      ? ' (redirects are not followed; set the server URL to the final address)'
      : '';
  // A 422 names the request fields the server refused (the first few, cleaned).
  const paths = (p?.errors ?? []).slice(0, MAX_ERROR_PATHS).map((e) => clean(e.path).slice(0, 100));
  const fields = paths.length === 0 ? '' : ` (${paths.join(', ')})`;
  return `${res.status}${code}${text === '' ? '' : `: ${text}`}${fields}${redirect}`;
}

/** Seconds from a `Retry-After` header (delta-seconds only), clamped to [min, max]. */
export function retryAfterMs(
  headers: IncomingHttpHeaders,
  minMs: number,
  maxMs: number,
): number | null {
  const raw = headers['retry-after'];
  const value = Array.isArray(raw) ? raw[0] : raw;
  if (value === undefined || !/^\d+$/.test(value.trim())) return null;
  return Math.min(maxMs, Math.max(minMs, Number(value.trim()) * 1000));
}

/** Parses a JSON response body with `schema`, or fails with exit 4 and `what`. */
export function parseJson<T>(res: HttpResponse, schema: z.ZodType<T>, what: string): T {
  let json: unknown;
  try {
    json = JSON.parse(res.body) as unknown;
  } catch {
    throw new CliError(EXIT.SERVER, `the server sent an invalid ${what} (not JSON)`);
  }
  const parsed = schema.safeParse(json);
  if (!parsed.success) throw new CliError(EXIT.SERVER, `the server sent an invalid ${what}`);
  return parsed.data;
}
