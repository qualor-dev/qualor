import { lookup as dnsLookup, type LookupAddress } from 'node:dns';
import http, { type IncomingHttpHeaders } from 'node:http';
import https from 'node:https';
import { isIP, type LookupFunction } from 'node:net';
import { hostOf, isNonPublicAddress } from '../webhooks/url';

/**
 * Ruling X7: the connection (lookup, TCP connect and, for https, the TLS handshake) must be up
 * within this, inside the request's whole deadline.
 */
export const CONNECT_TIMEOUT_MS = 3_000;

export type Resolver = (hostname: string) => Promise<LookupAddress[]>;

export interface OutboundRequest {
  url: string;
  method: 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
  headers: Record<string, string>;
  /** Sent with a `content-length`; none for a request without a body. */
  body?: string;
}

/** How failure texts name the other side: `The ${noun} URL …`, `The connection to ${target} …`. */
export interface OutboundNames {
  noun: string;
  target: string;
}

export interface OutboundOptions {
  allowInternalHosts: boolean;
  /**
   * Addresses refused even when internal hosts are allowed (checked on every resolved address,
   * before the connection): SCM connections refuse link-local and cloud metadata addresses always,
   * and loopback unless the listed host is itself loopback (scm.md §2.1). Webhooks pass none.
   */
  refuseAddress?: (address: string) => boolean;
  /** The whole exchange: resolve, connect, send, and read the answer. */
  timeoutMs: number;
  /** The connection only (resolve, connect, TLS handshake); default {@link CONNECT_TIMEOUT_MS}. */
  connectTimeoutMs?: number;
  /** Tests substitute DNS; the default is the system resolver (`dns.lookup`). */
  resolve?: Resolver;
  /** At most this many bytes of the body are read. */
  maxResponseBytes: number;
  /**
   * `truncate`: stop reading at the limit (or at the deadline once the status line arrived) and
   * answer with what arrived (webhooks judge an attempt by its status); `fail`: a body over the
   * limit, or not complete by the deadline, is a failure (a JSON API needs the whole answer).
   */
  overflow: 'truncate' | 'fail';
  names: OutboundNames;
}

export type OutboundResult =
  | { kind: 'response'; status: number; headers: IncomingHttpHeaders; body: Buffer }
  | {
      kind: 'failed';
      /** A short fixed text (never a URL, header or body). */
      reason: string;
      /** No answer at all: a timeout, or a connection or lookup failure. */
      unreachable: boolean;
      /** What failed, for callers that act on it without reading `reason`. */
      cause: OutboundFailure;
      /** The system error code (`ECONNREFUSED`), when there is one. */
      code: string | null;
    };

export type OutboundFailure =
  | 'invalid_url'
  | 'not_public'
  | 'refused_address'
  | 'unresolved'
  | 'timeout'
  | 'connect_timeout'
  | 'request'
  | 'connection'
  | 'too_large';

const systemResolver: Resolver = (hostname) =>
  new Promise((resolve, reject) => {
    dnsLookup(hostname, { all: true, order: 'verbatim' }, (err, addresses) => {
      if (err) reject(err);
      else resolve(addresses);
    });
  });

/**
 * A `lookup` that only ever answers with the addresses already resolved and checked, never
 * resolving the host again: all of them when asked for all (`autoSelectFamily`), else the first.
 */
export function pinnedLookup(checked: readonly LookupAddress[]): LookupFunction {
  const addresses = checked.map((a) => ({ address: a.address, family: a.family }));
  return (_hostname, options, callback) => {
    const [first] = addresses;
    if (options.all) callback(null, addresses);
    else if (first) callback(null, first.address, first.family);
    else callback(new Error('no checked address'), '', 0);
  };
}

/** A system error code (`ECONNREFUSED`, `CERT_HAS_EXPIRED`), never a message; else null. */
export function codeOf(err: unknown): string | null {
  const code = (err as { code?: unknown } | null)?.code;
  return typeof code === 'string' && /^[A-Z0-9_]{1,40}$/.test(code) ? code : null;
}

/** Only a system error code (`ECONNREFUSED`, `CERT_HAS_EXPIRED`), never a message. */
export function errorCode(err: unknown): string {
  const code = codeOf(err);
  return code === null ? '' : ` (${code})`;
}

function durationText(ms: number): string {
  return ms >= 1_000 ? `${Math.round(ms / 1_000)} s` : `${ms} ms`;
}

/**
 * One server-side request to a URL an administrator configured (webhooks, ruling W3; SCM
 * connections, scm.md §4.3), with the protections such a request needs:
 * - the host is resolved once; unless internal hosts are allowed, every address it resolves to
 *   must be public (not only the one used), and the connection is pinned to the checked addresses
 *   (a custom `lookup`), so a second, different DNS answer (rebinding) can never be used; an IP
 *   literal is checked as such, without a lookup;
 * - a fresh connection (`agent: false`), no proxy (a new `Agent` never reads the proxy
 *   environment), and no redirect is followed (a 3xx is answered as such); TLS certificates are
 *   verified against the URL's host name;
 * - one deadline for the whole exchange, the lookup included, and a shorter one for the
 *   connection ({@link CONNECT_TIMEOUT_MS}, ruling X7), which a lookup must also meet (else the
 *   host is `unresolved`); at most `maxResponseBytes` of the body are read.
 * Never throws; a failure is `kind: 'failed'` with a short fixed reason.
 */
export async function outboundRequest(
  request: OutboundRequest,
  options: OutboundOptions,
): Promise<OutboundResult> {
  const { noun, target } = options.names;
  const fail = (
    reason: string,
    cause: OutboundFailure,
    unreachable = false,
    code: string | null = null,
  ): OutboundResult => ({ kind: 'failed', reason, unreachable, cause, code });
  const timedOut = fail(`No response within ${durationText(options.timeoutMs)}`, 'timeout', true);
  // The connection has a deadline of its own only when it is shorter than the whole request's.
  const connectMs = Math.min(options.connectTimeoutMs ?? CONNECT_TIMEOUT_MS, options.timeoutMs);
  const notConnected =
    connectMs < options.timeoutMs
      ? fail(`No connection within ${durationText(connectMs)}`, 'connect_timeout', true)
      : timedOut;
  const startedAt = Date.now();
  let url: URL;
  try {
    url = new URL(request.url);
  } catch {
    return fail(`The ${noun} URL is not valid`, 'invalid_url');
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') {
    return fail(`The ${noun} URL is not http or https`, 'invalid_url');
  }
  const host = hostOf(url);
  let addresses: LookupAddress[];
  const literal = isIP(host);
  const unresolved = fail(`The ${noun} host could not be resolved`, 'unresolved', true);
  if (literal !== 0) {
    addresses = [{ address: host, family: literal }];
  } else {
    let timer: NodeJS.Timeout | undefined;
    try {
      const resolved = await Promise.race([
        (options.resolve ?? systemResolver)(host),
        new Promise<'timeout'>((resolve) => {
          timer = setTimeout(() => resolve('timeout'), connectMs);
        }),
      ]);
      // A lookup still running at the connect deadline is a name that does not resolve (a
      // single-label host the resolver keeps retrying, EAI_AGAIN after its own timeouts), not a
      // host that is slow to connect.
      if (resolved === 'timeout') {
        return fail(
          `The ${noun} host could not be resolved within ${durationText(connectMs)}`,
          'unresolved',
          true,
        );
      }
      addresses = resolved;
    } catch {
      return unresolved;
    } finally {
      clearTimeout(timer);
    }
  }
  if (addresses.length === 0 || addresses.some((a) => isIP(a.address) === 0)) return unresolved;
  if (!options.allowInternalHosts && addresses.some((a) => isNonPublicAddress(a.address))) {
    return fail(
      `The ${noun} host resolves to a private, loopback or otherwise non-public address`,
      'not_public',
    );
  }
  if (options.refuseAddress && addresses.some((a) => options.refuseAddress?.(a.address))) {
    return fail(
      `The ${noun} host resolves to a link-local, cloud metadata or loopback address`,
      'refused_address',
    );
  }
  const checked = addresses.map((a) => ({ address: a.address, family: isIP(a.address) }));
  const elapsedMs = Date.now() - startedAt;
  const remainingMs = options.timeoutMs - elapsedMs;
  const connectRemainingMs = connectMs - elapsedMs;
  if (remainingMs <= 0) return timedOut;
  if (connectRemainingMs <= 0) return notConnected;

  return new Promise<OutboundResult>((resolve) => {
    const secure = url.protocol === 'https:';
    let req: http.ClientRequest;
    try {
      req = (secure ? https : http).request(url, {
        method: request.method,
        headers:
          request.body === undefined
            ? request.headers
            : {
                ...request.headers,
                'content-length': String(Buffer.byteLength(request.body)),
              },
        agent: false,
        lookup: pinnedLookup(checked),
      });
    } catch (err) {
      // An invalid header value or option throws before any connection is attempted.
      resolve(
        fail(
          `The request to ${target} could not be made${errorCode(err)}`,
          'request',
          false,
          codeOf(err),
        ),
      );
      return;
    }
    let settled = false;
    let finishResponse: ((how: 'end' | 'deadline' | 'closed') => void) | undefined;
    let connectDeadline: NodeJS.Timeout | undefined;
    const deadline = setTimeout(() => {
      // Once the status line arrived, a truncating caller is answered with what the body gave.
      if (finishResponse) finishResponse('deadline');
      else settle(timedOut);
      req.destroy();
    }, remainingMs);
    const settle = (outcome: OutboundResult): void => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      clearTimeout(connectDeadline);
      resolve(outcome);
    };
    if (connectMs < options.timeoutMs) {
      connectDeadline = setTimeout(() => {
        settle(notConnected);
        req.destroy();
      }, connectRemainingMs);
      // Connected: the TCP connection for http, the finished TLS handshake for https.
      req.on('socket', (socket) => {
        socket.once(secure ? 'secureConnect' : 'connect', () => clearTimeout(connectDeadline));
      });
    }
    req.on('error', (err) =>
      settle(
        fail(
          `The connection to ${target} failed${errorCode(err)}`,
          'connection',
          true,
          codeOf(err),
        ),
      ),
    );
    req.on('response', (res) => {
      const status = res.statusCode ?? 0;
      const chunks: Buffer[] = [];
      let size = 0;
      const finish = (how: 'end' | 'deadline' | 'closed'): void => {
        if (options.overflow === 'fail' && how === 'deadline') settle(timedOut);
        else if (options.overflow === 'fail' && how === 'closed') {
          settle(fail(`The connection to ${target} failed`, 'connection', true));
        } else {
          const body = Buffer.concat(chunks);
          settle({
            kind: 'response',
            status,
            headers: res.headers,
            body:
              body.length > options.maxResponseBytes
                ? body.subarray(0, options.maxResponseBytes)
                : body,
          });
        }
        res.destroy();
      };
      finishResponse = finish;
      res.on('data', (chunk: Buffer) => {
        chunks.push(chunk);
        size += chunk.length;
        if (size >= options.maxResponseBytes && options.overflow === 'truncate') finish('end');
        else if (size > options.maxResponseBytes) {
          settle(
            fail(
              `The answer of ${target} is larger than ${options.maxResponseBytes} bytes`,
              'too_large',
            ),
          );
          res.destroy();
        }
      });
      res.on('end', () => finish('end'));
      res.on('error', () => finish('closed'));
      res.on('close', () => finish('closed'));
    });
    req.end(request.body);
  });
}
