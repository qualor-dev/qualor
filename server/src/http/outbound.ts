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
  /**
   * The caller gives the exchange up when this aborts: the request is cut where it is, as its
   * deadline cuts it, and the answer is `aborted`, never a timeout or a failed connection (the
   * other side was neither slow nor down).
   */
  signal?: AbortSignal;
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

/** An exchange that got no answer: the `failed` of an {@link OutboundResult}. */
export type OutboundFailed = Extract<OutboundResult, { kind: 'failed' }>;

export type OutboundFailure =
  | 'invalid_url'
  | 'not_public'
  | 'refused_address'
  | 'unresolved'
  | 'timeout'
  | 'connect_timeout'
  | 'request'
  | 'connection'
  | 'too_large'
  /** The caller's signal gave the exchange up. */
  | 'aborted';

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

function fail(
  reason: string,
  cause: OutboundFailure,
  unreachable = false,
  code: string | null = null,
): OutboundFailed {
  return { kind: 'failed', reason, unreachable, cause, code };
}

/** What an exchange is when its caller's signal gave it up. */
function givenUpOf(target: string): OutboundFailed {
  return fail(`The request to ${target} was given up`, 'aborted');
}

/** What an exchange is when its connection failed: `err`'s system error code, when it has one. */
function connectionFailedOf(target: string, err?: unknown): OutboundFailed {
  return fail(
    `The connection to ${target} failed${errorCode(err)}`,
    'connection',
    true,
    codeOf(err),
  );
}

/** What an exchange is when its answer has more bytes than `limit`. */
function tooLargeOf(target: string, limit: number): OutboundFailed {
  return fail(`The answer of ${target} is larger than ${limit} bytes`, 'too_large');
}

/** What the checks before a connection leave of an exchange, to make the connection with. */
interface Cleared {
  kind: 'cleared';
  url: URL;
  /** What the checks took of the exchange's deadline. */
  elapsedMs: number;
  /**
   * The connection's own deadline, when it is shorter than the exchange's: what is left of it, and
   * what an exchange that is not connected by then is.
   */
  connect: { remainingMs: number; failure: OutboundFailed } | null;
  /**
   * Makes the request, on a fresh connection (`agent: false`, and a new `Agent` never reads the
   * proxy environment) that is pinned to the addresses which passed the checks (a custom `lookup`),
   * so that no second, different DNS answer (rebinding) is ever used. It is a `failed` when the
   * signal gave the exchange up since the checks (nothing is sent) or the request cannot be made
   * (an invalid header value or option, which throws before any connection is attempted). It is
   * called where the request's handlers are attached, with nothing between that could abort or
   * fail it.
   */
  open: () => http.ClientRequest | OutboundFailed;
}

/** The addresses `host` resolves to within `connectMs`, or why it does not. */
async function addressesOf(
  host: string,
  resolver: Resolver | undefined,
  connectMs: number,
  noun: string,
): Promise<LookupAddress[] | OutboundFailed> {
  const literal = isIP(host);
  if (literal !== 0) return [{ address: host, family: literal }];
  let timer: NodeJS.Timeout | undefined;
  try {
    const resolved = await Promise.race([
      (resolver ?? systemResolver)(host),
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
    return resolved;
  } catch {
    return fail(`The ${noun} host could not be resolved`, 'unresolved', true);
  } finally {
    clearTimeout(timer);
  }
}

/**
 * The checks before a connection, which every exchange of this module makes, and which are made
 * here only:
 * - the URL is http or https;
 * - the host is resolved once, within the connect deadline (an IP literal is checked as such,
 *   without a lookup);
 * - unless internal hosts are allowed, every address it resolves to must be public, and
 *   `refuseAddress` may refuse more of them;
 * - the deadlines have not passed, and the caller's signal has not aborted (which is looked at once
 *   more when the request is made).
 * `deadlineMs` is how long the exchange may take in all, up to its status line, and `timedOut`
 * what it is when the checks use that up. Never throws; a check that fails is a `failed`.
 */
async function clear(
  request: OutboundRequest,
  options: Pick<
    OutboundOptions,
    'allowInternalHosts' | 'refuseAddress' | 'connectTimeoutMs' | 'resolve' | 'names' | 'signal'
  >,
  deadlineMs: number,
  timedOut: OutboundFailed,
): Promise<Cleared | OutboundFailed> {
  const { noun, target } = options.names;
  const givenUp = givenUpOf(target);
  const gaveUp = (): boolean => options.signal?.aborted === true;
  if (gaveUp()) return givenUp;
  // The connection has a deadline of its own only when it is shorter than the whole exchange's.
  const connectMs = Math.min(options.connectTimeoutMs ?? CONNECT_TIMEOUT_MS, deadlineMs);
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
  const unresolved = fail(`The ${noun} host could not be resolved`, 'unresolved', true);
  const resolved = await addressesOf(hostOf(url), options.resolve, connectMs, noun);
  if (!Array.isArray(resolved)) return resolved;
  const addresses = resolved;
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
  if (deadlineMs - elapsedMs <= 0) return timedOut;
  const connectRemainingMs = connectMs - elapsedMs;
  const connect =
    connectMs < deadlineMs
      ? {
          remainingMs: connectRemainingMs,
          failure: fail(`No connection within ${durationText(connectMs)}`, 'connect_timeout', true),
        }
      : null;
  if (connectRemainingMs <= 0) return connect?.failure ?? timedOut;
  const open = (): http.ClientRequest | OutboundFailed => {
    // Given up during the lookup, or since: nothing is sent.
    if (gaveUp()) return givenUp;
    try {
      return (url.protocol === 'https:' ? https : http).request(url, {
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
      return fail(
        `The request to ${target} could not be made${errorCode(err)}`,
        'request',
        false,
        codeOf(err),
      );
    }
  };
  return { kind: 'cleared', url, elapsedMs, connect, open };
}

/**
 * The connection's own deadline of an exchange that has one (`connect` is not null): `onTimeout` is
 * called with what the exchange is when no connection is up by then. Connected is the TCP
 * connection for http and the finished TLS handshake for https. Returns the timer, which the caller
 * clears when the exchange is over.
 */
function watchConnect(
  req: http.ClientRequest,
  secure: boolean,
  connect: Cleared['connect'],
  onTimeout: (failure: OutboundFailed) => void,
): NodeJS.Timeout | undefined {
  if (connect === null) return undefined;
  const timer = setTimeout(() => onTimeout(connect.failure), connect.remainingMs);
  req.on('socket', (socket) => {
    socket.once(secure ? 'secureConnect' : 'connect', () => clearTimeout(timer));
  });
  return timer;
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
 *   host is `unresolved`); at most `maxResponseBytes` of the body are read;
 * - a caller's `signal` that aborts cuts the exchange as the deadline does (`aborted`); one that
 *   aborted before sends nothing.
 * The checks before the connection are the same for {@link outboundStream}, and made by the one
 * function (`clear`).
 * Never throws; a failure is `kind: 'failed'` with a short fixed reason.
 */
export async function outboundRequest(
  request: OutboundRequest,
  options: OutboundOptions,
): Promise<OutboundResult> {
  const { target } = options.names;
  const timedOut = fail(`No response within ${durationText(options.timeoutMs)}`, 'timeout', true);
  const givenUp = givenUpOf(target);
  const cleared = await clear(request, options, options.timeoutMs, timedOut);
  if (cleared.kind === 'failed') return cleared;
  const remainingMs = options.timeoutMs - cleared.elapsedMs;

  return new Promise<OutboundResult>((resolve) => {
    const secure = cleared.url.protocol === 'https:';
    const req = cleared.open();
    if (!(req instanceof http.ClientRequest)) {
      resolve(req);
      return;
    }
    let settled = false;
    let finishResponse: ((how: 'end' | 'deadline' | 'closed') => void) | undefined;
    const connectDeadline = watchConnect(req, secure, cleared.connect, (failure) => {
      settle(failure);
      req.destroy();
    });
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
      options.signal?.removeEventListener('abort', giveUp);
      resolve(outcome);
    };
    // The caller gave up: the exchange is cut where it is, as the deadline cuts it.
    const giveUp = (): void => {
      settle(givenUp);
      req.destroy();
    };
    options.signal?.addEventListener('abort', giveUp, { once: true });
    req.on('error', (err) => settle(connectionFailedOf(target, err)));
    req.on('response', (res) => {
      const status = res.statusCode ?? 0;
      const chunks: Buffer[] = [];
      let size = 0;
      const finish = (how: 'end' | 'deadline' | 'closed'): void => {
        if (options.overflow === 'fail' && how === 'deadline') {
          settle(
            fail(
              `The answer did not finish within ${durationText(options.timeoutMs)}`,
              'timeout',
              true,
            ),
          );
        } else if (options.overflow === 'fail' && how === 'closed') {
          settle(connectionFailedOf(target));
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
          settle(tooLargeOf(target, options.maxResponseBytes));
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

/** The limits of a streamed exchange: milliseconds, and bytes. */
export interface OutboundStreamLimits {
  /** Until the status line: the other side must have answered by then. */
  firstByteMs: number;
  /** Then, between one chunk of the body and the next. */
  idleMs: number;
  /** The whole exchange, from the call to the last byte. */
  totalMs: number;
  /** The raw bytes of a streamed body, in all. */
  maxStreamBytes: number;
  /**
   * A body that is not a 2xx's is read up to this, and no further: it is read only to classify
   * the answer.
   */
  maxErrorBytes: number;
}

/**
 * What {@link OutboundOptions} says, but for the deadline and the body's limits, which are the
 * stream's own (`limits`).
 */
export interface OutboundStreamOptions extends Omit<
  OutboundOptions,
  'timeoutMs' | 'maxResponseBytes' | 'overflow'
> {
  limits: OutboundStreamLimits;
}

/** The timer of a streamed exchange that ran out. */
export type OutboundStreamTimer = 'first_byte' | 'idle' | 'total';

export type OutboundStreamResult =
  /**
   * What goes wrong before the status line, as {@link outboundRequest} says it; a `timeout` also
   * says which timer ran out.
   */
  | (OutboundFailed & { timer?: OutboundStreamTimer })
  /** A status outside 2xx, with its body (read only to classify the answer, so cut at the limit). */
  | { kind: 'response'; status: number; headers: IncomingHttpHeaders; body: Buffer }
  /** A 2xx: its body, as it arrives. */
  | { kind: 'stream'; status: number; headers: IncomingHttpHeaders; chunks: AsyncIterable<Buffer> };

/** What can stop a stream that has begun. */
export type OutboundStreamCause = Extract<
  OutboundFailure,
  'timeout' | 'too_large' | 'connection' | 'aborted'
>;

/** Thrown by the chunks of a stream that went wrong after its status line. */
export class OutboundStreamError extends Error {
  constructor(
    override readonly cause: OutboundStreamCause,
    /** A short fixed text (never a URL, header or body); the error's message too. */
    readonly reason: string,
    /** Which timer ran out, for a `timeout`. */
    readonly timer: OutboundStreamTimer | null = null,
    /** The system error code (`ECONNRESET`), when there is one. */
    readonly code: string | null = null,
  ) {
    super(reason);
    this.name = 'OutboundStreamError';
  }
}

function streamCause(cause: OutboundFailure): OutboundStreamCause {
  return cause === 'timeout' || cause === 'too_large' || cause === 'aborted' ? cause : 'connection';
}

interface Reader {
  resolve: (step: IteratorResult<Buffer, undefined>) => void;
  reject: (error: unknown) => void;
}

/**
 * The body of a streamed answer, for the one that reads it: the chunks that have arrived and are
 * not read yet wait here (the stream's raw cap bounds them), the end is told after them, and so is a
 * failure, once: the reader gets what the other side sent before it went wrong, and then the
 * error. `return()` is the reader that stops early: the exchange is cut (`stop`), and nothing more
 * is kept or told. It is what `for await` calls on `break`, and so it also works before the first
 * read.
 */
class StreamBody implements AsyncIterableIterator<Buffer, undefined> {
  private readonly chunks: Buffer[] = [];
  private readonly readers: Reader[] = [];
  private ended = false;
  private failure: OutboundStreamError | null = null;

  constructor(private readonly stop: () => void) {}

  /** A chunk of the body arrived. */
  push(chunk: Buffer): void {
    this.chunks.push(chunk);
    this.serve();
  }

  /** The body is over. */
  end(): void {
    this.ended = true;
    this.serve();
  }

  /** The exchange failed: what arrived before is read first, and then the next read throws. */
  fail(error: OutboundStreamError): void {
    this.failure = error;
    this.serve();
  }

  next(): Promise<IteratorResult<Buffer, undefined>> {
    return new Promise((resolve, reject) => {
      this.readers.push({ resolve, reject });
      this.serve();
    });
  }

  return(): Promise<IteratorResult<Buffer, undefined>> {
    this.ended = true;
    this.failure = null;
    this.chunks.length = 0;
    this.stop();
    this.serve();
    return Promise.resolve({ done: true, value: undefined });
  }

  [Symbol.asyncIterator](): this {
    return this;
  }

  /** Answers the reads that wait, with what there is to answer them with. */
  private serve(): void {
    while (this.readers.length > 0) {
      const chunk = this.chunks.shift();
      if (chunk !== undefined) {
        this.readers.shift()?.resolve({ done: false, value: chunk });
      } else if (this.failure !== null) {
        const error = this.failure;
        this.failure = null;
        this.ended = true;
        this.readers.shift()?.reject(error);
      } else if (this.ended) {
        this.readers.shift()?.resolve({ done: true, value: undefined });
      } else {
        return;
      }
    }
  }
}

/**
 * One server-side request whose answer is read as it arrives (a body of server-sent events), with
 * the protections of {@link outboundRequest}, which it shares the checks before the connection with
 * (`clear`): the address checks and the pinned lookup, a fresh connection without a proxy, no
 * redirect followed, the connect deadline, and a `signal` that gives the exchange up.
 *
 * Answers when the status line has arrived, with:
 * - `stream`, for a 2xx: its `chunks` are the body, as they arrive. They throw
 *   {@link OutboundStreamError} (after the chunks that arrived before the failure) with the cause
 *   `timeout` (a timer ran out: `reason` and `timer` say which), `too_large` (more than
 *   `maxStreamBytes` raw bytes), `connection` (closed or broken before the end of the body) or
 *   `aborted` (the signal); every one cuts the connection;
 * - `response`, for any other status: its body, read up to `maxErrorBytes` (what is over is cut and
 *   the connection closed), which is only to classify the answer. What cuts that short, a timer or
 *   a connection that breaks, gives the body as far as it came: the status is what counts;
 * - `failed`, as {@link outboundRequest} gives it, for what goes wrong before the status line, and
 *   for a signal that aborts while a refused answer's body is read.
 *
 * The timers: one is armed with the call, `firstByteMs` until the status line, then `idleMs`, which
 * every chunk of the body arms again; and one of `totalMs` runs from the call to the last byte. The
 * checks before the connection run within the shorter of `firstByteMs` and `totalMs`. Every timer,
 * the signal's listener and the socket are cleaned up on every way out of the exchange: its end, a
 * failure, an abort, and a reader that stops early (`return()`, which `break` calls), even before
 * its first read. Never throws.
 */
export async function outboundStream(
  request: OutboundRequest,
  options: OutboundStreamOptions,
): Promise<OutboundStreamResult> {
  const { limits } = options;
  const { target } = options.names;
  const timeoutText = (timer: OutboundStreamTimer): string => {
    if (timer === 'first_byte') return `No response within ${durationText(limits.firstByteMs)}`;
    if (timer === 'idle') return `No data from ${target} for ${durationText(limits.idleMs)}`;
    return `The answer of ${target} was not complete within ${durationText(limits.totalMs)}`;
  };
  const timeoutOf = (
    timer: OutboundStreamTimer,
  ): OutboundFailed & { timer: OutboundStreamTimer } => ({
    ...fail(timeoutText(timer), 'timeout', true),
    timer,
  });
  const checksTimer = limits.totalMs < limits.firstByteMs ? 'total' : 'first_byte';
  const cleared = await clear(
    request,
    options,
    Math.min(limits.firstByteMs, limits.totalMs),
    timeoutOf(checksTimer),
  );
  if (cleared.kind === 'failed') return cleared;

  return new Promise<OutboundStreamResult>((resolve) => {
    const secure = cleared.url.protocol === 'https:';
    const req = cleared.open();
    if (!(req instanceof http.ClientRequest)) {
      resolve(req);
      return;
    }
    const givenUp = givenUpOf(target);
    const tooLarge = tooLargeOf(target, limits.maxStreamBytes);
    const lost = (err?: unknown): OutboundFailed =>
      err === undefined
        ? fail(`The connection to ${target} was closed before the answer ended`, 'connection', true)
        : connectionFailedOf(target, err);
    /**
     * Where the exchange is: waiting for the status line; reading the body of a refused answer;
     * streaming a body; or over, with everything it held cleaned up.
     */
    let phase: 'sending' | 'refused' | 'streaming' | 'over' = 'sending';
    let res: http.IncomingMessage | undefined;
    /** The first-byte timer, and from the status line on the idle timer. */
    let waitTimer: NodeJS.Timeout | undefined;
    let received = 0;
    /** Ends the read of a refused answer's body, with what has arrived of it. */
    let endRefusal: () => void = () => undefined;
    const totalTimer = setTimeout(
      () => stop(timeoutOf('total')),
      limits.totalMs - cleared.elapsedMs,
    );
    const connectDeadline = watchConnect(req, secure, cleared.connect, (failure) => stop(failure));

    /** The exchange is over, whichever way: no timer, no listener on the signal, no socket. */
    const release = (): void => {
      if (phase === 'over') return;
      phase = 'over';
      clearTimeout(waitTimer);
      clearTimeout(totalTimer);
      clearTimeout(connectDeadline);
      options.signal?.removeEventListener('abort', giveUp);
      res?.destroy();
      req.destroy();
    };
    const body = new StreamBody(release);
    /** The exchange goes wrong as far as it has got (see the ends of {@link outboundStream}). */
    const stop = (failed: OutboundFailed & { timer?: OutboundStreamTimer }): void => {
      switch (phase) {
        case 'sending':
          release();
          resolve(failed);
          return;
        case 'refused':
          // Only the caller's giving up is more than a refused answer's body that ends early.
          if (failed.cause === 'aborted') {
            release();
            resolve(failed);
          } else {
            endRefusal();
          }
          return;
        case 'streaming':
          release();
          body.fail(
            new OutboundStreamError(
              streamCause(failed.cause),
              failed.reason,
              failed.timer ?? null,
              failed.code,
            ),
          );
          return;
        case 'over':
          return;
      }
    };
    const giveUp = (): void => stop(givenUp);
    const arm = (ms: number, timer: OutboundStreamTimer): void => {
      clearTimeout(waitTimer);
      waitTimer = setTimeout(() => stop(timeoutOf(timer)), ms);
    };

    const answerRefused = (incoming: http.IncomingMessage, status: number): void => {
      phase = 'refused';
      const parts: Buffer[] = [];
      let size = 0;
      endRefusal = () => {
        if (phase !== 'refused') return;
        release();
        resolve({
          kind: 'response',
          status,
          headers: incoming.headers,
          body: Buffer.concat(parts).subarray(0, limits.maxErrorBytes),
        });
      };
      arm(limits.idleMs, 'idle');
      incoming.on('data', (chunk: Buffer) => {
        if (phase !== 'refused') return;
        parts.push(chunk);
        size += chunk.length;
        if (size >= limits.maxErrorBytes) endRefusal();
        else arm(limits.idleMs, 'idle');
      });
      incoming.on('end', () => endRefusal());
      incoming.on('error', () => endRefusal());
      incoming.on('close', () => endRefusal());
    };

    const answerStreamed = (incoming: http.IncomingMessage, status: number): void => {
      phase = 'streaming';
      arm(limits.idleMs, 'idle');
      resolve({ kind: 'stream', status, headers: incoming.headers, chunks: body });
      incoming.on('data', (chunk: Buffer) => {
        if (phase !== 'streaming') return;
        received += chunk.length;
        if (received > limits.maxStreamBytes) {
          stop(tooLarge);
          return;
        }
        arm(limits.idleMs, 'idle');
        body.push(chunk);
      });
      incoming.on('end', () => {
        if (phase !== 'streaming') return;
        release();
        body.end();
      });
      incoming.on('error', (err) => stop(lost(err)));
      incoming.on('close', () => stop(lost()));
    };

    options.signal?.addEventListener('abort', giveUp, { once: true });
    arm(limits.firstByteMs - cleared.elapsedMs, 'first_byte');
    req.on('error', (err) => stop(lost(err)));
    req.on('response', (incoming) => {
      res = incoming;
      if (phase !== 'sending') {
        incoming.destroy();
        return;
      }
      const status = incoming.statusCode ?? 0;
      if (status >= 200 && status < 300) answerStreamed(incoming, status);
      else answerRefused(incoming, status);
    });
    req.end(request.body);
  });
}
