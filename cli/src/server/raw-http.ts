import type { IncomingHttpHeaders } from 'node:http';
import net from 'node:net';
import type { Readable } from 'node:stream';
import tls from 'node:tls';

/**
 * A request with a body over one plain socket (`node:net` / `node:tls`), HTTP/1.1 written and
 * parsed here. Ruling E5 needs `Expect: 100-continue` honoured exactly (the body only after a
 * `100 Continue`, never after a final answer) and upload progress measured on the socket; the
 * shipped binary runs on Bun, whose `node:http` client does neither: it emits 'continue' as soon
 * as the socket exists, buffers the whole body in memory, surfaces no response before the body is
 * sent, and closes a request on `timeout` even while it uploads. A socket behaves the same on
 * Node and Bun, so the unit tests (Node) and `smoke:upload` (Bun) check one code path.
 *
 * Ruling V9: `HTTPS_PROXY`/`HTTP_PROXY` (either case) and `NO_PROXY` are honoured as Bun's
 * `fetch` honours them for the JSON exchanges. Through a proxy the request always goes through a
 * `CONNECT` tunnel, for `http` origins too, so `Expect` works end to end; TLS runs inside the
 * tunnel with the origin's name. The token never goes to the proxy: proxy credentials come only
 * from the proxy URL and travel in `Proxy-Authorization`, and no message shows them.
 */
export interface RawRequest {
  url: URL;
  method: 'POST';
  /** Lower-case names; `host`, `connection` and framing headers are added here. */
  headers: Readonly<Record<string, string>>;
  body: { stream: () => Readable; contentLength: number };
  /** TLS trust (`caBundle`); the default store when undefined. */
  ca?: string[] | undefined;
  /**
   * No progress in either direction for this long fails the upload. Connecting (through a proxy
   * included), and the rest of the answer once its head has arrived or the whole body has been
   * handed over, must each complete within it.
   */
  timeoutMs: number;
  /** How long to wait for `100 Continue` before sending the body anyway. */
  continueWaitMs: number;
  maxResponseBytes: number;
  /** Where the proxy variables are read (default `process.env`). */
  env?: Readonly<Record<string, string | undefined>> | undefined;
}

export interface RawResponse {
  status: number;
  headers: IncomingHttpHeaders;
  body: Buffer;
}

/** Why a request failed, without any request data (the caller adds the origin). */
export class RawHttpError extends Error {}

const MAX_HEAD_BYTES = 64 * 1024;
/** 1xx answers accepted before the final one (100, 102, 103, …); more is a misbehaving server. */
const MAX_INFORMATIONAL = 8;
const MAX_CHUNK_LINE = 1024;
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const STATUS_LINE = /^HTTP\/1\.[01] (\d{3})(?: [^\r\n]*)?$/;

/** A field value: HTAB, visible ASCII, space and obs-text; no NUL, CR, LF or other control. */
function validFieldValue(value: string): boolean {
  for (let i = 0; i < value.length; i++) {
    const c = value.charCodeAt(i);
    if (c === 0x09) continue;
    if (c < 0x20 || c === 0x7f || c > 0xff) return false;
  }
  return true;
}

/** Only optional whitespace (SP / HTAB) is trimmed (RFC 9110 §5.5). */
function trimOws(value: string): string {
  return value.replace(/^[ \t]+|[ \t]+$/g, '');
}

function hostOf(url: URL): string {
  return url.hostname.replace(/^\[(.*)\]$/, '$1');
}

function portOf(url: URL): number {
  return Number(url.port || (url.protocol === 'https:' ? 443 : 80));
}

/** `host:port` of the origin, IPv6 in brackets, for `CONNECT`. */
function authority(url: URL): string {
  const host = hostOf(url);
  return `${net.isIP(host) === 6 ? `[${host}]` : host}:${portOf(url)}`;
}

const lookup = (env: Readonly<Record<string, string | undefined>>, name: string) => {
  const value = env[name.toLowerCase()] ?? env[name.toUpperCase()];
  return value === undefined || value.trim() === '' ? undefined : value.trim();
};

/**
 * True when `NO_PROXY` exempts the origin: `*`; or an entry `name[:port]` that equals the host or
 * is a domain suffix of it (a leading `.` or `*.` is ignored), with the port, when given, equal
 * to the origin's. Entries are separated by commas or whitespace; case does not matter.
 */
export function noProxyMatches(url: URL, noProxy: string | undefined): boolean {
  if (noProxy === undefined) return false;
  const host = hostOf(url).toLowerCase().replace(/\.$/, '');
  const port = portOf(url);
  for (const raw of noProxy.toLowerCase().split(/[\s,]+/)) {
    if (raw === '') continue;
    if (raw === '*') return true;
    let entry = raw;
    let entryPort: number | undefined;
    const bracketed = /^\[([^\]]+)\](?::(\d+))?$/.exec(entry);
    if (bracketed !== null) {
      entry = bracketed[1] ?? '';
      if (bracketed[2] !== undefined) entryPort = Number(bracketed[2]);
    } else {
      const withPort = /^([^:]+):(\d+)$/.exec(entry);
      if (withPort !== null) {
        entry = withPort[1] ?? '';
        entryPort = Number(withPort[2]);
      }
    }
    entry = entry.replace(/^\*?\./, '').replace(/\.$/, '');
    if (entry === '') continue;
    if (entryPort !== undefined && entryPort !== port) continue;
    if (host === entry || host.endsWith(`.${entry}`)) return true;
  }
  return false;
}

/**
 * `localhost` and loopback addresses (127.0.0.0/8, ::1) never go through a proxy, as in Go's
 * `httpproxy`: a proxy cannot reach the CLI's own loopback, and an `http` server there would
 * otherwise have its token cross the network to the proxy in clear text.
 */
export function isLoopback(url: URL): boolean {
  const host = hostOf(url).toLowerCase().replace(/\.$/, '');
  if (host === 'localhost') return true;
  if (net.isIPv4(host)) return host.startsWith('127.');
  return host === '::1' || host === '0:0:0:0:0:0:0:1';
}

/**
 * The proxy for `url` (ruling V9): `https_proxy`/`HTTPS_PROXY`, then `http_proxy`/`HTTP_PROXY`,
 * for an `https` origin; `http_proxy`/`HTTP_PROXY` for an `http` origin; none for a loopback
 * origin or when `NO_PROXY` exempts it. A value without a scheme means `http://`. Only `http://` proxies are supported;
 * anything else, or a value that is not a URL, fails (without showing it).
 */
export function proxyFor(url: URL, env: Readonly<Record<string, string | undefined>>): URL | null {
  const names = url.protocol === 'https:' ? ['https_proxy', 'http_proxy'] : ['http_proxy'];
  let value: string | undefined;
  let name = '';
  for (const n of names) {
    value = lookup(env, n);
    if (value !== undefined) {
      name = n.toUpperCase();
      break;
    }
  }
  if (value === undefined || isLoopback(url) || noProxyMatches(url, lookup(env, 'no_proxy'))) {
    return null;
  }
  let proxy: URL;
  try {
    proxy = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(value) ? value : `http://${value}`);
  } catch {
    throw new RawHttpError(`${name} is not a valid URL`);
  }
  if (proxy.protocol !== 'http:') {
    throw new RawHttpError(`${name} must be an http:// proxy (${proxy.protocol} is not supported)`);
  }
  return proxy;
}

/** `Proxy-Authorization` from the proxy URL's user info, if any. */
function proxyAuthorization(proxy: URL): string | undefined {
  if (proxy.username === '' && proxy.password === '') return undefined;
  let user: string;
  let pass: string;
  try {
    user = decodeURIComponent(proxy.username);
    pass = decodeURIComponent(proxy.password);
  } catch {
    throw new RawHttpError('the proxy credentials are not valid percent-encoding');
  }
  return `Basic ${Buffer.from(`${user}:${pass}`, 'utf8').toString('base64')}`;
}

/** The request head; a header that could split the request is refused (never shown). */
function requestHead(r: RawRequest): string {
  const lines = [`${r.method} ${r.url.pathname}${r.url.search} HTTP/1.1`, `host: ${r.url.host}`];
  const headers: Record<string, string> = {
    ...r.headers,
    'content-length': String(r.body.contentLength),
    expect: '100-continue',
    connection: 'close',
  };
  for (const [name, value] of Object.entries(headers)) {
    if (!TOKEN.test(name)) throw new RawHttpError('ERR_INVALID_HTTP_TOKEN');
    if (!validFieldValue(value)) throw new RawHttpError(`ERR_INVALID_CHAR (header ${name})`);
    lines.push(`${name}: ${value}`);
  }
  return `${lines.join('\r\n')}\r\n\r\n`;
}

interface Head {
  status: number;
  headers: IncomingHttpHeaders;
}

function parseHead(text: string): Head {
  const [statusLine = '', ...lines] = text.split('\r\n');
  const status = STATUS_LINE.exec(statusLine);
  if (status === null) throw new RawHttpError('the server did not answer with HTTP/1.1');
  // No prototype: a `__proto__` or `constructor` header is just a header.
  const headers = Object.create(null) as IncomingHttpHeaders;
  for (const line of lines) {
    const colon = line.indexOf(':');
    const name = line.slice(0, colon).toLowerCase();
    const value = trimOws(line.slice(colon + 1));
    if (colon <= 0 || !TOKEN.test(name) || !validFieldValue(value)) {
      throw new RawHttpError('the server sent an invalid response header');
    }
    const prev = headers[name];
    if (name === 'set-cookie') {
      headers[name] = [...(Array.isArray(prev) ? prev : []), value];
    } else {
      headers[name] = typeof prev === 'string' ? `${prev}, ${value}` : value;
    }
  }
  return { status: Number(status[1]), headers };
}

type Framing = { kind: 'length'; remaining: number } | { kind: 'chunked' } | { kind: 'close' };

function framing(head: Head): Framing {
  if (head.status === 204 || head.status === 304) return { kind: 'length', remaining: 0 };
  const te = head.headers['transfer-encoding'];
  if (typeof te === 'string') {
    const codings = te.toLowerCase().split(',');
    return codings[codings.length - 1]?.trim() === 'chunked'
      ? { kind: 'chunked' }
      : { kind: 'close' };
  }
  const cl = head.headers['content-length'];
  if (cl === undefined) return { kind: 'close' };
  const values = new Set(
    String(cl)
      .split(',')
      .map((v) => v.trim()),
  );
  const [only] = values;
  if (values.size !== 1 || only === undefined || !/^\d{1,15}$/.test(only)) {
    throw new RawHttpError('the server sent an invalid Content-Length');
  }
  return { kind: 'length', remaining: Number(only) };
}

/**
 * The connection to the origin, ready for the request head: direct, or through a `CONNECT`
 * tunnel (V9), with TLS for `https`. Connecting, the proxy's answer and the TLS handshake must
 * all complete within `timeoutMs` (a proxy that never answers or trickles cannot hold the CLI).
 */
function open(r: RawRequest, proxy: URL | null): Promise<net.Socket> {
  const originHost = hostOf(r.url);
  const tlsOptions = {
    // SNI only for names (RFC 6066); an IP address is checked against the certificate's IP SANs.
    ...(net.isIP(originHost) === 0 && { servername: originHost }),
    // Explicit, so NODE_TLS_REJECT_UNAUTHORIZED=0 in the environment cannot switch it off.
    rejectUnauthorized: true,
    ALPNProtocols: ['http/1.1'],
    ...(r.ca !== undefined && { ca: r.ca }),
  };
  const isHttps = r.url.protocol === 'https:';
  return new Promise((resolve, reject) => {
    const sockets: net.Socket[] = [];
    /** Only our own listeners are removed: TLS keeps its own on the tunnel socket. */
    const detach: (() => void)[] = [];
    let settled = false;
    const done = (err: RawHttpError | null, socket?: net.Socket) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      for (const d of detach) d();
      if (err !== null || socket === undefined) {
        for (const s of sockets) s.destroy();
        reject(err ?? new RawHttpError('cannot connect'));
      } else {
        // Errors after this point belong to the exchange, which listens itself.
        for (const s of sockets) s.on('error', () => undefined);
        resolve(socket);
      }
    };
    const timer = setTimeout(
      () =>
        done(
          new RawHttpError(
            proxy === null
              ? `cannot connect within ${r.timeoutMs / 1000} s`
              : `the proxy did not open a tunnel within ${r.timeoutMs / 1000} s`,
          ),
        ),
      r.timeoutMs,
    );
    const watch = (s: net.Socket, what: string) => {
      sockets.push(s);
      const onError = (e: NodeJS.ErrnoException) =>
        done(new RawHttpError(`${what}${e.code ?? e.message}`));
      const onClose = () => done(new RawHttpError(`${what}the connection closed`));
      s.on('error', onError);
      s.on('close', onClose);
      detach.push(() => {
        s.off('error', onError);
        s.off('close', onClose);
      });
    };
    const startTls = (socket: net.Socket) => {
      const secure = tls.connect({ socket, host: originHost, ...tlsOptions });
      watch(secure, '');
      secure.once('secureConnect', () => done(null, secure));
    };
    try {
      if (proxy === null) {
        const port = portOf(r.url);
        if (isHttps) {
          const secure = tls.connect({ host: originHost, port, ...tlsOptions });
          watch(secure, '');
          secure.once('secureConnect', () => done(null, secure));
        } else {
          const plain = net.connect({ host: originHost, port });
          watch(plain, '');
          plain.once('connect', () => done(null, plain));
        }
        return;
      }
      const auth = proxyAuthorization(proxy);
      const tunnel = net.connect({ host: hostOf(proxy), port: portOf(proxy) });
      watch(tunnel, 'proxy: ');
      tunnel.once('connect', () => {
        const target = authority(r.url);
        tunnel.write(
          `CONNECT ${target} HTTP/1.1\r\nhost: ${target}\r\n` +
            (auth === undefined ? '' : `proxy-authorization: ${auth}\r\n`) +
            '\r\n',
        );
      });
      let buffer: Buffer = Buffer.alloc(0);
      let informational = 0;
      const onData = (d: Buffer) => {
        buffer = buffer.length === 0 ? d : Buffer.concat([buffer, d]);
        for (;;) {
          const end = buffer.indexOf('\r\n\r\n');
          if (end < 0 ? buffer.length > MAX_HEAD_BYTES : end > MAX_HEAD_BYTES) {
            done(new RawHttpError('the proxy answer is too large'));
            return;
          }
          if (end < 0) {
            if (buffer.indexOf('\n\n') >= 0) {
              done(new RawHttpError('the proxy answered with bare LF line endings (not HTTP/1.1)'));
            }
            return;
          }
          let head: Head;
          try {
            head = parseHead(buffer.subarray(0, end).toString('latin1'));
          } catch {
            done(new RawHttpError('the proxy did not answer with HTTP/1.1'));
            return;
          }
          if (head.status >= 100 && head.status < 200 && head.status !== 101) {
            // An informational answer before the tunnel's own (e.g. 100 or 103): skipped, bounded.
            informational += 1;
            if (informational > MAX_INFORMATIONAL) {
              done(new RawHttpError('the proxy sent too many informational (1xx) answers'));
              return;
            }
            buffer = buffer.subarray(end + 4);
            continue;
          }
          if (head.status === 407) {
            done(
              new RawHttpError(
                'the proxy requires authentication (407); put the credentials in the proxy URL',
              ),
            );
          } else if (head.status < 200 || head.status > 299) {
            done(new RawHttpError(`the proxy refused the tunnel (${head.status})`));
          } else if (buffer.length > end + 4) {
            done(new RawHttpError('the proxy sent data before the tunnel was open'));
          } else {
            tunnel.pause();
            tunnel.off('data', onData);
            if (isHttps) startTls(tunnel);
            else done(null, tunnel);
          }
          return;
        }
      };
      tunnel.on('data', onData);
      detach.push(() => tunnel.off('data', onData));
    } catch (err) {
      done(
        err instanceof RawHttpError
          ? err
          : new RawHttpError(
              err instanceof Error && 'code' in err ? String(err.code) : 'cannot connect',
            ),
      );
    }
  });
}

/**
 * Sends one request with `Expect: 100-continue` and returns the final response. The body is
 * sent after `100 Continue`, or after `continueWaitMs` without any answer (RFC 9110 §10.1.1: a
 * proxy may ignore Expect); never after a final answer, and sending stops (the body stream is
 * closed) as soon as the final answer is complete. Every byte of the answer (1xx heads, chunk
 * lines, extensions and trailers included) counts toward one bound, at most `MAX_INFORMATIONAL`
 * 1xx answers are accepted, and once the final head has arrived or the whole body has been handed
 * over, the rest of the answer must arrive within `timeoutMs`. Settles once: errors reject with a
 * `RawHttpError` whose message holds no request data and no credentials.
 */
export async function rawRequestWithBody(r: RawRequest): Promise<RawResponse> {
  const head = requestHead(r);
  const proxy = proxyFor(r.url, r.env ?? process.env);
  const socket = await open(r, proxy);
  return exchange(r, socket, head);
}

function exchange(r: RawRequest, socket: net.Socket, head: string): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let stream: Readable | undefined;
    let bodyStarted = false;
    let sent = 0;
    let idleTimer: NodeJS.Timeout | undefined;
    let deadline: NodeJS.Timeout | undefined;
    /** Runs while a response head is incomplete: a head must arrive whole within `timeoutMs`. */
    let headTimer: NodeJS.Timeout | undefined;
    let buffer: Buffer = Buffer.alloc(0);
    let final: Head | undefined;
    let frame: Framing | undefined;
    let informational = 0;
    let received = 0;
    const maxReceived = r.maxResponseBytes + MAX_HEAD_BYTES;
    const bodyChunks: Buffer[] = [];
    let bodyBytes = 0;
    const tooLarge = `the response is larger than ${r.maxResponseBytes} bytes`;

    const stop = () => {
      clearTimeout(continueTimer);
      clearTimeout(idleTimer);
      clearTimeout(deadline);
      clearTimeout(headTimer);
      stream?.unpipe(socket);
      stream?.destroy();
      socket.destroy();
    };
    const fail = (why: string) => {
      if (settled) return;
      settled = true;
      stop();
      reject(new RawHttpError(why));
    };
    const finish = () => {
      if (settled || final === undefined) return;
      settled = true;
      // `Connection: close` was sent; a body still on its way is abandoned (never sent on).
      stop();
      resolve({ status: final.status, headers: final.headers, body: Buffer.concat(bodyChunks) });
    };
    const progress = () => {
      if (settled) return;
      clearTimeout(idleTimer);
      idleTimer = setTimeout(() => fail(`no response within ${r.timeoutMs / 1000} s`), r.timeoutMs);
    };
    /** From the final head, or the last body byte handed over: the rest within `timeoutMs`. */
    const startDeadline = () => {
      if (settled || deadline !== undefined) return;
      deadline = setTimeout(
        () => fail(`no complete response within ${r.timeoutMs / 1000} s`),
        r.timeoutMs,
      );
    };

    const sendBody = () => {
      if (bodyStarted || final !== undefined || settled) return;
      bodyStarted = true;
      clearTimeout(continueTimer);
      const s = r.body.stream();
      stream = s;
      s.on('error', (err) => fail(`cannot read the request body: ${err.message}`));
      s.on('data', (chunk: Buffer | string) => {
        sent += Buffer.byteLength(chunk);
        if (sent > r.body.contentLength) fail('the request body is longer than declared');
        progress();
      });
      s.on('end', () => {
        if (sent !== r.body.contentLength) fail('the request body is shorter than declared');
        else startDeadline();
      });
      s.pipe(socket, { end: false });
    };

    const addBody = (chunk: Buffer): boolean => {
      bodyBytes += chunk.length;
      if (bodyBytes > r.maxResponseBytes) {
        fail(tooLarge);
        return false;
      }
      bodyChunks.push(chunk);
      return true;
    };

    /** Consumes `buffer` as far as possible; returns when more bytes are needed. */
    const parse = () => {
      while (!settled) {
        if (final === undefined) {
          const end = buffer.indexOf('\r\n\r\n');
          if (end < 0 ? buffer.length > MAX_HEAD_BYTES : end > MAX_HEAD_BYTES) {
            fail('the response head is too large');
            return;
          }
          if (end < 0) {
            if (buffer.indexOf('\n\n') >= 0) {
              fail('the server answered with bare LF line endings (not HTTP/1.1)');
              return;
            }
            // A head that has started must be complete within `timeoutMs`: its bytes alone must
            // not keep the upload alive (a server that stopped reading the body and trickles a
            // head would otherwise hold it for weeks at one byte per timeout).
            if (buffer.length > 0 && headTimer === undefined) {
              headTimer = setTimeout(
                () => fail(`no complete response head within ${r.timeoutMs / 1000} s`),
                r.timeoutMs,
              );
            }
            return;
          }
          clearTimeout(headTimer);
          headTimer = undefined;
          const parsed = parseHead(buffer.subarray(0, end).toString('latin1'));
          buffer = buffer.subarray(end + 4);
          if (parsed.status === 101) throw new RawHttpError('the server switched protocols');
          if (parsed.status < 200) {
            informational += 1;
            if (informational > MAX_INFORMATIONAL) {
              throw new RawHttpError('the server sent too many informational (1xx) answers');
            }
            if (parsed.status === 100) sendBody();
            continue; // 102/103: informational only
          }
          final = parsed;
          clearTimeout(continueTimer);
          startDeadline();
          // Transfer-Encoding wins over Content-Length (RFC 9112 §6.3).
          frame = framing(parsed);
          if (frame.kind === 'length' && frame.remaining > r.maxResponseBytes) {
            fail(tooLarge);
            return;
          }
          continue;
        }
        if (frame === undefined) return;
        if (frame.kind === 'length') {
          const take = buffer.subarray(0, frame.remaining);
          buffer = buffer.subarray(take.length);
          frame.remaining -= take.length;
          if (take.length > 0 && !addBody(take)) return;
          if (frame.remaining === 0) finish();
          return;
        }
        if (frame.kind === 'close') {
          if (buffer.length > 0 && !addBody(buffer)) return;
          buffer = Buffer.alloc(0);
          return;
        }
        // chunked: `size[;ext]\r\n data \r\n`, … `0\r\n` trailers `\r\n`
        const lineEnd = buffer.indexOf('\r\n');
        if (lineEnd < 0 ? buffer.length > MAX_CHUNK_LINE : lineEnd > MAX_CHUNK_LINE) {
          fail('the server sent an invalid chunked response');
          return;
        }
        if (lineEnd < 0) return;
        const sizeText = buffer.subarray(0, lineEnd).toString('latin1').split(';')[0]?.trim();
        if (sizeText === undefined || !/^[0-9a-fA-F]{1,8}$/.test(sizeText)) {
          fail('the server sent an invalid chunked response');
          return;
        }
        const size = parseInt(sizeText, 16);
        if (size === 0) {
          // The last chunk, then an empty line or trailer lines ending in one (bounded by
          // `maxReceived`, like every byte of the answer).
          if (buffer.indexOf('\r\n\r\n', lineEnd) >= 0) finish();
          return;
        }
        if (bodyBytes + size > r.maxResponseBytes) {
          fail(tooLarge);
          return;
        }
        if (buffer.length < lineEnd + 2 + size + 2) return;
        if (buffer.subarray(lineEnd + 2 + size, lineEnd + 4 + size).toString('latin1') !== '\r\n') {
          fail('the server sent an invalid chunked response');
          return;
        }
        if (!addBody(buffer.subarray(lineEnd + 2, lineEnd + 2 + size))) return;
        buffer = buffer.subarray(lineEnd + 4 + size);
      }
    };

    progress();
    socket.on('drain', progress);
    socket.on('data', (d: Buffer) => {
      progress();
      received += d.length;
      if (received > maxReceived) {
        fail(tooLarge);
        return;
      }
      buffer = buffer.length === 0 ? d : Buffer.concat([buffer, d]);
      try {
        parse();
      } catch (err) {
        fail(err instanceof Error ? err.message : String(err));
      }
    });
    socket.on('end', () => {
      // A close-delimited answer is complete only at a clean end of the stream. Node reports a
      // reset as 'error' (ECONNRESET) instead, so it fails below; Bun 1.3 may report some resets
      // as a plain end, which cannot be told apart from a clean close here.
      if (frame?.kind === 'close') finish();
      else if (final === undefined) fail('the connection closed without a response');
      else fail('the connection closed before the response was complete');
    });
    // After a complete answer these change nothing (`finish` has settled).
    socket.on('error', (err: NodeJS.ErrnoException) => fail(err.code ?? err.message));
    socket.on('close', () => {
      if (final === undefined) fail('the connection closed without a response');
      else fail('the connection closed before the response was complete');
    });
    socket.resume();
    socket.write(head);
    // Declared last; the handlers above only run after this line (all events are async).
    const continueTimer = setTimeout(sendBody, r.continueWaitMs);
  });
}
