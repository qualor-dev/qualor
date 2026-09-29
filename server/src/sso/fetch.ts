import type { CustomFetch } from 'openid-client';
import { outboundRequest, type OutboundFailure, type Resolver } from '../http/outbound';
import { isInternalHostAllowed, scmRefusedAddress } from '../scm/url';

/** spec §14: 10 s in all (the connection's 3 s is outboundRequest's default). */
export const SSO_FETCH_TIMEOUT_MS = 10_000;
/** spec §14: at most 512 KiB of an answer is read. */
export const SSO_FETCH_MAX_BYTES = 512 * 1024;

export class SsoFetchRefused extends Error {
  constructor(
    readonly reason: 'not_allowed' | 'method' | 'status' | 'tls' | OutboundFailure,
    /** For the log only: the system error code (`CERT_HAS_EXPIRED`), when there is one. */
    readonly code: string | null = null,
    /** For the log only: the HTTP status of a `status` refusal, when one arrived. */
    readonly status: number | null = null,
  ) {
    super(`identity provider request refused: ${reason}`);
    this.name = 'SsoFetchRefused';
  }
}

/** A system error code of a failed TLS handshake or certificate check (`CERT_HAS_EXPIRED`). */
export function isTlsErrorCode(code: string | null): boolean {
  return code !== null && /CERT|SSL|TLS|^EPROTO$/.test(code);
}

/** The first SsoFetchRefused in an error's cause chain (openid-client wraps it), or null. */
export function ssoFetchRefusal(err: unknown): SsoFetchRefused | null {
  let current: unknown = err;
  for (let depth = 0; depth < 5 && current !== null && typeof current === 'object'; depth++) {
    if (current instanceof SsoFetchRefused) return current;
    current = (current as { cause?: unknown }).cause;
  }
  return null;
}

export interface SsoFetchPolicy {
  internalHosts: ReadonlySet<string>;
  /** Exact URLs, without query or fragment, that may be requested. */
  allowed: Set<string>;
  resolve?: Resolver;
  maxResponseBytes?: number;
}

export type SsoFetch = CustomFetch & { allow(url: string): void };

const withoutQuery = (raw: string): string => {
  const u = new URL(raw);
  u.search = '';
  u.hash = '';
  return u.href;
};

/** Only the bodies openid-client sends (a form, or JSON text); anything else is refused. */
function bodyText(body: unknown): string | undefined | null {
  if (body === undefined || body === null) return undefined;
  if (body instanceof URLSearchParams) return body.toString();
  if (typeof body === 'string') return body;
  return null;
}

/**
 * openid-client's timeout arrives as an AbortSignal. outboundRequest takes none, so the caller is
 * answered at once and the request itself ends at its own deadline (SSO_FETCH_TIMEOUT_MS, the
 * same 10 s), its answer discarded.
 */
function abortable<T>(request: Promise<T>, signal: AbortSignal | undefined): Promise<T> {
  if (!signal) return request;
  return new Promise<T>((resolve, reject) => {
    const onAbort = (): void => {
      reject(new SsoFetchRefused('timeout'));
    };
    if (signal.aborted) {
      onAbort();
      return;
    }
    signal.addEventListener('abort', onAbort, { once: true });
    request.then(
      (value) => {
        signal.removeEventListener('abort', onAbort);
        resolve(value);
      },
      (err: unknown) => {
        signal.removeEventListener('abort', onAbort);
        reject(err instanceof Error ? err : new Error('request failed'));
      },
    );
  });
}

/** Statuses a `Response` may not carry a body with. */
const NULL_BODY_STATUSES = new Set([101, 103, 204, 205, 304]);

/**
 * spec §14: openid-client's customFetch. Only URLs the configured issuer's discovery named (the
 * discovery URL itself first); GET and POST; the SSRF-guarded pinned client (http/outbound.ts: a
 * fresh connection, no proxy, no redirect followed, every resolved address checked); private
 * addresses only for a host listed in QUALOR_SSO_INTERNAL_HOSTS, and never link-local or cloud
 * metadata; bounded in time and size. Nothing of the request or the answer is logged.
 */
export function createSsoFetch(policy: SsoFetchPolicy): SsoFetch {
  // The entries are compared as lookups are: without query or fragment, in WHATWG form.
  const initial = [...policy.allowed].map(withoutQuery);
  policy.allowed.clear();
  for (const entry of initial) policy.allowed.add(entry);
  const fetchFn = (async (url, options) => {
    let key: string;
    try {
      key = withoutQuery(url);
    } catch {
      throw new SsoFetchRefused('invalid_url');
    }
    if (!policy.allowed.has(key)) throw new SsoFetchRefused('not_allowed');
    if (options.method !== 'GET' && options.method !== 'POST') throw new SsoFetchRefused('method');
    if (options.signal?.aborted) throw new SsoFetchRefused('timeout');
    const body = bodyText(options.body);
    if (body === null) throw new SsoFetchRefused('request');
    const target = new URL(url);
    const internal = isInternalHostAllowed(target, policy.internalHosts);
    // spec §14: https, or http only for a host QUALOR_SSO_INTERNAL_HOSTS lists.
    if (target.protocol !== 'https:' && !(target.protocol === 'http:' && internal)) {
      throw new SsoFetchRefused(target.protocol === 'http:' ? 'not_public' : 'invalid_url');
    }
    const request = outboundRequest(
      {
        url,
        method: options.method,
        headers: options.headers,
        ...(body === undefined ? {} : { body }),
      },
      {
        allowInternalHosts: internal,
        refuseAddress: scmRefusedAddress(target),
        timeoutMs: SSO_FETCH_TIMEOUT_MS,
        maxResponseBytes: policy.maxResponseBytes ?? SSO_FETCH_MAX_BYTES,
        overflow: 'fail',
        names: { noun: 'identity provider', target: 'the identity provider' },
        ...(policy.resolve ? { resolve: policy.resolve } : {}),
      },
    );
    const result = await abortable(request, options.signal);
    if (result.kind === 'failed') {
      const tls = result.cause === 'connection' && isTlsErrorCode(result.code);
      throw new SsoFetchRefused(tls ? 'tls' : result.cause, result.code);
    }
    // A Response carries only 200-599; anything else (a 1xx that ended the exchange, a 999) fails.
    if (result.status < 200 || result.status > 599) {
      throw new SsoFetchRefused('status', null, result.status);
    }
    const headers = new Headers();
    for (const [name, value] of Object.entries(result.headers)) {
      if (Array.isArray(value)) for (const v of value) headers.append(name, v);
      else if (value !== undefined) headers.set(name, value);
    }
    return new Response(
      NULL_BODY_STATUSES.has(result.status) ? null : new Uint8Array(result.body),
      { status: result.status, headers },
    );
  }) as SsoFetch;
  fetchFn.allow = (url: string) => {
    policy.allowed.add(withoutQuery(url));
  };
  return fetchFn;
}
