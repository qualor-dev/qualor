import { outboundRequest, type Resolver } from '../http/outbound';

export { CONNECT_TIMEOUT_MS, pinnedLookup, type Resolver } from '../http/outbound';

/** data-model.md §4.6: `webhook_deliveries.response_excerpt` holds at most 1 KiB. */
export const MAX_EXCERPT_BYTES = 1_024;

/**
 * How every excerpt of an attempt that reached no answer starts (timeouts, connection and lookup
 * failures): with an HTTP error status, what the circuit breaker counts as a receiver failure
 * (webhooks/deliver.ts). Refusals made before any request (a non-public address, a bad URL or
 * header) are not receiver failures and use other texts.
 */
export const UNREACHABLE_EXCERPT_PREFIXES = [
  'No response within',
  'No connection within',
  'The connection to the webhook failed',
  'The webhook host could not be resolved',
] as const;

export interface SendRequest {
  url: string;
  body: string;
  headers: Record<string, string>;
}

export interface SendOptions {
  allowInternalHosts: boolean;
  /** The whole exchange: resolve, connect, send, and read the status and the excerpt. */
  timeoutMs: number;
  /** The connection only (resolve, connect, TLS handshake); default 3 s (ruling X7). */
  connectTimeoutMs?: number;
  /** Tests substitute DNS; the default is the system resolver (`dns.lookup`). */
  resolve?: Resolver;
}

export interface SendOutcome {
  /** A 2xx status (api.md §3). */
  ok: boolean;
  status: number | null;
  /** The start of the response body, or why no response arrived. */
  excerpt: string | null;
}

/** C0 control characters except tab and line feed; NUL included (Postgres `text` rejects it). */
// eslint-disable-next-line no-control-regex -- matching control characters is the point
const C0_CONTROLS = /[\u0000-\u0008\u000B-\u001F]/g;

/**
 * At most {@link MAX_EXCERPT_BYTES} of UTF-8, without C0 control characters other than tab and
 * line feed (NUL, which Postgres `text` rejects, and terminal escapes a UI or a log could render).
 * A body cut inside a multi-byte character decodes to U+FFFD, which is longer, so the text is
 * trimmed again until it fits the column's `octet_length` check.
 */
export function excerptOf(bytes: Buffer): string | null {
  if (bytes.length === 0) return null;
  let text = bytes.subarray(0, MAX_EXCERPT_BYTES).toString('utf8').replace(C0_CONTROLS, '');
  while (Buffer.byteLength(text, 'utf8') > MAX_EXCERPT_BYTES) text = text.slice(0, -1);
  // A character cut at the 1 KiB boundary decodes to U+FFFD: drop that trailing replacement.
  if (bytes.length > MAX_EXCERPT_BYTES) text = text.replace(/�+$/, '');
  return text === '' ? null : text;
}

/**
 * POSTs one webhook delivery (ruling W3) through {@link outboundRequest}: every resolved address
 * public unless internal hosts are allowed, the connection pinned to them, a fresh connection
 * without proxy, no redirect (a 3xx is a failure), 10 s in all and 3 s to connect (ruling X7), and
 * at most {@link MAX_EXCERPT_BYTES} of the response read. Never throws; a failure is `ok: false`
 * with a short reason in `excerpt` (never a URL, header or body).
 */
export async function sendWebhook(
  request: SendRequest,
  options: SendOptions,
): Promise<SendOutcome> {
  const result = await outboundRequest(
    { url: request.url, method: 'POST', headers: request.headers, body: request.body },
    {
      allowInternalHosts: options.allowInternalHosts,
      timeoutMs: options.timeoutMs,
      ...(options.connectTimeoutMs === undefined
        ? {}
        : { connectTimeoutMs: options.connectTimeoutMs }),
      ...(options.resolve ? { resolve: options.resolve } : {}),
      maxResponseBytes: MAX_EXCERPT_BYTES,
      overflow: 'truncate',
      names: { noun: 'webhook', target: 'the webhook' },
    },
  );
  if (result.kind === 'failed') return { ok: false, status: null, excerpt: result.reason };
  return {
    ok: result.status >= 200 && result.status < 300,
    status: result.status,
    excerpt: excerptOf(result.body),
  };
}
