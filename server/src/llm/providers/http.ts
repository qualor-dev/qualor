import type { IncomingHttpHeaders } from 'node:http';
import { outboundRequest } from '../../http/outbound';
import { isInternalHostAllowed, scmRefusedAddress } from '../../scm/url';
import { llmBaseUrlProblem } from '../url';
import {
  LLM_MAX_ANSWER_BYTES,
  LlmError,
  type ProviderConfig,
  type ProviderHttpOptions,
} from './types';

export const NOT_UNDERSTOOD = "The provider's answer was not understood";
const UNREACHABLE = 'The model provider could not be reached';
const NOT_SENT = 'The request to the model provider could not be made; check the settings';

/**
 * llm.md §14: `Retry-After` (seconds or an HTTP date) first, else `retry-after-ms`, in whole
 * seconds; null when neither is present and readable.
 */
export function retryAfterSeconds(
  headers: IncomingHttpHeaders,
  now: () => number = Date.now,
): number | null {
  const raw = headers['retry-after'];
  if (typeof raw === 'string') {
    if (/^\d{1,9}$/.test(raw.trim())) return Number(raw.trim());
    const at = Date.parse(raw);
    if (!Number.isNaN(at)) return Math.max(0, Math.ceil((at - now()) / 1_000));
  }
  const ms = headers['retry-after-ms'];
  if (typeof ms === 'string' && /^\d{1,9}$/.test(ms.trim())) {
    return Math.ceil(Number(ms.trim()) / 1_000);
  }
  return null;
}

/**
 * One JSON POST to `<baseUrl><path>` through the outbound core (llm.md §4: the base URL checked
 * first, every resolved address checked and pinned, no proxy, no redirect followed, at most 1 MiB
 * read, the whole exchange within `timeoutSeconds`): the parsed JSON of a 2xx, else an LlmError.
 * The provider's error body is never read.
 */
export async function postJson(
  config: ProviderConfig,
  path: string,
  headers: Record<string, string>,
  body: unknown,
  http: ProviderHttpOptions,
): Promise<unknown> {
  const problem = llmBaseUrlProblem(config.baseUrl, http.internalHosts);
  if (problem) throw new LlmError('url_not_allowed', problem);
  // A base URL pasted with a trailing slash is the same address (plan 3B review focus 1).
  const url = new URL(`${config.baseUrl.replace(/\/+$/, '')}${path}`);
  const result = await outboundRequest(
    {
      url: url.href,
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        accept: 'application/json',
        'user-agent': `Qualor/${http.version}`,
        ...headers,
      },
      body: JSON.stringify(body),
    },
    {
      allowInternalHosts: isInternalHostAllowed(url, http.internalHosts),
      refuseAddress: scmRefusedAddress(url),
      timeoutMs: config.timeoutSeconds * 1_000,
      maxResponseBytes: LLM_MAX_ANSWER_BYTES,
      overflow: 'fail',
      names: { noun: 'model provider', target: 'the model provider' },
      ...(http.resolve ? { resolve: http.resolve } : {}),
    },
  );
  if (result.kind === 'failed') {
    switch (result.cause) {
      case 'timeout':
        throw new LlmError(
          'timeout',
          `The model did not answer within ${config.timeoutSeconds} s; raise the timeout in the AI assistant settings`,
        );
      case 'not_public':
      case 'refused_address':
      case 'invalid_url':
        throw new LlmError('url_not_allowed', result.reason);
      case 'too_large':
        throw new LlmError('bad_answer', NOT_UNDERSTOOD);
      case 'request':
        // The request could not be built (an invalid header value): retrying cannot help.
        throw new LlmError('rejected', NOT_SENT);
      default:
        // 'unresolved', 'connect_timeout' (no connection within 3 s), 'connection' (llm.md §14).
        throw new LlmError('unavailable', UNREACHABLE);
    }
  }
  const { status } = result;
  const retryAfter = retryAfterSeconds(result.headers);
  if (status === 429) {
    throw new LlmError(
      'rate_limited',
      'The model provider is rate limiting Qualor; try later',
      status,
      retryAfter,
    );
  }
  // Both keep the code `refused_key`; the status (in the text, the Test answer and the log) tells
  // a wrong key (401) from a key that may not do this (403: the model, the workspace, billing).
  if (status === 401) {
    throw new LlmError('refused_key', 'The provider refused the API key (HTTP 401)', status);
  }
  if (status === 403) {
    throw new LlmError(
      'refused_key',
      'The provider refused the request (HTTP 403): the key lacks access to this model, or the account has no credit',
      status,
    );
  }
  if (status >= 500) throw new LlmError('unavailable', UNREACHABLE, status, retryAfter);
  if (status < 200 || status >= 300) {
    throw new LlmError(
      'rejected',
      `The provider refused the request (HTTP ${status}); check the base URL and model`,
      status,
    );
  }
  try {
    return JSON.parse(result.body.toString('utf8')) as unknown;
  } catch {
    throw new LlmError('bad_answer', NOT_UNDERSTOOD, status);
  }
}
