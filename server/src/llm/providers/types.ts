import type { FinishReason } from '@qualor/shared';
import type { Resolver } from '../../http/outbound';

export const PROVIDER_KINDS = ['openai', 'anthropic'] as const;
export type ProviderKind = (typeof PROVIDER_KINDS)[number];

/** llm.md §3.2: the provider settings a call needs; the API key is passed on its own. */
export interface ProviderConfig {
  kind: ProviderKind;
  baseUrl: string;
  model: string;
  auth: 'bearer' | 'api-key';
  jsonMode: 'json_object' | 'none';
  maxTokensField: 'max_tokens' | 'max_completion_tokens';
  temperature: number | null;
  timeoutSeconds: number;
}

/** llm.md §2.1 */
export interface LlmCall {
  system: string;
  user: string;
  maxOutputTokens: number;
}

/** llm.md §2.1 */
export interface LlmAnswer {
  text: string;
  finishReason: FinishReason;
  usage: { inputTokens: number | null; outputTokens: number | null };
  model: string | null;
}

/** llm.md §14: why a provider call gave no usable answer. */
export const LLM_FAILURES = [
  'timeout',
  'unavailable',
  'rate_limited',
  'refused_key',
  'rejected',
  'bad_answer',
  'url_not_allowed',
] as const;
export type LlmFailure = (typeof LLM_FAILURES)[number];

/**
 * A provider call that did not answer usably. `message` is a fixed text, never the provider's
 * body, a header or the API key.
 */
export class LlmError extends Error {
  constructor(
    readonly failure: LlmFailure,
    message: string,
    readonly status: number | null = null,
    readonly retryAfterSeconds: number | null = null,
  ) {
    super(message);
    this.name = 'LlmError';
  }
}

export interface ProviderHttpOptions {
  internalHosts: ReadonlySet<string>;
  /** Qualor's version, for `User-Agent`. */
  version: string;
  resolve?: Resolver;
}

/**
 * llm.md §10.1: the largest token count stored. A provider's count is its own claim: one that is
 * not a whole number from 0 to this bound (a negative, a fraction, 1e300, a string) is stored as
 * unknown (null), never refused (the answer itself may be fine) and never allowed to overflow the
 * `integer` columns or inflate the token and cost budgets without bound.
 */
export const MAX_TOKEN_COUNT = 10_000_000;

/** A provider's token count, or null when it is missing or out of range. */
export function tokenCount(value: unknown): number | null {
  return typeof value === 'number' &&
    Number.isInteger(value) &&
    value >= 0 &&
    value <= MAX_TOKEN_COUNT
    ? value
    : null;
}

/** llm.md §4: answers over 1 MiB are refused. */
export const LLM_MAX_ANSWER_BYTES = 1024 * 1024;
