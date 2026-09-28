import type { LlmFailure } from './providers';

/** llm.md §14: the stored `error_code` values. */
export const LLM_ERROR_CODES = [
  'PROVIDER_TIMEOUT',
  'PROVIDER_UNAVAILABLE',
  'PROVIDER_RATE_LIMITED',
  'PROVIDER_REFUSED_KEY',
  'PROVIDER_REJECTED_REQUEST',
  'PROVIDER_BAD_ANSWER',
  'URL_NOT_ALLOWED',
  'KEY_UNDECRYPTABLE',
  'MALFORMED_OUTPUT',
  'OUTPUT_TRUNCATED',
  'MODEL_REFUSED',
  'OUTPUT_REFUSED',
  // Checked by the job before it sends anything (llm.md §14): the admin turned the organisation
  // or feature off, changed the provider or model, or the issue was re-analysed or deleted
  // between the click and the job.
  'AI_DISABLED',
  'SETTINGS_CHANGED',
  'ISSUE_CHANGED',
  'ISSUE_GONE',
  // The request's job ended without finishing it (its worker died, or it failed unexpectedly):
  // the `llm` worker's sweep fails the row (job.ts `reconcileStuckLlmRequests`).
  'REQUEST_ABANDONED',
] as const;
export type LlmErrorCode = (typeof LLM_ERROR_CODES)[number];

const BY_FAILURE: Record<LlmFailure, LlmErrorCode> = {
  timeout: 'PROVIDER_TIMEOUT',
  unavailable: 'PROVIDER_UNAVAILABLE',
  rate_limited: 'PROVIDER_RATE_LIMITED',
  refused_key: 'PROVIDER_REFUSED_KEY',
  rejected: 'PROVIDER_REJECTED_REQUEST',
  bad_answer: 'PROVIDER_BAD_ANSWER',
  url_not_allowed: 'URL_NOT_ALLOWED',
};

export function errorCodeOf(err: { failure: LlmFailure }): LlmErrorCode {
  return BY_FAILURE[err.failure];
}

/**
 * llm.md §14: what the person sees for a code that has no text of its own (a provider failure
 * carries its LlmError's fixed message instead: the seconds, the HTTP status, the URL problem).
 */
export const ERROR_TEXTS: Record<LlmErrorCode, string> = {
  PROVIDER_TIMEOUT: 'The model did not answer in time',
  PROVIDER_UNAVAILABLE: 'The model provider could not be reached',
  PROVIDER_RATE_LIMITED: 'The model provider is rate limiting Qualor; try later',
  PROVIDER_REFUSED_KEY: 'The provider refused the API key',
  PROVIDER_REJECTED_REQUEST: 'The provider refused the request; check the base URL and model',
  PROVIDER_BAD_ANSWER: "The provider's answer was not understood",
  URL_NOT_ALLOWED: 'The base URL is no longer allowed',
  KEY_UNDECRYPTABLE: 'Set the API key again',
  MALFORMED_OUTPUT: "The model's answer could not be used",
  OUTPUT_TRUNCATED: "The model's answer could not be used",
  MODEL_REFUSED: 'The model declined to answer',
  OUTPUT_REFUSED: 'The suggested fix was not safe to show',
  AI_DISABLED: 'Ask again',
  SETTINGS_CHANGED: 'Ask again',
  ISSUE_CHANGED: 'Ask again',
  ISSUE_GONE: 'Ask again',
  REQUEST_ABANDONED: 'The request was interrupted; ask again',
};

/** Retried failures (llm.md §14): the rest fail the request at once. */
export const TRANSIENT_FAILURES: ReadonlySet<LlmFailure> = new Set([
  'timeout',
  'unavailable',
  'rate_limited',
]);
