/**
 * What the decoration job needs of any SCM client (plan 2C ruling GH11): one error type whose
 * `kind` it acts on (scm.md §4.3, github.md §5.3), and bounded listings.
 */

/** `transient` and `rate_limited` are retried; the others stop the job. */
export type ScmErrorKind =
  'transient' | 'rate_limited' | 'auth' | 'not_found' | 'refused' | 'bad_answer' | 'budget';

/**
 * What exactly failed, for callers that act on it without reading the message (the test
 * endpoint's codes, scm.md §2.1, github.md §2.2): `not_public` (an address the policy refuses),
 * `unresolved`, `timeout`, `unreachable` (a connection failure), `http` (the provider answered with
 * an error status), `bad_answer`, `budget`, `invalid_input` (an id, revision or ref Qualor would not
 * put into a path), `not_installed` and `permission_missing` (GitHub only), `other`.
 */
export type ScmErrorReason =
  | 'not_public'
  | 'unresolved'
  | 'timeout'
  | 'unreachable'
  | 'http'
  | 'bad_answer'
  | 'budget'
  | 'invalid_input'
  | 'not_installed'
  | 'permission_missing'
  | 'other';

const DEFAULT_REASON: Record<ScmErrorKind, ScmErrorReason> = {
  transient: 'unreachable',
  rate_limited: 'http',
  auth: 'http',
  not_found: 'http',
  refused: 'other',
  bad_answer: 'bad_answer',
  budget: 'budget',
};

export interface ScmErrorOptions {
  status?: number | null;
  retryAfterSeconds?: number | null;
  providerMessage?: string | null;
  reason?: ScmErrorReason;
}

/** A failed SCM request. `message` is one of the specs' fixed texts, never the provider's words. */
export class ScmError extends Error {
  readonly kind: ScmErrorKind;
  readonly reason: ScmErrorReason;
  readonly status: number | null;
  readonly retryAfterSeconds: number | null;
  /**
   * The provider's own message, for decisions only (never logged or shown): not enumerable, so a
   * logger or `JSON.stringify` serialising the error never includes it.
   */
  declare readonly providerMessage: string | null;

  constructor(kind: ScmErrorKind, message: string, options: ScmErrorOptions = {}) {
    super(message);
    this.name = 'ScmError';
    this.kind = kind;
    this.reason = options.reason ?? DEFAULT_REASON[kind];
    this.status = options.status ?? null;
    this.retryAfterSeconds = options.retryAfterSeconds ?? null;
    Object.defineProperty(this, 'providerMessage', {
      value: options.providerMessage ?? null,
      enumerable: false,
      writable: false,
    });
  }
}

export interface Paged<T> {
  items: T[];
  /** False when the page bound stopped the listing before its end. */
  complete: boolean;
}
