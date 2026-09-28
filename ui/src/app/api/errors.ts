import type { Problem } from './types';

/**
 * A non-2xx answer of the API, with its RFC 9457 problem when the body was one, and the seconds of
 * its `Retry-After` header (429, 503) when that was a plain number of seconds.
 */
export class ApiError extends Error {
  readonly retryAfter: number | null;

  constructor(
    readonly status: number,
    readonly problem: Problem | null,
    retryAfter: string | null = null,
  ) {
    super(problem?.title ?? `HTTP ${status}`);
    this.name = 'ApiError';
    this.retryAfter =
      retryAfter !== null && /^\d{1,6}$/.test(retryAfter) ? Number(retryAfter) : null;
  }

  get code(): string | null {
    return this.problem?.code ?? null;
  }
}

/**
 * A 503 `CONCURRENCY_CONFLICT` (api.md §2.1): an ingestion held the rows, nothing was written,
 * and the same request may simply be sent again after `Retry-After`.
 */
export function isRetryable(err: unknown): err is ApiError {
  return err instanceof ApiError && err.status === 503 && err.code === 'CONCURRENCY_CONFLICT';
}

export function isProblem(value: unknown): value is Problem {
  const v = value as Partial<Problem> | null;
  return typeof v === 'object' && v !== null && typeof v.code === 'string';
}

/**
 * A localized sentence for an error the API (or the network) returned. Problem codes are stable
 * (api.md §2.1); the server's English `title` is never shown, so every word on screen is ours.
 */
export function problemMessage(err: unknown): string {
  if (!(err instanceof ApiError)) {
    return $localize`:@@error.network:The server could not be reached. Check your connection and try again.`;
  }
  switch (err.code) {
    case 'UNAUTHENTICATED':
      return $localize`:@@error.unauthenticated:Your session has ended. Sign in again.`;
    case 'CSRF_FAILED':
      return $localize`:@@error.csrf:Your session changed in another tab. Reload the page and try again.`;
    case 'FORBIDDEN':
    case 'INSUFFICIENT_SCOPE':
      return $localize`:@@error.forbidden:You are not allowed to do this.`;
    case 'SESSION_REQUIRED':
      return $localize`:@@error.sessionRequired:Personal tokens can only be created from a signed-in browser session, not with a token.`;
    case 'PASSWORD_CHANGE_REQUIRED':
      return $localize`:@@error.passwordChangeRequired:Change your password before doing anything else.`;
    case 'NOT_FOUND':
      return $localize`:@@error.notFound:This item does not exist, or you cannot see it.`;
    case 'VALIDATION_FAILED':
      return $localize`:@@error.validation:Some values are not valid. Check the highlighted fields.`;
    case 'COMMENT_REQUIRED':
      return $localize`:@@error.commentRequired:A comment is required for this status.`;
    case 'INVALID_TRANSITION':
      return $localize`:@@error.invalidTransition:This status change is not allowed any more; the issue changed. Reload and try again.`;
    case 'CONCURRENCY_CONFLICT':
      if (err.status === 503) {
        return err.retryAfter === null
          ? $localize`:@@error.concurrencyRetry:An analysis is updating these issues right now, so nothing was changed. Try again in a moment.`
          : $localize`:@@error.concurrencyRetryAfter:An analysis is updating these issues right now, so nothing was changed. Try again in ${err.retryAfter}:seconds: s.`;
      }
      return $localize`:@@error.conflict:Someone else changed this at the same time. Try again.`;
    case 'CONFLICT':
      return $localize`:@@error.conflict:Someone else changed this at the same time. Try again.`;
    case 'BUILTIN_READ_ONLY':
      return $localize`:@@error.builtinReadOnly:Built-in items cannot be changed. Copy it to make your own.`;
    case 'CONDITION_EXISTS':
      return $localize`:@@error.conditionExists:This gate already has a condition on that metric.`;
    case 'PROFILE_NAME_TAKEN':
      return $localize`:@@error.profileNameTaken:A profile with this name and language already exists.`;
    case 'PROFILE_HAS_CHILDREN':
      return $localize`:@@error.profileHasChildren:Other profiles inherit from this one; delete them first.`;
    case 'PROFILE_LIMIT_REACHED':
      return $localize`:@@error.profileLimitReached:This organization has as many quality profiles as it can have. Delete one first.`;
    case 'PROFILE_RULE_LIMIT_REACHED':
      return $localize`:@@error.profileRuleLimitReached:This profile sets as many rules itself as it can. Let some rules inherit again first.`;
    case 'WEBHOOK_LIMIT_REACHED':
      return $localize`:@@error.webhookLimitReached:This organization has as many webhooks as it can have (50). Delete one first.`;
    case 'SCM_CONNECTION_LIMIT_REACHED':
      return $localize`:@@error.scmConnectionLimitReached:This organization has as many GitLab connections as it can have (10). Delete one first.`;
    case 'LICENSE_MANAGED_BY_ENVIRONMENT':
      return $localize`:@@error.licenseManagedByEnvironment:The licence key is set by QUALOR_LICENSE or QUALOR_LICENSE_FILE, so it cannot be changed here.`;
    case 'FEATURE_NOT_LICENSED':
      return $localize`:@@error.featureNotLicensed:This feature needs an active Qualor Enterprise licence.`;
    case 'PROJECT_KEY_TAKEN':
      return $localize`:@@error.projectKeyTaken:A project with this key already exists.`;
    case 'USERNAME_TAKEN':
      return $localize`:@@error.usernameTaken:This username is already taken.`;
    case 'EMAIL_TAKEN':
      return $localize`:@@error.emailTaken:This email address is already in use.`;
    case 'LAST_ADMIN':
      return $localize`:@@error.lastAdmin:The last active administrator cannot be demoted, removed or deactivated.`;
    case 'RATE_LIMITED':
      return $localize`:@@error.rateLimited:Too many attempts. Wait a minute and try again.`;
    case 'PROJECT_GRANT_LIMIT_REACHED':
      return $localize`:@@error.projectGrantLimitReached:This project has as many role grants as it can have (1 000). Remove one first, or grant the role in the organization instead.`;
    case 'AUDIT_CHAIN_ANCHOR_MALFORMED':
      return $localize`:@@error.auditChainAnchorMalformed:The audit log's anchor record (the instance setting audit-chain) is damaged, so the audit chain can neither be read nor continued, and most audited changes are refused (removing access still works). An administrator must restore that setting from a backup; trying again does not help.`;
    default:
      return $localize`:@@error.generic:The request failed (HTTP ${err.status}:status:, ${err.code ?? '-'}:code:).`;
  }
}

/** Field messages of a 422, keyed by the problem's `errors[].path` (`body.newPassword`). */
export function fieldErrors(err: unknown): Record<string, string> {
  if (!(err instanceof ApiError)) return {};
  return Object.fromEntries((err.problem?.errors ?? []).map((e) => [e.path, e.message]));
}
