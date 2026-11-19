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

/** {@link problemMessage} of a Jira problem code (api.md §2.1); null for any other code. */
function jiraProblemMessage(code: string | null): string | null {
  switch (code) {
    case 'JIRA_NOT_CONNECTED':
      return $localize`:@@jira.error.notConnected:This organization has no Jira connection. An organization admin connects it under Settings → Jira.`;
    case 'JIRA_CONNECTION_BROKEN':
      return $localize`:@@jira.error.connectionBroken:The Jira connection has a problem that an organization admin must fix under Settings → Jira.`;
    case 'JIRA_PROJECT_NOT_MAPPED':
      return $localize`:@@jira.error.projectNotMapped:This project is not mapped to a Jira project yet.`;
    case 'JIRA_ISSUE_TYPE_UNSUPPORTED':
      return $localize`:@@jira.error.issueTypeUnsupported:Qualor cannot create this Jira issue type: it requires fields that Qualor cannot fill.`;
    case 'JIRA_UNAVAILABLE':
      return $localize`:@@jira.error.unavailable:Jira could not be reached or refused the request. Try again later.`;
    case 'JIRA_LINK_NOT_RETRYABLE':
      return $localize`:@@jira.error.linkNotRetryable:This can no longer be tried again: the finding is closed or can no longer have a Jira issue, or its Jira issue changed meanwhile.`;
    default:
      return null;
  }
}

/** {@link problemMessage} of a fix MR problem code (api.md §2.1); null for any other code. */
function fixProblemMessage(code: string | null): string | null {
  switch (code) {
    case 'FIXES_DISABLED':
      return $localize`:@@fix.error.disabled:Fix MRs are switched off for this project. A project admin turns them on under Settings → Fix MRs.`;
    case 'SCM_NOT_BOUND':
      return $localize`:@@fix.error.notBound:This project is not mapped to a repository yet.`;
    case 'FIX_MRS_NOT_ALLOWED':
      return $localize`:@@fix.error.notAllowed:An organization admin must allow fix MRs on the repository connection, under Settings → GitLab or GitHub.`;
    case 'MONITORING_OFF':
      return $localize`:@@fix.error.monitoringOff:Vulnerability monitoring is off for this project. Fix MRs need it.`;
    case 'FIX_LIMIT_REACHED':
      return $localize`:@@fix.error.limitReached:This project has as many fix MRs in progress as its limit allows. Close or cancel one, or raise the limit in the project's settings.`;
    case 'NOT_FIXABLE':
      return $localize`:@@fix.error.notFixable:No version of this package fixes its vulnerabilities on the main branch yet.`;
    case 'FIX_ECOSYSTEM_UNSUPPORTED':
      return $localize`:@@fix.error.ecosystemUnsupported:Qualor has no automatic fix for this kind of package yet.`;
    case 'FIX_NOT_RETRYABLE':
      return $localize`:@@fix.error.notRetryable:This fix is in progress. It can be tried again once it has ended.`;
    case 'FIX_BUSY':
      return $localize`:@@fix.error.busy:Qualor is writing this fix right now. Try again in a few seconds.`;
    case 'SCM_UNAVAILABLE':
      return $localize`:@@fix.error.scmUnavailable:The repository could not be reached. Try again later.`;
    default:
      return null;
  }
}

const NETWORK_MESSAGE = (): string =>
  $localize`:@@error.network:The server could not be reached. Check your connection and try again.`;

/** The sentence of each problem code that needs no more than the code itself. */
const PROBLEM_MESSAGES: Record<string, ((err: ApiError) => string) | undefined> = {
  UNAUTHENTICATED: () => $localize`:@@error.unauthenticated:Your session has ended. Sign in again.`,
  CSRF_FAILED: () =>
    $localize`:@@error.csrf:Your session changed in another tab. Reload the page and try again.`,
  FORBIDDEN: () => $localize`:@@error.forbidden:You are not allowed to do this.`,
  INSUFFICIENT_SCOPE: () => $localize`:@@error.forbidden:You are not allowed to do this.`,
  SESSION_REQUIRED: () =>
    $localize`:@@error.sessionRequired:Personal tokens can only be created from a signed-in browser session, not with a token.`,
  PASSWORD_CHANGE_REQUIRED: () =>
    $localize`:@@error.passwordChangeRequired:Change your password before doing anything else.`,
  NOT_FOUND: () => $localize`:@@error.notFound:This item does not exist, or you cannot see it.`,
  VALIDATION_FAILED: () =>
    $localize`:@@error.validation:Some values are not valid. Check the highlighted fields.`,
  COMMENT_REQUIRED: () =>
    $localize`:@@error.commentRequired:A comment is required for this status.`,
  INVALID_TRANSITION: () =>
    $localize`:@@error.invalidTransition:This status change is not allowed any more; the issue changed. Reload and try again.`,
  CONCURRENCY_CONFLICT: (err) => {
    if (err.status === 503) {
      return err.retryAfter === null
        ? $localize`:@@error.concurrencyRetry:An analysis is updating these issues right now, so nothing was changed. Try again in a moment.`
        : $localize`:@@error.concurrencyRetryAfter:An analysis is updating these issues right now, so nothing was changed. Try again in ${err.retryAfter}:seconds: s.`;
    }
    return $localize`:@@error.conflict:Someone else changed this at the same time. Try again.`;
  },
  CONFLICT: () =>
    $localize`:@@error.conflict:Someone else changed this at the same time. Try again.`,
  BUILTIN_READ_ONLY: () =>
    $localize`:@@error.builtinReadOnly:Built-in items cannot be changed. Copy it to make your own.`,
  CONDITION_EXISTS: () =>
    $localize`:@@error.conditionExists:This gate already has a condition on that metric.`,
  PROFILE_NAME_TAKEN: () =>
    $localize`:@@error.profileNameTaken:A profile with this name and language already exists.`,
  PROFILE_HAS_CHILDREN: () =>
    $localize`:@@error.profileHasChildren:Other profiles inherit from this one; delete them first.`,
  PROFILE_LIMIT_REACHED: () =>
    $localize`:@@error.profileLimitReached:This organization has as many quality profiles as it can have. Delete one first.`,
  PROFILE_RULE_LIMIT_REACHED: () =>
    $localize`:@@error.profileRuleLimitReached:This profile sets as many rules itself as it can. Let some rules inherit again first.`,
  WEBHOOK_LIMIT_REACHED: () =>
    $localize`:@@error.webhookLimitReached:This organization has as many webhooks as it can have (50). Delete one first.`,
  SCM_CONNECTION_LIMIT_REACHED: () =>
    $localize`:@@error.scmConnectionLimitReached:This organization has as many GitLab connections as it can have (10). Delete one first.`,
  LICENSE_MANAGED_BY_ENVIRONMENT: () =>
    $localize`:@@error.licenseManagedByEnvironment:The licence key is set by QUALOR_LICENSE or QUALOR_LICENSE_FILE, so it cannot be changed here.`,
  FEATURE_NOT_LICENSED: () =>
    $localize`:@@error.featureNotLicensed:This feature needs an active Qualor Enterprise licence.`,
  PROJECT_KEY_TAKEN: () =>
    $localize`:@@error.projectKeyTaken:A project with this key already exists.`,
  ORG_KEY_TAKEN: () =>
    $localize`:@@error.orgKeyTaken:An organization with this key already exists.`,
  USERNAME_TAKEN: () => $localize`:@@error.usernameTaken:This username is already taken.`,
  DEMO_USER: () =>
    $localize`:@@error.demoUser:The demo user keeps its name, and no other user can take it.`,
  LAST_ORGANIZATION: () =>
    $localize`:@@error.lastOrganization:The last organization cannot be deleted.`,
  ORGANIZATION_DELETING: () =>
    $localize`:@@error.organizationDeleting:A delete of this organization is already running.`,
  EMAIL_TAKEN: () => $localize`:@@error.emailTaken:This email address is already in use.`,
  LAST_ADMIN: () =>
    $localize`:@@error.lastAdmin:The last active administrator cannot be demoted, removed or deactivated.`,
  RATE_LIMITED: () =>
    $localize`:@@error.rateLimited:Too many attempts. Wait a minute and try again.`,
  PROJECT_GRANT_LIMIT_REACHED: () =>
    $localize`:@@error.projectGrantLimitReached:This project has as many role grants as it can have (1 000). Remove one first, or grant the role in the organization instead.`,
  AUDIT_CHAIN_ANCHOR_MALFORMED: () =>
    $localize`:@@error.auditChainAnchorMalformed:The audit log's anchor record (the instance setting audit-chain) is damaged, so the audit chain can neither be read nor continued, and most audited changes are refused (removing access still works). An administrator must restore that setting from a backup; trying again does not help.`,
};

/**
 * A localized sentence for an error the API (or the network) returned. Problem codes are stable
 * (api.md §2.1); the server's English `title` is never shown, so every word on screen is ours.
 */
export function problemMessage(err: unknown): string {
  if (!(err instanceof ApiError)) return NETWORK_MESSAGE();
  const jira = jiraProblemMessage(err.code);
  if (jira !== null) return jira;
  const fix = fixProblemMessage(err.code);
  if (fix !== null) return fix;
  const message =
    err.code !== null && Object.hasOwn(PROBLEM_MESSAGES, err.code)
      ? PROBLEM_MESSAGES[err.code]
      : undefined;
  return message
    ? message(err)
    : $localize`:@@error.generic:The request failed (HTTP ${err.status}:status:, ${err.code ?? '-'}:code:).`;
}

/** Field messages of a 422, keyed by the problem's `errors[].path` (`body.newPassword`). */
export function fieldErrors(err: unknown): Record<string, string> {
  if (!(err instanceof ApiError)) return {};
  return Object.fromEntries((err.problem?.errors ?? []).map((e) => [e.path, e.message]));
}
