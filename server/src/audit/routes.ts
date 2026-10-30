/**
 * rbac-audit.md §8, §10.2: the core mutating routes that never record an audit event.
 * Every other core mutating route records one in its transaction, so it may answer 409
 * AUDIT_CHAIN_ANCHOR_MALFORMED; the OpenAPI document says so (http/openapi.ts), and a sweep
 * (audited-routes.sweep.test.ts) checks this list against the routes' code. An id is
 * `METHOD <path as declared in routes/>`.
 */
export const UNAUDITED_MUTATIONS: ReadonlySet<string> = new Set([
  // Report uploads are not audited, nor the review snapshot a scanner sends with one (6I-2).
  'POST /analyses',
  'POST /analyses/:id/review-snapshot',
  // Connection and webhook tests change nothing.
  'POST /scm-connections/:id/test',
  'POST /webhooks/:id/test',
  'POST /system/llm/test',
  // Mail E2: reading who an invitation is for changes nothing (POST keeps the secret in the body).
  'POST /auth/invitations/inspect',
  // mail E3: personal notification preferences, like a token's last use.
  'PUT /projects/:id/watch',
  'DELETE /projects/:id/watch',
  'PUT /me/notifications',
  'POST /notifications/unsubscribe',
  // GitHub's own deliveries, and GitLab's, which only queue a scan of a merge request's notes.
  'POST /api/v0/github/webhooks/:connectionId',
  'POST /api/v0/gitlab/webhooks/:connectionId',
  // Onboarding: the run's job records each project, mapping and token it makes.
  'POST /repository-setups',
]);

/**
 * rbac-audit.md §10.2.1: the core mutating routes whose only event always removes access, which
 * they record through `recordOrSkipWhenAnchorMalformed`, so they never answer 409
 * AUDIT_CHAIN_ANCHOR_MALFORMED. The sweep checks this list against the routes' code too.
 */
export const ACCESS_REMOVING_MUTATIONS: ReadonlySet<string> = new Set([
  'POST /auth/logout',
  'DELETE /tokens/:id',
  'DELETE /projects/:id/tokens/:tokenId',
  'DELETE /organizations/:id/members/:userId',
  'DELETE /projects/:id/members/:userId',
  'DELETE /me/oauth-grants/:id',
  'DELETE /users/:id/oauth-grants/:grantId',
]);

const API_PREFIX = '/api/v0';
const READ_METHODS = new Set(['get', 'head', 'options']);

/**
 * Whether an operation of the OpenAPI document (`post`, `/api/v0/projects/{id}`) is a core route
 * that records an audit event it may refuse (so neither unaudited nor only access-removing). Plugin routes (`/api/v0/ee/…`) document their own problems.
 */
export function isAuditedMutation(method: string, openApiPath: string): boolean {
  if (READ_METHODS.has(method.toLowerCase())) return false;
  if (!openApiPath.startsWith(`${API_PREFIX}/`) || openApiPath.startsWith(`${API_PREFIX}/ee/`)) {
    return false;
  }
  const path = openApiPath.replace(/\{(\w+)\}/g, ':$1');
  const ids = [
    `${method.toUpperCase()} ${path}`,
    `${method.toUpperCase()} ${path.slice(API_PREFIX.length)}`,
  ];
  return !ids.some((id) => UNAUDITED_MUTATIONS.has(id) || ACCESS_REMOVING_MUTATIONS.has(id));
}
