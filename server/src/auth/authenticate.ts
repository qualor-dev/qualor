import type { FastifyInstance } from 'fastify';
import type { RouteDeps } from '../app';
import { ProblemError, unauthenticated } from '../http/problem';
import { isDemoUser } from './demo';
import { resolveRequestPrincipal, type UserPrincipal } from './principal';
import { csrfTokenFor, isSsoSession, safeEqual, SESSION_COOKIE } from './sessions';

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
/**
 * Ruling R7: a user who must change their password may do only that, on a session their password
 * made or with a personal token. An SSO session was not made with that password: it is not held
 * up, and the flag stays for their next password sign-in.
 */
/** The one change the demo account may make: signing out. */
const ALLOWED_TO_DEMO = new Set(['/api/v0/auth/logout']);
const ALLOWED_BEFORE_PASSWORD_CHANGE = new Set([
  '/api/v0/auth/me',
  '/api/v0/auth/me/password',
  '/api/v0/auth/logout',
]);

/**
 * Global onRequest hook (ruling R14): unknown routes fall through to the 404 handler, `config:
 * { public: true }` routes skip authentication entirely, everything else needs a valid principal
 * (401 before the body is parsed), then cookie-authenticated mutations need a matching
 * X-Qualor-CSRF header (403), then users flagged `passwordChangeRequired` may only reach the
 * handful of routes that let them change it (403), unless an SSO sign-in made the session. The
 * demo account (QUALOR_DEMO_USER) may change nothing but sign out (403), whatever its role.
 */
export function installAuthentication(app: FastifyInstance, deps: RouteDeps): void {
  app.decorateRequest('principal', null);
  app.addHook('onRequest', async (request) => {
    if (request.is404 || request.routeOptions.config.public === true) return;
    const principal = await resolveRequestPrincipal(
      deps.db,
      request.headers.authorization,
      request.cookies[SESSION_COOKIE],
    );
    request.principal = principal;
    if (!principal) throw unauthenticated();
    if (principal.kind === 'session' && MUTATING.has(request.method)) {
      const header = request.headers['x-qualor-csrf'];
      const expected = csrfTokenFor(deps.config.secretKey, principal.sessionSecret);
      if (typeof header !== 'string' || !safeEqual(header, expected)) {
        throw new ProblemError(403, 'CSRF_FAILED', 'Missing or invalid X-Qualor-CSRF header');
      }
    }
    if (
      principal.kind !== 'project' &&
      MUTATING.has(request.method) &&
      isDemoUser(deps.config.demoUser, principal.user) &&
      !ALLOWED_TO_DEMO.has(request.routeOptions.url ?? '')
    ) {
      throw new ProblemError(403, 'DEMO_READ_ONLY', 'The demo is read-only');
    }
    if (
      principal.kind !== 'project' &&
      passwordChangeRequired(principal, deps.config.secretKey) &&
      !ALLOWED_BEFORE_PASSWORD_CHANGE.has(request.routeOptions.url ?? '')
    ) {
      throw new ProblemError(
        403,
        'PASSWORD_CHANGE_REQUIRED',
        'Change your password before doing anything else',
      );
    }
  });
}

/** Ruling R7 for this request: the user's flag, unless an SSO sign-in made the session. */
export function passwordChangeRequired(principal: UserPrincipal, secretKey: string): boolean {
  if (!principal.user.passwordChangeRequired) return false;
  return !(principal.kind === 'session' && isSsoSession(secretKey, principal.sessionSecret));
}
