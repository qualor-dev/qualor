import type { FastifyInstance } from 'fastify';
import type { RouteDeps } from '../app';
import { ProblemError, unauthenticated } from '../http/problem';
import { resolveRequestPrincipal } from './principal';
import { csrfTokenFor, safeEqual, SESSION_COOKIE } from './sessions';

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
/** Ruling R7: a user who must change their password may do only that. */
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
 * handful of routes that let them change it (403).
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
      principal.user.passwordChangeRequired &&
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
