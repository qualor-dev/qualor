import { asc, eq } from 'drizzle-orm';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import type { RouteDeps } from '../app';
import { actorOf, anonymousActor, userActor } from '../audit/recorder';
import { accessOf, requirePrincipal, requireSession, requireUser } from '../auth/access';
import { passwordChangeRequired } from '../auth/authenticate';
import {
  DEMO_SESSION_MAX_HOURS,
  deleteExpiredSessions,
  demoAccount,
  isDemoUser,
} from '../auth/demo';
import {
  grantInOrganization,
  memberOf,
  organizationFacts,
  visibleOrganizationsCondition,
} from '../auth/facts';
import { ORGANIZATION_PERMISSIONS, organizationPermissions, PROJECT_ROLES } from '../auth/policy';
import {
  hashPassword,
  PASSWORD_MAX_LENGTH,
  PASSWORD_MIN_LENGTH,
  verifyPassword,
} from '../auth/password';
import {
  createSession,
  csrfTokenFor,
  deleteSession,
  deleteUserSessions,
  SESSION_COOKIE,
  sessionCookieOptions,
} from '../auth/sessions';
import { LoginThrottle } from '../auth/throttle';
import {
  memberships,
  ORGANIZATION_ROLES,
  organizations,
  projectMemberships,
  projects,
  users,
} from '../db/schema';
import { ProblemError, validationFailed } from '../http/problem';
import { noContent, text, userDto, userSchema } from '../http/schemas';
import { connectionsInEffect } from '../sso/connections';
import { effectivePasswordPolicy, mayUsePassword, readSignInSettings } from '../sso/sign-in-policy';
import { userSsoSummary } from './users';

export const LOGIN_ATTEMPTS_PER_MINUTE = 10;

// No upper bound here (task 6, controller ruling S6): an over-long password must fail exactly
// like a wrong one — 401 INVALID_CREDENTIALS with a dummy argon2 verify — not a 422 that tells an
// anonymous caller their input was merely too long. The 1 MiB JSON body limit still bounds it.
const loginBody = z.strictObject({
  username: text(64),
  password: z.string().min(1),
});
const passwordBody = z.strictObject({
  currentPassword: z.string().min(1).max(PASSWORD_MAX_LENGTH),
  newPassword: z.string().min(PASSWORD_MIN_LENGTH).max(PASSWORD_MAX_LENGTH),
});
const meResponse = z.object({
  user: userSchema,
  memberships: z.array(
    z.object({
      organizationId: z.uuid(),
      organizationKey: z.string(),
      organizationName: z.string(),
      /**
       * rbac-audit.md §16: the stored organisation role, any of the four; null where the caller
       * sees the organisation only through a project grant.
       */
      role: z.enum(ORGANIZATION_ROLES).nullable(),
      /** What the role (and a project grant) lets the caller do: effective, §3.2. */
      permissions: z.array(z.enum(ORGANIZATION_PERMISSIONS)),
    }),
  ),
  /** The caller's project grants (at most 1 000). */
  projectGrants: z.array(
    z.object({
      projectId: z.uuid(),
      projectKey: z.string(),
      organizationId: z.uuid(),
      role: z.enum(PROJECT_ROLES),
    }),
  ),
  csrfToken: z.string().nullable(),
  /** The caller is the read-only demo account (QUALOR_DEMO_USER): it may change nothing. */
  demo: z.boolean(),
});

const methodsResponse = z.object({
  /** The effective policy (sso-scim.md §10.2). */
  password: z.enum(['everyone', 'break_glass_only']),
  /** The enabled connections, only while `sso` is active. */
  providers: z.array(
    z.object({
      id: z.uuid(),
      name: z.string(),
      protocol: z.enum(['oidc', 'saml']),
      startUrl: z.string(),
    }),
  ),
  /** Whether guests may sign in to the read-only demo (`POST /auth/demo`). */
  demo: z.boolean(),
});

function setSessionCookie(
  request: FastifyRequest,
  reply: FastifyReply,
  secret: string,
  expires: Date,
): void {
  reply.setCookie(SESSION_COOKIE, secret, sessionCookieOptions(request, expires));
}

export const authRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (app, { deps }) => {
  const usernameThrottle = new LoginThrottle({ max: LOGIN_ATTEMPTS_PER_MINUTE, windowMs: 60_000 });

  app.post(
    '/auth/login',
    {
      config: {
        public: true,
        rateLimit: { max: LOGIN_ATTEMPTS_PER_MINUTE, timeWindow: 60_000 },
        openapi: { problems: [401, 429] },
      },
      schema: {
        tags: ['auth'],
        summary: 'Log in; sets the qualor_session cookie',
        security: [],
        body: loginBody,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const { username, password } = request.body;
      // rbac-audit.md §8: a refusal is recorded in its own transaction before the
      // problem is thrown; the user only when the typed name belongs to one, never the name.
      const refuse = async (
        reason: 'invalid_credentials' | 'inactive_user' | 'rate_limited' | 'password_disabled',
        known: { id: string; username: string } | undefined,
      ): Promise<void> => {
        await deps.audit.record(deps.db, anonymousActor(request, known ?? null), [
          {
            action: 'auth.sign_in_failed',
            outcome: 'failure',
            target: known ? { type: 'user', id: known.id, label: known.username } : null,
            details: { reason, knownUser: known !== undefined },
          },
        ]);
      };
      if (!usernameThrottle.hit(username.toLowerCase())) {
        if (deps.audit.active()) {
          const [known] = await deps.db
            .select({ id: users.id, username: users.username })
            .from(users)
            .where(eq(users.username, username));
          await refuse('rate_limited', known);
        }
        throw new ProblemError(
          429,
          'RATE_LIMITED',
          'Too many login attempts for this user; try again in a minute',
          {
            headers: { 'retry-after': '60' },
          },
        );
      }
      const [found] = await deps.db.select().from(users).where(eq(users.username, username));
      const user = found?.active === true ? found : undefined;
      // Read for every attempt, before argon2, so a refusal by the policy does no more work than
      // a wrong password (sso-scim.md §10.2): the timing tells nothing either.
      const stored = await readSignInSettings(deps.db, request.log);
      // Bound the argon2 input regardless: an over-long password always takes the dummy-hash
      // path (never the user's real hash), so a huge string cannot burn CPU and its timing is
      // identical to any other rejected login.
      const overLong = password.length > PASSWORD_MAX_LENGTH;
      const candidate = password.slice(0, PASSWORD_MAX_LENGTH);
      const ok = await verifyPassword(overLong ? null : (user?.passwordHash ?? null), candidate);
      if (!user || !ok || overLong) {
        // The answer stays the same for every reason; only the log knows the user is inactive.
        await refuse(found && !found.active ? 'inactive_user' : 'invalid_credentials', found);
        throw new ProblemError(401, 'INVALID_CREDENTIALS', 'Invalid username or password');
      }
      // Ruling SS6: the one policy function decides.
      const policy = mayUsePassword(user, stored, {
        sso: deps.edition.isFeatureActive('sso'),
        forced: deps.config.forcePasswordSignIn,
      });
      if (!policy.allowed) {
        // sso-scim.md §10.2: the caller learns nothing; the audit log knows the password was right.
        await refuse('password_disabled', found);
        throw new ProblemError(401, 'INVALID_CREDENTIALS', 'Invalid username or password');
      }
      // Session fixation: never keep a session id the client brought; always issue a new one.
      const presented = request.cookies[SESSION_COOKIE];
      const session = await deps.db.transaction(async (tx) => {
        // In the transaction: a sign-in refused later (409 AUDIT_CHAIN_ANCHOR_MALFORMED from
        // the audit append) keeps the session the client already had (rbac-audit.md §10.2).
        if (presented) await deleteSession(tx, presented);
        const created = await createSession(tx, {
          userId: user.id,
          ttlHours: deps.config.sessionTtlHours,
          ip: request.ip,
          userAgent: request.headers['user-agent'] ?? null,
        });
        await tx.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, user.id));
        await deps.audit.record(tx, userActor(request, user), [
          {
            action: 'auth.sign_in',
            target: { type: 'user', id: user.id, label: user.username },
            // §10.4: a sign-in only the emergency variable allowed says so.
            details: policy.forced ? { method: 'password', forced: true } : { method: 'password' },
          },
        ]);
        return created;
      });
      setSessionCookie(request, reply, session.secret, session.expiresAt);
      return reply.code(204).send();
    },
  );

  app.get(
    '/auth/methods',
    {
      config: {
        public: true,
        rateLimit: { max: 60, timeWindow: 60_000 },
        openapi: { problems: [429] },
      },
      schema: {
        tags: ['auth'],
        summary: 'How people can sign in: the password policy and the SSO providers',
        security: [],
        response: { 200: methodsResponse },
      },
    },
    async (request) => {
      // sso-scim.md §16.1: names no user and no setting beyond these; providers only with `sso`,
      // and only the connections in effect (§4.4).
      const sso = deps.edition.isFeatureActive('sso');
      const stored = await readSignInSettings(deps.db, request.log);
      const providers = sso ? await connectionsInEffect(deps.db, deps.edition) : [];
      return {
        password: effectivePasswordPolicy(stored, { sso, forced: deps.config.forcePasswordSignIn }),
        providers: providers.map((p) => ({
          id: p.id,
          name: p.name,
          protocol: p.protocol,
          startUrl: `/api/v0/ee/sso/${p.id}/start`,
        })),
        demo: (await demoAccount(deps.db, deps.config.demoUser)) !== null,
      };
    },
  );

  app.post(
    '/auth/demo',
    {
      config: {
        public: true,
        rateLimit: { max: LOGIN_ATTEMPTS_PER_MINUTE, timeWindow: 60_000 },
        openapi: { problems: [404, 429] },
      },
      schema: {
        tags: ['auth'],
        summary:
          'Sign in to the read-only demo as QUALOR_DEMO_USER; sets the qualor_session cookie',
        security: [],
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const user = await demoAccount(deps.db, deps.config.demoUser);
      if (!user) throw new ProblemError(404, 'DEMO_UNAVAILABLE', 'This server has no demo');
      // As a password sign-in: a session id the client brought is never kept.
      const presented = request.cookies[SESSION_COOKIE];
      const session = await deps.db.transaction(async (tx) => {
        if (presented) await deleteSession(tx, presented);
        await deleteExpiredSessions(tx, user.id);
        const created = await createSession(tx, {
          userId: user.id,
          ttlHours: Math.min(deps.config.sessionTtlHours, DEMO_SESSION_MAX_HOURS),
          ip: request.ip,
          userAgent: request.headers['user-agent'] ?? null,
        });
        await tx.update(users).set({ lastLoginAt: new Date() }).where(eq(users.id, user.id));
        await deps.audit.record(tx, userActor(request, user), [
          {
            action: 'auth.sign_in',
            target: { type: 'user', id: user.id, label: user.username },
            details: { method: 'demo' },
          },
        ]);
        return created;
      });
      setSessionCookie(request, reply, session.secret, session.expiresAt);
      return reply.code(204).send();
    },
  );

  app.post(
    '/auth/logout',
    {
      schema: { tags: ['auth'], summary: 'End the current session', response: { 204: noContent } },
    },
    async (request, reply) => {
      // The authentication hook has already refused an anonymous caller (401).
      const principal = requirePrincipal(request);
      if (principal.kind === 'session') {
        await deps.db.transaction(async (tx) => {
          await deleteSession(tx, principal.sessionSecret);
          // rbac-audit.md §10.2.1: signing out is never blocked by a malformed audit anchor.
          await deps.audit.recordOrSkipWhenAnchorMalformed(tx, actorOf(request), [
            {
              action: 'auth.sign_out',
              target: { type: 'user', id: principal.user.id, label: principal.user.username },
              details: {},
            },
          ]);
        });
        reply.clearCookie(SESSION_COOKIE, { path: '/' });
      }
      return reply.code(204).send();
    },
  );

  app.get(
    '/auth/me',
    {
      schema: {
        tags: ['auth'],
        summary: 'Current user, memberships and CSRF token',
        response: { 200: meResponse },
      },
    },
    async (request) => {
      const principal = requireUser(request);
      const access = accessOf(deps);
      const user = principal.user;
      // rbac-audit.md §5: the caller's own organisations (a role in it or a grant on one of its
      // projects), through the list condition; an instance admin lists its own too.
      const rows = await deps.db
        .select({
          organizationId: organizations.id,
          organizationKey: organizations.key,
          organizationName: organizations.name,
          organizationRole: memberships.role,
          hasProjectGrant: grantInOrganization(user, organizations.id),
        })
        .from(organizations)
        .leftJoin(memberships, memberOf(user, organizations.id))
        .where(visibleOrganizationsCondition(access, user, { own: true }))
        .orderBy(asc(organizations.key));
      // rbac-audit.md §6.1: the caller's project grants, at most 1 000.
      const grants = await deps.db
        .select({
          projectId: projectMemberships.projectId,
          projectKey: projects.key,
          organizationId: projects.organizationId,
          role: projectMemberships.role,
        })
        .from(projectMemberships)
        .innerJoin(projects, eq(projects.id, projectMemberships.projectId))
        .where(eq(projectMemberships.userId, user.id))
        .orderBy(asc(projects.key))
        .limit(1000);
      return {
        user: {
          ...userDto(user, await userSsoSummary(deps.db, user.id)),
          // For this session (ruling R7): an SSO session is not held up by the forced change.
          passwordChangeRequired: passwordChangeRequired(principal, deps.config.secretKey),
        },
        memberships: rows.map((row) => ({
          organizationId: row.organizationId,
          organizationKey: row.organizationKey,
          organizationName: row.organizationName,
          role: row.organizationRole,
          permissions: [...organizationPermissions(organizationFacts(user, row))].sort(),
        })),
        projectGrants: grants,
        csrfToken:
          principal.kind === 'session'
            ? csrfTokenFor(deps.config.secretKey, principal.sessionSecret)
            : null,
        demo: isDemoUser(deps.config.demoUser, user),
      };
    },
  );

  app.put(
    '/auth/me/password',
    {
      schema: {
        tags: ['auth'],
        summary: 'Change your password',
        body: passwordBody,
        response: { 204: noContent },
      },
    },
    async (request, reply) => {
      const principal = requireSession(request);
      const { currentPassword, newPassword } = request.body;
      if (!(await verifyPassword(principal.user.passwordHash, currentPassword))) {
        throw validationFailed([
          { path: 'body.currentPassword', message: 'Current password is incorrect' },
        ]);
      }
      if (currentPassword === newPassword) {
        throw validationFailed([
          { path: 'body.newPassword', message: 'New password must differ from the current one' },
        ]);
      }
      // Hash before opening the transaction: argon2 is CPU-bound, not DB-bound, and shouldn't
      // hold a pool connection for the duration. The update and the session cleanup then commit
      // atomically, so a crash between them can never leave the new hash active with the old
      // sessions (or vice versa) still valid.
      const passwordHash = await hashPassword(newPassword);
      await deps.db.transaction(async (tx) => {
        await tx
          .update(users)
          .set({ passwordHash, passwordChangeRequired: false })
          .where(eq(users.id, principal.user.id));
        await deleteUserSessions(tx, principal.user.id, principal.sessionSecret);
        await deps.audit.record(tx, actorOf(request), [
          {
            action: 'auth.password_changed',
            target: { type: 'user', id: principal.user.id, label: principal.user.username },
            details: {},
          },
        ]);
      });
      return reply.code(204).send();
    },
  );
};
