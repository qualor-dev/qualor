import { and, eq } from 'drizzle-orm';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { AuditRecorder } from '../audit/recorder';
import { userActor } from '../audit/recorder';
import {
  createSession,
  deleteSession,
  SESSION_COOKIE,
  sessionCookieOptions,
  type UserRow,
} from '../auth/sessions';
import type { Config } from '../config';
import type { Db } from '../db/client';
import { identities, users } from '../db/schema';
import { clearBindingCookie } from './binding';
import { SsoFailure } from './errors';
import { safeReturnTo } from './return-to';

/**
 * sso-scim.md §7.5: the session of an SSO sign-in, made as `POST /auth/login` makes it. In one
 * transaction the presented session is deleted (session fixation), a new one is created,
 * `last_login_at` and the identity's `last_sign_in_at` are set, and `auth.sign_in` is recorded;
 * then the cookie is set exactly as for a password sign-in, the binding cookie is cleared, and the
 * answer is a 303 to `returnTo`, made safe again here with `safeReturnTo`.
 *
 * The user is re-read under a row lock in the transaction: one deactivated since the account was
 * resolved (an admin, or SCIM) gets no session, and the call throws `SsoFailure('inactive_user')`
 * for the caller's `failSsoFlow`.
 */
export async function issueSsoSession(
  deps: { db: Db; config: Pick<Config, 'sessionTtlHours' | 'secretKey'>; audit: AuditRecorder },
  request: FastifyRequest,
  reply: FastifyReply,
  input: { user: UserRow; connectionId: string; protocol: 'oidc' | 'saml'; returnTo: string },
): Promise<FastifyReply> {
  const returnTo = safeReturnTo(input.returnTo);
  const presented = request.cookies[SESSION_COOKIE];
  const session = await deps.db.transaction(async (tx) => {
    // The identity's row before the user's, the order SCIM's writes and unlinking lock them in.
    await tx
      .select({ id: identities.id })
      .from(identities)
      .where(
        and(eq(identities.connectionId, input.connectionId), eq(identities.userId, input.user.id)),
      )
      .for('no key update');
    const [current] = await tx
      .select({ active: users.active })
      .from(users)
      .where(eq(users.id, input.user.id))
      .for('update');
    if (!current?.active) {
      throw new SsoFailure(
        'inactive_user',
        'account.inactive_user',
        current ? input.user.id : null,
      );
    }
    if (presented) await deleteSession(tx, presented);
    const created = await createSession(tx, {
      userId: input.user.id,
      ttlHours: deps.config.sessionTtlHours,
      ip: request.ip,
      userAgent: request.headers['user-agent'] ?? null,
      // Marked as an SSO session: a forced password change does not hold it up (authenticate.ts).
      ssoKey: deps.config.secretKey,
    });
    const now = new Date();
    await tx.update(users).set({ lastLoginAt: now }).where(eq(users.id, input.user.id));
    await tx
      .update(identities)
      .set({ lastSignInAt: now })
      .where(
        and(eq(identities.connectionId, input.connectionId), eq(identities.userId, input.user.id)),
      );
    await deps.audit.record(tx, userActor(request, input.user), [
      {
        action: 'auth.sign_in',
        target: { type: 'user', id: input.user.id, label: input.user.username },
        details: { method: input.protocol, connectionId: input.connectionId },
      },
    ]);
    return created;
  });
  reply.setCookie(SESSION_COOKIE, session.secret, sessionCookieOptions(request, session.expiresAt));
  clearBindingCookie(reply);
  return reply.code(303).header('location', returnTo).send();
}
