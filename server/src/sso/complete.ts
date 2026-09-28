import type { FastifyBaseLogger, FastifyReply, FastifyRequest } from 'fastify';
import { anonymousActor, userActor, type AuditRecorder } from '../audit/recorder';
import { resolveSession, SESSION_COOKIE } from '../auth/sessions';
import type { Config } from '../config';
import type { Db } from '../db/client';
import type { Resolver } from '../http/outbound';
import type { Edition } from '../license/edition';
import { linkIdentity, resolveAccount, type SignInClaims } from './accounts';
import { clearBindingCookie } from './binding';
import type { LoadedConnection } from './connections';
import { SsoFailure } from './errors';
import { syncGroupMemberships } from './groups';
import { safeReturnTo } from './return-to';
import { issueSsoSession } from './session';

/** What the OIDC and SAML flows need from the server. */
export interface FlowDeps {
  db: Db;
  config: Config;
  edition: Edition;
  audit: AuditRecorder;
  log: FastifyBaseLogger;
  /** Tests: the resolver ssoFetch uses (default: the system's). */
  resolve?: Resolver;
}

/** What a flow row carries to the end of the flow, whatever the protocol. */
export interface FlowIntent {
  returnTo: string;
  intent: 'sign_in' | 'link';
  linkUserId: string | null;
}

/** The message syncGroupMemberships throws beyond MAX_GROUP_VALUES. */
const TOO_MANY_GROUPS = 'groups.too_many';

/**
 * sso-scim.md §7.4–§8: the end of a validated flow, after the browser binding matched (SS4) and
 * the required claims held. Throws `SsoFailure` for the caller's `failSsoFlow`.
 *
 * - `link`: the session cookie sent with this request must belong to `linkUserId` (else
 *   `flow_mismatch`, `link.session`); the identity is linked and the person goes back to
 *   `returnTo` in the session they have (no new session).
 * - `sign_in`: in one transaction the account is resolved (§8.2) and, with `groupSource: claims`,
 *   the groups synced (§9.3); any failure rolls the transaction back, so nothing of a refused
 *   sign-in stays. Then the session is issued (§7.5).
 */
export async function completeSignIn(
  deps: FlowDeps,
  request: FastifyRequest,
  reply: FastifyReply,
  input: {
    connection: LoadedConnection;
    protocol: 'oidc' | 'saml';
    claims: SignInClaims;
    flow: FlowIntent;
  },
): Promise<FastifyReply> {
  const { connection, claims, flow } = input;
  const connectionId = connection.row.id;
  const returnTo = safeReturnTo(flow.returnTo);

  if (flow.intent === 'link') {
    const presented = request.cookies[SESSION_COOKIE];
    const sessionUser =
      typeof presented === 'string' ? await resolveSession(deps.db, presented) : null;
    if (!sessionUser || flow.linkUserId === null || sessionUser.id !== flow.linkUserId) {
      throw new SsoFailure('flow_mismatch', 'link.session', flow.linkUserId);
    }
    const linked = await deps.db.transaction((tx) =>
      linkIdentity(tx, {
        connectionId,
        userId: sessionUser.id,
        subject: claims.subject,
        audit: deps.audit,
        actor: userActor(request, sessionUser),
      }),
    );
    if (!linked.ok) throw new SsoFailure(linked.reason, `account.${linked.reason}`, sessionUser.id);
    clearBindingCookie(reply);
    return reply.code(303).header('location', returnTo).send();
  }

  const user = await deps.db.transaction(async (tx) => {
    const resolved = await resolveAccount(tx, {
      connectionId,
      config: connection.parsed,
      claims,
      audit: deps.audit,
      actor: anonymousActor(request, null),
    });
    if (!resolved.ok) {
      throw new SsoFailure(resolved.reason, `account.${resolved.reason}`, resolved.userId);
    }
    if (connection.parsed.config.groupSource === 'claims') {
      try {
        await syncGroupMemberships(tx, {
          connectionId,
          userId: resolved.user.id,
          username: resolved.user.username,
          groups: claims.groups,
          audit: deps.audit,
          log: deps.log,
        });
      } catch (err) {
        if (err instanceof Error && err.message === TOO_MANY_GROUPS) {
          throw new SsoFailure('invalid_response', TOO_MANY_GROUPS, resolved.user.id);
        }
        throw err;
      }
    }
    return resolved.user;
  });
  // The session gets a transaction of its own, as §7.5 describes it and as `POST /auth/login`
  // makes it. If it fails after the one above committed (the user deactivated in between, which
  // issueSsoSession re-checks under a row lock), what stays is harmless: an identity or a JIT
  // account without a session, and memberships the next sign-in's sync would write the same way,
  // each already in the audit chain. No session, and so no access, comes of it.
  return issueSsoSession(deps, request, reply, {
    user,
    connectionId,
    protocol: input.protocol,
    returnTo,
  });
}
