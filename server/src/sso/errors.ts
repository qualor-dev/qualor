import { eq } from 'drizzle-orm';
import type { FastifyBaseLogger, FastifyReply, FastifyRequest } from 'fastify';
import { SSO_ERROR_REASONS } from '../audit/catalogue';
import { anonymousActor, type AuditRecorder } from '../audit/recorder';
import type { Db } from '../db/client';
import { ssoConnections, users } from '../db/schema';
import { clearBindingCookie } from './binding';

/** sso-scim.md §7.7: the code a failed flow redirects with; the UI has a fixed message for each. */
export type SsoErrorCode = (typeof SSO_ERROR_REASONS)[number];

/**
 * sso-scim.md §7.7: the fixed sub-codes a failure's `detail` may take in the log. Library error
 * messages (which may echo attacker-controlled text) are never logged; a flow maps them to one of
 * these. The OIDC (Task 13) and SAML (Task 14) flows add each detail they can produce.
 */
export const SSO_DETAIL_CODES = [
  'start.other',
  'flow.expired',
  'flow.binding',
  'link.session',
  'groups.too_many',
  'oidc.not_configured',
  'oidc.disabled',
  'oidc.not_in_effect',
  'oidc.state_missing',
  'oidc.state_unknown',
  'oidc.binding',
  'oidc.id_token.missing',
  'oidc.id_token.iss',
  'oidc.id_token.aud',
  'oidc.id_token.azp',
  'oidc.id_token.nonce',
  'oidc.id_token.exp',
  'oidc.id_token.iat',
  'oidc.id_token.other',
  'oidc.id_token.signature',
  'oidc.key_selection',
  'oidc.iss_param',
  'oidc.discovery',
  'oidc.secret',
  'oidc.inactive',
  'oidc.token_endpoint',
  'oidc.invalid_response',
  'oidc.unsupported_alg',
  'oidc.userinfo',
  'oidc.claims',
  'oidc.required_claim',
  'oidc.other',
  'saml.form',
  'saml.validate',
  'saml.status',
  'saml.no_profile',
  'saml.recipient',
  'saml.in_response_to',
  'saml.authn_statement',
  'saml.destination',
  'saml.name_id_format',
  'saml.relay',
  'saml.claims',
  'saml.required_claim',
  'saml.other',
  'saml.not_configured',
  'saml.inactive',
  'saml.disabled',
  'saml.not_in_effect',
  'saml.sp_key',
  'saml.request_unknown',
  'saml.issuer',
  'saml.subject_confirmation',
  'saml.name_id',
  'saml.assertion_id',
  'saml.encryption',
  'saml.decrypt',
  'saml.replayed',
  'saml.claims_too_large',
  ...SSO_ERROR_REASONS.map((code) => `account.${code}` as const),
] as const;

/**
 * Families whose last part is a fixed code of another list (the IdP's OAuth `error`, a refusal of
 * `ssoFetch`, a pre-check code): the prefix, then 1–40 of `[a-z0-9_]`.
 */
export const SSO_DETAIL_FAMILIES = ['oidc.idp.', 'oidc.fetch.', 'saml.precheck.'] as const;
const FAMILY_TAIL = /^[a-z0-9_]{1,40}$/;
const KNOWN_DETAILS: ReadonlySet<string> = new Set(SSO_DETAIL_CODES);
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** The detail as logged: one of the fixed list or a family, else `other`. */
export function ssoDetail(detail: string): string {
  if (KNOWN_DETAILS.has(detail)) return detail;
  for (const family of SSO_DETAIL_FAMILIES) {
    if (detail.startsWith(family) && FAMILY_TAIL.test(detail.slice(family.length))) return detail;
  }
  return 'other';
}

/** A failed SSO flow: the code the browser sees and the fixed detail only the log sees. */
export class SsoFailure extends Error {
  constructor(
    readonly code: SsoErrorCode,
    readonly detail: string,
    /** The user, when the flow got far enough to know one (the audit event names them). */
    readonly userId: string | null = null,
  ) {
    super(`sso flow failed: ${code}`);
    this.name = 'SsoFailure';
  }
}

/** The class name of a thrown value, never its message. */
function className(err: unknown): string {
  return err instanceof Error ? err.constructor.name : typeof err;
}

/** The connection named by the URL, when it is a UUID of a connection that exists; else null. */
async function existingConnection(db: Db, raw: string): Promise<string | null> {
  if (!UUID.test(raw)) return null;
  const id = raw.toLowerCase();
  const [row] = await db
    .select({ id: ssoConnections.id })
    .from(ssoConnections)
    .where(eq(ssoConnections.id, id));
  return row ? id : null;
}

/**
 * sso-scim.md §7.7: ends a failed flow. Records `sso.sign_in_failed` in its own transaction only
 * for a connection that exists (enabled or not), and logs `{ component, connectionId, reason,
 * detail }` (fixed values only). A failure whose connection id is not a UUID, or names no
 * connection, is not recorded: it is logged as one fixed line with `connectionId: null`, the id
 * itself left out (anyone can call the public flow routes with any id, and the audit chain must
 * not grow with them). A recorder error is logged, never thrown, so the redirect always happens.
 * Then the binding cookie is cleared and the answer is 303 to `/login?sso_error=<code>`, never
 * with the IdP's text.
 */
export async function failSsoFlow(
  deps: { db: Db; audit: AuditRecorder; log: FastifyBaseLogger },
  request: FastifyRequest,
  reply: FastifyReply,
  input: { connectionId: string; protocol: 'oidc' | 'saml'; failure: SsoFailure },
): Promise<FastifyReply> {
  const { failure } = input;
  const detail = ssoDetail(failure.detail);
  let connectionId: string | null = null;
  try {
    connectionId = await existingConnection(deps.db, input.connectionId);
  } catch (err) {
    deps.log.error(
      { component: 'sso', errorClass: className(err) },
      'could not read the connection of a failed sign-in',
    );
  }
  if (connectionId === null) {
    deps.log.warn(
      { component: 'sso', connectionId: null, reason: failure.code, detail },
      'single sign-on failed for an unknown connection',
    );
  } else {
    deps.log.warn(
      { component: 'sso', connectionId, reason: failure.code, detail },
      'single sign-on failed',
    );
    try {
      await deps.db.transaction(async (tx) => {
        const [known] =
          failure.userId !== null && UUID.test(failure.userId)
            ? await tx
                .select({ id: users.id, username: users.username })
                .from(users)
                .where(eq(users.id, failure.userId))
            : [];
        await deps.audit.record(tx, anonymousActor(request, known ?? null), [
          {
            action: 'sso.sign_in_failed',
            outcome: 'failure',
            target: known ? { type: 'user', id: known.id, label: known.username } : null,
            details: { connectionId, protocol: input.protocol, reason: failure.code },
          },
        ]);
      });
    } catch (err) {
      deps.log.error(
        { component: 'sso', connectionId, errorClass: className(err) },
        'could not record sso.sign_in_failed',
      );
    }
  }
  clearBindingCookie(reply);
  return reply
    .code(303)
    .header('location', `/login?sso_error=${encodeURIComponent(failure.code)}`)
    .send();
}
