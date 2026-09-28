import { desc, sql } from 'drizzle-orm';
import type { FastifyRequest } from 'fastify';
import type { Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { LOCKS } from '../db/locks';
import { auditEvents } from '../db/schema';
import { canonicalJson, toStorableText, type AuditJson } from './canonical';
import {
  AUDIT_CATALOGUE,
  isAuditAction,
  type AuditAction,
  type AuditDetails,
  type AuditTargetType,
} from './catalogue';
import { eventHash, GENESIS_HASH, type AuditRecord } from './chain';
import { AuditAnchorMalformedError, readChainAnchor } from './settings';

/** rbac-audit.md §9: who acted. A failed sign-in is `anonymous`, retention is `system`. */
export type AuditActor =
  | { type: 'user'; userId: string; username: string; tokenId: string | null }
  | { type: 'anonymous'; userId: string | null; username: string | null }
  | { type: 'system' };

export interface AuditActorContext {
  actor: AuditActor;
  ip: string | null;
  userAgent: string | null;
}

export const SYSTEM_ACTOR: AuditActorContext = Object.freeze({
  actor: Object.freeze({ type: 'system' as const }),
  ip: null,
  userAgent: null,
});

export interface AuditEventInput<A extends AuditAction = AuditAction> {
  action: A;
  outcome?: 'success' | 'failure';
  organization?: { id: string; key: string } | null;
  project?: { id: string; key: string } | null;
  target?: { type: AuditTargetType; id: string; label?: string | null } | null;
  details: AuditDetails<A>;
}

const USER_AGENT_MAX = 256;
const LABEL_MAX = 255;

/**
 * Free text from outside (a user agent, a label): U+0000 and lone surrogates become U+FFFD (so the
 * text is storable and hashes as stored), then at most `max` code points, as `char_length` counts
 * them; empty becomes null.
 */
function clip(text: string | null | undefined, max: number): string | null {
  if (text === null || text === undefined || text === '') return null;
  return [...toStorableText(text)].slice(0, max).join('');
}

function header(value: string | string[] | undefined): string | null {
  return clip(Array.isArray(value) ? value[0] : value, USER_AGENT_MAX);
}

/** The acting person of a request: a session or personal token user, else anonymous. */
export function actorOf(request: FastifyRequest): AuditActorContext {
  const p = request.principal;
  const base = { ip: request.ip || null, userAgent: header(request.headers['user-agent']) };
  if (p && p.kind !== 'project') {
    return {
      ...base,
      actor: {
        type: 'user',
        userId: p.user.id,
        username: p.user.username,
        tokenId: p.kind === 'personal' ? p.tokenId : null,
      },
    };
  }
  return { ...base, actor: { type: 'anonymous', userId: null, username: null } };
}

/** A sign-in: the user who just proved who they are (the request has no principal yet). */
export function userActor(
  request: FastifyRequest,
  user: { id: string; username: string },
): AuditActorContext {
  return {
    ip: request.ip || null,
    userAgent: header(request.headers['user-agent']),
    actor: { type: 'user', userId: user.id, username: user.username, tokenId: null },
  };
}

/** A failed sign-in: the user only when the typed name belongs to one, never the name. */
export function anonymousActor(
  request: FastifyRequest,
  user: { id: string; username: string } | null,
): AuditActorContext {
  return {
    ip: request.ip || null,
    userAgent: header(request.headers['user-agent']),
    actor: { type: 'anonymous', userId: user?.id ?? null, username: user?.username ?? null },
  };
}

/** Under the chain lock: the newest event, else the anchor row (§11.2), else the genesis. */
async function chainHead(tx: Executor): Promise<{ seq: number; hash: string }> {
  const [last] = await tx
    .select({ seq: auditEvents.seq, hash: auditEvents.hash })
    .from(auditEvents)
    .orderBy(desc(auditEvents.seq))
    .limit(1);
  if (last) return last;
  const anchor = await readChainAnchor(tx);
  return anchor
    ? { seq: Number(anchor.throughSeq), hash: anchor.throughHash }
    : { seq: 0, hash: GENESIS_HASH };
}

function recordActor(actor: AuditActor): AuditRecord['actor'] {
  if (actor.type === 'system')
    return { type: 'system', userId: null, username: null, tokenId: null };
  if (actor.type === 'user') {
    return {
      type: 'user',
      userId: actor.userId,
      username: actor.username,
      tokenId: actor.tokenId,
    };
  }
  return { type: 'anonymous', userId: actor.userId, username: actor.username, tokenId: null };
}

/** rbac-audit.md §10.2 step 3: at most this many rows per INSERT. */
export const AUDIT_INSERT_CHUNK = 1000;

/**
 * rbac-audit.md §10.2 (ruling AU1): validates every event first (nothing is written if one is
 * invalid), then appends them under the chain lock inside a transaction (a savepoint when
 * `executor` is one already), so the lock is held until the caller's change commits and seq order
 * is commit order. Call it at the end of the caller's transaction, which must be READ COMMITTED
 * (the default): the head is read after the lock is taken, with a fresh snapshot.
 */
export async function appendEvents(
  executor: Executor,
  context: AuditActorContext,
  events: readonly AuditEventInput[],
  now: Date,
): Promise<void> {
  if (events.length === 0) return;
  const actor = recordActor(context.actor);
  const ip = clip(context.ip, USER_AGENT_MAX);
  const userAgent = clip(context.userAgent, USER_AGENT_MAX);
  const validated = events.map((e) => {
    if (!isAuditAction(e.action)) throw new Error(`unknown audit action ${String(e.action)}`);
    const details = AUDIT_CATALOGUE[e.action].details.parse(e.details) as Record<string, AuditJson>;
    // Refuses what the hash could not reproduce from the stored row (U+0000, a lone surrogate).
    canonicalJson(details);
    const target = e.target
      ? { type: e.target.type, id: e.target.id, label: clip(e.target.label, LABEL_MAX) }
      : null;
    return { ...e, details, target };
  });
  await executor.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.auditChain})`);
    let head = await chainHead(tx);
    const rows = validated.map((e) => {
      const seq = head.seq + 1;
      const id = uuidv7();
      const record: AuditRecord = {
        v: 1,
        seq: String(seq),
        id,
        occurredAt: now.toISOString(),
        action: e.action,
        outcome: e.outcome ?? 'success',
        actor,
        organization: e.organization ? { id: e.organization.id, key: e.organization.key } : null,
        project: e.project ? { id: e.project.id, key: e.project.key } : null,
        target: e.target,
        ip,
        userAgent,
        details: e.details,
      };
      const hash = eventHash(head.hash, record);
      const row = {
        id,
        seq,
        createdAt: now,
        action: record.action,
        outcome: record.outcome,
        actorType: actor.type,
        actorUserId: actor.userId,
        actorUsername: actor.username,
        actorTokenId: actor.tokenId,
        organizationId: record.organization?.id ?? null,
        organizationKey: record.organization?.key ?? null,
        projectId: record.project?.id ?? null,
        projectKey: record.project?.key ?? null,
        targetType: record.target?.type ?? null,
        targetId: record.target?.id ?? null,
        targetLabel: record.target?.label ?? null,
        ip,
        userAgent,
        details: record.details,
        prevHash: head.hash,
        hash,
      };
      head = { seq, hash };
      return row;
    });
    // §10.2 step 3: a statement holds at most 65 535 parameters (21 a row), so a large bulk is
    // written in chunks, all in this transaction and under the lock above.
    for (let i = 0; i < rows.length; i += AUDIT_INSERT_CHUNK) {
      await tx.insert(auditEvents).values(rows.slice(i, i + AUDIT_INSERT_CHUNK));
    }
  });
}

/**
 * rbac-audit.md §10.2.1 (sso-scim.md §15 extends it): the actions whose change removes access,
 * which a malformed anchor must never block. `removesAccess` narrows the role changes to
 * demotions and `user.updated` to a deactivation or an instance-admin demotion; every other listed
 * action, SSO and SCIM ones included, always removes access.
 */
export const ACCESS_REMOVING_ACTIONS: ReadonlySet<AuditAction> = new Set<AuditAction>([
  'auth.sign_out',
  'token.revoked',
  'project_token.revoked',
  'user.updated',
  'member.removed',
  'member.role_changed',
  'project_member.removed',
  'project_member.role_changed',
  // sso-scim.md §15: these events always remove access, so `removesAccess` needs no branch for
  // them (the fallthrough `return true` below covers them, like sign-out and the revocations).
  'scim.user_deactivated',
  'scim.user_deleted',
  'scim_token.revoked',
  'sso.identity_unlinked',
  'sso.connection_deleted',
]);

/** Organisation and project roles, highest first (rbac-audit.md §3.2). */
const ROLE_RANK: Readonly<Record<string, number>> = {
  admin: 4,
  project_admin: 3,
  member: 2,
  viewer: 1,
};

/** A user change that only takes access away: `active` or `isInstanceAdmin` true → false. */
const REVOKING_USER_FIELDS: ReadonlySet<string> = new Set(['active', 'isInstanceAdmin']);

/** rbac-audit.md §10.2.1: whether this event records a change that only removes access. */
export function removesAccess(event: AuditEventInput): boolean {
  if (!ACCESS_REMOVING_ACTIONS.has(event.action)) return false;
  if (event.action === 'member.role_changed' || event.action === 'project_member.role_changed') {
    const { from, to } = event.details as { from: string; to: string };
    const before = ROLE_RANK[from];
    const after = ROLE_RANK[to];
    return before !== undefined && after !== undefined && after < before;
  }
  if (event.action === 'user.updated') {
    const { changes, passwordReset } = event.details as {
      changes: readonly { field: string; from: unknown; to: unknown }[];
      passwordReset: boolean;
    };
    return (
      passwordReset === false &&
      changes.length > 0 &&
      changes.every((c) => REVOKING_USER_FIELDS.has(c.field) && c.from === true && c.to === false)
    );
  }
  return true;
}

/** Where a skipped event is reported (the server's logger): ids only, never a secret. */
export interface AuditLog {
  error(fields: Record<string, unknown>, message: string): void;
}

export const ANCHOR_SKIP_MESSAGE = 'audit event skipped: the audit-chain anchor is malformed';

export interface AuditRecorder {
  active(): boolean;
  record(
    executor: Executor,
    context: AuditActorContext,
    events: readonly AuditEventInput[],
  ): Promise<void>;
  /**
   * rbac-audit.md §10.2.1: `record`, except that when every event removes access
   * (`removesAccess`) and the anchor is malformed, the events are skipped and each is logged in one
   * line, so the change still commits. Anything else fails closed, as `record` does.
   */
  recordOrSkipWhenAnchorMalformed(
    executor: Executor,
    context: AuditActorContext,
    events: readonly AuditEventInput[],
  ): Promise<void>;
}

/** §8.1: nothing is validated or written while `isActive` is false. */
export function createAuditRecorder(options: {
  isActive: () => boolean;
  now?: () => Date;
  /** §10.2.1: the server's logger, for the events skipped while the anchor is malformed. */
  log: AuditLog;
}): AuditRecorder {
  const now = options.now ?? (() => new Date());
  return {
    active: options.isActive,
    record: async (executor, context, events) => {
      if (!options.isActive()) return;
      await appendEvents(executor, context, events, now());
    },
    recordOrSkipWhenAnchorMalformed: async (executor, context, events) => {
      if (!options.isActive()) return;
      if (!events.every(removesAccess)) {
        await appendEvents(executor, context, events, now());
        return;
      }
      try {
        // appendEvents runs in a savepoint of the caller's transaction, so the refusal below
        // rolls back only the append, and the change itself still commits.
        await appendEvents(executor, context, events, now());
      } catch (err) {
        if (!(err instanceof AuditAnchorMalformedError)) throw err;
        const actorId = context.actor.type === 'system' ? null : context.actor.userId;
        for (const e of events) {
          options.log.error(
            { component: 'audit', action: e.action, actorId, targetId: e.target?.id ?? null },
            ANCHOR_SKIP_MESSAGE,
          );
        }
      }
    },
  };
}
