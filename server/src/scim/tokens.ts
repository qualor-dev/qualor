import { and, asc, count, eq, gt, isNull, or, sql } from 'drizzle-orm';
import type { AuditActorContext, AuditRecorder } from '../audit/recorder';
import { hashesEqual, hashToken, randomBase62 } from '../auth/tokens';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { first } from '../db/rows';
import { scimTokens, ssoConnections, type ScimTokenRow } from '../db/schema';
import { conflict, notFound, validationFailed } from '../http/problem';

/** sso-scim.md §12.2: `qlr_scim_` and 32 base62 characters (190 bits), shown once. */
export const SCIM_TOKEN_PREFIX = 'qlr_scim_';
/** Active (not revoked, not expired) tokens per connection. */
export const MAX_SCIM_TOKENS = 5;
const PATTERN = /^qlr_scim_[0-9A-Za-z]{32}$/;
const SECRET_LENGTH = 32;
/** The stored lookup prefix: `qlr_scim_` and the first 3 secret characters. */
const PREFIX_LENGTH = 12;
/** `last_used_at` is evidence of use, written at most once a minute per token. */
const TOUCH_INTERVAL_MS = 60_000;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const NAME_MAX = 100;
/** No control, format (bidi overrides, zero-width) or lone surrogate characters. */
const NAME = /^[^\p{Cc}\p{Cf}\p{Cs}]+$/u;

export interface ScimTokenDeps {
  db: Db;
  audit: AuditRecorder;
}

/** What the API shows of a token: never the token or its hash. */
export interface ScimTokenView {
  id: string;
  connectionId: string;
  name: string;
  prefix: string;
  expiresAt: string | null;
  lastUsedAt: string | null;
  revokedAt: string | null;
  createdAt: string;
}

export interface ResolvedScimToken {
  tokenId: string;
  connectionId: string;
  prefix: string;
}

export function generateScimToken(): { token: string; prefix: string; secretHash: Buffer } {
  const token = SCIM_TOKEN_PREFIX + randomBase62(SECRET_LENGTH);
  return { token, prefix: token.slice(0, PREFIX_LENGTH), secretHash: hashToken(token) };
}

function toView(row: ScimTokenRow): ScimTokenView {
  return {
    id: row.id,
    connectionId: row.connectionId,
    name: row.name,
    prefix: row.prefix,
    expiresAt: row.expiresAt?.toISOString() ?? null,
    lastUsedAt: row.lastUsedAt?.toISOString() ?? null,
    revokedAt: row.revokedAt?.toISOString() ?? null,
    createdAt: row.createdAt.toISOString(),
  };
}

/**
 * The token's connection, or null (a 401 for the caller, and nothing else said). As
 * `resolveToken` (auth/principal.ts): every candidate with the prefix is compared in constant time
 * with no early exit, and the state (revoked, expired) is checked only after the loop. A refused
 * presentation never touches `last_used_at`. The token is never logged.
 */
export async function resolveScimToken(
  db: Executor,
  presented: string,
  now = new Date(),
): Promise<ResolvedScimToken | null> {
  if (!PATTERN.test(presented)) return null;
  const candidates = await db
    .select()
    .from(scimTokens)
    .where(eq(scimTokens.prefix, presented.slice(0, PREFIX_LENGTH)));
  const hash = hashToken(presented);
  let match: ScimTokenRow | undefined;
  for (const c of candidates) {
    if (hashesEqual(c.secretHash, hash)) match = c;
  }
  if (!match || match.revokedAt || (match.expiresAt && match.expiresAt <= now)) return null;
  if (!match.lastUsedAt || now.getTime() - match.lastUsedAt.getTime() >= TOUCH_INTERVAL_MS) {
    await db.update(scimTokens).set({ lastUsedAt: now }).where(eq(scimTokens.id, match.id));
  }
  return { tokenId: match.id, connectionId: match.connectionId, prefix: match.prefix };
}

/** Every token, or a connection's, oldest first (revoked ones included: the row stays). */
export async function listScimTokens(
  db: Executor,
  connectionId?: string,
): Promise<ScimTokenView[]> {
  if (connectionId !== undefined && !UUID.test(connectionId)) return [];
  const rows = await db
    .select()
    .from(scimTokens)
    .where(connectionId === undefined ? undefined : eq(scimTokens.connectionId, connectionId))
    .orderBy(asc(scimTokens.createdAt), asc(scimTokens.id));
  return rows.map(toView);
}

function checkInput(input: { name: string; expiresAt: Date | null }): void {
  const errors = [];
  const { name, expiresAt } = input;
  if (
    typeof name !== 'string' ||
    name.length === 0 ||
    [...name].length > NAME_MAX ||
    !NAME.test(name)
  ) {
    errors.push({
      path: 'body.name',
      message: `1 to ${NAME_MAX} characters, no control or format characters`,
    });
  }
  if (
    expiresAt !== null &&
    (!(expiresAt instanceof Date) ||
      Number.isNaN(expiresAt.getTime()) ||
      expiresAt.getTime() <= Date.now())
  ) {
    errors.push({ path: 'body.expiresAt', message: 'Give a time in the future, or none' });
  }
  if (errors.length > 0) throw validationFailed(errors);
}

/**
 * Creates a token for a connection (instance admins, `POST /ee/scim/tokens`). The token is
 * returned here once; only its SHA-256 is stored. At most `MAX_SCIM_TOKENS` active per connection.
 */
export async function createScimToken(
  deps: ScimTokenDeps,
  actor: AuditActorContext,
  input: { connectionId: string; name: string; expiresAt: Date | null },
): Promise<{ view: ScimTokenView; token: string }> {
  checkInput(input);
  if (!UUID.test(input.connectionId)) throw notFound('SSO connection');
  const generated = generateScimToken();
  const createdBy = actor.actor.type === 'system' ? null : actor.actor.userId;
  const row = await deps.db.transaction(async (tx) => {
    // The connections' lock: a connection deleted meanwhile, or a concurrent create, waits.
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.ssoConnections})`);
    const [connection] = await tx
      .select({ id: ssoConnections.id })
      .from(ssoConnections)
      .where(eq(ssoConnections.id, input.connectionId));
    if (!connection) throw notFound('SSO connection');
    const [{ n } = { n: 0 }] = await tx
      .select({ n: count() })
      .from(scimTokens)
      .where(
        and(
          eq(scimTokens.connectionId, input.connectionId),
          isNull(scimTokens.revokedAt),
          or(isNull(scimTokens.expiresAt), gt(scimTokens.expiresAt, sql`now()`)),
        ),
      );
    if (n >= MAX_SCIM_TOKENS) {
      throw conflict(
        'SCIM_TOKEN_LIMIT_REACHED',
        `At most ${MAX_SCIM_TOKENS} active SCIM tokens per connection`,
      );
    }
    const inserted = first(
      await tx
        .insert(scimTokens)
        .values({
          connectionId: input.connectionId,
          name: input.name,
          prefix: generated.prefix,
          secretHash: generated.secretHash,
          expiresAt: input.expiresAt,
          createdBy,
        })
        .returning(),
    );
    await deps.audit.record(tx, actor, [
      {
        action: 'scim_token.created',
        target: { type: 'scim_token', id: inserted.id, label: inserted.name },
        details: {
          connectionId: inserted.connectionId,
          name: inserted.name,
          prefix: inserted.prefix,
          expiresAt: inserted.expiresAt?.toISOString() ?? null,
        },
      },
    ]);
    return inserted;
  });
  return { view: toView(row), token: generated.token };
}

/**
 * Revokes a token (`DELETE /ee/scim/tokens/{id}`): `revoked_at` is set and the row stays.
 * Idempotent: a revoked token is returned as it is, with no second event. Access-removing
 * (rbac-audit.md §10.2.1): a malformed audit anchor skips the event, not the revocation.
 */
export async function revokeScimToken(
  deps: ScimTokenDeps,
  actor: AuditActorContext,
  id: string,
): Promise<ScimTokenView> {
  if (!UUID.test(id)) throw notFound('SCIM token');
  const row = await deps.db.transaction(async (tx) => {
    const [current] = await tx.select().from(scimTokens).where(eq(scimTokens.id, id)).for('update');
    if (!current) throw notFound('SCIM token');
    if (current.revokedAt) return current;
    const revoked = first(
      await tx
        .update(scimTokens)
        .set({ revokedAt: sql`now()` })
        .where(eq(scimTokens.id, id))
        .returning(),
    );
    await deps.audit.recordOrSkipWhenAnchorMalformed(tx, actor, [
      {
        action: 'scim_token.revoked',
        target: { type: 'scim_token', id, label: revoked.name },
        details: { connectionId: revoked.connectionId, name: revoked.name, prefix: revoked.prefix },
      },
    ]);
    return revoked;
  });
  return toView(row);
}
