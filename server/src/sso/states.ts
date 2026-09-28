import { createHash } from 'node:crypto';
import type { CacheProvider } from '@node-saml/node-saml';
import { and, eq, gt, sql } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgErrorCode } from '../db/errors';
import { ssoStates, type SsoStateKind } from '../db/schema';

/** A pending OIDC or SAML flow (sso-scim.md §7.1). */
export const FLOW_TTL_MS = 600_000;
/** A SAML finish code (sso-scim.md §6.4, §7.4). */
export const FINISH_TTL_MS = 60_000;
/** Rows per pruning DELETE, as housekeeping's other steps. */
const PRUNE_BATCH = 5_000;

/** The key is taken already: a replayed SAML assertion id, or a duplicate flow. */
export class StateExists extends Error {
  constructor() {
    super('state exists');
    this.name = 'StateExists';
  }
}

const sha = (raw: string): string => createHash('sha256').update(raw, 'utf8').digest('hex');

/**
 * sso-scim.md §7.1 keys: `oidc:<sha256 hex of state>`, `saml-request:<request ID>` (Qualor made it,
 * and node-saml's cache needs to find it again by that id), `saml-assertion:<connection id>:<sha256
 * hex of assertion ID>` (an assertion id is unique only per IdP), `finish:<sha256 hex of code>`.
 * Secrets (state, code) are stored only as hashes.
 */
export function stateKey(kind: SsoStateKind, raw: string, connectionId?: string): string {
  switch (kind) {
    case 'oidc':
      return `oidc:${sha(raw)}`;
    case 'saml-request':
      return `saml-request:${raw}`;
    case 'saml-assertion':
      if (!connectionId) throw new Error('a saml-assertion key needs its connection id');
      return `saml-assertion:${connectionId}:${sha(raw)}`;
    case 'finish':
      return `finish:${sha(raw)}`;
  }
}

/** Inserts a row expiring `ttlMs` after `now`; a key that exists (even expired) is `StateExists`. */
export async function putState(
  db: Executor,
  input: {
    key: string;
    kind: SsoStateKind;
    connectionId: string;
    payload: unknown;
    ttlMs: number;
    now?: Date;
  },
): Promise<void> {
  const now = input.now ?? new Date();
  try {
    await db.insert(ssoStates).values({
      key: input.key,
      kind: input.kind,
      connectionId: input.connectionId,
      payload: input.payload,
      expiresAt: new Date(now.getTime() + input.ttlMs),
    });
  } catch (err) {
    if (pgErrorCode(err) === PG_UNIQUE_VIOLATION) throw new StateExists();
    throw err;
  }
}

/**
 * Ruling SS3: the only reader that matters. `DELETE … RETURNING` of an unexpired row, so what it
 * returns is gone for every replica, and of two takers at the same moment only one gets it.
 */
export async function takeState<T>(
  db: Executor,
  key: string,
  now: Date = new Date(),
): Promise<{ connectionId: string; payload: T } | null> {
  const [row] = await db
    .delete(ssoStates)
    .where(and(eq(ssoStates.key, key), gt(ssoStates.expiresAt, now)))
    .returning({ connectionId: ssoStates.connectionId, payload: ssoStates.payload });
  return row ? { connectionId: row.connectionId, payload: row.payload as T } : null;
}

/**
 * Housekeeping (data-model.md §7): deletes expired rows by the database clock, in batches; a row a
 * `takeState` holds is skipped (`SKIP LOCKED`) and left to the next run. Returns how many went.
 */
export async function pruneSsoStates(db: Executor): Promise<number> {
  let total = 0;
  for (;;) {
    const result = await db.execute(sql`
      DELETE FROM sso_states WHERE key IN (
        SELECT key FROM sso_states WHERE expires_at <= now()
         LIMIT ${PRUNE_BATCH} FOR UPDATE SKIP LOCKED)`);
    const n = result.rowCount ?? 0;
    total += n;
    if (n < PRUNE_BATCH) return total;
  }
}

/**
 * node-saml's request-id cache, backed by `sso_states` so every replica sees it. `saveAsync` stores
 * the flow (`pending`) with the request's issue instant for `FLOW_TTL_MS`; `getAsync` reads an
 * unexpired row; `removeAsync` does nothing, since `takeState` is what consumes the row (SS3).
 * `pending` is null where no request is started (validating a response).
 */
export function samlCacheProvider(
  db: Executor,
  pending: { connectionId: string; payload: unknown } | null,
): CacheProvider {
  return {
    async saveAsync(key, value) {
      if (!pending) return null;
      const base =
        pending.payload && typeof pending.payload === 'object' ? (pending.payload as object) : {};
      await putState(db, {
        key: stateKey('saml-request', key),
        kind: 'saml-request',
        connectionId: pending.connectionId,
        payload: { ...base, issueInstant: value },
        ttlMs: FLOW_TTL_MS,
      });
      return { value, createdAt: Date.now() };
    },
    async getAsync(key) {
      const [row] = await db
        .select({ payload: ssoStates.payload })
        .from(ssoStates)
        .where(
          and(
            eq(ssoStates.key, stateKey('saml-request', key)),
            gt(ssoStates.expiresAt, new Date()),
          ),
        );
      const instant = (row?.payload as { issueInstant?: unknown } | undefined)?.issueInstant;
      return typeof instant === 'string' ? instant : null;
    },
    async removeAsync() {
      return null;
    },
  };
}
