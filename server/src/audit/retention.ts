import { eq, sql } from 'drizzle-orm';
import type { Db } from '../db/client';
import { LOCKS } from '../db/locks';
import { auditEvents } from '../db/schema';
import { appendEvents, SYSTEM_ACTOR } from './recorder';
import { AUDIT_CHAIN_KEY, readChainAnchor, writeSetting } from './settings';

/** rbac-audit.md §11.1: at most this many events per run; a larger backlog takes several runs. */
export const AUDIT_PRUNE_BATCH = 50_000;
const DAY_MS = 24 * 60 * 60 * 1000;

/**
 * rbac-audit.md §11 (ruling AU2): deletes the oldest events older than the period, a prefix of
 * the chain of at most AUDIT_PRUNE_BATCH, and records the anchor in the same transaction: the
 * `audit-chain` row and an `audit.pruned` event by `system`. Runs whether or not `audit-log` is
 * active; a table with nothing old enough (or no events at all) is left untouched.
 *
 * The only code that sets `qualor.audit_prune` (§7.3; a sweep test enforces it), and only to the
 * id of this transaction, transaction-locally (set_config's is_local). Fails closed: a malformed
 * `audit-chain` row throws (readChainAnchor) and nothing is deleted, so a run never overwrites a
 * row someone changed.
 */
export async function pruneAuditEvents(
  db: Db,
  options: { retentionDays: number; now: Date },
): Promise<number> {
  const cutoff = new Date(options.now.getTime() - options.retentionDays * DAY_MS);
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.auditChain})`);
    const bounds = await tx.execute<{ oldest: string | null; through: string | null }>(sql`
      SELECT min(seq)::text AS oldest,
             (max(seq) FILTER (WHERE created_at < ${cutoff}))::text AS through
        FROM audit_events`);
    const b = bounds.rows[0];
    if (!b?.through || !b.oldest) return 0;
    await readChainAnchor(tx);
    // Everything up to `through` goes, so what stays is still one unbroken chain (§11.1).
    const through = Math.min(Number(b.through), Number(b.oldest) + AUDIT_PRUNE_BATCH - 1);
    const [last] = await tx
      .select({ hash: auditEvents.hash })
      .from(auditEvents)
      .where(eq(auditEvents.seq, through));
    if (!last) throw new Error(`audit event ${String(through)} vanished under the chain lock`);
    // §7.3: the flag is this transaction's own id, local to it (is_local = true).
    await tx.execute(sql`SELECT set_config('qualor.audit_prune', txid_current()::text, true)`);
    const deleted =
      (await tx.execute(sql`DELETE FROM audit_events WHERE seq <= ${through}`)).rowCount ?? 0;
    await tx.execute(sql`SELECT set_config('qualor.audit_prune', '', true)`);
    const anchor = { throughSeq: String(through), throughHash: last.hash };
    await writeSetting(tx, AUDIT_CHAIN_KEY, { ...anchor, prunedAt: options.now.toISOString() });
    await appendEvents(
      tx,
      SYSTEM_ACTOR,
      [{ action: 'audit.pruned', details: { ...anchor, deleted, cutoff: cutoff.toISOString() } }],
      options.now,
    );
    return deleted;
  });
}
