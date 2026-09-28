import { and, asc, count, desc, eq, gt, lt, lte, min } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { auditEvents } from '../db/schema';
import { eventHash, GENESIS_HASH, recordOf } from './chain';
import {
  AuditAnchorMalformedError,
  auditAnchorSchema,
  readChainAnchor,
  type AuditAnchor,
} from './settings';

export type { AuditAnchor } from './settings';

export interface AuditHead {
  seq: string | null;
  hash: string | null;
  occurredAt: string | null;
  count: number;
  anchor: AuditAnchor | null;
}

export type AuditBreakReason = 'hash_mismatch' | 'prev_mismatch' | 'gap' | 'anchor_mismatch';

/** rbac-audit.md §10.3. */
export interface AuditVerification {
  ok: boolean;
  checked: number;
  firstSeq: string | null;
  lastSeq: string | null;
  anchor: AuditAnchor | null;
  break: { seq: string; reason: AuditBreakReason } | null;
}

/**
 * §11.2: the newest `audit.pruned` event still stored, else the `audit-chain` row. Throws when
 * that row exists but is malformed (readChainAnchor fails closed).
 */
export async function currentAnchor(db: Executor): Promise<AuditAnchor | null> {
  const [pruned] = await db
    .select({ details: auditEvents.details })
    .from(auditEvents)
    .where(eq(auditEvents.action, 'audit.pruned'))
    .orderBy(desc(auditEvents.seq))
    .limit(1);
  const fromEvent = auditAnchorSchema.safeParse(pruned?.details);
  if (fromEvent.success && fromEvent.data.throughSeq !== '0') {
    return { throughSeq: fromEvent.data.throughSeq, throughHash: fromEvent.data.throughHash };
  }
  return readChainAnchor(db);
}

export async function auditHead(db: Executor): Promise<AuditHead> {
  const [last] = await db.select().from(auditEvents).orderBy(desc(auditEvents.seq)).limit(1);
  const [total] = await db.select({ n: count() }).from(auditEvents);
  return {
    seq: last ? String(last.seq) : null,
    hash: last?.hash ?? null,
    occurredAt: last ? last.createdAt.toISOString() : null,
    count: Number(total?.n ?? 0),
    anchor: await currentAnchor(db),
  };
}

const PAGE = 1000;
const DEFAULT_LIMIT = 1_000_000;

/**
 * rbac-audit.md §10.3: reads events in seq order, a page at a time, and stops at the first break.
 * The oldest event checked is compared with the event before it when one is stored (a range that
 * starts inside the chain), else with the anchor (§11.2) or the genesis (seq 1, 64 zeros).
 */
export async function verifyAuditChain(
  db: Executor,
  range: { fromSeq?: number; toSeq?: number; limit?: number } = {},
): Promise<AuditVerification> {
  const limit = range.limit ?? DEFAULT_LIMIT;
  let anchor: AuditAnchor | null;
  try {
    anchor = await currentAnchor(db);
  } catch (err) {
    if (!(err instanceof AuditAnchorMalformedError)) throw err;
    // Fail closed: a malformed anchor row is a break before the oldest stored event.
    const [oldest] = await db.select({ seq: min(auditEvents.seq) }).from(auditEvents);
    const seq = oldest?.seq;
    return {
      ok: false,
      checked: 0,
      firstSeq: null,
      lastSeq: null,
      anchor: null,
      break: {
        seq: seq === null || seq === undefined ? '0' : String(seq),
        reason: 'anchor_mismatch',
      },
    };
  }
  let expected: { seq: number; hash: string } | null = null;
  let checked = 0;
  let firstSeq: string | null = null;
  let lastSeq: string | null = null;
  const result = (brk: AuditVerification['break']): AuditVerification => ({
    ok: brk === null,
    checked,
    firstSeq,
    lastSeq,
    anchor,
    break: brk,
  });
  const fail = (seq: number, reason: AuditBreakReason) => result({ seq: String(seq), reason });

  if (range.fromSeq !== undefined) {
    const [before] = await db
      .select({ seq: auditEvents.seq, hash: auditEvents.hash })
      .from(auditEvents)
      .where(lt(auditEvents.seq, range.fromSeq))
      .orderBy(desc(auditEvents.seq))
      .limit(1);
    if (before) expected = { seq: before.seq + 1, hash: before.hash };
  }
  let after = (range.fromSeq ?? 1) - 1;
  for (;;) {
    const rows = await db
      .select()
      .from(auditEvents)
      .where(
        and(
          gt(auditEvents.seq, after),
          range.toSeq === undefined ? undefined : lte(auditEvents.seq, range.toSeq),
        ),
      )
      .orderBy(asc(auditEvents.seq))
      .limit(PAGE);
    for (const row of rows) {
      if (expected === null) {
        const start = anchor
          ? { seq: Number(anchor.throughSeq), hash: anchor.throughHash }
          : { seq: 0, hash: GENESIS_HASH };
        if (row.seq !== start.seq + 1 || row.prevHash !== start.hash) {
          return fail(row.seq, 'anchor_mismatch');
        }
      } else {
        if (row.seq !== expected.seq) return fail(row.seq, 'gap');
        if (row.prevHash !== expected.hash) return fail(row.seq, 'prev_mismatch');
      }
      if (eventHash(row.prevHash, recordOf(row)) !== row.hash)
        return fail(row.seq, 'hash_mismatch');
      checked += 1;
      firstSeq ??= String(row.seq);
      lastSeq = String(row.seq);
      expected = { seq: row.seq + 1, hash: row.hash };
      if (checked >= limit) return result(null);
    }
    const last = rows.at(-1);
    if (rows.length < PAGE || !last) break;
    after = last.seq;
  }
  return result(null);
}
