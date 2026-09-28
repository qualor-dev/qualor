import { and, asc, desc, eq, gt, gte, inArray, lt, or, sql, type SQL } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { auditEvents } from '../db/schema';
import { validationFailed } from '../http/problem';
import { exportRecordOf, type AuditEventRecord } from './chain';

/** rbac-audit.md §13: the filters of the read API and the export. Every one is optional. */
export interface AuditFilter {
  /** Inclusive. */
  from?: Date;
  /** Exclusive. */
  to?: Date;
  /** Exact names, or prefixes ending in `.*`. */
  actions?: string[];
  outcome?: 'success' | 'failure';
  actorUserId?: string;
  organizationId?: string;
  projectId?: string;
  targetType?: string;
  targetId?: string;
  /** Instance admins see instance-level events; an organisation's view excludes them. */
  instanceLevel?: 'include' | 'exclude';
}

/** rbac-audit.md §12: an export covers at most this many days. */
export const MAX_EXPORT_DAYS = 366;
const DAY_MS = 86_400_000;

/** rbac-audit.md §13: `limit` is at most 500. */
export const MAX_QUERY_LIMIT = 500;

export function encodeSeqCursor(seq: number): string {
  return Buffer.from(String(seq), 'utf8').toString('base64url');
}

/** The seq a page continues below; 422 on `query.cursor` for anything but a plain integer. */
export function decodeSeqCursor(cursor: string | undefined): number | undefined {
  if (cursor === undefined) return undefined;
  const text = Buffer.from(cursor, 'base64url').toString('utf8');
  // Round-trip too: base64url decoding ignores stray characters, so only the canonical form counts.
  if (!/^\d{1,15}$/.test(text) || encodeSeqCursor(Number(text)) !== cursor) {
    throw validationFailed([{ path: 'query.cursor', message: 'Invalid cursor' }]);
  }
  return Number(text);
}

/**
 * The WHERE conditions of a filter. Every value is a bound parameter; no SQL text is built from
 * input. A prefix uses `starts_with`, not LIKE: action names contain `_`, a LIKE wildcard.
 */
function conditions(filter: AuditFilter): SQL[] {
  const where: SQL[] = [];
  if (filter.from) where.push(gte(auditEvents.createdAt, filter.from));
  if (filter.to) where.push(lt(auditEvents.createdAt, filter.to));
  if (filter.actions?.length) {
    const exact = filter.actions.filter((a) => !a.endsWith('.*'));
    const prefixes = filter.actions.filter((a) => a.endsWith('.*')).map((a) => a.slice(0, -1));
    const any: SQL[] = [];
    if (exact.length) any.push(inArray(auditEvents.action, exact));
    for (const p of prefixes) any.push(sql`starts_with(${auditEvents.action}, ${p})`);
    const either = or(...any);
    if (either) where.push(either);
  }
  if (filter.outcome) where.push(eq(auditEvents.outcome, filter.outcome));
  if (filter.actorUserId) where.push(eq(auditEvents.actorUserId, filter.actorUserId));
  if (filter.organizationId) where.push(eq(auditEvents.organizationId, filter.organizationId));
  if (filter.projectId) where.push(eq(auditEvents.projectId, filter.projectId));
  if (filter.targetType) where.push(eq(auditEvents.targetType, filter.targetType));
  if (filter.targetId) where.push(eq(auditEvents.targetId, filter.targetId));
  if (filter.instanceLevel === 'exclude') {
    where.push(sql`${auditEvents.organizationId} IS NOT NULL`);
  }
  return where;
}

/**
 * rbac-audit.md §13: newest first. The cursor is the last seq returned, so rows appended between
 * two pages (always a higher seq) never shift a later page.
 */
export async function queryAuditEvents(
  db: Executor,
  filter: AuditFilter,
  page: { limit: number; cursor?: string },
): Promise<{ items: AuditEventRecord[]; nextCursor: string | null }> {
  if (!Number.isInteger(page.limit) || page.limit < 1 || page.limit > MAX_QUERY_LIMIT) {
    throw validationFailed([{ path: 'query.limit', message: `Use 1 to ${MAX_QUERY_LIMIT}` }]);
  }
  const before = decodeSeqCursor(page.cursor);
  const rows = await db
    .select()
    .from(auditEvents)
    .where(
      and(...conditions(filter), before === undefined ? undefined : lt(auditEvents.seq, before)),
    )
    .orderBy(desc(auditEvents.seq))
    .limit(page.limit + 1);
  const items = rows.slice(0, page.limit);
  const last = items.at(-1);
  return {
    items: items.map(exportRecordOf),
    nextCursor: rows.length > page.limit && last ? encodeSeqCursor(last.seq) : null,
  };
}

const EXPORT_PAGE = 1000;

/**
 * rbac-audit.md §12: the events of a period (`from` inclusive, `to` exclusive, at most 366 days;
 * 422 on `query.to` otherwise), oldest first, one JSON text per event without a newline. Read in
 * keyset pages of {@link EXPORT_PAGE}, one page only when the consumer asks for more, so an
 * export is never held in memory. Recording `audit.exported` before the first line is the
 * route's job (it knows the actor).
 */
export async function* exportAuditLines(
  db: Executor,
  filter: AuditFilter & { from: Date; to: Date },
): AsyncIterable<string> {
  const span = filter.to.getTime() - filter.from.getTime();
  if (!(span > 0) || span > MAX_EXPORT_DAYS * DAY_MS) {
    throw validationFailed([
      {
        path: 'query.to',
        message: `to must be after from, at most ${MAX_EXPORT_DAYS} days later`,
      },
    ]);
  }
  let after = 0;
  for (;;) {
    const rows = await db
      .select()
      .from(auditEvents)
      .where(and(...conditions(filter), gt(auditEvents.seq, after)))
      .orderBy(asc(auditEvents.seq))
      .limit(EXPORT_PAGE);
    for (const row of rows) yield JSON.stringify(exportRecordOf(row));
    const last = rows.at(-1);
    if (rows.length < EXPORT_PAGE || !last) return;
    after = last.seq;
  }
}
