import { createHash } from 'node:crypto';
import type { AuditEventRow } from '../db/schema';
import { canonicalJson, type AuditJson } from './canonical';

/** rbac-audit.md §10.1: the `prev_hash` of the first event (`seq` 1). */
export const GENESIS_HASH = '0'.repeat(64);
const PREFIX = 'qualor-audit-v1';

/** rbac-audit.md §10.1: what is hashed, exported and streamed. Absent values are null. */
export interface AuditRecord {
  v: 1;
  seq: string;
  id: string;
  occurredAt: string;
  action: string;
  outcome: 'success' | 'failure';
  actor:
    | { type: 'user'; userId: string | null; username: string | null; tokenId: string | null }
    | { type: 'anonymous'; userId: string | null; username: string | null; tokenId: null }
    | { type: 'system'; userId: null; username: null; tokenId: null };
  organization: { id: string; key: string | null } | null;
  project: { id: string; key: string | null } | null;
  target: { type: string; id: string | null; label: string | null } | null;
  ip: string | null;
  userAgent: string | null;
  details: Record<string, AuditJson>;
}

/** An export line or a streamed event: the record with its place in the chain. */
export interface AuditEventRecord extends AuditRecord {
  prevHash: string;
  hash: string;
}

/** lowercase hex SHA-256( UTF-8( "qualor-audit-v1\n" + prevHash + "\n" + canonical(record) ) ). */
export function eventHash(prevHash: string, record: AuditRecord): string {
  return createHash('sha256')
    .update(`${PREFIX}\n${prevHash}\n${canonicalJson(record as unknown as AuditJson)}`, 'utf8')
    .digest('hex');
}

/** The record of a stored row, exactly as it was hashed when the row was appended. */
export function recordOf(row: AuditEventRow): AuditRecord {
  return {
    v: 1,
    seq: String(row.seq),
    id: row.id,
    occurredAt: row.createdAt.toISOString(),
    action: row.action,
    outcome: row.outcome,
    actor: {
      type: row.actorType,
      userId: row.actorUserId,
      username: row.actorUsername,
      tokenId: row.actorTokenId,
    } as AuditRecord['actor'],
    organization: row.organizationId ? { id: row.organizationId, key: row.organizationKey } : null,
    project: row.projectId ? { id: row.projectId, key: row.projectKey } : null,
    target: row.targetType
      ? { type: row.targetType, id: row.targetId, label: row.targetLabel }
      : null,
    ip: row.ip,
    userAgent: row.userAgent,
    details: row.details as Record<string, AuditJson>,
  };
}

export function exportRecordOf(row: AuditEventRow): AuditEventRecord {
  return { ...recordOf(row), prevHash: row.prevHash, hash: row.hash };
}
