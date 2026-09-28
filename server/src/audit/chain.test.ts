import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import type { AuditEventRow } from '../db/schema';
import { canonicalJson } from './canonical';
import { eventHash, exportRecordOf, GENESIS_HASH, recordOf, type AuditRecord } from './chain';

const record: AuditRecord = {
  v: 1,
  seq: '1',
  id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f',
  occurredAt: '2026-10-01T12:00:00.123Z',
  action: 'auth.sign_in',
  outcome: 'success',
  actor: {
    type: 'user',
    userId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60',
    username: 'alice',
    tokenId: null,
  },
  organization: null,
  project: null,
  target: { type: 'user', id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60', label: 'alice' },
  ip: '10.0.0.5',
  userAgent: null,
  details: { method: 'password' },
};

/*
 * Golden vectors, computed independently (Python: json.dumps(sort_keys=True,
 * separators=(',', ':'), ensure_ascii=False), then SHA-256 over the prefixed UTF-8 text). A change
 * to canonical JSON or to the hash input breaks every chain already stored, so these never move.
 */
const GOLDEN_1_CANONICAL =
  '{"action":"auth.sign_in","actor":{"tokenId":null,"type":"user","userId":"0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60","username":"alice"},"details":{"method":"password"},"id":"0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f","ip":"10.0.0.5","occurredAt":"2026-10-01T12:00:00.123Z","organization":null,"outcome":"success","project":null,"seq":"1","target":{"id":"0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60","label":"alice","type":"user"},"userAgent":null,"v":1}';
const GOLDEN_1_HASH = 'addf901674166344521322d601ca006215936dc6f7b19fcc2e3fe85fd24a2041';

const second: AuditRecord = {
  ...record,
  seq: '2',
  id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e61',
  action: 'member.role_changed',
  organization: { id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e62', key: 'acme' },
  target: {
    type: 'user',
    id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e63',
    label: `Zo${String.fromCharCode(0xeb)} ${String.fromCharCode(0xe9)}`,
  },
  userAgent: `Mozilla/5.0 ${String.fromCharCode(0x2014)} test`,
  details: { from: 'member', to: 'viewer' },
};
const GOLDEN_2_HASH = '817818eafe717945502c927603314ef3a15e906068ba716643dbd81bb8b52a00';

describe('the chain hash (rbac-audit.md §10.1)', () => {
  it('is SHA-256 over the prefix, the previous hash and the canonical record', () => {
    const expected = createHash('sha256')
      .update(`qualor-audit-v1\n${GENESIS_HASH}\n${canonicalJson(record as never)}`, 'utf8')
      .digest('hex');
    expect(eventHash(GENESIS_HASH, record)).toBe(expected);
    expect(GENESIS_HASH).toBe('0'.repeat(64));
  });

  it('matches the golden vectors (genesis event, then a non-ASCII successor)', () => {
    expect(canonicalJson(record as never)).toBe(GOLDEN_1_CANONICAL);
    expect(eventHash(GENESIS_HASH, record)).toBe(GOLDEN_1_HASH);
    expect(eventHash(GOLDEN_1_HASH, second)).toBe(GOLDEN_2_HASH);
  });

  it('changes with any field and with the previous hash', () => {
    const base = eventHash(GENESIS_HASH, record);
    expect(eventHash(GENESIS_HASH, { ...record, action: 'auth.sign_out' })).not.toBe(base);
    expect(eventHash(GENESIS_HASH, { ...record, seq: '2' })).not.toBe(base);
    expect(eventHash(GENESIS_HASH, { ...record, ip: null })).not.toBe(base);
    expect(eventHash(GENESIS_HASH, { ...record, details: { method: 'passworD' } })).not.toBe(base);
    expect(eventHash('f'.repeat(64), record)).not.toBe(base);
  });
});

describe('recordOf (rbac-audit.md §10.1)', () => {
  const row: AuditEventRow = {
    id: second.id,
    seq: 2,
    createdAt: new Date('2026-10-01T12:00:00.123Z'),
    action: 'member.role_changed',
    outcome: 'success',
    actorType: 'user',
    actorUserId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60',
    actorUsername: 'alice',
    actorTokenId: null,
    organizationId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e62',
    organizationKey: 'acme',
    projectId: null,
    projectKey: null,
    targetType: 'user',
    targetId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e63',
    targetLabel: second.target?.label ?? null,
    ip: '10.0.0.5',
    userAgent: second.userAgent,
    details: { to: 'viewer', from: 'member' },
    prevHash: GOLDEN_1_HASH,
    hash: GOLDEN_2_HASH,
  };

  it('rebuilds the hashed record from a stored row, with nulls and never missing keys', () => {
    expect(recordOf(row)).toEqual(second);
    expect(eventHash(row.prevHash, recordOf(row))).toBe(row.hash);
    expect(
      recordOf({ ...row, organizationId: null, organizationKey: null, targetType: null }),
    ).toMatchObject({
      organization: null,
      target: null,
    });
  });

  it('adds prevHash and hash for an export line', () => {
    expect(exportRecordOf(row)).toEqual({
      ...second,
      prevHash: GOLDEN_1_HASH,
      hash: GOLDEN_2_HASH,
    });
  });
});
