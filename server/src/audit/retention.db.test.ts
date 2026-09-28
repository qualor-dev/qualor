import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { appendEvents, type AuditActorContext } from './recorder';
import { AUDIT_PRUNE_BATCH, pruneAuditEvents } from './retention';
import { MALFORMED_ANCHOR } from './settings';
import { auditHead, verifyAuditChain } from './verify';

const DAY = 24 * 60 * 60 * 1000;
const alice: AuditActorContext = {
  actor: {
    type: 'user',
    userId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60',
    username: 'alice',
    tokenId: null,
  },
  ip: null,
  userAgent: null,
};
const now = new Date('2027-06-01T00:00:00Z');
const at = (daysAgo: number) => new Date(now.getTime() - daysAgo * DAY);
const signOut = { action: 'auth.sign_out' as const, details: {} };

describe('audit retention and its anchor (rbac-audit.md §11)', () => {
  let database: TestDatabase;
  beforeAll(async () => {
    database = await createTestDatabase();
  });
  afterAll(async () => database.close());
  beforeEach(async () => {
    await database.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT set_config('qualor.audit_prune', txid_current()::text, true)`);
      await tx.execute(sql`DELETE FROM audit_events`);
    });
    await database.db.execute(sql`DELETE FROM instance_settings WHERE key = 'audit-chain'`);
  });

  const anchorRow = async () =>
    (
      await database.db.execute<{ value: unknown }>(
        sql`SELECT value FROM instance_settings WHERE key = 'audit-chain'`,
      )
    ).rows[0]?.value;

  it('deletes exactly the old prefix, anchors it, and the chain still verifies', async () => {
    await appendEvents(database.db, alice, [signOut, signOut, signOut], at(400));
    await appendEvents(database.db, alice, [signOut, signOut], at(10));
    const deleted = await pruneAuditEvents(database.db, { retentionDays: 365, now });
    expect(deleted).toBe(3);
    const head = await auditHead(database.db);
    expect(head).toMatchObject({ count: 3, anchor: { throughSeq: '3' } });
    const verification = await verifyAuditChain(database.db);
    expect(verification).toMatchObject({ ok: true, firstSeq: '4', checked: 3 });
  });

  it('writes the anchor row and a system audit.pruned event in the chain', async () => {
    await appendEvents(database.db, alice, [signOut, signOut], at(400));
    const [through] = (
      await database.db.execute<{ hash: string }>(sql`SELECT hash FROM audit_events WHERE seq = 2`)
    ).rows;
    await pruneAuditEvents(database.db, { retentionDays: 365, now });
    expect(await anchorRow()).toEqual({
      throughSeq: '2',
      throughHash: through?.hash,
      prunedAt: now.toISOString(),
    });
    const events = await database.db.execute<{
      seq: string;
      action: string;
      actor_type: string;
      details: unknown;
    }>(sql`SELECT seq::text, action, actor_type, details FROM audit_events ORDER BY seq`);
    expect(events.rows).toEqual([
      {
        seq: '3',
        action: 'audit.pruned',
        actor_type: 'system',
        details: {
          throughSeq: '2',
          throughHash: through?.hash,
          deleted: 2,
          cutoff: at(365).toISOString(),
        },
      },
    ]);
    // Every event aged out later: the chain continues from the row (§10.2 step 2).
    await pruneAuditEvents(database.db, {
      retentionDays: 30,
      now: new Date(now.getTime() + 60 * DAY),
    });
    expect((await auditHead(database.db)).count).toBe(1);
    expect(await verifyAuditChain(database.db)).toMatchObject({ ok: true, firstSeq: '4' });
  });

  it('writes nothing when nothing is old enough', async () => {
    await appendEvents(database.db, alice, [signOut], at(10));
    expect(await pruneAuditEvents(database.db, { retentionDays: 365, now })).toBe(0);
    expect((await auditHead(database.db)).count).toBe(1);
    expect(await anchorRow()).toBeUndefined();
  });

  it('does nothing on an empty table (a server that was never licensed)', async () => {
    expect(await pruneAuditEvents(database.db, { retentionDays: 30, now })).toBe(0);
    expect((await auditHead(database.db)).count).toBe(0);
    expect(await anchorRow()).toBeUndefined();
  });

  it('keeps anchoring across runs: the newest anchor governs', async () => {
    await appendEvents(database.db, alice, [signOut, signOut], at(400));
    await pruneAuditEvents(database.db, { retentionDays: 365, now });
    await appendEvents(database.db, alice, [signOut], at(200));
    await pruneAuditEvents(database.db, { retentionDays: 100, now });
    expect(await verifyAuditChain(database.db)).toMatchObject({ ok: true });
  });

  it('reports a changed anchor', async () => {
    await appendEvents(database.db, alice, [signOut, signOut], at(400));
    await appendEvents(database.db, alice, [signOut], at(1));
    await pruneAuditEvents(database.db, { retentionDays: 365, now });
    await database.db.transaction(async (tx) => {
      await tx.execute(sql`ALTER TABLE audit_events DISABLE TRIGGER audit_events_guard`);
      await tx.execute(
        sql`UPDATE audit_events SET details = jsonb_set(details, '{throughHash}', ${JSON.stringify('b'.repeat(64))}::jsonb) WHERE action = 'audit.pruned'`,
      );
      await tx.execute(sql`ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_guard`);
    });
    expect((await verifyAuditChain(database.db)).ok).toBe(false);
  });

  it('prunes at most one batch per run', () => {
    expect(AUDIT_PRUNE_BATCH).toBe(50_000);
  });

  it('prunes a backlog in batches of 50 000, and the chain verifies after every run', async () => {
    const old = AUDIT_PRUNE_BATCH * 2 + 1;
    // 2 000 events per insert keeps each statement under PostgreSQL's 65 535 parameters.
    for (let done = 0; done < old; done += 2000) {
      const n = Math.min(2000, old - done);
      await appendEvents(database.db, alice, Array<typeof signOut>(n).fill(signOut), at(400));
    }
    await appendEvents(database.db, alice, [signOut, signOut], at(10));

    const runs: number[] = [];
    for (let run = 0; run < 4; run += 1) {
      runs.push(await pruneAuditEvents(database.db, { retentionDays: 365, now }));
      expect(await verifyAuditChain(database.db)).toMatchObject({ ok: true, break: null });
    }
    expect(runs).toEqual([AUDIT_PRUNE_BATCH, AUDIT_PRUNE_BATCH, 1, 0]);
    const head = await auditHead(database.db);
    // The two recent events and one audit.pruned per run that deleted something.
    expect(head).toMatchObject({ count: 5, anchor: { throughSeq: String(old) } });
    expect(await verifyAuditChain(database.db)).toMatchObject({
      ok: true,
      firstSeq: String(old + 1),
      checked: 5,
    });
  }, 300_000);

  it('serialises concurrent runs on two connections: each prefix is deleted once', async () => {
    await appendEvents(database.db, alice, [signOut, signOut, signOut], at(400));
    const results = await Promise.all([
      pruneAuditEvents(database.db, { retentionDays: 365, now }),
      pruneAuditEvents(database.db, { retentionDays: 365, now }),
    ]);
    expect(results.sort()).toEqual([0, 3]);
    expect(await verifyAuditChain(database.db)).toMatchObject({ ok: true, checked: 1 });
  });

  it('fails closed on a malformed anchor row: nothing is deleted or written', async () => {
    await appendEvents(database.db, alice, [signOut, signOut], at(400));
    await database.db.execute(sql`
      INSERT INTO instance_settings (key, value) VALUES ('audit-chain', '{"throughSeq":"x"}'::jsonb)`);
    await expect(pruneAuditEvents(database.db, { retentionDays: 365, now })).rejects.toThrow(
      MALFORMED_ANCHOR,
    );
    await expect(auditHead(database.db)).rejects.toThrow(MALFORMED_ANCHOR);
    const count = await database.db.execute<{ n: number }>(
      sql`SELECT count(*)::int AS n FROM audit_events`,
    );
    expect(count.rows).toEqual([{ n: 2 }]);
    expect(await anchorRow()).toEqual({ throughSeq: 'x' });
  });
});
