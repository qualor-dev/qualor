import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { createDatabase, type Executor } from '../db/client';
import { auditEvents } from '../db/schema';
import { eventHash, recordOf } from './chain';
import {
  appendEvents,
  createAuditRecorder,
  SYSTEM_ACTOR,
  type AuditActorContext,
} from './recorder';
import { AuditAnchorMalformedError } from './settings';
import { auditHead, verifyAuditChain } from './verify';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';

const alice: AuditActorContext = {
  actor: {
    type: 'user',
    userId: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e60',
    username: 'alice',
    tokenId: null,
  },
  ip: '10.0.0.5',
  userAgent: 'test',
};
const signOut = { action: 'auth.sign_out' as const, details: {} };

/** Runs `statements` with the immutability trigger off, as a test (or an attacker with DDL) can. */
async function tamper(db: Executor, ...statements: ReturnType<typeof sql>[]): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.execute(sql`ALTER TABLE audit_events DISABLE TRIGGER audit_events_guard`);
    for (const statement of statements) await tx.execute(statement);
    await tx.execute(sql`ALTER TABLE audit_events ENABLE ALWAYS TRIGGER audit_events_guard`);
  });
}

/** Deletes the prefix through `seq` as retention does (§11.1), without recording an anchor. */
async function prunePrefix(db: Executor, seq: number): Promise<void> {
  await db.transaction(async (tx) => {
    await tx.execute(sql`SELECT set_config('qualor.audit_prune', txid_current()::text, true)`);
    await tx.execute(sql`DELETE FROM audit_events WHERE seq <= ${seq}`);
  });
}

async function hashOf(db: Executor, seq: number): Promise<string> {
  const [row] = await db
    .select({ hash: auditEvents.hash })
    .from(auditEvents)
    .where(eq(auditEvents.seq, seq));
  return row!.hash;
}

async function writeAnchorRow(
  db: Executor,
  throughSeq: string,
  throughHash: string,
): Promise<void> {
  await db.execute(sql`
    INSERT INTO instance_settings (key, value)
    VALUES ('audit-chain', ${JSON.stringify({ throughSeq, throughHash, prunedAt: '2026-01-01T00:00:00.000Z' })}::jsonb)
    ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`);
}

describe('the audit chain (rbac-audit.md §9–§10)', () => {
  let database: TestDatabase;
  beforeAll(async () => {
    database = await createTestDatabase();
  });
  afterAll(async () => database.close());
  beforeEach(async () => {
    await prunePrefix(database.db, Number.MAX_SAFE_INTEGER);
    await database.db.execute(sql`DELETE FROM instance_settings WHERE key = 'audit-chain'`);
  });

  it('writes nothing while the feature is inactive', async () => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => false });
    expect(recorder.active()).toBe(false);
    await recorder.record(database.db, alice, [signOut]);
    expect((await auditHead(database.db)).count).toBe(0);
  });

  it('chains events from the genesis and verifies them', async () => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    await recorder.record(database.db, alice, [signOut, signOut]);
    await recorder.record(database.db, SYSTEM_ACTOR, [
      {
        action: 'audit.pruned',
        details: {
          throughSeq: '0',
          throughHash: '0'.repeat(64),
          deleted: 0,
          cutoff: '2026-01-01T00:00:00.000Z',
        },
      },
    ]);
    const head = await auditHead(database.db);
    expect(head).toMatchObject({ seq: '3', count: 3, anchor: null });
    expect(head.hash).toBe(await hashOf(database.db, 3));
    expect(await verifyAuditChain(database.db)).toEqual({
      ok: true,
      checked: 3,
      firstSeq: '1',
      lastSeq: '3',
      anchor: null,
      break: null,
    });
  });

  it('stores the record it hashed: actor, context, target and the recorder clock', async () => {
    const at = new Date('2026-10-01T12:00:00.123Z');
    const recorder = createAuditRecorder({
      log: QUIET_AUDIT_LOG,
      isActive: () => true,
      now: () => at,
    });
    await recorder.record(database.db, alice, [
      {
        action: 'member.role_changed',
        organization: { id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e62', key: 'acme' },
        target: { type: 'user', id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e63', label: 'bob' },
        details: { from: 'member', to: 'viewer' },
      },
    ]);
    const [row] = await database.db.select().from(auditEvents);
    expect(recordOf(row!)).toMatchObject({
      seq: '1',
      occurredAt: '2026-10-01T12:00:00.123Z',
      action: 'member.role_changed',
      outcome: 'success',
      actor: alice.actor,
      organization: { id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e62', key: 'acme' },
      project: null,
      target: { type: 'user', id: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e63', label: 'bob' },
      ip: '10.0.0.5',
      userAgent: 'test',
      details: { from: 'member', to: 'viewer' },
    });
    expect(row!.prevHash).toBe('0'.repeat(64));
    expect(eventHash(row!.prevHash, recordOf(row!))).toBe(row!.hash);
  });

  it('clips and cleans the user agent and the target label so the stored record still hashes', async () => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    const odd = `a${String.fromCharCode(0)}b${String.fromCharCode(0xd800)}c`;
    await recorder.record(database.db, { ...alice, userAgent: `${odd}${'x'.repeat(400)}` }, [
      { ...signOut, target: { type: 'user', id: alice.actor.type, label: 'y'.repeat(300) } },
    ]);
    const [row] = await database.db.select().from(auditEvents);
    const replacement = String.fromCharCode(0xfffd);
    expect(row!.userAgent).toBe(`a${replacement}b${replacement}c${'x'.repeat(251)}`);
    expect(row!.targetLabel).toBe('y'.repeat(255));
    expect((await verifyAuditChain(database.db)).ok).toBe(true);
  });

  it('refuses an action outside the catalogue and details outside its schema, writing nothing', async () => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    await expect(
      recorder.record(database.db, alice, [{ action: 'auth.nope' as never, details: {} }]),
    ).rejects.toThrow();
    await expect(
      recorder.record(database.db, alice, [{ action: 'toString' as never, details: {} }]),
    ).rejects.toThrow();
    await expect(
      recorder.record(database.db, alice, [
        signOut,
        { action: 'auth.sign_in', details: { method: 'password', password: 'x' } as never },
      ]),
    ).rejects.toThrow();
    await expect(
      recorder.record(database.db, alice, [
        {
          action: 'organization.created',
          details: { key: 'k', name: `a${String.fromCharCode(0)}` },
        },
      ]),
    ).rejects.toThrow();
    expect((await auditHead(database.db)).count).toBe(0);
  });

  it('does nothing for an empty list', async () => {
    await createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true }).record(
      database.db,
      alice,
      [],
    );
    expect((await auditHead(database.db)).count).toBe(0);
  });

  it('concurrent recorders produce consecutive seqs and a chain that verifies', async () => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    await Promise.all(
      Array.from({ length: 20 }, () =>
        database.db.transaction(async (tx) => {
          await tx.execute(sql`SELECT pg_sleep(0.01)`);
          await recorder.record(tx, alice, [signOut]);
        }),
      ),
    );
    const seqs = await database.db.execute<{ seq: string }>(
      sql`SELECT seq::text FROM audit_events ORDER BY audit_events.seq`,
    );
    expect(seqs.rows.map((r) => Number(r.seq))).toEqual(
      Array.from({ length: 20 }, (_, i) => i + 1),
    );
    expect((await verifyAuditChain(database.db)).ok).toBe(true);
  });

  it('holds the chain lock until commit, across two replicas (two pools)', async () => {
    const replica = createDatabase(database.url, { max: 5 });
    try {
      const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
      // Each transaction records, then keeps working before it commits: a lock released before
      // commit would let the next writer read a stale head and reuse a seq (the unique key fails).
      const run = (db: Executor, i: number) =>
        db.transaction(async (tx) => {
          await recorder.record(tx, alice, [signOut, signOut]);
          await tx.execute(sql`SELECT pg_sleep(${(i % 3) * 0.01})`);
        });
      await Promise.all(
        Array.from({ length: 16 }, (_, i) => run(i % 2 === 0 ? database.db : replica.db, i)),
      );
    } finally {
      await replica.close();
    }
    const head = await auditHead(database.db);
    expect(head).toMatchObject({ seq: '32', count: 32 });
    expect(await verifyAuditChain(database.db)).toMatchObject({ ok: true, checked: 32 });
  });

  it('rolls the events back with the transaction they were recorded in', async () => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    await expect(
      database.db.transaction(async (tx) => {
        await recorder.record(tx, alice, [signOut]);
        throw new Error('the change failed');
      }),
    ).rejects.toThrow('the change failed');
    expect((await auditHead(database.db)).count).toBe(0);
    await recorder.record(database.db, alice, [signOut]);
    expect((await auditHead(database.db)).seq).toBe('1');
  });

  it.each([
    [
      'a changed field',
      [sql`UPDATE audit_events SET action = 'auth.sign_in' WHERE seq = 2`],
      'hash_mismatch',
      '2',
    ],
    ['a deleted middle event', [sql`DELETE FROM audit_events WHERE seq = 2`], 'gap', '3'],
    [
      'a reordered seq (two events swapped)',
      [
        sql`UPDATE audit_events SET seq = 1000 WHERE seq = 2`,
        sql`UPDATE audit_events SET seq = 2 WHERE seq = 3`,
        sql`UPDATE audit_events SET seq = 3 WHERE seq = 1000`,
      ],
      'prev_mismatch',
      '2',
    ],
    [
      'a changed prev_hash',
      [sql`UPDATE audit_events SET prev_hash = ${'c'.repeat(64)} WHERE seq = 3`],
      'prev_mismatch',
      '3',
    ],
  ])('reports %s with its seq and reason', async (_what, statements, reason, seq) => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    await recorder.record(database.db, alice, [signOut, signOut, signOut, signOut]);
    await tamper(database.db, ...statements);
    expect(await verifyAuditChain(database.db)).toMatchObject({
      ok: false,
      break: { seq, reason },
    });
  });

  it('reports a rewritten event whose own hash was recomputed at its successor', async () => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    await recorder.record(database.db, alice, [signOut, signOut, signOut]);
    const [row] = await database.db.select().from(auditEvents).where(eq(auditEvents.seq, 2));
    const forged = eventHash(row!.prevHash, { ...recordOf(row!), action: 'auth.sign_in' });
    await tamper(
      database.db,
      sql`UPDATE audit_events SET action = 'auth.sign_in', hash = ${forged} WHERE seq = 2`,
    );
    expect(await verifyAuditChain(database.db)).toMatchObject({
      ok: false,
      checked: 2,
      lastSeq: '2',
      break: { seq: '3', reason: 'prev_mismatch' },
    });
  });

  it('verifies a range against its stored predecessor, and honours toSeq and limit', async () => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    await recorder.record(database.db, alice, [signOut, signOut, signOut, signOut, signOut]);
    expect(await verifyAuditChain(database.db, { fromSeq: 3 })).toMatchObject({
      ok: true,
      checked: 3,
      firstSeq: '3',
      lastSeq: '5',
    });
    expect(await verifyAuditChain(database.db, { fromSeq: 2, toSeq: 3 })).toMatchObject({
      ok: true,
      checked: 2,
      firstSeq: '2',
      lastSeq: '3',
    });
    expect(await verifyAuditChain(database.db, { limit: 2 })).toMatchObject({
      ok: true,
      checked: 2,
      lastSeq: '2',
    });
    await tamper(
      database.db,
      sql`UPDATE audit_events SET prev_hash = ${'d'.repeat(64)} WHERE seq = 3`,
    );
    expect(await verifyAuditChain(database.db, { fromSeq: 3 })).toMatchObject({
      ok: false,
      break: { seq: '3', reason: 'prev_mismatch' },
    });
    await tamper(database.db, sql`DELETE FROM audit_events WHERE seq = 4`);
    expect(await verifyAuditChain(database.db, { fromSeq: 4 })).toMatchObject({
      ok: false,
      break: { seq: '5', reason: 'gap' },
    });
  });

  it('pages through more than 1 000 events', async () => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    await recorder.record(
      database.db,
      SYSTEM_ACTOR,
      Array.from({ length: 2100 }, () => signOut),
    );
    expect(await verifyAuditChain(database.db)).toMatchObject({
      ok: true,
      checked: 2100,
      lastSeq: '2100',
    });
    await tamper(database.db, sql`UPDATE audit_events SET outcome = 'failure' WHERE seq = 1500`);
    expect(await verifyAuditChain(database.db)).toMatchObject({
      ok: false,
      break: { seq: '1500', reason: 'hash_mismatch' },
    });
  });

  it('writes more events than one statement can hold (3 300), in one transaction (§10.2 step 3)', async () => {
    // 21 parameters a row: one INSERT of 3 300 rows would pass PostgreSQL's 65 535 (a 500).
    await database.db.transaction(async (tx) => {
      await appendEvents(
        tx,
        alice,
        Array.from({ length: 3300 }, () => signOut),
        new Date(),
      );
      await appendEvents(tx, alice, [signOut], new Date());
    });
    expect(await verifyAuditChain(database.db)).toMatchObject({
      ok: true,
      checked: 3301,
      lastSeq: '3301',
    });
    // All or nothing: a failure after the chunks rolls every one of them back.
    await expect(
      database.db.transaction(async (tx) => {
        await appendEvents(
          tx,
          alice,
          Array.from({ length: 2500 }, () => signOut),
          new Date(),
        );
        throw new Error('the change failed after its events');
      }),
    ).rejects.toThrow('the change failed');
    expect((await auditHead(database.db)).count).toBe(3301);
  });

  it('continues from the anchor row when the table is empty', async () => {
    await writeAnchorRow(database.db, '41', 'a'.repeat(64));
    await appendEvents(database.db, alice, [signOut], new Date());
    const [row] = (
      await database.db.execute<{ seq: string; prev_hash: string }>(
        sql`SELECT seq::text, prev_hash FROM audit_events`,
      )
    ).rows;
    expect(row).toEqual({ seq: '42', prev_hash: 'a'.repeat(64) });
    expect(await verifyAuditChain(database.db)).toMatchObject({
      ok: true,
      checked: 1,
      anchor: { throughSeq: '41', throughHash: 'a'.repeat(64) },
    });
  });

  describe('the anchor (§11.2)', () => {
    const recorder = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });

    async function writeRawAnchor(value: unknown): Promise<void> {
      await database.db.execute(sql`
        INSERT INTO instance_settings (key, value) VALUES ('audit-chain', ${JSON.stringify(value)}::jsonb)
        ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value`);
    }

    it.each([
      ['a wrong shape', { throughSeq: 41 }],
      ['a short hash', { throughSeq: '41', throughHash: 'a'.repeat(63) }],
      [
        'a seq above MAX_SAFE_INTEGER',
        { throughSeq: '9007199254740993', throughHash: 'a'.repeat(64) },
      ],
    ])(
      'refuses to record on an empty table over a malformed anchor row (%s), rolling the change back',
      async (_what, value) => {
        await writeRawAnchor(value);
        await expect(
          database.db.transaction(async (tx) => {
            await tx.execute(
              sql`INSERT INTO instance_settings (key, value) VALUES ('t7-change', '{}'::jsonb)`,
            );
            await recorder.record(tx, alice, [signOut]);
          }),
        ).rejects.toThrow(AuditAnchorMalformedError);
        expect(await database.db.$count(auditEvents)).toBe(0);
        const change = await database.db.execute(
          sql`SELECT 1 FROM instance_settings WHERE key = 't7-change'`,
        );
        expect(change.rows).toEqual([]);
      },
    );

    it('fails verification closed over a malformed anchor row: at the oldest seq, or 0', async () => {
      await writeRawAnchor({ throughSeq: 'x', throughHash: 'a'.repeat(64) });
      expect(await verifyAuditChain(database.db)).toEqual({
        ok: false,
        checked: 0,
        firstSeq: null,
        lastSeq: null,
        anchor: null,
        break: { seq: '0', reason: 'anchor_mismatch' },
      });
      await database.db.execute(sql`DELETE FROM instance_settings WHERE key = 'audit-chain'`);
      await recorder.record(database.db, alice, [signOut, signOut, signOut]);
      await prunePrefix(database.db, 1);
      await writeRawAnchor({ throughSeq: '1' });
      expect(await verifyAuditChain(database.db)).toMatchObject({
        ok: false,
        checked: 0,
        anchor: null,
        break: { seq: '2', reason: 'anchor_mismatch' },
      });
    });

    it('verifies a pruned chain against the anchor row, and reports a forged hash or seq', async () => {
      await recorder.record(database.db, alice, [signOut, signOut, signOut, signOut]);
      const through = await hashOf(database.db, 2);
      await prunePrefix(database.db, 2);
      await writeAnchorRow(database.db, '2', through);
      expect(await verifyAuditChain(database.db)).toMatchObject({ ok: true, firstSeq: '3' });

      await writeAnchorRow(database.db, '2', 'b'.repeat(64));
      expect(await verifyAuditChain(database.db)).toMatchObject({
        ok: false,
        anchor: { throughSeq: '2', throughHash: 'b'.repeat(64) },
        break: { seq: '3', reason: 'anchor_mismatch' },
      });

      await writeAnchorRow(database.db, '1', through);
      expect(await verifyAuditChain(database.db)).toMatchObject({
        ok: false,
        break: { seq: '3', reason: 'anchor_mismatch' },
      });
    });

    it('reports a prefix deleted without an anchor', async () => {
      await recorder.record(database.db, alice, [signOut, signOut, signOut]);
      await prunePrefix(database.db, 1);
      expect(await verifyAuditChain(database.db)).toMatchObject({
        ok: false,
        anchor: null,
        break: { seq: '2', reason: 'anchor_mismatch' },
      });
    });

    it('takes the anchor from the newest audit.pruned event, and reports it forged', async () => {
      await recorder.record(database.db, alice, [signOut, signOut, signOut]);
      const through = await hashOf(database.db, 2);
      await database.db.transaction(async (tx) => {
        await tx.execute(sql`SELECT set_config('qualor.audit_prune', txid_current()::text, true)`);
        await tx.execute(sql`DELETE FROM audit_events WHERE seq <= 2`);
        await recorder.record(tx, SYSTEM_ACTOR, [
          {
            action: 'audit.pruned',
            details: {
              throughSeq: '2',
              throughHash: through,
              deleted: 2,
              cutoff: '2026-01-01T00:00:00.000Z',
            },
          },
        ]);
      });
      // The row is stale on purpose: the event wins while it is in the table.
      await writeAnchorRow(database.db, '0', '0'.repeat(64));
      expect(await verifyAuditChain(database.db)).toMatchObject({
        ok: true,
        checked: 2,
        firstSeq: '3',
        lastSeq: '4',
        anchor: { throughSeq: '2', throughHash: through },
      });
      expect((await auditHead(database.db)).anchor).toEqual({
        throughSeq: '2',
        throughHash: through,
      });

      await tamper(
        database.db,
        sql`UPDATE audit_events SET details = jsonb_set(details, '{throughHash}', ${JSON.stringify('e'.repeat(64))}::jsonb) WHERE seq = 4`,
      );
      expect(await verifyAuditChain(database.db)).toMatchObject({
        ok: false,
        break: { seq: '3', reason: 'anchor_mismatch' },
      });
    });
  });
});
