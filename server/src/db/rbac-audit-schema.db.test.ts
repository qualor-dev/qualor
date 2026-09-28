import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { uuidv7 } from './ids';

const ZEROS = '0'.repeat(64);

/**
 * drizzle-orm 0.45 wraps the driver's error in a `DrizzleQueryError` whose own `.message` is just
 * "Failed query: …"; the real PostgreSQL message (the constraint name, or the trigger's RAISE
 * EXCEPTION text) is on `.cause`. `.rejects.toThrow(regex)` only inspects the top-level `.message`,
 * so this walks the `cause` chain and matches the failure's own text instead.
 */
async function expectRejection(action: PromiseLike<unknown>, pattern: RegExp): Promise<void> {
  const error: unknown = await Promise.resolve(action).then(
    () => null,
    (err: unknown) => err,
  );
  expect(error, 'expected the query to be rejected').not.toBeNull();
  const messages: string[] = [];
  let current: unknown = error;
  for (let depth = 0; depth < 5 && typeof current === 'object' && current !== null; depth++) {
    const message = (current as { message?: unknown }).message;
    if (typeof message === 'string') messages.push(message);
    current = (current as { cause?: unknown }).cause;
  }
  expect(messages.join(' | ')).toMatch(pattern);
}

describe('migration 0005: roles, project grants, audit events (rbac-audit.md §7)', () => {
  let database: TestDatabase;
  let orgId: string;
  let userId: string;
  let projectId: string;

  beforeAll(async () => {
    database = await createTestDatabase();
    const db = database.db;
    orgId = uuidv7();
    userId = uuidv7();
    projectId = uuidv7();
    await db.execute(sql`INSERT INTO organizations (id, key, name) VALUES (${orgId}, 'o5', 'O5')`);
    await db.execute(sql`INSERT INTO users (id, username) VALUES (${userId}, 'u5')`);
    await db.execute(
      sql`INSERT INTO projects (id, organization_id, key, name) VALUES (${projectId}, ${orgId}, 'p5', 'P5')`,
    );
  });
  afterAll(async () => database.close());

  const insertEvent = (seq: number) =>
    database.db.execute(sql`
      INSERT INTO audit_events (id, seq, created_at, action, outcome, actor_type, prev_hash, hash)
      VALUES (${uuidv7()}, ${seq}, now(), 'auth.sign_in', 'success', 'user', ${ZEROS}, ${ZEROS})`);

  it.each(['admin', 'project_admin', 'member', 'viewer'])(
    'accepts the organisation role %s',
    async (role) => {
      await database.db.execute(sql`DELETE FROM memberships WHERE user_id = ${userId}`);
      await database.db.execute(
        sql`INSERT INTO memberships (organization_id, user_id, role) VALUES (${orgId}, ${userId}, ${role})`,
      );
    },
  );

  it('refuses an unknown organisation role', async () => {
    await database.db.execute(sql`DELETE FROM memberships WHERE user_id = ${userId}`);
    await expectRejection(
      database.db.execute(
        sql`INSERT INTO memberships (organization_id, user_id, role) VALUES (${orgId}, ${userId}, 'owner')`,
      ),
      /memberships_role_check/,
    );
  });

  it('keeps project grants to three roles and removes them with the project', async () => {
    await expectRejection(
      database.db.execute(
        sql`INSERT INTO project_memberships (project_id, user_id, role) VALUES (${projectId}, ${userId}, 'admin')`,
      ),
      /project_memberships_role_check/,
    );
    const other = uuidv7();
    await database.db.execute(
      sql`INSERT INTO projects (id, organization_id, key, name) VALUES (${other}, ${orgId}, 'p6', 'P6')`,
    );
    await database.db.execute(
      sql`INSERT INTO project_memberships (project_id, user_id, role) VALUES (${other}, ${userId}, 'viewer')`,
    );
    await database.db.execute(sql`DELETE FROM projects WHERE id = ${other}`);
    const left = await database.db.execute(
      sql`SELECT count(*)::int AS n FROM project_memberships WHERE project_id = ${other}`,
    );
    expect(left.rows[0]).toEqual({ n: 0 });
  });

  it('keeps seq unique', async () => {
    await insertEvent(1);
    await expectRejection(insertEvent(1), /audit_events_seq_key/);
  });

  it('refuses UPDATE, TRUNCATE, and DELETE outside retention', async () => {
    await insertEvent(2);
    await expectRejection(
      database.db.execute(sql`UPDATE audit_events SET action = 'auth.sign_out' WHERE seq = 2`),
      /immutable/,
    );
    await expectRejection(
      database.db.execute(sql`DELETE FROM audit_events WHERE seq = 2`),
      /immutable/,
    );
    await expectRejection(database.db.execute(sql`TRUNCATE audit_events`), /immutable/);
  });

  /** Rows left with `seq`, read outside any transaction. */
  const left = async (seq: number) =>
    (
      await database.db.execute<{ n: number }>(
        sql`SELECT count(*)::int AS n FROM audit_events WHERE seq = ${seq}`,
      )
    ).rows[0]!.n;

  it('allows DELETE only in a transaction whose own id is the prune flag (§7.3)', async () => {
    await insertEvent(3);
    await database.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT set_config('qualor.audit_prune', txid_current()::text, true)`);
      await tx.execute(sql`DELETE FROM audit_events WHERE seq = 3`);
    });
    expect(await left(3)).toBe(0);
    // The setting does not leak out of its transaction.
    await expectRejection(
      database.db.execute(sql`DELETE FROM audit_events WHERE seq = 2`),
      /immutable/,
    );
    // The old flag value 'on' allows nothing any more, not even with SET LOCAL.
    await expectRejection(
      database.db.transaction(async (tx) => {
        await tx.execute(sql`SET LOCAL qualor.audit_prune = 'on'`);
        await tx.execute(sql`DELETE FROM audit_events WHERE seq = 2`);
      }),
      /immutable/,
    );
    expect(await left(2)).toBe(1);
  });

  it('ignores a flag set for the session, or left from another transaction', async () => {
    const client = await database.pool.connect();
    try {
      await client.query("SET qualor.audit_prune = 'on'");
      await expectRejection(client.query('DELETE FROM audit_events WHERE seq = 2'), /immutable/);
      // A transaction's own id, kept in the session after it ended, never matches a later one.
      await client.query('BEGIN');
      const own = await client.query<{ id: string }>('SELECT txid_current()::text AS id');
      await client.query('SELECT set_config($1, $2, false)', [
        'qualor.audit_prune',
        own.rows[0]!.id,
      ]);
      await client.query('COMMIT');
      await expectRejection(client.query('DELETE FROM audit_events WHERE seq = 2'), /immutable/);
      await client.query('BEGIN');
      await expectRejection(client.query('DELETE FROM audit_events WHERE seq = 2'), /immutable/);
      await client.query('ROLLBACK');
    } finally {
      await client.query('RESET qualor.audit_prune');
      client.release();
    }
    expect(await left(2)).toBe(1);
  });

  it('fires both triggers under session_replication_role = replica (ENABLE ALWAYS)', async (test) => {
    const [role] = (
      await database.db.execute<{ superuser: boolean }>(
        sql`SELECT rolsuper AS superuser FROM pg_roles WHERE rolname = current_user`,
      )
    ).rows;
    // Setting session_replication_role needs a superuser; the test containers run as one.
    if (!role?.superuser) test.skip('session_replication_role needs a superuser');
    const triggers = await database.db.execute<{ name: string; enabled: string }>(sql`
      SELECT tgname AS name, tgenabled AS enabled FROM pg_trigger
       WHERE tgrelid = 'audit_events'::regclass AND NOT tgisinternal ORDER BY tgname`);
    expect(triggers.rows).toEqual([
      { name: 'audit_events_guard', enabled: 'A' },
      { name: 'audit_events_no_truncate', enabled: 'A' },
    ]);
    const client = await database.pool.connect();
    try {
      await client.query('SET session_replication_role = replica');
      await expectRejection(
        client.query("UPDATE audit_events SET action = 'auth.sign_out' WHERE seq = 2"),
        /immutable/,
      );
      await expectRejection(client.query('DELETE FROM audit_events WHERE seq = 2'), /immutable/);
      await expectRejection(client.query('TRUNCATE audit_events'), /immutable/);
    } finally {
      await client.query('RESET session_replication_role');
      client.release();
    }
    expect(await left(2)).toBe(1);
  });

  it('keeps hash and prev_hash to 64 lowercase hex digits', async () => {
    const insert = (prevHash: string, hash: string) =>
      database.db.execute(sql`
        INSERT INTO audit_events (id, seq, created_at, action, outcome, actor_type, prev_hash, hash)
        VALUES (${uuidv7()}, 80, now(), 'auth.sign_in', 'success', 'user', ${prevHash}, ${hash})`);
    await expectRejection(insert(ZEROS, 'A'.repeat(64)), /audit_events_hash_format/);
    await expectRejection(insert(ZEROS, 'g'.repeat(64)), /audit_events_hash_format/);
    await expectRejection(insert(ZEROS, '0'.repeat(63)), /audit_events_hash_format/);
    await expectRejection(insert('z'.repeat(64), ZEROS), /audit_events_prev_hash_format/);
    await insert('f'.repeat(64), 'a'.repeat(64));
    expect(await left(80)).toBe(1);
  });

  it('refuses a malformed action and oversized details', async () => {
    await expectRejection(
      database.db.execute(sql`
        INSERT INTO audit_events (id, seq, created_at, action, outcome, actor_type, prev_hash, hash)
        VALUES (${uuidv7()}, 90, now(), 'Sign In', 'success', 'user', ${ZEROS}, ${ZEROS})`),
      /audit_events_action_check/,
    );
    await expectRejection(
      database.db.execute(sql`
        INSERT INTO audit_events (id, seq, created_at, action, outcome, actor_type, details, prev_hash, hash)
        VALUES (${uuidv7()}, 91, now(), 'auth.sign_in', 'success', 'user',
                jsonb_build_object('x', repeat('a', 9000)), ${ZEROS}, ${ZEROS})`),
      /audit_events_details_size/,
    );
  });
});
