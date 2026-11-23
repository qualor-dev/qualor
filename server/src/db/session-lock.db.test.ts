import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { withSessionLock } from './session-lock';

const KEY = 7_399_001;

describe('withSessionLock', () => {
  let t: TestDatabase;

  beforeAll(async () => {
    t = await createTestDatabase({ migrated: false });
  });
  afterAll(async () => {
    await t.close();
  });

  /** Whether another session can take the lock now (and then lets it go). */
  const free = async (name: string) => {
    const client = await t.pool.connect();
    try {
      const taken = await client.query<{ ok: boolean }>(
        'SELECT pg_try_advisory_lock($1, hashtext($2)) AS ok',
        [KEY, name],
      );
      if (taken.rows[0]?.ok) {
        await client.query('SELECT pg_advisory_unlock($1, hashtext($2))', [KEY, name]);
      }
      return taken.rows[0]?.ok === true;
    } finally {
      client.release();
    }
  };

  it('holds the lock while it runs, on one connection, and lets it go after', async () => {
    const seen = await withSessionLock(t.db, KEY, 'a', async (db) => {
      expect(await free('a')).toBe(false);
      expect(await free('b')).toBe(true);
      // Its transactions run on the reserved connection: the session that holds the lock.
      return db.transaction(async (tx) => {
        const held = await tx.execute<{ n: number }>(sql`
          SELECT count(*)::int AS n FROM pg_locks
           WHERE locktype = 'advisory' AND pid = pg_backend_pid() AND granted`);
        return held.rows[0]?.n;
      });
    });
    expect(seen).toBe(1);
    expect(await free('a')).toBe(true);
    expect(t.pool.totalCount - t.pool.idleCount).toBe(0);
  });

  it('lets the lock go when the work throws, and rethrows', async () => {
    await expect(
      withSessionLock(t.db, KEY, 'a', () => Promise.reject(new Error('boom'))),
    ).rejects.toThrow('boom');
    expect(await free('a')).toBe(true);
  });

  it('runs two holders of one name one after the other', async () => {
    const order: string[] = [];
    let release!: () => void;
    const gate = new Promise<void>((resolve) => (release = resolve));
    const first = withSessionLock(t.db, KEY, 'a', async () => {
      order.push('first in');
      await gate;
      order.push('first out');
    });
    while (order.length === 0) await new Promise((resolve) => setTimeout(resolve, 5));
    const second = withSessionLock(t.db, KEY, 'a', async () => {
      order.push('second in');
    });
    await new Promise((resolve) => setTimeout(resolve, 100));
    expect(order).toEqual(['first in']);
    release();
    await Promise.all([first, second]);
    expect(order).toEqual(['first in', 'first out', 'second in']);
  });
});
