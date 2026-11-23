import { drizzle } from 'drizzle-orm/node-postgres';
import type { Pool } from 'pg';
import type { Db } from './client';
import * as schema from './schema';

const asError = (err: unknown): Error => (err instanceof Error ? err : new Error(String(err)));

/**
 * Runs `run` while this session holds `pg_advisory_lock(key, hashtext(name))`, on a connection
 * reserved from the pool for the whole call. `run` gets a database bound to that connection: its
 * short transactions run there, so a caller waiting for the lock never needs a second connection.
 * The lock holds no row and no other lock, and no transaction stays open while `run` waits on
 * anything else (the network). It is released in `finally`; when taking or releasing it fails, the
 * connection is closed instead of returned, which releases the lock on the server too.
 */
export async function withSessionLock<T>(
  db: Db,
  key: number,
  name: string,
  run: (db: Db) => Promise<T>,
): Promise<T> {
  const pool = (db as unknown as { $client: Pool }).$client;
  const client = await pool.connect();
  let broken: Error | undefined;
  try {
    try {
      await client.query('SELECT pg_advisory_lock($1, hashtext($2))', [key, name]);
    } catch (err) {
      broken = asError(err);
      throw err;
    }
    try {
      return await run(drizzle({ client, schema }));
    } finally {
      try {
        await client.query('SELECT pg_advisory_unlock($1, hashtext($2))', [key, name]);
      } catch (err) {
        broken = asError(err);
      }
    }
  } finally {
    client.release(broken);
  }
}
