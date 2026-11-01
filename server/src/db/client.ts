import { drizzle, type NodePgDatabase } from 'drizzle-orm/node-postgres';
import pg from 'pg';
import type { Pool } from 'pg';
import * as schema from './schema';

export type Db = NodePgDatabase<typeof schema>;
export type Tx = Parameters<Parameters<Db['transaction']>[0]>[0];
/** Anything that can run a query: the pool-backed Db or an open transaction. */
export type Executor = Db | Tx;

export interface Database {
  db: Db;
  pool: Pool;
  close(): Promise<void>;
}

export interface DatabaseOptions {
  max?: number;
  onError?: (err: Error) => void;
  /**
   * Every new session is made read-only with an SQL `SET` before its first query, so nothing can
   * write: the support-bundle command. A `SET`, not the `options` startup parameter, which
   * PgBouncer and hosted poolers refuse.
   */
  readOnly?: boolean;
}

/** What `readOnly` runs on each new connection, before the pool hands it out. */
export const READ_ONLY_SESSION = 'SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY';
/**
 * What every new connection runs first: drizzle reads dates and timestamps as ISO text, which a
 * server DateStyle such as `SQL, DMY` would break. A `SET`, not the `options` startup parameter,
 * which PgBouncer and hosted poolers refuse.
 */
export const SESSION_DATESTYLE = "SET DateStyle = 'ISO, MDY'";

export function createDatabase(url: string, options: DatabaseOptions = {}): Database {
  const pool = new pg.Pool({
    connectionString: url,
    max: options.max ?? 10,
    // pg-pool awaits the hook; a failure ends the connection and fails the query (fails closed).
    onConnect: async (client: pg.ClientBase) => {
      await client.query(SESSION_DATESTYLE);
      if (options.readOnly) await client.query(READ_ONLY_SESSION);
    },
  });
  // An idle client that loses its connection emits 'error' on the pool; with no listener the
  // process would crash.
  pool.on('error', (err) => options.onError?.(err));
  const db = drizzle({ client: pool, schema });
  return { db, pool, close: () => pool.end() };
}
