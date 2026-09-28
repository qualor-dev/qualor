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
}

export function createDatabase(url: string, options: DatabaseOptions = {}): Database {
  const pool = new pg.Pool({ connectionString: url, max: options.max ?? 10 });
  // An idle client that loses its connection emits 'error' on the pool; with no listener the
  // process would crash.
  pool.on('error', (err) => options.onError?.(err));
  const db = drizzle({ client: pool, schema });
  return { db, pool, close: () => pool.end() };
}
