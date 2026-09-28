import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { sql } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { migrate } from 'drizzle-orm/node-postgres/migrator';
import type { Pool } from 'pg';
import type { Executor } from './client';
import { pgErrorCode } from './errors';
import { LOCKS } from './locks';

interface Journal {
  entries: { tag: string }[];
}

/** Applies pending migrations while holding an advisory lock, so replicas can boot together. */
export async function runMigrations(pool: Pool, migrationsFolder: string): Promise<void> {
  const client = await pool.connect();
  try {
    await client.query('SELECT pg_advisory_lock($1)', [LOCKS.migrations]);
    try {
      await migrate(drizzle({ client }), { migrationsFolder });
    } finally {
      await client.query('SELECT pg_advisory_unlock($1)', [LOCKS.migrations]);
    }
  } finally {
    client.release();
  }
}

export async function pendingMigrations(db: Executor, migrationsFolder: string): Promise<number> {
  const journal = JSON.parse(
    await readFile(join(migrationsFolder, 'meta', '_journal.json'), 'utf8'),
  ) as Journal;
  try {
    const result = await db.execute<{ applied: number }>(
      sql`SELECT count(*)::int AS applied FROM drizzle.__drizzle_migrations`,
    );
    return Math.max(0, journal.entries.length - (result.rows[0]?.applied ?? 0));
  } catch (err) {
    // 42P01 undefined_table, 3F000 invalid_schema_name: nothing applied yet.
    const code = pgErrorCode(err);
    if (code === '42P01' || code === '3F000') return journal.entries.length;
    throw err;
  }
}

export function readinessCheck(db: Executor, migrationsFolder: string): () => Promise<boolean> {
  return async () => (await pendingMigrations(db, migrationsFolder)) === 0;
}
