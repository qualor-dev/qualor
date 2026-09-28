import { randomBytes } from 'node:crypto';
import pg from 'pg';
import { expect, inject } from 'vitest';
import { createDatabase, type Database } from '../src/db/client';
import { pgErrorCode } from '../src/db/errors';
import { databaseUrl, TEMPLATE_DATABASE } from './urls';

export interface TestDatabase extends Database {
  url: string;
  name: string;
}

async function adminQueries(statements: readonly string[]): Promise<void> {
  const client = new pg.Client({ connectionString: inject('databaseAdminUrl') });
  await client.connect();
  try {
    for (const statement of statements) await client.query(statement);
  } finally {
    await client.end();
  }
}

/** A fresh database per test file: a clone of the migrated template (default) or empty. */
export async function createTestDatabase(
  options: { migrated?: boolean } = {},
): Promise<TestDatabase> {
  const name = `qualor_test_${randomBytes(6).toString('hex')}`;
  const template = options.migrated === false ? '' : ` TEMPLATE ${TEMPLATE_DATABASE}`;
  // Two files cloning the template at the same instant can collide; serialise the CREATE.
  await adminQueries([
    'SELECT pg_advisory_lock(7310099)',
    `CREATE DATABASE ${name}${template}`,
    'SELECT pg_advisory_unlock(7310099)',
  ]);
  const database = createDatabase(databaseUrl(inject('databaseAdminUrl'), name), { max: 10 });
  return {
    ...database,
    url: databaseUrl(inject('databaseAdminUrl'), name),
    name,
    close: async () => {
      await database.close();
      await adminQueries([`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`]);
    },
  };
}

export async function expectPgError(action: PromiseLike<unknown>, code: string): Promise<void> {
  const error = await Promise.resolve(action).then(
    () => null,
    (err: unknown) => err,
  );
  expect(pgErrorCode(error), `expected SQLSTATE ${code}`).toBe(code);
}
