import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import pg from 'pg';
import type { TestProject } from 'vitest/node';
import { createDatabase } from '../src/db/client';
import { runMigrations } from '../src/db/migrate';
import { MIGRATIONS_DIR } from './paths';
import { databaseUrl, TEMPLATE_DATABASE } from './urls';

declare module 'vitest' {
  export interface ProvidedContext {
    databaseAdminUrl: string;
  }
}

/**
 * Starts one PostgreSQL 18 (QUALOR_TEST_POSTGRES_IMAGE picks another image, e.g. postgres:16-alpine
 * for the oldest supported version; or QUALOR_TEST_DATABASE_URL, e.g. a CI service), migrates a
 * template database once, and hands the server URL to test files, which clone the template.
 * Without Docker and without the variable this throws, so DB tests fail loudly (never skip).
 */
export default async function setup(project: TestProject): Promise<() => Promise<void>> {
  let container: StartedPostgreSqlContainer | undefined;
  let adminUrl = process.env.QUALOR_TEST_DATABASE_URL;
  if (!adminUrl) {
    try {
      container = await new PostgreSqlContainer(
        process.env.QUALOR_TEST_POSTGRES_IMAGE ?? 'postgres:18-alpine',
      ).start();
    } catch (err) {
      throw new Error(
        'Database tests need Docker (Testcontainers) or QUALOR_TEST_DATABASE_URL pointing at a PostgreSQL 16+ server.',
        { cause: err },
      );
    }
    adminUrl = container.getConnectionUri();
  }
  const admin = new pg.Client({ connectionString: adminUrl });
  await admin.connect();
  try {
    await admin.query(`DROP DATABASE IF EXISTS ${TEMPLATE_DATABASE} WITH (FORCE)`);
    await admin.query(`CREATE DATABASE ${TEMPLATE_DATABASE}`);
  } finally {
    await admin.end();
  }
  const template = createDatabase(databaseUrl(adminUrl, TEMPLATE_DATABASE), { max: 1 });
  try {
    await runMigrations(template.pool, MIGRATIONS_DIR);
  } finally {
    await template.close();
  }
  project.provide('databaseAdminUrl', adminUrl);
  return async () => {
    await container?.stop();
  };
}
