import { spawn } from 'node:child_process';
import path from 'node:path';
import pg from 'pg';
import type { Config } from '../config';
import {
  EmbeddedPostgresError,
  startEmbeddedPostgres,
  type EmbeddedLogger,
  type EmbeddedPostgres,
} from './embedded';

/**
 * `main.js restore` (embedded-postgres.md §6): restores a `pg_dump -Fc` archive from standard
 * input into a fresh `qualor` database of the embedded PostgreSQL, with no server running on the
 * data directory (the cluster refuses to start while another one holds it). The dump is loaded
 * beside the existing database first and replaces it only once it loaded (restoreSwapping).
 * Returns the exit code.
 */
export async function restoreEmbedded(config: Config, logger: EmbeddedLogger): Promise<number> {
  if (config.databaseUrl !== null) {
    process.stderr.write(
      'qualor-server: restore works on the embedded database only; restore an external database with pg_restore\n',
    );
    return 1;
  }
  if (process.stdin.isTTY) {
    process.stderr.write(
      'qualor-server: pipe the dump into standard input: restore < backup.dump\n',
    );
    return 1;
  }
  let embedded: EmbeddedPostgres;
  try {
    embedded = await startEmbeddedPostgres({ ...config.embedded, logger });
  } catch (err) {
    // The start's own refusals (another server holds the volume, a wrong major version) are
    // written for the operator; main's generic handler would print only the class name.
    if (!(err instanceof EmbeddedPostgresError)) throw err;
    process.stderr.write(`qualor-server: ${err.message}
`);
    return 1;
  }
  try {
    const admin = new pg.Client({
      connectionString: embedded.url.replace(/\/qualor$/, '/postgres'),
    });
    await admin.connect();
    const run = path.join(config.embedded.dataDir, 'run');
    let code: number;
    try {
      code = await restoreSwapping({
        query: async (sql) => {
          await admin.query(sql);
        },
        pgRestore: (database) =>
          new Promise<number>((resolve) => {
            const child = spawn(
              path.join(config.embedded.postgresDir, 'bin', 'pg_restore'),
              ['--no-owner', '--exit-on-error', '-h', run, '-U', 'qualor', '-d', database],
              { stdio: ['inherit', 'inherit', 'inherit'] },
            );
            child.once('error', () => resolve(1));
            child.once('exit', (exitCode) => resolve(exitCode ?? 1));
          }),
      });
    } finally {
      await admin.end();
    }
    if (code === 0) logger.info({ component: 'restore' }, 'the backup was restored');
    else {
      process.stderr.write(
        `qualor-server: pg_restore failed (exit ${code}); the existing database was not changed\n`,
      );
    }
    return code === 0 ? 0 : 1;
  } finally {
    await embedded.stop();
  }
}

/** What a restore does to the cluster: SQL on the maintenance database, and pg_restore into one. */
export interface RestoreSteps {
  query(sql: string): Promise<void>;
  pgRestore(database: string): Promise<number>;
}

/** The database a dump is loaded into before it replaces `qualor`. */
export const RESTORE_DATABASE = 'qualor_restore';

/**
 * Loads the dump into a separate database and replaces `qualor` with it only when pg_restore
 * succeeded, so a truncated, empty or wrong file leaves the existing data as it was. Returns
 * pg_restore's exit code.
 */
export async function restoreSwapping(steps: RestoreSteps): Promise<number> {
  await steps.query(`DROP DATABASE IF EXISTS ${RESTORE_DATABASE} WITH (FORCE)`);
  await steps.query(`CREATE DATABASE ${RESTORE_DATABASE}`);
  const code = await steps.pgRestore(RESTORE_DATABASE);
  if (code !== 0) {
    await steps.query(`DROP DATABASE IF EXISTS ${RESTORE_DATABASE} WITH (FORCE)`);
    return code;
  }
  await steps.query('DROP DATABASE IF EXISTS qualor WITH (FORCE)');
  await steps.query(`ALTER DATABASE ${RESTORE_DATABASE} RENAME TO qualor`);
  return 0;
}
