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
 * data directory (the cluster refuses to start while another one holds it). Returns the exit code.
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
    try {
      await admin.query('DROP DATABASE IF EXISTS qualor WITH (FORCE)');
      await admin.query('CREATE DATABASE qualor');
    } finally {
      await admin.end();
    }
    const run = path.join(config.embedded.dataDir, 'run');
    const code = await new Promise<number>((resolve) => {
      const child = spawn(
        path.join(config.embedded.postgresDir, 'bin', 'pg_restore'),
        ['--no-owner', '--exit-on-error', '-h', run, '-U', 'qualor', '-d', 'qualor'],
        { stdio: ['inherit', 'inherit', 'inherit'] },
      );
      child.once('error', () => resolve(1));
      child.once('exit', (exitCode) => resolve(exitCode ?? 1));
    });
    if (code === 0) logger.info({ component: 'restore' }, 'the backup was restored');
    else process.stderr.write(`qualor-server: pg_restore failed (exit ${code})\n`);
    return code === 0 ? 0 : 1;
  } finally {
    await embedded.stop();
  }
}
