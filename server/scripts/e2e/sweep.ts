import type pg from 'pg';

/** The databases serve.ts creates: `qualor_e2e_` and 12 hex digits (never anything else). */
const E2E_DATABASE = /^qualor_e2e_[0-9a-f]{12}$/;

/**
 * Drops the e2e databases earlier runs left behind on a shared server (QUALOR_TEST_DATABASE_URL):
 * on Windows the runner ends serve.ts without a signal, so its clean-up never runs. Only databases
 * nobody is connected to go, with a plain DROP (never FORCE): a database another run is using
 * stays, and one that gains a connection meanwhile makes its DROP fail, which is skipped.
 * Returns the names dropped.
 */
export async function sweepE2eDatabases(admin: pg.Client): Promise<string[]> {
  const { rows } = await admin.query<{ datname: string }>(
    `SELECT d.datname FROM pg_database d
      WHERE starts_with(d.datname, 'qualor_e2e_')
        AND NOT EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.datname = d.datname)`,
  );
  const dropped: string[] = [];
  for (const { datname } of rows) {
    if (!E2E_DATABASE.test(datname)) continue;
    try {
      await admin.query(`DROP DATABASE IF EXISTS ${datname}`);
      dropped.push(datname);
    } catch {
      // In use after all (a run started meanwhile): leave it.
    }
  }
  return dropped;
}
