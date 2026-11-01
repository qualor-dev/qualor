import { sql } from 'drizzle-orm';
import type { Executor } from '../../db/client';
import { LOCKS } from '../../db/locks';
import type { EpssFile, KevEntry } from './parse';

/** Rows written by one statement. */
const BATCH_ROWS = 5000;

/**
 * Makes the KEV table list exactly `entries`, in one transaction (a savepoint when `db` is a
 * transaction already). An id the file lacks stays with `delisted_at` set; listing it again clears
 * it and keeps the first `listed_at`. `added` counts the ids that were not in the table, `relisted`
 * the delisted ones that came back.
 */
export async function replaceKev(
  db: Executor,
  entries: readonly KevEntry[],
): Promise<{ count: number; added: number; relisted: number }> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityPriority})`);
    const ids = entries.map((e) => e.vulnerabilityId);
    const relisted = (
      await tx.execute(sql`
        UPDATE vulnerability_kev SET delisted_at = NULL
         WHERE delisted_at IS NOT NULL AND vulnerability_id = ANY(${sql.param(ids)}::text[])`)
    ).rowCount;
    let added = 0;
    for (let at = 0; at < entries.length; at += BATCH_ROWS) {
      const part = entries.slice(at, at + BATCH_ROWS);
      const { rows } = await tx.execute<{ inserted: boolean }>(sql`
        INSERT INTO vulnerability_kev (vulnerability_id, date_added, ransomware)
        SELECT * FROM unnest(
          ${sql.param(part.map((e) => e.vulnerabilityId))}::text[],
          ${sql.param(part.map((e) => e.dateAdded))}::date[],
          ${sql.param(part.map((e) => e.ransomware))}::boolean[])
        ON CONFLICT (vulnerability_id) DO UPDATE
          SET date_added = EXCLUDED.date_added, ransomware = EXCLUDED.ransomware,
              delisted_at = NULL
        RETURNING (xmax = 0) AS inserted`);
      added += rows.filter((r) => r.inserted).length;
    }
    await tx.execute(sql`
      UPDATE vulnerability_kev SET delisted_at = now()
       WHERE delisted_at IS NULL AND vulnerability_id <> ALL(${sql.param(ids)}::text[])`);
    return { count: entries.length, added, relisted: relisted ?? 0 };
  });
}

/**
 * Makes the EPSS table hold exactly the rows of `file`, in one transaction (a savepoint when `db`
 * is a transaction already).
 */
export async function replaceEpss(db: Executor, file: EpssFile): Promise<{ count: number }> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityPriority})`);
    await tx.execute(sql`DELETE FROM vulnerability_epss`);
    for (let at = 0; at < file.ids.length; at += BATCH_ROWS) {
      const end = at + BATCH_ROWS;
      await tx.execute(sql`
        INSERT INTO vulnerability_epss (vulnerability_id, score, percentile)
        SELECT * FROM unnest(
          ${sql.param(file.ids.slice(at, end))}::text[],
          ${sql.param(file.scores.slice(at, end))}::real[],
          ${sql.param(file.percentiles.slice(at, end))}::real[])`);
    }
    return { count: file.ids.length };
  });
}
