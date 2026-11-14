import { sql } from 'drizzle-orm';
import { jsonChunks } from '../db/bulk';
import type { Executor } from '../db/client';

/** data-model.md §6: the statuses a user may set; only the system sets `closed`. */
export const USER_STATUSES = ['open', 'resolved', 'wont_fix', 'false_positive'] as const;
export type UserStatus = (typeof USER_STATUSES)[number];

/** One `issue_changes` row of a status change, as a transition writes it. */
export interface StatusLogRow {
  id: string;
  issue_id: string;
  old_value: string;
  comment: string | null;
}

/**
 * Sets `to` on each issue of `rows` that still has its `from_status` (the lost-update guard), as
 * resolved now by the user `resolvedBy` (null: nobody, a change of the system's), or no longer
 * resolved when `to` is `open`. Answers the issues it changed, with the status each had.
 */
export async function writeStatus(
  tx: Executor,
  rows: readonly { id: string; from_status: string }[],
  to: UserStatus,
  resolvedBy: string | null,
): Promise<{ id: string; old_value: string }[]> {
  const resolving = to !== 'open';
  const applied: { id: string; old_value: string }[] = [];
  for (const chunk of jsonChunks(rows)) {
    const updated = await tx.execute<{ id: string; old_value: string }>(sql`
      UPDATE issues AS i SET status = ${to},
        resolved_at = ${resolving ? sql`now()` : sql`NULL`},
        resolved_by = ${resolving ? resolvedBy : null}::uuid,
        updated_at = now()
      FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, from_status text)
      WHERE i.id = r.id AND i.status = r.from_status
      RETURNING i.id, r.from_status AS old_value`);
    applied.push(...updated.rows);
  }
  return applied;
}

/** The changelog of a status change to `to`: one row of `log` each, by `userId` (null: the system). */
export async function writeStatusLog(
  tx: Executor,
  log: readonly StatusLogRow[],
  userId: string | null,
  to: UserStatus,
): Promise<void> {
  for (const chunk of jsonChunks(log)) {
    await tx.execute(sql`
      INSERT INTO issue_changes (id, issue_id, user_id, field, old_value, new_value, comment)
      SELECT r.id, r.issue_id, ${userId}::uuid, 'status', r.old_value, ${to}, r.comment
        FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, issue_id uuid, old_value text, comment text)`);
  }
}
