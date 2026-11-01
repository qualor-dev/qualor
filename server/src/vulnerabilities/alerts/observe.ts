import { sql, type SQL } from 'drizzle-orm';
import type { Executor } from '../../db/client';
import { uuidv7 } from '../../db/ids';
import type { Target } from '../targets';

/** Item rows written by one statement. */
const BATCH_ROWS = 5000;
/** Targets whose missing pairs are read at once, so a day one never holds the instance's pairs. */
export const TARGET_SLICE = 500;

export interface ObservedAlerts {
  targetsAdded: number;
  targetsSeeded: number;
  itemsAdded: number;
  targetsRemoved: number;
  /** The projects of the targets added, sorted: a re-check of each seeds them (R6). */
  recheckProjectIds: string[];
}

/**
 * Brings the alert memory in line with `scope` (`alertScope`) as of `now` (4b A1–A3, R3, R4, R6).
 * The caller holds LOCKS.vulnerabilityAlerts in `tx`, and queues a re-check of
 * `recheckProjectIds`; this function enqueues nothing.
 * 1. Deletes the target rows out of scope; their items go with them.
 * 2. Records each target in scope without a row, at `now` and unseeded, without items. It needs
 *    a re-check row with a basis (R3) and must still exist (R4). The row is `day_one` when its
 *    project had no row left after step 1: the project's first observation, or its return.
 * 3. Seeds each unseeded target re-checked since it was recorded (`checked_at >= observed_at`).
 *    Every pair it holds now becomes a baseline item. Rows written before the target entered the
 *    scope (R17 keeps them) are never taken for its baseline (R6). A target recorded in step 2 is
 *    seeded by a later pass, because its re-check row predates `now`.
 * 4. Adds an item, found at `now`, for each (target, vulnerability id) pair of
 *    `target_vulnerabilities` that a seeded target has no item for. Steps 3 and 4 share one read
 *    per `targetSlice` targets. An item is a baseline when step 3 of this call seeded its target.
 *    A package bump keeps the pair, so it adds nothing.
 *
 * `target_vulnerabilities` is only read: the rows of a target out of scope stay there.
 */
export async function observeAlerts(
  tx: Executor,
  scope: Map<string, Target[]>,
  now: Date,
  targetSlice: number = TARGET_SLICE,
): Promise<ObservedAlerts> {
  const ids: string[] = [];
  const projectIds: string[] = [];
  const branchIds: (string | null)[] = [];
  const versionIds: (string | null)[] = [];
  for (const [projectId, targets] of scope) {
    for (const target of targets) {
      ids.push(uuidv7());
      projectIds.push(projectId);
      branchIds.push(target.kind === 'branch' ? target.branchId : null);
      versionIds.push(target.kind === 'version' ? target.versionId : null);
    }
  }
  const at = sql`${now.toISOString()}::timestamptz`;

  const removed = await tx.execute(sql`
    DELETE FROM vulnerability_alert_targets a
     WHERE NOT EXISTS (SELECT 1 FROM unnest(${sql.param(nonNull(branchIds))}::uuid[]) AS s(id)
                        WHERE s.id = a.branch_id)
       AND NOT EXISTS (SELECT 1 FROM unnest(${sql.param(nonNull(versionIds))}::uuid[]) AS s(id)
                        WHERE s.id = a.version_id)`);
  const targetsRemoved = removed.rowCount ?? 0;
  if (ids.length === 0) {
    return {
      targetsAdded: 0,
      targetsSeeded: 0,
      itemsAdded: 0,
      targetsRemoved,
      recheckProjectIds: [],
    };
  }

  // A statement never sees its own inserts, so `day_one` reads the rows left after the delete.
  // The two partial unique indexes skip a target that has its row already.
  const added = await tx.execute<{ projectId: string }>(sql`
    INSERT INTO vulnerability_alert_targets
           (id, project_id, branch_id, version_id, day_one, observed_at)
    SELECT s.id, s.project_id, s.branch_id, s.version_id,
           NOT EXISTS (SELECT 1 FROM vulnerability_alert_targets a
                        WHERE a.project_id = s.project_id),
           ${at}
      FROM unnest(${sql.param(ids)}::uuid[], ${sql.param(projectIds)}::uuid[],
                  ${sql.param(branchIds)}::uuid[], ${sql.param(versionIds)}::uuid[])
           AS s(id, project_id, branch_id, version_id)
     WHERE (EXISTS (SELECT 1 FROM branches b WHERE b.id = s.branch_id)
            AND EXISTS (SELECT 1 FROM vulnerability_target_checks c
                         WHERE c.branch_id = s.branch_id AND c.basis <> ''))
        OR (EXISTS (SELECT 1 FROM project_versions v WHERE v.id = s.version_id)
            AND EXISTS (SELECT 1 FROM vulnerability_target_checks c
                         WHERE c.version_id = s.version_id AND c.basis <> ''))
    ON CONFLICT DO NOTHING
    RETURNING project_id AS "projectId"`);

  // Every row left is in scope (step 1). The basis condition is R3's, for a branch that lost it.
  const seeded = await tx.execute<{ id: string }>(sql`
    UPDATE vulnerability_alert_targets a SET seeded_at = ${at}
     WHERE a.seeded_at IS NULL
       AND (EXISTS (SELECT 1 FROM vulnerability_target_checks c
                     WHERE c.branch_id = a.branch_id AND c.basis <> ''
                       AND c.checked_at >= a.observed_at)
            OR EXISTS (SELECT 1 FROM vulnerability_target_checks c
                        WHERE c.version_id = a.version_id AND c.basis <> ''
                          AND c.checked_at >= a.observed_at))
    RETURNING a.id`);
  const seededNow = new Set(seeded.rows.map((row) => row.id));

  const step = Math.max(1, Math.floor(targetSlice));
  let itemsAdded = 0;
  for (let from = 0; from < ids.length; from += step) {
    itemsAdded += await addItems(
      tx,
      nonNull(branchIds.slice(from, from + step)),
      nonNull(versionIds.slice(from, from + step)),
      seededNow,
      at,
    );
  }
  return {
    targetsAdded: added.rows.length,
    targetsSeeded: seededNow.size,
    itemsAdded,
    targetsRemoved,
    recheckProjectIds: [...new Set(added.rows.map((row) => row.projectId))].sort(),
  };
}

const nonNull = (ids: readonly (string | null)[]): string[] =>
  ids.filter((id): id is string => id !== null);

/** Steps 3 and 4 for one slice of the scope's targets; returns the items added. */
async function addItems(
  tx: Executor,
  branchIds: readonly string[],
  versionIds: readonly string[],
  seededNow: ReadonlySet<string>,
  at: SQL,
): Promise<number> {
  // Ids are uuidv7 from the application, as for every table: the missing pairs are read first.
  const missing = await tx.execute<{ targetId: string; vulnerabilityId: string }>(sql`
    SELECT p.target_id AS "targetId", p.vulnerability_id AS "vulnerabilityId"
      FROM (SELECT a.id AS target_id, v.vulnerability_id
              FROM unnest(${sql.param(branchIds)}::uuid[]) AS s(id)
              JOIN vulnerability_alert_targets a ON a.branch_id = s.id
              JOIN target_vulnerabilities v ON v.branch_id = s.id
             WHERE a.seeded_at IS NOT NULL
            UNION
            SELECT a.id, v.vulnerability_id
              FROM unnest(${sql.param(versionIds)}::uuid[]) AS s(id)
              JOIN vulnerability_alert_targets a ON a.version_id = s.id
              JOIN target_vulnerabilities v ON v.version_id = s.id
             WHERE a.seeded_at IS NOT NULL) p
     WHERE NOT EXISTS (SELECT 1 FROM vulnerability_alert_items i
                        WHERE i.target_id = p.target_id AND i.vulnerability_id = p.vulnerability_id)
     ORDER BY p.target_id, p.vulnerability_id`);
  let added = 0;
  for (let from = 0; from < missing.rows.length; from += BATCH_ROWS) {
    const part = missing.rows.slice(from, from + BATCH_ROWS);
    const inserted = await tx.execute(sql`
      INSERT INTO vulnerability_alert_items (id, target_id, vulnerability_id, baseline, found_at)
      SELECT u.id, u.target_id, u.vulnerability_id, u.baseline, ${at}
        FROM unnest(${sql.param(part.map(() => uuidv7()))}::uuid[],
                    ${sql.param(part.map((p) => p.targetId))}::uuid[],
                    ${sql.param(part.map((p) => p.vulnerabilityId))}::text[],
                    ${sql.param(part.map((p) => seededNow.has(p.targetId)))}::boolean[])
             AS u(id, target_id, vulnerability_id, baseline)
      ON CONFLICT (target_id, vulnerability_id) DO NOTHING`);
    added += inserted.rowCount ?? 0;
  }
  return added;
}
