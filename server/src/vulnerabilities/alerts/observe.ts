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
  itemsAdded: number;
  targetsRemoved: number;
}

/**
 * Brings the alert memory in line with `scope` (`alertScope`) as of `now` (4b A1–A3). The caller
 * holds LOCKS.vulnerabilityAlerts in `tx`.
 * 1. Deletes the target rows out of scope; their items go with them.
 * 2. Adds a row for each target in scope without one, once its first re-check is in: its
 *    `vulnerability_target_checks` row has a basis (R3). Before that, what the target holds is
 *    not its baseline yet, so it waits for a later pass. A target deleted since `alertScope` read
 *    it is skipped (R4). The row is `day_one` when its project had no row left after step 1: the
 *    project's first observation, or its return to scope.
 * 3. Adds an item, found at `now`, for each (target, vulnerability id) pair of
 *    `target_vulnerabilities` without one, `targetSlice` targets at a time. It is a baseline when
 *    step 2 of this call added its target. A package bump keeps the pair, so it adds nothing.
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
  if (ids.length === 0) return { targetsAdded: 0, itemsAdded: 0, targetsRemoved };

  // A statement never sees its own inserts, so `day_one` reads the rows left after the delete.
  // The two partial unique indexes skip a target that has its row already.
  const added = await tx.execute<{ id: string }>(sql`
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
    RETURNING id`);
  const addedTargets = new Set(added.rows.map((row) => row.id));

  const step = Math.max(1, Math.floor(targetSlice));
  let itemsAdded = 0;
  for (let from = 0; from < ids.length; from += step) {
    itemsAdded += await addItems(
      tx,
      nonNull(branchIds.slice(from, from + step)),
      nonNull(versionIds.slice(from, from + step)),
      addedTargets,
      at,
    );
  }
  return { targetsAdded: addedTargets.size, itemsAdded, targetsRemoved };
}

const nonNull = (ids: readonly (string | null)[]): string[] =>
  ids.filter((id): id is string => id !== null);

/** Step 3 for one slice of the scope's targets; returns the items added. */
async function addItems(
  tx: Executor,
  branchIds: readonly string[],
  versionIds: readonly string[],
  addedTargets: ReadonlySet<string>,
  at: SQL,
): Promise<number> {
  // Ids are uuidv7 from the application, as for every table: the missing pairs are read first.
  const missing = await tx.execute<{ targetId: string; vulnerabilityId: string }>(sql`
    SELECT p.target_id AS "targetId", p.vulnerability_id AS "vulnerabilityId"
      FROM (SELECT a.id AS target_id, v.vulnerability_id
              FROM unnest(${sql.param(branchIds)}::uuid[]) AS s(id)
              JOIN vulnerability_alert_targets a ON a.branch_id = s.id
              JOIN target_vulnerabilities v ON v.branch_id = s.id
            UNION
            SELECT a.id, v.vulnerability_id
              FROM unnest(${sql.param(versionIds)}::uuid[]) AS s(id)
              JOIN vulnerability_alert_targets a ON a.version_id = s.id
              JOIN target_vulnerabilities v ON v.version_id = s.id) p
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
                    ${sql.param(part.map((p) => addedTargets.has(p.targetId)))}::boolean[])
             AS u(id, target_id, vulnerability_id, baseline)
      ON CONFLICT (target_id, vulnerability_id) DO NOTHING`);
    added += inserted.rowCount ?? 0;
  }
  return added;
}
