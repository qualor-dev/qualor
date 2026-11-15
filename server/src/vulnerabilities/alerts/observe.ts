import { sql, type SQL } from 'drizzle-orm';
import type { Executor } from '../../db/client';
import { uuidv7 } from '../../db/ids';
import { branchHasInventory } from '../../dependencies/inventory';
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
 * 0. Writes the missing project row of each project with a target row, dated by its earliest
 *    target, as migration 0029 did: a 0.15 replica of a rolling upgrade records targets without
 *    one. A project with targets is past its day one.
 * 1. Deletes the target rows out of scope; their items go with them. The project rows stay.
 * 2. Records each target in scope without a row, unseeded, without items. `observed_at` is the
 *    database's `now()`, the clock the re-check stamps `checked_at` with (A12), so a job clock
 *    ahead of the database's never holds back step 3. It needs a re-check row with a basis (R3)
 *    and a dependency inventory (for a branch {@link branchHasInventory}, for a version
 *    `has_inventory`; without one, its first inventory would count as all new, spec §8.5). An
 *    empty inventory is one: the packages added to it later are new. It must still exist (R4).
 *    The row is `day_one` on the project's day one, its first observation ever: the project has
 *    no `vulnerability_alert_projects` row yet. That row is written with the project's first
 *    target and stays until the project is deleted, so a target added later, a main branch
 *    replaced or a project back in scope is no day one (D17).
 * 3. Seeds, at `now`, each unseeded target re-checked since it was recorded
 *    (`checked_at >= observed_at`). Every pair it holds now becomes a baseline item. Rows written
 *    before the target entered the scope (R17 keeps them) are never taken for its baseline (R6).
 *    A target recorded in step 2 is usually seeded by a later pass, because its re-check row
 *    predates the record. Both times are a transaction's start (`now()`): a check whose
 *    transaction began at or after this one's, and committed before step 3 reads, seeds it in the
 *    same pass, which is harmless.
 * 4. Adds an item, found at `now`, for each (target, vulnerability id) pair of
 *    `target_vulnerabilities` that a seeded target has no item for. It reads only the seeded
 *    targets whose re-check is newer than their last read (`items_checked_at`, D18): a re-check
 *    writes a target's rows and its check row together, so a target not re-checked since has no
 *    new pair. A target seeded in step 3 is always read, and a re-check of every project makes
 *    the next pass read every target. One read per `targetSlice` targets. An item is a baseline
 *    when step 3 of this call seeded its target. A package bump keeps the pair, so it adds
 *    nothing. A target deleted since the read is skipped.
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

  // Step 0: 0029's backfill again, for the targets a 0.15 replica recorded after it ran (a rolling
  // upgrade). Before step 1, so a target that leaves the scope now still marks its day one.
  await tx.execute(sql`
    INSERT INTO vulnerability_alert_projects (project_id, day_one_at)
    SELECT a.project_id, min(a.observed_at)
      FROM vulnerability_alert_targets a
     WHERE NOT EXISTS (SELECT 1 FROM vulnerability_alert_projects p
                        WHERE p.project_id = a.project_id)
     GROUP BY a.project_id
    ON CONFLICT DO NOTHING`);

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

  // `day_one` holds for a project without a project row. That row is written after this
  // statement, so every target its day one records gets it. The two partial unique indexes skip a
  // target that has its row already. `observed_at` is on the database clock, as `checked_at` is:
  // step 3 compares the two (A12).
  const added = await tx.execute<{ projectId: string }>(sql`
    INSERT INTO vulnerability_alert_targets
           (id, project_id, branch_id, version_id, day_one, observed_at)
    SELECT s.id, s.project_id, s.branch_id, s.version_id,
           NOT EXISTS (SELECT 1 FROM vulnerability_alert_projects p
                        WHERE p.project_id = s.project_id),
           now()
      FROM unnest(${sql.param(ids)}::uuid[], ${sql.param(projectIds)}::uuid[],
                  ${sql.param(branchIds)}::uuid[], ${sql.param(versionIds)}::uuid[])
           AS s(id, project_id, branch_id, version_id)
     WHERE (EXISTS (SELECT 1 FROM branches b WHERE b.id = s.branch_id)
            AND ${branchHasInventory(sql`s.branch_id`)}
            AND EXISTS (SELECT 1 FROM vulnerability_target_checks c
                         WHERE c.branch_id = s.branch_id AND c.basis <> ''))
        OR (EXISTS (SELECT 1 FROM project_versions v
                     WHERE v.id = s.version_id AND v.has_inventory)
            AND EXISTS (SELECT 1 FROM vulnerability_target_checks c
                         WHERE c.version_id = s.version_id AND c.basis <> ''))
    ON CONFLICT DO NOTHING
    RETURNING project_id AS "projectId"`);
  const addedProjectIds = added.rows.map((row) => row.projectId);
  if (addedProjectIds.length > 0) {
    // A project's first target writes its row. The targets just inserted hold a key-share lock on
    // each project, so none is gone.
    await tx.execute(sql`
      INSERT INTO vulnerability_alert_projects (project_id)
      SELECT DISTINCT u.id FROM unnest(${sql.param(addedProjectIds)}::uuid[]) AS u(id)
      ON CONFLICT DO NOTHING`);
  }

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
    recheckProjectIds: [...new Set(addedProjectIds)].sort(),
  };
}

const nonNull = (ids: readonly (string | null)[]): string[] =>
  ids.filter((id): id is string => id !== null);

/** A seeded target whose pairs a pass reads, with the `checked_at` of its re-check then. */
interface Scanned extends Record<string, unknown> {
  id: string;
  branchId: string | null;
  versionId: string | null;
  /** As text: a JS Date would cut the microseconds, and the next pass would read it again. */
  checkedAt: string | null;
}

/** Step 4 for one slice of the scope's targets; returns the items added. */
async function addItems(
  tx: Executor,
  branchIds: readonly string[],
  versionIds: readonly string[],
  seededNow: ReadonlySet<string>,
  at: SQL,
): Promise<number> {
  // Read 1: the seeded targets re-checked since their last read, or never read (null after 0030,
  // and for a target seeded in step 3 of this pass). It comes before read 2: a re-check that
  // commits in between moves `checked_at` past the value stored below, so the next pass reads the
  // target again. A pair is never missed, at worst read twice.
  const scanned = await tx.execute<Scanned>(sql`
    SELECT a.id, a.branch_id AS "branchId", NULL::uuid AS "versionId",
           c.checked_at::text AS "checkedAt"
      FROM unnest(${sql.param(branchIds)}::uuid[]) AS s(id)
      JOIN vulnerability_alert_targets a ON a.branch_id = s.id
      LEFT JOIN vulnerability_target_checks c ON c.branch_id = s.id
     WHERE a.seeded_at IS NOT NULL
       AND (a.items_checked_at IS NULL OR c.checked_at IS DISTINCT FROM a.items_checked_at)
    UNION ALL
    SELECT a.id, NULL::uuid, a.version_id, c.checked_at::text
      FROM unnest(${sql.param(versionIds)}::uuid[]) AS s(id)
      JOIN vulnerability_alert_targets a ON a.version_id = s.id
      LEFT JOIN vulnerability_target_checks c ON c.version_id = s.id
     WHERE a.seeded_at IS NOT NULL
       AND (a.items_checked_at IS NULL OR c.checked_at IS DISTINCT FROM a.items_checked_at)`);
  if (scanned.rows.length === 0) return 0;

  // Read 2: their missing pairs, before the insert: ids are uuidv7 from the application.
  const scannedBranches = nonNull(scanned.rows.map((row) => row.branchId));
  const scannedVersions = nonNull(scanned.rows.map((row) => row.versionId));
  const missing = await tx.execute<{ targetId: string; vulnerabilityId: string }>(sql`
    SELECT p.target_id AS "targetId", p.vulnerability_id AS "vulnerabilityId"
      FROM (SELECT a.id AS target_id, v.vulnerability_id
              FROM unnest(${sql.param(scannedBranches)}::uuid[]) AS s(id)
              JOIN vulnerability_alert_targets a ON a.branch_id = s.id
              JOIN target_vulnerabilities v ON v.branch_id = s.id
            UNION
            SELECT a.id, v.vulnerability_id
              FROM unnest(${sql.param(scannedVersions)}::uuid[]) AS s(id)
              JOIN vulnerability_alert_targets a ON a.version_id = s.id
              JOIN target_vulnerabilities v ON v.version_id = s.id) p
     WHERE NOT EXISTS (SELECT 1 FROM vulnerability_alert_items i
                        WHERE i.target_id = p.target_id AND i.vulnerability_id = p.vulnerability_id)
     ORDER BY p.target_id, p.vulnerability_id`);

  let added = 0;
  for (let from = 0; from < missing.rows.length; from += BATCH_ROWS) {
    const part = missing.rows.slice(from, from + BATCH_ROWS);
    // A target deleted since the read (its branch, version or project went, by cascade) is
    // skipped, not a foreign key failure of the whole pass.
    const inserted = await tx.execute(sql`
      INSERT INTO vulnerability_alert_items (id, target_id, vulnerability_id, baseline, found_at)
      SELECT u.id, u.target_id, u.vulnerability_id, u.baseline, ${at}
        FROM unnest(${sql.param(part.map(() => uuidv7()))}::uuid[],
                    ${sql.param(part.map((p) => p.targetId))}::uuid[],
                    ${sql.param(part.map((p) => p.vulnerabilityId))}::text[],
                    ${sql.param(part.map((p) => seededNow.has(p.targetId)))}::boolean[])
             AS u(id, target_id, vulnerability_id, baseline)
       WHERE EXISTS (SELECT 1 FROM vulnerability_alert_targets a WHERE a.id = u.target_id)
      ON CONFLICT (target_id, vulnerability_id) DO NOTHING`);
    added += inserted.rowCount ?? 0;
  }

  // Each target read keeps the `checked_at` of read 1, not the one current now.
  await tx.execute(sql`
    UPDATE vulnerability_alert_targets a SET items_checked_at = u.checked_at
      FROM unnest(${sql.param(scanned.rows.map((row) => row.id))}::uuid[],
                  ${sql.param(scanned.rows.map((row) => row.checkedAt))}::timestamptz[])
           AS u(id, checked_at)
     WHERE a.id = u.id`);
  return added;
}
