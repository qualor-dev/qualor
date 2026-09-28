import { and, asc, eq, ne, or, sql } from 'drizzle-orm';
import type { Severity } from '@qualor/shared';
import { jsonChunks } from '../db/bulk';
import type { Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { issues, rules } from '../db/schema';
import {
  REOPEN_WINDOW_DAYS,
  type CandidateIssue,
  type CloseWrite,
  type IssueStatus,
  type StatusChange,
  type TrackingPlan,
} from './plan';

/** The database clock of the current transaction (`now()` is fixed for its whole duration). */
export async function dbNow(tx: Executor): Promise<Date> {
  const result = await tx.execute<{ now: Date | string }>(sql`SELECT now() AS now`);
  const value = result.rows[0]?.now;
  if (value === undefined) throw new Error('SELECT now() returned no row');
  return value instanceof Date ? value : new Date(value);
}

/**
 * data-model.md §5.2 inputs: the branch's issues that are not closed, or closed recently. Ordered
 * by position so the matcher's line/column ranking (match.ts) sees candidates in a stable,
 * reproducible order instead of whatever order the database happens to return them in (U5 fix
 * round 1, #1) — without this, which of two same-line, same-hash candidates ends up paired with
 * which finding could flip between otherwise-identical analyses.
 */
export async function loadCandidates(tx: Executor, branchId: string): Promise<CandidateIssue[]> {
  const rows = await tx
    .select({
      id: issues.id,
      ruleId: issues.ruleId,
      ruleKey: rules.key,
      engineId: rules.engineId,
      cwe: rules.cwe,
      path: issues.path,
      lineHash: issues.lineHash,
      contextHash: issues.contextHash,
      startLine: issues.startLine,
      startColumn: issues.startColumn,
      message: issues.message,
      status: issues.status,
      severity: issues.severity,
      severityOverridden: issues.severityOverridden,
      duplicateOfIssueId: issues.duplicateOfIssueId,
      // Only meaningful (non-null) when status = 'closed': the status this issue had right
      // before the system closed it, so a re-detected wont_fix/false_positive can be restored
      // instead of silently reopened to 'open' (data-model.md §6; U5 fix round 1, #2). The CASE
      // means the correlated subquery only ever runs for rows that are actually closed.
      preCloseStatus: sql<string | null>`CASE WHEN ${issues.status} = 'closed' THEN (
        SELECT ic.old_value FROM issue_changes ic
         WHERE ic.issue_id = ${issues.id} AND ic.field = 'status' AND ic.new_value = 'closed'
         ORDER BY ic.id DESC LIMIT 1
      ) END`,
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .where(
      and(
        eq(issues.branchId, branchId),
        or(
          ne(issues.status, 'closed'),
          sql`${issues.closedAt} > now() - make_interval(days => ${REOPEN_WINDOW_DAYS})`,
        ),
      ),
    )
    .orderBy(asc(issues.startLine), asc(issues.startColumn), asc(issues.id));
  return rows.map((r) => ({
    ...r,
    status: r.status as IssueStatus,
    severity: r.severity as Severity,
    preCloseStatus: (r.preCloseStatus as IssueStatus | null) ?? null,
  }));
}

const WRITE_RECORD = `id uuid, rule_id uuid, fingerprint text, line_hash text, context_hash text,
  path text, start_line integer, start_column integer, end_line integer, end_column integer,
  message text, severity text, quality text, kind text, status text, in_new_code boolean,
  snippet jsonb, secondary_locations jsonb`;

/** {@link WRITE_RECORD} plus the guard column updateMatched needs (see its SQL). */
const UPDATE_RECORD = `${WRITE_RECORD}, from_status text`;

/** Sorts by a stable key before chunking, so a batched statement's row (and lock) order is a
 *  reproducible function of the input, not of incidental report/array iteration order. Every call
 *  site below explains, on its own, whether that reproducibility is also deadlock avoidance for
 *  that particular statement (it depends on what kind of lock the statement takes). */
function sortedBy<T>(rows: readonly T[], key: (row: T) => string): T[] {
  return [...rows].sort((a, b) => {
    const ka = key(a);
    const kb = key(b);
    return ka < kb ? -1 : ka > kb ? 1 : 0;
  });
}

/**
 * Applies the matched-issue updates and returns the status transitions that actually took effect
 * (U5 fix round 2, #3): a plan is built from a snapshot of the candidates, and the lost-update
 * guard below (U5 fix round 1, #3) may silently skip a row whose status changed since — logging a
 * changelog entry for a transition that never happened would then corrupt the very history
 * `loadCandidates`' `preCloseStatus` reads.
 *
 * Locks and reads each row's status *before* the guarded `UPDATE`, in a separate statement, and
 * compares that captured value to `from_status` in JS (U5 fix round 3, #C): comparing the
 * `UPDATE`'s own `RETURNING` output to what was planned (`i.status = r.status`) is not exact — if
 * a concurrent writer already set the row to exactly the value this plan also intended, the guard
 * correctly blocks the write, but the post-update value still happens to equal `r.status`, making
 * a naive `RETURNING`-only check report a transition that never actually applied. Holding the
 * row lock from the read through to the `UPDATE` (same transaction) rules out any further
 * change in between, so the captured status is exactly what the guard itself evaluates against.
 */
async function updateMatched(
  tx: Executor,
  rows: TrackingPlan['updates'],
  analysisId: string,
  blocked: string[],
): Promise<StatusChange[]> {
  const applied: StatusChange[] = [];
  const seenStatus = new Map<string, string>();
  // Sorted by id for a reproducible statement order. The rows are already locked by
  // lockPlannedRows (one id-ordered pass over the matched and close sets together, which is what
  // keeps this deadlock-free against user transitions and other writers); the locked read below
  // takes the same FOR NO KEY UPDATE level, so it never waits and never upgrades.
  for (const chunk of jsonChunks(sortedBy(rows, (r) => r.id))) {
    const locked = await tx.execute<{ id: string; status: string }>(sql`
      SELECT i.id, i.status
        FROM issues i
        JOIN jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid) ON i.id = r.id
       FOR NO KEY UPDATE OF i`);
    const statusBeforeUpdate = new Map(locked.rows.map((r) => [r.id, r.status]));
    for (const [id, status] of statusBeforeUpdate) seenStatus.set(id, status);
    const result = await tx.execute<{ id: string; old_value: string; new_value: string }>(sql`
      UPDATE issues AS i SET
        fingerprint = r.fingerprint, line_hash = r.line_hash, context_hash = r.context_hash,
        path = r.path, start_line = r.start_line, start_column = r.start_column,
        end_line = r.end_line, end_column = r.end_column, message = r.message,
        severity = CASE WHEN i.severity_overridden THEN i.severity ELSE r.severity END,
        quality = r.quality, kind = r.kind,
        -- Lost-update guard (U5 fix round 1, #3), mirroring the severity_overridden CASE above:
        -- only apply the planned status transition (and what follows from it) when the row's
        -- status still matches what the plan was built from; otherwise something else already
        -- changed it since, and that wins.
        status = CASE WHEN i.status = r.from_status THEN r.status ELSE i.status END,
        in_new_code = r.in_new_code,
        snippet = r.snippet, secondary_locations = r.secondary_locations,
        last_seen_analysis_id = ${analysisId},
        -- A matched row is never left 'closed', so once the guard passes closed_at always clears.
        closed_at = CASE WHEN i.status = r.from_status THEN NULL ELSE i.closed_at END,
        resolved_at = CASE WHEN i.status <> r.from_status THEN i.resolved_at
                           WHEN r.status = 'open' THEN NULL ELSE i.resolved_at END,
        resolved_by = CASE WHEN i.status <> r.from_status THEN i.resolved_by
                           WHEN r.status = 'open' THEN NULL ELSE i.resolved_by END,
        updated_at = now()
      FROM jsonb_to_recordset(${chunk}::jsonb) AS r(${sql.raw(UPDATE_RECORD)})
      WHERE i.id = r.id
      RETURNING i.id, r.from_status AS old_value, r.status AS new_value`);
    for (const row of result.rows) {
      const guardPassed = statusBeforeUpdate.get(row.id) === row.old_value;
      if (guardPassed && row.old_value !== row.new_value) {
        applied.push({
          issueId: row.id,
          oldValue: row.old_value as IssueStatus,
          newValue: row.new_value as IssueStatus,
        });
      }
    }
  }
  // The guard's verdict per row, from the same locked read: a row whose status was not the
  // planned `from_status` (or that no longer exists) kept its status.
  for (const row of rows) if (seenStatus.get(row.id) !== row.from_status) blocked.push(row.id);
  return applied;
}

async function insertNew(
  tx: Executor,
  rows: TrackingPlan['inserts'],
  ids: { projectId: string; branchId: string; analysisId: string },
): Promise<void> {
  // Sorted by rule_id for a deterministic, reproducible order — not deadlock avoidance: this is
  // an INSERT, so the only lock its FK to `rules` takes is FOR KEY SHARE, and two FOR KEY SHARE
  // locks never conflict with each other, so ordering them cannot by itself create or break a
  // lock cycle (U5 fix round 1, #6 — corrects an earlier, inaccurate comment here that claimed
  // this prevented a Postgres 40P01 deadlock). A fixed order is still worth having: it makes the
  // statement's locking (and query plan) behaviour the same from one run to the next instead of
  // depending on incidental report/array iteration order.
  for (const chunk of jsonChunks(sortedBy(rows, (r) => r.rule_id))) {
    await tx.execute(sql`
      INSERT INTO issues (id, project_id, branch_id, rule_id, fingerprint, line_hash,
        context_hash, path, start_line, start_column, end_line, end_column, message, severity,
        severity_overridden, quality, kind, status, in_new_code, snippet, secondary_locations,
        first_seen_analysis_id, first_seen_at, last_seen_analysis_id, resolved_at, resolved_by)
      SELECT r.id, ${ids.projectId}, ${ids.branchId}, r.rule_id, r.fingerprint, r.line_hash,
        r.context_hash, r.path, r.start_line, r.start_column, r.end_line, r.end_column,
        r.message, r.severity, r.severity_overridden, r.quality, r.kind, r.status, r.in_new_code,
        r.snippet, r.secondary_locations, ${ids.analysisId}, r.first_seen_at, ${ids.analysisId},
        r.resolved_at, r.resolved_by
      FROM jsonb_to_recordset(${chunk}::jsonb) AS r(${sql.raw(WRITE_RECORD)},
        severity_overridden boolean, first_seen_at timestamptz, resolved_at timestamptz,
        resolved_by uuid)`);
  }
}

/**
 * Closes the unmatched candidates and returns the closes that actually applied, same reasoning
 * as {@link updateMatched}: guarded on `from_status` (U5 fix round 2, #3), so a candidate whose
 * status already changed since the plan was built is neither closed nor logged as closed.
 */
async function closeUnmatched(
  tx: Executor,
  rows: readonly CloseWrite[],
  blocked: string[],
): Promise<StatusChange[]> {
  const applied: StatusChange[] = [];
  const closed = new Set<string>();
  // Sorted by id, like updateMatched; these rows are already held (lockPlannedRows).
  for (const chunk of jsonChunks(sortedBy(rows, (r) => r.id))) {
    const result = await tx.execute<{ id: string; old_value: string }>(sql`
      UPDATE issues AS i SET status = 'closed', closed_at = now(), duplicate_of_issue_id = NULL,
        updated_at = now()
      FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, from_status text)
      WHERE i.id = r.id AND i.status = r.from_status
      RETURNING i.id, r.from_status AS old_value`);
    for (const row of result.rows) {
      closed.add(row.id);
      applied.push({ issueId: row.id, oldValue: row.old_value as IssueStatus, newValue: 'closed' });
    }
  }
  for (const row of rows) if (!closed.has(row.id)) blocked.push(row.id);
  return applied;
}

async function logChanges(
  tx: Executor,
  changes: readonly StatusChange[],
  analysisId: string,
): Promise<void> {
  // Sorted by issue_id for the same determinism reason as insertNew: this INSERT's FK to `issues`
  // is also a FOR KEY SHARE check, not a conflicting lock.
  const rows = sortedBy(changes, (c) => c.issueId).map((c) => ({
    id: uuidv7(),
    issue_id: c.issueId,
    old_value: c.oldValue,
    new_value: c.newValue,
  }));
  for (const chunk of jsonChunks(rows)) {
    await tx.execute(sql`
      INSERT INTO issue_changes (id, issue_id, user_id, analysis_id, field, old_value, new_value)
      SELECT r.id, r.issue_id, NULL, ${analysisId}, 'status', r.old_value, r.new_value
      FROM jsonb_to_recordset(${chunk}::jsonb)
        AS r(id uuid, issue_id uuid, old_value text, new_value text)`);
  }
}

export interface WrittenPlan {
  /**
   * Ids of the updated or closed issues whose planned status transition the lost-update guard
   * blocked (or whose row was gone): their status in the database is not what `plan.live` says,
   * so cross-engine dedupe must re-read them (dedupe.ts `liveAfterWrites`).
   */
  blockedIds: string[];
}

/**
 * Locks every existing issue the plan will change — the matched set and the close set together —
 * in ONE id-ordered pass, before any write (Task 3 fix round 1). A user transition locks its
 * issues in id order too, in one statement (issues/transitions.ts), so the two can no longer
 * form a lock cycle: without this, ingestion locked the matched set, then (after the inserts)
 * the close set in a second pass, and a transition holding a closing row while waiting on a
 * matched one deadlocked with it — and Postgres could abort the whole ingestion.
 *
 * `FOR NO KEY UPDATE` is the lock every later statement here needs (no `issues` column it
 * changes is a key: the only unique index is the primary key), so none of them has to upgrade;
 * the rows the later statements touch are all held from here on — updates and closes are these
 * rows, dedupe links rewrite live rows (these plus the issues this analysis inserts, which no
 * one else can see yet), and the changelog's and `duplicate_of_issue_id`'s FK checks take
 * `FOR KEY SHARE`, which never conflicts with a transition's `FOR NO KEY UPDATE`.
 *
 * Chunked like every bulk statement (jsonChunks), the ids sorted globally first, so the chunks
 * lock in one ascending order; `ORDER BY` puts the row locks of each chunk in that order too.
 */
async function lockPlannedRows(tx: Executor, plan: TrackingPlan): Promise<void> {
  const ids = [...new Set([...plan.updates.map((r) => r.id), ...plan.closes.map((r) => r.id)])];
  ids.sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  for (const chunk of jsonChunks(ids)) {
    await tx.execute(sql`
      SELECT i.id FROM issues i
       WHERE i.id IN (SELECT jsonb_array_elements_text(${chunk}::jsonb)::uuid)
       ORDER BY i.id
         FOR NO KEY UPDATE OF i`);
  }
}

/** Applies a tracking plan: a few dozen statements even for 100k issues (bulk.ts). */
export async function writePlan(
  tx: Executor,
  plan: TrackingPlan,
  ids: { projectId: string; branchId: string; analysisId: string },
): Promise<WrittenPlan> {
  const blockedIds: string[] = [];
  await lockPlannedRows(tx, plan);
  const updateChanges = await updateMatched(tx, plan.updates, ids.analysisId, blockedIds);
  await insertNew(tx, plan.inserts, ids);
  const closeChanges = await closeUnmatched(tx, plan.closes, blockedIds);
  await logChanges(tx, [...updateChanges, ...closeChanges], ids.analysisId);
  return { blockedIds };
}
