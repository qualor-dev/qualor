import { eq, gt, or, sql, type SQL } from 'drizzle-orm';
import { uuidList } from '../db/bulk';
import type { Db } from '../db/client';
import { pgErrorCode } from '../db/errors';
import { instanceSettings, projects } from '../db/schema';
import { analysisConcurrencyKey } from '../ingest/service';
import { branchMatcher } from '../versions/branches';
import { vulnerabilitySettingsOf } from '../versions/settings';
import { CLEANUP_SETTINGS_KEY, effectiveCleanup, readCleanupDefaults } from './settings';

/** Rows per DELETE: each batch is its own short transaction. */
export const CLEANUP_BATCH = 500;

export interface CleanupCounts {
  branches: number;
  mergeRequests: number;
}

type CleanupKind = 'branch' | 'merge_request';

/** A project with at least one rule in force, and the stored settings that rule came from. */
interface ProjectPlan {
  id: string;
  /** The project's own values, as stored. */
  branchesDays: number | null;
  mergeRequestsDays: number | null;
  keepBranches: string[];
  /** The vulnerability-monitoring branch patterns, whether monitoring is on or off. */
  trackedPatterns: string[];
  /** The rules in force: the days of each kind, null while it is off. */
  rules: { kind: CleanupKind; days: number }[];
}

/** What one run deletes by: every setting it read, from one snapshot. */
export interface CleanupPlan {
  /** Inactivity is measured up to this time. */
  now: Date;
  /** The stored `cleanup` row of the server defaults, null while there is none. */
  storedDefaults: unknown;
  projects: ProjectPlan[];
}

/**
 * Reads the settings of a run in one read-only snapshot: the server defaults (as stored and as
 * read), the projects with a rule in force and their tracked patterns. `now` defaults to the
 * database clock, as every other housekeeping step.
 */
export function readCleanupPlan(db: Db, now?: Date): Promise<CleanupPlan> {
  return db.transaction(
    async (tx) => {
      const clock = await tx.execute<{ now: Date | string }>(sql`SELECT now() AS now`);
      const [stored] = await tx
        .select({ value: instanceSettings.value })
        .from(instanceSettings)
        .where(eq(instanceSettings.key, CLEANUP_SETTINGS_KEY));
      const defaults = await readCleanupDefaults(tx);
      const anyDefault = defaults.branchesDays !== null || defaults.mergeRequestsDays !== null;
      const rows = await tx
        .select({
          id: projects.id,
          cleanupBranchesDays: projects.cleanupBranchesDays,
          cleanupMergeRequestsDays: projects.cleanupMergeRequestsDays,
          cleanupKeepBranches: projects.cleanupKeepBranches,
        })
        .from(projects)
        // Without a server default, only a project's own days can put a rule in force.
        .where(
          anyDefault
            ? undefined
            : or(gt(projects.cleanupBranchesDays, 0), gt(projects.cleanupMergeRequestsDays, 0)),
        )
        .orderBy(projects.id);
      const ruled = rows.flatMap((row) => {
        const effective = effectiveCleanup(row, defaults);
        const rules: ProjectPlan['rules'] = [];
        if (effective.branchesDays !== null) {
          rules.push({ kind: 'branch', days: effective.branchesDays });
        }
        if (effective.mergeRequestsDays !== null) {
          rules.push({ kind: 'merge_request', days: effective.mergeRequestsDays });
        }
        return rules.length === 0 ? [] : [{ row, rules }];
      });
      const monitoring = await vulnerabilitySettingsOf(
        tx,
        ruled.map(({ row }) => row.id),
      );
      return {
        now: now ?? new Date(clock.rows[0]?.now ?? Date.now()),
        storedDefaults: stored?.value ?? null,
        projects: ruled.map(({ row, rules }) => ({
          id: row.id,
          branchesDays: row.cleanupBranchesDays,
          mergeRequestsDays: row.cleanupMergeRequestsDays,
          keepBranches: [...row.cleanupKeepBranches],
          trackedPatterns: [...(monitoring.get(row.id)?.branchPatterns ?? [])],
          rules,
        })),
      };
    },
    { isolationLevel: 'repeatable read', accessMode: 'read only' },
  );
}

/**
 * True while the settings the plan read are still those stored: the project's own values and
 * keep patterns, its tracked patterns and the server defaults. A batch after a change deletes
 * nothing; the next run decides by the new settings.
 */
function settingsUnchanged(plan: CleanupPlan, project: ProjectPlan): SQL {
  return sql`EXISTS (
      SELECT 1 FROM projects p
       WHERE p.id = ${project.id}
         AND p.cleanup_branches_days IS NOT DISTINCT FROM ${project.branchesDays}::integer
         AND p.cleanup_merge_requests_days IS NOT DISTINCT FROM ${project.mergeRequestsDays}::integer
         AND to_jsonb(p.cleanup_keep_branches) = ${JSON.stringify(project.keepBranches)}::jsonb
         AND to_jsonb(coalesce(
               (SELECT v.branch_patterns FROM project_vulnerability_settings v
                 WHERE v.project_id = p.id), '{}'::text[]))
             = ${JSON.stringify(project.trackedPatterns)}::jsonb)
    AND (SELECT s.value FROM instance_settings s WHERE s.key = ${CLEANUP_SETTINGS_KEY})
        IS NOT DISTINCT FROM ${plan.storedDefaults === null ? null : JSON.stringify(plan.storedDefaults)}::jsonb`;
}

/**
 * Deletes the rows `ids` of one project and kind that are still inactive, in one statement. A
 * branch delete cascades to its analyses (and so their measures, files, dependencies and stored
 * reports), its issues (and their changes, Jira and Boards links, AI findings), its vulnerability
 * rows, review snapshots, runs and replies, as `DELETE /branches/{id}` does; project versions,
 * version dependencies, issue changes and compliance reports that point at it only lose the
 * pointer (SET NULL). No foreign key restricts the delete. Kept, and never deleted here:
 * - a row another transaction holds (`SKIP LOCKED`): an ingestion holds its branch row from its
 *   upsert to its commit, and an insert of a row that refers to it holds it for its key check;
 * - every row of a project while an analysis or gate re-evaluation of it waits or runs: an upload
 *   names its branch only in the report the job reads (ruling R3), so a queued one may be for any;
 * - a branch whose analysis a project version takes its inventory from (a label version from a
 *   once-tracked branch): its compliance report reads the revision and the date from it;
 * - a branch with an issue linked to a Jira issue or an Azure Boards work item (only main or
 *   tracked branches carry them, `issueLinkable`): the link is the one record of that ticket;
 * - a merge request whose AI review run or reply is still to finish (its job reads the row).
 */
async function deleteBatch(
  db: Db,
  plan: CleanupPlan,
  project: ProjectPlan,
  kind: CleanupKind,
  cutoff: SQL,
  ids: readonly string[],
): Promise<number> {
  try {
    const result = await db.execute(sql`
      DELETE FROM branches WHERE id IN (
        SELECT b.id FROM branches b
         WHERE b.id IN ${uuidList(ids)}
           AND b.project_id = ${project.id} AND b.kind = ${kind} AND NOT b.is_main
           AND b.last_analyzed_at < ${cutoff}
           AND ${settingsUnchanged(plan, project)}
           AND NOT EXISTS (
                 SELECT 1 FROM jobs j
                  WHERE j.concurrency_key = ${analysisConcurrencyKey(project.id)}
                    AND j.status IN ('queued', 'running'))
           AND NOT EXISTS (
                 SELECT 1 FROM analyses a JOIN project_versions v ON v.analysis_id = a.id
                  WHERE a.branch_id = b.id)
           AND NOT EXISTS (
                 SELECT 1 FROM jira_links l JOIN issues i ON i.id = l.issue_id
                  WHERE l.project_id = b.project_id AND i.branch_id = b.id)
           AND NOT EXISTS (
                 SELECT 1 FROM boards_links l JOIN issues i ON i.id = l.issue_id
                  WHERE l.project_id = b.project_id AND i.branch_id = b.id)
           AND NOT EXISTS (
                 SELECT 1 FROM review_runs r
                  WHERE r.branch_id = b.id AND r.status IN ('waiting', 'running'))
           AND NOT EXISTS (
                 SELECT 1 FROM review_replies r
                  WHERE r.branch_id = b.id AND r.status IN ('queued', 'running'))
         FOR UPDATE OF b SKIP LOCKED)`);
    return result.rowCount ?? 0;
  } catch (err) {
    // A deadlock with a transaction that locked a row of the cascade first (a user's issue
    // transition, say) and then wants the branch: this batch is left to the next run.
    if (pgErrorCode(err) !== '40P01') throw err;
    return 0;
  }
}

/**
 * One rule of one project: walks its inactive rows by id, CLEANUP_BATCH at a time, so a page full
 * of kept branches never hides the ones behind it. Branches matching a tracked or a keep pattern
 * are left out with the monitoring patterns' matcher; merge requests go by inactivity alone.
 */
async function cleanRule(
  db: Db,
  plan: CleanupPlan,
  project: ProjectPlan,
  rule: ProjectPlan['rules'][number],
): Promise<number> {
  const kept =
    rule.kind === 'branch'
      ? branchMatcher([...project.trackedPatterns, ...project.keepBranches])
      : () => false;
  const cutoff = sql`(${plan.now}::timestamptz - make_interval(days => ${rule.days}))`;
  let total = 0;
  let after: string | null = null;
  for (;;) {
    const from: SQL = after === null ? sql`` : sql`AND b.id > ${after}`;
    const { rows } = await db.execute<{ id: string; name: string }>(sql`
      SELECT b.id, b.name FROM branches b
       WHERE b.project_id = ${project.id} AND b.kind = ${rule.kind} AND NOT b.is_main
         AND b.last_analyzed_at < ${cutoff}
         ${from}
       ORDER BY b.id
       LIMIT ${CLEANUP_BATCH}`);
    const ids = rows.filter((row) => !kept(row.name)).map((row) => row.id);
    if (ids.length > 0) total += await deleteBatch(db, plan, project, rule.kind, cutoff, ids);
    const last = rows.at(-1);
    if (rows.length < CLEANUP_BATCH || last === undefined) return total;
    after = last.id;
  }
}

/** Deletes what the plan's rules reach, project by project. */
export async function applyCleanupPlan(db: Db, plan: CleanupPlan): Promise<CleanupCounts> {
  const counts: CleanupCounts = { branches: 0, mergeRequests: 0 };
  for (const project of plan.projects) {
    for (const rule of project.rules) {
      const n = await cleanRule(db, plan, project, rule);
      if (rule.kind === 'branch') counts.branches += n;
      else counts.mergeRequests += n;
    }
  }
  return counts;
}

/**
 * Issue #38, the daily housekeeping step: in each project with a rule in force, deletes the
 * branches (never the main one, nor one matching a tracked or a keep pattern) and the merge
 * requests whose last analysis is older than the rule's days. A row never analysed is left to the
 * retention of branches without an analysis. Off by default: with no server default and no
 * project value, it reads the settings and deletes nothing. Not audited, as every retention
 * deletion; the housekeeping run logs the counts.
 */
export async function cleanInactiveBranches(db: Db, now?: Date): Promise<CleanupCounts> {
  return applyCleanupPlan(db, await readCleanupPlan(db, now));
}
