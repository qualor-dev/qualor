import { and, asc, eq, ne, sql, type SQL } from 'drizzle-orm';
import type { Report, Severity } from '@qualor/shared';
import { jsonChunks } from '../db/bulk';
import type { Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { branches, issues, rules } from '../db/schema';
import type { AcceptedFinding } from '../ingest/state';
import { matchFindings, renamer } from './match';
import {
  candidateTrackable,
  findingTrackable,
  type CandidateIssue,
  type InheritedIssue,
  type IssueInsert,
  type IssueStatus,
} from './plan';

type BranchRow = typeof branches.$inferSelect;

/**
 * data-model.md §5.4: the branch a first analysis inherits from — a merge request's target
 * branch, or the project's main branch for any other non-main branch. Null for the main branch
 * itself, and when the reference branch does not exist (yet).
 */
export async function referenceBranchId(tx: Executor, branch: BranchRow): Promise<string | null> {
  if (branch.isMain) return null;
  const condition =
    branch.kind === 'merge_request'
      ? branch.mrTargetBranch === null
        ? undefined
        : and(eq(branches.kind, 'branch'), eq(branches.name, branch.mrTargetBranch))
      : eq(branches.isMain, true);
  if (!condition) return null;
  const [ref] = await tx
    .select({ id: branches.id })
    .from(branches)
    .where(and(eq(branches.projectId, branch.projectId), condition));
  return ref && ref.id !== branch.id ? ref.id : null;
}

/**
 * data-model.md §5.4: a branch inherits only while it has no issue at all (of any status, however
 * old) and no previous analysis. The analysis row alone is not enough: retention or a deleted
 * analysis can null `last_analysis_id` on a branch that already has issues, and inheriting again
 * would undo what users changed on the branch since.
 */
export async function branchHasIssues(tx: Executor, branchId: string): Promise<boolean> {
  const result = await tx.execute(
    sql`SELECT 1 FROM ${issues} WHERE ${issues.branchId} = ${branchId} LIMIT 1`,
  );
  return result.rows.length > 0;
}

export interface ReferenceIssue extends CandidateIssue {
  firstSeenAt: Date;
  resolvedAt: Date | null;
  resolvedBy: string | null;
}

/** The reference branch's issues that are not closed. */
export async function loadReferenceIssues(
  tx: Executor,
  branchId: string,
): Promise<ReferenceIssue[]> {
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
      firstSeenAt: issues.firstSeenAt,
      resolvedAt: issues.resolvedAt,
      resolvedBy: issues.resolvedBy,
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .where(and(eq(issues.branchId, branchId), ne(issues.status, 'closed')))
    // Same stable order as loadCandidates (writes.ts), so which of two indistinguishable
    // reference issues a finding inherits from does not depend on the database's row order.
    .orderBy(asc(issues.startLine), asc(issues.startColumn), asc(issues.id));
  return rows.map((r) => ({
    ...r,
    status: r.status as IssueStatus,
    severity: r.severity as Severity,
    // Only closed issues have a pre-close status, and closed ones are never inherited.
    preCloseStatus: null,
  }));
}

/**
 * data-model.md §5.4: runs the §5.2 matching against the reference branch's issues. A match
 * passes on its `wont_fix`/`false_positive` status (with who resolved it and when),
 * `first_seen_at`, and a user severity override (ruling T5); anything else starts `open`.
 *
 * Only findings that none of the branch's own `candidates` claim take part, so a finding that
 * will match an existing issue of the branch cannot use up a reference issue another finding
 * needs. (The stage inherits only into a branch without issues, where `candidates` is empty and
 * this costs nothing; the parameter keeps the function correct on its own.)
 */
export function planInheritance(
  report: Report,
  findings: readonly AcceptedFinding[],
  reference: readonly ReferenceIssue[],
  candidates: readonly CandidateIssue[] = [],
): Map<number, InheritedIssue> {
  const rename = renamer(report.scm.renames);
  const claimed =
    candidates.length === 0
      ? new Map<number, number>()
      : matchFindings(
          findings.map(findingTrackable),
          candidates.map((c) => candidateTrackable(c, rename)),
        );
  const unclaimed = findings.flatMap((f, i) => (claimed.has(i) ? [] : [i]));
  const matched = matchFindings(
    unclaimed.map((i) => findingTrackable(findings[i] as AcceptedFinding)),
    reference.map((r) => candidateTrackable(r, rename)),
  );
  const inherited = new Map<number, InheritedIssue>();
  for (const [unclaimedIndex, referenceIndex] of matched) {
    const findingIndex = unclaimed[unclaimedIndex];
    const ref = reference[referenceIndex];
    if (findingIndex === undefined) continue;
    if (!ref) continue;
    const sticky = ref.status === 'wont_fix' || ref.status === 'false_positive';
    inherited.set(findingIndex, {
      sourceIssueId: ref.id,
      status: sticky ? (ref.status as 'wont_fix' | 'false_positive') : 'open',
      firstSeenAt: ref.firstSeenAt,
      resolvedAt: sticky ? ref.resolvedAt : null,
      resolvedBy: sticky ? ref.resolvedBy : null,
      severityOverride: ref.severityOverridden ? ref.severity : null,
    });
  }
  return inherited;
}

/** Source issues per changelog SELECT in {@link copyChangelogs}. */
export const CHANGELOG_SOURCE_CHUNK = 2_000;
/** Changelog rows per page read by {@link copyChangelogs}. */
export const CHANGELOG_PAGE_ROWS = 5_000;

type ChangeRow = {
  id: string;
  issue_id: string;
  user_id: string | null;
  analysis_id: string | null;
  field: string;
  old_value: string | null;
  new_value: string | null;
  comment: string | null;
  created_at: string;
  /** `created_at` in UTC at microsecond precision, fixed width, so it sorts as a string. */
  at: string;
};

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);
const byTime = (a: ChangeRow, b: ChangeRow): number =>
  compare(a.issue_id, b.issue_id) || compare(a.at, b.at) || compare(a.id, b.id);

/**
 * One keyset page of the source issues' changelogs for {@link copyChangelogs}, in
 * `issue_changes_issue_idx` order (issue_id, id), so the index returns it without a sort. The
 * ids go in as one `uuid[]` parameter (they are issue ids read from the database): `= ANY` over an
 * array is an index condition whose scan is ordered, where an IN-subquery (`uuidList`, db/bulk.ts)
 * becomes a hash join followed by a sort of every matching row.
 */
export function changelogPage(
  sourceIds: readonly string[],
  after: { issueId: string; id: string } | null,
  pageRows: number,
): SQL {
  const keyset =
    after === null
      ? sql``
      : sql`AND (c.issue_id, c.id) > (${after.issueId}::uuid, ${after.id}::uuid)`;
  return sql`
    SELECT c.id, c.issue_id, c.user_id, c.analysis_id, c.field, c.old_value, c.new_value,
      c.comment, to_json(c.created_at) #>> '{}' AS created_at,
      to_char(c.created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD HH24:MI:SS.US') AS at
    FROM issue_changes c
    WHERE c.issue_id = ANY (${`{${sourceIds.join(',')}}`}::uuid[]) ${keyset}
    ORDER BY c.issue_id, c.id
    LIMIT ${pageRows}`;
}

/**
 * data-model.md §5.4: "a copy of its changelog", in the original order and with its dates, the
 * source's user and `analysis_id` included.
 *
 * Bounded memory whatever the size of the reference branch: the source ids go in chunks of
 * `sourceChunk`, and each chunk's changelog is read in keyset pages of `pageRows` rows ordered by
 * (issue_id, id), which the `issue_changes_issue_idx` index returns in order, each page written
 * before the next is read. Ids and times can disagree (a row's id comes from the writing
 * server's clock, its `created_at` from the database's transaction start), so the rows of each
 * source issue are re-sorted by (created_at, id) before they are copied: a page's last issue may
 * continue on the next page, so its rows are carried over until the issue is complete (memory:
 * one page plus the longest single changelog). A copy's id is a fresh UUIDv7 made in that order,
 * and UUIDv7s made by one process only grow, so each copied changelog's id order is its
 * chronological order: `loadCandidates`' `preCloseStatus` reads the latest status change by id.
 */
export async function copyChangelogs(
  tx: Executor,
  inserts: readonly Pick<IssueInsert, 'id' | 'inherited_from'>[],
  options: { sourceChunk?: number; pageRows?: number } = {},
): Promise<void> {
  const sourceChunk = options.sourceChunk ?? CHANGELOG_SOURCE_CHUNK;
  const pageRows = options.pageRows ?? CHANGELOG_PAGE_ROWS;
  const targetOf = new Map<string, string[]>();
  for (const insert of inserts) {
    if (insert.inherited_from === null) continue;
    const targets = targetOf.get(insert.inherited_from) ?? [];
    targets.push(insert.id);
    targetOf.set(insert.inherited_from, targets);
  }
  const write = async (complete: ChangeRow[]): Promise<void> => {
    const rows = complete.sort(byTime).flatMap(({ at, ...c }) => {
      void at;
      return (targetOf.get(c.issue_id) ?? []).map((issueId) => ({
        ...c,
        id: uuidv7(),
        issue_id: issueId,
      }));
    });
    for (const chunk of jsonChunks(rows)) {
      await tx.execute(sql`
        INSERT INTO issue_changes (id, issue_id, user_id, analysis_id, field, old_value,
          new_value, comment, created_at)
        SELECT r.id, r.issue_id, r.user_id, r.analysis_id, r.field, r.old_value, r.new_value,
          r.comment, r.created_at
        FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, issue_id uuid, user_id uuid,
          analysis_id uuid, field text, old_value text, new_value text, comment text,
          created_at timestamptz)`);
    }
  };
  const sourceIds = [...targetOf.keys()].sort();
  for (let start = 0; start < sourceIds.length; start += sourceChunk) {
    const ids = sourceIds.slice(start, start + sourceChunk);
    let after: { issueId: string; id: string } | null = null;
    let carried: ChangeRow[] = [];
    for (;;) {
      const page: { rows: ChangeRow[] } = await tx.execute<ChangeRow>(
        changelogPage(ids, after, pageRows),
      );
      const last: ChangeRow | undefined = page.rows.at(-1);
      const rows = [...carried, ...page.rows];
      if (last === undefined || page.rows.length < pageRows) {
        await write(rows);
        break;
      }
      // The page is full, so its last issue may go on: hold its rows back until it is complete.
      const split = rows.findIndex((r) => r.issue_id === last.issue_id);
      carried = rows.slice(split);
      await write(rows.slice(0, split));
      after = { issueId: last.issue_id, id: last.id };
    }
  }
}
