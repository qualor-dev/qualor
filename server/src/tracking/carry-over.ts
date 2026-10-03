import { enginePriority } from '@qualor/shared';
import { sql } from 'drizzle-orm';
import { jsonChunks, uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { compareCodeUnits as compare, type DuplicateChange } from './dedupe';
import type { IssueStatus, LiveIssue } from './plan';

/** data-model.md §5.3 (plan 6B-1): engines whose new root issues take a triaged duplicate's status. */
export const STATUS_CARRYING_ENGINES: ReadonlySet<string> = new Set(['qualor']);

/** The statuses carried over, in precedence order. */
const CARRIED = ['false_positive', 'wont_fix'] as const;
type CarriedStatus = (typeof CARRIED)[number];

/**
 * The longest changelog comment, in code points: the `issue_changes` check is
 * `char_length(comment) <= 2000` (routes/issues.ts accepts at most 2,000 characters).
 */
export const CARRY_OVER_COMMENT_CHARS = 2_000;

export interface CarryOver {
  issueId: string;
  status: CarriedStatus;
  sourceIssueId: string;
  sourceRuleKey: string;
}

const carried = (s: IssueStatus): s is CarriedStatus => (CARRIED as readonly string[]).includes(s);

/**
 * data-model.md §5.3 (plan 6B-1), without I/O. For each issue this analysis created (`createdIds`:
 * the inserts not inherited from a reference branch, data-model.md §5.4 — an inherited copy keeps
 * the reference issue's status, so a reopen there is never undone on a new branch or MR)
 * of a status-carrying engine that is open and stays a root once `changes` (planDedupe's) are
 * applied over the pointers in `live`: the triaged duplicate of another engine whose status it
 * takes. `false_positive` before `wont_fix`, then the higher-priority engine, the lower rule key,
 * the lower id. Sorted by issue id.
 */
export function planCarryOver(
  live: readonly LiveIssue[],
  changes: readonly DuplicateChange[],
  createdIds: ReadonlySet<string>,
): CarryOver[] {
  const pointer = new Map(live.map((i) => [i.id, i.duplicateOfIssueId]));
  for (const c of changes) pointer.set(c.id, c.duplicateOf);
  const sources = new Map<string, LiveIssue[]>();
  for (const issue of live) {
    const primary = pointer.get(issue.id) ?? null;
    if (primary === null || !carried(issue.status)) continue;
    sources.set(primary, [...(sources.get(primary) ?? []), issue]);
  }
  const out: CarryOver[] = [];
  for (const root of live) {
    if (!createdIds.has(root.id) || root.status !== 'open') continue;
    if (!STATUS_CARRYING_ENGINES.has(root.engineId)) continue;
    if ((pointer.get(root.id) ?? null) !== null) continue;
    const best = (sources.get(root.id) ?? [])
      .filter((s) => s.engineId !== root.engineId)
      .sort(
        (a, b) =>
          CARRIED.indexOf(a.status as CarriedStatus) - CARRIED.indexOf(b.status as CarriedStatus) ||
          enginePriority(b.engineId) - enginePriority(a.engineId) ||
          compare(a.ruleKey, b.ruleKey) ||
          compare(a.id, b.id),
      )[0];
    if (best === undefined) continue;
    out.push({
      issueId: root.id,
      status: best.status as CarriedStatus,
      sourceIssueId: best.id,
      sourceRuleKey: best.ruleKey,
    });
  }
  return out.sort((a, b) => compare(a.issueId, b.issueId));
}

/**
 * The changelog comment of a carried status: the source rule, then the source's own comment. Cut
 * by code points, like the database counts them, so a surrogate pair is never split (a lone
 * surrogate in the jsonb parameter would make Postgres reject the whole analysis's write).
 */
export function carryOverComment(sourceRuleKey: string, sourceComment: string | null): string {
  const note = `Status carried over from ${sourceRuleKey}.`;
  const text =
    sourceComment === null || sourceComment.trim() === '' ? note : `${note} ${sourceComment}`;
  const points = Array.from(text);
  return points.length <= CARRY_OVER_COMMENT_CHARS
    ? text
    : `${points.slice(0, CARRY_OVER_COMMENT_CHARS - 1).join('')}…`;
}

/**
 * Writes {@link planCarryOver}'s statuses. Each new issue takes its source's status, `resolved_at`
 * and `resolved_by`, guarded on the source still having the planned status and the new issue still
 * being `open`, and gets one system changelog entry (no user, this analysis, `open` → the status)
 * quoting the comment of the source's latest change to that status. The new issues were inserted
 * by this same transaction, so no one else can hold them. No audit event: the tracking stage
 * records none for system changes. Returns how many applied.
 */
export async function writeCarryOver(
  tx: Executor,
  carry: readonly CarryOver[],
  analysisId: string,
): Promise<number> {
  if (carry.length === 0) return 0;
  const sourceIds = [...new Set(carry.map((c) => c.sourceIssueId))].sort(compare);
  const sources = await tx.execute<{
    id: string;
    status: string;
    resolved_at: string | null;
    resolved_by: string | null;
    comment: string | null;
  }>(sql`
    SELECT i.id, i.status, to_json(i.resolved_at) #>> '{}' AS resolved_at, i.resolved_by,
      (SELECT ic.comment FROM issue_changes ic
        WHERE ic.issue_id = i.id AND ic.field = 'status' AND ic.new_value = i.status
        ORDER BY ic.id DESC LIMIT 1) AS comment
      FROM issues i
     WHERE i.id IN ${uuidList(sourceIds)}`);
  const byId = new Map(sources.rows.map((r) => [r.id, r]));
  const rows = carry.flatMap((c) => {
    const s = byId.get(c.sourceIssueId);
    // A source whose status changed since planning (a concurrent reopen: sources are not locked)
    // carries nothing, rather than another status's resolution fields or comment.
    return s === undefined || s.status !== c.status
      ? []
      : [
          {
            id: c.issueId,
            status: c.status,
            resolved_at: s.resolved_at,
            resolved_by: s.resolved_by,
            comment: carryOverComment(c.sourceRuleKey, s.comment),
          },
        ];
  });
  let applied = 0;
  for (const chunk of jsonChunks(rows)) {
    const updated = await tx.execute<{ id: string; status: string; comment: string }>(sql`
      UPDATE issues AS i
         SET status = r.status, resolved_at = r.resolved_at, resolved_by = r.resolved_by,
             updated_at = now()
        FROM jsonb_to_recordset(${chunk}::jsonb)
          AS r(id uuid, status text, resolved_at timestamptz, resolved_by uuid, comment text)
       WHERE i.id = r.id AND i.status = 'open'
      RETURNING i.id, r.status, r.comment`);
    const changes = updated.rows
      .map((u) => ({ id: uuidv7(), issue_id: u.id, new_value: u.status, comment: u.comment }))
      .sort((a, b) => compare(a.issue_id, b.issue_id));
    for (const part of jsonChunks(changes)) {
      await tx.execute(sql`
        INSERT INTO issue_changes (id, issue_id, user_id, analysis_id, field, old_value, new_value, comment)
        SELECT r.id, r.issue_id, NULL, ${analysisId}, 'status', 'open', r.new_value, r.comment
          FROM jsonb_to_recordset(${part}::jsonb)
            AS r(id uuid, issue_id uuid, new_value text, comment text)`);
    }
    applied += updated.rows.length;
  }
  return applied;
}
