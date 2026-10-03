import {
  effectiveCwe,
  enginePriority,
  equivalentPartners,
  sameEnginePrimaries,
  sameEngineRank,
} from '@qualor/shared';
import { and, eq, ne, sql } from 'drizzle-orm';
import { jsonChunks, uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { issues, rules } from '../db/schema';
import type { IssueStatus, LiveIssue } from './plan';

/** Code-unit order, the same as `sortedBy` in writes.ts (not locale-dependent). */
function compareCodeUnits(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0;
}

export interface DuplicateChange {
  id: string;
  duplicateOf: string | null;
}

/** A root (an issue that is not a duplicate) of one (path, start line) group. */
interface Root {
  /** Its position in the group's priority order: lower is higher priority. */
  order: number;
  id: string;
  engineId: string;
}

/**
 * The earliest root carrying some index key, and the earliest one whose engine differs from it.
 * Whatever an issue's engine, the earliest root of *another* engine with that key is one of these
 * two, so a lookup is O(1).
 */
interface EarliestRoots {
  first: Root;
  second: Root | null;
}

function register<K>(index: Map<K, EarliestRoots>, key: K, root: Root): void {
  const at = index.get(key);
  if (!at) index.set(key, { first: root, second: null });
  else if (!at.second && at.first.engineId !== root.engineId) at.second = root;
}

function earliestOtherEngine<K>(
  index: ReadonlyMap<K, EarliestRoots>,
  key: K,
  engineId: string,
): Root | null {
  const at = index.get(key);
  if (!at) return null;
  return at.first.engineId !== engineId ? at.first : at.second;
}

const earlier = (a: Root | null, b: Root | null): Root | null =>
  !a ? b : !b ? a : a.order <= b.order ? a : b;

/**
 * data-model.md §5.3: among the branch's issues that are not closed, two on the same path and
 * start line are duplicates when their rules are equivalent: from different engines with a shared
 * CWE or a curated cross-engine pair, or from one engine with a curated same-engine pair (plan 6A;
 * within one engine the CWE never matches). Across engines the issue of the higher-priority
 * engine is primary; in a same-engine pair the core rule is primary. The other points at it.
 * Recomputed from scratch on every analysis, so a duplicate whose primary was closed is promoted
 * automatically (its pointer becomes null, its status is untouched). Returns only the issues
 * whose `duplicate_of_issue_id` must change.
 *
 * Each group is walked in priority order (engine, then the same-engine rank of the rule); an
 * issue points at the highest-priority earlier root it is equivalent to, or becomes a root
 * itself. Roots are indexed by CWE and by rule key, so the matching roots are looked up (one per
 * CWE of the issue and per curated partner of its rule), never scanned: O(N log N) for N issues,
 * even when a minified file puts them all on one line.
 */
export function planDedupe(live: readonly LiveIssue[]): DuplicateChange[] {
  const groups = new Map<string, LiveIssue[]>();
  const primaryOf = new Map<string, string | null>();
  for (const issue of live) {
    primaryOf.set(issue.id, null);
    if (issue.path === null || issue.startLine === null) continue;
    const key = `${issue.path}\u0000${issue.startLine}`;
    const group = groups.get(key);
    if (group) group.push(issue);
    else groups.set(key, [issue]);
  }
  // effectiveCwe depends only on the engine and the rule's own CWE list: computed once per rule.
  const cweCache = new Map<string, readonly number[]>();
  const cweOf = (issue: LiveIssue): readonly number[] => {
    const key = `${issue.engineId}\u0000${issue.cwe.join(',')}`;
    let cwe = cweCache.get(key);
    if (!cwe) {
      cwe = effectiveCwe({ key: issue.ruleKey, engineId: issue.engineId, cwe: issue.cwe });
      cweCache.set(key, cwe);
    }
    return cwe;
  };
  for (const group of groups.values()) {
    if (group.length < 2) continue;
    group.sort(
      (a, b) =>
        enginePriority(b.engineId) - enginePriority(a.engineId) ||
        compareCodeUnits(a.engineId, b.engineId) ||
        sameEngineRank(b.ruleKey) - sameEngineRank(a.ruleKey) ||
        compareCodeUnits(a.id, b.id),
    );
    const byCwe = new Map<number, EarliestRoots>();
    const byRuleKey = new Map<string, EarliestRoots>();
    group.forEach((issue, order) => {
      const cwe = cweOf(issue);
      let primary: Root | null = null;
      for (const c of cwe)
        primary = earlier(primary, earliestOtherEngine(byCwe, c, issue.engineId));
      for (const partner of equivalentPartners(issue.ruleKey)) {
        primary = earlier(primary, earliestOtherEngine(byRuleKey, partner, issue.engineId));
      }
      // Plan 6A: a curated same-engine pair; its primary was walked first (the sort above).
      for (const key of sameEnginePrimaries(issue.ruleKey)) {
        primary = earlier(primary, byRuleKey.get(key)?.first ?? null);
      }
      if (primary) {
        primaryOf.set(issue.id, primary.id);
        return;
      }
      const root: Root = { order, id: issue.id, engineId: issue.engineId };
      for (const c of cwe) register(byCwe, c, root);
      register(byRuleKey, issue.ruleKey, root);
    });
  }
  return live
    .filter((issue) => (primaryOf.get(issue.id) ?? null) !== issue.duplicateOfIssueId)
    .map((issue) => ({ id: issue.id, duplicateOf: primaryOf.get(issue.id) ?? null }));
}

/**
 * The branch's issues that are not closed as they really are after `writePlan`: `live` is what
 * the plan intended, which differs for every row whose transition the lost-update guard blocked
 * (`blockedIds`). Those rows are re-read — a blocked close is still live with its current
 * pointer, a blocked reopen stays closed and drops out — so dedupe never promotes the duplicates
 * of a primary that is in fact still open, nor points at one that is in fact closed.
 */
export async function liveAfterWrites(
  tx: Executor,
  live: readonly LiveIssue[],
  blockedIds: readonly string[],
): Promise<LiveIssue[]> {
  if (blockedIds.length === 0) return [...live];
  const blocked = new Set(blockedIds);
  const current = await tx
    .select({
      id: issues.id,
      engineId: rules.engineId,
      ruleKey: rules.key,
      cwe: rules.cwe,
      path: issues.path,
      startLine: issues.startLine,
      status: issues.status,
      duplicateOfIssueId: issues.duplicateOfIssueId,
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .where(and(sql`${issues.id} IN ${uuidList([...blocked])}`, ne(issues.status, 'closed')));
  return [
    ...live.filter((issue) => !blocked.has(issue.id)),
    ...current.map((r) => ({ ...r, status: r.status as IssueStatus })),
  ];
}

/** Writes {@link planDedupe}'s changes, sorted by id like the other row-locking writes (writes.ts). */
export async function writeDedupe(
  tx: Executor,
  changes: readonly DuplicateChange[],
): Promise<void> {
  const rows = [...changes]
    .sort((a, b) => compareCodeUnits(a.id, b.id))
    .map((c) => ({ id: c.id, duplicate_of: c.duplicateOf }));
  for (const chunk of jsonChunks(rows)) {
    await tx.execute(sql`
      UPDATE issues AS i SET duplicate_of_issue_id = r.duplicate_of, updated_at = now()
      FROM jsonb_to_recordset(${chunk}::jsonb) AS r(id uuid, duplicate_of uuid)
      WHERE i.id = r.id`);
  }
}
