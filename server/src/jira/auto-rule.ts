import { and, asc, eq, isNotNull, or, sql, type SQL } from 'drizzle-orm';
import { textList, uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import {
  jiraConnections,
  projectJiraSettings,
  projects,
  type JiraAutoSeverity,
} from '../db/schema';
import { compare, SEVERITIES } from '../vulnerabilities/order';
import { IS_NEW, scopedRows } from '../vulnerabilities/summary';
import { trackedTargets, type Target } from '../vulnerabilities/targets';
import { sameAddress } from './connection';
import { insertPendingLinks, pairKey, type LinkTarget } from './links';
import type { JiraMappingRow } from './mapping';
import type { VulnerabilityPair } from './presence';
import type { JiraRunContext } from './run';

/**
 * spec §6.6: the automatic rule makes at most this many links per organisation per pass; the rest
 * qualify again in the next pass, so a day's burst spreads over hours.
 */
export const AUTO_PER_PASS = 50;

/** The severities at or above `min`, worst first: never `unknown` (spec §6.6). */
export const atOrAbove = (min: JiraAutoSeverity): string[] =>
  SEVERITIES.slice(0, SEVERITIES.indexOf(min) + 1);

/** A {@link scopedRows} condition: the row is on one of the targets. */
export function onTargets(targets: readonly Target[]): SQL {
  const branchIds = targets.flatMap((t) => (t.kind === 'branch' ? [t.branchId] : []));
  const versionIds = targets.flatMap((t) => (t.kind === 'version' ? [t.versionId] : []));
  return sql`(tv.branch_id IN ${uuidList(branchIds)} OR tv.version_id IN ${uuidList(versionIds)})`;
}

/**
 * The rows that make their pair qualify, as conditions on a {@link scopedRows} row that is
 * effective-open and not ignored. New is the Vulnerabilities tab's own (`IS_NEW`: first seen after
 * its target's baseline) and at or after `since`. Severe: new, at or above `min`. Exploited: in
 * the KEV catalogue, not delisted, with CISA's `date_added` on or after the UTC day of `since` (not
 * Qualor's `listed_at`, which a refilled table sets to now), or new. The automatic fix mode uses
 * it as it is (0.16 fix MRs §6.3, ruling F23).
 */
export function qualifyingRow(min: JiraAutoSeverity | null, exploited: boolean, since: Date): SQL {
  const at = sql`${since.toISOString()}::timestamptz`;
  const fresh = sql`(${IS_NEW} AND first_seen_at >= ${at})`;
  const severe =
    min === null ? sql`false` : sql`(${fresh} AND severity IN ${textList(atOrAbove(min))})`;
  const listed = exploited
    ? sql`(kev AND (kev_date_added >= to_char(${at} AT TIME ZONE 'UTC', 'YYYY-MM-DD') OR ${fresh}))`
    : sql`false`;
  return sql`(${severe} OR ${listed})`;
}

/**
 * spec §6.6: the project's pairs the mapping's rule qualifies now, at most `limit`, the pair with
 * the oldest qualifying row first. A pair qualifies with a row on a tracked target
 * (`trackedTargets`: none while monitoring is off for the instance or the project) that is not
 * ignored, whose effective decision is open and that is new and severe or exploited
 * ({@link qualifyingRow}), and no link row in any state (`dismissed` included). `exploited` is the
 * rule's own as it applies now: stored and `vuln.priority` active.
 */
export async function qualifyingPairs(
  db: Executor,
  mapping: JiraMappingRow,
  options: { exploited: boolean; limit: number },
): Promise<VulnerabilityPair[]> {
  const { projectId, autoMinSeverity: min, autoSince: since } = mapping;
  if (since === null || options.limit <= 0 || (min === null && !options.exploited)) return [];
  const targets = await trackedTargets(db, projectId);
  if (targets.length === 0) return [];
  const found = await db.execute<{ package_name: string; vulnerability_id: string }>(sql`
    SELECT package_name, vulnerability_id
      FROM (${scopedRows(sql`tv.project_id = ${projectId} AND ${onTargets(targets)}`)}) r
     WHERE eff_status = 'open' AND NOT ignored
       AND ${qualifyingRow(min, options.exploited, since)}
       AND NOT EXISTS (
         SELECT 1 FROM jira_links l
          WHERE l.project_id = ${projectId} AND l.kind = 'vulnerability'
            AND l.package_name = r.package_name AND l.vulnerability_id = r.vulnerability_id)
     GROUP BY package_name, vulnerability_id
     ORDER BY min(first_seen_at), package_name COLLATE "C", vulnerability_id COLLATE "C"
     LIMIT ${options.limit}`);
  return found.rows.map((r) => ({
    packageName: r.package_name,
    vulnerabilityId: r.vulnerability_id,
  }));
}

/**
 * The connection's projects whose rule is on, as it applies now (an `exploited`-only rule needs
 * `vuln.priority`): the rule switched on longest ago first.
 */
async function ruleProjects(ctx: JiraRunContext, priority: boolean): Promise<string[]> {
  const s = projectJiraSettings;
  const rows = await ctx.deps.db
    .select({ projectId: s.projectId })
    .from(s)
    .where(
      and(
        eq(s.connectionId, ctx.connection.id),
        isNotNull(s.autoSince),
        priority
          ? or(isNotNull(s.autoMinSeverity), eq(s.autoExploited, true))
          : isNotNull(s.autoMinSeverity),
      ),
    )
    .orderBy(asc(s.autoSince), asc(s.projectId));
  return rows.map((r) => r.projectId);
}

/**
 * The project's qualifying pairs made pending rows (`origin` auto, no `created_by`, no audit) in
 * one transaction. It takes the links route's lock order (the project row, then the connection
 * row), then the mapping row shared: a save or removal of the mapping waits, so the rows are those
 * of the rule as stored. A pair linked meanwhile makes none (`ON CONFLICT DO NOTHING`); the rows
 * are written by pair, the route's order, so the two never deadlock. Returns how many it made, or
 * null when the connection is gone or has another address than the run's (M1: the rows of a new
 * site are not the old run's to make).
 */
function linkProject(
  ctx: JiraRunContext,
  projectId: string,
  options: { priority: boolean; limit: number },
): Promise<number | null> {
  return ctx.deps.db.transaction(async (tx) => {
    await tx
      .select({ id: projects.id })
      .from(projects)
      .where(eq(projects.id, projectId))
      .for('key share');
    const [connection] = await tx
      .select({
        id: jiraConnections.id,
        deployment: jiraConnections.deployment,
        siteUrl: jiraConnections.siteUrl,
        apiUrl: jiraConnections.apiUrl,
      })
      .from(jiraConnections)
      .where(eq(jiraConnections.id, ctx.connection.id))
      .for('key share');
    if (!connection || !sameAddress(connection, ctx.connection)) return null;
    const [mapping] = await tx
      .select()
      .from(projectJiraSettings)
      .where(eq(projectJiraSettings.projectId, projectId))
      .for('share');
    if (!mapping || mapping.connectionId !== connection.id) return 0;
    const exploited = options.priority && mapping.autoExploited;
    const targets: LinkTarget[] = (
      await qualifyingPairs(tx, mapping, { exploited, limit: options.limit })
    )
      .map((p) => ({ kind: 'vulnerability' as const, ...p }))
      .sort((a, b) =>
        compare(
          pairKey(a.packageName, a.vulnerabilityId),
          pairKey(b.packageName, b.vulnerabilityId),
        ),
      );
    if (targets.length === 0) return 0;
    const made = await insertPendingLinks(
      tx,
      { projectId, connectionId: connection.id, userId: null },
      targets,
    );
    return made.length;
  });
}

/**
 * spec §6.5 step 3, §6.6: the automatic rule of the organisation's mapped projects, at most `cap`
 * new links in all (counted across its projects). It calls no Jira: the pass's create step sends
 * the rows (ruling P5). A stored `exploited` applies only while `vuln.priority` is active.
 * Returns how many links it made.
 */
export async function runAutoRule(ctx: JiraRunContext, cap = AUTO_PER_PASS): Promise<number> {
  const { priority } = ctx.deps.limits().vulnerabilities;
  let made = 0;
  for (const projectId of await ruleProjects(ctx, priority)) {
    if (made >= cap) break;
    const n = await linkProject(ctx, projectId, { priority, limit: cap - made });
    if (n === null) break;
    made += n;
  }
  return made;
}
