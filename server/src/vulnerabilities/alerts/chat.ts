import { inArray, sql } from 'drizzle-orm';
import { uuidList } from '../../db/bulk';
import type { Executor } from '../../db/client';
import { projects } from '../../db/schema';
import {
  MAX_EXPLOITED_PROJECTS,
  MAX_EXPLOITED_ROWS,
  MAX_TARGET_NAMES,
  MAX_VULNERABILITY_PROJECTS,
  type ChatExploitedMessage,
  type DigestVulnerabilities,
  type ExploitedRow,
} from '../../webhooks/chat/messages';
import { clipUtf16 } from '../../webhooks/chat/text';
import { createDeliveries, type NewDelivery } from '../../webhooks/deliveries';
import { subscriptionsToNotify } from '../../webhooks/stage';
import { alertRows, type VulnerabilityMailRow } from './content';

const EVENT = 'vulnerabilities.exploited' as const;

type Project = { id: string; key: string; name: string; organizationId: string };

/** The rows of `exploited` in the message's shape; a row without a KEV entry is left out. */
function messageRows(rows: readonly VulnerabilityMailRow[]): ExploitedRow[] {
  const result: ExploitedRow[] = [];
  for (const row of rows) {
    if (row.exploited === null) continue;
    result.push({
      vulnerabilityId: row.vulnerabilityId,
      severity: row.severity,
      title: row.title === null ? null : clipUtf16(row.title, 2000),
      packageName: clipUtf16(row.packageName, 500),
      installedVersions: row.installedVersions.slice(0, 50).map((v) => clipUtf16(v, 200)),
      fixedVersion: row.fixedVersion === null ? null : clipUtf16(row.fixedVersion, 200),
      kevDateAdded: row.exploited.dateAdded,
      targets: row.targets.slice(0, 200).map((target) => clipUtf16(target, 500)),
    });
  }
  return result;
}

/**
 * The message of one webhook: the given projects (already ordered), with at most
 * MAX_EXPLOITED_ROWS rows in all and MAX_EXPLOITED_PROJECTS projects; what the caps drop is
 * counted in `more` and `moreProjects` (0.15 plan 6 C5).
 */
function exploitedMessage(
  covered: readonly { project: Project; rows: ExploitedRow[] }[],
): ChatExploitedMessage {
  let left = MAX_EXPLOITED_ROWS;
  const shown = covered.slice(0, MAX_EXPLOITED_PROJECTS).map(({ project, rows }) => {
    const keep = Math.min(left, rows.length);
    left -= keep;
    return {
      id: project.id,
      key: clipUtf16(project.key, 500),
      name: clipUtf16(project.name, 500),
      rows: rows.slice(0, keep),
      more: rows.length - keep,
    };
  });
  return {
    type: 'exploited',
    projects: shown,
    moreProjects: Math.max(0, covered.length - MAX_EXPLOITED_PROJECTS),
  };
}

/**
 * One `vulnerabilities.exploited` delivery per active Slack or Teams webhook that lists the event,
 * about the projects of `rowsOf` (the `alertRows` of the run's items, with `priority`) it covers
 * (org-wide, or its own project); the number created. A project with no KEV row left (triaged
 * since the pick) is left out, and a webhook with no project left gets nothing. The caller marks
 * the items.
 */
export async function exploitedDeliveries(
  tx: Executor,
  rowsOf: ReadonlyMap<string, VulnerabilityMailRow[]>,
): Promise<number> {
  const withRows = new Map<string, ExploitedRow[]>();
  for (const [projectId, rows] of rowsOf) {
    const mapped = messageRows(rows);
    if (mapped.length > 0) withRows.set(projectId, mapped);
  }
  if (withRows.size === 0) return 0;
  const facts = await tx
    .select({
      id: projects.id,
      key: projects.key,
      name: projects.name,
      organizationId: projects.organizationId,
    })
    .from(projects)
    .where(inArray(projects.id, uuidList([...withRows.keys()])));

  const bySubscription = new Map<string, { project: Project; rows: ExploitedRow[] }[]>();
  // In id order: the subscriptions are locked FOR KEY SHARE until this transaction commits.
  for (const project of [...facts].sort((a, b) => (a.id < b.id ? -1 : 1))) {
    const rows = withRows.get(project.id);
    if (rows === undefined) continue;
    const subscribed = (await subscriptionsToNotify(tx, project)).filter(
      (s) => (s.kind === 'slack' || s.kind === 'teams') && s.events.includes(EVENT),
    );
    for (const { id } of subscribed) {
      const list = bySubscription.get(id) ?? [];
      list.push({ project, rows });
      bySubscription.set(id, list);
    }
  }

  const deliveries: NewDelivery[] = [];
  for (const [subscriptionId, covered] of bySubscription) {
    covered.sort(
      (a, b) =>
        a.project.name.localeCompare(b.project.name, 'en') ||
        (a.project.id < b.project.id ? -1 : 1),
    );
    deliveries.push({ subscriptionId, event: EVENT, payload: exploitedMessage(covered) });
  }
  return (await createDeliveries(tx, deliveries)).length;
}

const compare = (a: string, b: string): number => (a < b ? -1 : a > b ? 1 : 0);

/**
 * The vulnerability section of the weekly digest (0.15 plan 6 C6): the High and Critical rows of
 * the items found in `[since, until)` on the scope's tracked targets (the organisation's projects,
 * or the one project), that are not baseline, still open and not ignored. Counts are rows;
 * `exploited` is null without `options.priority`. Null when no row qualifies. It only reads: the
 * alert lock is not taken (C7), one statement sees one snapshot and a `found_at` lies in one window.
 */
export async function digestVulnerabilities(
  tx: Executor,
  scope: { organizationId: string; projectId: string | null },
  window: { since: Date; until: Date },
  options: { priority: boolean },
): Promise<DigestVulnerabilities | null> {
  const projectFilter = scope.projectId === null ? sql`` : sql`AND p.id = ${scope.projectId}`;
  const items = await tx.execute<{ id: string }>(sql`
    SELECT i.id
      FROM vulnerability_alert_items i
      JOIN vulnerability_alert_targets t ON t.id = i.target_id
      JOIN projects p ON p.id = t.project_id
     WHERE p.organization_id = ${scope.organizationId} ${projectFilter}
       AND NOT i.baseline AND i.found_at >= ${window.since} AND i.found_at < ${window.until}`);
  if (items.rows.length === 0) return null;
  const rowsOf = await alertRows(
    tx,
    items.rows.map((item) => item.id),
    options,
  );
  const perProject: {
    projectId: string;
    critical: number;
    high: number;
    exploited: number;
    targets: string[];
  }[] = [];
  for (const [projectId, rows] of rowsOf) {
    const kept = rows.filter((r) => r.severity === 'critical' || r.severity === 'high');
    if (kept.length === 0) continue;
    const targets = new Set<string>();
    for (const row of kept) for (const target of row.targets) targets.add(target);
    perProject.push({
      projectId,
      critical: kept.filter((r) => r.severity === 'critical').length,
      high: kept.filter((r) => r.severity === 'high').length,
      exploited: kept.filter((r) => r.exploited !== null).length,
      targets: [...targets],
    });
  }
  if (perProject.length === 0) return null;
  const names = new Map(
    (
      await tx
        .select({ id: projects.id, name: sql<string>`left(${projects.name}, 500)` })
        .from(projects)
        .where(inArray(projects.id, uuidList(perProject.map((p) => p.projectId))))
    ).map((p) => [p.id, p.name]),
  );
  const named = perProject.map((p) => ({ ...p, name: names.get(p.projectId) ?? '' }));
  named.sort(
    (a, b) =>
      b.exploited - a.exploited ||
      b.critical - a.critical ||
      b.high - a.high ||
      a.name.localeCompare(b.name, 'en') ||
      compare(a.projectId, b.projectId),
  );
  const sum = (pick: (p: (typeof named)[number]) => number) =>
    named.reduce((n, p) => n + pick(p), 0);
  return {
    critical: sum((p) => p.critical),
    high: sum((p) => p.high),
    exploited: options.priority ? sum((p) => p.exploited) : null,
    projects: named.slice(0, MAX_VULNERABILITY_PROJECTS).map((p) => ({
      projectId: p.projectId,
      name: p.name,
      critical: p.critical,
      high: p.high,
      exploited: options.priority ? p.exploited : null,
      targets: p.targets.slice(0, MAX_TARGET_NAMES).map((name) => clipUtf16(name, 500)),
      moreTargets: Math.max(0, p.targets.length - MAX_TARGET_NAMES),
    })),
    moreProjects: Math.max(0, named.length - MAX_VULNERABILITY_PROJECTS),
  };
}
