import { inArray } from 'drizzle-orm';
import { uuidList } from '../../db/bulk';
import type { Executor } from '../../db/client';
import { projects } from '../../db/schema';
import {
  MAX_EXPLOITED_PROJECTS,
  MAX_EXPLOITED_ROWS,
  type ChatExploitedMessage,
  type ExploitedRow,
} from '../../webhooks/chat/messages';
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
      title: row.title === null ? null : row.title.slice(0, 2000),
      packageName: row.packageName.slice(0, 500),
      installedVersions: row.installedVersions.slice(0, 50).map((v) => v.slice(0, 200)),
      fixedVersion: row.fixedVersion === null ? null : row.fixedVersion.slice(0, 200),
      kevDateAdded: row.exploited.dateAdded,
      targets: row.targets.slice(0, 200),
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
      key: project.key.slice(0, 500),
      name: project.name.slice(0, 500),
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
 * about the projects of `items` it covers (org-wide, or its own project); the number created.
 * A project with no row left (triaged since the pick) is left out, and a webhook with no project
 * left gets nothing. The caller marks the items.
 */
export async function exploitedDeliveries(
  tx: Executor,
  items: readonly { id: string; project_id: string }[],
): Promise<number> {
  if (items.length === 0) return 0;
  const rowsOf = await alertRows(
    tx,
    items.map((item) => item.id),
    { priority: true },
  );
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
