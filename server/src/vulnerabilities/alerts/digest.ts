import { inArray, sql } from 'drizzle-orm';
import { uuidList } from '../../db/bulk';
import type { Executor } from '../../db/client';
import { LOCKS } from '../../db/locks';
import { projects } from '../../db/schema';
import { queueMail } from '../../mail/outbox';
import { renderVulnerabilityDigest } from '../../mail/templates/notify-vulnerabilities';
import { publicLink } from '../../mail/templates/text';
import {
  VULNERABILITY_UNSUBSCRIBE_API,
  vulnerabilityMailLinks,
  withUnsubscribe,
} from '../../notifications/links';
import { vulnerabilityWatchers } from '../../notifications/recipients';
import { enqueue } from '../../queue/queue';
import { readVulndbState } from '../../vulndb/state';
import { currentDataset } from '../../vulndb/store';
import { createDeliveries, type NewDelivery } from '../../webhooks/deliveries';
import { subscriptionsToNotify } from '../../webhooks/stage';
import { enqueueRecheck } from '../recheck';
import { alertRows, capRows, watcherSections, type VulnerabilityMailRow } from './content';
import type { AlertDeps } from './jobs';
import { observeAlerts } from './observe';
import { alertScope } from './scope';

/** The digest job's queue, and its concurrency key. */
export const DIGEST_QUEUE = 'vulnerabilities.digest';
/** The most vulnerabilities one `vulnerabilities.found` delivery lists (R11). */
export const MAX_WEBHOOK_VULNERABILITIES = 1_000;

const NOTHING = { mails: 0, deliveries: 0, items: 0 };

type DigestProject = { id: string; key: string; name: string; organizationId: string };
type DigestRows = ReadonlyMap<string, VulnerabilityMailRow[]>;

/**
 * The items this run processes (4b A5): not baseline, not digested, found up to `cutoff`. The
 * caller has just observed, and observing deleted every target out of scope with its items, so
 * what is left is in scope.
 */
async function pendingItems(tx: Executor, cutoff: Date): Promise<string[]> {
  const found = await tx.execute<{ id: string }>(sql`
    SELECT id FROM vulnerability_alert_items
     WHERE NOT baseline AND digested_at IS NULL
       AND found_at <= ${cutoff.toISOString()}::timestamptz
     ORDER BY id`);
  return found.rows.map((row) => row.id);
}

/** Per project, the rows a digest shows: High and Critical. A project left with none is absent. */
function digestRows(rows: DigestRows): Map<string, VulnerabilityMailRow[]> {
  const listed = new Map<string, VulnerabilityMailRow[]>();
  for (const [projectId, ofProject] of rows) {
    const kept = ofProject.filter((r) => r.severity === 'critical' || r.severity === 'high');
    if (kept.length > 0) listed.set(projectId, kept);
  }
  return listed;
}

/** One digest per watcher, about that watcher's projects only; the number queued. */
async function mailWatchers(
  tx: Executor,
  deps: AlertDeps,
  now: Date,
  listed: DigestRows,
  facts: ReadonlyMap<string, DigestProject>,
  databaseDate: Date | null,
): Promise<number> {
  const watchers = await vulnerabilityWatchers(tx, {
    projectIds: [...listed.keys()],
    demoUser: deps.config.demoUser,
  });
  const names = new Map([...facts].map(([id, project]) => [id, project.name]));
  const day = now.toISOString().slice(0, 10);
  let mails = 0;
  for (const { watcher, sections } of watcherSections(watchers, names, listed)) {
    const links = vulnerabilityMailLinks(deps.config, watcher.userId);
    const result = await queueMail(tx, deps, {
      kind: 'notify.vulnerabilities-digest',
      to: { address: watcher.email, userId: watcher.userId },
      dedupe: { key: `vulnerabilities.digest:${watcher.userId}:${day}`, withinHours: 20 },
      render: () =>
        withUnsubscribe(
          renderVulnerabilityDigest({ projects: capRows(sections), databaseDate, links }),
          links.publicUrl,
          links.token,
          VULNERABILITY_UNSUBSCRIBE_API,
        ),
    });
    if (result.status === 'queued') mails += 1;
  }
  return mails;
}

/** The `vulnerabilities.found` payload of one project (A6, R11). */
function foundPayload(
  project: DigestProject,
  rows: readonly VulnerabilityMailRow[],
  databaseDate: Date | null,
  publicUrl: string | null,
) {
  return {
    project: {
      id: project.id,
      key: project.key,
      name: project.name,
      url: publicLink(publicUrl, `/projects/${project.id}/vulnerabilities`),
    },
    database: { builtAt: databaseDate?.toISOString() ?? null },
    vulnerabilities: rows.slice(0, MAX_WEBHOOK_VULNERABILITIES).map((row) => ({
      vulnerabilityId: row.vulnerabilityId,
      severity: row.severity,
      title: row.title,
      packageName: row.packageName,
      installedVersions: row.installedVersions,
      fixedVersion: row.fixedVersion,
      exploited: row.exploited,
      targets: row.targets,
    })),
    more: Math.max(0, rows.length - MAX_WEBHOOK_VULNERABILITIES),
  };
}

/** One delivery per project with rows and active generic subscription that lists the event. */
async function deliverFound(
  tx: Executor,
  deps: AlertDeps,
  listed: DigestRows,
  facts: ReadonlyMap<string, DigestProject>,
  databaseDate: Date | null,
): Promise<number> {
  const deliveries: NewDelivery[] = [];
  // In id order: the subscriptions are locked FOR KEY SHARE until this transaction commits.
  for (const projectId of [...listed.keys()].sort()) {
    const project = facts.get(projectId);
    const rows = listed.get(projectId);
    if (project === undefined || rows === undefined) continue;
    const subscribed = (await subscriptionsToNotify(tx, project)).filter(
      (s) => s.kind === 'generic' && s.events.includes('vulnerabilities.found'),
    );
    if (subscribed.length === 0) continue;
    const payload = foundPayload(project, rows, databaseDate, deps.config.publicUrl);
    for (const { id } of subscribed) {
      deliveries.push({ subscriptionId: id, event: 'vulnerabilities.found', payload });
    }
  }
  return (await createDeliveries(tx, deliveries)).length;
}

/** Mails and creates the deliveries of what `itemIds` list, then marks every one of the items. */
async function processItems(
  tx: Executor,
  deps: AlertDeps,
  now: Date,
  priority: boolean,
): Promise<{ mails: number; deliveries: number; items: number }> {
  const itemIds = await pendingItems(tx, now);
  if (itemIds.length === 0) return NOTHING;
  const listed = digestRows(await alertRows(tx, itemIds, { priority }));
  let mails = 0;
  let deliveries = 0;
  if (listed.size > 0) {
    const facts = new Map(
      (
        await tx
          .select({
            id: projects.id,
            key: projects.key,
            name: projects.name,
            organizationId: projects.organizationId,
          })
          .from(projects)
          .where(inArray(projects.id, uuidList([...listed.keys()])))
      ).map((project) => [project.id, project]),
    );
    const dataset = await currentDataset(tx, await readVulndbState(tx));
    const databaseDate = dataset?.builtAt ?? null;
    mails = await mailWatchers(tx, deps, now, listed, facts, databaseDate);
    deliveries = await deliverFound(tx, deps, listed, facts, databaseDate);
  }
  await tx.execute(sql`
    UPDATE vulnerability_alert_items SET digested_at = ${now.toISOString()}::timestamptz
     WHERE id IN ${uuidList(itemIds)}`);
  return { mails, deliveries, items: itemIds.length };
}

/**
 * The daily pass, in one transaction under LOCKS.vulnerabilityAlerts (it shares that lock with the
 * KEV email job): observes the targets in scope, emails every watcher their digest, creates the
 * `vulnerabilities.found` deliveries, marks every item it processed, and queues the re-check the
 * targets it recorded need. Items found by this pass are included: the cutoff is `now`.
 *
 * It always observes (R9): with `vuln.alerts` off the scope is empty, and that is what deletes the
 * alert memory. Only the sending and the marking need `vuln.alerts`. An item is marked whether it
 * was listed or not (A5), so nothing builds up.
 */
export async function runVulnerabilityDigest(
  deps: AlertDeps,
): Promise<{ mails: number; deliveries: number; items: number }> {
  const { vulnerabilities } = deps.limits();
  return deps.db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityAlerts})`);
    // After the lock: a wait behind the other alert job would leave it stale.
    const now = deps.now?.() ?? new Date();
    const observed = await observeAlerts(tx, await alertScope(tx, { vulnerabilities }), now);
    const result = vulnerabilities.alerts
      ? await processItems(tx, deps, now, vulnerabilities.priority)
      : NOTHING;
    // Last: its advisory lock and its job row wait for this transaction.
    await enqueueRecheck(tx, { projectIds: observed.recheckProjectIds });
    return result;
  });
}

/**
 * Inserts the next run unless one is queued, at the next 06:00 UTC strictly after `now`: the
 * database clock unless given, as the queue compares `run_at` with it. `date_bin` counts from a
 * fixed 06:00 UTC, so no session time zone can move it. A running job does not count: its handler
 * asks for the run after it.
 */
async function schedule(db: Executor, now?: Date): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityDigestSchedule})`);
    const queued = await tx.execute(
      sql`SELECT 1 FROM jobs WHERE queue = ${DIGEST_QUEUE} AND status = 'queued' LIMIT 1`,
    );
    if (queued.rows.length > 0) return false;
    const at = now === undefined ? sql`now()` : sql`${now.toISOString()}::timestamptz`;
    await enqueue(tx, {
      queue: DIGEST_QUEUE,
      concurrencyKey: DIGEST_QUEUE,
      payload: {},
      runAt: sql`date_bin('24 hours', ${at}, timestamptz '2000-01-01 06:00:00+00') + interval '24 hours'`,
    });
    return true;
  });
}

/** After listen (main.ts): one queued run across replicas. */
export function scheduleVulnerabilityDigestAtBoot(db: Executor): Promise<boolean> {
  return schedule(db);
}

/** After every reap, and after every run: a run lost with its worker is replaced. */
export function ensureVulnerabilityDigestScheduled(db: Executor, now?: Date): Promise<boolean> {
  return schedule(db, now);
}
