import { SEVERITIES, type Severity } from '@qualor/shared';
import { and, asc, eq, ne, sql } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import type { Db, Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { LOCKS } from '../db/locks';
import { organizations, webhookSubscriptions } from '../db/schema';
import type { Limits } from '../limits';
import { digestVulnerabilities } from '../vulnerabilities/alerts/chat';
import type { JobHandlers } from '../queue/worker';
import {
  MAX_DIGEST_ROWS,
  MAX_TOP_ISSUES,
  type ChatDigestMessage,
  type DigestGate,
  type DigestRow,
} from './chat/messages';
import { digestDue, digestWindow } from './chat/week';
import { createDeliveries } from './deliveries';

export const DIGEST_QUEUE = 'webhook.digest';
/** The message schema's bound on names (chat/messages.ts). */
const NAME_MAX = 500;
const zero = (): Record<Severity, number> => ({ blocker: 0, high: 0, medium: 0, low: 0, info: 0 });

export interface DigestDeps {
  db: Db;
  /** Tests fix the clock. */
  now?: () => Date;
  /** Read once per run: the vulnerability section needs `vuln.alerts` (and `vuln.priority`). */
  limits: () => Pick<Limits, 'vulnerabilities'>;
  logger?: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
}

const isFailing = (r: DigestRow): boolean => r.gate === 'failed' || r.gate === 'error';

/** R8: a project needs a line when it has new security issues or a failed or error gate. */
function needsAttention(r: DigestRow): boolean {
  return r.newSecurity > 0 || isFailing(r);
}

/**
 * R8: nothing new and every gate passes (none and never analysed count as passing). New High or
 * Critical vulnerabilities in the section (0.15 plan 6 C6) are news too.
 */
export function isQuiet(m: ChatDigestMessage): boolean {
  const vulnerabilities = m.vulnerabilities;
  return (
    m.totals.newSecurity === 0 &&
    m.totals.failing === 0 &&
    (vulnerabilities === undefined || vulnerabilities.critical + vulnerabilities.high === 0)
  );
}

/** The result column holding the new issues of one severity (a fixed name, never user input). */
function newColumn(severity: string) {
  return sql.raw(`new_${severity}`);
}

/**
 * 6G spec §4, R8: the digest of one scope (the organisation's projects, or one project) over
 * `[since, until)`. One query for the per-project counts (main branch only) and one for the top
 * issues.
 */
export async function buildDigest(
  tx: Executor,
  scope: { organizationId: string; projectId: string | null },
  window: { since: Date; until: Date; week: string; timezone: string },
  options: { vulnerabilities: { alerts: boolean; priority: boolean } },
): Promise<ChatDigestMessage> {
  const projectFilter = scope.projectId === null ? sql`` : sql`AND p.id = ${scope.projectId}`;
  const isNew = sql`i.first_seen_at >= ${window.since} AND i.first_seen_at < ${window.until}`;
  const perSeverity = SEVERITIES.map(
    (s) => sql`count(i.id) FILTER (WHERE ${isNew} AND i.severity = ${s})::int AS ${newColumn(s)}`,
  );
  const result = await tx.execute<Record<string, unknown>>(sql`
    SELECT p.id, left(p.name, ${NAME_MAX}) AS name,
           CASE WHEN a.status = 'succeeded' THEN coalesce(a.gate_status, 'none') ELSE 'never' END
             AS gate,
           count(i.id)::int AS open_security,
           ${sql.join(perSeverity, sql`, `)}
      FROM projects p
      LEFT JOIN branches b ON b.project_id = p.id AND b.is_main
      LEFT JOIN analyses a ON a.id = b.last_analysis_id
      LEFT JOIN issues i ON i.branch_id = b.id AND i.status = 'open' AND i.kind = 'issue'
                        AND i.quality = 'security' AND i.duplicate_of_issue_id IS NULL
     WHERE p.organization_id = ${scope.organizationId} ${projectFilter}
     GROUP BY p.id, p.name, a.status, a.gate_status`);
  const all: DigestRow[] = result.rows.map((r) => {
    const bySeverity = zero();
    for (const s of SEVERITIES) bySeverity[s] = Number(r[`new_${s}`] ?? 0);
    return {
      projectId: String(r.id),
      name: String(r.name),
      gate: String(r.gate) as DigestGate,
      newSecurity: SEVERITIES.reduce((n, s) => n + bySeverity[s], 0),
      newBySeverity: bySeverity,
      openSecurity: Number(r.open_security ?? 0),
    };
  });
  // R8: failed first, then most new issues, then name.
  const attention = all
    .filter(needsAttention)
    .sort(
      (a, b) =>
        Number(isFailing(b)) - Number(isFailing(a)) ||
        b.newSecurity - a.newSecurity ||
        a.name.localeCompare(b.name),
    );
  const totals = {
    projects: all.length,
    failing: all.filter(isFailing).length,
    newSecurity: all.reduce((n, r) => n + r.newSecurity, 0),
    openSecurity: all.reduce((n, r) => n + r.openSecurity, 0),
    newBySeverity: zero(),
  };
  for (const r of all) for (const s of SEVERITIES) totals.newBySeverity[s] += r.newBySeverity[s];

  const top = await tx.execute<{
    id: string;
    project_id: string;
    project_name: string;
    severity: Severity;
    rule_name: string;
    message: string;
    path: string | null;
    start_line: number | null;
  }>(sql`
    SELECT i.id, i.project_id, left(p.name, ${NAME_MAX}) AS project_name, i.severity,
           left(r.name, ${NAME_MAX}) AS rule_name, left(i.message, 4000) AS message,
           left(i.path, 4000) AS path, i.start_line
      FROM issues i
      JOIN branches b ON b.id = i.branch_id AND b.is_main
      JOIN projects p ON p.id = i.project_id
      JOIN rules r ON r.id = i.rule_id
     WHERE p.organization_id = ${scope.organizationId} ${projectFilter}
       AND i.status = 'open' AND i.kind = 'issue' AND i.quality = 'security'
       AND i.duplicate_of_issue_id IS NULL AND ${isNew}
     ORDER BY i.severity_rank, i.first_seen_at DESC, i.id DESC
     LIMIT ${MAX_TOP_ISSUES}`);

  const [organization] = await tx
    .select({ name: sql<string>`left(${organizations.name}, ${NAME_MAX})` })
    .from(organizations)
    .where(eq(organizations.id, scope.organizationId));
  const project =
    scope.projectId === null ? null : (all.find((r) => r.projectId === scope.projectId) ?? null);
  const vulnerabilities = options.vulnerabilities.alerts
    ? await digestVulnerabilities(tx, scope, window, {
        priority: options.vulnerabilities.priority,
      })
    : null;
  return {
    type: 'digest',
    week: window.week,
    since: window.since.toISOString(),
    until: window.until.toISOString(),
    timezone: window.timezone,
    scope: {
      organization: { id: scope.organizationId, name: organization?.name ?? '' },
      project: project === null ? null : { id: project.projectId, name: project.name },
    },
    totals,
    rows: attention.slice(0, MAX_DIGEST_ROWS),
    moreProjects: Math.max(0, attention.length - MAX_DIGEST_ROWS),
    quietProjects: all.length - attention.length,
    top: top.rows.map((i) => ({
      id: i.id,
      projectId: i.project_id,
      projectName: i.project_name,
      severity: i.severity,
      ruleName: i.rule_name,
      message: i.message,
      path: i.path,
      line: i.start_line,
    })),
    ...(vulnerabilities !== null && { vulnerabilities }),
  };
}

/**
 * One hourly run (R14): every active chat webhook with `digest.weekly` whose digest is due in its
 * zone gets its week marked and, unless the week is quiet, a delivery — both in one transaction,
 * the mark conditional on the week not being marked yet, so a concurrent run (another replica, a
 * retried job) sends nothing twice. A failure of one webhook is logged, its week stays unmarked
 * (the next hourly run tries again) and the run goes on.
 */
export async function runDigests(
  deps: DigestDeps,
): Promise<{ sent: number; quiet: number; failed: number }> {
  const now = deps.now?.() ?? new Date();
  const { vulnerabilities } = deps.limits();
  const candidates = await deps.db
    .select({
      id: webhookSubscriptions.id,
      organizationId: webhookSubscriptions.organizationId,
      projectId: webhookSubscriptions.projectId,
      timezone: webhookSubscriptions.timezone,
      digestLastWeek: webhookSubscriptions.digestLastWeek,
    })
    .from(webhookSubscriptions)
    .where(
      and(
        eq(webhookSubscriptions.active, true),
        ne(webhookSubscriptions.kind, 'generic'),
        sql`'digest.weekly' = ANY(${webhookSubscriptions.events})`,
      ),
    )
    .orderBy(asc(webhookSubscriptions.id));
  const result = { sent: 0, quiet: 0, failed: 0 };
  for (const c of candidates) {
    const week = digestDue(now, c.timezone, c.digestLastWeek);
    if (week === null) continue;
    try {
      const outcome = await deps.db.transaction(async (tx) => {
        // The row lock serialises concurrent runs; the loser re-reads the marked week, updates
        // nothing and sends nothing (READ COMMITTED re-checks the WHERE after the wait).
        const marked = await tx
          .update(webhookSubscriptions)
          .set({ digestLastWeek: week })
          .where(
            and(
              eq(webhookSubscriptions.id, c.id),
              sql`${webhookSubscriptions.digestLastWeek} IS DISTINCT FROM ${week}`,
            ),
          )
          .returning({ id: webhookSubscriptions.id });
        if (marked.length === 0) return 'taken' as const;
        const message = await buildDigest(
          tx,
          { organizationId: c.organizationId, projectId: c.projectId },
          { ...digestWindow(now, c.timezone), week, timezone: c.timezone },
          { vulnerabilities },
        );
        if (isQuiet(message)) return 'quiet' as const;
        await createDeliveries(tx, [
          { subscriptionId: c.id, event: 'digest.weekly', payload: message },
        ]);
        return 'sent' as const;
      });
      if (outcome === 'sent') result.sent += 1;
      if (outcome === 'quiet') result.quiet += 1;
    } catch (err) {
      // Its week stays unmarked: a lasting failure is retried, and logged, every hour until the
      // local Monday ends (then the week is skipped, R8).
      result.failed += 1;
      deps.logger?.warn(
        {
          component: 'digest',
          webhookId: c.id,
          errorClass: err instanceof Error ? err.constructor.name : typeof err,
        },
        'weekly digest not queued',
      );
    }
  }
  return result;
}

/**
 * R14: inserts the next run at minute 1 of the next hour unless one is queued (`alsoRunning`: or
 * running), under LOCKS.chatDigest so replicas starting together insert one.
 */
async function schedule(db: Db, alsoRunning: boolean): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.chatDigest})`);
    const statuses = alsoRunning ? sql`('queued', 'running')` : sql`('queued')`;
    const existing = await tx.execute(sql`
      SELECT 1 FROM jobs WHERE queue = ${DIGEST_QUEUE} AND status IN ${statuses} LIMIT 1`);
    if (existing.rows.length > 0) return false;
    // At 10:20 UTC this is 11:01 UTC; truncated in UTC, so a session time zone with a
    // half-hour offset (Asia/Kolkata) cannot move it to minute 31.
    await tx.execute(sql`
      INSERT INTO jobs (id, queue, concurrency_key, payload, run_at)
      VALUES (${uuidv7()}, ${DIGEST_QUEUE}, ${DIGEST_QUEUE}, '{}'::jsonb,
              date_trunc('hour', now(), 'UTC') + interval '61 minutes')`);
    return true;
  });
}

/** At boot (main.ts): the first run at the next hour's minute 1, one across replicas. */
export function scheduleDigestAtBoot(db: Db): Promise<boolean> {
  return schedule(db, true);
}

/** After every reap: a run lost with its worker is replaced. */
export function ensureDigestScheduled(db: Db): Promise<boolean> {
  return schedule(db, true);
}

/** On the analysis worker (main.ts): run, then schedule the next hour's run. */
export function digestHandlers(deps: DigestDeps): JobHandlers {
  return {
    [DIGEST_QUEUE]: async () => {
      try {
        const result = await runDigests(deps);
        if (result.sent + result.quiet + result.failed > 0) {
          deps.logger?.info({ component: 'digest', ...result }, 'weekly digests');
        }
      } catch (err) {
        // Not retried: the next hourly run looks again (until Monday ends).
        deps.logger?.warn(
          {
            component: 'digest',
            errorClass: err instanceof Error ? err.constructor.name : typeof err,
          },
          'weekly digest run failed',
        );
      }
      await schedule(deps.db, false);
    },
  };
}
