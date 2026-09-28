import { sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import { pruneAuditEvents } from '../audit/retention';
import { AuditAnchorMalformedError, readAuditSettings } from '../audit/settings';
import type { Db, Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { LOCKS } from '../db/locks';
import { ANALYSIS_QUEUE } from '../ingest/service';
import { readLlmSettings } from '../llm/settings';
import { STALLED_DELIVERY_MINUTES, WEBHOOK_QUEUE } from '../webhooks/deliveries';
import type { JobHandlers } from '../queue/worker';
import { instanceSetting } from '../settings';
import { pruneSsoStates } from '../sso/states';

export const HOUSEKEEPING_QUEUE = 'housekeeping';
export const HOUSEKEEPING_INTERVAL_SECONDS = 24 * 60 * 60;

/** data-model.md §7 defaults; an `instance_settings` row `retention` may override any of them. */
export const DEFAULT_RETENTION = {
  analysisReportsDays: 7,
  closedIssuesDays: 30,
  branchesWithoutAnalysisDays: 30,
  webhookDeliveriesDays: 30,
  /** AI requests and their answers (llm.md §10.1). */
  llmRequestsDays: 90,
  /** Not in §7: finished jobs are only useful for debugging (ruling H1). */
  finishedJobsDays: 7,
};
export type Retention = typeof DEFAULT_RETENTION;

const days = z.number().int().min(1).max(36_500);
const retentionSchema = z
  .object({
    analysisReportsDays: days,
    closedIssuesDays: days,
    branchesWithoutAnalysisDays: days,
    webhookDeliveriesDays: days,
    llmRequestsDays: days,
    finishedJobsDays: days,
  })
  .partial();

export async function retentionSettings(db: Executor): Promise<Retention> {
  const overrides = await instanceSetting(db, 'retention', retentionSchema, {});
  return { ...DEFAULT_RETENTION, ...overrides };
}

/** Rows per DELETE, so no single statement holds locks on 100k closed issues at once. */
const BATCH = 5_000;
/** Stored reports are up to the upload limit each; delete fewer per statement. */
const REPORT_BATCH = 500;

/** A strictly formatted UUID, checked before a jsonb string is cast (a malformed payload must not
 *  make the cast, and the whole run, fail). */
const UUID_PATTERN =
  '^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$';

/**
 * Runs `statement(limit)` (a DELETE of at most `limit` rows, each its own short transaction) until
 * it deletes fewer than `limit` rows. Rows skipped because another transaction holds them locked
 * (`SKIP LOCKED`) end the loop early; the next daily run picks them up.
 */
async function deleteInBatches(
  db: Db,
  limit: number,
  statement: (limit: number) => SQL,
): Promise<number> {
  let total = 0;
  for (;;) {
    const n = (await db.execute(statement(limit))).rowCount ?? 0;
    total += n;
    if (n < limit) return total;
  }
}

export interface HousekeepingResult {
  analysisReports: number;
  closedIssues: number;
  branches: number;
  webhookDeliveries: number;
  /** Pending deliveries failed because their next attempt's job was lost. */
  stalledWebhookDeliveries: number;
  llmRequests: number;
  /** Stored prompts cleared after `promptRetentionDays` (llm.md §10.1); the row stays. */
  llmPromptsCleared: number;
  jobs: number;
  sessions: number;
  /** Audit events past the `audit` setting's retentionDays, at most one batch a run (rbac-audit.md §11). */
  auditEvents: number;
  /** Expired SSO flow state: pending flows, used assertion ids, finish codes (sso-scim.md §7.1). */
  ssoStates: number;
}

export interface HousekeepingLogger {
  info: (obj: object, msg: string) => void;
  error: (obj: object, msg: string) => void;
}

/**
 * rbac-audit.md §11: prunes audit events, but a malformed `audit-chain` row (pruning refuses it and
 * changes nothing) is logged and skipped, so the rest of housekeeping completes and the job is not
 * retried in a loop. Any other error propagates.
 */
async function pruneAuditStep(db: Db, logger: HousekeepingLogger | undefined): Promise<number> {
  // The database clock decides here too (the other steps compare with its now()).
  const clock = await db.execute<{ now: Date | string }>(sql`SELECT now() AS now`);
  try {
    return await pruneAuditEvents(db, {
      retentionDays: (await readAuditSettings(db)).retentionDays,
      now: new Date(clock.rows[0]?.now ?? Date.now()),
    });
  } catch (err) {
    if (!(err instanceof AuditAnchorMalformedError)) throw err;
    logger?.error(
      { component: 'audit-retention' },
      'the instance setting audit-chain is malformed; audit retention was skipped',
    );
    return 0;
  }
}

/**
 * data-model.md §7: applies every retention rule once. Idempotent, and the database clock decides.
 * Nothing a running or future job still needs is deleted:
 * - a stored report only once its analysis is `succeeded`/`failed` (never re-processed after);
 * - closed issues and analysis-less branches only on branches no ingestion currently holds (the
 *   ingestion transaction locks its branch row from its upsert to its commit; `SKIP LOCKED` leaves
 *   those branches to the next run, so tracking never loses a candidate it has already loaded);
 * - a branch only if no analysis row at all refers to it (deleting it would cascade to those
 *   analyses, which are kept forever);
 * - a dead analysis job only once its analysis left `queued`/`processing`
 *   (`reconcileDeadAnalyses` reads it);
 * - a webhook delivery a delivery worker holds locked is skipped;
 * - a pending webhook delivery is failed (not deleted) only when its next attempt is an hour
 *   overdue and no job of the `webhook` queue is queued or running for it (its job died on
 *   database errors), so the webhook's history shows it and it can be redelivered;
 * - an AI request after `llmRequestsDays` whatever its status: a row that old cannot be in
 *   flight (a job gives up within hours, llm.md §12.3, §14), so a queued or running one is a
 *   stuck row; its stored prompt is cleared after the `llm` setting's `promptRetentionDays`,
 *   whatever its status;
 * - audit events only as a prefix of the chain, anchored in the same transaction, and whether or
 *   not `audit-log` is active (rbac-audit.md §11);
 * - expired SSO flow state (sso-scim.md §7.1), skipping a row a sign-in is taking at that moment.
 */
export async function runHousekeeping(
  db: Db,
  logger?: HousekeepingLogger,
): Promise<HousekeepingResult> {
  const r = await retentionSettings(db);
  const analysisReports = await deleteInBatches(
    db,
    REPORT_BATCH,
    (limit) => sql`
      DELETE FROM analysis_reports WHERE analysis_id IN (
        SELECT ar.analysis_id FROM analysis_reports ar JOIN analyses a ON a.id = ar.analysis_id
         WHERE a.status IN ('succeeded', 'failed')
           AND a.finished_at < now() - make_interval(days => ${r.analysisReportsDays})
         LIMIT ${limit}
         FOR UPDATE OF ar SKIP LOCKED)`,
  );
  const closedIssues = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      DELETE FROM issues WHERE id IN (
        SELECT i.id FROM issues i JOIN branches b ON b.id = i.branch_id
         WHERE i.status = 'closed'
           AND i.closed_at < now() - make_interval(days => ${r.closedIssuesDays})
         LIMIT ${limit}
         FOR SHARE OF b SKIP LOCKED)
        -- Re-checked on the row being deleted: the subquery locks the branch, not the issue, so
        -- a row reopened after the subquery read it must survive.
        AND status = 'closed'
        AND closed_at < now() - make_interval(days => ${r.closedIssuesDays})`,
  );
  const branches = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      DELETE FROM branches WHERE id IN (
        SELECT b.id FROM branches b
         WHERE NOT b.is_main AND b.last_analysis_id IS NULL
           AND b.created_at < now() - make_interval(days => ${r.branchesWithoutAnalysisDays})
           AND NOT EXISTS (SELECT 1 FROM analyses a WHERE a.branch_id = b.id)
         LIMIT ${limit}
         FOR UPDATE OF b SKIP LOCKED)`,
  );
  const webhookDeliveries = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      DELETE FROM webhook_deliveries WHERE id IN (
        SELECT id FROM webhook_deliveries
         WHERE created_at < now() - make_interval(days => ${r.webhookDeliveriesDays})
         LIMIT ${limit}
         FOR UPDATE SKIP LOCKED)`,
  );
  const stalledWebhookDeliveries = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      UPDATE webhook_deliveries
         SET status = 'failed', next_attempt_at = NULL,
             response_excerpt = 'The delivery was abandoned: its next attempt was never run'
       WHERE id IN (
         SELECT d.id FROM webhook_deliveries d
          WHERE d.status = 'pending'
            AND d.next_attempt_at < now() - make_interval(mins => ${STALLED_DELIVERY_MINUTES})
            AND NOT EXISTS (
                  SELECT 1 FROM jobs j
                   WHERE j.queue = ${WEBHOOK_QUEUE} AND j.status IN ('queued', 'running')
                     AND j.payload ->> 'deliveryId' = d.id::text)
          LIMIT ${limit}
          FOR UPDATE SKIP LOCKED)
         -- Re-checked on the row being updated: an attempt recorded meanwhile moved it on.
         AND status = 'pending'
         AND next_attempt_at < now() - make_interval(mins => ${STALLED_DELIVERY_MINUTES})`,
  );
  const llmRequests = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      DELETE FROM llm_requests WHERE id IN (
        SELECT id FROM llm_requests
         WHERE created_at < now() - make_interval(days => ${r.llmRequestsDays})
         LIMIT ${limit}
         FOR UPDATE SKIP LOCKED)`,
  );
  const { promptRetentionDays } = await readLlmSettings(db);
  const llmPromptsCleared = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      UPDATE llm_requests SET prompt = NULL, updated_at = now() WHERE id IN (
        SELECT id FROM llm_requests
         WHERE prompt IS NOT NULL
           AND created_at < now() - make_interval(days => ${promptRetentionDays})
         LIMIT ${limit}
         FOR UPDATE SKIP LOCKED)`,
  );
  const jobs = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      DELETE FROM jobs WHERE id IN (
        SELECT j.id FROM jobs j
         WHERE j.status IN ('succeeded', 'dead')
           AND j.updated_at < now() - make_interval(days => ${r.finishedJobsDays})
           AND NOT (j.status = 'dead' AND j.queue = ${ANALYSIS_QUEUE} AND EXISTS (
                 SELECT 1 FROM analyses a
                  WHERE a.id = CASE WHEN j.payload ->> 'analysisId' ~ ${UUID_PATTERN}
                                    THEN (j.payload ->> 'analysisId')::uuid END
                    AND a.status IN ('queued', 'processing')))
         LIMIT ${limit}
         FOR UPDATE OF j SKIP LOCKED)`,
  );
  const sessions = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      DELETE FROM sessions WHERE id IN (
        SELECT id FROM sessions WHERE expires_at < now() LIMIT ${limit} FOR UPDATE SKIP LOCKED)`,
  );
  const auditEvents = await pruneAuditStep(db, logger);
  const ssoStates = await pruneSsoStates(db);
  return {
    analysisReports,
    closedIssues,
    branches,
    webhookDeliveries,
    stalledWebhookDeliveries,
    llmRequests,
    llmPromptsCleared,
    jobs,
    sessions,
    auditEvents,
    ssoStates,
  };
}

/** How long after a housekeeping job died the next one may run (no retry storm). */
export const HOUSEKEEPING_DEAD_BACKOFF_SECONDS = 60 * 60;

/**
 * Enqueues the next housekeeping run `delaySeconds` after the database's now(), unless one is
 * already waiting (`alsoRunning`: or running). The advisory lock makes this safe when several
 * replicas boot, or reap, at the same moment; the job's concurrency key (the queue name) means
 * two replicas never run it at the same time either. When the latest housekeeping job is dead
 * (it failed every attempt), the next run waits until an hour after it died, so a run that keeps
 * failing is not rescheduled at once by every boot and every reap.
 */
export async function scheduleHousekeeping(
  db: Db,
  delaySeconds: number,
  alsoRunning: boolean,
): Promise<boolean> {
  return db.transaction(async (tx) => {
    await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.housekeeping})`);
    const statuses = alsoRunning ? sql`('queued', 'running')` : sql`('queued')`;
    const existing = await tx.execute(sql`
      SELECT 1 FROM jobs WHERE queue = ${HOUSEKEEPING_QUEUE} AND status IN ${statuses} LIMIT 1`);
    if (existing.rows.length > 0) return false;
    await tx.execute(sql`
      INSERT INTO jobs (id, queue, concurrency_key, payload, run_at)
      VALUES (${uuidv7()}, ${HOUSEKEEPING_QUEUE}, ${HOUSEKEEPING_QUEUE}, '{}'::jsonb,
              -- GREATEST ignores the NULL of a latest job that is not dead.
              GREATEST(now() + make_interval(secs => ${delaySeconds}), (
                SELECT CASE WHEN j.status = 'dead'
                            THEN j.updated_at + make_interval(secs => ${HOUSEKEEPING_DEAD_BACKOFF_SECONDS})
                       END
                  FROM jobs j WHERE j.queue = ${HOUSEKEEPING_QUEUE}
                 ORDER BY j.id DESC LIMIT 1)))`);
    return true;
  });
}

/** At boot and after every reap: make sure a housekeeping run is pending (it may have died). */
export function ensureHousekeepingScheduled(db: Db): Promise<boolean> {
  return scheduleHousekeeping(db, 0, true);
}

export function housekeepingHandlers(deps: {
  db: Db;
  logger?: HousekeepingLogger | undefined;
}): JobHandlers {
  return {
    [HOUSEKEEPING_QUEUE]: async () => {
      const result = await runHousekeeping(deps.db, deps.logger);
      deps.logger?.info({ ...result }, 'housekeeping finished');
      await scheduleHousekeeping(deps.db, HOUSEKEEPING_INTERVAL_SECONDS, false);
    },
  };
}
