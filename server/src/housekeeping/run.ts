import { lt, sql, type SQL } from 'drizzle-orm';
import { z } from 'zod';
import { pruneAccountTokens } from '../auth/account-tokens';
import { pruneAuditEvents } from '../audit/retention';
import { AuditAnchorMalformedError, readAuditSettings } from '../audit/settings';
import { cleanInactiveBranches } from '../cleanup/run';
import type { Db, Executor } from '../db/client';
import { uuidv7 } from '../db/ids';
import { pgErrorCode } from '../db/errors';
import { LOCKS } from '../db/locks';
import { oauthClients, oauthRequests, oauthTokens } from '../db/schema';
import { ANALYSIS_QUEUE } from '../ingest/service';
import { readLlmSettings } from '../llm/settings';
import { purgeInactiveSnapshots } from '../review/lifecycle';
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
  /** The email delivery log (E1 spec). */
  mailMessagesDays: 30,
  /**
   * AI review snapshots (6I-2, spec §5): the most days the server keeps a merge request's copy of
   * the repository. The data-sharing notice names it, so the number shown is read from here.
   */
  reviewSnapshotsDays: 14,
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
    mailMessagesDays: days,
    reviewSnapshotsDays: days,
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
/** A review snapshot may hold tens of thousands of file rows, which go with it (6I-2). */
const SNAPSHOT_BATCH = 50;
/** 6I-2: a rejected review snapshot is kept this long (its reason says why it was refused). */
export const REJECTED_SNAPSHOT_DAYS = 1;
/** 6I-4: a finished row of the replies ledger (a note Qualor answered, skipped or failed) is kept this long. */
const REVIEW_REPLY_DAYS = 90;

/** E1 spec: a message still pending this long lost its job: it is failed and its body dropped. */
export const MAIL_GIVE_UP_DAYS = 2;
export const MAIL_GAVE_UP_TEXT = 'Gave up: not delivered within 2 days';

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
  /** Branches and merge requests not analysed within their project's cleanup days (issue #38). */
  inactiveBranches: number;
  inactiveMergeRequests: number;
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
  /** Expired account links (mail E2): resets at once, invitations 30 days after they expired. */
  accountTokens: number;
  /** Email log rows past `mailMessagesDays` (E1 spec). */
  mailMessages: number;
  /** Pending messages failed after MAIL_GIVE_UP_DAYS, their body dropped. */
  abandonedMailMessages: number;
  /** Review snapshots past `reviewSnapshotsDays`, and rejected ones after a day (6I-2). */
  reviewSnapshots: number;
  /** Review snapshots of projects AI review no longer covers (6I-3), as the purge after a settings write. */
  reviewSnapshotsInactive: number;
  /** Finished rows of the replies ledger past REVIEW_REPLY_DAYS (6I-4). */
  reviewReplies: number;
  /** Expired OAuth authorization requests, expired OAuth tokens, and clients nothing uses any more. */
  oauthRequests: number;
  oauthTokens: number;
  oauthClients: number;
}

export interface HousekeepingLogger {
  info: (obj: object, msg: string) => void;
  warn: (obj: object, msg: string) => void;
  error: (obj: object, msg: string) => void;
}

/**
 * Issue #38, the last step of a run: it deletes whole histories, so it runs after the cheap steps,
 * and an error of it is logged (the error's code only: no branch name, no error text) and ends it
 * for the day. The run still completes; the next one starts it again.
 */
async function cleanupStep(
  db: Db,
  logger: HousekeepingLogger | undefined,
): Promise<{ branches: number; mergeRequests: number }> {
  try {
    return await cleanInactiveBranches(db, { logger });
  } catch (err) {
    logger?.warn(
      { component: 'branch-cleanup', code: pgErrorCode(err) ?? null },
      'the cleanup of inactive branches and merge requests failed; the next run starts it again',
    );
    return { branches: 0, mergeRequests: 0 };
  }
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

/** How long a client may sit unused without a live grant (DCR: since its last use; CIMD: since its cache expired). */
const OAUTH_CLIENT_GRACE_DAYS = 30;

/**
 * MCP spec §4.5: expired requests and tokens; clients that hold no live grant and no unexpired
 * request: DCR ones unused for 30 days (the latest of registration, last approval or token
 * exchange, and the creation or revocation of a grant), CIMD ones 30 days after their cached
 * document expired (an authorize fetches it again).
 *
 * The client delete skips rows someone holds (`SKIP LOCKED`: an approval or authorize in flight
 * locks its client row), and a client used meanwhile fails the re-checked `last_used_at` test. A
 * deadlock with an approval that started inside this one statement (it locks its pending request,
 * then wants the client row this statement holds) is possible only in that instant; the step then
 * deletes nothing and the next run retries.
 */
export async function cleanOAuth(
  db: Executor,
  now: Date,
): Promise<{ requests: number; tokens: number; clients: number }> {
  const requests = await db
    .delete(oauthRequests)
    .where(lt(oauthRequests.expiresAt, now))
    .returning({ id: oauthRequests.id });
  const tokens = await db
    .delete(oauthTokens)
    .where(lt(oauthTokens.expiresAt, now))
    .returning({ id: oauthTokens.id });
  const cutoff = new Date(now.getTime() - OAUTH_CLIENT_GRACE_DAYS * 86_400_000);
  let clients: { id: string }[] = [];
  try {
    clients = await db
      .delete(oauthClients)
      .where(
        sql`${oauthClients.id} IN (
          SELECT c.id FROM oauth_clients c
           WHERE NOT EXISTS (SELECT 1 FROM oauth_grants g WHERE g.client_row_id = c.id AND g.revoked_at IS NULL)
             AND NOT EXISTS (SELECT 1 FROM oauth_requests r WHERE r.client_row_id = c.id)
             AND ((c.source = 'dcr' AND greatest(c.created_at, c.last_used_at,
                    (SELECT max(greatest(g.created_at, g.revoked_at)) FROM oauth_grants g
                      WHERE g.client_row_id = c.id)) < ${cutoff})
               OR (c.source = 'cimd' AND greatest(c.expires_at, c.last_used_at) < ${cutoff}))
           FOR UPDATE SKIP LOCKED)
        -- Re-checked on the locked row: a use recorded meanwhile keeps it.
        AND (${oauthClients.lastUsedAt} IS NULL OR ${oauthClients.lastUsedAt} < ${cutoff})`,
      )
      .returning({ id: oauthClients.id });
  } catch (err) {
    if (pgErrorCode(err) !== '40P01') throw err;
  }
  return { requests: requests.length, tokens: tokens.length, clients: clients.length };
}

/**
 * data-model.md §7: applies every retention rule once. Idempotent, and the database clock decides.
 * Nothing a running or future job still needs is deleted:
 * - a stored report only once its analysis is `succeeded`/`failed` (never re-processed after);
 * - closed issues and analysis-less branches only on branches no ingestion currently holds (the
 *   ingestion transaction locks its branch row from its upsert to its commit; `SKIP LOCKED` leaves
 *   those branches to the next run, so tracking never loses a candidate it has already loaded);
 * - a branch without an analysis only if no analysis row at all refers to it (deleting it would
 *   cascade to those analyses, which this rule keeps);
 * - an analysed branch or merge request only under the cleanup rule a project has in force (issue
 *   #38, off by default), with its analyses; never the main branch nor a tracked or kept one, and
 *   skipping what an analysis or review still needs (cleanInactiveBranches). It runs last, and its
 *   error never fails the run (cleanupStep);
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
 * - expired SSO flow state (sso-scim.md §7.1), skipping a row a sign-in is taking at that moment;
 * - an email log row after mailMessagesDays; a message pending for 2 days is failed and its body
 *   dropped (its job was lost);
 * - expired account links (mail E2), skipping a row a request is taking at that moment;
 * - a review snapshot after `reviewSnapshotsDays` (spec §5), a rejected one after a day, whatever
 *   its status (its unpack job then finds it gone), skipping one a job holds at that moment;
 * - the review snapshots of projects AI review no longer covers, which the purge queued after every
 *   AI settings write, unmapping and connection deletion deletes at once (6I-3, R17): this run
 *   catches what that missed (a snapshot uploaded while the settings changed, a row a job held at
 *   that moment), skipping rows a job holds;
 * - a row of the replies ledger (6I-4) 90 days after it ended `done`, `skipped` or `failed`: one
 *   still queued or running is never deleted by its age, skipping a row a job holds at that moment;
 * - expired OAuth requests and tokens, and clients without a live grant (cleanOAuth).
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
           -- An automatic fix row is what "never suggests again" looks at (4E-3a §3): it stays
           -- while its issue does. A deleted issue sets issue_id to NULL, and the row goes.
           AND NOT (feature = 'fix' AND user_id IS NULL AND issue_id IS NOT NULL)
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
  const mailMessages = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      DELETE FROM mail_messages WHERE id IN (
        SELECT id FROM mail_messages
         WHERE created_at < now() - make_interval(days => ${r.mailMessagesDays})
         LIMIT ${limit}
         FOR UPDATE SKIP LOCKED)`,
  );
  const abandonedMailMessages = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      UPDATE mail_messages
         SET status = 'failed', payload_enc = NULL, next_attempt_at = NULL,
             last_error = ${MAIL_GAVE_UP_TEXT}, updated_at = now()
       WHERE id IN (
         SELECT id FROM mail_messages
          WHERE status = 'pending'
            AND created_at < now() - make_interval(days => ${MAIL_GIVE_UP_DAYS})
          LIMIT ${limit}
          FOR UPDATE SKIP LOCKED)
         -- Re-checked on the row being updated: an attempt recorded meanwhile moved it on.
         AND status = 'pending'`,
  );
  const reviewSnapshots = await deleteInBatches(
    db,
    SNAPSHOT_BATCH,
    (limit) => sql`
      DELETE FROM review_snapshots WHERE id IN (
        SELECT id FROM review_snapshots
         WHERE created_at < now() - make_interval(days => ${r.reviewSnapshotsDays})
            OR (status = 'rejected'
                AND created_at < now() - make_interval(days => ${REJECTED_SNAPSHOT_DAYS}))
         LIMIT ${limit}
         FOR UPDATE SKIP LOCKED)`,
  );
  const reviewSnapshotsInactive = await purgeInactiveSnapshots(db, null);
  const reviewReplies = await deleteInBatches(
    db,
    BATCH,
    (limit) => sql`
      DELETE FROM review_replies WHERE id IN (
        SELECT id FROM review_replies
         WHERE status IN ('done', 'skipped', 'failed')
           AND finished_at < now() - make_interval(days => ${REVIEW_REPLY_DAYS})
         LIMIT ${limit}
         FOR UPDATE SKIP LOCKED)`,
  );
  const auditEvents = await pruneAuditStep(db, logger);
  const ssoStates = await pruneSsoStates(db);
  const accountTokens = await pruneAccountTokens(db);
  const clock = await db.execute<{ now: Date | string }>(sql`SELECT now() AS now`);
  const oauth = await cleanOAuth(db, new Date(clock.rows[0]?.now ?? Date.now()));
  const inactive = await cleanupStep(db, logger);
  return {
    analysisReports,
    closedIssues,
    branches,
    inactiveBranches: inactive.branches,
    inactiveMergeRequests: inactive.mergeRequests,
    webhookDeliveries,
    stalledWebhookDeliveries,
    llmRequests,
    llmPromptsCleared,
    jobs,
    sessions,
    auditEvents,
    ssoStates,
    accountTokens,
    mailMessages,
    abandonedMailMessages,
    reviewSnapshots,
    reviewSnapshotsInactive,
    reviewReplies,
    oauthRequests: oauth.requests,
    oauthTokens: oauth.tokens,
    oauthClients: oauth.clients,
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
