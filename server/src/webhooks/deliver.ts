import { and, eq, sql } from 'drizzle-orm';
import type { FastifyBaseLogger } from 'fastify';
import { z } from 'zod';
import { decryptSecret, encryptionKey } from '../crypto/secrets';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { webhookDeliveries, webhookSubscriptions } from '../db/schema';
import { VERSION } from '../index';
import { enqueue } from '../queue/queue';
import type { JobHandlers } from '../queue/worker';
import { DELIVERY_JOB_MAX_ATTEMPTS, WEBHOOK_QUEUE, WEBHOOK_SECRET_AAD } from './deliveries';
import { sendWebhook, UNREACHABLE_EXCERPT_PREFIXES, type Resolver, type SendOutcome } from './send';
import { signatureHeaders } from './sign';
import { webhookSettings, webhookUrlProblem } from './url';

/** api.md §3: the first attempt and up to 6 retries. */
export const MAX_DELIVERY_ATTEMPTS = 7;
/** api.md §3: 10 s per attempt. */
export const DELIVERY_TIMEOUT_MS = 10_000;

/**
 * Ruling X7: a job whose webhook already has an attempt in flight runs again this much later,
 * without using an attempt.
 */
export const BUSY_DEFER_SECONDS = 2;
/**
 * Attempts of one organisation's webhooks in flight at once, instance-wide (2 of the delivery
 * worker's 4 slots), so an organisation whose many webhooks are all unreachable cannot fill every
 * slot before their circuits open. A job over the bound is deferred like a busy webhook.
 */
export const MAX_IN_FLIGHT_PER_ORGANIZATION = 2;
/** Ruling X7: this many consecutive failed attempts of a webhook open its circuit ... */
export const CIRCUIT_FAILURES = 5;
/** ... for this long: its attempts fail at once, without a request. */
export const CIRCUIT_OPEN_MINUTES = 10;
/** How an attempt refused by an open circuit is recorded: the prefix, an ISO time, `)`. */
export const CIRCUIT_OPEN_EXCERPT_PREFIX = 'Receiver unreachable (circuit open until ';
/** Deliveries created longer ago than this are settled (about 64 min) and not consulted. */
const CIRCUIT_LOOKBACK_MS = 2 * 60 * 60_000;

const CIRCUIT_EXCERPT_PATTERN = String.raw`^Receiver unreachable \(circuit open until (\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z)\)$`;
const UNREACHABLE_PATTERN = `^(${UNREACHABLE_EXCERPT_PREFIXES.join('|')})`;

/**
 * api.md §3: 1 min after the first failed attempt, doubling to 32 min after the sixth, so a
 * delivery is settled about 63 minutes (plus 7 × 10 s) after its first attempt — far inside the
 * 30 days housekeeping keeps `webhook_deliveries` (ruling W4).
 */
export function retryDelaySeconds(failedAttempts: number): number {
  return 60 * 2 ** (failedAttempts - 1);
}

/** The smallest UUIDv7 of the millisecond `ms`: every id created at or after it sorts after it. */
function uuidv7Floor(ms: number): string {
  const hex = Math.max(0, Math.floor(ms)).toString(16).padStart(12, '0');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-0000-0000-000000000000`;
}

/**
 * Ruling X7's circuit breaker, derived from the webhook's own recent delivery history, so it needs
 * no state of its own (no schema change) and holds across every worker process. Returns the time
 * until which the circuit is open, or null when it is closed.
 *
 * Each delivery row records its last attempt: its outcome (`status`, `response_code`,
 * `response_excerpt`) and, while pending, its exact time (`next_attempt_at` minus the retry delay;
 * `now()` of the attempt's transaction). A settled row's time is estimated from `created_at` plus
 * the scheduled delays (a lower bound). An attempt is a success; a receiver failure (an HTTP error
 * status, or no answer: {@link UNREACHABLE_EXCERPT_PREFIXES}); or a refusal by an open circuit,
 * whose excerpt carries the time the circuit was open until (`response_code` null, so a
 * receiver's own answer can never pass for one). Refusals made without a request (an inactive
 * webhook, a secret, the URL settings) are ignored.
 *
 * The circuit is open until the later of:
 * - the latest time an open-circuit refusal recorded, so it stays open for its whole window even
 *   once the failures that opened it were overwritten by their own retries;
 * - 10 minutes after the latest attempt, when that attempt is a receiver failure and the last 5
 *   attempts are all failures (receiver failures or open-circuit refusals, so a failed attempt
 *   after the window, the half-open probe, opens the circuit again at once).
 */
async function circuitOpenUntil(tx: Executor, webhookId: string): Promise<Date | null> {
  const result = await tx.execute<{ open_until: Date | string | null; open: boolean | null }>(sql`
    WITH recent AS (
      SELECT CASE WHEN status = 'pending'
                  THEN next_attempt_at - make_interval(secs => 60 * power(2, attempts - 1))
                  ELSE created_at + make_interval(secs => 60 * (power(2, attempts - 1) - 1))
             END AS at,
             CASE WHEN status = 'succeeded' THEN 'ok'
                  WHEN response_code IS NOT NULL OR response_excerpt ~ ${UNREACHABLE_PATTERN}
                    THEN 'failed'
                  WHEN response_excerpt ~ ${CIRCUIT_EXCERPT_PATTERN} THEN 'circuit'
             END AS kind,
             CASE WHEN response_code IS NULL AND response_excerpt ~ ${CIRCUIT_EXCERPT_PATTERN}
                  THEN substring(response_excerpt FROM ${CIRCUIT_EXCERPT_PATTERN})::timestamptz
             END AS recorded_until
        FROM webhook_deliveries
       WHERE subscription_id = ${webhookId}
         AND id >= ${uuidv7Floor(Date.now() - CIRCUIT_LOOKBACK_MS)}::uuid
         AND attempts >= 1
    ), streak AS (
      SELECT kind, at FROM recent WHERE kind IS NOT NULL ORDER BY at DESC LIMIT ${CIRCUIT_FAILURES}
    ), bounds AS (
      SELECT (SELECT max(recorded_until) FROM recent) AS recorded,
             (SELECT CASE WHEN count(*) = ${CIRCUIT_FAILURES} AND bool_and(kind <> 'ok')
                           AND (array_agg(kind ORDER BY at DESC))[1] = 'failed'
                          THEN max(at) + make_interval(mins => ${CIRCUIT_OPEN_MINUTES})
                     END FROM streak) AS opened
    )
    SELECT greatest(recorded, opened) AS open_until, greatest(recorded, opened) > now() AS open
      FROM bounds`);
  const [row] = result.rows;
  if (!row?.open || row.open_until === null) return null;
  return row.open_until instanceof Date ? row.open_until : new Date(row.open_until);
}

export interface DeliveryDeps {
  db: Db;
  secretKey: string;
  logger?: Pick<FastifyBaseLogger, 'info' | 'warn'> | undefined;
  /** Tests shorten the timeouts and substitute DNS. */
  timeoutMs?: number;
  connectTimeoutMs?: number;
  resolve?: Resolver;
}

/** `busy`: another attempt of the same webhook is in flight; the job is to run again later. */
export type DeliveryResult = 'gone' | 'settled' | 'busy' | 'succeeded' | 'retrying' | 'failed';

/**
 * One delivery attempt (ruling W4). At-least-once: a worker that dies after the POST but before
 * recording it repeats the attempt, so receivers deduplicate on `X-Qualor-Delivery`.
 *
 * - Ruling X7: at most one attempt per webhook is in flight, instance-wide. The attempt runs in a
 *   transaction holding an advisory lock keyed by the webhook (released at commit, or when a dead
 *   worker's connection closes); when another attempt holds it this returns `busy` at once,
 *   touching nothing, and the handler runs the job again {@link BUSY_DEFER_SECONDS} later. One
 *   unreachable receiver therefore occupies at most one delivery slot, for one attempt's deadline,
 *   and one organisation at most {@link MAX_IN_FLIGHT_PER_ORGANIZATION} slots.
 * - A delivery whose row is gone (webhook deleted, or housekeeping after 30 days) or that is no
 *   longer `pending` completes as a no-op (read again under the lock, so a duplicate job that ran
 *   after the attempt it duplicates sends nothing).
 * - An inactive webhook, a secret that no longer decrypts (`QUALOR_SECRET_KEY` changed) or a URL
 *   the instance settings no longer allow fail the delivery at once, without a request.
 * - Ruling X7: while the webhook's circuit is open ({@link circuitOpenUntil}) the attempt fails at
 *   once, without a request, and is recorded and retried like any failed attempt.
 * - Otherwise the attempt is sent (connected within 3 s, all of it within 10 s); its outcome is
 *   recorded fenced on `attempts`, so a duplicate run of the same attempt records nothing, and a
 *   retry is scheduled as a new job in the same transaction. Each job names the attempts made
 *   before it (`expectedAttempts`; the first job, from createDelivery, implies 0): a job whose
 *   attempt is already recorded (a job reaped and requeued after its worker died) is a no-op, so
 *   it can never start a second retry chain.
 */
export async function deliverWebhook(
  deps: DeliveryDeps,
  deliveryId: string,
  expectedAttempts?: number,
): Promise<DeliveryResult> {
  const load = async (db: Executor) => {
    const [found] = await db
      .select({ delivery: webhookDeliveries, webhook: webhookSubscriptions })
      .from(webhookDeliveries)
      .innerJoin(
        webhookSubscriptions,
        eq(webhookSubscriptions.id, webhookDeliveries.subscriptionId),
      )
      .where(eq(webhookDeliveries.id, deliveryId));
    return found;
  };
  const isStale = (row: NonNullable<Awaited<ReturnType<typeof load>>>): boolean =>
    row.delivery.status !== 'pending' ||
    (expectedAttempts !== undefined && row.delivery.attempts !== expectedAttempts);
  const first = await load(deps.db);
  if (!first) return 'gone';
  if (isStale(first)) return 'settled';

  return deps.db.transaction(async (tx): Promise<DeliveryResult> => {
    const lock = await tx.execute<{ locked: boolean }>(
      sql`SELECT pg_try_advisory_xact_lock(${LOCKS.webhookDelivery}, hashtext(${first.webhook.id}::text)) AS locked`,
    );
    if (!lock.rows[0]?.locked) return 'busy';
    // Read again under the lock: the attempt this job waited behind may have settled it.
    const row = await load(tx);
    if (!row) return 'gone';
    if (isStale(row)) return 'settled';
    const { delivery, webhook } = row;
    // One of the organisation's slots (try-locks, so never a wait; a hash collision between two
    // organisations only shares their slots).
    let slot = false;
    for (let i = 0; i < MAX_IN_FLIGHT_PER_ORGANIZATION && !slot; i++) {
      const taken = await tx.execute<{ locked: boolean }>(
        sql`SELECT pg_try_advisory_xact_lock(${LOCKS.webhookOrganizationSlot}, hashtext(${`${webhook.organizationId}:${i}`}::text)) AS locked`,
      );
      slot = taken.rows[0]?.locked === true;
    }
    if (!slot) return 'busy';

    const record = async (outcome: SendOutcome, final: boolean): Promise<DeliveryResult> => {
      const attempts = delivery.attempts + 1;
      const status = outcome.ok
        ? 'succeeded'
        : final || attempts >= MAX_DELIVERY_ATTEMPTS
          ? 'failed'
          : 'pending';
      const [updated] = await tx
        .update(webhookDeliveries)
        .set({
          status,
          attempts,
          responseCode: outcome.status,
          responseExcerpt: outcome.excerpt,
          // now() is the start of this transaction, i.e. of the attempt (the circuit reads it back).
          nextAttemptAt:
            status === 'pending'
              ? sql`now() + make_interval(secs => ${retryDelaySeconds(attempts)})`
              : null,
        })
        .where(
          and(
            eq(webhookDeliveries.id, delivery.id),
            eq(webhookDeliveries.status, 'pending'),
            eq(webhookDeliveries.attempts, delivery.attempts),
          ),
        )
        .returning({ nextAttemptAt: webhookDeliveries.nextAttemptAt });
      // Deleted meanwhile, or a duplicate run of this attempt recorded it first.
      if (!updated) return 'settled';
      if (status === 'pending' && updated.nextAttemptAt) {
        await enqueue(tx, {
          queue: WEBHOOK_QUEUE,
          payload: { deliveryId: delivery.id, attempts },
          runAt: updated.nextAttemptAt,
          maxAttempts: DELIVERY_JOB_MAX_ATTEMPTS,
        });
      }
      deps.logger?.info(
        {
          deliveryId: delivery.id,
          webhookId: webhook.id,
          attempts,
          status,
          responseCode: outcome.status,
        },
        'webhook delivery attempt',
      );
      return status === 'pending' ? 'retrying' : status;
    };
    const refuse = (excerpt: string) => record({ ok: false, status: null, excerpt }, true);

    if (!webhook.active) return refuse('The webhook is inactive');
    const secret = decryptSecret(
      encryptionKey(deps.secretKey),
      webhook.secretEnc,
      WEBHOOK_SECRET_AAD,
    );
    if (secret === null) {
      return refuse(
        'The webhook secret cannot be decrypted (QUALOR_SECRET_KEY changed?); set a new secret',
      );
    }
    const settings = await webhookSettings(tx);
    const problem = webhookUrlProblem(webhook.url, settings);
    if (problem) return refuse(problem);
    const openUntil = await circuitOpenUntil(tx, webhook.id);
    if (openUntil) {
      const excerpt = `${CIRCUIT_OPEN_EXCERPT_PREFIX}${openUntil.toISOString()})`;
      return record({ ok: false, status: null, excerpt }, false);
    }

    const body = JSON.stringify(delivery.payload);
    const outcome = await sendWebhook(
      {
        url: webhook.url,
        body,
        headers: {
          'content-type': 'application/json',
          'user-agent': `Qualor-Webhook/${VERSION}`,
          'x-qualor-event': delivery.event,
          'x-qualor-delivery': delivery.id,
          ...signatureHeaders(secret, body, Math.floor(Date.now() / 1000)),
        },
      },
      {
        allowInternalHosts: settings.allowInternalHosts,
        timeoutMs: deps.timeoutMs ?? DELIVERY_TIMEOUT_MS,
        ...(deps.connectTimeoutMs === undefined ? {} : { connectTimeoutMs: deps.connectTimeoutMs }),
        ...(deps.resolve ? { resolve: deps.resolve } : {}),
      },
    );
    return record(outcome, false);
  });
}

/** `attempts`: the attempts made before this job's; absent on the first job (createDelivery). */
const deliveryPayload = z.object({
  deliveryId: z.uuid(),
  attempts: z.number().int().min(0).optional(),
});

/** The `webhook` queue's handler; its own worker runs it (main.ts), apart from analyses. */
export function webhookHandlers(deps: DeliveryDeps): JobHandlers {
  return {
    [WEBHOOK_QUEUE]: async (job) => {
      const parsed = deliveryPayload.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger?.warn(
          { jobId: job.id },
          'malformed webhook job payload; completing without retry',
        );
        return;
      }
      const { deliveryId } = parsed.data;
      const attempts = parsed.data.attempts ?? 0;
      if ((await deliverWebhook(deps, deliveryId, attempts)) === 'busy') {
        // Ruling X7: the same attempt again shortly, rather than a slot held while waiting.
        await enqueue(deps.db, {
          queue: WEBHOOK_QUEUE,
          payload: { deliveryId, attempts },
          runAt: sql`now() + make_interval(secs => ${BUSY_DEFER_SECONDS})`,
          maxAttempts: DELIVERY_JOB_MAX_ATTEMPTS,
        });
      }
    },
  };
}
