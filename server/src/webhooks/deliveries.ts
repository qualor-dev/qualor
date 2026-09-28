import { sql } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { first } from '../db/rows';
import { webhookDeliveries } from '../db/schema';
import { enqueueMany } from '../queue/queue';

/** api.md §3: the webhook events of v0. */
export const WEBHOOK_EVENTS = ['analysis.completed', 'gate.status_changed'] as const;
export type WebhookEvent = (typeof WEBHOOK_EVENTS)[number];

/** Deliveries run on their own queue and worker, so a slow receiver never delays analyses. */
export const WEBHOOK_QUEUE = 'webhook';

/**
 * One delivery attempt is one job; the handler (webhooks/deliver.ts) enqueues the next attempt
 * itself. The job's own retries are only for database failures around an attempt.
 */
export const DELIVERY_JOB_MAX_ATTEMPTS = 3;

/** The `aad` of `webhook_subscriptions.secret_enc` (crypto/secrets.ts). */
export const WEBHOOK_SECRET_AAD = 'webhook_subscriptions.secret_enc';

export interface NewDelivery {
  subscriptionId: string;
  event: WebhookEvent;
  payload: unknown;
}

/**
 * Payload bytes per INSERT in {@link createDeliveries}. A payload can be several hundred KiB (up
 * to 100 warnings and 64 engines of 4 000 characters each), so a fan-out to 50 webhooks × 2
 * events is written in statements of at most about this many parameter bytes rather than one
 * (a single larger payload goes alone).
 */
export const DELIVERY_INSERT_MAX_BYTES = 4 * 1024 * 1024;

/**
 * A pending delivery whose next attempt is this long overdue has lost its job (it died on
 * database errors): housekeeping fails it, and the redelivery bound ignores it.
 */
export const STALLED_DELIVERY_MINUTES = 60;

/** Consecutive runs of `inputs` whose serialised payloads stay within `maxBytes` together. */
function batchesByBytes(inputs: readonly NewDelivery[], maxBytes: number): NewDelivery[][] {
  const sizes = new Map<unknown, number>();
  const sizeOf = (payload: unknown): number => {
    // The stage shares one payload object between webhooks: serialise it once.
    let size = sizes.get(payload);
    if (size === undefined) {
      size = Buffer.byteLength(JSON.stringify(payload) ?? 'null', 'utf8');
      sizes.set(payload, size);
    }
    return size;
  };
  const batches: NewDelivery[][] = [];
  let current: NewDelivery[] = [];
  let bytes = 0;
  for (const input of inputs) {
    const size = sizeOf(input.payload);
    if (current.length > 0 && bytes + size > maxBytes) {
      batches.push(current);
      current = [];
      bytes = 0;
    }
    current.push(input);
    bytes += size;
  }
  if (current.length > 0) batches.push(current);
  return batches;
}

/**
 * Stores pending deliveries and enqueues each one's first attempt, in the caller's transaction
 * (the ingestion transaction for new events, so an analysis that rolls back sends nothing).
 * Returns the ids of the created deliveries.
 */
export async function createDeliveries(
  tx: Executor,
  inputs: readonly NewDelivery[],
): Promise<string[]> {
  const ids: string[] = [];
  for (const batch of batchesByBytes(inputs, DELIVERY_INSERT_MAX_BYTES)) {
    const rows = await tx
      .insert(webhookDeliveries)
      .values(
        batch.map((input) => ({
          subscriptionId: input.subscriptionId,
          event: input.event,
          payload: input.payload,
          status: 'pending' as const,
          nextAttemptAt: sql`now()`,
        })),
      )
      .returning({ id: webhookDeliveries.id });
    const batchIds = rows.map((r) => r.id);
    await enqueueMany(
      tx,
      batchIds.map((deliveryId) => ({
        queue: WEBHOOK_QUEUE,
        payload: { deliveryId },
        maxAttempts: DELIVERY_JOB_MAX_ATTEMPTS,
      })),
    );
    ids.push(...batchIds);
  }
  return ids;
}

/** {@link createDeliveries} for one delivery (redelivery, tests). */
export async function createDelivery(tx: Executor, input: NewDelivery): Promise<string> {
  return first(await createDeliveries(tx, [input]));
}
