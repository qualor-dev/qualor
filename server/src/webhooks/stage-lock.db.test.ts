import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Db } from '../db/client';
import { webhookDeliveries, webhookSubscriptions } from '../db/schema';
import { createDeliveries, WEBHOOK_SECRET_AAD } from './deliveries';
import { subscriptionsToNotify } from './stage';

/** Resolves once a statement matching `pattern` waits on a lock (a barrier on the database). */
async function waitingOnLock(
  db: Db,
  pattern: string,
  until: { done: boolean },
): Promise<'waiting' | 'stopped'> {
  while (!until.done) {
    const result = await db.execute<{ n: number }>(sql`
      SELECT count(*)::int AS n FROM pg_stat_activity
       WHERE datname = current_database() AND wait_event_type = 'Lock' AND query ILIKE ${pattern}`);
    if ((result.rows[0]?.n ?? 0) > 0) return 'waiting';
    await new Promise((resolve) => setImmediate(resolve));
  }
  return 'stopped';
}

describe('webhook stage and a concurrent webhook DELETE (E1 wave)', () => {
  let h: IngestHarness;
  let project: IngestProject;

  beforeAll(async () => {
    h = await createIngestHarness();
    project = await h.project('acme/stage-lock');
  });
  afterAll(async () => {
    await h.close();
  });

  it('holds KEY SHARE on the webhooks it notifies: a DELETE waits instead of failing the ingestion', async () => {
    const [hook] = await h.ctx.db
      .insert(webhookSubscriptions)
      .values({
        organizationId: h.organizationId,
        url: 'https://hooks.example.com/',
        secretEnc: encryptSecret(
          encryptionKey(h.ctx.config.secretKey),
          'x'.repeat(16),
          WEBHOOK_SECRET_AAD,
        ),
        events: ['analysis.completed'],
      })
      .returning();
    let deleting: Promise<unknown> | undefined;
    await h.ctx.db.transaction(async (tx) => {
      const subscriptions = await subscriptionsToNotify(tx, {
        id: project.id,
        organizationId: h.organizationId,
      });
      expect(subscriptions.map((s) => s.id)).toEqual([hook!.id]);
      // An admin deletes the webhook while the ingestion is between choosing it and recording
      // its delivery: the DELETE waits for the ingestion...
      deleting = Promise.resolve(
        h.ctx.db.delete(webhookSubscriptions).where(eq(webhookSubscriptions.id, hook!.id)),
      );
      const until = { done: false };
      const first = await Promise.race([
        deleting.then(() => 'deleted' as const),
        waitingOnLock(h.ctx.db, 'delete from "webhook_subscriptions"%', until),
      ]);
      until.done = true;
      expect(first).toBe('waiting');
      // ...so the delivery insert (a foreign key to the webhook) succeeds.
      await createDeliveries(tx, [
        { subscriptionId: hook!.id, event: 'analysis.completed', payload: { id: 'a' } },
      ]);
    });
    // Then the DELETE goes through and takes the delivery with it.
    await deleting;
    expect(
      await h.ctx.db
        .select()
        .from(webhookDeliveries)
        .where(eq(webhookDeliveries.subscriptionId, hook!.id)),
    ).toEqual([]);
  });
});
