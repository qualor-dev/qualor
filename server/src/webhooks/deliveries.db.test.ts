import { eq } from 'drizzle-orm';
import { drizzle } from 'drizzle-orm/node-postgres';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestContext, organizationId, type TestContext } from '../../test/app';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import * as schema from '../db/schema';
import { jobs, webhookDeliveries, webhookSubscriptions } from '../db/schema';
import {
  createDeliveries,
  DELIVERY_INSERT_MAX_BYTES,
  WEBHOOK_SECRET_AAD,
  type NewDelivery,
} from './deliveries';

describe('createDeliveries batches its INSERTs by payload bytes (E1 wave)', () => {
  let t: TestContext;
  let hook: string;

  beforeAll(async () => {
    t = await createTestContext();
    const [row] = await t.db
      .insert(webhookSubscriptions)
      .values({
        organizationId: await organizationId(t, 'default'),
        url: 'https://hooks.example.com/',
        secretEnc: encryptSecret(
          encryptionKey(t.config.secretKey),
          'x'.repeat(16),
          WEBHOOK_SECRET_AAD,
        ),
        events: ['analysis.completed'],
      })
      .returning();
    hook = row!.id;
  });
  afterAll(async () => {
    await t.close();
  });

  const inserts = async (deliveries: readonly NewDelivery[]) => {
    const statements: string[] = [];
    const logged = drizzle({
      client: t.database.pool,
      schema,
      logger: { logQuery: (query) => void statements.push(query) },
    });
    const ids = await logged.transaction((tx) => createDeliveries(tx, deliveries));
    return {
      ids,
      count: statements.filter((q) => q.startsWith('insert into "webhook_deliveries"')).length,
    };
  };
  const payloadOf = (bytes: number, n: number) => ({ id: `a${n}`, text: 'x'.repeat(bytes) });

  it('keeps each INSERT under the byte bound, however many deliveries it carries', async () => {
    // 7 payloads of 40 % of the bound each: two fit an INSERT, three do not.
    const big = Array.from({ length: 7 }, (_, n) => ({
      subscriptionId: hook,
      event: 'analysis.completed' as const,
      payload: payloadOf(Math.floor(DELIVERY_INSERT_MAX_BYTES * 0.4), n),
    }));
    const first = await inserts(big);
    expect(first.ids).toHaveLength(7);
    expect(first.count).toBe(Math.ceil(7 / 2));
    // 100 small payloads fit one INSERT.
    const small = Array.from({ length: 100 }, (_, n) => ({
      subscriptionId: hook,
      event: 'analysis.completed' as const,
      payload: payloadOf(100, n),
    }));
    const second = await inserts(small);
    expect(second.ids).toHaveLength(100);
    expect(second.count).toBe(1);
    // One payload over the bound still goes, alone.
    const oversized = await inserts([
      {
        subscriptionId: hook,
        event: 'analysis.completed',
        payload: payloadOf(DELIVERY_INSERT_MAX_BYTES + 10, 0),
      },
      { subscriptionId: hook, event: 'analysis.completed', payload: payloadOf(10, 1) },
    ]);
    expect(oversized.count).toBe(2);
    // Every delivery has its first job, in order.
    const all = [...first.ids, ...second.ids, ...oversized.ids];
    const stored = await t.db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.subscriptionId, hook));
    expect(stored).toHaveLength(all.length);
    const queued = await t.db.select().from(jobs);
    const jobIds = new Set(queued.map((j) => (j.payload as { deliveryId: string }).deliveryId));
    for (const id of all) expect(jobIds.has(id)).toBe(true);
  });
});
