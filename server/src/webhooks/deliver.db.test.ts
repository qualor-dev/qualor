import { createHmac } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestContext, organizationId, type TestContext } from '../../test/app';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { first } from '../db/rows';
import { instanceSettings, jobs, webhookDeliveries, webhookSubscriptions } from '../db/schema';
import { enqueue } from '../queue/queue';
import { runUntilIdle } from '../queue/worker';
import {
  createDelivery,
  DELIVERY_JOB_MAX_ATTEMPTS,
  WEBHOOK_QUEUE,
  WEBHOOK_SECRET_AAD,
  type WebhookEvent,
} from './deliveries';
import {
  deliverWebhook,
  MAX_DELIVERY_ATTEMPTS,
  retryDelaySeconds,
  webhookHandlers,
  type DeliveryDeps,
} from './deliver';

const SECRET = 'whsec_test-secret-value';
const silent = { info: () => undefined, warn: () => undefined, error: () => undefined };

interface Received {
  headers: IncomingMessage['headers'];
  body: string;
}

describe('webhook delivery job (api.md §3, ruling W4)', () => {
  let t: TestContext;
  let org: string;
  let server: Server;
  let port: number;
  let received: Received[];
  let respond: (res: ServerResponse) => void;
  let deps: DeliveryDeps;

  const subscription = async (
    overrides: Partial<typeof webhookSubscriptions.$inferInsert> = {},
  ): Promise<string> =>
    first(
      await t.db
        .insert(webhookSubscriptions)
        .values({
          organizationId: org,
          url: `http://127.0.0.1:${port}/hook`,
          secretEnc: encryptSecret(encryptionKey(t.config.secretKey), SECRET, WEBHOOK_SECRET_AAD),
          events: ['analysis.completed'],
          ...overrides,
        })
        .returning({ id: webhookSubscriptions.id }),
    ).id;
  const delivery = (subscriptionId: string, payload: unknown = { id: 'a1', status: 'succeeded' }) =>
    t.db.transaction((tx) =>
      createDelivery(tx, {
        subscriptionId,
        event: 'analysis.completed' as WebhookEvent,
        payload,
      }),
    );
  const row = async (id: string) =>
    first(await t.db.select().from(webhookDeliveries).where(eq(webhookDeliveries.id, id)));
  const queuedJobs = (deliveryId: string) =>
    t.db
      .select()
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, WEBHOOK_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'deliveryId' = ${deliveryId}`,
        ),
      );
  /** Makes every queued retry due now, then runs the webhook queue until idle. */
  const runDue = async () => {
    await t.db
      .update(jobs)
      .set({ runAt: sql`now()` })
      .where(eq(jobs.queue, WEBHOOK_QUEUE));
    return runUntilIdle(t.db, webhookHandlers(deps), silent);
  };

  beforeAll(async () => {
    t = await createTestContext();
    org = await organizationId(t, 'default');
    // Deliveries to the local receiver need both settings (the defaults refuse it).
    await t.db
      .insert(instanceSettings)
      .values({ key: 'webhooks', value: { allowHttp: true, allowInternalHosts: true } });
    server = createServer((req, res) => {
      const chunks: Buffer[] = [];
      req.on('data', (c: Buffer) => chunks.push(c));
      req.on('end', () => {
        received.push({ headers: req.headers, body: Buffer.concat(chunks).toString() });
        respond(res);
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    port = (server.address() as AddressInfo).port;
    deps = { db: t.db, secretKey: t.config.secretKey, timeoutMs: 1_000 };
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await t.close();
  });
  beforeEach(() => {
    received = [];
    respond = (res) => res.writeHead(204).end();
  });

  it('delivers once with the documented headers; a receiver verifies the signature', async () => {
    const id = await delivery(await subscription(), { id: 'a1', gateStatus: 'failed' });
    expect(await runUntilIdle(t.db, webhookHandlers(deps), silent)).toBe(1);
    expect(received).toHaveLength(1);
    const [request] = received;
    expect(request!.headers).toMatchObject({
      'content-type': 'application/json',
      'x-qualor-event': 'analysis.completed',
      'x-qualor-delivery': id,
    });
    expect(request!.headers['user-agent']).toMatch(/^Qualor-Webhook\//);
    expect(JSON.parse(request!.body)).toEqual({ id: 'a1', gateStatus: 'failed' });
    // The receiver side of api.md §3, written independently of sign.ts.
    const timestamp = String(request!.headers['x-qualor-timestamp']);
    expect(Math.abs(Number(timestamp) - Date.now() / 1000)).toBeLessThan(60);
    const expected = createHmac('sha256', SECRET)
      .update(`${timestamp}.${request!.body}`)
      .digest('hex');
    expect(request!.headers['x-qualor-signature']).toBe(`sha256=${expected}`);
    expect(await row(id)).toMatchObject({
      status: 'succeeded',
      attempts: 1,
      responseCode: 204,
      responseExcerpt: null,
      nextAttemptAt: null,
    });
  });

  it('retries with exponential backoff (1 → 32 min), then fails after 7 attempts', async () => {
    respond = (res) => res.writeHead(500).end('receiver down');
    const id = await delivery(await subscription());
    await runUntilIdle(t.db, webhookHandlers(deps), silent);
    const afterFirst = await row(id);
    expect(afterFirst).toMatchObject({
      status: 'pending',
      attempts: 1,
      responseCode: 500,
      responseExcerpt: 'receiver down',
    });
    const [retry] = await queuedJobs(id);
    expect(retry!.runAt.getTime()).toBe(afterFirst.nextAttemptAt!.getTime());
    // Exactly 1 min after the attempt: the retry job is inserted in the attempt's transaction,
    // so its created_at is the same now() the delay was added to (no wall-clock window).
    expect(retry!.runAt.getTime() - retry!.createdAt.getTime()).toBe(60_000);
    for (let attempt = 2; attempt <= MAX_DELIVERY_ATTEMPTS; attempt++) await runDue();
    expect(await row(id)).toMatchObject({
      status: 'failed',
      attempts: MAX_DELIVERY_ATTEMPTS,
      nextAttemptAt: null,
    });
    expect(await queuedJobs(id)).toEqual([]);
    expect(received).toHaveLength(MAX_DELIVERY_ATTEMPTS);
    expect([1, 2, 3, 4, 5, 6].map(retryDelaySeconds)).toEqual([60, 120, 240, 480, 960, 1_920]);
    // Every attempt settles within about 64 minutes: far inside the 30-day retention.
    expect([1, 2, 3, 4, 5, 6].reduce((sum, n) => sum + retryDelaySeconds(n), 0)).toBe(3_780);
  });

  it('succeeds on a retry', async () => {
    let calls = 0;
    respond = (res) => {
      calls += 1;
      res.writeHead(calls === 1 ? 503 : 200).end();
    };
    const id = await delivery(await subscription());
    await runUntilIdle(t.db, webhookHandlers(deps), silent);
    await runDue();
    expect(await row(id)).toMatchObject({ status: 'succeeded', attempts: 2, responseCode: 200 });
  });

  it('completes as a no-op when the delivery row is gone, or no longer pending', async () => {
    const hook = await subscription();
    const gone = await delivery(hook);
    await t.db.delete(webhookDeliveries).where(eq(webhookDeliveries.id, gone));
    expect(await runUntilIdle(t.db, webhookHandlers(deps), silent)).toBe(1);
    const [job] = await t.db
      .select()
      .from(jobs)
      .where(sql`${jobs.payload} ->> 'deliveryId' = ${gone}`);
    expect(job!.status).toBe('succeeded');
    expect(await deliverWebhook(deps, gone)).toBe('gone');
    const done = await delivery(hook);
    await t.db
      .update(webhookDeliveries)
      .set({ status: 'succeeded' })
      .where(eq(webhookDeliveries.id, done));
    expect(await deliverWebhook(deps, done)).toBe('settled');
    expect(received).toEqual([]);
  });

  it('fails at once, without a request, for an inactive webhook or an undecryptable secret', async () => {
    const inactive = await delivery(await subscription({ active: false }));
    expect(await deliverWebhook(deps, inactive)).toBe('failed');
    expect(await row(inactive)).toMatchObject({
      status: 'failed',
      attempts: 1,
      responseExcerpt: 'The webhook is inactive',
    });
    const rotated = await delivery(
      await subscription({
        secretEnc: encryptSecret(
          encryptionKey('a-different-server-key-of-32-characters'),
          SECRET,
          WEBHOOK_SECRET_AAD,
        ),
      }),
    );
    expect(await deliverWebhook(deps, rotated)).toBe('failed');
    expect((await row(rotated)).responseExcerpt).toMatch(/cannot be decrypted/);
    expect(received).toEqual([]);
  });

  it('re-checks the URL at delivery time: an internal host is refused once the setting is off', async () => {
    const id = await delivery(await subscription());
    await t.db
      .update(instanceSettings)
      .set({ value: { allowHttp: true } })
      .where(eq(instanceSettings.key, 'webhooks'));
    try {
      expect(await deliverWebhook(deps, id)).toBe('failed');
      expect((await row(id)).responseExcerpt).toMatch(/non-public/);
      // A host name that resolves inside the network is refused the same way.
      const named = await delivery(await subscription({ url: `http://hooks.test:${port}/` }));
      const resolveInternal = async () => [{ address: '10.1.2.3', family: 4 }];
      expect(await deliverWebhook({ ...deps, resolve: resolveInternal }, named)).toBe('retrying');
      expect((await row(named)).responseExcerpt).toMatch(/non-public/);
      expect(received).toEqual([]);
    } finally {
      await t.db
        .update(instanceSettings)
        .set({ value: { allowHttp: true, allowInternalHosts: true } })
        .where(eq(instanceSettings.key, 'webhooks'));
    }
  });

  it('records a duplicate run of the same attempt only once (webhook lock, then attempts fence)', async () => {
    const id = await delivery(await subscription());
    const [a, b] = await Promise.all([deliverWebhook(deps, id), deliverWebhook(deps, id)]);
    // The duplicate either found the webhook busy (ruling X7) or, run after the first attempt
    // committed, found the delivery settled; either way it sent nothing.
    const results = [a, b];
    expect(results).toContain('succeeded');
    expect(['busy', 'settled']).toContain(results.find((r) => r !== 'succeeded'));
    expect(received).toHaveLength(1);
    expect(await row(id)).toMatchObject({ status: 'succeeded', attempts: 1 });
  });
  it('ignores a stale job for an attempt already recorded (a reaped duplicate)', async () => {
    respond = (res) => res.writeHead(500).end();
    const id = await delivery(await subscription());
    await runUntilIdle(t.db, webhookHandlers(deps), silent);
    expect(await row(id)).toMatchObject({ status: 'pending', attempts: 1 });
    // The first attempt's job again, as if its worker died after recording the outcome.
    await enqueue(t.db, {
      queue: WEBHOOK_QUEUE,
      payload: { deliveryId: id },
      maxAttempts: DELIVERY_JOB_MAX_ATTEMPTS,
    });
    expect(await runUntilIdle(t.db, webhookHandlers(deps), silent)).toBe(1);
    expect(received).toHaveLength(1);
    expect(await row(id)).toMatchObject({ status: 'pending', attempts: 1 });
    // The scheduled retry carries the attempt it is for, and still runs.
    const [retry] = await queuedJobs(id);
    expect(retry!.payload).toEqual({ deliveryId: id, attempts: 1 });
    await runDue();
    expect(received).toHaveLength(2);
    expect((await row(id)).attempts).toBe(2);
  });

  it('never logs the URL, the secret, the body or the signature', async () => {
    const lines: string[] = [];
    const capture = {
      info: (...args: unknown[]) => void lines.push(JSON.stringify(args)),
      warn: (...args: unknown[]) => void lines.push(JSON.stringify(args)),
    };
    const id = await delivery(await subscription(), { marker: 'payload-marker' });
    expect(await deliverWebhook({ ...deps, logger: capture }, id)).toBe('succeeded');
    expect(lines.length).toBeGreaterThan(0);
    const logged = lines.join('\n');
    expect(logged).toContain(id);
    for (const secretish of [SECRET, `127.0.0.1:${port}`, 'payload-marker', 'sha256=', '/hook']) {
      expect(logged).not.toContain(secretish);
    }
  });
});
