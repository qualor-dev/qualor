import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createTcpServer, type AddressInfo, type Socket } from 'node:net';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestContext, organizationId, type TestContext } from '../../test/app';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { first } from '../db/rows';
import {
  instanceSettings,
  jobs,
  organizations,
  webhookDeliveries,
  webhookSubscriptions,
} from '../db/schema';
import { runUntilIdle, startWorker } from '../queue/worker';
import { createDelivery, WEBHOOK_QUEUE, WEBHOOK_SECRET_AAD } from './deliveries';
import {
  BUSY_DEFER_SECONDS,
  MAX_IN_FLIGHT_PER_ORGANIZATION,
  CIRCUIT_FAILURES,
  CIRCUIT_OPEN_EXCERPT_PREFIX,
  CIRCUIT_OPEN_MINUTES,
  deliverWebhook,
  MAX_DELIVERY_ATTEMPTS,
  webhookHandlers,
  type DeliveryDeps,
} from './deliver';

/** An open-circuit refusal's excerpt: when the circuit was open until. */
const circuitOpen = expect.stringMatching(
  /^Receiver unreachable \(circuit open until \d{4}-\d{2}-\d{2}T[\d:.]+Z\)$/,
);

const silent = { info: () => undefined, warn: () => undefined, error: () => undefined };

/** A promise and the function that resolves it: a barrier the test controls. */
function barrier<T = void>(): { promise: Promise<T>; open: (value: T) => void } {
  let open: ((value: T) => void) | undefined;
  const promise = new Promise<T>((resolve) => {
    open = resolve;
  });
  return { promise, open: (value) => open?.(value) };
}

async function listen(server: Server | ReturnType<typeof createTcpServer>): Promise<number> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return (server.address() as AddressInfo).port;
}

describe('webhook delivery isolation (ruling X7)', () => {
  let t: TestContext;
  let org: string;
  let deps: DeliveryDeps;
  /** An http receiver whose answer each test decides. */
  let receiver: Server;
  let receiverPort: number;
  let respond: (req: IncomingMessage, res: ServerResponse) => void;
  let requests: string[];

  const subscription = async (url: string, organization = org): Promise<string> =>
    first(
      await t.db
        .insert(webhookSubscriptions)
        .values({
          organizationId: organization,
          url,
          secretEnc: encryptSecret(
            encryptionKey(t.config.secretKey),
            'whsec_isolation-secret',
            WEBHOOK_SECRET_AAD,
          ),
          events: ['analysis.completed'],
        })
        .returning({ id: webhookSubscriptions.id }),
    ).id;
  const delivery = (subscriptionId: string) =>
    t.db.transaction((tx) =>
      createDelivery(tx, { subscriptionId, event: 'analysis.completed', payload: { id: 'a1' } }),
    );
  const row = async (id: string) =>
    first(await t.db.select().from(webhookDeliveries).where(eq(webhookDeliveries.id, id)));
  const jobsOf = (deliveryId: string) =>
    t.db
      .select()
      .from(jobs)
      .where(
        and(eq(jobs.queue, WEBHOOK_QUEUE), sql`${jobs.payload} ->> 'deliveryId' = ${deliveryId}`),
      )
      .orderBy(jobs.id);
  /** Every queued webhook job due now: the time a test skips over. */
  const makeDue = () =>
    t.db
      .update(jobs)
      .set({ runAt: sql`now()` })
      .where(and(eq(jobs.queue, WEBHOOK_QUEUE), eq(jobs.status, 'queued')));
  /**
   * Moves a webhook's delivery history `minutes` into the past (the clock moving on), the time an
   * open-circuit refusal recorded in its excerpt included.
   */
  const age = async (subscriptionId: string, minutes: number) => {
    const rows = await t.db
      .select()
      .from(webhookDeliveries)
      .where(eq(webhookDeliveries.subscriptionId, subscriptionId));
    for (const r of rows) {
      const shift = (d: Date | null) => (d ? new Date(d.getTime() - minutes * 60_000) : null);
      const until = r.responseExcerpt?.startsWith(CIRCUIT_OPEN_EXCERPT_PREFIX)
        ? r.responseExcerpt.slice(CIRCUIT_OPEN_EXCERPT_PREFIX.length, -1)
        : null;
      await t.db
        .update(webhookDeliveries)
        .set({
          nextAttemptAt: shift(r.nextAttemptAt),
          createdAt: shift(r.createdAt)!,
          ...(until
            ? {
                responseExcerpt: `${CIRCUIT_OPEN_EXCERPT_PREFIX}${shift(new Date(until))!.toISOString()})`,
              }
            : {}),
        })
        .where(eq(webhookDeliveries.id, r.id));
    }
  };
  /** Drops every queued webhook job (earlier tests' retries must not run in later ones). */
  const clearQueue = () =>
    t.db.delete(jobs).where(and(eq(jobs.queue, WEBHOOK_QUEUE), eq(jobs.status, 'queued')));

  beforeAll(async () => {
    t = await createTestContext();
    org = await organizationId(t, 'default');
    await t.db
      .insert(instanceSettings)
      .values({ key: 'webhooks', value: { allowHttp: true, allowInternalHosts: true } });
    receiver = createServer((req, res) => {
      req.resume();
      req.on('end', () => {
        requests.push(req.url ?? '');
        respond(req, res);
      });
    });
    receiverPort = await listen(receiver);
    deps = { db: t.db, secretKey: t.config.secretKey, timeoutMs: 30_000 };
  });
  afterAll(async () => {
    receiver.closeAllConnections();
    await new Promise<void>((resolve) => receiver.close(() => resolve()));
    await t.close();
  });
  beforeEach(async () => {
    requests = [];
    respond = (_req, res) => res.writeHead(204).end();
    await clearQueue();
  });

  it('runs at most one attempt per webhook: a second one is deferred without using an attempt', async () => {
    const arrived = barrier();
    const release = barrier();
    respond = (_req, res) => {
      arrived.open();
      void release.promise.then(() => res.writeHead(204).end());
    };
    const hook = await subscription(`http://127.0.0.1:${receiverPort}/one-at-a-time`);
    const firstDelivery = await delivery(hook);
    const secondDelivery = await delivery(hook);
    // The first attempt is in flight (its receiver holds the answer)...
    const inFlight = deliverWebhook(deps, firstDelivery, 0);
    await arrived.promise;
    // ...so the second delivery's job finds its webhook busy: no request, no attempt used, and
    // the same job again a few seconds later.
    await t.db
      .update(jobs)
      .set({ status: 'succeeded' })
      .where(sql`${jobs.payload} ->> 'deliveryId' = ${firstDelivery}`);
    const before = await jobsOf(secondDelivery);
    expect(before).toHaveLength(1);
    expect(await runUntilIdle(t.db, webhookHandlers(deps), silent)).toBe(1);
    expect(requests).toHaveLength(1);
    expect(await row(secondDelivery)).toMatchObject({ status: 'pending', attempts: 0 });
    const after = await jobsOf(secondDelivery);
    expect(after.map((j) => j.status)).toEqual(['succeeded', 'queued']);
    expect(after[1]!.payload).toEqual({ deliveryId: secondDelivery, attempts: 0 });
    const deferredBy = await t.db.execute<{ s: number }>(sql`
      SELECT extract(epoch FROM j.run_at - j.created_at)::int AS s FROM jobs j WHERE j.id = ${after[1]!.id}`);
    expect(deferredBy.rows[0]!.s).toBe(BUSY_DEFER_SECONDS);
    release.open();
    expect(await inFlight).toBe('succeeded');
    // Once the first attempt is over, the deferred job delivers.
    await makeDue();
    expect(await runUntilIdle(t.db, webhookHandlers(deps), silent)).toBe(1);
    expect(await row(secondDelivery)).toMatchObject({ status: 'succeeded', attempts: 1 });
    expect(requests).toHaveLength(2);
  });

  it('keeps delivering promptly for other organisations while a receiver never answers', async () => {
    // A receiver that accepts connections and never answers, with a 30 s deadline per attempt:
    // before X7, its deliveries took all 4 worker slots for 30 s.
    const blackholeSockets: Socket[] = [];
    const connected: Array<() => void> = [];
    const blackhole = createTcpServer((socket) => {
      blackholeSockets.push(socket);
      connected.shift()?.();
    });
    const blackholePort = await listen(blackhole);
    const firstConnection = barrier();
    connected.push(() => firstConnection.open());
    const other = first(
      await t.db
        .insert(organizations)
        .values({ key: 'isolation-other', name: 'Other' })
        .returning({ id: organizations.id }),
    ).id;
    const stuck = await subscription(`http://127.0.0.1:${blackholePort}/never`);
    const stuckDeliveries: string[] = [];
    for (let i = 0; i < 8; i++) stuckDeliveries.push(await delivery(stuck));
    let healthy: string | undefined;
    const worker = startWorker({
      db: t.db,
      handlers: webhookHandlers(deps),
      concurrency: 4,
      logger: silent,
      pollIntervalMs: 10,
    });
    try {
      await firstConnection.promise;
      const healthyArrived = barrier();
      respond = (_req, res) => {
        res.writeHead(204).end();
        healthyArrived.open();
      };
      healthy = await delivery(
        await subscription(`http://127.0.0.1:${receiverPort}/healthy`, other),
      );
      // Delivered while the blackhole attempt is still hanging (it has 30 s to go).
      await healthyArrived.promise;
      expect(blackholeSockets).toHaveLength(1);
      // The blackhole's other deliveries were deferred, not attempted.
      const stuckRows = await Promise.all(stuckDeliveries.map(row));
      expect(stuckRows.filter((r) => r.attempts > 0)).toEqual([]);
    } finally {
      // End the hanging attempt: no new connection is accepted, the open one is cut, the attempt
      // is recorded, and the worker can stop.
      const closed = new Promise<void>((resolve) => blackhole.close(() => resolve()));
      for (const socket of blackholeSockets) socket.destroy();
      await worker.stop();
      await closed;
    }
    // Recorded once the worker stopped (it waits for the attempt in flight).
    expect((await row(healthy!)).status).toBe('succeeded');
  });

  it('runs at most 2 attempts per organisation at once, so one organisation cannot fill every slot', async () => {
    const sockets: Socket[] = [];
    const connections: Array<() => void> = [];
    const blackhole = createTcpServer((socket) => {
      sockets.push(socket);
      connections.shift()?.();
    });
    const blackholePort = await listen(blackhole);
    const both = [barrier(), barrier()];
    connections.push(both[0]!.open, both[1]!.open);
    const crowded = first(
      await t.db
        .insert(organizations)
        .values({ key: 'isolation-crowded', name: 'Crowded' })
        .returning({ id: organizations.id }),
    ).id;
    const calm = first(
      await t.db
        .insert(organizations)
        .values({ key: 'isolation-calm', name: 'Calm' })
        .returning({ id: organizations.id }),
    ).id;
    // Four dead webhooks of one organisation, one delivery each, on a 4-slot worker.
    for (let i = 0; i < 4; i++) {
      await delivery(await subscription(`http://127.0.0.1:${blackholePort}/dead-${i}`, crowded));
    }
    let healthy: string | undefined;
    const worker = startWorker({
      db: t.db,
      handlers: webhookHandlers(deps),
      concurrency: 4,
      logger: silent,
      pollIntervalMs: 10,
    });
    try {
      await Promise.all(both.map((b) => b.promise));
      const healthyArrived = barrier();
      respond = (_req, res) => {
        res.writeHead(204).end();
        healthyArrived.open();
      };
      healthy = await delivery(await subscription(`http://127.0.0.1:${receiverPort}/calm`, calm));
      await healthyArrived.promise;
      // Two of the four dead webhooks hang; the other two were deferred, not attempted.
      expect(sockets).toHaveLength(MAX_IN_FLIGHT_PER_ORGANIZATION);
    } finally {
      const closed = new Promise<void>((resolve) => blackhole.close(() => resolve()));
      for (const socket of sockets) socket.destroy();
      await worker.stop();
      await closed;
    }
    // Recorded once the worker stopped (it waits for the attempt in flight).
    expect((await row(healthy!)).status).toBe('succeeded');
  });

  it('opens the circuit after 5 consecutive failures: fails fast for 10 min, then probes', async () => {
    // A receiver that accepts and resets every connection at once, and counts them.
    let connections = 0;
    let healthy = false;
    const flaky = createTcpServer((socket) => {
      connections += 1;
      if (!healthy) {
        socket.resetAndDestroy();
        return;
      }
      socket.once('data', () => socket.end('HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n'));
    });
    const flakyPort = await listen(flaky);
    try {
      const hook = await subscription(`http://127.0.0.1:${flakyPort}/flaky`);
      const ids: string[] = [];
      for (let i = 0; i < CIRCUIT_FAILURES + 2; i++) ids.push(await delivery(hook));
      // One at a time, in order: 5 real attempts fail, then the circuit is open.
      for (const id of ids) expect(await deliverWebhook(deps, id, 0)).toBe('retrying');
      expect(connections).toBe(CIRCUIT_FAILURES);
      const rows = await Promise.all(ids.map(row));
      for (const r of rows.slice(0, CIRCUIT_FAILURES)) {
        expect(r.responseExcerpt).toMatch(/^The connection to the webhook failed/);
      }
      for (const r of rows.slice(CIRCUIT_FAILURES)) {
        // Recorded as a failed attempt and scheduled like any other (1 min after the first).
        expect(r).toMatchObject({ status: 'pending', attempts: 1, responseCode: null });
        expect(r.responseExcerpt).toEqual(circuitOpen);
        const [retry] = (await jobsOf(r.id)).filter(
          (j) => (j.payload as { attempts?: number }).attempts === 1,
        );
        expect(retry!.runAt.getTime()).toBe(r.nextAttemptAt!.getTime());
      }
      // Still open 9 minutes on: the retries fail fast too.
      await age(hook, CIRCUIT_OPEN_MINUTES - 1);
      const retrying = rows[0]!;
      expect(await deliverWebhook(deps, retrying.id, 1)).toBe('retrying');
      expect(connections).toBe(CIRCUIT_FAILURES);
      expect((await row(retrying.id)).responseExcerpt).toEqual(circuitOpen);
      // 10 minutes after the 5th failure, one attempt goes through (half-open). It fails: the
      // circuit is open again for 10 minutes.
      await age(hook, 2);
      expect(await deliverWebhook(deps, rows[1]!.id, 1)).toBe('retrying');
      expect(connections).toBe(CIRCUIT_FAILURES + 1);
      expect(await deliverWebhook(deps, rows[2]!.id, 1)).toBe('retrying');
      expect(connections).toBe(CIRCUIT_FAILURES + 1);
      expect((await row(rows[2]!.id)).responseExcerpt).toEqual(circuitOpen);
      // After another 10 minutes the receiver is back: the probe succeeds and closes the circuit.
      await age(hook, CIRCUIT_OPEN_MINUTES + 1);
      healthy = true;
      expect(await deliverWebhook(deps, rows[3]!.id, 1)).toBe('succeeded');
      expect(await deliverWebhook(deps, rows[4]!.id, 1)).toBe('succeeded');
      expect(await deliverWebhook(deps, rows[5]!.id, 1)).toBe('succeeded');
      expect(connections).toBe(CIRCUIT_FAILURES + 4);
    } finally {
      await new Promise<void>((resolve) => flaky.close(() => resolve()));
    }
  });

  it('settles a delivery on schedule while the circuit is open: the last attempt fails it', async () => {
    const closed = createTcpServer();
    const closedPort = await listen(closed);
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const hook = await subscription(`http://127.0.0.1:${closedPort}/gone`);
    const ids: string[] = [];
    for (let i = 0; i <= CIRCUIT_FAILURES; i++) ids.push(await delivery(hook));
    for (const id of ids.slice(0, CIRCUIT_FAILURES)) await deliverWebhook(deps, id, 0);
    // A delivery on its last attempt while the circuit is open: failed, like any last attempt.
    const last = ids[CIRCUIT_FAILURES]!;
    await t.db
      .update(webhookDeliveries)
      .set({ attempts: MAX_DELIVERY_ATTEMPTS - 1 })
      .where(eq(webhookDeliveries.id, last));
    expect(await deliverWebhook(deps, last, MAX_DELIVERY_ATTEMPTS - 1)).toBe('failed');
    expect(await row(last)).toMatchObject({
      status: 'failed',
      attempts: MAX_DELIVERY_ATTEMPTS,
      responseExcerpt: circuitOpen,
      nextAttemptAt: null,
    });
  });

  it('does not count refusals or other webhooks towards the circuit', async () => {
    const closed = createTcpServer();
    const closedPort = await listen(closed);
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    const failing = await subscription(`http://127.0.0.1:${closedPort}/down`);
    for (let i = 0; i < CIRCUIT_FAILURES; i++)
      await deliverWebhook(deps, await delivery(failing), 0);
    // Another webhook, even on the same receiver host, is judged on its own history.
    const fine = await subscription(`http://127.0.0.1:${receiverPort}/fine`);
    expect(await deliverWebhook(deps, await delivery(fine), 0)).toBe('succeeded');
    // Refused deliveries (an inactive webhook) are not receiver failures.
    const paused = await subscription(`http://127.0.0.1:${receiverPort}/paused`);
    await t.db
      .update(webhookSubscriptions)
      .set({ active: false })
      .where(eq(webhookSubscriptions.id, paused));
    for (let i = 0; i < CIRCUIT_FAILURES; i++) {
      expect(await deliverWebhook(deps, await delivery(paused), 0)).toBe('failed');
    }
    await t.db
      .update(webhookSubscriptions)
      .set({ active: true })
      .where(eq(webhookSubscriptions.id, paused));
    expect(await deliverWebhook(deps, await delivery(paused), 0)).toBe('succeeded');
  });
});
