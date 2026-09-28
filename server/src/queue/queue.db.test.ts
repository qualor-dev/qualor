import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { jobs } from '../db/schema';
import {
  backoffSeconds,
  claimJob,
  completeJob,
  enqueue,
  extendLease,
  failJob,
  reapExpiredLeases,
} from './queue';
import { runUntilIdle, startWorker, type HeartbeatOutcome, type JobHandlers } from './worker';

const silent = { info: () => undefined, warn: () => undefined, error: () => undefined };
const LEASE = 60_000;

/**
 * These force a row past-due using the database's own clock (`now() - interval …`), never the
 * test process's `Date.now()`. Comparing a Node-computed timestamp against Postgres's `now()`
 * flakes under load: a Testcontainers Postgres can lag the host clock by more than the margin
 * these tests need when the host is busy running the rest of the suite in parallel, so
 * `claimJob`'s `run_at <= now()` or `reapExpiredLeases`'s `locked_until < now()` can see the
 * row as still in the future even though the test set it "1 second in the past" by the host's
 * clock. Computing the past-due value with the database's own `now()` in the same statement
 * removes any cross-clock comparison.
 */
async function expireRunAt(db: TestDatabase['db'], id: string): Promise<void> {
  await db.execute(sql`UPDATE jobs SET run_at = now() - interval '1 second' WHERE id = ${id}`);
}

async function expireLease(db: TestDatabase['db'], id: string): Promise<void> {
  await db.execute(
    sql`UPDATE jobs SET locked_until = now() - interval '1 second' WHERE id = ${id}`,
  );
}

async function expireAllLeases(db: TestDatabase['db']): Promise<void> {
  await db.execute(sql`UPDATE jobs SET locked_until = now() - interval '1 second'`);
}

/** Whether `run_at` is in the future by the database's own clock — never the test's `Date.now()`,
 *  for the same reason as the `expire*` helpers above. */
async function isRunAtInFuture(db: TestDatabase['db'], id: string): Promise<boolean> {
  const result = await db.execute(
    sql`SELECT run_at > now() AS "inFuture" FROM jobs WHERE id = ${id}`,
  );
  return Boolean(result.rows[0]?.inFuture);
}

describe('job queue', () => {
  let t: TestDatabase;
  beforeAll(async () => {
    t = await createTestDatabase();
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(async () => {
    await t.db.delete(jobs);
  });

  it('claims a queued job once and marks it running', async () => {
    const id = await enqueue(t.db, { queue: 'q', payload: { n: 1 } });
    const job = await claimJob(t.db, 'q', 'w1', LEASE);
    expect(job).toMatchObject({ id, queue: 'q', payload: { n: 1 }, attempts: 1, maxAttempts: 5 });
    expect(await claimJob(t.db, 'q', 'w2', LEASE)).toBeNull();
    const [row] = await t.db.select().from(jobs).where(eq(jobs.id, id));
    expect(row).toMatchObject({ status: 'running', lockedBy: 'w1' });
  });

  it('claims only from the requested queue and never before run_at', async () => {
    await enqueue(t.db, { queue: 'other', payload: {} });
    await enqueue(t.db, { queue: 'q', payload: {}, runAt: new Date(Date.now() + 60_000) });
    expect(await claimJob(t.db, 'q', 'w', LEASE)).toBeNull();
  });

  it('runs the jobs of one concurrency key one at a time, in order', async () => {
    const a = await enqueue(t.db, { queue: 'q', payload: {}, concurrencyKey: 'k' });
    const b = await enqueue(t.db, { queue: 'q', payload: {}, concurrencyKey: 'k' });
    const other = await enqueue(t.db, { queue: 'q', payload: {}, concurrencyKey: 'other' });
    const claimedA = await claimJob(t.db, 'q', 'w', LEASE);
    expect(claimedA?.id).toBe(a);
    expect((await claimJob(t.db, 'q', 'w', LEASE))?.id).toBe(other);
    expect(await claimJob(t.db, 'q', 'w', LEASE)).toBeNull();
    expect(await completeJob(t.db, claimedA!, 'w')).toBe('completed');
    expect((await claimJob(t.db, 'q', 'w', LEASE))?.id).toBe(b);
  });

  it('never runs two jobs of one key when many workers race', async () => {
    for (let i = 0; i < 5; i++)
      await enqueue(t.db, { queue: 'q', payload: { i }, concurrencyKey: 'race' });
    const claims = await Promise.all(
      Array.from({ length: 8 }, (_, i) => claimJob(t.db, 'q', `w${i}`, LEASE)),
    );
    expect(claims.filter((c) => c !== null)).toHaveLength(1);
  });

  it('hands each keyless job to at most one of many racing workers', async () => {
    for (let i = 0; i < 20; i++) await enqueue(t.db, { queue: 'q', payload: { i } });
    const claims = await Promise.all(
      Array.from({ length: 20 }, (_, i) => claimJob(t.db, 'q', `w${i}`, LEASE)),
    );
    const ids = claims.flatMap((c) => (c ? [c.id] : []));
    expect(ids.length).toBeGreaterThan(0);
    expect(new Set(ids).size).toBe(ids.length);
  });

  it('retries a failed job with backoff and buries it after max attempts', async () => {
    const id = await enqueue(t.db, { queue: 'q', payload: {}, maxAttempts: 2 });
    const firstTry = await claimJob(t.db, 'q', 'w', LEASE);
    expect(await failJob(t.db, firstTry!, 'w', new Error('boom'))).toBe('queued');
    const [row] = await t.db.select().from(jobs).where(eq(jobs.id, id));
    expect(row).toMatchObject({ status: 'queued', lastError: 'boom', lockedBy: null });
    expect(await isRunAtInFuture(t.db, id)).toBe(true);
    expect(await claimJob(t.db, 'q', 'w', LEASE)).toBeNull();
    await expireRunAt(t.db, id);
    const secondTry = await claimJob(t.db, 'q', 'w', LEASE);
    expect(secondTry?.attempts).toBe(2);
    expect(await failJob(t.db, secondTry!, 'w', 'again')).toBe('dead');
  });

  it('scrubs a DB query error before storing it, so bind params never leak into last_error (ruling S13 #4)', async () => {
    // Mirrors what drizzle-orm's DrizzleQueryError actually looks like: message/stack embed the
    // failed query *and its bind params* verbatim, plus the same values again as own properties.
    // A handler's write of report-derived data (e.g. an analysis's engines/warnings) failing a
    // check constraint would otherwise put that data straight into this unredacted column.
    const secretParam = 'CANARY-REPORT-SECRET-9f3k';
    const fakeDrizzleError = Object.assign(
      new Error(`Failed query: update "analyses" ... \nparams: ${secretParam}`),
      { query: 'update "analyses" set ... where id = $1', params: [secretParam] },
    );
    const id = await enqueue(t.db, { queue: 'q', payload: {} });
    const claimed = await claimJob(t.db, 'q', 'w', LEASE);
    expect(await failJob(t.db, claimed!, 'w', fakeDrizzleError)).toBe('queued');
    const [row] = await t.db.select().from(jobs).where(eq(jobs.id, id));
    expect(row!.lastError).not.toContain(secretParam);
    expect(row!.lastError).toContain('database query failed');
  });

  it('keeps later jobs of a key behind an earlier one that is backing off', async () => {
    const a = await enqueue(t.db, { queue: 'q', payload: {}, concurrencyKey: 'k' });
    await enqueue(t.db, { queue: 'q', payload: {}, concurrencyKey: 'k' });
    await failJob(t.db, (await claimJob(t.db, 'q', 'w', LEASE))!, 'w', new Error('x'));
    expect(await claimJob(t.db, 'q', 'w', LEASE)).toBeNull();
    await expireRunAt(t.db, a);
    expect((await claimJob(t.db, 'q', 'w', LEASE))?.id).toBe(a);
  });

  it('requeues jobs whose lease expired, or buries them when out of attempts', async () => {
    const a = await enqueue(t.db, { queue: 'q', payload: {} });
    const b = await enqueue(t.db, { queue: 'q', payload: {}, maxAttempts: 1 });
    await claimJob(t.db, 'q', 'w', LEASE);
    await claimJob(t.db, 'q', 'w', LEASE);
    await expireAllLeases(t.db);
    expect(await reapExpiredLeases(t.db)).toBe(2);
    const rows = await t.db.select().from(jobs);
    expect(Object.fromEntries(rows.map((r) => [r.id, r.status]))).toEqual({
      [a]: 'queued',
      [b]: 'dead',
    });
  });

  it('fences completeJob/failJob on the claim: a reaped-and-reclaimed job ignores its stale claimer', async () => {
    const id = await enqueue(t.db, { queue: 'q', payload: {} });
    const staleClaim = await claimJob(t.db, 'q', 'w1', LEASE);
    expect(staleClaim?.attempts).toBe(1);
    await expireLease(t.db, id);
    expect(await reapExpiredLeases(t.db)).toBe(1);
    const freshClaim = await claimJob(t.db, 'q', 'w2', LEASE);
    expect(freshClaim).toMatchObject({ id, attempts: 2 });
    expect(await completeJob(t.db, staleClaim!, 'w1')).toBe('lost');
    expect(await failJob(t.db, staleClaim!, 'w1', new Error('too late'))).toBe('lost');
    const [row] = await t.db.select().from(jobs).where(eq(jobs.id, id));
    expect(row).toMatchObject({ status: 'running', lockedBy: 'w2', attempts: 2 });
  });

  it('extendLease keeps a running job from being reaped', async () => {
    const id = await enqueue(t.db, { queue: 'q', payload: {} });
    const claim = await claimJob(t.db, 'q', 'w1', LEASE);
    await expireLease(t.db, id);
    expect(await extendLease(t.db, claim!, 'w1', LEASE)).toBe('extended');
    expect(await reapExpiredLeases(t.db)).toBe(0);
    const result = await t.db.execute(
      sql`SELECT locked_until > now() + interval '50 seconds' AS "extended" FROM jobs WHERE id = ${id}`,
    );
    expect(result.rows[0]?.extended).toBe(true);
  });

  it('fences extendLease on the claim: a reaped-and-reclaimed job keeps its new lease', async () => {
    const id = await enqueue(t.db, { queue: 'q', payload: {} });
    const staleClaim = await claimJob(t.db, 'q', 'w1', LEASE);
    await expireLease(t.db, id);
    expect(await reapExpiredLeases(t.db)).toBe(1);
    await claimJob(t.db, 'q', 'w2', LEASE);
    expect(await extendLease(t.db, staleClaim!, 'w1', LEASE)).toBe('lost');
    const [row] = await t.db.select().from(jobs).where(eq(jobs.id, id));
    expect(row).toMatchObject({ status: 'running', lockedBy: 'w2', attempts: 2 });
  });

  it('startWorker heartbeats the lease of a running handler and stops heartbeating once it settles', async () => {
    let release!: () => void;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    let started!: (lockedUntil: Date) => void;
    const running = new Promise<Date>((resolve) => {
      started = resolve;
    });
    const outcomes: HeartbeatOutcome[] = [];
    let firstBeat!: () => void;
    const beaten = new Promise<void>((resolve) => {
      firstBeat = resolve;
    });
    const id = await enqueue(t.db, { queue: 'slow', payload: {} });
    const worker = startWorker({
      db: t.db,
      handlers: {
        slow: async () => {
          const [row] = await t.db.select().from(jobs).where(eq(jobs.id, id));
          started(row!.lockedUntil!);
          await released;
        },
      },
      concurrency: 1,
      logger: silent,
      pollIntervalMs: 20,
      leaseMs: LEASE,
      heartbeatIntervalMs: 10,
      onHeartbeat: (_job, outcome) => {
        outcomes.push(outcome);
        firstBeat();
      },
    });
    try {
      const initial = await running;
      await beaten;
      const [row] = await t.db.select().from(jobs).where(eq(jobs.id, id));
      expect(row!.lockedUntil!.getTime()).toBeGreaterThan(initial.getTime());
      release();
      await worker.stop();
      const [done] = await t.db.select().from(jobs).where(eq(jobs.id, id));
      expect(done).toMatchObject({ status: 'succeeded', lockedUntil: null });
      expect(outcomes).not.toContain('lost');
      expect(outcomes).not.toContain('error');
    } finally {
      release();
      await worker.stop();
    }
  });

  it('strips NUL bytes from a stored error message instead of failing the update', async () => {
    const handlers: JobHandlers = {
      bad: async () => {
        throw new Error('boom\u0000oops');
      },
    };
    const id = await enqueue(t.db, { queue: 'bad', payload: {} });
    expect(await runUntilIdle(t.db, handlers, silent)).toBe(1);
    const [row] = await t.db.select().from(jobs).where(eq(jobs.id, id));
    expect(row).toMatchObject({ status: 'queued', lastError: 'boomoops' });
  });

  it('runUntilIdle runs handlers, completes successes and records failures', async () => {
    const seen: unknown[] = [];
    const handlers: JobHandlers = {
      ok: async (job) => {
        seen.push(job.payload);
      },
      bad: async () => {
        throw new Error('nope');
      },
    };
    await enqueue(t.db, { queue: 'ok', payload: { n: 1 } });
    await enqueue(t.db, { queue: 'bad', payload: {} });
    await enqueue(t.db, { queue: 'unhandled', payload: {} });
    expect(await runUntilIdle(t.db, handlers, silent)).toBe(2);
    expect(seen).toEqual([{ n: 1 }]);
    const rows = await t.db.select().from(jobs);
    expect(rows.map((r) => `${r.queue}:${r.status}`).sort()).toEqual([
      'bad:queued',
      'ok:succeeded',
      'unhandled:queued',
    ]);
  });

  it('startWorker picks up new jobs and stops cleanly', async () => {
    let seen!: (payload: unknown) => void;
    const received = new Promise<unknown>((resolve) => {
      seen = resolve;
    });
    const worker = startWorker({
      db: t.db,
      handlers: {
        q: async (job) => {
          seen(job.payload);
        },
      },
      concurrency: 2,
      logger: silent,
      pollIntervalMs: 20,
    });
    try {
      await enqueue(t.db, { queue: 'q', payload: { hello: 'world' } });
      expect(await received).toEqual({ hello: 'world' });
    } finally {
      await worker.stop();
    }
  });

  it('calls afterReap after every reap cycle (ruling S13 #2: lets a caller reconcile domain state tied to a job going dead outside failJob)', async () => {
    let resolveCalled!: (db: unknown) => void;
    const called = new Promise((resolve) => {
      resolveCalled = resolve;
    });
    const worker = startWorker({
      db: t.db,
      handlers: {},
      concurrency: 1,
      logger: silent,
      pollIntervalMs: 20,
      reapIntervalMs: 20,
      afterReap: (db) => {
        resolveCalled(db);
        return Promise.resolve();
      },
    });
    try {
      expect(await called).toBe(t.db);
    } finally {
      await worker.stop();
    }
  });

  it('backs off exponentially, capped at five minutes', () => {
    expect([1, 2, 3, 8, 9, 20].map((n) => backoffSeconds(n))).toEqual([2, 4, 8, 256, 300, 300]);
  });
});
