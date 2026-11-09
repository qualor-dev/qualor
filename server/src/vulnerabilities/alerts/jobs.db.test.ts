import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { testConfig } from '../../../test/config';
import { createTestDatabase, type TestDatabase } from '../../../test/db';
import { jobs } from '../../db/schema';
import { notifyDeps } from '../../notifications/deps';
import { claimJob } from '../../queue/queue';
import { runUntilIdle } from '../../queue/worker';
import { ALERTS_QUEUE, alertHandlers, enqueueVulnerabilityAlerts } from './jobs';

const silent = { info: () => undefined, warn: () => undefined, error: () => undefined };
const LEASE_MS = 60_000;

describe('the vulnerability alert job', () => {
  let t: TestDatabase;

  const alertJobs = () =>
    t.db
      .select({
        status: jobs.status,
        key: jobs.concurrencyKey,
        attempts: jobs.attempts,
        lastError: jobs.lastError,
      })
      .from(jobs)
      .where(eq(jobs.queue, ALERTS_QUEUE))
      .orderBy(jobs.id);
  const queuedJob = { status: 'queued', key: ALERTS_QUEUE, attempts: 0, lastError: null };

  beforeAll(async () => {
    t = await createTestDatabase();
  });
  beforeEach(async () => {
    await t.db.delete(jobs);
  });
  afterAll(async () => {
    await t.close();
  });

  it('keeps one queued job, however often it is asked for', async () => {
    expect(await enqueueVulnerabilityAlerts(t.db)).toBe(true);
    expect(await enqueueVulnerabilityAlerts(t.db)).toBe(false);
    expect(await alertJobs()).toEqual([queuedJob]);
  });

  it('queues a follow-up while one runs, which waits behind it', async () => {
    await enqueueVulnerabilityAlerts(t.db);
    const running = await claimJob(t.db, ALERTS_QUEUE, 'worker-1', LEASE_MS);
    expect(running).not.toBeNull();

    expect(await enqueueVulnerabilityAlerts(t.db)).toBe(true);
    expect(await alertJobs()).toEqual([
      { ...queuedJob, status: 'running', attempts: 1 },
      queuedJob,
    ]);
    expect(await claimJob(t.db, ALERTS_QUEUE, 'worker-2', LEASE_MS)).toBeNull();
  });

  it('leaves nothing behind when the caller rolls back', async () => {
    await expect(
      t.db.transaction(async (tx) => {
        expect(await enqueueVulnerabilityAlerts(tx)).toBe(true);
        throw new Error('rolled back');
      }),
    ).rejects.toThrow('rolled back');
    expect(await alertJobs()).toEqual([]);
  });

  it('keeps a queued job from being claimed until the caller commits', async () => {
    await enqueueVulnerabilityAlerts(t.db);
    await t.db.transaction(async (tx) => {
      expect(await enqueueVulnerabilityAlerts(tx)).toBe(false);
      // The data this request is about is not visible yet: a run now would miss it.
      expect(await claimJob(t.db, ALERTS_QUEUE, 'worker-1', LEASE_MS)).toBeNull();
    });
    expect(await claimJob(t.db, ALERTS_QUEUE, 'worker-1', LEASE_MS)).not.toBeNull();
  });

  it('lets an error reach the queue, so the job is retried', async () => {
    await enqueueVulnerabilityAlerts(t.db);
    const handlers = alertHandlers({
      ...notifyDeps(testConfig()),
      db: t.db,
      limits: () => {
        throw new Error('no limits today');
      },
      logger: silent,
    });
    await runUntilIdle(t.db, handlers, silent);
    expect(await alertJobs()).toEqual([
      { ...queuedJob, attempts: 1, lastError: 'no limits today' },
    ]);
  });
});
