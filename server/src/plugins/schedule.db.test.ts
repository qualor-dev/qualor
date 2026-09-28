import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { TestContext } from '../../test/app';
import { AFTER_GRACE, rbacContext } from '../../test/rbac';
import { runUntilIdle } from '../queue/worker';
import type { QualorPlugin } from './contract';
import { ensurePluginSchedules, pluginJobHandlers } from './mount';
import { ensurePluginScheduled } from './schedule';

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

const LICENSED = new Date('2027-01-01T00:00:00Z');
let ran = 0;
let fail = false;

const fixture: QualorPlugin = {
  name: 'sched-fixture',
  apiVersion: 1,
  features: ['fixture.f'],
  register(ctx) {
    ctx.jobs('fixture.f', {
      'ee.tick': async () => {
        ran += 1;
        if (fail) throw new Error('the tick failed');
      },
    });
    ctx.schedule('fixture.f', 'ee.tick', 10);
  },
};

describe('plugin schedules (rbac-audit.md §15)', () => {
  let now = LICENSED;
  let ctx: TestContext;

  const ticks = async () =>
    (
      await ctx.db.execute(sql`
        SELECT status, count(*)::int AS n, max(max_attempts)::int AS attempts FROM jobs
         WHERE queue = 'ee.tick' GROUP BY status ORDER BY status`)
    ).rows;
  const handlers = () =>
    pluginJobHandlers(ctx.plugins!, ctx.edition!, quietLogger(), { db: ctx.db });

  beforeAll(async () => {
    ctx = await rbacContext({ now: () => now, features: ['fixture.f'], plugin: fixture });
    expect(ctx.plugins?.schedules).toEqual([
      { plugin: 'sched-fixture', feature: 'fixture.f', queue: 'ee.tick', everySeconds: 10 },
    ]);
  });
  beforeEach(async () => {
    await ctx.db.execute(sql`DELETE FROM jobs WHERE queue = 'ee.tick'`);
    ran = 0;
    fail = false;
    now = LICENSED;
  });
  afterAll(async () => ctx.close());

  it('keeps one queued job per scheduled queue, and reschedules after each run, active or not', async () => {
    expect(await ensurePluginScheduled(ctx.db, 'ee.tick', 0)).toBe(true);
    expect(await ensurePluginScheduled(ctx.db, 'ee.tick', 0)).toBe(false); // one is queued
    await runUntilIdle(ctx.db, handlers(), quietLogger());
    expect(ran).toBe(1);
    const queued = await ctx.db.execute(
      sql`SELECT count(*)::int AS n, min(run_at) > now() + interval '5 seconds' AS later FROM jobs WHERE queue = 'ee.tick' AND status = 'queued'`,
    );
    expect(queued.rows[0]).toEqual({ n: 1, later: true });
    now = AFTER_GRACE; // the feature lapses: the job is skipped, and still rescheduled
    await ctx.db.execute(
      sql`UPDATE jobs SET run_at = now() WHERE queue = 'ee.tick' AND status = 'queued'`,
    );
    await runUntilIdle(ctx.db, handlers(), quietLogger());
    expect(ran).toBe(1);
    const again = await ctx.db.execute(
      sql`SELECT count(*)::int AS n FROM jobs WHERE queue = 'ee.tick' AND status = 'queued'`,
    );
    expect(again.rows[0]).toEqual({ n: 1 });
  });

  it('reschedules a failed run once, and the queue does not retry it beside the next', async () => {
    fail = true;
    await ensurePluginScheduled(ctx.db, 'ee.tick', 0);
    await runUntilIdle(ctx.db, handlers(), quietLogger());
    expect(ran).toBe(1);
    expect(await ticks()).toEqual([
      { status: 'dead', n: 1, attempts: 1 },
      { status: 'queued', n: 1, attempts: 1 },
    ]);
  });

  it('enqueues every schedule at boot and after a reap, without a second waiting job', async () => {
    await ensurePluginSchedules(ctx.db, ctx.plugins!, 'now');
    await ensurePluginSchedules(ctx.db, ctx.plugins!, 'interval');
    expect(await ticks()).toEqual([{ status: 'queued', n: 1, attempts: 1 }]);
    const [due] = (
      await ctx.db.execute(
        sql`SELECT run_at <= now() AS due FROM jobs WHERE queue = 'ee.tick' AND status = 'queued'`,
      )
    ).rows;
    expect(due).toEqual({ due: true });
  });

  it('never runs two at once: the queue name is the concurrency key', async () => {
    await ensurePluginScheduled(ctx.db, 'ee.tick', 0);
    // Another replica is running the queue's job.
    await ctx.db.execute(
      sql`UPDATE jobs SET status = 'running', locked_by = 'other', locked_until = now() + interval '1 minute' WHERE queue = 'ee.tick'`,
    );
    await ensurePluginScheduled(ctx.db, 'ee.tick', 0);
    expect(await runUntilIdle(ctx.db, handlers(), quietLogger())).toBe(0);
    expect(ran).toBe(0);
  });
});
