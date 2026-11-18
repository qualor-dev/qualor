import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { dependencyFixes, jobs, organizations, projectFixSettings, projects } from '../db/schema';
import {
  enqueueFixJob,
  ensureFixSyncScheduled,
  FIX_QUEUE,
  FIX_SYNC_INTERVAL_SECONDS,
  fixKey,
  fixSyncKey,
  scheduleFixSync,
  syncFixesNow,
} from './jobs';

function fixRow(projectId: string, packageName: string, state: 'open' | 'merged') {
  return {
    projectId,
    family: 'js' as const,
    packageName,
    state,
    origin: 'manual' as const,
    branch: `qualor/fix/js/${packageName}`,
    ...(state === 'open' ? { mrNumber: 1, headSha: 'a'.repeat(40) } : {}),
  };
}

describe('the fix MR job schedule', () => {
  let h: IngestHarness;
  let orgs: string[];
  let projectIds: string[];

  const queued = (key: string) =>
    h.ctx.db
      .select()
      .from(jobs)
      .where(
        and(eq(jobs.queue, FIX_QUEUE), eq(jobs.status, 'queued'), eq(jobs.concurrencyKey, key)),
      );

  beforeAll(async () => {
    h = await createIngestHarness();
    const [second, third] = await h.ctx.db
      .insert(organizations)
      .values([
        { key: 'second', name: 'Second' },
        { key: 'third', name: 'Third' },
      ])
      .returning({ id: organizations.id });
    orgs = [h.organizationId, second!.id, third!.id];
    const made = await h.ctx.db
      .insert(projects)
      .values(
        orgs.map((organizationId, i) => ({ organizationId, key: `fj-${i}`, name: `fj-${i}` })),
      )
      .returning({ id: projects.id });
    projectIds = made.map((p) => p.id);
  });
  afterAll(async () => {
    await h.close();
  });

  it('queues one pass per organisation with an enabled project or an active fix when two replicas boot at once', async () => {
    // Organisation 0: an enabled project. Organisation 1: only an open fix. Organisation 2: a
    // disabled project and a merged fix, so none (R18).
    await h.ctx.db.insert(projectFixSettings).values([
      { projectId: projectIds[0]!, enabled: true },
      { projectId: projectIds[2]!, enabled: false },
    ]);
    await h.ctx.db
      .insert(dependencyFixes)
      .values([fixRow(projectIds[1]!, 'a', 'open'), fixRow(projectIds[2]!, 'b', 'merged')]);
    const counts = await Promise.all([
      ensureFixSyncScheduled(h.ctx.db),
      ensureFixSyncScheduled(h.ctx.db),
    ]);
    expect(counts.reduce((a, b) => a + b, 0)).toBe(2);
    for (const o of orgs.slice(0, 2)) {
      const rows = await queued(fixSyncKey(o));
      expect(rows).toHaveLength(1);
      expect(rows[0]?.payload).toEqual({ kind: 'sync', organizationId: o });
    }
    expect(await queued(fixSyncKey(orgs[2]!))).toHaveLength(0);
    expect(await ensureFixSyncScheduled(h.ctx.db)).toBe(0);
  });

  it('skips an organisation whose pass is running, while the pass may queue its successor', async () => {
    const org = orgs[0]!;
    await h.ctx.db.execute(
      sql`UPDATE jobs SET status = 'running', locked_by = 'w', locked_until = now() + interval '1 minute'
           WHERE concurrency_key = ${fixSyncKey(org)}`,
    );
    expect(await ensureFixSyncScheduled(h.ctx.db)).toBe(0);
    expect(await scheduleFixSync(h.ctx.db, org, FIX_SYNC_INTERVAL_SECONDS)).toBe(true);
    expect(await scheduleFixSync(h.ctx.db, org, FIX_SYNC_INTERVAL_SECONDS)).toBe(false);
    expect(await queued(fixSyncKey(org))).toHaveLength(1);
    await h.ctx.db.execute(
      sql`DELETE FROM jobs WHERE concurrency_key = ${fixSyncKey(org)} AND status = 'running'`,
    );
  });

  it('moves a pass due in 15 minutes to now, or queues one', async () => {
    const org = orgs[1]!;
    await h.ctx.db.execute(
      sql`UPDATE jobs SET run_at = now() + interval '15 minutes' WHERE concurrency_key = ${fixSyncKey(org)}`,
    );
    await syncFixesNow(h.ctx.db, org);
    const [moved] = await queued(fixSyncKey(org));
    expect(moved!.runAt.getTime()).toBeLessThanOrEqual(Date.now() + 60_000);
    expect(await queued(fixSyncKey(org))).toHaveLength(1);
    await h.ctx.db.execute(sql`DELETE FROM jobs WHERE concurrency_key = ${fixSyncKey(org)}`);
    await syncFixesNow(h.ctx.db, org);
    expect(await queued(fixSyncKey(org))).toHaveLength(1);
  });

  it('queues a commit or close job under the key of its fix, after its delay', async () => {
    const fixId = projectIds[0]!;
    const payload = { kind: 'commit', fixId, generation: 1, attempt: 0 } as const;
    await enqueueFixJob(h.ctx.db, payload);
    await enqueueFixJob(h.ctx.db, { ...payload, kind: 'close' }, 60);
    const rows = await queued(fixKey(fixId));
    expect(rows.map((r) => r.payload)).toEqual(
      expect.arrayContaining([payload, { ...payload, kind: 'close' }]),
    );
    const delayed = rows.find((r) => (r.payload as { kind: string }).kind === 'close');
    expect(delayed!.runAt.getTime()).toBeGreaterThan(Date.now() + 30_000);
  });
});
