import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { azureConnection } from '../../test/azure-pending';
import { boardsJobDeps } from '../../test/boards';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { boardsLinks, jobs, projectBoardsSettings, scmConnections } from '../db/schema';
import type { WorkerLogger } from '../queue/worker';
import {
  BOARDS_QUEUE,
  BOARDS_SYNC_INTERVAL_SECONDS,
  boardsCreateKey,
  boardsPassWanted,
  boardsSyncKey,
  enqueueBoardsCreate,
  ensureBoardsSyncScheduled,
  scheduleBoardsSync,
  syncBoardsNow,
} from './jobs';
import { recordUnmovedProblem } from './create';
import { boardsHandlers } from './run';

const AZURE_PROJECT = '6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c';

describe('the Boards job schedule (design §7.8, plan Ruling 6)', () => {
  let h: IngestHarness;
  /** Mapped, linked (a pending link), dismissed-only, and bare connections. */
  let mapped: string;
  let linked: string;
  let dismissed: string;
  let bare: string;

  const queued = (connectionId: string, kind: 'create' | 'sync') =>
    h.ctx.db
      .select()
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, BOARDS_QUEUE),
          eq(jobs.status, 'queued'),
          eq(
            jobs.concurrencyKey,
            kind === 'sync' ? boardsSyncKey(connectionId) : boardsCreateKey(connectionId),
          ),
        ),
      );
  const connection = async (name: string) =>
    (
      await azureConnection(h.ctx.db, {
        organizationId: h.organizationId,
        baseUrl: `https://dev.azure.com/${name}`,
        secretKey: h.ctx.config.secretKey,
      })
    ).id;

  beforeAll(async () => {
    h = await createIngestHarness();
    mapped = await connection('jobs-mapped');
    linked = await connection('jobs-linked');
    dismissed = await connection('jobs-dismissed');
    bare = await connection('jobs-bare');
    const project = await h.project('BJ');
    const other = await h.project('BJO');
    await h.ctx.db.insert(projectBoardsSettings).values({
      projectId: project.id,
      connectionId: mapped,
      azureProjectId: AZURE_PROJECT,
      azureProjectName: 'Payments',
      workItemTypeRef: 'Microsoft.VSTS.WorkItemTypes.Bug',
      workItemTypeName: 'Bug',
    });
    const rule = await seedRule(h.ctx.db, { key: 'eslint:jobs', name: 'Jobs' });
    const main = await mainBranchId(h.ctx.db, other.id);
    const link = async (connectionId: string, state: 'pending' | 'dismissed') => {
      const issueId = await seedIssue(h.ctx.db, {
        projectId: other.id,
        branchId: main,
        ruleId: rule,
      });
      await h.ctx.db.insert(boardsLinks).values({
        projectId: other.id,
        connectionId,
        azureProjectId: AZURE_PROJECT,
        kind: 'issue',
        issueId,
        state,
        origin: 'manual',
      });
    };
    await link(linked, 'pending');
    await link(dismissed, 'dismissed');
  });
  afterAll(async () => {
    await h.close();
  });

  it('queues one pass per connection when two replicas boot at once', async () => {
    const counts = await Promise.all([
      ensureBoardsSyncScheduled(h.ctx.db),
      ensureBoardsSyncScheduled(h.ctx.db),
    ]);
    expect(counts.reduce((a, b) => a + b, 0)).toBe(2);
    for (const c of [mapped, linked]) {
      const rows = await queued(c, 'sync');
      expect(rows).toHaveLength(1);
      expect(rows[0]?.payload).toEqual({ kind: 'sync', connectionId: c });
    }
    // A connection with only a dismissed link, or nothing at all, wants no pass.
    expect(await queued(dismissed, 'sync')).toHaveLength(0);
    expect(await queued(bare, 'sync')).toHaveLength(0);
    expect(await ensureBoardsSyncScheduled(h.ctx.db)).toBe(0);
    expect(
      await Promise.all(
        [mapped, linked, dismissed, bare].map((c) => boardsPassWanted(h.ctx.db, c)),
      ),
    ).toEqual([true, true, false, false]);
  });

  it('skips a connection whose pass is running, while the pass may queue its successor', async () => {
    await h.ctx.db.execute(
      sql`UPDATE jobs SET status = 'running', locked_by = 'w', locked_until = now() + interval '1 minute'
           WHERE concurrency_key = ${boardsSyncKey(mapped)}`,
    );
    expect(await ensureBoardsSyncScheduled(h.ctx.db)).toBe(0);
    expect(await scheduleBoardsSync(h.ctx.db, mapped, BOARDS_SYNC_INTERVAL_SECONDS)).toBe(true);
    expect(await scheduleBoardsSync(h.ctx.db, mapped, BOARDS_SYNC_INTERVAL_SECONDS)).toBe(false);
    expect(await queued(mapped, 'sync')).toHaveLength(1);
    await h.ctx.db.execute(
      sql`DELETE FROM jobs WHERE concurrency_key = ${boardsSyncKey(mapped)} AND status = 'running'`,
    );
  });

  it('queues one create job at a time, under a key of its own, inside the caller’s transaction', async () => {
    const results = await Promise.all([
      enqueueBoardsCreate(h.ctx.db, linked),
      enqueueBoardsCreate(h.ctx.db, linked),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await enqueueBoardsCreate(h.ctx.db, linked)).toBe(false);
    const rows = await queued(linked, 'create');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.payload).toEqual({ kind: 'create', connectionId: linked });
    // The pass waiting under its own key does not hold the create back.
    expect(await queued(linked, 'sync')).toHaveLength(1);

    // A delay holds a queued job back; a shorter one never brings it forward.
    await enqueueBoardsCreate(h.ctx.db, linked, 120);
    await enqueueBoardsCreate(h.ctx.db, linked, 10);
    const [held] = await queued(linked, 'create');
    expect(held!.runAt.getTime()).toBeGreaterThan(Date.now() + 100_000);

    // Queued in a transaction that rolls back, the job is gone with the rows.
    await expect(
      h.ctx.db.transaction(async (tx) => {
        await enqueueBoardsCreate(tx, bare);
        throw new Error('rolled back');
      }),
    ).rejects.toThrow('rolled back');
    expect(await queued(bare, 'create')).toHaveLength(0);
  });

  it('moves a pass due in 15 minutes to now, or queues one', async () => {
    await h.ctx.db.execute(
      sql`UPDATE jobs SET run_at = now() + interval '15 minutes' WHERE concurrency_key = ${boardsSyncKey(linked)}`,
    );
    await syncBoardsNow(h.ctx.db, linked);
    const [moved] = await queued(linked, 'sync');
    expect(moved!.runAt.getTime()).toBeLessThanOrEqual(Date.now() + 60_000);
    expect(await queued(linked, 'sync')).toHaveLength(1);
    await h.ctx.db.execute(sql`DELETE FROM jobs WHERE concurrency_key = ${boardsSyncKey(linked)}`);
    await syncBoardsNow(h.ctx.db, linked);
    expect(await queued(linked, 'sync')).toHaveLength(1);
  });

  it('a queued create and sync job of a deleted connection end quietly and queue nothing', async () => {
    const gone = await connection('jobs-gone');
    await enqueueBoardsCreate(h.ctx.db, gone);
    await syncBoardsNow(h.ctx.db, gone);
    const jobOf = async (kind: 'create' | 'sync') => (await queued(gone, kind))[0]!;
    const create = await jobOf('create');
    const sync = await jobOf('sync');
    await h.ctx.db.delete(scmConnections).where(eq(scmConnections.id, gone));
    const lines: string[] = [];
    const logger: WorkerLogger = {
      info: (...a: unknown[]) => void lines.push(JSON.stringify(['info', ...a])),
      warn: (...a: unknown[]) => void lines.push(JSON.stringify(['warn', ...a])),
      error: (...a: unknown[]) => void lines.push(JSON.stringify(['error', ...a])),
    };
    const handle = boardsHandlers(boardsJobDeps(h, { logger }))[BOARDS_QUEUE]!;
    await handle(create);
    await handle(sync);
    expect(lines).toEqual([]);
    expect(
      await h.ctx.db
        .select()
        .from(jobs)
        .where(
          and(
            eq(jobs.queue, BOARDS_QUEUE),
            sql`${jobs.payload} ->> 'connectionId' = ${gone}`,
            sql`${jobs.id} NOT IN (${create.id}, ${sync.id})`,
          ),
        ),
    ).toEqual([]);
  });

  it("records a run's problem only while the connection keeps the address the run read", async () => {
    const id = await connection('jobs-moved');
    const rowOf = async () =>
      (await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, id)))[0]!;
    const problemOf = async () => (await rowOf()).problem;
    // The address the run read, then moved before its write.
    const read = { id, baseUrl: (await rowOf()).baseUrl };
    await h.ctx.db
      .update(scmConnections)
      .set({ baseUrl: 'https://dev.azure.com/jobs-elsewhere' })
      .where(eq(scmConnections.id, id));
    expect(await recordUnmovedProblem(h.ctx.db, read, 'undecryptable')).toBe(false);
    expect(await problemOf()).toBeNull();
    const now = { id, baseUrl: 'https://dev.azure.com/jobs-elsewhere' };
    expect(await recordUnmovedProblem(h.ctx.db, now, 'undecryptable')).toBe(true);
    expect(await problemOf()).toMatchObject({ code: 'undecryptable' });
  });
});
