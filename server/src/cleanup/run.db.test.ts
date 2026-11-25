import { eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { file, finding, reportWith } from '../../test/reports';
import { uuidList } from '../db/bulk';
import { uuidv7 } from '../db/ids';
import {
  analyses,
  boardsLinks,
  branches,
  issues,
  jiraConnections,
  jiraLinks,
  projects,
  projectVersions,
  projectVulnerabilitySettings,
  reviewReplies,
  reviewRuns,
  scmConnections,
} from '../db/schema';
import {
  ensureHousekeepingScheduled,
  HOUSEKEEPING_QUEUE,
  housekeepingHandlers,
  runHousekeeping,
} from '../housekeeping/run';
import { analysisConcurrencyKey, ANALYSIS_QUEUE } from '../ingest/service';
import { runUntilIdle } from '../queue/worker';
import {
  applyCleanupPlan,
  cleanInactiveBranches,
  CLEANUP_BATCH,
  CLEANUP_CHUNK,
  readCleanupPlan,
} from './run';
import { CLEANUP_SETTINGS_KEY, writeCleanupDefaults } from './settings';

const ENVELOPE = { v: 1 as const, iv: 'aXY=', ct: 'Y3Q=', tag: 'dGFn' };
const DAY_MS = 86_400_000;

describe('the cleanup of inactive branches and merge requests (issue #38)', () => {
  let h: IngestHarness;
  let projectCount = 0;
  const db = () => h.ctx.db;

  /** A new project (with its main branch), its own cleanup values set as given. */
  const project = async (
    own: { branchesDays?: number | null; mergeRequestsDays?: number | null; keep?: string[] } = {},
  ) => {
    const p = await h.project(`cleanup/p${++projectCount}`);
    await db()
      .update(projects)
      .set({
        cleanupBranchesDays: own.branchesDays ?? null,
        cleanupMergeRequestsDays: own.mergeRequestsDays ?? null,
        cleanupKeepBranches: own.keep ?? [],
      })
      .where(eq(projects.id, p.id));
    return p;
  };

  /** One more succeeded analysis of each branch, `daysAgo` days ago: its latest. */
  const analyse = async (projectId: string, ids: readonly string[], daysAgo: number) => {
    await db().execute(sql`
      WITH a AS (
        INSERT INTO analyses (id, project_id, branch_id, status, revision, analysis_date,
                              baseline_status, scanner_version, finished_at)
        SELECT gen_random_uuid(), ${projectId}, b.id, 'succeeded', repeat('a', 40),
               now() - make_interval(days => ${daysAgo}), 'first_analysis', 'test',
               now() - make_interval(days => ${daysAgo})
          FROM branches b WHERE b.id IN ${uuidList(ids)}
        RETURNING id, branch_id, finished_at)
      UPDATE branches b SET last_analysis_id = a.id, last_analyzed_at = a.finished_at
        FROM a WHERE b.id = a.branch_id`);
  };

  /** Branches (or merge requests) in creation order, each last analysed `daysAgo` days ago. */
  const seed = async (
    projectId: string,
    kind: 'branch' | 'merge_request',
    names: readonly string[],
    daysAgo: number,
  ): Promise<string[]> => {
    const rows = names.map((name) => ({ id: uuidv7(), projectId, kind, name }));
    await db().insert(branches).values(rows);
    const ids = rows.map((r) => r.id);
    await analyse(projectId, ids, daysAgo);
    return ids;
  };

  /** The project's branches as `branch <name>` and merge requests as `mr <name>`, sorted. */
  const remaining = async (projectId: string) =>
    (
      await db()
        .select({ kind: branches.kind, name: branches.name })
        .from(branches)
        .where(eq(branches.projectId, projectId))
    )
      .map((r) => `${r.kind === 'branch' ? 'branch' : 'mr'} ${r.name}`)
      .sort();

  const analysisOf = async (branchId: string) => {
    const [row] = await db()
      .select({ id: analyses.id })
      .from(analyses)
      .where(eq(analyses.branchId, branchId));
    return row!.id;
  };

  /** A queued upload of the project: its branch is unknown until the job reads the report (R3). */
  const queueAnalysis = async (projectId: string) => {
    const id = uuidv7();
    await db().execute(sql`
      INSERT INTO jobs (id, queue, concurrency_key, payload)
      VALUES (${id}, ${ANALYSIS_QUEUE}, ${analysisConcurrencyKey(projectId)}, '{}'::jsonb)`);
    return id;
  };

  /**
   * Runs `body` while deleting the branch named `name` also runs `action` (PL/pgSQL), `timing` the
   * row's delete: what happens beside one chunk of the cleanup, in the middle of a run.
   */
  const onDeleteOf = async (
    name: string,
    timing: 'BEFORE' | 'AFTER',
    action: string,
    body: () => Promise<void>,
  ) => {
    await db().execute(
      sql.raw(`CREATE FUNCTION cleanup_test_hook() RETURNS trigger LANGUAGE plpgsql
                 AS $$ BEGIN ${action} RETURN OLD; END $$`),
    );
    await db().execute(
      sql.raw(`CREATE TRIGGER cleanup_test_hook ${timing} DELETE ON branches FOR EACH ROW
                 WHEN (OLD.name = '${name}') EXECUTE FUNCTION cleanup_test_hook()`),
    );
    try {
      await body();
    } finally {
      await db().execute(sql.raw('DROP TRIGGER cleanup_test_hook ON branches'));
      await db().execute(sql.raw('DROP FUNCTION cleanup_test_hook()'));
    }
  };

  beforeAll(async () => {
    h = await createIngestHarness();
  });
  afterEach(async () => {
    await db().execute(sql`DELETE FROM projects`);
    await db().execute(sql`DELETE FROM instance_settings WHERE key = ${CLEANUP_SETTINGS_KEY}`);
    await db().execute(sql`DELETE FROM jobs`);
    await db().execute(sql`DELETE FROM jira_connections`);
    await db().execute(sql`DELETE FROM scm_connections`);
  });
  afterAll(async () => {
    await h.close();
  });

  it('deletes nothing after an upgrade from 0.16: no server default and no project value', async () => {
    const p = await project();
    await seed(p.id, 'branch', ['feature/old'], 400);
    await seed(p.id, 'merge_request', ['7'], 400);
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 0, mergeRequests: 0 });
    expect(await runHousekeeping(db())).toMatchObject({
      inactiveBranches: 0,
      inactiveMergeRequests: 0,
    });
    expect(await remaining(p.id)).toEqual(['branch feature/old', 'branch main', 'mr 7']);
  });

  it('deletes branches and merge requests not analysed within the days, and counts them', async () => {
    await writeCleanupDefaults(db(), { branchesDays: 30, mergeRequestsDays: 14 });
    const p = await project();
    await seed(p.id, 'branch', ['feature/a', 'feature/b'], 31);
    await seed(p.id, 'branch', ['feature/recent'], 29);
    await seed(p.id, 'merge_request', ['7', '8', '9'], 15);
    await seed(p.id, 'merge_request', ['10'], 13);
    // Never analysed: the existing retention of branches without an analysis decides, not this rule.
    const [never] = await db()
      .insert(branches)
      .values({ projectId: p.id, kind: 'branch', name: 'feature/never' })
      .returning();
    await db().execute(
      sql`UPDATE branches SET created_at = now() - interval '400 days' WHERE id = ${never!.id}`,
    );

    expect(await cleanInactiveBranches(db())).toEqual({ branches: 2, mergeRequests: 3 });
    expect(await remaining(p.id)).toEqual([
      'branch feature/never',
      'branch feature/recent',
      'branch main',
      'mr 10',
    ]);
    // The deleted ones took their analyses with them.
    expect((await db().select().from(analyses).where(eq(analyses.projectId, p.id))).length).toBe(2);
  });

  it('keeps a branch and a merge request analysed again yesterday', async () => {
    await writeCleanupDefaults(db(), { branchesDays: 30, mergeRequestsDays: 30 });
    const p = await project();
    const [branch] = await seed(p.id, 'branch', ['feature/back'], 90);
    const [mr] = await seed(p.id, 'merge_request', ['5'], 90);
    await analyse(p.id, [branch!, mr!], 1);
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 0, mergeRequests: 0 });
    expect(await remaining(p.id)).toEqual(['branch feature/back', 'branch main', 'mr 5']);
  });

  it('never deletes the main branch, a tracked branch, a kept branch or one an ingestion holds', async () => {
    await writeCleanupDefaults(db(), { branchesDays: 30, mergeRequestsDays: null });
    const p = await project({ keep: ['keep/**', 'hotfix-*'] });
    // Vulnerability monitoring is switched off: its branch patterns still keep a branch.
    await db()
      .insert(projectVulnerabilitySettings)
      .values({ projectId: p.id, enabled: false, branchPatterns: ['release/*'] });
    await analyse(p.id, [await mainBranchId(db(), p.id)], 400);
    const ids = await seed(
      p.id,
      'branch',
      ['release/1.0', 'keep/a/b', 'hotfix-12', 'held', 'gone', 'release/1.0/x'],
      400,
    );
    const held = ids[3]!;

    // The ingestion transaction holds its branch row from its upsert until it commits.
    let release!: () => void;
    const released = new Promise<void>((resolve) => (release = resolve));
    let locked!: () => void;
    const isLocked = new Promise<void>((resolve) => (locked = resolve));
    const ingestion = db().transaction(async (tx) => {
      await tx.execute(sql`UPDATE branches SET updated_at = now() WHERE id = ${held}`);
      locked();
      await released;
    });
    await isLocked;
    try {
      // `release/*` does not match `release/1.0/x`: the glob of the monitoring patterns.
      expect(await cleanInactiveBranches(db())).toEqual({ branches: 2, mergeRequests: 0 });
    } finally {
      release();
      await ingestion;
    }
    expect(await remaining(p.id)).toEqual([
      'branch held',
      'branch hotfix-12',
      'branch keep/a/b',
      'branch main',
      'branch release/1.0',
    ]);
    // The next run finds it free.
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 1, mergeRequests: 0 });
  });

  it('leaves a project alone while an analysis of it waits or runs', async () => {
    await writeCleanupDefaults(db(), { branchesDays: 30, mergeRequestsDays: 30 });
    const busy = await project();
    const idle = await project();
    for (const p of [busy, idle]) {
      await seed(p.id, 'branch', ['feature/x'], 40);
      await seed(p.id, 'merge_request', ['3'], 40);
    }
    await queueAnalysis(busy.id);
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 1, mergeRequests: 1 });
    expect(await remaining(busy.id)).toEqual(['branch feature/x', 'branch main', 'mr 3']);

    await db().execute(sql`UPDATE jobs SET status = 'succeeded'`);
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 1, mergeRequests: 1 });
    expect(await remaining(busy.id)).toEqual(['branch main']);
  });

  it('follows the server default where a project has no value, and never where it has 0', async () => {
    await writeCleanupDefaults(db(), { branchesDays: 30, mergeRequestsDays: 30 });
    const off = await project({ branchesDays: 0, mergeRequestsDays: 0 });
    const inherits = await project();
    const own = await project({ branchesDays: 60, mergeRequestsDays: 10 });
    for (const p of [off, inherits, own]) {
      await seed(p.id, 'branch', ['b40'], 40);
      await seed(p.id, 'branch', ['b70'], 70);
      await seed(p.id, 'merge_request', ['20'], 20);
    }
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 3, mergeRequests: 1 });
    expect(await remaining(off.id)).toEqual(['branch b40', 'branch b70', 'branch main', 'mr 20']);
    expect(await remaining(inherits.id)).toEqual(['branch main', 'mr 20']);
    expect(await remaining(own.id)).toEqual(['branch b40', 'branch main']);
  });

  it('leaves a project without a rule untouched while another has its own', async () => {
    const none = await project();
    const ruled = await project({ branchesDays: 30, mergeRequestsDays: 30 });
    for (const p of [none, ruled]) {
      await seed(p.id, 'branch', ['feature/x'], 400);
      await seed(p.id, 'merge_request', ['1'], 400);
    }
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 1, mergeRequests: 1 });
    expect(await remaining(none.id)).toEqual(['branch feature/x', 'branch main', 'mr 1']);
    expect(await remaining(ruled.id)).toEqual(['branch main']);
  });

  it('applies to a merge request and a branch of the same name each its own rule', async () => {
    const branchesOnly = await project({ branchesDays: 30, mergeRequestsDays: 0 });
    const mergeRequestsOnly = await project({ branchesDays: 0, mergeRequestsDays: 30 });
    const keeps = await project({ branchesDays: 30, mergeRequestsDays: 30, keep: ['42'] });
    for (const p of [branchesOnly, mergeRequestsOnly, keeps]) {
      await seed(p.id, 'branch', ['42'], 40);
      await seed(p.id, 'merge_request', ['42'], 40);
    }
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 1, mergeRequests: 2 });
    expect(await remaining(branchesOnly.id)).toEqual(['branch main', 'mr 42']);
    expect(await remaining(mergeRequestsOnly.id)).toEqual(['branch 42', 'branch main']);
    // Keep patterns name branches; a merge request goes by its inactivity alone.
    expect(await remaining(keeps.id)).toEqual(['branch 42', 'branch main']);
  });

  it('deletes more than one batch in a run', async () => {
    const p = await project({ branchesDays: 30, mergeRequestsDays: 30 });
    const count = 2 * CLEANUP_BATCH + 1;
    await seed(
      p.id,
      'branch',
      Array.from({ length: count }, (_, i) => `feature/${i}`),
      40,
    );
    await seed(
      p.id,
      'merge_request',
      Array.from({ length: CLEANUP_BATCH + 1 }, (_, i) => String(i)),
      40,
    );
    expect(CLEANUP_BATCH).toBe(500);
    expect(await cleanInactiveBranches(db())).toEqual({
      branches: count,
      mergeRequests: CLEANUP_BATCH + 1,
    });
    expect(await remaining(p.id)).toEqual(['branch main']);
  });

  it('reaches the branches behind a full batch of kept ones', async () => {
    const p = await project({ branchesDays: 30, keep: ['keep/*'] });
    // Ids grow with creation (UUIDv7): every kept branch comes before the two to delete.
    await seed(
      p.id,
      'branch',
      Array.from({ length: CLEANUP_BATCH + 10 }, (_, i) => `keep/${i}`),
      40,
    );
    await seed(p.id, 'branch', ['old/1', 'old/2'], 40);
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 2, mergeRequests: 0 });
    const left = await remaining(p.id);
    expect(left).toHaveLength(CLEANUP_BATCH + 11);
    expect(left).not.toContain('branch old/1');
    expect(left).not.toContain('branch old/2');
  });

  it('deletes in chunks, and stops at the next chunk once the settings changed', async () => {
    expect(CLEANUP_CHUNK).toBe(50);
    const p = await project({ branchesDays: 30 });
    const names = Array.from(
      { length: 2 * CLEANUP_CHUNK + 10 },
      (_, i) => `feature/${String(i).padStart(3, '0')}`,
    );
    await seed(p.id, 'branch', names, 40);
    // A project admin switches the rule off while the first chunk is deleted.
    await onDeleteOf(
      'feature/000',
      'AFTER',
      'UPDATE projects SET cleanup_branches_days = 0 WHERE id = OLD.project_id;',
      async () => {
        expect(await cleanInactiveBranches(db())).toEqual({
          branches: CLEANUP_CHUNK,
          mergeRequests: 0,
        });
      },
    );
    const left = await remaining(p.id);
    expect(left).toHaveLength(CLEANUP_CHUNK + 10 + 1);
    expect(left).not.toContain('branch feature/000');
    expect(left).toContain(`branch feature/0${CLEANUP_CHUNK}`);
  });

  it('tries a project an analysis kept busy again at the end of the run, and logs those still busy once', async () => {
    await writeCleanupDefaults(db(), { branchesDays: 30, mergeRequestsDays: 30 });
    // Ids grow with creation (UUIDv7): the run takes the projects in this order.
    const freed = await project();
    const busy = await project();
    const after = await project();
    await seed(freed.id, 'branch', ['feature/x'], 40);
    await seed(busy.id, 'branch', ['feature/y'], 40);
    await seed(busy.id, 'merge_request', ['4'], 40);
    await seed(after.id, 'branch', ['frees-the-first'], 40);
    const freedJob = await queueAnalysis(freed.id);
    await queueAnalysis(busy.id);
    const logger = { info: vi.fn(), warn: vi.fn() };
    // The first project's analysis ends while the run deletes the third project's branch.
    await onDeleteOf(
      'frees-the-first',
      'AFTER',
      `UPDATE jobs SET status = 'succeeded' WHERE id = '${freedJob}';`,
      async () => {
        expect(await cleanInactiveBranches(db(), { logger })).toEqual({
          branches: 2,
          mergeRequests: 0,
        });
      },
    );
    expect(await remaining(freed.id)).toEqual(['branch main']);
    expect(await remaining(busy.id)).toEqual(['branch feature/y', 'branch main', 'mr 4']);
    expect(await remaining(after.id)).toEqual(['branch main']);
    expect(logger.info.mock.calls).toEqual([
      [
        { component: 'branch-cleanup', projectIds: [busy.id] },
        'cleanup skipped projects while an analysis of them waits or runs; the next run tries them again',
      ],
    ]);
    expect(logger.warn).not.toHaveBeenCalled();
  });

  it('a chunk that fails stops its project only, and housekeeping logs it and completes', async () => {
    await writeCleanupDefaults(db(), { branchesDays: 30, mergeRequestsDays: null });
    const failing = await project();
    const next = await project();
    await seed(failing.id, 'branch', ['feature/a', 'explode', 'feature/b'], 40);
    await seed(next.id, 'branch', ['feature/c'], 40);
    // An expired session: a step of the same run, which still completes.
    await db().execute(sql`
      INSERT INTO sessions (id, user_id, expires_at)
      VALUES (decode('c1ea', 'hex'), ${h.ctx.adminId}, now() - interval '1 minute')`);
    const logger = { info: vi.fn(), warn: vi.fn(), error: vi.fn() };
    // A statement timeout, a lock wait or any other error of one chunk.
    await onDeleteOf('explode', 'BEFORE', `RAISE EXCEPTION 'boom';`, async () => {
      await ensureHousekeepingScheduled(db());
      expect(
        await runUntilIdle(db(), housekeepingHandlers({ db: db(), logger }), h.ctx.app.log),
      ).toBe(1);
    });
    // The run succeeded, and the next one waits for tomorrow.
    const housekeeping = await db().execute<{ status: string }>(
      sql`SELECT status FROM jobs WHERE queue = ${HOUSEKEEPING_QUEUE} ORDER BY status`,
    );
    expect(housekeeping.rows.map((r) => r.status)).toEqual(['queued', 'succeeded']);
    expect(logger.info).toHaveBeenCalledWith(
      expect.objectContaining({ sessions: 1, inactiveBranches: 1, inactiveMergeRequests: 0 }),
      'housekeeping finished',
    );
    expect(await remaining(failing.id)).toEqual([
      'branch explode',
      'branch feature/a',
      'branch feature/b',
      'branch main',
    ]);
    expect(await remaining(next.id)).toEqual(['branch main']);
    // Logged once, with the project and the error's code: no branch name, no error text.
    expect(logger.warn.mock.calls).toEqual([
      [
        { component: 'branch-cleanup', projectId: failing.id, code: 'P0001' },
        'the cleanup of a project failed; the next run tries it again',
      ],
    ]);
    expect(logger.error).not.toHaveBeenCalled();
  });

  it('keeps a branch whose analysis a project version takes its inventory from', async () => {
    const p = await project({ branchesDays: 30 });
    // A label version made while the branch was tracked; the patterns changed since.
    const [branch] = await seed(p.id, 'branch', ['release/1.0'], 40);
    const [version] = await db()
      .insert(projectVersions)
      .values({
        projectId: p.id,
        label: '1.0.0',
        source: 'label',
        analysisId: await analysisOf(branch!),
        analyzedAt: new Date(),
      })
      .returning();
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 0, mergeRequests: 0 });

    // Once the version takes its inventory from elsewhere, the branch goes.
    await db()
      .update(projectVersions)
      .set({ analysisId: null })
      .where(eq(projectVersions.id, version!.id));
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 1, mergeRequests: 0 });
  });

  it('keeps a branch with an issue linked to a Jira issue or an Azure Boards work item', async () => {
    const p = await project({ branchesDays: 30 });
    const [toJira, toBoards, plain] = await seed(
      p.id,
      'branch',
      ['was-tracked/jira', 'was-tracked/boards', 'plain'],
      40,
    );
    const ruleId = await seedRule(db(), { key: 'trivy:CVE-2026-1' });
    const jiraIssue = await seedIssue(db(), { projectId: p.id, branchId: toJira!, ruleId });
    const boardsIssue = await seedIssue(db(), { projectId: p.id, branchId: toBoards!, ruleId });
    await seedIssue(db(), { projectId: p.id, branchId: plain!, ruleId });
    const [jira] = await db()
      .insert(jiraConnections)
      .values({
        organizationId: h.organizationId,
        deployment: 'data_center',
        siteUrl: 'https://jira.example.com',
        tokenEnc: ENVELOPE,
      })
      .returning();
    await db().insert(jiraLinks).values({
      projectId: p.id,
      connectionId: jira!.id,
      kind: 'issue',
      issueId: jiraIssue,
      state: 'created',
      origin: 'manual',
      jiraIssueId: '10001',
      jiraKey: 'Q-1',
    });
    const [scm] = await db()
      .insert(scmConnections)
      .values({
        organizationId: h.organizationId,
        provider: 'azure',
        baseUrl: 'https://dev.azure.com/acme',
        tokenEnc: ENVELOPE,
        azureAuth: 'pat',
      })
      .returning();
    await db().insert(boardsLinks).values({
      projectId: p.id,
      connectionId: scm!.id,
      azureProjectId: '00000000-0000-0000-0000-000000000001',
      kind: 'issue',
      issueId: boardsIssue,
      state: 'created',
      origin: 'manual',
      workItemId: 7,
    });

    expect(await cleanInactiveBranches(db())).toEqual({ branches: 1, mergeRequests: 0 });
    expect(await remaining(p.id)).toEqual([
      'branch main',
      'branch was-tracked/boards',
      'branch was-tracked/jira',
    ]);
  });

  it('keeps a merge request while an AI review run or a reply on it waits or runs', async () => {
    const p = await project({ mergeRequestsDays: 30 });
    const [withRun, withReply] = await seed(p.id, 'merge_request', ['1', '2', '3'], 40);
    const [run] = await db()
      .insert(reviewRuns)
      .values({
        projectId: p.id,
        branchId: withRun!,
        analysisId: await analysisOf(withRun!),
        deadlineAt: new Date(Date.now() + DAY_MS),
      })
      .returning();
    const [reply] = await db()
      .insert(reviewReplies)
      .values({
        projectId: p.id,
        branchId: withReply!,
        provider: 'gitlab',
        noteId: 1,
        threadId: 'a'.repeat(40),
        kind: 'reply',
        author: 'jane',
      })
      .returning();
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 0, mergeRequests: 1 });
    expect(await remaining(p.id)).toEqual(['branch main', 'mr 1', 'mr 2']);

    await db().update(reviewRuns).set({ status: 'done' }).where(eq(reviewRuns.id, run!.id));
    await db()
      .update(reviewReplies)
      .set({ status: 'done', finishedAt: new Date() })
      .where(eq(reviewReplies.id, reply!.id));
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 0, mergeRequests: 2 });
  });

  it('deletes nothing in a project whose settings changed after the run read them', async () => {
    await writeCleanupDefaults(db(), { branchesDays: 30, mergeRequestsDays: 30 });
    const switchedOff = await project();
    const keeps = await project();
    const tracks = await project();
    for (const p of [switchedOff, keeps, tracks]) {
      await seed(p.id, 'branch', ['feature/x'], 40);
      await seed(p.id, 'merge_request', ['1'], 40);
    }
    const plan = await readCleanupPlan(db());
    await db()
      .update(projects)
      .set({ cleanupBranchesDays: 0, cleanupMergeRequestsDays: 0 })
      .where(eq(projects.id, switchedOff.id));
    await db()
      .update(projects)
      .set({ cleanupKeepBranches: ['feature/*'] })
      .where(eq(projects.id, keeps.id));
    await db()
      .insert(projectVulnerabilitySettings)
      .values({ projectId: tracks.id, branchPatterns: ['feature/*'] });
    expect(await applyCleanupPlan(db(), plan)).toEqual({ branches: 0, mergeRequests: 0 });

    // The next run reads the new settings.
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 0, mergeRequests: 2 });
    expect(await remaining(switchedOff.id)).toEqual(['branch feature/x', 'branch main', 'mr 1']);
    expect(await remaining(keeps.id)).toEqual(['branch feature/x', 'branch main']);
    expect(await remaining(tracks.id)).toEqual(['branch feature/x', 'branch main']);
  });

  it('deletes nothing when the server default changed after the run read it', async () => {
    await writeCleanupDefaults(db(), { branchesDays: 30, mergeRequestsDays: 30 });
    const p = await project();
    await seed(p.id, 'branch', ['feature/x'], 40);
    await seed(p.id, 'merge_request', ['1'], 40);
    const plan = await readCleanupPlan(db());
    await writeCleanupDefaults(db(), { branchesDays: null, mergeRequestsDays: null });
    expect(await applyCleanupPlan(db(), plan)).toEqual({ branches: 0, mergeRequests: 0 });
    expect(await cleanInactiveBranches(db())).toEqual({ branches: 0, mergeRequests: 0 });
    expect(await remaining(p.id)).toEqual(['branch feature/x', 'branch main', 'mr 1']);
  });

  it('deletes an ingested branch and merge request with their analyses and issues', async () => {
    const p = await project({ branchesDays: 30, mergeRequestsDays: 30 });
    const findings = [finding({ line: 1 }), finding({ line: 2, ruleId: 'r2' })];
    const mainAnalysis = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-01T10:00:00Z',
        files: [file('src/a.ts')],
        findings,
      }),
    );
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: 'feature/old',
        analysisDate: '2026-09-02T10:00:00Z',
        files: [file('src/a.ts')],
        findings,
      }),
    );
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: 'feature/old',
        mergeRequest: { id: '17', sourceBranch: 'feature/old', targetBranch: 'main' },
        analysisDate: '2026-09-03T10:00:00Z',
        files: [file('src/a.ts')],
        findings,
      }),
    );
    const main = await mainBranchId(db(), p.id);
    await db().execute(sql`
      UPDATE branches SET last_analyzed_at = now() - interval '40 days' WHERE project_id = ${p.id}`);

    expect(await cleanInactiveBranches(db())).toEqual({ branches: 1, mergeRequests: 1 });
    expect(await remaining(p.id)).toEqual(['branch main']);
    expect(
      (await db().select().from(analyses).where(eq(analyses.projectId, p.id))).map((a) => a.id),
    ).toEqual([mainAnalysis]);
    const left = await db().select().from(issues).where(eq(issues.projectId, p.id));
    expect(left).toHaveLength(2);
    expect(left.every((i) => i.branchId === main)).toBe(true);
  });

  it('measures inactivity from the time it is given', async () => {
    const p = await project({ branchesDays: 30, mergeRequestsDays: 30 });
    await seed(p.id, 'branch', ['feature/x'], 10);
    await seed(p.id, 'merge_request', ['1'], 10);
    expect(await cleanInactiveBranches(db(), { now: new Date(Date.now() + 15 * DAY_MS) })).toEqual({
      branches: 0,
      mergeRequests: 0,
    });
    expect(await cleanInactiveBranches(db(), { now: new Date(Date.now() + 25 * DAY_MS) })).toEqual({
      branches: 1,
      mergeRequests: 1,
    });
  });

  it('runs in the daily housekeeping, which reports its counts', async () => {
    await writeCleanupDefaults(db(), { branchesDays: 30, mergeRequestsDays: 30 });
    const p = await project();
    await seed(p.id, 'branch', ['feature/x', 'feature/y'], 40);
    await seed(p.id, 'merge_request', ['1'], 40);
    expect(await runHousekeeping(db())).toMatchObject({
      inactiveBranches: 2,
      inactiveMergeRequests: 1,
    });
    expect(await remaining(p.id)).toEqual(['branch main']);
  });
});
