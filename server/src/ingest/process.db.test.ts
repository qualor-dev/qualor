import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it, vi } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { gzipDeeplyNestedArray, gzipJson, sampleReport, uploadReport } from '../../test/reports';
import { analyses, analysisReports, branches, jobs } from '../db/schema';
import {
  claimJob,
  completeJob,
  DEFAULT_MAX_ATTEMPTS,
  enqueue,
  reapExpiredLeases,
} from '../queue/queue';
import { runUntilIdle } from '../queue/worker';
import { jobHandlers } from './handlers';
import {
  AnalysisFailure,
  markFailed,
  processAnalysis,
  reconcileDeadAnalyses,
  type IngestionContext,
  type IngestionStage,
} from './process';
import { ANALYSIS_QUEUE } from './service';

const KEY = 'acme/api';

describe('analysis processing job', () => {
  let ctx: TestContext;
  let orgAdmin: Session;
  let projectId: string;
  let token: string;

  const processAll = (stages?: readonly IngestionStage[]) =>
    runUntilIdle(
      ctx.db,
      jobHandlers({ db: ctx.db, upload: ctx.config.upload, stages, logger: ctx.app.log }),
      ctx.app.log,
    );
  const upload = (report: unknown) => uploadReport(ctx, bearer(token), KEY, gzipJson(report));
  const read = async (id: string) =>
    (
      await ctx.app.inject({ method: 'GET', url: `/api/v0/analyses/${id}`, headers: bearer(token) })
    ).json();
  const branchNamed = async (name: string) =>
    (
      await ctx.db
        .select()
        .from(branches)
        .where(and(eq(branches.projectId, projectId), eq(branches.name, name)))
    )[0];

  beforeAll(async () => {
    ctx = await createTestContext();
    const a = await createUser(ctx, { username: 'job-admin' });
    await addMember(ctx, await organizationId(ctx, 'default'), a.id, 'admin');
    orgAdmin = await login(ctx, a.username, a.password);
    projectId = (
      await createProject(ctx, orgAdmin, {
        organizationId: await organizationId(ctx, 'default'),
        key: KEY,
      })
    ).id;
    token = await createProjectToken(ctx, orgAdmin, projectId);
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('processes a valid report onto the main branch', async () => {
    const id = await upload(sampleReport());
    expect(await processAll()).toBe(1);
    const main = await branchNamed('main');
    const res = await ctx.app.inject({
      method: 'GET',
      url: `/api/v0/analyses/${id}`,
      headers: bearer(token),
    });
    expect(res.headers['retry-after']).toBeUndefined();
    expect(res.json()).toMatchObject({
      status: 'succeeded',
      branch: { id: main!.id, kind: 'branch', name: 'main' },
      revision: 'a'.repeat(40),
      analysisDate: '2026-09-22T10:15:00.000Z',
      error: null,
      engines: [
        {
          id: 'eslint',
          kind: 'builtin',
          version: '9.12.0',
          status: 'ok',
          reason: null,
          durationMs: 1200,
        },
      ],
      warnings: [
        { code: 'COVERAGE_PATH_UNRESOLVED', message: '2 coverage paths did not resolve', count: 2 },
      ],
    });
    expect(res.json().engines[0]).not.toHaveProperty('rules');
    expect(main!.lastAnalysisId).toBe(id);
    // The main branch row is created (isMain: true) at project-creation time (routes/projects.ts);
    // the ingest job's upsertBranch must never clear that flag on conflict.
    expect(main).toMatchObject({ isMain: true });
    const [row] = await ctx.db.select().from(analyses).where(eq(analyses.id, id));
    expect(row).toMatchObject({
      baselineStatus: 'ok',
      baselineRevision: 'b'.repeat(40),
      versionLabel: '1.0.0',
      scannerVersion: '0.1.0',
    });
  });

  it('maintains analyses.updated_at through processing and the dead-job sweep (data-model.md §2)', async () => {
    const old = new Date('2000-01-01T00:00:00Z');
    const age = (id: string) =>
      ctx.db.execute(sql`UPDATE analyses SET updated_at = ${old} WHERE id = ${id}`);
    const updatedAt = async (id: string) =>
      (await ctx.db.select().from(analyses).where(eq(analyses.id, id)))[0]!.updatedAt.getTime();
    const processed = await upload(sampleReport({ branch: 'updated-at' }));
    await age(processed);
    expect(await processAll()).toBe(1);
    expect(await updatedAt(processed)).toBeGreaterThan(old.getTime());

    const abandoned = await upload(sampleReport({ branch: 'updated-at-dead' }));
    await age(abandoned);
    await ctx.db.execute(
      sql`UPDATE jobs SET status = 'dead' WHERE payload ->> 'analysisId' = ${abandoned}`,
    );
    expect(await reconcileDeadAnalyses(ctx.db)).toBe(1);
    expect(await updatedAt(abandoned)).toBeGreaterThan(old.getTime());
    // Later tests look up "the" dead job; don't leave this one behind.
    await ctx.db.execute(sql`DELETE FROM jobs WHERE payload ->> 'analysisId' = ${abandoned}`);
  });

  it('creates feature branches and merge requests on their first analysis', async () => {
    await upload(sampleReport({ branch: 'feature/x' }));
    await upload(
      sampleReport({
        branch: 'feature/x',
        mergeRequest: { id: '482', targetBranch: 'main', sourceBranch: 'feature/x' },
      }),
    );
    expect(await processAll()).toBe(2);
    expect(await branchNamed('feature/x')).toMatchObject({ kind: 'branch', isMain: false });
    expect(await branchNamed('482')).toMatchObject({
      kind: 'merge_request',
      mrSourceBranch: 'feature/x',
      mrTargetBranch: 'main',
    });
  });

  it('fails an invalid report with REPORT_INVALID and errors[].path (ruling R1)', async () => {
    const bad = sampleReport({ branch: 'invalid' });
    bad.findings[0]!.location = { path: 'src/missing.ts', startLine: 1 };
    const id = await upload(bad);
    const notJson = await uploadReport(ctx, bearer(token), KEY, gzipJson('not a report'));
    await processAll();
    const body = await read(id);
    expect(body).toMatchObject({
      status: 'failed',
      branch: null,
      error: { code: 'REPORT_INVALID' },
    });
    expect(body.error.errors).toContainEqual({
      path: 'findings.0.location.path',
      message: 'location.path is not listed in files[]',
    });
    expect((await read(notJson)).error.code).toBe('REPORT_INVALID');
    expect(await branchNamed('invalid')).toBeUndefined();
  });

  it('fails a pathologically deep report with REPORT_INVALID in one pass, without retrying (ruling U4 fix round 2)', async () => {
    const id = await uploadReport(ctx, bearer(token), KEY, gzipDeeplyNestedArray(5_000));
    // A single runUntilIdle pass processes exactly one job for it: decodeStoredReport now returns
    // a normal decode failure instead of throwing, so processAnalysis marks it failed on the first
    // attempt rather than the job handler treating a stack overflow as a retriable error.
    expect(await processAll()).toBe(1);
    expect(await read(id)).toMatchObject({
      status: 'failed',
      error: { code: 'REPORT_INVALID', message: 'The report is nested too deeply' },
    });
  });

  it('stamps started_at, finished_at and last_analyzed_at from the database clock, not the worker clock', async () => {
    const ok = await upload(sampleReport({ branch: 'feature/clock' }));
    const failed = await upload(
      sampleReport({ branch: 'feature/clock', projectKey: 'acme/other' }),
    );
    // A worker whose clock runs 70+ years ahead.
    vi.useFakeTimers({ toFake: ['Date'], now: new Date('2099-01-01T00:00:00Z') });
    try {
      await processAll();
    } finally {
      vi.useRealTimers();
    }
    const stamps = await ctx.db.execute<{ status: string; sane: boolean }>(sql`
      SELECT a.status, (a.started_at <= now() AND a.finished_at <= now()
                        AND coalesce(b.last_analyzed_at <= now(), true)) AS sane
        FROM analyses a LEFT JOIN branches b ON b.last_analysis_id = a.id
       WHERE a.id IN (${ok}::uuid, ${failed}::uuid)
       ORDER BY a.status`);
    expect(stamps.rows).toEqual([
      { status: 'failed', sane: true },
      { status: 'succeeded', sane: true },
    ]);
  });

  it('fails a report for another project with PROJECT_KEY_MISMATCH', async () => {
    const id = await upload(sampleReport({ projectKey: 'acme/elsewhere' }));
    await processAll();
    expect((await read(id)).error.code).toBe('PROJECT_KEY_MISMATCH');
  });

  it('fails a detached report (no branch, no MR) with BRANCH_REQUIRED', async () => {
    const id = await upload(sampleReport({ branch: null }));
    await processAll();
    expect((await read(id)).error.code).toBe('BRANCH_REQUIRED');
  });

  it('caps the warnings stored on a STALE_ANALYSIS too', async () => {
    await upload(sampleReport({ branch: 'stale-cap', analysisDate: '2026-09-22T12:00:00Z' }));
    await processAll();
    const noisy = sampleReport({ branch: 'stale-cap', analysisDate: '2026-09-22T11:00:00Z' });
    noisy.warnings = Array.from({ length: 150 }, (_, i) => ({
      code: `W_${i}`,
      message: 'a noisy report',
    }));
    const older = await upload(noisy);
    await processAll();
    const body = await read(older);
    expect(body.error.code).toBe('STALE_ANALYSIS');
    expect(body.warnings).toHaveLength(100);
    expect(body.warnings[99].code).toBe('WARNINGS_TRUNCATED');
  });

  it('reconciles dead jobs even when another dead job has a malformed analysisId', async () => {
    const malformedJobId = await enqueue(ctx.db, {
      queue: ANALYSIS_QUEUE,
      payload: { analysisId: 'not-a-uuid' },
    });
    const id = await upload(sampleReport({ branch: 'reconcile-text' }));
    // Controller ruling T5: scoped to exactly the two jobs this test just created — never "every
    // queued job in the table" — so this test's outcome can never depend on whether some other
    // test in this file (or a future one) happens to have left a job queued at this moment.
    await ctx.db.execute(sql`
      UPDATE jobs SET status = 'dead'
       WHERE id = ${malformedJobId} OR payload ->> 'analysisId' = ${id}
    `);
    expect(await reconcileDeadAnalyses(ctx.db)).toBe(1);
    expect((await read(id)).error.code).toBe('PROCESSING_ERROR');
    await ctx.db.execute(sql`
      DELETE FROM jobs WHERE id = ${malformedJobId} OR payload ->> 'analysisId' = ${id}
    `);
  });

  it('stores an older report as STALE_ANALYSIS without moving the branch (Review Focus 5)', async () => {
    const newer = await upload(
      sampleReport({ branch: 'stale-test', analysisDate: '2026-09-22T12:00:00Z' }),
    );
    await processAll();
    const older = await upload(
      sampleReport({
        branch: 'stale-test',
        analysisDate: '2026-09-22T11:00:00Z',
        revision: 'c'.repeat(40),
      }),
    );
    await processAll();
    const branch = await branchNamed('stale-test');
    expect(branch!.lastAnalysisId).toBe(newer);
    const body = await read(older);
    expect(body).toMatchObject({
      status: 'failed',
      error: { code: 'STALE_ANALYSIS' },
      branch: { id: branch!.id },
      revision: 'c'.repeat(40),
    });
  });

  it('runs one analysis of a project at a time, in upload order (ruling R3)', async () => {
    const first = await upload(
      sampleReport({ branch: 'order', analysisDate: '2026-09-23T01:00:00Z' }),
    );
    const second = await upload(
      sampleReport({ branch: 'order', analysisDate: '2026-09-23T02:00:00Z' }),
    );
    const job = await claimJob(ctx.db, ANALYSIS_QUEUE, 'w1', 60_000);
    expect((job!.payload as { analysisId: string }).analysisId).toBe(first);
    expect(await claimJob(ctx.db, ANALYSIS_QUEUE, 'w2', 60_000)).toBeNull();
    await jobHandlers({ db: ctx.db, upload: ctx.config.upload })[ANALYSIS_QUEUE]!(job!);
    // completeJob is fenced on the claimed Job + the claiming workerId (Task 4 ruling), not the
    // job id alone; the brief's original call signature predates that fencing change.
    await completeJob(ctx.db, job!, 'w1');
    expect(await processAll()).toBe(1);
    expect((await branchNamed('order'))!.lastAnalysisId).toBe(second);
  });

  it('processes an analysis exactly once even when two calls race past the outer guard (ruling S13 #1)', async () => {
    // The outer claim update accepts both 'queued' and 'processing' (so a run whose worker
    // actually died can be re-claimed), which means Postgres itself does not stop a second,
    // still-alive caller for the same analysisId from also passing it — only the FOR UPDATE lock
    // inside the ingest transaction serialises them. Driving two real, concurrently-executing
    // processAnalysis calls against the same row (not a sleep, not a manual DB hack) is exactly
    // that race: whichever transaction's row lock wins runs the stage and commits 'succeeded';
    // the other blocks on the lock, wakes to the committed row, and no-ops.
    let stageRuns = 0;
    const counting: IngestionStage = {
      name: 'counting',
      run: () => {
        stageRuns += 1;
        return Promise.resolve();
      },
    };
    const id = await upload(sampleReport({ branch: 'race-lock' }));
    const deps = { db: ctx.db, upload: ctx.config.upload, stages: [counting] };
    await Promise.all([processAnalysis(deps, id), processAnalysis(deps, id)]);
    expect(stageRuns).toBe(1);
    expect((await read(id)).status).toBe('succeeded');
    expect((await branchNamed('race-lock'))!.lastAnalysisId).toBe(id);
    // The upload above still left a real, untouched job queued (calling processAnalysis directly
    // bypasses claim/complete); drain it through the normal queue path so it doesn't also get
    // claimed — as a harmless but count-skewing no-op — by a later test's processAll().
    expect(await processAll()).toBe(1);
  });

  it('does not flip a succeeded analysis back to failed on a stale final-attempt failure (ruling S13 #1)', async () => {
    const id = await upload(sampleReport({ branch: 'succeeded-then-stale-fail' }));
    expect(await processAll()).toBe(1);
    expect((await read(id)).status).toBe('succeeded');
    // This is exactly what jobHandlers' catch block does on a job's last attempt; markFailed must
    // refuse to touch an analysis that already left 'queued'/'processing'.
    await markFailed(ctx.db, id, {
      code: 'PROCESSING_ERROR',
      message: 'a stale duplicate attempt failing after the real one already succeeded',
    });
    expect((await read(id)).status).toBe('succeeded');
  });

  it('runs plugged-in stages inside the ingestion transaction', async () => {
    const seen: string[] = [];
    const recorder: IngestionStage = {
      name: 'recorder',
      run: async (stageCtx) => {
        seen.push(
          `${stageCtx.project.key}@${stageCtx.branch.name}:${stageCtx.report.findings.length}`,
        );
        stageCtx.warnings.push({ code: 'STAGE_RAN', message: 'recorder ran' });
      },
    };
    const id = await upload(sampleReport({ branch: 'stages' }));
    await processAll([recorder]);
    expect(seen).toEqual(['acme/api@stages:1']);
    expect((await read(id)).warnings.map((w: { code: string }) => w.code)).toEqual([
      'COVERAGE_PATH_UNRESOLVED',
      'STAGE_RAN',
    ]);
  });

  it("gives stages a logger, the analysis row and the branch's previous succeeded analysis", async () => {
    const seen: {
      analysisId: string;
      status: string;
      previous: string | null;
      hasLogger: boolean;
    }[] = [];
    const inspector: IngestionStage = {
      name: 'inspector',
      run: async (stageCtx: IngestionContext) => {
        stageCtx.logger.debug({ stage: 'inspector' }, 'inspecting');
        seen.push({
          analysisId: stageCtx.analysis.id,
          status: stageCtx.analysis.status,
          previous: stageCtx.previousAnalysis?.id ?? null,
          hasLogger: typeof stageCtx.logger.info === 'function',
        });
      },
    };
    const firstId = await upload(
      sampleReport({ branch: 'ctx-branch', analysisDate: '2026-09-23T06:00:00Z' }),
    );
    await processAll([inspector]);
    const failedInBetween = await upload(sampleReport({ branch: 'ctx-branch', projectKey: 'x/y' }));
    await processAll([inspector]);
    expect((await read(failedInBetween)).status).toBe('failed');
    const secondId = await upload(
      sampleReport({ branch: 'ctx-branch', analysisDate: '2026-09-23T07:00:00Z' }),
    );
    await processAll([inspector]);
    expect(seen).toEqual([
      { analysisId: firstId, status: 'processing', previous: null, hasLogger: true },
      // Only succeeded analyses count as "previous": the PROJECT_KEY_MISMATCH one is skipped.
      { analysisId: secondId, status: 'processing', previous: firstId, hasLogger: true },
    ]);
  });

  it("fails the analysis with a stage's AnalysisFailure at once, without retrying, and rolls the stage back", async () => {
    let runs = 0;
    const rejecting: IngestionStage = {
      name: 'rejecting',
      run: async (stageCtx) => {
        runs += 1;
        // A write the rollback must undo.
        await stageCtx.tx
          .update(branches)
          .set({ mrTitle: 'written by a failing stage' })
          .where(eq(branches.id, stageCtx.branch.id));
        throw new AnalysisFailure('RULES_UNKNOWN', 'The report uses rules this server rejects', [
          { path: 'findings.0.ruleId', message: 'unknown rule' },
        ]);
      },
    };
    const id = await upload(sampleReport({ branch: 'stage-failure' }));
    expect(await processAll([rejecting])).toBe(1);
    expect(runs).toBe(1);
    expect(await read(id)).toMatchObject({
      status: 'failed',
      branch: null,
      revision: 'a'.repeat(40),
      error: {
        code: 'RULES_UNKNOWN',
        message: 'The report uses rules this server rejects',
        errors: [{ path: 'findings.0.ruleId', message: 'unknown rule' }],
      },
    });
    expect(await branchNamed('stage-failure')).toBeUndefined();
    const job = (await ctx.db.select().from(jobs)).find(
      (j) => (j.payload as { analysisId?: string }).analysisId === id,
    );
    expect(job).toMatchObject({ status: 'succeeded', attempts: 1 });
  });

  it('caps stage-appended warnings at 100 with one summary warning (ruling S13 #4)', async () => {
    const chatty: IngestionStage = {
      name: 'chatty',
      run: async (stageCtx) => {
        for (let i = 0; i < 150; i++) {
          stageCtx.warnings.push({ code: `NOISY_${i}`, message: 'a stage that will not shut up' });
        }
      },
    };
    const id = await upload(sampleReport({ branch: 'chatty-stage' }));
    await processAll([chatty]);
    const warnings = (await read(id)).warnings as { code: string; count?: number }[];
    expect(warnings).toHaveLength(100);
    expect(warnings[0]).toEqual({
      code: 'COVERAGE_PATH_UNRESOLVED',
      message: '2 coverage paths did not resolve',
      count: 2,
    });
    const summary = warnings[warnings.length - 1]!;
    expect(summary.code).toBe('WARNINGS_TRUNCATED');
    // 1 report warning + 150 stage warnings = 151 total; 99 are kept plus this summary = 100
    // entries, so the other 151 - 99 = 52 are dropped.
    expect(summary.count).toBe(52);
  });

  it('rolls back a failing stage, retries, then fails the analysis with PROCESSING_ERROR', async () => {
    const boom: IngestionStage = {
      name: 'boom',
      run: async () => {
        throw new Error('stage exploded');
      },
    };
    const id = await upload(sampleReport({ branch: 'boom-branch' }));
    for (let attempt = 0; attempt < DEFAULT_MAX_ATTEMPTS; attempt++) {
      await processAll([boom]);
      // Controller ruling T5: force the backoff delay to be over using the database's OWN clock
      // (`now() - interval`), never the test process's `Date.now()`. Comparing a Node-computed
      // timestamp against Postgres's `now()` flakes whenever the two clocks drift (host vs.
      // container) — the same failure mode `queue.db.test.ts`'s `expireRunAt` was written to
      // avoid (ruling S8); this test had regressed past that convention. Scoped to this test's
      // own job (never "every queued job") for the same reason as the reconcile test above.
      await ctx.db.execute(sql`
        UPDATE jobs SET run_at = now() - interval '1 second'
         WHERE queue = ${ANALYSIS_QUEUE} AND status = 'queued' AND payload ->> 'analysisId' = ${id}
      `);
    }
    expect(await read(id)).toMatchObject({ status: 'failed', error: { code: 'PROCESSING_ERROR' } });
    expect(await branchNamed('boom-branch')).toBeUndefined();
    // Scoped by this test's own analysisId, not "whichever dead job happens to be first" — a
    // later test (ruling S13 #2's crash/lease-expiry test) also leaves a dead job behind, and an
    // unscoped, unordered SELECT could just as easily return that one.
    const deadJobs = await ctx.db.select().from(jobs).where(eq(jobs.status, 'dead'));
    const job = deadJobs.find((j) => (j.payload as { analysisId?: string }).analysisId === id);
    expect(job).toBeDefined();
    // Don't leave this test's dead job behind for a later broad-ish lookup to trip over.
    await ctx.db.delete(jobs).where(eq(jobs.id, job!.id));
  });

  it('fails an analysis whose ingest job died without ever throwing — crash/lease-expiry, not an explicit failure (ruling S13 #2)', async () => {
    const id = await upload(sampleReport({ branch: 'abandoned' }));
    const job = await claimJob(ctx.db, ANALYSIS_QUEUE, 'crasher', 60_000);
    expect((job!.payload as { analysisId: string }).analysisId).toBe(id);
    // Simulate a worker that claimed the job, got as far as processAnalysis's own outer claim
    // (which flips the analysis to 'processing') and then crashed before it could do anything
    // else: it never reaches jobHandlers' catch/markFailed. Its last attempt is already used up,
    // so once the reaper notices the expired lease it goes straight to 'dead' with the analysis
    // stuck 'processing'. Force this with real DB state (the database's own clock, per
    // queue.db.test.ts convention), not a sleep.
    await ctx.db
      .update(analyses)
      .set({ status: 'processing', startedAt: new Date() })
      .where(eq(analyses.id, id));
    await ctx.db.update(jobs).set({ attempts: job!.maxAttempts }).where(eq(jobs.id, job!.id));
    await ctx.db.execute(
      sql`UPDATE jobs SET locked_until = now() - interval '1 second' WHERE id = ${job!.id}`,
    );
    expect(await reapExpiredLeases(ctx.db)).toBe(1);
    const [deadJob] = await ctx.db.select().from(jobs).where(eq(jobs.id, job!.id));
    expect(deadJob!.status).toBe('dead');
    expect((await read(id)).status).toBe('processing');
    expect(await reconcileDeadAnalyses(ctx.db)).toBe(1);
    expect(await read(id)).toMatchObject({ status: 'failed', error: { code: 'PROCESSING_ERROR' } });
    // Idempotent: nothing left to reconcile, and a second pass never re-touches it.
    expect(await reconcileDeadAnalyses(ctx.db)).toBe(0);
    // Controller ruling T5: don't leave this test's own dead job behind — an unscoped lookup in a
    // later test (or one added by a future implementer) should never have to account for it.
    await ctx.db.delete(jobs).where(eq(jobs.id, job!.id));
  });

  it('completes a malformed job payload immediately with a warn log instead of retrying into dead (ruling S13 #4)', async () => {
    const jobId = await enqueue(ctx.db, {
      queue: ANALYSIS_QUEUE,
      payload: { analysisId: 'not-a-uuid' },
    });
    expect(await processAll()).toBe(1);
    const [job] = await ctx.db.select().from(jobs).where(eq(jobs.id, jobId));
    expect(job).toMatchObject({ status: 'succeeded', attempts: 1 });
    expect(ctx.logs.join('\n')).toContain('malformed analysis job payload');
  });

  it('lists a branch history newest first with pagination', async () => {
    const ids: string[] = [];
    for (const hour of ['03', '04', '05']) {
      ids.push(
        await upload(
          sampleReport({ branch: 'history', analysisDate: `2026-09-23T${hour}:00:00Z` }),
        ),
      );
    }
    await processAll();
    const branch = await branchNamed('history');
    const url = `/api/v0/branches/${branch!.id}/analyses?limit=2`;
    const page1 = (await ctx.app.inject({ method: 'GET', url, headers: orgAdmin.headers })).json();
    expect(page1.items.map((a: { id: string }) => a.id)).toEqual([ids[2], ids[1]]);
    const page2 = (
      await ctx.app.inject({
        method: 'GET',
        url: `${url}&cursor=${page1.nextCursor}`,
        headers: orgAdmin.headers,
      })
    ).json();
    expect(page2).toEqual({
      items: [expect.objectContaining({ id: ids[0], status: 'succeeded' })],
      nextCursor: null,
    });
  });

  it('tolerates a report row deleted after upload: marks REPORT_MISSING, completes the job (Task 12 brief)', async () => {
    const id = await upload(sampleReport({ branch: 'no-report' }));
    await ctx.db.delete(analysisReports).where(eq(analysisReports.analysisId, id));
    expect(await processAll()).toBe(1);
    expect((await read(id)).error.code).toBe('REPORT_MISSING');
    const dead = (await ctx.db.select().from(jobs).where(eq(jobs.status, 'dead'))).filter(
      (j) => (j.payload as { analysisId: string }).analysisId === id,
    );
    expect(dead).toEqual([]);
  });

  // Deleting the project cascade-deletes this very analysis row (analyses.project_id ON DELETE
  // CASCADE) before the job ever runs, so this exercises the same `!analysis` / outer-guard path
  // as the previous test, not process.ts's separate (and currently unreachable — see the comment
  // on `!project` there) "project vanished but the analysis row is still here" branch. Kept as its
  // own test because it drives the deletion through the real DELETE /projects endpoint rather than
  // deleting a row directly, proving the whole cascade end to end (progress.md Task 9 carry-over).
  it('tolerates the analysis row being cascade-deleted when its project is deleted after upload (ruling S13 #5)', async () => {
    const deletedKey = 'acme/deleted';
    const deletedProject = await createProject(ctx, orgAdmin, {
      organizationId: await organizationId(ctx, 'default'),
      key: deletedKey,
    });
    const deletedToken = await createProjectToken(ctx, orgAdmin, deletedProject.id);
    const id = await uploadReport(
      ctx,
      bearer(deletedToken),
      deletedKey,
      gzipJson(sampleReport({ projectKey: deletedKey, branch: 'gone' })),
    );
    const del = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/projects/${deletedProject.id}?confirm=${encodeURIComponent(deletedKey)}`,
      headers: orgAdmin.headers,
    });
    expect(del.statusCode).toBe(204);
    expect(await processAll()).toBe(1);
    const [row] = await ctx.db.select().from(analyses).where(eq(analyses.id, id));
    expect(row).toBeUndefined(); // cascade-deleted with the project
    const dead = (await ctx.db.select().from(jobs).where(eq(jobs.status, 'dead'))).filter(
      (j) => (j.payload as { analysisId: string }).analysisId === id,
    );
    expect(dead).toEqual([]);
  });

  it('never logs the password, the token or report content (api.md §6 criterion 7)', async () => {
    const password = 'leak-canary passphrase 42';
    const u = await createUser(ctx, { username: 'canary', password });
    await addMember(ctx, await organizationId(ctx, 'default'), u.id, 'member');
    const failed = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/auth/login',
      payload: { username: 'canary', password: `${password}-wrong` },
    });
    expect(failed.statusCode).toBe(401);
    const session = await login(ctx, 'canary', password);
    const pat = (
      await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: session.headers,
        payload: { name: 'ci', scopes: ['analysis:write', 'read'] },
      })
    ).json().token as string;
    const report = sampleReport({ branch: 'canary' });
    report.findings[0]!.message = 'CANARY-REPORT-9f3k';
    await uploadReport(ctx, bearer(pat), KEY, gzipJson(report));
    await processAll();
    const logs = ctx.logs.join('\n');
    expect(ctx.logs.length).toBeGreaterThan(0);
    for (const secret of [
      password,
      pat,
      pat.slice(12),
      session.cookie,
      session.csrf,
      'CANARY-REPORT-9f3k',
      ADMIN_PASSWORD,
    ]) {
      expect(logs).not.toContain(secret);
    }
  });
});
