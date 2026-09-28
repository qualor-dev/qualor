import { randomUUID } from 'node:crypto';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { reportWith } from '../../test/reports';
import {
  decorationDeps,
  mappedProject,
  mergeRequestReport,
  PUBLIC_URL,
  queuedDecorations,
  runDecorations,
  scmTestConfig,
} from '../../test/scm';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Db } from '../db/client';
import { branches, jobs, scmConnections } from '../db/schema';
import type { Job } from '../queue/queue';
import { SCM_TOKEN_AAD } from './connections';
import { markerOf } from './markdown';
import { scmHandlers } from './decorate';
import {
  enqueueDecoration,
  inSeconds,
  MAX_DECORATION_ATTEMPTS,
  REDECORATION_INTERVAL_SECONDS,
  requeueDecoration,
  SCM_QUEUE,
} from './queue';
import { statusName } from './render';
import { createScmRuntime, SCM_CIRCUIT_FAILURES } from './runtime';

const HEAD = '1'.repeat(40);

/** Polls until `n` backends of this file's own database wait on a lock (never a fixed sleep). */
async function waitForLockWaiters(db: Db, n: number, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = await db.execute(sql`
      SELECT count(*)::int AS n FROM pg_stat_activity
       WHERE wait_event_type = 'Lock' AND datname = current_database()`);
    if (Number(result.rows[0]?.n) >= n) return;
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${n} lock waiter(s)`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

const BASE = 'b'.repeat(40);
const DIFF = '@@ -1,2 +1,5 @@\n a\n b\n+c\n+d\n+e\n';

describe('GitLab decoration: commit status and summary (scm.md §4, §5.1–§5.3)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;
  let nextGitLabProject = 100;

  /** A mapped project with an open merge request !12 at HEAD. */
  const setup = async (key: string, options: { ownConnection?: boolean } = {}) => {
    const gitlabId = nextGitLabProject++;
    fake.addProject({ id: gitlabId, path: `acme/${key.replace(/\W/g, '-')}` });
    fake.addPipeline(gitlabId, 99001, 'main');
    fake.addMergeRequest(gitlabId, {
      iid: 12,
      title: 'Refund limits\u0000 @all',
      state: 'opened',
      sourceBranch: 'feature/x',
      targetBranch: 'main',
      headSha: HEAD,
      baseSha: BASE,
      startSha: BASE,
      diffs: [{ oldPath: 'src/a.ts', newPath: 'src/a.ts', diff: DIFF }],
    });
    const project = await mappedProject(h, fake, key, gitlabId, options);
    return { project, gitlabId };
  };
  const summaries = (gitlabId: number) =>
    fake
      .discussions(gitlabId, 12)
      .flatMap((d) => d.notes)
      .filter((n) => markerOf(n.body)?.kind === 'summary');
  const statusesOf = (gitlabId: number) => fake.statuses.filter((s) => s.projectId === gitlabId);
  const writes = () =>
    fake.requests.filter((r) => r.method !== 'GET').map((r) => r.method + r.path);

  beforeAll(async () => {
    fake = await createFakeGitLab();
    h = await createIngestHarness({ config: scmTestConfig(fake) });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(() => fake.clearRequests());

  it('sets the commit status of a main-branch analysis, with its pipeline and a link', async () => {
    const { project, gitlabId } = await setup('scm/main');
    const analysisId = await project.ingestOk({
      ...reportWith({ projectKey: project.key, revision: 'c'.repeat(40) }),
      scm: {
        ...reportWith({ projectKey: project.key, revision: 'c'.repeat(40) }).scm,
        gitlab: { projectId: String(gitlabId), pipelineId: '99001' },
      },
    });
    expect(await runDecorations(h, decorationDeps(h))).toBe(1);
    const [main] = await h.ctx.db.select().from(branches).where(eq(branches.projectId, project.id));
    expect(statusesOf(gitlabId)).toEqual([
      {
        projectId: gitlabId,
        sha: 'c'.repeat(40),
        name: `qualor/${project.key}`,
        state: 'failed',
        description: 'Quality gate failed: new_issues 1 > 0',
        targetUrl: `${PUBLIC_URL}/projects/${project.id}/branches/${main!.id}`,
        pipelineId: 99001,
        ref: 'main',
      },
    ]);
    // With a pipeline, GitLab takes the ref from it: none is sent beside pipeline_id.
    const posted = fake.requests.find((r) => r.method === 'POST');
    expect(JSON.parse(posted!.body)).not.toHaveProperty('ref');
    // A branch analysis never touches merge requests.
    expect(fake.requests.some((r) => r.path.includes('merge_requests'))).toBe(false);
    expect(analysisId).toBeTruthy();
  });

  it('adds no status row on a rerun when GitLab refused the pipeline and took the status without it', async () => {
    const { project, gitlabId } = await setup('scm/gone-pipeline');
    const revision = 'd'.repeat(40);
    const base = reportWith({ projectKey: project.key, revision });
    // A pipeline GitLab does not know (deleted, say): the post with it is refused (404), and the
    // status is posted again with the ref only, which GitLab attaches to another pipeline.
    const analysisId = await project.ingestOk({
      ...base,
      scm: { ...base.scm, gitlab: { projectId: String(gitlabId), pipelineId: '424242' } },
    });
    await runDecorations(h, decorationDeps(h));
    expect(statusesOf(gitlabId)).toHaveLength(1);
    expect(statusesOf(gitlabId)[0]).toMatchObject({ pipelineId: null, ref: 'main' });
    const [main] = await h.ctx.db.select().from(branches).where(eq(branches.projectId, project.id));
    // The same decoration again (a retry, a re-evaluation): the listed status is on another
    // pipeline, but its name and ref match and it says the same, so nothing is posted again.
    for (let run = 0; run < 2; run++) {
      fake.clearRequests();
      await enqueueDecoration(h.ctx.db, {
        analysisId,
        branchId: main!.id,
        gitlab: { projectId: String(gitlabId), pipelineId: '424242' },
      });
      await runDecorations(h, decorationDeps(h));
      expect(statusesOf(gitlabId)).toHaveLength(1);
      expect(
        fake.requests.filter((r) => r.method === 'POST' && !/"pipeline_id"/.test(r.body)),
      ).toHaveLength(0);
    }
  });

  it('posts one summary on the merge request and edits it in place afterwards', async () => {
    const { project, gitlabId } = await setup('scm/mr');
    await project.ingestOk(
      mergeRequestReport(12, HEAD, {
        projectKey: project.key,
        gitlab: { projectId: String(gitlabId), mergeRequestEventType: 'detached' },
      }),
    );
    await runDecorations(h, decorationDeps(h));
    const [summary] = summaries(gitlabId);
    expect(summaries(gitlabId)).toHaveLength(1);
    expect(summary?.authorId).toBe(fake.botUserId);
    expect(summary?.body).toContain('### Qualor: quality gate failed');
    expect(summary?.body).toContain('**New issues:** 1 (1 medium)');
    expect(summary?.body).toContain('` src/a.ts:3 ` ` Unexpected console statement. `');
    // Without a pipeline, the status names the merge request's source branch as its ref.
    expect(statusesOf(gitlabId).map((s) => [s.state, s.ref])).toEqual([['failed', 'feature/x']]);
    // The merge request's title and URL land on the branch, the title without controls.
    const [mr] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    expect(mr).toMatchObject({
      kind: 'merge_request',
      mrTitle: 'Refund limits  @all',
      mrUrl: `${fake.url}/acme/scm-mr/-/merge_requests/12`,
    });
    // The same job again changes nothing on GitLab: no second note, no edit, and no status post
    // (GitLab would add a second row for the same final state, so the job reads it first).
    fake.clearRequests();
    await enqueueDecoration(h.ctx.db, {
      analysisId: mr!.lastAnalysisId!,
      branchId: mr!.id,
      gitlab: null,
    });
    await runDecorations(h, decorationDeps(h));
    expect(summaries(gitlabId)).toHaveLength(1);
    expect(writes()).toEqual([]);
    expect(statusesOf(gitlabId)).toHaveLength(1);
    // A new analysis (the issue fixed) edits the same note.
    await project.ingestOk(
      mergeRequestReport(12, HEAD, {
        projectKey: project.key,
        findings: [],
        analysisDate: '2026-09-23T10:15:00Z',
      }),
    );
    await runDecorations(h, decorationDeps(h));
    expect(summaries(gitlabId)).toHaveLength(1);
    expect(summaries(gitlabId)[0]?.body).toContain('### Qualor: quality gate passed');
    expect(statusesOf(gitlabId).map((s) => s.state)).toEqual(['failed', 'success']);
    // Another analysis with the same result posts no status and edits nothing.
    fake.clearRequests();
    await project.ingestOk(
      mergeRequestReport(12, HEAD, {
        projectKey: project.key,
        findings: [],
        analysisDate: '2026-09-23T10:30:00Z',
      }),
    );
    await runDecorations(h, decorationDeps(h));
    expect(writes()).toEqual([]);
    expect(statusesOf(gitlabId)).toHaveLength(2);
  });

  it('ignores a summary marker in someone else’s note, and a stale analysis only sets its status', async () => {
    const { project, gitlabId } = await setup('scm/foreign');
    fake.addNote(gitlabId, 12, {
      body: `<!-- qualor:summary ${project.id} -->\nforged`,
      authorId: 5,
    });
    fake.updateMergeRequest(gitlabId, 12, { headSha: 'f'.repeat(40) });
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    await runDecorations(h, decorationDeps(h));
    const notes = fake.discussions(gitlabId, 12).flatMap((d) => d.notes);
    expect(notes.find((n) => n.authorId === 5)?.body).toContain('forged');
    const own = notes.filter((n) => n.authorId === fake.botUserId);
    expect(own).toHaveLength(1);
    expect(own[0]?.body).toContain('the merge request is now at ` ffffffffffff `');
  });

  it('never says "now at" for a merged-results pipeline, whose merge commit is never the head (§5.2)', async () => {
    const { project, gitlabId } = await setup('scm/merged-result');
    const mergeCommit = '9'.repeat(40);
    await project.ingestOk(
      mergeRequestReport(12, mergeCommit, {
        projectKey: project.key,
        gitlab: { projectId: String(gitlabId), mergeRequestEventType: 'merged_result' },
      }),
    );
    await runDecorations(h, decorationDeps(h));
    const [summary] = summaries(gitlabId);
    expect(summary?.body).toContain('merged-results pipeline');
    expect(summary?.body).not.toContain('now at');
    // The merge commit's status goes to the source branch's ref (it is on no branch itself).
    expect(statusesOf(gitlabId)).toMatchObject([{ sha: mergeCommit, ref: 'feature/x' }]);
  });

  it('decorates nothing for a local scan, an unmapped project or a closed merge request', async () => {
    const { project, gitlabId } = await setup('scm/nothing');
    const local = reportWith({ projectKey: project.key });
    await project.ingestOk({ ...local, scm: { ...local.scm, provider: 'none' } });
    expect(await queuedDecorations(h)).toHaveLength(0);
    const unmapped = await h.project('scm/unmapped');
    await unmapped.ingestOk(reportWith({ projectKey: unmapped.key }));
    expect(await queuedDecorations(h)).toHaveLength(0);
    fake.updateMergeRequest(gitlabId, 12, { state: 'merged' });
    await project.ingestOk(
      mergeRequestReport(12, HEAD, {
        projectKey: project.key,
        analysisDate: '2026-09-23T10:15:00Z',
      }),
    );
    await runDecorations(h, decorationDeps(h));
    expect(statusesOf(gitlabId)).toHaveLength(1);
    expect(fake.discussions(gitlabId, 12)).toHaveLength(0);
  });

  it('refuses a pipeline of another GitLab project than the mapped one', async () => {
    const { project, gitlabId } = await setup('scm/mismatch');
    await project.ingestOk(
      mergeRequestReport(12, HEAD, { projectKey: project.key, gitlab: { projectId: '999999' } }),
    );
    await runDecorations(h, decorationDeps(h));
    expect(statusesOf(gitlabId)).toHaveLength(0);
    expect(fake.discussions(gitlabId, 12)).toHaveLength(0);
    expect(await queuedDecorations(h)).toHaveLength(0);
  });

  it('retries a 429 after Retry-After and 5xx with backoff, and stops at once on 401', async () => {
    const { project, gitlabId } = await setup('scm/retry');
    const deps = decorationDeps(h);
    fake.inject('POST', new RegExp(`^/projects/${gitlabId}/statuses/`), {
      status: 429,
      headers: { 'retry-after': '600' },
    });
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    await runDecorations(h, deps);
    const [retry] = await queuedDecorations(h);
    expect(retry?.payload).toMatchObject({ attempt: 1 });
    // On the database clock: the retry is created and scheduled by it (Node's may drift).
    const inSeconds = (retry!.runAt.getTime() - retry!.createdAt.getTime()) / 1000;
    expect(inSeconds).toBeGreaterThan(595);
    expect(inSeconds).toBeLessThan(605);
    // The retry runs (made due) and succeeds.
    await runDecorations(h, deps);
    expect(statusesOf(gitlabId)).toHaveLength(1);
    expect(await queuedDecorations(h)).toHaveLength(0);

    // 401: no retry at all.
    const refused = await setup('scm/refused');
    fake.inject('GET', new RegExp(`^/projects/${refused.gitlabId}$`), { status: 401 });
    await refused.project.ingestOk(
      mergeRequestReport(12, HEAD, { projectKey: refused.project.key }),
    );
    await runDecorations(h, deps);
    expect(await queuedDecorations(h)).toHaveLength(0);
    expect(statusesOf(refused.gitlabId)).toHaveLength(0);
  });

  it('goes on to the summary when the commit status fails, and sets the status on the retry', async () => {
    const { project, gitlabId } = await setup('scm/status-down');
    fake.inject('POST', new RegExp(`^/projects/${gitlabId}/statuses/`), { status: 502 });
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    await runDecorations(h, decorationDeps(h));
    expect(statusesOf(gitlabId)).toHaveLength(0);
    expect(summaries(gitlabId)).toHaveLength(1);
    const [retry] = await queuedDecorations(h);
    expect(retry?.payload).toMatchObject({ attempt: 1 });
    fake.clearRequests();
    await runDecorations(h, decorationDeps(h));
    expect(statusesOf(gitlabId)).toHaveLength(1);
    expect(writes()).toEqual([`POST/projects/${gitlabId}/statuses/${HEAD}`]);
    expect(summaries(gitlabId)).toHaveLength(1);
    expect(await queuedDecorations(h)).toHaveLength(0);
  });

  it('stops without retry when a job runs out of its request budget (§4.3)', async () => {
    const { project, gitlabId } = await setup('scm/budget');
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    const deps = decorationDeps(h);
    await runDecorations(h, {
      ...deps,
      scm: { ...deps.scm, clientOptions: { timeoutMs: 2_000, maxRequests: 4 } },
    });
    // project, statuses (read), status (post), merge request; then the budget is spent.
    expect(statusesOf(gitlabId)).toHaveLength(1);
    expect(summaries(gitlabId)).toHaveLength(0);
    expect(await queuedDecorations(h)).toHaveLength(0);
    expect(
      h.ctx.logs.some(
        (line) =>
          line.includes('GitLab decoration stopped') &&
          line.includes('More than 4 GitLab requests in one job'),
      ),
    ).toBe(true);
  });

  it(`gives up after ${MAX_DECORATION_ATTEMPTS} attempts and opens the circuit after ${SCM_CIRCUIT_FAILURES} failures`, async () => {
    const { project, gitlabId } = await setup('scm/down');
    let now = Date.now();
    const deps = decorationDeps(h, { runtime: createScmRuntime(() => now) });
    const down = { status: 503 };
    fake.inject(
      'GET',
      new RegExp(`^/projects/${gitlabId}$`),
      ...Array(SCM_CIRCUIT_FAILURES).fill(down),
    );
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    for (let attempt = 1; attempt <= SCM_CIRCUIT_FAILURES; attempt++) {
      await runDecorations(h, deps);
      expect((await queuedDecorations(h))[0]?.payload).toMatchObject({ attempt });
    }
    // The circuit is open: the sixth attempt makes no request and is the last.
    fake.clearRequests();
    await runDecorations(h, deps);
    expect(fake.requests).toHaveLength(0);
    expect(await queuedDecorations(h)).toHaveLength(0);
    // Ten minutes later one decoration goes through again and closes the circuit.
    now += 10 * 60_000 + 1;
    await project.ingestOk(
      mergeRequestReport(12, HEAD, {
        projectKey: project.key,
        analysisDate: '2026-09-23T10:15:00Z',
      }),
    );
    await runDecorations(h, deps);
    expect(statusesOf(gitlabId)).toHaveLength(1);
    expect(deps.runtime.circuit.openUntil(project.connectionId)).toBeNull();
  });

  it('lets a new decoration of the branch replace its queued retries', async () => {
    const { project, gitlabId } = await setup('scm/supersede');
    fake.inject('POST', new RegExp(`^/projects/${gitlabId}/statuses/`), { status: 502 });
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    await runDecorations(h, decorationDeps(h));
    const [retry] = await queuedDecorations(h);
    expect(retry?.payload).toMatchObject({ attempt: 1 });
    await project.ingestOk(
      mergeRequestReport(12, HEAD, {
        projectKey: project.key,
        analysisDate: '2026-09-23T10:15:00Z',
      }),
    );
    const queued = await queuedDecorations(h);
    expect(queued).toHaveLength(1);
    expect(queued[0]?.payload).toMatchObject({ attempt: 0 });
    expect(queued[0]?.id).not.toBe(retry?.id);
  });

  it('stops at once when GitLab rate-limits the commit status, without the merge request part', async () => {
    const { project, gitlabId } = await setup('scm/status-429');
    fake.inject('POST', new RegExp(`^/projects/${gitlabId}/statuses/`), {
      status: 429,
      headers: { 'retry-after': '30' },
    });
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    await runDecorations(h, decorationDeps(h));
    expect(
      fake.requests.filter((r) => r.path.startsWith(`/projects/${gitlabId}/merge_requests`)),
    ).toHaveLength(0);
    expect(summaries(gitlabId)).toHaveLength(0);
    const [retry] = await queuedDecorations(h);
    expect(retry?.payload).toMatchObject({ attempt: 1 });
    await h.ctx.db.delete(jobs).where(eq(jobs.id, retry!.id));
  });

  it('never queues a retry beside a newer decoration being enqueued (one branch lock)', async () => {
    const { project } = await setup('scm/race');
    const analysisId = await project.ingestOk(
      mergeRequestReport(12, HEAD, { projectKey: project.key }),
    );
    const [first] = await queuedDecorations(h);
    // The ingestion's decoration runs (it is no longer queued) and fails ...
    await h.ctx.db.update(jobs).set({ status: 'running' }).where(eq(jobs.id, first!.id));
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    let retried: Promise<boolean> | undefined;
    // ... while a newer decoration of the branch is being enqueued in another transaction.
    await h.ctx.db.transaction(async (tx) => {
      await enqueueDecoration(tx, { analysisId, branchId: branch!.id, gitlab: null });
      retried = requeueDecoration(
        h.ctx.db,
        branch!.id,
        { analysisId, attempt: 1, gitlab: null },
        inSeconds(60),
      );
      await waitForLockWaiters(h.ctx.db, 1);
    });
    expect(await retried!).toBe(false);
    const queued = await queuedDecorations(h);
    expect(queued).toHaveLength(1);
    expect(queued[0]?.payload).toMatchObject({ attempt: 0 });
    await h.ctx.db.delete(jobs).where(eq(jobs.id, first!.id));
    await h.ctx.db.delete(jobs).where(eq(jobs.id, queued[0]!.id));
  });

  it('logs a failed decoration whose retry a newer decoration of the branch replaces', async () => {
    const { project, gitlabId } = await setup('scm/superseded');
    const older = await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    // A newer analysis of the branch queues its decoration (and deletes the older one's) ...
    await project.ingestOk(
      mergeRequestReport(12, HEAD, {
        projectKey: project.key,
        analysisDate: '2026-09-23T10:15:00Z',
      }),
    );
    // ... while the older one was already running, and now fails.
    fake.inject('GET', new RegExp(`^/projects/${gitlabId}$`), { status: 502 });
    await scmHandlers(decorationDeps(h))[SCM_QUEUE]!({
      id: randomUUID(),
      payload: { analysisId: older, attempt: 0, gitlab: null },
    } as unknown as Job);
    const lines = h.ctx.logs.filter((line) => line.includes(older));
    expect(lines.some((line) => line.includes('GitLab decoration superseded'))).toBe(true);
    expect(lines.some((line) => line.includes('GitLab decoration retried'))).toBe(false);
    const queued = await queuedDecorations(h);
    expect(queued).toHaveLength(1);
    await h.ctx.db.delete(jobs).where(eq(jobs.id, queued[0]!.id));
  });

  it(`re-decorates a branch after a re-evaluation at most once per ${REDECORATION_INTERVAL_SECONDS} s (ruling G7)`, async () => {
    const { project } = await setup('scm/redecorate-rate');
    const analysisId = await project.ingestOk(
      mergeRequestReport(12, HEAD, { projectKey: project.key }),
    );
    const deps = decorationDeps(h);
    await runDecorations(h, deps);
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    const redecorate = () =>
      enqueueDecoration(h.ctx.db, {
        analysisId,
        branchId: branch!.id,
        gitlab: null,
        reevaluation: true,
      });
    // Times are compared on the database clock (a container's clock may drift from Node's).
    const queuedWait = async () => {
      const [queued] = await queuedDecorations(h);
      return (queued!.runAt.getTime() - queued!.createdAt.getTime()) / 1_000;
    };
    const lastRedecoration = async () => {
      const [last] = await h.ctx.db
        .select({ createdAt: jobs.createdAt })
        .from(jobs)
        .where(
          sql`${jobs.queue} = ${SCM_QUEUE} AND ${jobs.status} <> 'queued' AND ${jobs.concurrencyKey} = ${`scm:branch:${branch!.id}`} AND ${jobs.payload} ->> 'reevaluation' = 'true'`,
        )
        .orderBy(sql`${jobs.createdAt} DESC`)
        .limit(1);
      return last!.createdAt.getTime();
    };
    // The first re-decoration is not held back by the ingestion's decoration.
    await redecorate();
    expect(await queuedWait()).toBeLessThan(1);
    await runDecorations(h, deps);
    // The next one waits for the interval after the previous one, and toggling again while it
    // waits does not push it later: at most one re-decoration per interval, never starved.
    await redecorate();
    const [held] = await queuedDecorations(h);
    expect((held!.runAt.getTime() - (await lastRedecoration())) / 1_000).toBeCloseTo(
      REDECORATION_INTERVAL_SECONDS,
      2,
    );
    // Held back at all: it runs after it was enqueued (the interval is not over yet).
    expect(await queuedWait()).toBeGreaterThan(0);
    await redecorate();
    const again = await queuedDecorations(h);
    expect(again).toHaveLength(1);
    expect(again[0]!.runAt.getTime()).toBe(held!.runAt.getTime());
    // A new analysis's decoration is never held back.
    await enqueueDecoration(h.ctx.db, { analysisId, branchId: branch!.id, gitlab: null });
    expect(await queuedWait()).toBeLessThan(1);
    await runDecorations(h, deps);
  });

  it('records no merge request link when the connection moved while the job ran (scm.md §8)', async () => {
    const { project, gitlabId } = await setup('scm/moved-meanwhile', { ownConnection: true });
    // The address changes (as a PATCH with a new token would) after the job loaded the
    // connection and before it records the merge request GitLab answered with.
    fake.inject('GET', new RegExp(`^/projects/${gitlabId}/merge_requests/12$`), {
      status: 200,
      passThrough: true,
      before: async () => {
        await h.ctx.db
          .update(scmConnections)
          .set({ baseUrl: 'https://gitlab.moved.example' })
          .where(eq(scmConnections.id, project.connectionId));
      },
    });
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    await runDecorations(h, decorationDeps(h));
    const [mr] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    expect(mr?.mrUrl).toBeNull();
  });

  it('never writes the token into a log line, a job row or a comment', async () => {
    const { project, gitlabId } = await setup('scm/secret');
    fake.inject('GET', new RegExp(`^/projects/${gitlabId}$`), { status: 500 });
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    await runDecorations(h, decorationDeps(h));
    await runDecorations(h, decorationDeps(h));
    const allJobs = await h.ctx.db.select().from(jobs);
    expect(JSON.stringify(allJobs)).not.toContain(fake.token);
    expect(h.ctx.logs.join('\n')).not.toContain(fake.token);
    expect(h.ctx.logs.join('\n')).toContain('GitLab decoration retried');
    const bodies = fake.discussions(gitlabId, 12).flatMap((d) => d.notes.map((n) => n.body));
    expect(bodies.join('\n')).not.toContain(fake.token);
  });

  // Review Focus of plan 2A: what the spec implies and a user will meet.

  it('sends nothing with a token that no longer decrypts (QUALOR_SECRET_KEY rotated), and says so', async () => {
    const { project, gitlabId } = await setup('scm/rotated', { ownConnection: true });
    await h.ctx.db
      .update(scmConnections)
      .set({
        tokenEnc: encryptSecret(
          encryptionKey('another-secret-key-of-at-least-32-chars'),
          fake.token,
          SCM_TOKEN_AAD,
        ),
      })
      .where(eq(scmConnections.id, project.connectionId));
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    fake.clearRequests();
    await runDecorations(h, decorationDeps(h));
    expect(fake.requests).toHaveLength(0);
    expect(statusesOf(gitlabId)).toHaveLength(0);
    expect(await queuedDecorations(h)).toHaveLength(0);
    expect(
      h.ctx.logs.some(
        (line) =>
          line.includes('GitLab decoration stopped') && line.includes('cannot be decrypted'),
      ),
    ).toBe(true);
  });

  it('sends nothing to a host the operator no longer lists in QUALOR_SCM_INTERNAL_HOSTS', async () => {
    const { project } = await setup('scm/unlisted');
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    fake.clearRequests();
    const deps = decorationDeps(h);
    await runDecorations(h, { ...deps, scm: { ...deps.scm, internalHosts: new Set() } });
    expect(fake.requests).toHaveLength(0);
    expect(await queuedDecorations(h)).toHaveLength(0);
  });

  it('keeps one summary per Qualor project when two projects decorate one merge request', async () => {
    const { project, gitlabId } = await setup('scm/mono-a');
    const other = await mappedProject(h, fake, 'scm/mono-b', gitlabId);
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    await other.ingestOk(mergeRequestReport(12, HEAD, { projectKey: other.key, findings: [] }));
    await runDecorations(h, decorationDeps(h));
    await project.ingestOk(
      mergeRequestReport(12, HEAD, {
        projectKey: project.key,
        analysisDate: '2026-09-23T10:15:00Z',
      }),
    );
    await runDecorations(h, decorationDeps(h));
    const owners = summaries(gitlabId).map((n) => {
      const marker = markerOf(n.body);
      return marker?.kind === 'summary' ? marker.projectId : null;
    });
    expect(owners.sort()).toEqual([project.id, other.id].sort());
    // Ruling G4: each project has its own commit status on the shared commit.
    expect(
      statusesOf(gitlabId)
        .filter((s) => s.sha === HEAD)
        .map((s) => [s.name, s.state])
        .sort(),
    ).toEqual(
      [
        [statusName(project.key), 'failed'],
        [statusName(other.key), 'success'],
      ].sort(),
    );
    expect(summaries(gitlabId).find((n) => n.body.includes(other.id))?.body).toContain(
      'quality gate passed',
    );
  });

  it('sets only the commit status for a merge request GitLab does not have, or a non-GitLab id', async () => {
    const { project, gitlabId } = await setup('scm/no-mr');
    await project.ingestOk(mergeRequestReport(99, HEAD, { projectKey: project.key }));
    await runDecorations(h, decorationDeps(h));
    expect(statusesOf(gitlabId)).toHaveLength(1);
    expect(await queuedDecorations(h)).toHaveLength(0);
    const pr = await setup('scm/pr-id');
    const report = mergeRequestReport(12, 'e'.repeat(40), { projectKey: pr.project.key });
    await pr.project.ingestOk({
      ...report,
      scm: {
        ...report.scm,
        mergeRequest: { id: 'pr-12', targetBranch: 'main', sourceBranch: 'feature/x' },
      },
    });
    fake.clearRequests();
    await runDecorations(h, decorationDeps(h));
    expect(statusesOf(pr.gitlabId)).toHaveLength(1);
    expect(fake.requests.some((r) => r.path.includes('merge_requests'))).toBe(false);
  });

  it('does nothing when the connection was deleted while the decoration waited', async () => {
    const { project } = await setup('scm/deleted', { ownConnection: true });
    await project.ingestOk(mergeRequestReport(12, HEAD, { projectKey: project.key }));
    const removed = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/scm-connections/${project.connectionId}`,
      headers: h.orgAdmin.headers,
    });
    expect(removed.statusCode).toBe(204);
    fake.clearRequests();
    expect(await runDecorations(h, decorationDeps(h))).toBe(1);
    expect(fake.requests).toHaveLength(0);
    expect(await queuedDecorations(h)).toHaveLength(0);
  });

  it('does nothing for an analysis of a local scan, however its decoration was queued', async () => {
    const { project } = await setup('scm/local-scan');
    const report = mergeRequestReport(12, HEAD, { projectKey: project.key });
    const analysisId = await project.ingestOk({
      ...report,
      scm: { ...report.scm, provider: 'none' },
    });
    // §4.1: the stage enqueues nothing for it ...
    expect(await queuedDecorations(h)).toHaveLength(0);
    // ... and a decoration queued anyway (a re-evaluation, say) reads the stored context.
    const [mr] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    await enqueueDecoration(h.ctx.db, { analysisId, branchId: mr!.id, gitlab: null });
    fake.clearRequests();
    expect(await runDecorations(h, decorationDeps(h))).toBe(1);
    expect(fake.requests).toHaveLength(0);
  });
});
