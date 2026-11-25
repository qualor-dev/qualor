import type { SnapshotLine } from '@qualor/shared';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitLab, type FakeGitLab, type FakeMergeRequest } from '../../test/fake-gitlab';
import { createFakeLlm, type FakeLlm } from '../../test/fake-llm';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { FIXED_TEXT, outsideCodeSpans } from '../../test/markdown-check';
import { reviewOff, reviewOn, reviewScope } from '../../test/replies';
import { reviewResponder, reviewRoleOf, storeTestSnapshot } from '../../test/review';
import {
  decorationDeps,
  mappedProject,
  mergeRequestReport,
  PUBLIC_URL,
  silentLogger,
} from '../../test/scm';
import { first } from '../db/rows';
import {
  branches,
  jobs,
  reviewReplies,
  reviewRuns,
  type ReplyCommand,
  type ReviewFailureReason,
  type ReviewSkipReason,
} from '../db/schema';
import { createLlmRuntime } from '../llm/job';
import { readLlmSettings } from '../llm/settings';
import { runUntilIdle } from '../queue/worker';
import { codeSpan } from '../scm/markdown';
import { lockBranchQueue, SCM_QUEUE } from '../scm/queue';
import { parseInternalHosts } from '../scm/url';
import {
  handleCommand,
  NothingToReview,
  RIGHTS_UNREADABLE,
  type CommandContext,
  type ReviewRight,
} from './commands';
import { reviewHandlers, type ReviewJobDeps } from './job';
import { claimReply, insertReplies, type ReplyRow } from './replies';
import { AI_REVIEW_QUEUE } from './runs';

/*
 * What a person's `qualor review`, `qualor fix` or `qualor stop` comes to (6I-4): `handleCommand`
 * decides it, under the branch's decoration lock and the run's row, and keeps the answer on the
 * command's row of the replies ledger. These cases call it as the answer job does, with the row
 * taken (`running`); the job's own steps, with the providers, are in reply-job.db.test.ts.
 */

/** The head commit of `storeTestSnapshot`'s header: the one a review reads. */
const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
/** The commit the analyses are of, which no snapshot is of. */
const REVISION = '1'.repeat(40);
/** A commit a run holds of its own. */
const RUN_HEAD = '3'.repeat(40);
const IID = 5;
/** A merge request that adds three lines: a trivial change, which one reviewer and the judge read. */
const CHANGE: SnapshotLine[] = [
  {
    type: 'change',
    path: 'src/cart.ts',
    oldPath: null,
    status: 'added',
    patch: '@@ -0,0 +1,3 @@\n+export const a = 1;\n+export const b = 2;\n+export const c = 3;\n',
    since: null,
  },
  {
    type: 'file',
    path: 'src/cart.ts',
    text: 'export const a = 1;\nexport const b = 2;\nexport const c = 3;\n',
  },
];

const NOT_AVAILABLE = 'Auto-fix is not switched on for this project.';
const NOT_A_MEMBER = 'Only project members can ask for an AI review.';
const REVIEW_OFF = 'AI review is not switched on for this project.';
const IN_PROGRESS = 'A review of this commit is in progress.';
const reviewed = (sha: string) =>
  `This commit (${codeSpan(sha.slice(0, 12))}) has been reviewed. Push a new commit to review again.`;
const requested = (sha: string) => `Reviewing this commit (${codeSpan(sha.slice(0, 12))}).`;

describe('the qualor review, fix and stop commands (6I-4)', () => {
  let h: IngestHarness;
  let gitlab: FakeGitLab;
  let llm: FakeLlm;
  let nextProject = 0;
  let nextNote = 1_000;

  /**
   * A merge request of a project of its own on the fake GitLab, and its analysis, ingested with AI
   * review on: its run waits for a snapshot.
   */
  const mergeRequest = async (over: Partial<FakeMergeRequest> = {}) => {
    nextProject += 1;
    const gitlabId = 600 + nextProject;
    gitlab.addProject({ id: gitlabId, path: `acme/commands-${nextProject}` });
    gitlab.addMergeRequest(gitlabId, {
      iid: IID,
      title: 'Add the cart',
      state: 'opened',
      sourceBranch: 'feature/cart',
      targetBranch: 'main',
      headSha: HEAD,
      baseSha: BASE,
      startSha: BASE,
      diffs: [],
      ...over,
    });
    const project = await mappedProject(h, gitlab, `commands/p${nextProject}`, gitlabId);
    const analysisId = await ingest(project, gitlabId, REVISION, 1);
    const [branch] = await h.ctx.db
      .select({ id: branches.id })
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    await forgetDecorations(analysisId);
    return { project, gitlabId, analysisId, branchId: branch!.id };
  };
  type Mr = Awaited<ReturnType<typeof mergeRequest>>;
  /** Another analysis of the project's merge request, `n` days after the first. */
  const ingest = (
    project: Awaited<ReturnType<typeof mappedProject>>,
    gitlabId: number,
    revision: string,
    n: number,
  ) =>
    project.ingestOk(
      mergeRequestReport(IID, revision, {
        projectKey: project.key,
        analysisDate: `2026-10-0${n}T10:00:00Z`,
        gitlab: { projectId: String(gitlabId), mergeRequestEventType: 'detached' },
      }),
    );
  const snapshot = (mr: Mr) =>
    storeTestSnapshot(h.ctx.db, mr.analysisId, CHANGE, {
      mergeRequest: { id: String(IID), title: 'Add the cart', description: null },
    });

  const runOf = async (analysisId: string) =>
    first(await h.ctx.db.select().from(reviewRuns).where(eq(reviewRuns.analysisId, analysisId)));
  const runsOfBranch = (branchId: string) =>
    h.ctx.db.select().from(reviewRuns).where(eq(reviewRuns.branchId, branchId));
  /** The review jobs queued for the run, each with whether it is due now. */
  const reviewJobs = (runId: string) =>
    h.ctx.db
      .select({ due: sql<boolean>`${jobs.runAt} <= now()` })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, AI_REVIEW_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'runId' = ${runId}`,
        ),
      );
  /** The decorations queued for the analysis. */
  const decorations = (analysisId: string) =>
    h.ctx.db
      .select({ id: jobs.id })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, SCM_QUEUE),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'analysisId' = ${analysisId}`,
        ),
      );
  /** Forgets the decoration ingestion queued for the analysis, so that only a command's are left to see. */
  const forgetDecorations = (analysisId: string) =>
    h.ctx.db
      .delete(jobs)
      .where(and(eq(jobs.queue, SCM_QUEUE), sql`${jobs.payload} ->> 'analysisId' = ${analysisId}`));
  /** The merge request's analysis has no run, as when AI review was off at its ingestion. */
  const withoutRun = async (mr: Mr) => {
    const run = await runOf(mr.analysisId);
    await h.ctx.db.delete(reviewRuns).where(eq(reviewRuns.id, run.id));
    await h.ctx.db
      .delete(jobs)
      .where(and(eq(jobs.queue, AI_REVIEW_QUEUE), sql`${jobs.payload} ->> 'runId' = ${run.id}`));
  };
  /**
   * The merge request's run as a review leaves it once it ended (or is running): its job is gone.
   */
  const settle = async (mr: Mr, state: Partial<typeof reviewRuns.$inferInsert>) => {
    const run = await runOf(mr.analysisId);
    await h.ctx.db
      .update(reviewRuns)
      .set({ phase: null, finishedAt: new Date(), ...state })
      .where(eq(reviewRuns.id, run.id));
    await h.ctx.db
      .delete(jobs)
      .where(and(eq(jobs.queue, AI_REVIEW_QUEUE), sql`${jobs.payload} ->> 'runId' = ${run.id}`));
  };

  /** A command's row as the answer job holds it: queued by a decoration, then taken. */
  const command = async (mr: Mr, which: ReplyCommand, author = 'octocat'): Promise<ReplyRow> => {
    nextNote += 1;
    const [id] = await insertReplies(h.ctx.db, [
      {
        projectId: mr.project.id,
        branchId: mr.branchId,
        provider: 'gitlab',
        noteId: nextNote,
        threadId: 'abcdef0123',
        kind: 'command',
        command: which,
        author,
      },
    ]);
    const taken = await claimReply(h.ctx.db, id!);
    if (taken === null) throw new Error('the command row was not queued');
    return taken;
  };
  const rowById = async (id: string) =>
    first(await h.ctx.db.select().from(reviewReplies).where(eq(reviewReplies.id, id)));
  /** The job's loads; the author has the rights `qualor review` needs unless the case says not. */
  const contextOf = async (
    mr: Mr,
    authorMayReview: ReviewRight = true,
  ): Promise<CommandContext> => ({
    settings: await readLlmSettings(h.ctx.db),
    project: {
      id: mr.project.id,
      organizationId: h.organizationId,
      scmConnectionId: mr.project.connectionId,
    },
    branch: { id: mr.branchId },
    logger: silentLogger,
    authorMayReview,
  });
  const decide = async (mr: Mr, row: ReplyRow, authorMayReview: ReviewRight = true) =>
    handleCommand(h.ctx.db, row, await contextOf(mr, authorMayReview));

  const jobDeps = (): ReviewJobDeps => ({
    db: h.ctx.db,
    config: h.ctx.config,
    logger: silentLogger,
    llmCircuit: createLlmRuntime().circuit,
    scm: decorationDeps(h).scm,
    scmRuntime: decorationDeps(h).runtime,
    shutdown: new AbortController().signal,
  });
  /** Runs the `ai-review` jobs that are due, as the review worker does. */
  const reviews = () => runUntilIdle(h.ctx.db, reviewHandlers(jobDeps()), silentLogger);
  const reviewCalls = () => llm.requests.filter((request) => reviewRoleOf(request) !== null);

  beforeAll(async () => {
    llm = await createFakeLlm();
    gitlab = await createFakeGitLab();
    h = await createIngestHarness({
      config: {
        publicUrl: PUBLIC_URL,
        scmInternalHosts: parseInternalHosts(new URL(gitlab.url).host),
        llmInternalHosts: parseInternalHosts(llm.host),
      },
    });
  });
  afterAll(async () => {
    await h.close();
    await gitlab.close();
    await llm.close();
  });
  beforeEach(async () => {
    await reviewOn(h, llm);
    // Each case sees the reviews of its own merge request only.
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, AI_REVIEW_QUEUE));
  });

  it('qualor review on a draft reviews it', async () => {
    const mr = await mergeRequest({ draft: true });
    await snapshot(mr);
    // The run was skipped as a draft: no one had asked for it.
    expect(await reviews()).toBe(1);
    expect(await runOf(mr.analysisId)).toMatchObject({
      status: 'skipped',
      reason: 'draft',
      requestedBy: null,
    });
    const row = await command(mr, 'review', 'octocat');
    expect(await decide(mr, row)).toEqual({
      outcome: 'review_requested',
      text: requested(HEAD),
    });
    const calls = reviewCalls().length;
    llm.enqueue(reviewResponder(), reviewResponder());
    expect(await reviews()).toBe(1);
    // The same run, now asked for by the person, was reviewed though the merge request is a draft.
    expect(await runsOfBranch(mr.branchId)).toHaveLength(1);
    expect(await runOf(mr.analysisId)).toMatchObject({
      status: 'done',
      reason: null,
      requestedBy: 'octocat',
      headSha: HEAD,
    });
    expect(reviewCalls()).toHaveLength(calls + 2);
  });

  it('qualor review on a reviewed commit answers it was reviewed and makes no run', async () => {
    const mr = await mergeRequest();
    await settle(mr, { status: 'done', headSha: HEAD, startedAt: new Date() });
    const before = await runOf(mr.analysisId);
    const row = await command(mr, 'review');
    const text = reviewed(HEAD);
    expect(text).toBe(
      'This commit (` aaaaaaaaaaaa `) has been reviewed. Push a new commit to review again.',
    );
    expect(await decide(mr, row)).toEqual({ outcome: 'already_reviewed', text });
    // Nothing was made or touched: one run, the row as it was, no job, no decoration.
    expect(await runsOfBranch(mr.branchId)).toEqual([before]);
    expect(await reviewJobs(before.id)).toEqual([]);
    expect(await decorations(mr.analysisId)).toEqual([]);
    expect(await rowById(row.id)).toMatchObject({ outcome: 'already_reviewed', answer: text });
  });

  it('a run skipped as unchanged is answered as reviewed, and not restarted', async () => {
    const mr = await mergeRequest();
    await settle(mr, {
      status: 'skipped',
      reason: 'unchanged',
      headSha: RUN_HEAD,
      startedAt: new Date(),
    });
    const before = await runOf(mr.analysisId);
    const row = await command(mr, 'review');
    expect(await decide(mr, row)).toEqual({
      outcome: 'already_reviewed',
      text: reviewed(RUN_HEAD),
    });
    expect(await runsOfBranch(mr.branchId)).toEqual([before]);
    expect(await reviewJobs(before.id)).toEqual([]);
    expect(await decorations(mr.analysisId)).toEqual([]);
  });

  it.each(['waiting', 'running'] as const)(
    'qualor review during a review (%s) answers it is in progress',
    async (status) => {
      const mr = await mergeRequest();
      if (status === 'running') {
        await settle(mr, {
          status: 'running',
          phase: 'judge',
          headSha: HEAD,
          startedAt: new Date(),
          finishedAt: null,
        });
      }
      const before = await runOf(mr.analysisId);
      const jobsBefore = await reviewJobs(before.id);
      const row = await command(mr, 'review');
      expect(await decide(mr, row)).toEqual({ outcome: 'in_progress', text: IN_PROGRESS });
      expect(await runsOfBranch(mr.branchId)).toEqual([before]);
      expect(await reviewJobs(before.id)).toEqual(jobsBefore);
      expect(await decorations(mr.analysisId)).toEqual([]);
    },
  );

  it('qualor review restarts a skipped run once, however often it is written', async () => {
    const mr = await mergeRequest({ draft: true });
    await settle(mr, { status: 'skipped', reason: 'draft', headSha: HEAD, startedAt: new Date() });
    const rows = [
      await command(mr, 'review', 'octocat'),
      await command(mr, 'review', 'hubot'),
      await command(mr, 'review', 'octocat'),
    ];
    const decided = [];
    for (const row of rows) decided.push(await decide(mr, row));
    // The first restarts the run; the others find it waiting.
    expect(decided).toEqual([
      { outcome: 'review_requested', text: requested(HEAD) },
      { outcome: 'in_progress', text: IN_PROGRESS },
      { outcome: 'in_progress', text: IN_PROGRESS },
    ]);
    const run = await runOf(mr.analysisId);
    expect(await runsOfBranch(mr.branchId)).toHaveLength(1);
    expect(run).toMatchObject({
      status: 'waiting',
      reason: null,
      requestedBy: 'octocat',
      startedAt: null,
      finishedAt: null,
    });
    // One job, due now, and one decoration, so that the summary says the review is in progress.
    expect(await reviewJobs(run.id)).toEqual([{ due: true }]);
    expect(await decorations(mr.analysisId)).toHaveLength(1);
    for (const [index, row] of rows.entries()) {
      expect(await rowById(row.id)).toMatchObject({
        outcome: decided[index]!.outcome,
        answer: decided[index]!.text,
      });
    }
  });

  it.each([
    ['skipped', 'no_snapshot'],
    ['skipped', 'snapshot_rejected'],
    ['skipped', 'draft'],
    ['skipped', 'closed'],
    ['skipped', 'inactive'],
    ['skipped', 'empty_diff'],
    ['skipped', 'budget_spent'],
    ['failed', 'provider_error'],
    ['failed', 'provider_no_tools'],
    ['failed', 'bad_answer'],
    ['failed', 'internal'],
    ['superseded', null],
  ] as const)('qualor review restarts a run that ended %s (%s)', async (status, reason) => {
    const mr = await mergeRequest();
    await settle(mr, {
      status,
      reason: reason as ReviewSkipReason | ReviewFailureReason | null,
      headSha: RUN_HEAD,
      startedAt: new Date(),
    });
    const row = await command(mr, 'review');
    expect(await decide(mr, row)).toEqual({
      outcome: 'review_requested',
      text: requested(RUN_HEAD),
    });
    expect(await runOf(mr.analysisId)).toMatchObject({ status: 'waiting', requestedBy: 'octocat' });
    expect(await runsOfBranch(mr.branchId)).toHaveLength(1);
  });

  it('qualor review with AI review off answers so', async () => {
    const mr = await mergeRequest();
    const before = await runOf(mr.analysisId);
    const jobsBefore = await reviewJobs(before.id);
    const answered = async (why: string) => {
      const row = await command(mr, 'review');
      expect(await decide(mr, row), why).toEqual({ outcome: 'review_off', text: REVIEW_OFF });
      expect(await rowById(row.id), why).toMatchObject({
        outcome: 'review_off',
        answer: REVIEW_OFF,
      });
      // The run is untouched, whatever state it is in.
      expect(await runsOfBranch(mr.branchId), why).toEqual([before]);
      expect(await reviewJobs(before.id), why).toEqual(jobsBefore);
    };
    await reviewOff(h);
    await answered('no provider is configured');
    await reviewOn(h, llm);
    await reviewScope(h, 'selected');
    await answered('the project is not in the scope of AI review');
    // A run that ended is not restarted either.
    await reviewOn(h, llm);
    await settle(mr, { status: 'failed', reason: 'internal', startedAt: new Date() });
    await reviewOff(h);
    const failed = await runOf(mr.analysisId);
    const row = await command(mr, 'review');
    expect(await decide(mr, row)).toEqual({ outcome: 'review_off', text: REVIEW_OFF });
    expect(await runOf(mr.analysisId)).toEqual(failed);
  });

  it('qualor fix and qualor stop answer that auto-fix is not switched on', async () => {
    const mr = await mergeRequest();
    const before = await runOf(mr.analysisId);
    for (const which of ['fix', 'stop'] as const) {
      for (const switchedOn of [true, false]) {
        if (!switchedOn) await reviewOff(h);
        const row = await command(mr, which);
        expect(await decide(mr, row), `${which}, AI review on: ${switchedOn}`).toEqual({
          outcome: 'not_available',
          text: NOT_AVAILABLE,
        });
        expect(await rowById(row.id)).toMatchObject({
          outcome: 'not_available',
          answer: NOT_AVAILABLE,
        });
      }
      await reviewOn(h, llm);
    }
    // They touch no run.
    expect(await runsOfBranch(mr.branchId)).toEqual([before]);
    expect(await decorations(mr.analysisId)).toEqual([]);
  });

  it('qualor review from someone without the rights is refused with a fixed text, and no run is made, started again or touched', async () => {
    // Whatever the run is: one a review would start again, one that waits, one that is done, none.
    const runs: [string, Partial<typeof reviewRuns.$inferInsert> | null][] = [
      ['failed', { status: 'failed', reason: 'internal', headSha: HEAD, startedAt: new Date() }],
      ['waiting', {}],
      ['done', { status: 'done', headSha: HEAD, startedAt: new Date() }],
      ['no run', null],
    ];
    for (const [which, state] of runs) {
      const mr = await mergeRequest();
      if (state === null) await withoutRun(mr);
      else if (which !== 'waiting') await settle(mr, state);
      const before = await runsOfBranch(mr.branchId);
      const row = await command(mr, 'review', 'eve');
      expect(await decide(mr, row, false), which).toEqual({
        outcome: 'not_available',
        text: NOT_A_MEMBER,
      });
      expect(await rowById(row.id), which).toMatchObject({
        outcome: 'not_available',
        answer: NOT_A_MEMBER,
      });
      // Nothing was made, asked for or touched: the runs as they were, no job, no decoration.
      expect(await runsOfBranch(mr.branchId), which).toEqual(before);
      for (const run of before) {
        expect(await reviewJobs(run.id), which).toEqual(
          which === 'waiting' ? [{ due: false }] : [],
        );
      }
      expect(await decorations(mr.analysisId), which).toEqual([]);
    }
  });

  it("qualor review whose rights Qualor's own credential cannot read names that credential, not the author, and makes no run", async () => {
    const mr = await mergeRequest();
    await settle(mr, {
      status: 'failed',
      reason: 'internal',
      headSha: HEAD,
      startedAt: new Date(),
    });
    const before = await runsOfBranch(mr.branchId);
    const row = await command(mr, 'review', 'octocat');
    expect(await decide(mr, row, 'unreadable')).toEqual({
      outcome: 'not_available',
      text: RIGHTS_UNREADABLE,
    });
    expect(await rowById(row.id)).toMatchObject({
      outcome: 'not_available',
      answer: RIGHTS_UNREADABLE,
    });
    expect(await runsOfBranch(mr.branchId)).toEqual(before);
    // An author who may not is still told so.
    expect(await decide(mr, await command(mr, 'review', 'eve'), false)).toEqual({
      outcome: 'not_available',
      text: NOT_A_MEMBER,
    });
  });

  it('the refusal comes before the AI-review-off answer', async () => {
    const mr = await mergeRequest();
    await reviewOff(h);
    expect(await decide(mr, await command(mr, 'review'), false)).toEqual({
      outcome: 'not_available',
      text: NOT_A_MEMBER,
    });
    // With the rights, it is AI review that is off.
    expect(await decide(mr, await command(mr, 'review'), true)).toEqual({
      outcome: 'review_off',
      text: REVIEW_OFF,
    });
  });

  it('qualor fix and qualor stop are answered for everyone: the rights decide nothing for them', async () => {
    const mr = await mergeRequest();
    for (const which of ['fix', 'stop'] as const) {
      const row = await command(mr, which, 'eve');
      expect(await decide(mr, row, false), which).toEqual({
        outcome: 'not_available',
        text: NOT_AVAILABLE,
      });
    }
  });

  it('a refusal and a restart are decided once: a retry finds the decision, whatever the rights say then', async () => {
    const mr = await mergeRequest();
    await settle(mr, {
      status: 'failed',
      reason: 'internal',
      headSha: HEAD,
      startedAt: new Date(),
    });
    const refused = await command(mr, 'review', 'eve');
    expect(await decide(mr, refused, false)).toEqual({
      outcome: 'not_available',
      text: NOT_A_MEMBER,
    });
    const asked = await command(mr, 'review', 'octocat');
    expect(await decide(mr, asked, true)).toEqual({
      outcome: 'review_requested',
      text: requested(HEAD),
    });
    // The rights of the one are now the other's: nothing is decided again.
    expect(await decide(mr, refused, true)).toEqual({
      outcome: 'not_available',
      text: NOT_A_MEMBER,
    });
    expect(await decide(mr, asked, false)).toEqual({
      outcome: 'review_requested',
      text: requested(HEAD),
    });
    // The run is the member's, once.
    expect(await runsOfBranch(mr.branchId)).toHaveLength(1);
    expect(await runOf(mr.analysisId)).toMatchObject({ status: 'waiting', requestedBy: 'octocat' });
  });

  it('each command note gets one answer: a row that was decided is not decided again', async () => {
    const mr = await mergeRequest();
    await settle(mr, {
      status: 'failed',
      reason: 'internal',
      headSha: HEAD,
      startedAt: new Date(),
    });
    const row = await command(mr, 'review');
    const decided = await decide(mr, row);
    expect(decided).toEqual({ outcome: 'review_requested', text: requested(HEAD) });
    const run = await runOf(mr.analysisId);
    // A retry of the job finds the decision on the row: not the "in progress" of the run its first
    // try restarted, and no second restart.
    expect(await decide(mr, await rowById(row.id))).toEqual(decided);
    expect(await decide(mr, row)).toEqual(decided);
    expect(await runOf(mr.analysisId)).toEqual(run);
    expect(await reviewJobs(run.id)).toEqual([{ due: true }]);
    expect(await decorations(mr.analysisId)).toHaveLength(1);
    expect(await rowById(row.id)).toMatchObject({
      outcome: 'review_requested',
      answer: requested(HEAD),
    });
  });

  it('names the commit of the run, else of the analysis’ snapshot, else of the analysis', async () => {
    // The run holds its head.
    const ofRun = await mergeRequest();
    await settle(ofRun, { status: 'skipped', reason: 'draft', headSha: RUN_HEAD });
    expect((await decide(ofRun, await command(ofRun, 'review'))).text).toBe(requested(RUN_HEAD));
    // No head on the run (it never started): the snapshot's.
    const ofSnapshot = await mergeRequest();
    await snapshot(ofSnapshot);
    await settle(ofSnapshot, { status: 'skipped', reason: 'no_snapshot' });
    expect((await decide(ofSnapshot, await command(ofSnapshot, 'review'))).text).toBe(
      requested(HEAD),
    );
    // No snapshot either: the commit the analysis was made of.
    const ofAnalysis = await mergeRequest();
    await settle(ofAnalysis, { status: 'skipped', reason: 'no_snapshot' });
    expect((await decide(ofAnalysis, await command(ofAnalysis, 'review'))).text).toBe(
      requested(REVISION),
    );
    // The same for a reviewed commit.
    const reviewedOne = await mergeRequest();
    await settle(reviewedOne, { status: 'done', headSha: RUN_HEAD });
    expect((await decide(reviewedOne, await command(reviewedOne, 'review'))).text).toBe(
      reviewed(RUN_HEAD),
    );
  });

  it('makes the run of the newest analysis when it has none, and supersedes the older run', async () => {
    const mr = await mergeRequest();
    const older = await runOf(mr.analysisId);
    // A newer analysis that came while AI review was off: it has no run.
    await reviewOff(h);
    const newer = await ingest(mr.project, mr.gitlabId, '2'.repeat(40), 2);
    await reviewOn(h, llm);
    expect(
      await h.ctx.db.select().from(reviewRuns).where(eq(reviewRuns.analysisId, newer)),
    ).toEqual([]);
    const row = await command(mr, 'review', 'octocat');
    expect(await decide(mr, row)).toEqual({
      outcome: 'review_requested',
      text: requested('2'.repeat(40)),
    });
    const run = await runOf(newer);
    expect(run).toMatchObject({
      branchId: mr.branchId,
      status: 'waiting',
      requestedBy: 'octocat',
    });
    expect(await reviewJobs(run.id)).toEqual([{ due: true }]);
    expect(await decorations(newer)).toHaveLength(1);
    expect(await runOf(mr.analysisId)).toMatchObject({ id: older.id, status: 'superseded' });
    expect(await reviewJobs(older.id)).toEqual([]);
  });

  it('a branch with no newest analysis has nothing to review: no answer is stored', async () => {
    const mr = await mergeRequest();
    await h.ctx.db
      .update(branches)
      .set({ lastAnalysisId: null })
      .where(eq(branches.id, mr.branchId));
    const before = await runOf(mr.analysisId);
    const row = await command(mr, 'review');
    await expect(decide(mr, row)).rejects.toBeInstanceOf(NothingToReview);
    expect(await rowById(row.id)).toMatchObject({ answer: null, outcome: null });
    expect(await runOf(mr.analysisId)).toEqual(before);
  });

  it('two commands decided at once restart the run once', async () => {
    const mr = await mergeRequest();
    await settle(mr, { status: 'skipped', reason: 'draft', headSha: HEAD, startedAt: new Date() });
    const rows = [await command(mr, 'review', 'octocat'), await command(mr, 'review', 'hubot')];
    const decided = await Promise.all(rows.map((row) => decide(mr, row)));
    expect(decided.map((d) => d.outcome).sort()).toEqual(['in_progress', 'review_requested']);
    const run = await runOf(mr.analysisId);
    expect(await runsOfBranch(mr.branchId)).toHaveLength(1);
    expect(await reviewJobs(run.id)).toEqual([{ due: true }]);
    expect(await decorations(mr.analysisId)).toHaveLength(1);
    // Whoever came first asked for the run.
    const winner = decided.findIndex((d) => d.outcome === 'review_requested');
    expect(run.requestedBy).toBe(rows[winner]!.author);
  });

  it.each([
    [
      'the branch’s decoration lock alone, as an ingestion holds it before it reaches the run',
      { branchLock: true, runRow: false },
    ],
    [
      'the branch’s lock and the run’s row, as a review job’s decision holds them',
      { branchLock: true, runRow: true },
    ],
    ['the run’s row alone, as a snapshot’s wake holds it', { branchLock: false, runRow: true }],
  ] as const)('waits for %s, and decides on what its holder left', async (_holder, holds) => {
    const mr = await mergeRequest();
    const row = await command(mr, 'review');
    let release!: () => void;
    const held = new Promise<void>((resolve) => (release = resolve));
    let locked!: () => void;
    const taken = new Promise<void>((resolve) => (locked = resolve));
    // A review that ends while the command waits.
    const holder = h.ctx.db.transaction(async (tx) => {
      if (holds.branchLock) await lockBranchQueue(tx, mr.branchId);
      if (holds.runRow) {
        await tx
          .select()
          .from(reviewRuns)
          .where(eq(reviewRuns.analysisId, mr.analysisId))
          .for('update');
      }
      locked();
      await held;
      await tx
        .update(reviewRuns)
        .set({ status: 'done', headSha: HEAD, startedAt: new Date(), finishedAt: new Date() })
        .where(eq(reviewRuns.analysisId, mr.analysisId));
    });
    await taken;
    let decided = false;
    const deciding = decide(mr, row).then((answer) => {
      decided = true;
      return answer;
    });
    try {
      await new Promise((resolve) => setTimeout(resolve, 300));
      expect(decided).toBe(false);
    } finally {
      release();
    }
    await holder;
    // It saw the run done, not waiting: reviewed, and no restart.
    expect(await deciding).toEqual({ outcome: 'already_reviewed', text: reviewed(HEAD) });
    expect(await runsOfBranch(mr.branchId)).toHaveLength(1);
  });

  it('two commands decided at once for an analysis with no run make its run once', async () => {
    const mr = await mergeRequest();
    await withoutRun(mr);
    const rows = [await command(mr, 'review', 'octocat'), await command(mr, 'review', 'hubot')];
    // Both find no run: the second must wait for the first to make it, not make a second one (an
    // analysis has one run, which its unique key would refuse).
    const decided = await Promise.all(rows.map((row) => decide(mr, row)));
    expect(decided.map((d) => d.outcome).sort()).toEqual(['in_progress', 'review_requested']);
    const made = await runOf(mr.analysisId);
    expect(await runsOfBranch(mr.branchId)).toHaveLength(1);
    expect(await reviewJobs(made.id)).toEqual([{ due: true }]);
    expect(await decorations(mr.analysisId)).toHaveLength(1);
    const winner = decided.findIndex((d) => d.outcome === 'review_requested');
    expect(made.requestedBy).toBe(rows[winner]!.author);
  });

  it('answers in Qualor’s own words: no author name and no other text is in it', async () => {
    const mr = await mergeRequest();
    const author = '@all <b>x</b> `y` [z](https://evil.example)';
    const texts: string[] = [];
    const answer = async (which: ReplyCommand, mayReview = true) => {
      const decided = await decide(mr, await command(mr, which, author), mayReview);
      texts.push(decided.text);
    };
    await answer('fix');
    await answer('stop');
    await answer('review', false);
    await reviewOff(h);
    await answer('review');
    await reviewOn(h, llm);
    await settle(mr, { status: 'done', headSha: HEAD, startedAt: new Date() });
    await answer('review');
    await settle(mr, { status: 'failed', reason: 'internal', startedAt: new Date() });
    await answer('review');
    await answer('review');
    expect(texts).toHaveLength(7);
    for (const text of texts) {
      expect(text).not.toContain('evil');
      expect(text).not.toContain('@all');
      expect(text).not.toContain(author);
      // Fixed words, and a commit in a code span.
      expect(outsideCodeSpans(text), text).toMatch(FIXED_TEXT);
    }
    // The author is the run's, as who asked.
    expect((await runOf(mr.analysisId)).requestedBy).toBe(author);
  });

  it('is no command of a reply row', async () => {
    const mr = await mergeRequest();
    const [id] = await insertReplies(h.ctx.db, [
      {
        projectId: mr.project.id,
        branchId: mr.branchId,
        provider: 'gitlab',
        noteId: 9_999,
        threadId: 'abcdef0123',
        kind: 'reply',
        author: 'octocat',
      },
    ]);
    const row = await claimReply(h.ctx.db, id!);
    await expect(decide(mr, row!)).rejects.toThrow('no command');
  });
});
