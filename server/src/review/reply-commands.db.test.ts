import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import type { FakeAzureDevOps } from '../../test/fake-azure-devops';
import type { FakeGitHub } from '../../test/fake-github';
import type { FakeGitLab } from '../../test/fake-gitlab';
import type { FakeLlm } from '../../test/fake-llm';
import { githubDeps } from '../../test/github';
import type { IngestHarness } from '../../test/ingest';
import { reviewOff, reviewOn } from '../../test/replies';
import {
  azureNote,
  createReplyHarness,
  HEAD,
  INSIDERS,
  OUTSIDERS,
  type AzureMr,
  type Person,
} from '../../test/reply-drivers';
import { reviewResponder, switchReviewOn } from '../../test/review';
import type { reviewRuns } from '../db/schema';
import { branches, jobs, llmRequests, reviewReplies } from '../db/schema';
import { enqueue } from '../queue/queue';
import { codeSpan, firstLineOf, markerOf, replyMarker } from '../scm/markdown';
import { SCM_CIRCUIT_FAILURES } from '../scm/runtime';
import { commandNote } from './render';
import { AI_REPLY_QUEUE, reconcileStuckReplies, replyKey } from './reply-queue';
import { AI_REVIEW_QUEUE } from './runs';

/*
 * The commands of the answer job (6I-4): a person's `qualor review`, `qualor fix` or `qualor stop`
 * on a GitLab merge request or a GitHub pull request is a row of the replies' ledger, which the job
 * answers with a fixed text beside the command's note, and, for `qualor review`, a run it makes or
 * restarts. The drivers of the two providers and the harness are in test/reply-drivers.ts, shared
 * with the answers' tests (reply-job.db.test.ts) and the scan's (reply-scan.db.test.ts). On an
 * Azure DevOps pull request (Azure sub-plan 5) a command is the first comment of a thread a person
 * opened, and its answer a reply to it in that thread.
 */

/** A request that asks for someone's rights, on either provider. */
const RIGHTS_LOOKUP = /\/members\/all\/|\/collaborators\/[^/]+\/permission/;

/** What Qualor answers to a command: fixed texts, with a commit in a code span. */
const REVIEW_OFF = 'AI review is not switched on for this project.';
const NOT_AVAILABLE = 'Auto-fix is not switched on for this project.';
const NOT_A_MEMBER = 'Only project members can ask for an AI review.';
const RIGHTS_UNREADABLE =
  'Qualor could not check your rights: its Azure DevOps credential cannot read identities and permissions (a personal access token needs the Identity (Read) scope).';
const IN_PROGRESS = 'A review of this commit is in progress.';
const requested = (sha: string) => `Reviewing this commit (${codeSpan(sha.slice(0, 12))}).`;
/** The review of HEAD ended without its findings: a command restarts it. */
const FAILED = { status: 'failed', reason: 'provider_error', summary: null } as const;
/** The post of an answer to a command: GitLab's reply in its discussion, GitHub's comment on the page. */
const POST_OF_COMMAND = /^POST .*\/(discussions\/[0-9a-f]+\/notes|issues\/7\/comments)$/;

describe('the answer job (6I-4)', () => {
  const harness = createReplyHarness();
  const {
    gitlabDriver,
    githubDriver,
    rowById,
    jobsOf,
    callsSince,
    answer,
    withUnreadableToken,
    retryNow,
    reviews,
    runOf,
    runsOfBranch,
    reviewJobsOf,
    endRun,
    commandRows,
    commandRow,
    queuedDecorations,
  } = harness;
  // The app and the fakes, once the harness has started them.
  let h: IngestHarness;
  let gitlab: FakeGitLab;
  let github: FakeGitHub;
  let llm: FakeLlm;
  let azure: FakeAzureDevOps;

  beforeAll(async () => {
    ({ h, gitlab, github, llm, azure } = await harness.start());
  });
  afterAll(async () => {
    await harness.close();
  });

  describe.each([
    ['GitLab', () => gitlabDriver],
    ['GitHub', () => githubDriver],
  ] as const)('on %s', (provider, driverOf) => {
    const slug = provider.toLowerCase();

    describe('the commands', () => {
      // A command restarts a run, whose review job stays queued: the reviews a case runs are its own.
      beforeEach(async () => {
        await h.ctx.db.delete(jobs).where(eq(jobs.queue, AI_REVIEW_QUEUE));
      });

      /**
       * A merge request whose review of HEAD ended as `end` says (the seeded one is done), and a
       * command written on it (`qualor review` unless `body` says) by a member (unless `who` says
       * otherwise), queued by a decoration.
       */
      const commanded = async (
        key: string,
        o: { end?: Partial<typeof reviewRuns.$inferInsert>; body?: string; who?: Person } = {},
      ) => {
        const d = driverOf();
        const mr = await d.setup(`${slug}-command-${key}`);
        await reviewOn(h, llm);
        if (o.end !== undefined) await endRun(mr.analysisId, o.end);
        const sent = mr.command(o.body ?? 'qualor review', o.who);
        await mr.decorate();
        const row = await commandRow(mr.branchId, sent.noteId);
        expect(row).toMatchObject({
          kind: 'command',
          status: 'queued',
          threadId: sent.threadId,
          author: mr.username(o.who ?? 'member'),
        });
        return { d, mr, sent, row };
      };

      it('a command row whose project is not its merge request’s has no merge request: it ends failed: internal, with nothing asked, no run and no answer', async () => {
        const { d, mr, row } = await commanded('foreign-project', { end: FAILED });
        const before = await runOf(mr.analysisId);
        const other = await driverOf().setup(`${slug}-command-foreign-project-other`);
        await h.ctx.db
          .update(reviewReplies)
          .set({ projectId: other.project.id })
          .where(eq(reviewReplies.id, row.id));
        await reviewOn(h, llm);
        d.clearRequests();
        await answer();
        expect(await rowById(row.id)).toMatchObject({ status: 'failed', reason: 'internal' });
        expect(d.requests()).toEqual([]);
        expect(mr.commandAnswers()).toEqual([]);
        expect(await runOf(mr.analysisId)).toEqual(before);
      });

      it('a connection that cannot be made ends the command’s row failed: internal, with no run and no answer', async () => {
        const { d, mr, sent, row } = await commanded('unusable', { end: FAILED });
        const before = await runOf(mr.analysisId);
        d.clearRequests();
        await withUnreadableToken(mr.connectionId, async () => void (await answer()));
        expect(await rowById(row.id)).toMatchObject({ status: 'failed', reason: 'internal' });
        expect(d.requests()).toEqual([]);
        expect(mr.commandAnswers()).toEqual([]);
        expect(await runOf(mr.analysisId)).toEqual(before);
        expect(sent.noteId).toBe(row.noteId);
      });

      it('qualor review on a draft reviews it', async () => {
        const { mr, sent } = await commanded('draft', {
          end: { status: 'skipped', reason: 'draft', summary: null },
        });
        mr.setDraft(true);
        expect(await answer()).toBe(1);
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'done',
          outcome: 'review_requested',
        });
        // The same run waits again, asked for by the person who wrote the note.
        const asker = mr.username('member');
        expect(await runOf(mr.analysisId)).toMatchObject({ status: 'waiting', requestedBy: asker });
        // The review worker then reviews the draft: a lite review, two reviewers and the judge.
        const calls = llm.requests.length;
        llm.enqueue(reviewResponder(), reviewResponder(), reviewResponder());
        expect(await reviews()).toBe(1);
        expect(await runOf(mr.analysisId)).toMatchObject({
          status: 'done',
          reason: null,
          requestedBy: asker,
          headSha: HEAD,
        });
        expect(callsSince(calls)).toHaveLength(3);
      });

      it('each command note gets one answer, and a decoration or a second job of a note adds none', async () => {
        const { d, mr, sent, row: firstRow } = await commanded('one-each', { end: FAILED });
        mr.command('qualor fix');
        mr.command('Qualor  STOP please');
        mr.command('qualor review');
        await mr.decorate();
        expect(await commandRows(mr.branchId)).toHaveLength(4);
        d.clearRequests();
        const calls = llm.requests.length;
        expect(await answer()).toBe(4);
        // A command makes no model call.
        expect(callsSince(calls)).toEqual([]);
        const rows = await commandRows(mr.branchId);
        expect(rows.map((r) => [r.command, r.status, r.outcome])).toEqual([
          ['review', 'done', 'review_requested'],
          ['fix', 'done', 'not_available'],
          ['stop', 'done', 'not_available'],
          // The first note restarted the run: the second finds it waiting.
          ['review', 'done', 'in_progress'],
        ]);
        expect(rows.map((r) => r.answer)).toEqual([
          requested(HEAD),
          NOT_AVAILABLE,
          NOT_AVAILABLE,
          IN_PROGRESS,
        ]);
        // One answer for each, with its row's marker, and its id on the row.
        const answers = mr.commandAnswers();
        expect(answers.map((a) => a.body)).toEqual(rows.map((r) => commandNote(r.id, r.answer!)));
        expect(rows.map((r) => r.answerNoteId)).toEqual(answers.map((a) => a.id));
        expect(d.requests().filter((r) => POST_OF_COMMAND.test(r))).toHaveLength(4);
        // The run was restarted once.
        const run = await runOf(mr.analysisId);
        expect(run).toMatchObject({ status: 'waiting', requestedBy: mr.username('member') });
        expect(await reviewJobsOf(run.id)).toEqual([{ due: true }]);

        // Another decoration finds the notes held: no new row, no new answer. Its listing holds
        // Qualor's own answers, which are no commands.
        await mr.decorate();
        expect(await commandRows(mr.branchId)).toEqual(rows);
        expect(await answer()).toBe(0);
        // A second job for a note that was answered finds it done, and answers nothing.
        await enqueue(h.ctx.db, {
          queue: AI_REPLY_QUEUE,
          payload: { kind: 'answer', replyId: firstRow.id },
          concurrencyKey: replyKey(mr.branchId),
          maxAttempts: 2,
        });
        expect(await answer()).toBe(1);
        expect(mr.commandAnswers()).toEqual(answers);
        expect(await commandRow(mr.branchId, sent.noteId)).toEqual(rows[0]);
        expect(await runOf(mr.analysisId)).toEqual(run);
      });

      it('a GitLab answer goes into the command’s discussion, and a GitHub answer is an issue comment, each with its marker', async () => {
        const { d, mr, sent, row } = await commanded('where', { end: FAILED });
        d.clearRequests();
        await answer();
        const answers = mr.commandAnswers();
        expect(answers).toHaveLength(1);
        const [posted] = answers;
        expect(posted).toMatchObject({
          body: commandNote(row.id, requested(HEAD)),
          // On GitLab the discussion the person's note opened; on GitHub the page, no thread.
          threadId: sent.threadId,
        });
        expect(firstLineOf(posted!.body)).toBe(replyMarker(row.id));
        expect(markerOf(posted!.body)).toBeNull();
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'done',
          outcome: 'review_requested',
          reason: null,
          answer: requested(HEAD),
          answerNoteId: posted!.id,
          model: null,
          finishedAt: expect.any(Date),
        });
        const posts = d.requests().filter((r) => r.startsWith('POST') && !r.includes('graphql'));
        expect(posts.filter((r) => POST_OF_COMMAND.test(r))).toHaveLength(1);
        if (provider === 'GitLab') {
          expect(posts.join('\n')).toContain(`/discussions/${sent.threadId}/notes`);
        } else {
          expect(posts.join('\n')).toMatch(/\/issues\/7\/comments/);
        }
        // The job is done with it.
        expect((await jobsOf(row.id)).map((j) => j.status)).toEqual(['succeeded']);
      });

      it('a retry after the restart but before the post answers what the first try decided, posts once and restarts nothing more', async () => {
        const { d, mr, sent } = await commanded('retry-before-post', { end: FAILED });
        mr.failNextPost(false, 'command');
        d.clearRequests();
        await answer();
        // The first try asked for the author's rights, once.
        expect(d.requests().filter((r) => RIGHTS_LOOKUP.test(r))).toHaveLength(1);
        // The decision is on the row and the run waits again; nothing was posted.
        const row = await commandRow(mr.branchId, sent.noteId);
        expect(row).toMatchObject({
          status: 'running',
          outcome: 'review_requested',
          answer: requested(HEAD),
          answerNoteId: null,
        });
        const restarted = await runOf(mr.analysisId);
        expect(restarted).toMatchObject({ status: 'waiting', requestedBy: mr.username('member') });
        expect(mr.commandAnswers()).toEqual([]);

        d.clearRequests();
        await retryNow();
        expect(await answer()).toBe(1);
        // The decision has the rights in it: the retry asks for them no more.
        expect(d.requests().filter((r) => RIGHTS_LOOKUP.test(r))).toEqual([]);
        // "Reviewing", not the "in progress" of the run the first try restarted.
        const answers = mr.commandAnswers();
        expect(answers.map((a) => a.body)).toEqual([commandNote(row.id, requested(HEAD))]);
        expect(d.requests().filter((r) => POST_OF_COMMAND.test(r))).toHaveLength(1);
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'done',
          outcome: 'review_requested',
          answerNoteId: answers[0]!.id,
        });
        expect(await runOf(mr.analysisId)).toEqual(restarted);
        expect(await reviewJobsOf(restarted.id)).toEqual([{ due: true }]);
      });

      it('a command that waited longer than the reply window ends skipped: expired, with no run touched and nothing posted', async () => {
        const { d, mr, sent } = await commanded('expired', { end: FAILED });
        const before = await runOf(mr.analysisId);
        await h.ctx.db
          .update(reviewReplies)
          .set({ createdAt: sql`now() - interval '31 days'` })
          .where(
            and(eq(reviewReplies.branchId, mr.branchId), eq(reviewReplies.noteId, sent.noteId)),
          );
        d.clearRequests();
        await answer();
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'skipped',
          reason: 'expired',
          outcome: null,
          answer: null,
        });
        expect(d.requests()).toEqual([]);
        expect(await runOf(mr.analysisId)).toEqual(before);
        expect(mr.commandAnswers()).toEqual([]);
      });

      it('a command that restarted the run and whose post fails on both tries keeps its outcome when the sweep ends it', async () => {
        const { mr, sent } = await commanded('swept-after-decision', { end: FAILED });
        mr.failNextPost(false, 'command');
        await answer();
        mr.failNextPost(false, 'command');
        await retryNow();
        await answer();
        const row = await commandRow(mr.branchId, sent.noteId);
        expect((await jobsOf(row.id)).map((j) => j.status)).toEqual(['dead']);
        expect(await reconcileStuckReplies(h.ctx.db)).toEqual([
          { replyId: row.id, outcome: 'review_requested' },
        ]);
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'failed',
          reason: 'internal',
          outcome: 'review_requested',
          answerNoteId: null,
        });
        expect(mr.commandAnswers()).toEqual([]);
      });

      it('a post whose answer is lost but which the provider stored: the retry finds the marker and posts nothing', async () => {
        const { d, mr, sent } = await commanded('lost-post', { end: FAILED });
        mr.failNextPost(true, 'command');
        await answer();
        const stored = mr.commandAnswers();
        expect(stored).toHaveLength(1);
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'running',
          answerNoteId: null,
        });
        d.clearRequests();
        await retryNow();
        await answer();
        expect(d.requests().filter((r) => POST_OF_COMMAND.test(r))).toEqual([]);
        expect(mr.commandAnswers()).toEqual(stored);
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'done',
          outcome: 'review_requested',
          answerNoteId: stored[0]!.id,
        });
      });

      it('a note of a person that forges the answer’s marker is no answer: Qualor posts its own', async () => {
        const { mr, sent, row } = await commanded('forged-marker', { end: FAILED });
        mr.writeBeside(sent, `${replyMarker(row.id)}\n**AI review** · reply\n\nDone.`);
        await answer();
        expect(mr.commandAnswers().map((a) => a.body)).toEqual([
          commandNote(row.id, requested(HEAD)),
        ]);
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'done',
          answerNoteId: mr.commandAnswers()[0]!.id,
        });
      });

      // On GitLab: no membership at all, a Reporter and a Guest. On GitHub: no permission (a 404),
      // the read role and a custom role on read.
      it.each(OUTSIDERS)(
        'qualor review from %s is refused with a fixed text: one request for the rights, and no run is made or restarted',
        async (who) => {
          const { d, mr, sent, row } = await commanded(`refused-${who}`, { end: FAILED, who });
          const before = await runOf(mr.analysisId);
          d.clearRequests();
          expect(await answer()).toBe(1);
          expect(d.requests().filter((r) => RIGHTS_LOOKUP.test(r))).toHaveLength(1);
          const answers = mr.commandAnswers();
          expect(answers.map((a) => a.body)).toEqual([commandNote(row.id, NOT_A_MEMBER)]);
          expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
            status: 'done',
            outcome: 'not_available',
            reason: null,
            answer: NOT_A_MEMBER,
            answerNoteId: answers[0]!.id,
          });
          // The run is as it was: not restarted, no job, no decoration.
          expect(await runOf(mr.analysisId)).toEqual(before);
          expect(before.status).toBe('failed');
          expect(await reviewJobsOf(before.id)).toEqual([]);
          expect(await queuedDecorations(mr.analysisId)).toEqual([]);
        },
      );

      it('qualor review from someone with the rights restarts the run, whatever their role: the first of five asks, one request each', async () => {
        const { d, mr } = await commanded('insiders', { end: FAILED, who: INSIDERS[0] });
        for (const who of INSIDERS.slice(1)) mr.command('qualor review', who);
        await mr.decorate();
        d.clearRequests();
        await answer();
        // None is refused: the first restarted the run, the others find it waiting.
        const rows = await commandRows(mr.branchId);
        expect(rows.map((r) => [r.author, r.status, r.outcome])).toEqual([
          [mr.username('member'), 'done', 'review_requested'],
          ...INSIDERS.slice(1).map((who) => [mr.username(who), 'done', 'in_progress']),
        ]);
        expect(d.requests().filter((r) => RIGHTS_LOOKUP.test(r))).toHaveLength(INSIDERS.length);
        expect(await runOf(mr.analysisId)).toMatchObject({
          status: 'waiting',
          requestedBy: mr.username('member'),
        });
        expect(await runsOfBranch(mr.branchId)).toHaveLength(1);
      });

      it('qualor fix and qualor stop from someone without the rights still get the auto-fix answer, and ask for no rights', async () => {
        const { d, mr } = await commanded('fix-stop-outsider', {
          body: 'qualor fix',
          who: 'outsider',
        });
        mr.command('qualor stop', 'outsider');
        await mr.decorate();
        d.clearRequests();
        await answer();
        const rows = await commandRows(mr.branchId);
        expect(rows.map((r) => [r.command, r.status, r.outcome, r.answer])).toEqual([
          ['fix', 'done', 'not_available', NOT_AVAILABLE],
          ['stop', 'done', 'not_available', NOT_AVAILABLE],
        ]);
        expect(mr.commandAnswers().map((a) => a.body)).toEqual(
          rows.map((r) => commandNote(r.id, NOT_AVAILABLE)),
        );
        expect(d.requests().filter((r) => RIGHTS_LOOKUP.test(r))).toEqual([]);
      });

      it.skipIf(provider === 'GitHub')(
        'a GitLab command whose note was deleted from a discussion that a reply keeps ends the row skipped: thread_gone, with no rights asked for and nothing posted',
        async () => {
          const { d, mr, sent } = await commanded('note-gone-reply-stays', { end: FAILED });
          const before = await runOf(mr.analysisId);
          // Someone replied to the command in its discussion, and then the command's note was
          // deleted: the discussion is listed, with the reply and without the note.
          mr.writeBeside(sent, 'Thanks, I will have a look.');
          mr.deleteNote(sent.threadId!, sent.noteId);
          d.clearRequests();
          await answer();
          expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
            status: 'skipped',
            reason: 'thread_gone',
            outcome: null,
            answer: null,
            finishedAt: expect.any(Date),
          });
          expect(await runOf(mr.analysisId)).toEqual(before);
          expect(d.requests().filter((r) => RIGHTS_LOOKUP.test(r))).toEqual([]);
          expect(d.requests().filter((r) => POST_OF_COMMAND.test(r))).toEqual([]);
          expect(mr.commandAnswers()).toEqual([]);
        },
      );

      it.skipIf(provider === 'GitLab')(
        'qualor review from a login GitHub could not have is refused, and no request is made for it',
        async () => {
          const { d, mr, sent, row } = await commanded('refused-login', {
            end: FAILED,
            who: 'refused',
          });
          const before = await runOf(mr.analysisId);
          d.clearRequests();
          await answer();
          expect(d.requests().filter((r) => RIGHTS_LOOKUP.test(r))).toEqual([]);
          expect(mr.commandAnswers().map((a) => a.body)).toEqual([
            commandNote(row.id, NOT_A_MEMBER),
          ]);
          expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
            status: 'done',
            outcome: 'not_available',
          });
          expect(await runOf(mr.analysisId)).toEqual(before);
        },
      );

      it.skipIf(provider === 'GitLab')(
        'a permission answer of GitHub that does not parse gives no rights: the command is refused, with one line that holds no text of the answer',
        async () => {
          const { mr, sent, row } = await commanded('odd-permission', { end: FAILED });
          const before = await runOf(mr.analysisId);
          github.inject('GET', /\/collaborators\/octocat\/permission$/, {
            status: 200,
            body: { role_name: 'write' },
          });
          const warned: unknown[][] = [];
          const logger = {
            info: () => undefined,
            warn: (...args: unknown[]) => void warned.push(args),
            error: () => undefined,
          };
          await answer({ logger });
          expect(mr.commandAnswers().map((a) => a.body)).toEqual([
            commandNote(row.id, NOT_A_MEMBER),
          ]);
          expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
            status: 'done',
            outcome: 'not_available',
          });
          expect(await runOf(mr.analysisId)).toEqual(before);
          expect(warned.filter(([, message]) => String(message).includes('permission'))).toEqual([
            [
              { replyId: row.id },
              'GitHub permission answer not understood; the command is refused',
            ],
          ]);
        },
      );

      it.skipIf(provider === 'GitHub')(
        'a members answer of GitLab that does not parse gives no rights: the command is refused, with one line that holds no text of the answer',
        async () => {
          const { mr, sent, row } = await commanded('odd-membership', { end: FAILED });
          const before = await runOf(mr.analysisId);
          gitlab.inject('GET', /\/members\/all\/\d+$/, { status: 200, body: { id: 5 } });
          const warned: unknown[][] = [];
          const logger = {
            info: () => undefined,
            warn: (...args: unknown[]) => void warned.push(args),
            error: () => undefined,
          };
          await answer({ logger });
          expect(mr.commandAnswers().map((a) => a.body)).toEqual([
            commandNote(row.id, NOT_A_MEMBER),
          ]);
          expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
            status: 'done',
            outcome: 'not_available',
          });
          expect(await runOf(mr.analysisId)).toEqual(before);
          expect(warned.filter(([, message]) => String(message).includes('membership'))).toEqual([
            [
              { replyId: row.id },
              'GitLab membership answer not understood; the command is refused',
            ],
          ]);
        },
      );

      it('a closed merge request ends the row skipped: closed, with no answer and no run', async () => {
        const { d, mr, sent } = await commanded('closed', { end: FAILED });
        const before = await runOf(mr.analysisId);
        mr.close();
        d.clearRequests();
        await answer();
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'skipped',
          reason: 'closed',
          outcome: null,
          answer: null,
          finishedAt: expect.any(Date),
        });
        expect(mr.commandAnswers()).toEqual([]);
        expect(d.requests().filter((r) => POST_OF_COMMAND.test(r))).toEqual([]);
        expect(await runOf(mr.analysisId)).toEqual(before);
      });

      it('a row that has its answer note ends done with its outcome and makes no request, whatever became of the merge request since', async () => {
        const { d, mr, sent, row } = await commanded('answered', { end: FAILED });
        await answer();
        const answered = await commandRow(mr.branchId, sent.noteId);
        expect(answered).toMatchObject({
          status: 'done',
          outcome: 'review_requested',
          answerNoteId: expect.any(Number),
        });
        const run = await runOf(mr.analysisId);
        // A job that was cut once it had recorded the answer note, before it ended the row: the row
        // is queued again, with a job; and the merge request has been closed since.
        await h.ctx.db
          .update(reviewReplies)
          .set({ status: 'queued', finishedAt: null })
          .where(eq(reviewReplies.id, row.id));
        await enqueue(h.ctx.db, {
          queue: AI_REPLY_QUEUE,
          payload: { kind: 'answer', replyId: row.id },
          concurrencyKey: replyKey(mr.branchId),
          maxAttempts: 2,
        });
        mr.close();
        d.clearRequests();
        expect(await answer()).toBe(1);
        expect(d.requests()).toEqual([]);
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'done',
          outcome: 'review_requested',
          reason: null,
          answerNoteId: answered.answerNoteId,
        });
        expect(mr.commandAnswers()).toHaveLength(1);
        expect(await runOf(mr.analysisId)).toEqual(run);
      });

      it('a command whose note was deleted ends the row skipped: thread_gone, with no rights asked for, no run made and no answer posted', async () => {
        const { d, mr, sent } = await commanded('note-gone', { end: FAILED });
        const before = await runOf(mr.analysisId);
        mr.deleteCommand(sent);
        d.clearRequests();
        await answer();
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'skipped',
          reason: 'thread_gone',
          outcome: null,
          answer: null,
          finishedAt: expect.any(Date),
        });
        expect(await runOf(mr.analysisId)).toEqual(before);
        expect(d.requests().filter((r) => RIGHTS_LOOKUP.test(r))).toEqual([]);
        expect(d.requests().filter((r) => POST_OF_COMMAND.test(r))).toEqual([]);
        expect(mr.commandAnswers()).toEqual([]);
      });

      it.skipIf(provider === 'GitHub')(
        'a GitLab discussion that is gone only when the answer is posted ends the row skipped: thread_gone, the run restarted',
        async () => {
          const { mr, sent } = await commanded('discussion-gone-at-post', { end: FAILED });
          mr.goneOnNextPost();
          await answer();
          expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
            status: 'skipped',
            reason: 'thread_gone',
            answerNoteId: null,
          });
          expect(await runOf(mr.analysisId)).toMatchObject({ status: 'waiting' });
        },
      );

      it('a branch with no newest analysis has nothing to review: the row ends failed: internal, with no answer', async () => {
        const { d, mr, sent, row } = await commanded('no-analysis', { end: FAILED });
        await h.ctx.db
          .update(branches)
          .set({ lastAnalysisId: null })
          .where(eq(branches.id, mr.branchId));
        d.clearRequests();
        await answer();
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'failed',
          reason: 'internal',
          outcome: null,
          answer: null,
          finishedAt: expect.any(Date),
        });
        expect(mr.commandAnswers()).toEqual([]);
        expect(d.requests().filter((r) => POST_OF_COMMAND.test(r))).toEqual([]);
        // Nothing to try again: the job is done with it.
        expect((await jobsOf(row.id)).map((j) => j.status)).toEqual(['succeeded']);
      });

      it('makes no model call and asks no budget: a day with no tokens left answers a command all the same', async () => {
        const { mr, sent } = await commanded('no-budget', { end: FAILED });
        await switchReviewOn(h.ctx.db, {
          secretKey: h.ctx.config.secretKey,
          fake: llm,
          organizationId: h.organizationId,
          userId: h.ctx.adminId,
          consentAt: new Date(Date.now() - 3_600_000),
          budgets: { tokensPerDay: 0 },
        });
        const calls = llm.requests.length;
        await answer();
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'done',
          outcome: 'review_requested',
          model: null,
          inputTokens: 0,
          outputTokens: 0,
        });
        expect(callsSince(calls)).toEqual([]);
        expect(
          await h.ctx.db
            .select()
            .from(llmRequests)
            .where(
              and(
                eq(llmRequests.feature, 'review-reply'),
                eq(llmRequests.projectId, mr.project.id),
              ),
            ),
        ).toEqual([]);
      });

      it('qualor review with AI review switched off meanwhile answers so, and the row ends done', async () => {
        const { mr, sent } = await commanded('review-off', { end: FAILED });
        const before = await runOf(mr.analysisId);
        await reviewOff(h);
        await answer();
        const row = await commandRow(mr.branchId, sent.noteId);
        expect(row).toMatchObject({
          status: 'done',
          outcome: 'review_off',
          reason: null,
          answer: REVIEW_OFF,
        });
        expect(mr.commandAnswers().map((a) => a.body)).toEqual([commandNote(row.id, REVIEW_OFF)]);
        expect(await runOf(mr.analysisId)).toEqual(before);
      });

      it('qualor fix and qualor stop are answered when AI review is off, as when it is on', async () => {
        const { mr } = await commanded('fix-stop', { body: 'qualor fix' });
        const stop = mr.command('qualor stop');
        await mr.decorate();
        await reviewOff(h);
        await answer();
        const rows = await commandRows(mr.branchId);
        expect(rows.map((r) => [r.command, r.status, r.outcome])).toEqual([
          ['fix', 'done', 'not_available'],
          ['stop', 'done', 'not_available'],
        ]);
        expect(mr.commandAnswers().map((a) => a.body)).toEqual(
          rows.map((r) => commandNote(r.id, NOT_AVAILABLE)),
        );
        expect(rows[1]!.noteId).toBe(stop.noteId);
      });

      it('waits while the connection’s circuit is open: the command is queued again with no try spent, and answered once when it has closed', async () => {
        const { d, mr, sent } = await commanded('circuit', { end: FAILED });
        const runtime = githubDeps(h).runtime;
        for (let n = 0; n < SCM_CIRCUIT_FAILURES; n += 1) runtime.circuit.failure(mr.connectionId);
        d.clearRequests();
        expect(await answer({ scmRuntime: runtime })).toBe(1);
        // Nothing is asked of the provider, and no run is made: the decision comes after the wait.
        expect(d.requests()).toEqual([]);
        const row = await commandRow(mr.branchId, sent.noteId);
        expect(row).toMatchObject({
          status: 'queued',
          answer: null,
          outcome: null,
          finishedAt: null,
        });
        expect(await runOf(mr.analysisId)).toMatchObject({ status: 'failed' });
        expect((await jobsOf(row.id)).map((j) => [j.status, j.attempts])).toEqual([
          ['succeeded', 1],
          ['queued', 0],
        ]);
        // Once the circuit has closed, the next job answers.
        runtime.circuit.success(mr.connectionId);
        await retryNow();
        await answer({ scmRuntime: runtime });
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'done',
          outcome: 'review_requested',
        });
        expect(mr.commandAnswers()).toHaveLength(1);
      });

      it('a circuit that is closed to the post: the decision is kept, nothing is posted, and the next job posts it without a second run', async () => {
        const { d, mr, sent } = await commanded('circuit-at-post', { end: FAILED });
        const runtime = githubDeps(h).runtime;
        // The first go (the merge request and the discussion) passes the circuit; the second, the
        // post, finds it closed to it.
        const tryPass = runtime.circuit.tryPass.bind(runtime.circuit);
        let goes = 0;
        vi.spyOn(runtime.circuit, 'tryPass').mockImplementation((id) =>
          goes++ === 0 ? tryPass(id) : false,
        );
        d.clearRequests();
        expect(await answer({ scmRuntime: runtime })).toBe(1);
        expect(d.requests().filter((r) => POST_OF_COMMAND.test(r))).toEqual([]);
        // The run was restarted and the decision is on the row, which waits in the queue.
        const row = await commandRow(mr.branchId, sent.noteId);
        expect(row).toMatchObject({
          status: 'queued',
          outcome: 'review_requested',
          answer: requested(HEAD),
          answerNoteId: null,
          finishedAt: null,
        });
        const restarted = await runOf(mr.analysisId);
        expect(restarted).toMatchObject({ status: 'waiting', requestedBy: mr.username('member') });
        expect(mr.commandAnswers()).toEqual([]);
        expect((await jobsOf(row.id)).map((j) => [j.status, j.attempts])).toEqual([
          ['succeeded', 1],
          ['queued', 0],
        ]);

        // The next job answers what was decided: "Reviewing", not "in progress", and no second run.
        await retryNow();
        expect(await answer()).toBe(1);
        expect(mr.commandAnswers().map((a) => a.body)).toEqual([
          commandNote(row.id, requested(HEAD)),
        ]);
        expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
          status: 'done',
          outcome: 'review_requested',
        });
        expect(await runOf(mr.analysisId)).toEqual(restarted);
        expect(await reviewJobsOf(restarted.id)).toEqual([{ due: true }]);
      });

      it('the restart queues a decoration: the summary then says the review is in progress, found beside the answer and updated in place', async () => {
        const { mr } = await commanded('summary', { end: FAILED });
        const [before, ...others] = mr.summaries();
        expect(others).toEqual([]);
        expect(before!.body).toContain('AI review failed');
        expect(await answer()).toBe(1);
        // The restart queued the decoration of the analysis; nothing ran it yet.
        expect(await queuedDecorations(mr.analysisId)).toHaveLength(1);
        const answered = mr.commandAnswers();
        expect(answered).toHaveLength(1);
        await mr.decorateQueued();
        // The summary is the same note, updated: the answer is not taken for it, and no second
        // summary is posted.
        expect(mr.summaries()).toEqual([
          { id: before!.id, body: expect.stringContaining('AI review in progress…') },
        ]);
        expect(mr.summaries()[0]!.body).not.toContain('AI review failed');
        // The answer is left as it was.
        expect(mr.commandAnswers()).toEqual(answered);
        expect(await queuedDecorations(mr.analysisId)).toEqual([]);
      });

      it('a decoration that finds no summary posts one, and does not take the command’s answer for it', async () => {
        const { mr } = await commanded('summary-lost', { end: FAILED });
        const [lost] = mr.summaries();
        expect(await answer()).toBe(1);
        const answered = mr.commandAnswers();
        expect(answered).toHaveLength(1);
        // Qualor's summary is deleted before the decoration runs: the answer is the only comment
        // that has a marker of Qualor's.
        mr.deleteSummaries();
        expect(mr.summaries()).toEqual([]);
        expect(await queuedDecorations(mr.analysisId)).toHaveLength(1);
        await mr.decorateQueued();
        // The answer is left as it was, and one new summary is posted.
        expect(mr.commandAnswers()).toEqual(answered);
        const [posted, ...others] = mr.summaries();
        expect(others).toEqual([]);
        expect(posted!.body).toContain('AI review in progress…');
        expect(posted!.id).not.toBe(lost!.id);
      });
    });
  });

  describe('the commands on Azure DevOps (Azure sub-plan 5)', () => {
    // A command restarts a run, whose review job stays queued: the reviews a case runs are its own.
    beforeEach(async () => {
      await h.ctx.db.delete(jobs).where(eq(jobs.queue, AI_REVIEW_QUEUE));
    });

    /**
     * A pull request whose review of HEAD ended as `end` says (the seeded one is done), and a
     * thread a person opened with a command (`qualor review` unless `body` says) by a member (a
     * contributor, unless `who` says otherwise), queued by a decoration.
     */
    const commanded = async (
      key: string,
      o: { end?: Partial<typeof reviewRuns.$inferInsert>; body?: string; who?: Person } = {},
    ) => {
      const mr = await harness.azureDriver.setup(`azure-command-${key}`);
      await reviewOn(h, llm);
      if (o.end !== undefined) await endRun(mr.analysisId, o.end);
      const sent = mr.command(o.body ?? 'qualor review', o.who);
      await mr.decorate();
      const row = await commandRow(mr.branchId, sent.noteId);
      expect(row).toMatchObject({
        provider: 'azure',
        kind: 'command',
        status: 'queued',
        threadId: sent.threadId,
        author: mr.username(o.who ?? 'member'),
      });
      return { mr, sent, row };
    };
    /** Qualor's one answer in the command's thread: a reply to the command's comment. */
    const answerIn = (mr: AzureMr, threadId: string) => {
      const answers = mr.commandAnswers().filter((a) => a.threadId === threadId);
      expect(answers).toHaveLength(1);
      const answered = mr
        .thread(threadId)
        .comments.find((c) => azureNote(Number(threadId), c.id) === answers[0]!.id);
      expect(answered?.parentCommentId).toBe(1);
      return answered!;
    };

    it('`qualor review` by a reader, or by someone Azure DevOps does not know, is refused: only project members may ask (review focus 3)', async () => {
      for (const who of ['reporter', 'refused'] as const) {
        const { mr, sent, row } = await commanded(`reader-${who}`, { end: FAILED, who });
        const before = await runOf(mr.analysisId);
        expect(await answer(), who).toBe(1);
        expect(await commandRow(mr.branchId, sent.noteId), who).toMatchObject({
          status: 'done',
          outcome: 'not_available',
          answer: NOT_A_MEMBER,
        });
        const answered = answerIn(mr, sent.threadId!);
        expect(answered.content, who).toBe(commandNote(row.id, NOT_A_MEMBER));
        // No run was made or restarted.
        expect(await runOf(mr.analysisId), who).toEqual(before);
      }
    });

    it("`qualor review` whose rights Qualor's own credential cannot read is answered so, not as a refusal of the author (check 1 of 2026-11-25)", async () => {
      const { mr, sent, row } = await commanded('rights-unreadable', { end: FAILED });
      const before = await runOf(mr.analysisId);
      // A personal access token without the scope: the identities host answers 401, no body.
      azure.inject('GET', /\/_apis\/identities$/, { status: 401 });
      expect(await answer()).toBe(1);
      expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
        status: 'done',
        outcome: 'not_available',
        answer: RIGHTS_UNREADABLE,
      });
      expect(answerIn(mr, sent.threadId!).content).toBe(commandNote(row.id, RIGHTS_UNREADABLE));
      expect(await runOf(mr.analysisId)).toEqual(before);
    });

    it('`qualor review` by a contributor asks for a review of the commit, answered in the command’s thread', async () => {
      const { mr, sent, row } = await commanded('contributor', { end: FAILED });
      expect(await answer()).toBe(1);
      const answered = answerIn(mr, sent.threadId!);
      expect(answered.content).toBe(commandNote(row.id, requested(HEAD)));
      expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
        status: 'done',
        outcome: 'review_requested',
        answer: requested(HEAD),
        answerNoteId: azureNote(Number(sent.threadId), answered.id),
      });
      // The run waits again, asked for by the person's display name, with its review job due.
      const run = await runOf(mr.analysisId);
      expect(run).toMatchObject({ status: 'waiting', requestedBy: mr.username('member') });
      expect(await reviewJobsOf(run.id)).toEqual([{ due: true }]);
      // A decoration after it finds the command held and Qualor's answer no command.
      await mr.decorate();
      expect(await commandRows(mr.branchId)).toHaveLength(1);
      expect(await answer()).toBe(0);
    });

    it('`qualor fix` and `qualor stop` are answered that auto-fix is not switched on, with no run', async () => {
      for (const body of ['qualor fix', 'qualor stop']) {
        const { mr, sent, row } = await commanded(body.replace(' ', '-'), { end: FAILED, body });
        const before = await runOf(mr.analysisId);
        expect(await answer(), body).toBe(1);
        expect(answerIn(mr, sent.threadId!).content, body).toBe(commandNote(row.id, NOT_AVAILABLE));
        expect(await commandRow(mr.branchId, sent.noteId), body).toMatchObject({
          status: 'done',
          outcome: 'not_available',
        });
        expect(await runOf(mr.analysisId), body).toEqual(before);
      }
    });

    it('a command whose comment was deleted ends the row skipped: thread_gone, with no answer', async () => {
      const { mr, sent } = await commanded('deleted', { end: FAILED });
      const before = await runOf(mr.analysisId);
      mr.deleteCommand(sent);
      await answer();
      expect(await commandRow(mr.branchId, sent.noteId)).toMatchObject({
        status: 'skipped',
        reason: 'thread_gone',
      });
      expect(mr.commandAnswers()).toEqual([]);
      expect(await runOf(mr.analysisId)).toEqual(before);
    });
  });
});
