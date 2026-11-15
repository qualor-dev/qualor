import { and, asc, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import type { FakeGitHub } from '../../test/fake-github';
import type { FakeLlm } from '../../test/fake-llm';
import { githubDeps } from '../../test/github';
import type { IngestHarness } from '../../test/ingest';
import { answerJob, queuedAnswers, reviewOff, reviewOn, reviewScope } from '../../test/replies';
import { createReplyHarness, HEAD, KEEP, type Driver } from '../../test/reply-drivers';
import { uuidv7 } from '../db/ids';
import { branches, issueChanges, issues, jobs, projects } from '../db/schema';
import { firstLineOf, markerOf, replyMarker } from '../scm/markdown';
import {
  CircuitBreaker,
  MAX_DECORATIONS_PER_ORGANIZATION,
  SCM_CIRCUIT_FAILURES,
  SCM_CIRCUIT_OPEN_MS,
} from '../scm/runtime';
import { AI_REPLY_QUEUE, queueScan, replyKey } from './reply-queue';

/*
 * The scan (6I-4): the `ai-reply` job a webhook queues for a merge request, which reads its notes
 * through the API with a client of its own and queues what it finds as a decoration queues the notes
 * it read (reply-scan.ts). On a GitLab merge request and on a GitHub pull request, through the shared
 * drivers (test/reply-drivers.ts): Qualor's thread, a person's reply and a person's command are
 * found, nothing is read of a merge request that is closed or whose project has no AI review, and a
 * merge request the provider no longer has, a provider that fails and a circuit that is closed to
 * the connection each end the job as they should.
 */

describe('the notes scan (a webhook’s job)', () => {
  const harness = createReplyHarness();
  const {
    gitlabDriver,
    githubDriver,
    aiFinding,
    callsSince,
    answer,
    withUnreadableToken,
    scan,
    retryNow,
  } = harness;
  // The app and the fakes, once the harness has started them.
  let h: IngestHarness;
  let github: FakeGitHub;
  let llm: FakeLlm;

  beforeAll(async () => {
    ({ h, github, llm } = await harness.start());
  });
  afterAll(async () => {
    await harness.close();
  });

  describe.each([
    ['GitLab', () => gitlabDriver],
    ['GitHub', () => githubDriver],
  ] as const)('on %s', (provider, driverOf) => {
    const slug = provider.toLowerCase();

    // A scan run alone leaves the answers it queued for the worker: each case starts with none.
    beforeEach(async () => {
      await h.ctx.db.delete(jobs).where(eq(jobs.queue, AI_REPLY_QUEUE));
    });

    /** A merge request with an open AI finding and Qualor's thread for it, and no reply yet. */
    const threaded = async (key: string) => {
      const d = driverOf();
      const mr = await d.setup(`${slug}-scan-${key}`);
      await reviewOn(h, llm);
      const issueId = await aiFinding(mr.branchId, 9);
      await mr.decorate();
      return { d, mr, issueId, threadId: mr.threadOf(issueId) };
    };
    /** What the scan queued for the branch: its rows and their jobs. */
    const queuedFor = (branchId: string) => queuedAnswers(h.ctx.db, branchId);
    /** The requests of the provider that are no reads (a token and a GraphQL query are POSTs). */
    const writesOf = (d: Driver) =>
      d.requests().filter((r) => !r.startsWith('GET ') && !/access_tokens|graphql/.test(r));
    /** GitHub's GraphQL requests whose text has `needle`: none on GitLab. */
    const graphqlWith = (needle: string) =>
      provider === 'GitHub' ? github.requests.filter((r) => r.body.includes(needle)) : [];
    /** The branch's `ai-reply` jobs, with their tries. */
    const scanJobs = (branchId: string) =>
      h.ctx.db
        .select()
        .from(jobs)
        .where(and(eq(jobs.queue, AI_REPLY_QUEUE), eq(jobs.concurrencyKey, replyKey(branchId))))
        .orderBy(asc(jobs.id));
    /** The paths of the requests the provider received, without their queries. */
    const pathsOf = (d: Driver) =>
      d.requests().map((r) => r.split('?')[0]!.replace(/\/projects\/\d+\//, '/projects/:id/'));
    /** A logger that keeps what it is told at each level. */
    const recording = () => {
      const said = { info: [] as unknown[][], warn: [] as unknown[][], error: [] as unknown[][] };
      const logger = {
        info: (...args: unknown[]) => void said.info.push(args),
        warn: (...args: unknown[]) => void said.warn.push(args),
        error: (...args: unknown[]) => void said.error.push(args),
      };
      return { said, logger };
    };

    it('queues the reply and the command it finds as a decoration would, and writes nothing to the provider', async () => {
      const { d, mr, issueId, threadId } = await threaded('found');
      const noteId = mr.reply(threadId, 'We accept this for now.');
      const sent = mr.command('qualor review');
      d.clearRequests();
      github.clearRequests();
      await scan(mr.branchId);
      const { rows, jobs: queued } = await queuedFor(mr.branchId);
      const reply = rows.find((r) => r.kind === 'reply')!;
      const command = rows.find((r) => r.kind === 'command')!;
      expect(rows).toHaveLength(2);
      expect(reply).toMatchObject({
        noteId,
        threadId,
        issueId,
        author: mr.username('member'),
        status: 'queued',
      });
      expect(command).toMatchObject({
        noteId: sent.noteId,
        threadId: sent.threadId,
        command: 'review',
        author: mr.username('member'),
        status: 'queued',
      });
      // The rounds' jobs come first and the commands' after, as a decoration queues them.
      expect(queued).toEqual([
        answerJob(mr.branchId, reply.id),
        answerJob(mr.branchId, command.id),
      ]);
      // It only read, and made no model call.
      expect(writesOf(d)).toEqual([]);
      expect(graphqlWith('mutation')).toEqual([]);
      const reads = pathsOf(d);
      if (provider === 'GitLab') {
        // The merge request's state, then who Qualor is, then the discussions: its own client's.
        expect(reads).toEqual([
          'GET /projects/:id/merge_requests/12',
          'GET /user',
          'GET /projects/:id/merge_requests/12/discussions',
        ]);
      } else {
        for (const wanted of [/\/pulls\/7$/, /\/pulls\/7\/comments$/, /\/issues\/7\/comments$/]) {
          expect(
            reads.filter((r) => wanted.test(r)),
            String(wanted),
          ).toHaveLength(1);
        }
        expect(graphqlWith('reviewThreads')).toHaveLength(1);
      }
    });

    it('through the queue the scan is done and its answers follow it; a second scan finds only Qualor’s own answers, which are no replies', async () => {
      const { mr, threadId } = await threaded('chain');
      mr.reply(threadId, 'Why is this a problem?');
      mr.command('qualor review');
      expect(await queueScan(h.ctx.db, mr.branchId)).toBe(true);
      llm.say(KEEP);
      expect(await answer()).toBe(3);
      const kinds = (await queuedFor(mr.branchId)).jobs.map((job) => [
        (job.payload as { kind: string }).kind,
        job.status,
      ]);
      expect(kinds).toEqual([
        ['scan', 'succeeded'],
        ['answer', 'succeeded'],
        ['answer', 'succeeded'],
      ]);
      expect(mr.answers(threadId)).toHaveLength(1);
      expect(mr.commandAnswers()).toHaveLength(1);
      // Scanned again, it finds the answers in the notes: nobody's replies, and nothing to queue.
      const { rows } = await queuedFor(mr.branchId);
      expect(await queueScan(h.ctx.db, mr.branchId)).toBe(true);
      expect(await answer()).toBe(1);
      expect((await queuedFor(mr.branchId)).rows).toEqual(rows);
      expect(mr.answers(threadId)).toHaveLength(1);
    });

    it('answers a reply that Qualor’s note of the fixed finding came after: the note is no answer, and no reply', async () => {
      const { mr, issueId, threadId } = await threaded('fixed-note');
      const noteId = mr.reply(threadId, 'Is this still a problem?');
      // A later review of the analysis finds it fixed. AI review is off when the decoration runs:
      // it writes its note in the thread the person keeps open, and queues no answer.
      await h.ctx.db
        .update(issues)
        .set({ status: 'closed', closedAt: sql`now()` })
        .where(eq(issues.id, issueId));
      await h.ctx.db.insert(issueChanges).values({
        issueId,
        analysisId: mr.analysisId,
        field: 'status',
        oldValue: 'open',
        newValue: 'closed',
      });
      await reviewOff(h);
      await mr.decorate();
      const notes = mr.answers(threadId);
      expect(notes).toHaveLength(1);
      expect(markerOf(notes[0]!.body)).toEqual({ kind: 'fixed', issueId, sha: HEAD });
      expect(mr.resolved(threadId)).toBe(false);
      expect((await queuedFor(mr.branchId)).rows).toEqual([]);
      // On again: the webhook's scan finds the person's reply unanswered, Qualor's note after it
      // taken neither for its answer nor for a reply, and the answer follows.
      await reviewOn(h, llm);
      await scan(mr.branchId);
      const { rows } = await queuedFor(mr.branchId);
      expect(rows).toMatchObject([{ kind: 'reply', noteId, threadId, issueId, status: 'queued' }]);
      llm.say(KEEP);
      expect(await answer()).toBe(1);
      const [, answered] = mr.answers(threadId);
      expect(firstLineOf(answered?.body ?? '')).toBe(replyMarker(rows[0]!.id));
      expect((await queuedFor(mr.branchId)).rows).toMatchObject([{ noteId, status: 'done' }]);
    });

    it.each(['a decoration first', 'the scan first'])(
      'the scan and a decoration of the same reply make one answer: %s',
      async (order) => {
        const { mr, threadId } = await threaded(`both-${order.replaceAll(' ', '-')}`);
        const noteId = mr.reply(threadId, 'We will not fix this now.');
        if (order === 'a decoration first') {
          await mr.decorate();
          await scan(mr.branchId);
        } else {
          await scan(mr.branchId);
          await mr.decorate();
        }
        const { rows, jobs: queued } = await queuedFor(mr.branchId);
        expect(rows).toMatchObject([{ kind: 'reply', noteId, status: 'queued' }]);
        expect(queued).toEqual([answerJob(mr.branchId, rows[0]!.id)]);
        const calls = llm.requests.length;
        llm.say(KEEP);
        expect(await answer()).toBe(1);
        expect(callsSince(calls)).toHaveLength(1);
        expect(mr.answers(threadId)).toHaveLength(1);
      },
    );

    it('queues nothing for a closed merge request, and does not read its notes', async () => {
      const { d, mr, threadId } = await threaded('closed');
      mr.reply(threadId, 'Still not a problem.');
      mr.command('qualor stop');
      mr.close();
      d.clearRequests();
      github.clearRequests();
      await scan(mr.branchId);
      expect(await queuedFor(mr.branchId)).toMatchObject({ rows: [], jobs: [] });
      // Its state was read; its notes were not.
      const reads = pathsOf(d);
      expect(reads.some((r) => /\/(merge_requests\/12|pulls\/7)$/.test(r))).toBe(true);
      expect(reads.filter((r) => /discussions|\/comments$|\/user$/.test(r))).toEqual([]);
      expect(graphqlWith('reviewThreads')).toEqual([]);
    });

    it('takes no organisation slot: with every slot taken by decorations, it still queues what it finds', async () => {
      const { mr, threadId } = await threaded('no-slot');
      mr.reply(threadId, 'We accept this for now.');
      const runtime = githubDeps(h).runtime;
      const [project] = await h.ctx.db
        .select({ organizationId: projects.organizationId })
        .from(projects)
        .where(eq(projects.id, mr.project.id));
      for (let n = 0; n < MAX_DECORATIONS_PER_ORGANIZATION; n += 1) {
        expect(runtime.slots.tryTake(project!.organizationId)).toBe(true);
      }
      await scan(mr.branchId, { scmRuntime: runtime });
      expect((await queuedFor(mr.branchId)).rows).toHaveLength(1);
    });

    it('queues nothing, and asks the provider nothing, while AI review is not active for the project', async () => {
      const { d, mr, threadId } = await threaded('inactive');
      mr.reply(threadId, 'Not a problem.');
      for (const switchOff of [() => reviewOff(h), () => reviewScope(h, 'selected')]) {
        await switchOff();
        d.clearRequests();
        await scan(mr.branchId);
        expect(d.requests()).toEqual([]);
        expect(await queuedFor(mr.branchId)).toMatchObject({ rows: [], jobs: [] });
        await reviewOn(h, llm);
      }
      // Switched on again, the scan finds the reply.
      await scan(mr.branchId);
      expect((await queuedFor(mr.branchId)).rows).toHaveLength(1);
    });

    it('leaves a branch that is not a merge request’s, and one that is gone, alone', async () => {
      const { d, mr, threadId } = await threaded('not-a-merge-request');
      mr.reply(threadId, 'Not a problem.');
      // A plain branch named like the merge request's number would find the merge request's notes.
      const [plain] = await h.ctx.db
        .insert(branches)
        .values({
          projectId: mr.project.id,
          kind: 'branch',
          name: provider === 'GitLab' ? '12' : '7',
        })
        .returning({ id: branches.id });
      d.clearRequests();
      await scan(plain!.id);
      await scan(uuidv7());
      expect(d.requests()).toEqual([]);
      expect(await queuedFor(plain!.id)).toMatchObject({ rows: [], jobs: [] });
      expect((await queuedFor(mr.branchId)).rows).toEqual([]);
    });

    it('warns, and queues nothing, when the connection cannot be made: its key no longer decrypts', async () => {
      const { d, mr, threadId } = await threaded('unusable');
      mr.reply(threadId, 'Not a problem.');
      const { said, logger } = recording();
      d.clearRequests();
      await withUnreadableToken(mr.connectionId, async () => {
        await scan(mr.branchId, { logger });
      });
      expect(d.requests()).toEqual([]);
      expect((await queuedFor(mr.branchId)).rows).toEqual([]);
      expect(said.warn.map(([fields]) => fields)).toEqual([{ branchId: mr.branchId }]);
    });

    it('ends quietly for a merge request the provider no longer has: one line at info with the branch, none of the provider’s words, and the circuit hears an answer', async () => {
      const { mr, threadId } = await threaded('gone');
      mr.reply(threadId, 'Fine.');
      const runtime = githubDeps(h).runtime;
      const { said, logger } = recording();
      mr.goneOnNextListing();
      await scan(mr.branchId, { logger, scmRuntime: runtime });
      expect((await queuedFor(mr.branchId)).rows).toEqual([]);
      expect(said.info.map(([fields]) => fields)).toEqual([{ branchId: mr.branchId }]);
      expect(JSON.stringify(said)).not.toMatch(/not found|\b404\b|GitLab|GitHub/i);
      expect(said.warn).toEqual([]);
      expect(said.error).toEqual([]);
      expect(runtime.circuit.inspect(mr.connectionId).failures).toBe(0);
    });

    it('a provider that fails fails the job into its second try, which scans again; its last try logs the codes and nothing the provider said', async () => {
      const { mr, threadId } = await threaded('failing');
      mr.reply(threadId, 'We accept this.');
      const runtime = githubDeps(h).runtime;
      const { said, logger } = recording();
      expect(await queueScan(h.ctx.db, mr.branchId)).toBe(true);
      mr.failNextThreadRead();
      await answer({ scmRuntime: runtime, logger });
      expect((await queuedFor(mr.branchId)).rows).toEqual([]);
      // Queued for its second try; the circuit counts the failure; the line holds codes only.
      expect((await scanJobs(mr.branchId)).map((j) => [j.status, j.attempts])).toEqual([
        ['queued', 1],
      ]);
      expect(runtime.circuit.inspect(mr.connectionId).failures).toBe(1);
      expect(said.warn).toEqual([
        [
          {
            branchId: mr.branchId,
            errorClass: expect.any(String),
            code: null,
            errorKind: 'transient',
            httpStatus: 502,
          },
          expect.stringContaining('tried again'),
        ],
      ]);
      expect(JSON.stringify(said)).not.toMatch(/Bad Gateway/);
      // The second try scans again, queues the reply and answers it; the count starts again.
      await retryNow();
      llm.say(KEEP);
      expect(await answer({ scmRuntime: runtime })).toBe(2);
      expect(runtime.circuit.inspect(mr.connectionId).failures).toBe(0);
      expect(mr.answers(threadId)).toHaveLength(1);

      // The last try says so at error level, and fails the job all the same.
      const last = await threaded('failing-last');
      last.mr.failNextThreadRead();
      await expect(scan(last.mr.branchId, { logger }, 2)).rejects.toThrow();
      expect(said.error).toEqual([
        [
          {
            branchId: last.mr.branchId,
            errorClass: expect.any(String),
            code: null,
            errorKind: 'transient',
            httpStatus: 502,
          },
          expect.stringContaining('last try'),
        ],
      ]);
    });

    it('waits while the connection’s circuit is open: queued again for when it opens, no try spent, and run once it has closed', async () => {
      const { d, mr, threadId } = await threaded('circuit-open');
      mr.reply(threadId, 'We accept this.');
      const runtime = githubDeps(h).runtime;
      for (let n = 0; n < SCM_CIRCUIT_FAILURES; n += 1) runtime.circuit.failure(mr.connectionId);
      const opensIn = (runtime.circuit.openUntil(mr.connectionId) ?? 0) - Date.now();
      await queueScan(h.ctx.db, mr.branchId);
      d.clearRequests();
      expect(await answer({ scmRuntime: runtime })).toBe(1);
      // Nothing is asked of the provider, and nothing is queued for the notes.
      expect(d.requests()).toEqual([]);
      expect((await queuedFor(mr.branchId)).rows).toEqual([]);
      // The job is done, no try spent; the next is due when the circuit opens again.
      const queued = await scanJobs(mr.branchId);
      expect(queued.map((j) => [j.status, j.attempts])).toEqual([
        ['succeeded', 1],
        ['queued', 0],
      ]);
      const waits = (queued[1]!.runAt.getTime() - queued[1]!.createdAt.getTime()) / 1000;
      expect(Math.abs(waits - opensIn / 1000)).toBeLessThan(5);
      // A webhook meanwhile adds none: the scan that waits reads the notes.
      expect(await queueScan(h.ctx.db, mr.branchId)).toBe(false);
      // Once the circuit has closed, the next job scans, and its answers follow.
      runtime.circuit.success(mr.connectionId);
      await retryNow();
      llm.say(KEEP);
      await answer({ scmRuntime: runtime });
      expect(mr.answers(threadId)).toHaveLength(1);
    });

    it('waits a minute when the circuit is half-open and another job probes it', async () => {
      const { d, mr, threadId } = await threaded('circuit-probe');
      mr.reply(threadId, 'We accept this.');
      let clock = Date.now();
      // The circuit on a clock of the test's; the rest of the runtime as in the other tests.
      const runtime = githubDeps(h).runtime;
      runtime.circuit = new CircuitBreaker(() => clock);
      for (let n = 0; n < SCM_CIRCUIT_FAILURES; n += 1) runtime.circuit.failure(mr.connectionId);
      // The window is over, and another job took the probe.
      clock += SCM_CIRCUIT_OPEN_MS + 1;
      expect(runtime.circuit.tryPass(mr.connectionId)).toBe(true);
      await queueScan(h.ctx.db, mr.branchId);
      d.clearRequests();
      await answer({ scmRuntime: runtime });
      expect(d.requests()).toEqual([]);
      const [, next] = await scanJobs(mr.branchId);
      expect((next!.runAt.getTime() - next!.createdAt.getTime()) / 1000).toBe(60);
      // The probe's answer closes the circuit, and the next job scans.
      runtime.circuit.success(mr.connectionId);
      await retryNow();
      llm.say(KEEP);
      await answer({ scmRuntime: runtime });
      expect(mr.answers(threadId)).toHaveLength(1);
    });
  });
});
