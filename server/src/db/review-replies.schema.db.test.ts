import { randomUUID } from 'node:crypto';
import { LLM_FEATURES, SCM_PROVIDERS } from '@qualor/shared';
import { eq, inArray } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { seedIssue, seedRule } from '../../test/issues';
import {
  checkViolation,
  llmRequestRow,
  PG_NOT_NULL_VIOLATION,
  refusal,
  type Refusal,
} from '../../test/refusals';
import { PG_FOREIGN_KEY_VIOLATION, PG_UNIQUE_VIOLATION } from './errors';
import { first } from './rows';
import {
  analyses,
  branches,
  issues,
  llmRequests,
  organizations,
  projects,
  REPLY_COMMANDS,
  REPLY_KINDS,
  REPLY_OUTCOMES,
  REPLY_REASONS,
  REPLY_STATUSES,
  REPLY_VERDICTS,
  reviewReplies,
  reviewRuns,
  THREAD_ID,
  type LlmRequestFeature,
} from './schema';

const DEADLINE = new Date('2026-10-24T09:15:00Z');
const FINISHED_AT = new Date('2026-10-24T08:00:41Z');
/** The statuses a row has only once it has ended, and so only with its finish time. */
const ENDED: readonly string[] = ['done', 'skipped', 'failed'];

type ReplyInsert = typeof reviewReplies.$inferInsert;
type RunInsert = typeof reviewRuns.$inferInsert;

/** `value` in the column `name`, whatever the column's type allows: for a value the checks must refuse. */
const column = (name: keyof ReplyInsert, value: unknown): Partial<ReplyInsert> =>
  ({ [name]: value }) as Partial<ReplyInsert>;

describe('review_replies and the columns beside it (6I-4, migration 0017_review_replies)', () => {
  let t: TestDatabase;
  let organizationId: string;
  let projectId: string;
  let mergeRequestId: string;
  let ruleId: string;
  let noteSequence = 1_000;

  const newProject = async (key: string) =>
    first(await t.db.insert(projects).values({ organizationId, key, name: key }).returning()).id;
  const newBranch = async (name: string, ofProject = projectId) =>
    first(
      await t.db
        .insert(branches)
        .values({ projectId: ofProject, kind: 'merge_request', name })
        .returning(),
    ).id;
  const newAnalysis = async () =>
    first(await t.db.insert(analyses).values({ projectId }).returning()).id;
  const newIssue = () => seedIssue(t.db, { projectId, branchId: mergeRequestId, ruleId });

  /** A reply to a GitLab thread with a note of its own, unless `over` says otherwise. */
  const replyValues = (over: Partial<ReplyInsert> = {}): ReplyInsert => {
    noteSequence += 1;
    return {
      projectId,
      branchId: mergeRequestId,
      provider: 'gitlab',
      noteId: noteSequence,
      threadId: 'a'.repeat(40),
      kind: 'reply',
      author: 'jane',
      ...over,
    };
  };
  const reply = async (over: Partial<ReplyInsert> = {}) =>
    first(await t.db.insert(reviewReplies).values(replyValues(over)).returning());
  /** The refusal of a reply made with `over`, or null when it was accepted. */
  const tryReply = (over: Partial<ReplyInsert>): Promise<Refusal | null> =>
    refusal(t.db.insert(reviewReplies).values(replyValues(over)));
  const survivors = async (ids: string[]) =>
    (
      await t.db
        .select({ id: reviewReplies.id })
        .from(reviewReplies)
        .where(inArray(reviewReplies.id, ids))
    )
      .map((row) => row.id)
      .sort();

  const runValues = async (over: Partial<RunInsert> = {}): Promise<RunInsert> => ({
    projectId,
    branchId: mergeRequestId,
    analysisId: await newAnalysis(),
    deadlineAt: DEADLINE,
    ...over,
  });

  beforeAll(async () => {
    t = await createTestDatabase();
    organizationId = first(
      await t.db.insert(organizations).values({ key: 'replies', name: 'Replies' }).returning(),
    ).id;
    projectId = await newProject('replies/api');
    mergeRequestId = await newBranch('7');
    ruleId = await seedRule(t.db, { key: 'ai:logic' });
  });
  afterAll(async () => {
    await t.close();
  });

  it('lists the values the checks allow', () => {
    expect(REPLY_STATUSES).toEqual(['queued', 'running', 'done', 'skipped', 'failed']);
    expect(REPLY_KINDS).toEqual(['reply', 'command']);
    expect(REPLY_COMMANDS).toEqual(['review', 'fix', 'stop']);
    expect(REPLY_VERDICTS).toEqual(['keep', 'wont_fix', 'false_positive']);
    expect(REPLY_OUTCOMES).toEqual([
      'answered',
      'acknowledged',
      'explained',
      'wont_fix',
      'false_positive',
      'review_requested',
      'in_progress',
      'already_reviewed',
      'not_available',
      'review_off',
    ]);
    expect(REPLY_REASONS).toEqual([
      'budget_spent',
      'inactive',
      'closed',
      'thread_gone',
      'superseded',
      'expired',
      'provider_error',
      'provider_no_tools',
      'bad_answer',
      'internal',
    ]);
  });

  it('stores a queued reply with its defaults', async () => {
    const stored = await reply();
    expect(stored).toMatchObject({
      projectId,
      branchId: mergeRequestId,
      provider: 'gitlab',
      threadId: 'a'.repeat(40),
      issueId: null,
      kind: 'reply',
      command: null,
      author: 'jane',
      status: 'queued',
      outcome: null,
      reason: null,
      verdict: null,
      answer: null,
      answerNoteId: null,
      model: null,
      inputTokens: 0,
      outputTokens: 0,
      costMicroUsd: null,
      startedAt: null,
      finishedAt: null,
    });
    expect(stored.id).toMatch(/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/);
    expect(stored.noteId).toBe(noteSequence);
    expect(stored.createdAt).toBeInstanceOf(Date);
  });

  it('keeps what a finished reply records, with note ids past 2^31', async () => {
    const issueId = await newIssue();
    const stored = await reply({
      provider: 'github',
      noteId: 3_000_000_000,
      threadId: '2999999999',
      issueId,
      author: 'octocat',
      status: 'done',
      outcome: 'wont_fix',
      verdict: 'wont_fix',
      answer: 'Understood, this is not worth fixing now.',
      answerNoteId: 3_000_000_007,
      model: 'model-1',
      inputTokens: 41_000,
      outputTokens: 800,
      costMicroUsd: 12_500,
      startedAt: new Date('2026-10-24T08:00:05Z'),
      finishedAt: FINISHED_AT,
    });
    expect(stored).toMatchObject({
      provider: 'github',
      noteId: 3_000_000_000,
      threadId: '2999999999',
      issueId,
      author: 'octocat',
      status: 'done',
      outcome: 'wont_fix',
      reason: null,
      verdict: 'wont_fix',
      answer: 'Understood, this is not worth fixing now.',
      answerNoteId: 3_000_000_007,
      model: 'model-1',
      inputTokens: 41_000,
      outputTokens: 800,
      costMicroUsd: 12_500,
    });
    expect(stored.startedAt).toEqual(new Date('2026-10-24T08:00:05Z'));
    expect(stored.finishedAt).toEqual(FINISHED_AT);
  });

  it('keeps one row per note of a project, provider and kind', async () => {
    await reply({ noteId: 77 });
    const unique = { code: PG_UNIQUE_VIOLATION, constraint: 'review_replies_note_unique' };
    expect(await tryReply({ noteId: 77 })).toEqual(unique);
    // Whatever else the second row says, a reply of that number is the same note, and a note is the
    // project's: another branch of the project does not make it another one.
    expect(await tryReply({ noteId: 77, author: 'mallory', threadId: null })).toEqual(unique);
    expect(await tryReply({ noteId: 77, branchId: await newBranch('10') })).toEqual(unique);
    // The same number is another note on the other provider, in another project, and as a
    // command: on GitHub a reply is a review comment and a command an issue comment, two id spaces
    // that can share a number.
    expect(await tryReply({ noteId: 77, provider: 'github' })).toBeNull();
    const other = await newProject('replies/other');
    expect(
      await tryReply({ noteId: 77, projectId: other, branchId: await newBranch('7', other) }),
    ).toBeNull();
    const asCommand: Partial<ReplyInsert> = { noteId: 77, kind: 'command', threadId: null };
    expect(await tryReply({ ...asCommand, command: 'review' })).toBeNull();
    // A command of that number is one note too.
    expect(await tryReply({ ...asCommand, command: 'stop' })).toEqual(unique);
  });

  it('a command has a command, a reply has none', async () => {
    const byKind = checkViolation('review_replies_command_by_kind');
    for (const kind of REPLY_KINDS) {
      for (const command of [null, ...REPLY_COMMANDS]) {
        expect(await tryReply({ kind, command }), `${kind} with ${String(command)}`).toEqual(
          (kind === 'command') === (command !== null) ? null : byKind,
        );
      }
    }
    // A command outside the list is refused.
    for (const command of ['Review', 'review ', 'merge', '']) {
      expect(await tryReply({ kind: 'command', ...column('command', command) }), command).toEqual(
        checkViolation('review_replies_command_check'),
      );
    }
  });

  it('status, kind, verdict, outcome and reason are limited to their lists', async () => {
    const lists = [
      ['status', 'review_replies_status_check', REPLY_STATUSES],
      ['kind', 'review_replies_kind_check', REPLY_KINDS],
      ['verdict', 'review_replies_verdict_check', REPLY_VERDICTS],
      ['outcome', 'review_replies_outcome_check', REPLY_OUTCOMES],
      ['reason', 'review_replies_reason_check', REPLY_REASONS],
    ] as const;
    for (const [name, constraint, values] of lists) {
      for (const value of values) {
        // A command is only a command with its command, and a row has ended only with its time.
        const over: Partial<ReplyInsert> = {};
        if (name === 'kind' && value === 'command') over.command = 'stop';
        if (name === 'status' && ENDED.includes(value)) over.finishedAt = FINISHED_AT;
        expect(await tryReply({ ...column(name, value), ...over }), `${name} ${value}`).toBeNull();
      }
      for (const value of ['Done', 'done ', 'unknown', 'queued,running', '']) {
        expect(await tryReply(column(name, value)), `${name} ${value}`).toEqual(
          checkViolation(constraint),
        );
      }
    }
    // None of outcome, reason and verdict is required.
    expect(await tryReply({ outcome: null, reason: null, verdict: null })).toBeNull();
  });

  it('a row has a finish time exactly when it has ended', async () => {
    const finishedByStatus = checkViolation('review_replies_finished_by_status');
    for (const status of REPLY_STATUSES) {
      const ended = ENDED.includes(status);
      expect(await tryReply({ status, finishedAt: null }), `${status} without a time`).toEqual(
        ended ? finishedByStatus : null,
      );
      expect(await tryReply({ status, finishedAt: FINISHED_AT }), `${status} with a time`).toEqual(
        ended ? null : finishedByStatus,
      );
    }
    // An update is held to it as an insert is: a row cannot end without its time, nor get a time
    // while it is still to do.
    const queued = await reply();
    for (const set of [{ status: 'done' as const }, { finishedAt: FINISHED_AT }]) {
      expect(
        await refusal(t.db.update(reviewReplies).set(set).where(eq(reviewReplies.id, queued.id))),
        JSON.stringify(set),
      ).toEqual(finishedByStatus);
    }
    await t.db
      .update(reviewReplies)
      .set({ status: 'done', finishedAt: FINISHED_AT })
      .where(eq(reviewReplies.id, queued.id));
  });

  it('a provider is gitlab, github or azure', async () => {
    // `review_replies accepts provider azure` (migration 0034).
    for (const provider of SCM_PROVIDERS) {
      expect(await tryReply({ provider }), provider).toBeNull();
    }
    for (const provider of ['bitbucket', 'GitLab', '']) {
      expect(await tryReply(column('provider', provider)), provider).toEqual(
        checkViolation('review_replies_provider_check'),
      );
    }
  });

  it('an answer holds at most 1 200 characters, counted as characters and not as bytes', async () => {
    for (const answer of ['x'.repeat(1_200), 'é'.repeat(1_200), '', null]) {
      expect(await tryReply({ answer }), String(answer).slice(0, 5)).toBeNull();
    }
    for (const answer of ['x'.repeat(1_201), 'é'.repeat(1_201)]) {
      expect(await tryReply({ answer }), answer.slice(0, 5)).toEqual(
        checkViolation('review_replies_answer_length'),
      );
    }
  });

  it('an author holds at most 255 characters, counted as characters and not as bytes', async () => {
    for (const author of ['x'.repeat(255), 'é'.repeat(255)]) {
      expect(await tryReply({ author }), author.slice(0, 5)).toBeNull();
    }
    for (const author of ['x'.repeat(256), 'é'.repeat(256)]) {
      expect(await tryReply({ author }), author.slice(0, 5)).toEqual(
        checkViolation('review_replies_author_length'),
      );
    }
  });

  it('a thread is a GitLab discussion id, a GitHub comment id, or none', async () => {
    const valid = [
      // A GitLab discussion id: hexadecimal digits, 40 of them as GitLab writes it.
      'a1b2c3d4e5f60718293a4b5c6d7e8f9012345678',
      '0',
      'f'.repeat(64),
      // A GitHub comment id: digits, as many as a bigint has.
      '2999999999',
      '9'.repeat(19),
      '1'.repeat(20),
      // A GitHub top-level command has no thread.
      null,
    ];
    for (const threadId of valid) {
      expect(await tryReply({ threadId }), String(threadId)).toBeNull();
    }
    const invalid = [
      '',
      ' ',
      'A1B2C3',
      'xyz',
      'g'.repeat(40),
      'a'.repeat(65),
      '1'.repeat(65),
      'abc def',
      'abc-def',
      '12.5',
      '-1',
      'abc\n',
    ];
    for (const threadId of invalid) {
      expect(await tryReply({ threadId }), JSON.stringify(threadId)).toEqual(
        checkViolation('review_replies_thread_id_format'),
      );
    }
    // The pattern the queue tests a thread id by is the one the CHECK is written from: they take
    // and refuse the same ids.
    for (const threadId of valid) {
      if (threadId !== null) expect(THREAD_ID.test(threadId), threadId).toBe(true);
    }
    for (const threadId of invalid) {
      expect(THREAD_ID.test(threadId), JSON.stringify(threadId)).toBe(false);
    }
  });

  it('a reply has a project, a branch, a provider, a note, a kind and an author', async () => {
    for (const missing of [
      'projectId',
      'branchId',
      'provider',
      'noteId',
      'kind',
      'author',
    ] as const) {
      const values = { ...replyValues(), [missing]: undefined } as ReplyInsert;
      expect((await refusal(t.db.insert(reviewReplies).values(values)))?.code, missing).toBe(
        PG_NOT_NULL_VIOLATION,
      );
    }
  });

  it('a reply names a project, a branch and an issue that exist', async () => {
    expect(await tryReply({ projectId: randomUUID() })).toEqual({
      code: PG_FOREIGN_KEY_VIOLATION,
      constraint: 'review_replies_project_id_projects_id_fk',
    });
    expect(await tryReply({ branchId: randomUUID() })).toEqual({
      code: PG_FOREIGN_KEY_VIOLATION,
      constraint: 'review_replies_branch_id_branches_id_fk',
    });
    expect(await tryReply({ issueId: randomUUID() })).toEqual({
      code: PG_FOREIGN_KEY_VIOLATION,
      constraint: 'review_replies_issue_id_issues_id_fk',
    });
  });

  it('deleting the branch or the project deletes its replies', async () => {
    const doomedBranch = await newBranch('8');
    const onBranch = await reply({ branchId: doomedBranch });
    const elsewhere = await reply();
    await t.db.delete(branches).where(eq(branches.id, doomedBranch));
    expect(await survivors([onBranch.id, elsewhere.id])).toEqual([elsewhere.id]);

    // The reply's own project FK, on its own: its branch belongs to the surviving project.
    const doomedProject = await newProject('replies/doomed');
    const ofProject = await reply({ projectId: doomedProject });
    await t.db.delete(projects).where(eq(projects.id, doomedProject));
    expect(await survivors([ofProject.id, elsewhere.id])).toEqual([elsewhere.id]);
  });

  it('deleting the issue keeps the reply, with issue_id null', async () => {
    const doomed = await newIssue();
    const kept = await newIssue();
    const ofDoomed = await reply({
      issueId: doomed,
      status: 'done',
      outcome: 'answered',
      finishedAt: FINISHED_AT,
    });
    const ofKept = await reply({ issueId: kept });
    await t.db.delete(issues).where(eq(issues.id, doomed));
    const rows = await t.db
      .select({
        id: reviewReplies.id,
        issueId: reviewReplies.issueId,
        outcome: reviewReplies.outcome,
      })
      .from(reviewReplies)
      .where(inArray(reviewReplies.id, [ofDoomed.id, ofKept.id]));
    const byId = Object.fromEntries(rows.map((row) => [row.id, row]));
    expect(byId[ofDoomed.id]).toEqual({ id: ofDoomed.id, issueId: null, outcome: 'answered' });
    expect(byId[ofKept.id]).toMatchObject({ issueId: kept });
  });

  it('indexes the replies of a thread by note, the replies of an issue, and the rows still to answer', async () => {
    const { rows } = await t.pool.query<{ indexname: string; indexdef: string }>(
      `SELECT indexname, indexdef FROM pg_indexes
        WHERE schemaname = 'public' AND tablename = 'review_replies'`,
    );
    const definitions = Object.fromEntries(
      rows.map((row) => [row.indexname, row.indexdef.replace(/^.* USING /, '')]),
    );
    expect(definitions['review_replies_thread_idx']).toBe('btree (branch_id, thread_id, note_id)');
    expect(definitions['review_replies_issue_idx']).toBe(
      'btree (issue_id) WHERE (issue_id IS NOT NULL)',
    );
    expect(definitions['review_replies_note_unique']).toBe(
      'btree (project_id, provider, kind, note_id)',
    );
    // The sweep's rows, after every reap of the review worker.
    expect(definitions['review_replies_active_idx']).toBe(
      "btree (status) WHERE (status = ANY (ARRAY['queued'::text, 'running'::text]))",
    );
  });

  it('llm_requests accepts feature review-reply and still refuses another value', async () => {
    const request = (feature: string) =>
      llmRequestRow({ organizationId, projectId }, feature, {
        promptVersion: 'reply.v1',
        field: 'reply',
      });
    // The three single-shot features and the review, as before, and the reply.
    for (const feature of [...LLM_FEATURES, 'review', 'review-reply']) {
      expect(await refusal(t.db.insert(llmRequests).values(request(feature))), feature).toBeNull();
    }
    const stored = first(
      await t.db.insert(llmRequests).values(request('review-reply')).returning(),
    );
    // The column's TypeScript type says so too.
    const feature: LlmRequestFeature = stored.feature;
    expect(feature).toBe('review-reply');
    expect(stored).toMatchObject({ issueId: null, userId: null, status: 'queued' });
    for (const other of ['poem', 'Review-Reply', 'review_reply', 'review-replies', '']) {
      expect(await refusal(t.db.insert(llmRequests).values(request(other))), other).toEqual(
        checkViolation('llm_requests_feature_check'),
      );
    }
    // LLM_FEATURES stays the three single-shot features.
    expect(LLM_FEATURES).toEqual(['explain', 'triage', 'fix']);
  });

  it('a review run keeps who asked for it, in at most 255 characters', async () => {
    // Asked for by nobody, as every run before the replies.
    const plain = first(
      await t.db
        .insert(reviewRuns)
        .values(await runValues())
        .returning(),
    );
    expect(plain.requestedBy).toBeNull();
    for (const requestedBy of ['jane', 'x'.repeat(255), 'é'.repeat(255)]) {
      const run = first(
        await t.db
          .insert(reviewRuns)
          .values(await runValues({ requestedBy }))
          .returning(),
      );
      expect(run.requestedBy).toBe(requestedBy);
    }
    for (const requestedBy of ['x'.repeat(256), 'é'.repeat(256)]) {
      expect(
        await refusal(t.db.insert(reviewRuns).values(await runValues({ requestedBy }))),
        requestedBy.slice(0, 5),
      ).toEqual(checkViolation('review_runs_requested_by_length'));
    }
  });
});
