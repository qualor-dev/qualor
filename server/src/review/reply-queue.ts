import {
  and,
  asc,
  count,
  eq,
  gt,
  gte,
  inArray,
  lt,
  not,
  notExists,
  or,
  sql,
  type SQL,
} from 'drizzle-orm';
import { alias } from 'drizzle-orm/pg-core';
import { z } from 'zod';
import type { ScmProvider } from '@qualor/shared';
import type { Db, Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import {
  branches,
  issues,
  jobs,
  reviewReplies,
  THREAD_ID,
  type ReplyKind,
  type ReplyOutcome,
} from '../db/schema';
import { readLlmSettings } from '../llm/settings';
import { enqueue } from '../queue/queue';
import type { AzureThread } from '../scm/azure/client';
import type { GitHubComment } from '../scm/github/client';
import type { GitLabDiscussion } from '../scm/gitlab/client';
import { insertReplies, largestNoteIds } from './replies';
import {
  azureCommands,
  azureRounds,
  githubCommands,
  gitlabCommands,
  gitlabRounds,
  type CommandNote,
  type DetectOptions,
  type Round,
} from './reply-detect';
import { REVIEW_AFTER_STOP_SECONDS } from './runs';
import { reviewActive, reviewSettingsOf } from './settings';

/*
 * The queue of the answers to what people write in a merge request (6I-4). Detection
 * (reply-detect.ts) finds the new replies in Qualor's threads and the notes that give a command;
 * `queueReplies` writes what it found, in one short transaction: a row of the replies ledger
 * (replies.ts) for each note that is new to the project, and the `ai-reply` job that answers it,
 * which the review worker runs beside the reviews (reply-job.ts). Nothing else writes these rows
 * and jobs (the job's own stop, and its wait for an SCM circuit, queue its row again here too), so
 * a row is queued exactly when its job is, and the sweep below ends a row its job left running.
 *
 * The other `ai-reply` job, a scan, is a webhook's: it names a merge request and reads its notes
 * through the API (reply-scan.ts), never trusting what the webhook carried. `queueScan` queues it,
 * at most one waiting for a merge request: a delivery waits only for another delivery's turn at the
 * branch's lock, never for ingestion. What a scan finds is queued as a decoration's notes are.
 *
 * A pass is bounded: at most 50 rounds and 20 commands, new ones and notes queued again together,
 * the oldest first, and the rest wait for the next pass. The caps count only what the ledger does
 * not hold already: detection hands over every command in the window each time, and a note that
 * was queued takes no place of the cap that a note nobody queued yet could have.
 */

export const AI_REPLY_QUEUE = 'ai-reply';

/**
 * A job is tried twice at most: the second try is for an error before the answer was decided or
 * for a lease that expired, and resumes after the last step the row records.
 */
export const AI_REPLY_MAX_ATTEMPTS = 2;

/** The jobs of one merge request run one at a time, in the order they were queued. */
export function replyKey(branchId: string): string {
  return `ai-reply:branch:${branchId}`;
}

/**
 * What a job is for: answering the note a ledger row holds, or reading a merge request's notes
 * through the API for the ones nobody has queued yet (a webhook's, which never trusts the text it
 * carries).
 */
export const replyPayload = z.discriminatedUnion('kind', [
  z.object({ kind: z.literal('answer'), replyId: z.uuid() }),
  z.object({ kind: z.literal('scan'), branchId: z.uuid() }),
]);
export type ReplyPayload = z.infer<typeof replyPayload>;

/**
 * Queues a scan of the merge request's notes (a webhook's job, reply-scan.ts), unless one is queued
 * already for the branch: that one has not read the notes yet, so it reads the new note too. A scan
 * that is running does not count, since it may have listed the notes before this one was written,
 * and neither do the branch's answer jobs. The check and the queueing are one step for the branch,
 * under an advisory lock of its own (`LOCKS.replyScan`): a caller that finds it taken waits its
 * turn, the few milliseconds of the other's check and queueing, and then checks, a statement of its
 * own that sees what the other committed. So a burst of notes makes at most one scan waiting, and a
 * note written as a scan starts to run is read by the scan queued after it. The branch's row is read
 * and not locked: ingestion holds it from the upsert of the branch until it commits, and a delivery
 * that waited for it could outlast the provider's timeout (ten seconds on GitLab); ingestion does
 * not take this lock. The scan is due `runAt` (now when left out). Answers whether it queued one; a
 * branch that is gone has none.
 */
export async function queueScan(db: Db, branchId: string, runAt?: SQL): Promise<boolean> {
  return db.transaction(async (tx) => {
    const [branch] = await tx
      .select({ id: branches.id })
      .from(branches)
      .where(eq(branches.id, branchId));
    if (branch === undefined) return false;
    await lockScanQueue(tx, branchId);
    const [waiting] = await tx
      .select({ id: jobs.id })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, AI_REPLY_QUEUE),
          eq(jobs.concurrencyKey, replyKey(branchId)),
          eq(jobs.status, 'queued'),
          sql`${jobs.payload} ->> 'kind' = 'scan'`,
        ),
      )
      .limit(1);
    if (waiting !== undefined) return false;
    await enqueue(tx, {
      queue: AI_REPLY_QUEUE,
      payload: { kind: 'scan', branchId } satisfies ReplyPayload,
      concurrencyKey: replyKey(branchId),
      maxAttempts: AI_REPLY_MAX_ATTEMPTS,
      ...(runAt === undefined ? {} : { runAt }),
    });
    return true;
  });
}

/**
 * The branch's scan-queueing lock until the transaction ends. It waits while another transaction
 * holds it, and only a request between its check and its queueing does: a few milliseconds.
 */
async function lockScanQueue(db: Executor, branchId: string): Promise<void> {
  await db.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.replyScan}, hashtext(${branchId}))`);
}

/**
 * The most rounds one pass queues, new ones and replies queued again together. The oldest go first
 * and the rest wait for the next pass, which bounds the statements that write them and the burst
 * of jobs.
 */
export const MAX_QUEUED_ROUNDS = 50;
/** The most commands one pass queues, as {@link MAX_QUEUED_ROUNDS} bounds the rounds. */
export const MAX_QUEUED_COMMANDS = 20;

/**
 * The most rounds of one thread the ledger takes in a UTC day: past them, a round of the thread is
 * not queued until the next day, when its notes are found and queued as ever. On top of the day's
 * budget, it bounds a thread where a reply bot answers Qualor, or a noisy public one.
 */
export const MAX_ROUNDS_PER_THREAD_PER_DAY = 5;

/** A note older than this is never answered, whenever the consent was given: old threads are left alone. */
export const REPLY_MAX_AGE_DAYS = 30;

/** The merge request the notes are in, as a row of the ledger knows it. */
export interface ReplyContext {
  projectId: string;
  branchId: string;
  provider: ScmProvider;
}

/**
 * Where decoration looks for notes to answer: the newest note the ledger holds of each thread of
 * the branch, and the earliest moment a note counts from.
 */
export type ReplyWindow = Pick<DetectOptions, 'largestNoteIds' | 'since'>;

/**
 * The later of the organisation's review consent and {@link REPLY_MAX_AGE_DAYS} days before `now`:
 * a note before it is never answered, so switching review on does not answer a project's old
 * threads.
 */
export function repliesSince(consentAt: string, now: Date): Date {
  const oldest = now.getTime() - REPLY_MAX_AGE_DAYS * 86_400_000;
  return new Date(Math.max(Date.parse(consentAt), oldest));
}

/**
 * The window of a decoration of the project's branch, or null when Qualor answers nothing there:
 * AI review is not active for the project.
 */
export async function replyWindow(
  db: Executor,
  project: { id: string; organizationId: string; scmConnectionId: string | null },
  branchId: string,
  now: Date = new Date(),
): Promise<ReplyWindow | null> {
  const settings = await readLlmSettings(db);
  const consent = reviewSettingsOf(settings, project.organizationId).consent;
  // An active review has a consent, which names the provider configured now.
  if (!reviewActive(settings, project).active || consent === null) return null;
  return {
    largestNoteIds: await largestNoteIds(db, branchId),
    since: repliesSince(consent.at, now),
  };
}

/** The start of the UTC day `now` is in, which the day's budget counts from. */
export function utcDayStart(now: Date): Date {
  return new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()));
}

/** The longest author name the ledger keeps. */
const MAX_AUTHOR_CHARS = 255;

/**
 * The first `limit` of `items` by note id, the oldest first: what is left waits for the next
 * pass. Rows go in by note id, so two transactions that find the same notes take them in one
 * order, and neither can wait on a row the other takes later: they cannot deadlock.
 */
function oldest<T>(items: readonly T[], noteOf: (item: T) => number, limit: number): T[] {
  return items.toSorted((a, b) => noteOf(a) - noteOf(b)).slice(0, limit);
}

/**
 * Queues the job that answers each of the rows `replyIds`, after the jobs the branch has, due at
 * `runAt` (now when left out).
 */
async function enqueueAnswers(
  db: Executor,
  branchId: string,
  replyIds: readonly string[],
  runAt?: SQL,
): Promise<void> {
  for (const replyId of replyIds) {
    await enqueue(db, {
      queue: AI_REPLY_QUEUE,
      payload: { kind: 'answer', replyId } satisfies ReplyPayload,
      concurrencyKey: replyKey(branchId),
      maxAttempts: AI_REPLY_MAX_ATTEMPTS,
      ...(runAt === undefined ? {} : { runAt }),
    });
  }
}

/**
 * A running row queued again, its start kept (a queued row may have one), with a new job due in
 * `seconds`, in one transaction: the job that gave it back ends, and no try of the new one is
 * spent yet. The new job comes after the branch's jobs queued before it, a newer round of the
 * row's thread among them, which then answers the row's notes too: the row is superseded
 * (reply-job.ts). Answers whether the row was still running.
 */
async function queueAgain(
  db: Db,
  reply: { id: string; branchId: string },
  seconds: number,
): Promise<boolean> {
  return db.transaction(async (tx) => {
    const [queued] = await tx
      .update(reviewReplies)
      .set({ status: 'queued' })
      .where(and(eq(reviewReplies.id, reply.id), eq(reviewReplies.status, 'running')))
      .returning({ id: reviewReplies.id });
    if (queued === undefined) return false;
    await enqueueAnswers(
      tx,
      reply.branchId,
      [reply.id],
      sql`now() + make_interval(secs => ${seconds})`,
    );
    return true;
  });
}

/**
 * A running row whose answer the stopping server gave up before anything was decided: it is
 * queued again with a new job a few seconds on, for another replica or for this server once it is
 * up again (not at once, so that a worker of the stopping server that is still polling does not
 * take it straight back). Answers whether the row was still running.
 */
export async function queueAfterStop(
  db: Db,
  reply: { id: string; branchId: string },
): Promise<boolean> {
  return queueAgain(db, reply, REVIEW_AFTER_STOP_SECONDS);
}

/**
 * How long an answer waits for its SCM connection's circuit when the circuit cannot tell when it
 * lets a job through: it is half-open, and another job's probe has no answer yet.
 */
export const REPLY_CIRCUIT_WAIT_SECONDS = 60;

/**
 * A running row whose job found a circuit closed to it (reply-job.ts): its SCM connection's before
 * its own requests, or its model provider's before the model decided. It is queued again with a
 * new job due in `waitSeconds`, when the circuit lets a job through again. Nothing of the wait is
 * written on the row. Answers whether the row was still running.
 */
export async function queueAfterCircuit(
  db: Db,
  reply: { id: string; branchId: string },
  waitSeconds: number,
): Promise<boolean> {
  return queueAgain(db, reply, waitSeconds);
}

/**
 * A scan whose job found its SCM connection's circuit closed to it before its own requests: the
 * scan is queued again, due in `waitSeconds`, when the circuit lets a job through again. The job
 * that gave it back ends, and no try of the new one is spent. A scan the branch has queued already
 * is that one (`queueScan`): it runs sooner and waits for the circuit in its turn. Answers whether
 * it queued one.
 */
export async function queueScanAfterCircuit(
  db: Db,
  branchId: string,
  waitSeconds: number,
): Promise<boolean> {
  return queueScan(db, branchId, sql`now() + make_interval(secs => ${waitSeconds})`);
}

/**
 * Whether an `ai-reply` job is queued or running for the row of the replies ledger that the
 * statement reads (`review_replies.id`): a row with one is alive, and a running row without one is
 * the sweep's (below). Compared as text, so that a malformed payload never fails the statement.
 */
export function withLiveJob(): SQL {
  return sql`EXISTS (SELECT 1 FROM ${jobs}
                      WHERE ${jobs.queue} = ${AI_REPLY_QUEUE}
                        AND ${jobs.status} IN ('queued', 'running')
                        AND ${jobs.payload} ->> 'replyId' = ${reviewReplies.id}::text)`;
}

/**
 * The rows that are `running` with no `ai-reply` job queued or running for them: their job is gone
 * for good (its lease expired on both tries, or both tries failed), so nothing would ever end them.
 * After every reap of the review worker (main.ts) each ends `failed: internal` here, as the sweep of
 * the review runs ends a run without its job (runs.ts), and keeps an outcome it recorded (the status
 * its reply changed, the decision of its command: they happened). Decided by whether a job is
 * there, never by the row's age: a job that runs keeps its lease. A row and its job are written
 * together (above), and a row is running only while a job has taken it, so one statement is enough.
 * Answers the rows it ended, each by its id and the outcome it kept (null for none): what the
 * sweep's line in the log names, and nothing else.
 */
export async function reconcileStuckReplies(
  db: Executor,
): Promise<{ replyId: string; outcome: ReplyOutcome | null }[]> {
  return db
    .update(reviewReplies)
    .set({ status: 'failed', reason: 'internal', finishedAt: sql`now()` })
    .where(and(eq(reviewReplies.status, 'running'), not(withLiveJob())))
    .returning({ replyId: reviewReplies.id, outcome: reviewReplies.outcome });
}

/**
 * The rounds that are for an issue of the project: a thread whose marker names the issue of
 * another Qualor project of a monorepo, or one that was deleted, is none of its answering.
 */
async function ownRounds(
  db: Executor,
  ctx: ReplyContext,
  rounds: readonly Round[],
): Promise<Round[]> {
  if (rounds.length === 0) return [];
  const ids = [...new Set(rounds.map((round) => round.issueId))];
  const found = await db
    .select({ id: issues.id })
    .from(issues)
    .where(and(inArray(issues.id, ids), eq(issues.projectId, ctx.projectId)));
  const own = new Set(found.map((issue) => issue.id));
  return rounds.filter((round) => own.has(round.issueId));
}

/**
 * The notes of the rounds and of the commands that the ledger holds already, whatever became of
 * them, by one read of its unique index (the project, the provider, the kind and the note).
 */
async function heldNotes(
  db: Executor,
  ctx: ReplyContext,
  notes: { rounds: readonly number[]; commands: readonly number[] },
): Promise<{ rounds: Set<number>; commands: Set<number> }> {
  const kinds = [
    ...(notes.rounds.length === 0
      ? []
      : [and(eq(reviewReplies.kind, 'reply'), inArray(reviewReplies.noteId, [...notes.rounds]))]),
    ...(notes.commands.length === 0
      ? []
      : [
          and(
            eq(reviewReplies.kind, 'command'),
            inArray(reviewReplies.noteId, [...notes.commands]),
          ),
        ]),
  ];
  const held = { rounds: new Set<number>(), commands: new Set<number>() };
  if (kinds.length === 0) return held;
  const rows = await db
    .select({ kind: reviewReplies.kind, noteId: reviewReplies.noteId })
    .from(reviewReplies)
    .where(
      and(
        eq(reviewReplies.projectId, ctx.projectId),
        eq(reviewReplies.provider, ctx.provider),
        or(...kinds),
      ),
    );
  for (const row of rows) (row.kind === 'reply' ? held.rounds : held.commands).add(row.noteId);
  return held;
}

/**
 * The threads among `rounds` that have had {@link MAX_ROUNDS_PER_THREAD_PER_DAY} rounds since
 * `dayStart` (a row of the ledger each, whatever became of it), by one read of the threads' index.
 */
async function busyThreads(
  db: Executor,
  ctx: ReplyContext,
  rounds: readonly Round[],
  dayStart: Date,
): Promise<Set<string>> {
  if (rounds.length === 0) return new Set();
  const rows = await db
    .select({ threadId: reviewReplies.threadId, rounds: count() })
    .from(reviewReplies)
    .where(
      and(
        eq(reviewReplies.branchId, ctx.branchId),
        inArray(reviewReplies.threadId, [...new Set(rounds.map((round) => round.threadId))]),
        eq(reviewReplies.kind, 'reply'),
        gte(reviewReplies.createdAt, dayStart),
      ),
    )
    .groupBy(reviewReplies.threadId);
  return new Set(
    rows.flatMap((row) =>
      row.threadId !== null && row.rounds >= MAX_ROUNDS_PER_THREAD_PER_DAY ? [row.threadId] : [],
    ),
  );
}

/**
 * The rounds and commands of `found` that are the project's to queue and new to its ledger. The
 * ones detection handed over again are dropped before the caps count anything: detection has no
 * ledger bound for a command, and a round the ledger holds was queued by a pass that ran at the
 * same time. So is a round of a thread that has had its rounds of the day (`busyThreads`): its
 * notes stay unqueued, so a pass of a later day finds them again.
 */
async function newNotes(
  db: Executor,
  ctx: ReplyContext,
  found: { rounds: readonly Round[]; commands: readonly CommandNote[] },
  dayStart: Date,
): Promise<{ rounds: Round[]; commands: CommandNote[] }> {
  const rounds = await ownRounds(db, ctx, found.rounds);
  const held = await heldNotes(db, ctx, {
    rounds: rounds.map((round) => round.newest),
    commands: found.commands.map((note) => note.noteId),
  });
  const fresh = rounds.filter((round) => !held.rounds.has(round.newest));
  const busy = await busyThreads(db, ctx, fresh, dayStart);
  return {
    rounds: fresh.filter((round) => !busy.has(round.threadId)),
    commands: found.commands.filter((note) => !held.commands.has(note.noteId)),
  };
}

/**
 * Writes the rows of `rounds` (the ledger's row of a round is its newest note's), the first
 * {@link MAX_QUEUED_ROUNDS} by note id; a round the ledger cannot hold is left out and takes no
 * place. Answers the ids of the rows it made.
 */
function insertRounds(
  db: Executor,
  ctx: ReplyContext,
  rounds: readonly Round[],
): Promise<string[]> {
  const queued = oldest(
    rounds.filter((round) => THREAD_ID.test(round.threadId)),
    (round) => round.newest,
    MAX_QUEUED_ROUNDS,
  );
  return insertReplies(
    db,
    queued.map((round) => ({
      projectId: ctx.projectId,
      branchId: ctx.branchId,
      provider: ctx.provider,
      noteId: round.newest,
      threadId: round.threadId,
      issueId: round.issueId,
      kind: 'reply',
      author: round.author.slice(0, MAX_AUTHOR_CHARS),
    })),
  );
}

/**
 * Writes the rows of the commands in `notes`, as {@link insertRounds} writes rounds, the first
 * {@link MAX_QUEUED_COMMANDS}. A GitLab command has the discussion it opened, and an Azure DevOps
 * one the thread, which its answer goes into; a GitHub one is in no thread.
 */
function insertCommands(
  db: Executor,
  ctx: ReplyContext,
  notes: readonly CommandNote[],
): Promise<string[]> {
  const queued = oldest(
    notes.filter((note) => note.threadId === null || THREAD_ID.test(note.threadId)),
    (note) => note.noteId,
    MAX_QUEUED_COMMANDS,
  );
  return insertReplies(
    db,
    queued.map((note) => ({
      projectId: ctx.projectId,
      branchId: ctx.branchId,
      provider: ctx.provider,
      noteId: note.noteId,
      threadId: note.threadId,
      kind: 'command',
      command: note.command,
      author: note.author.slice(0, MAX_AUTHOR_CHARS),
    })),
  );
}

/** What {@link requeueBudgetSkips} may queue again. */
interface RequeueBounds {
  /** Only skips that ended before this: the start of the day, which has a budget of its own. */
  dayStart: Date;
  /**
   * Only rows made at or after this, as detection counts notes ({@link repliesSince}). An older
   * row has aged out: queued again it would end skipped again with a new end, and housekeeping,
   * which deletes a finished row by its end, would never reach it.
   */
  since: Date;
  /** The most replies, and the most commands, to queue again: the room the caps have left. */
  rounds: number;
  commands: number;
}

/**
 * Moves the branch's replies and commands that were skipped for the day's budget back to `queued`
 * (a new day has a new budget), within `bounds`: skips of an earlier day, whose row is no older
 * than the window, the oldest note first up to the room of each kind. Only the newest row of a
 * thread: the newer round of a thread reads its older notes anyway. Their end is cleared and their
 * start is kept (a queued row may have one: the job that takes it starts it again). Answers their
 * ids, the oldest note first. The others stay as they are: a skip of the day itself until the day
 * is over, an aged row for housekeeping, a row with a newer one in its thread for good, the rest
 * for a later pass. A row that two writers choose at once is queued again by one of them.
 */
async function requeueBudgetSkips(
  db: Executor,
  branchId: string,
  bounds: RequeueBounds,
): Promise<string[]> {
  const skippedForBudget = and(
    eq(reviewReplies.status, 'skipped'),
    eq(reviewReplies.reason, 'budget_spent'),
  );
  const newer = alias(reviewReplies, 'newer');
  /** Whether the thread of the row has a row of a newer note; a row in no thread has none. */
  const hasNewerRow = () =>
    db
      .select({ one: sql`1` })
      .from(newer)
      .where(
        and(
          eq(newer.branchId, reviewReplies.branchId),
          eq(newer.threadId, reviewReplies.threadId),
          gt(newer.noteId, reviewReplies.noteId),
        ),
      );
  const oldestSkips = (kind: ReplyKind, room: number) =>
    db
      .select({ id: reviewReplies.id })
      .from(reviewReplies)
      .where(
        and(
          eq(reviewReplies.branchId, branchId),
          eq(reviewReplies.kind, kind),
          skippedForBudget,
          lt(reviewReplies.finishedAt, bounds.dayStart),
          gte(reviewReplies.createdAt, bounds.since),
          notExists(hasNewerRow()),
        ),
      )
      .orderBy(asc(reviewReplies.noteId))
      .limit(room);
  const requeued = await db
    .update(reviewReplies)
    .set({ status: 'queued', outcome: null, reason: null, finishedAt: null })
    .where(
      and(
        eq(reviewReplies.branchId, branchId),
        // Again what makes a row a skip for the budget: one another writer queued meanwhile is no
        // longer one, and is left to that writer.
        skippedForBudget,
        or(
          inArray(reviewReplies.id, oldestSkips('reply', bounds.rounds)),
          inArray(reviewReplies.id, oldestSkips('command', bounds.commands)),
        ),
      ),
    )
    .returning({ id: reviewReplies.id, noteId: reviewReplies.noteId });
  return requeued.toSorted((a, b) => a.noteId - b.noteId).map((row) => row.id);
}

/**
 * What a decoration (or a webhook's scan) does with the notes it found, in one transaction. The
 * rounds and commands are the project's and new to its ledger (`newNotes`); their rows are written
 * first, within the caps; the replies skipped for the budget of an earlier day are queued again in
 * the room those leave (`requeueBudgetSkips`, within `window`: a row older than the window stays
 * as it is); and each row written or queued again has its answer job, the requeued ones first:
 * their notes are the older. A row and its job are written together or not at all. Answers how
 * many jobs it queued.
 */
export async function queueReplies(
  db: Db,
  ctx: ReplyContext,
  window: Pick<ReplyWindow, 'since'>,
  found: { rounds: readonly Round[]; commands: readonly CommandNote[] },
  now: Date = new Date(),
): Promise<number> {
  const dayStart = utcDayStart(now);
  return db.transaction(async (tx) => {
    const fresh = await newNotes(tx, ctx, found, dayStart);
    const rounds = await insertRounds(tx, ctx, fresh.rounds);
    const commands = await insertCommands(tx, ctx, fresh.commands);
    const again = await requeueBudgetSkips(tx, ctx.branchId, {
      dayStart,
      since: window.since,
      rounds: MAX_QUEUED_ROUNDS - rounds.length,
      commands: MAX_QUEUED_COMMANDS - commands.length,
    });
    const answered = [...again, ...rounds, ...commands];
    await enqueueAnswers(tx, ctx.branchId, answered);
    return answered.length;
  });
}

/** The merge request a pass queues the answers of, for the ledger's rows. */
type AnswerIds = Pick<ReplyContext, 'projectId' | 'branchId'>;

/**
 * Queues the answers to what people wrote in a GitLab merge request (6I-4): the new replies in
 * Qualor's threads and the commands among `discussions`, as the listing a decoration or a scan
 * read holds them, cut by the page bound or not: a note it saw is a note, and the threads it did
 * not see wait for a later pass. `botId` is Qualor's own GitLab user. Reads nothing from GitLab.
 * Without a `window` AI review is not active for the project, and Qualor answers none. Answers how
 * many jobs it queued.
 */
export async function queueGitLabAnswers(
  db: Db,
  ids: AnswerIds,
  window: ReplyWindow | null,
  botId: number,
  discussions: readonly GitLabDiscussion[],
): Promise<number> {
  if (window === null) return 0;
  const options = { qualor: { gitlabUserId: botId }, ...window };
  return queueReplies(db, { ...ids, provider: 'gitlab' }, window, {
    rounds: gitlabRounds(discussions, options),
    commands: gitlabCommands(discussions, options),
  });
}

/**
 * Queues the answers to what people wrote in a GitHub pull request (6I-4): the new `rounds` of its
 * review threads, found where the listing of the review comments and threads was read (the
 * decoration's plan, or a scan: `githubRounds`), and the commands among `comments`, the comments
 * on the pull request's own page. `login` is the App's `<slug>[bot]`. Reads nothing from GitHub.
 * Without a `window` AI review is not active for the project, and Qualor answers none. Answers how
 * many jobs it queued.
 */
export async function queueGitHubAnswers(
  db: Db,
  ids: AnswerIds,
  window: ReplyWindow | null,
  login: string,
  found: { rounds: readonly Round[]; comments: readonly GitHubComment[] },
): Promise<number> {
  if (window === null) return 0;
  const options = { qualor: { githubLogin: login }, ...window };
  return queueReplies(db, { ...ids, provider: 'github' }, window, {
    rounds: found.rounds,
    commands: githubCommands(found.comments, options),
  });
}

/**
 * Queues the answers to what people wrote in an Azure DevOps pull request (Azure sub-plan 5): the
 * new replies in Qualor's threads and the commands among `threads`, the pull request's threads as
 * the listing a decoration or a scan read holds them (Azure DevOps lists them all in one answer).
 * `identityId` is Qualor's identity in Azure DevOps. Each note is a comment's `azureNoteId`, the
 * thread's id and the comment's in one number, so comment 1 of two threads is two notes. Reads
 * nothing from Azure DevOps. Without a `window` AI review is not active for the project, and
 * Qualor answers none. Answers how many jobs it queued.
 */
export async function queueAzureAnswers(
  db: Db,
  ids: AnswerIds,
  window: ReplyWindow | null,
  identityId: string,
  threads: readonly AzureThread[],
): Promise<number> {
  if (window === null) return 0;
  const options = { qualor: { azureIdentityId: identityId }, ...window };
  return queueReplies(db, { ...ids, provider: 'azure' }, window, {
    rounds: azureRounds(threads, options),
    commands: azureCommands(threads, options),
  });
}
