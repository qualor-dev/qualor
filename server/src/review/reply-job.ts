import { and, desc, eq, gt, inArray, isNotNull, lt, max, or } from 'drizzle-orm';
import { assertNever } from '@qualor/shared';
import { SYSTEM_ACTOR } from '../audit/recorder';
import type { Db } from '../db/client';
import {
  issues,
  projects,
  reviewFindings,
  reviewReplies,
  reviewSnapshots,
  rules,
  type ReplyOutcome,
} from '../db/schema';
import { transitionAsSystem } from '../issues/transitions';
import { readLlmSettings, type StoredLlmSettings } from '../llm/settings';
import type { JobHandlers } from '../queue/worker';
import { AI_ENGINE } from '../rules/server-engines';
import type { IssueStatus } from '../tracking/plan';
import type { ReviewJobDeps } from './job';
import { ofBranch } from './lifecycle';
import { replyNote } from './render';
import {
  claimReply,
  recordAnswerNote,
  recordDecision,
  recordStatusChange,
  type ReplyDecision,
  type ReplyEnd,
  type ReplyRow,
} from './replies';
import { answerCommand } from './reply-commands';
import { decideReply, replyTokensLeft, type ReplyDeps, type ReplyIssue } from './reply-engine';
import {
  AI_REPLY_QUEUE,
  queueAfterCircuit,
  queueAfterStop,
  REPLY_CIRCUIT_WAIT_SECONDS,
  REPLY_MAX_AGE_DAYS,
  replyPayload,
  withLiveJob,
} from './reply-queue';
import { scanMergeRequest } from './reply-scan';
import {
  azureSide,
  GONE,
  githubSide,
  gitlabSide,
  orGone,
  providerClientOf,
  type ReadThread,
  type ReplyInThread,
  type ThreadNote,
  type ThreadSide,
} from './reply-sides';
import {
  circuitWaitSeconds,
  CLOSED,
  JobSteps,
  targetOf,
  THREAD_GONE,
  WAITING,
  type Target,
} from './reply-steps';
import { reviewActive } from './settings';
import { openSnapshotReader, type SnapshotReader } from './snapshot-reader';

/*
 * The `ai-reply` jobs (6I-4): Qualor's answer to a round of people's replies in one of its
 * threads, or to a person's command, which decoration (or a webhook's scan) wrote as a row of the
 * replies ledger with its job (reply-queue.ts). The job takes the row (a row queued longer ago than
 * the reply window, which waited that long for a failing SCM connection or model provider, ends
 * `skipped: expired`) and then, for a reply, in this order, each step written on the row, or found
 * again where it was done, so that a retry resumes after the last one:
 * 1. AI review no longer active for the project ends the row `skipped: inactive`;
 * 2. with no decision yet, a day with no tokens left for it ends it `skipped: budget_spent`, and a
 *    newer round of its thread that was answered, posted its answer, or holds a decision and is
 *    alive (that round read this row's notes too: `coveredByNewer`) `skipped: superseded`, before
 *    anything is read or sent;
 * 3. the merge request is read, as the review job reads it: merged or closed ends the row
 *    `skipped: closed`. The thread is read again through the job's own client: one that is gone
 *    ends it `skipped: thread_gone`, and so does one that someone resolved before Qualor answered,
 *    unless the row already changed the status;
 * 4. with no decision yet, the model decides (reply-engine.ts) over the people's notes of the round,
 *    with the rights in the SCM of those who wrote them, and the decision is stored: the model is
 *    never asked twice for one row. A row put back in the queue runs behind the jobs queued before
 *    it, so a row that has neither changed the status nor posted its answer is then skipped as
 *    superseded, its decision dropped, when a newer round covers it meanwhile (as in 2). A row
 *    that has done either finishes, whatever newer rows did: its effect happened, and its answer
 *    says so;
 * 5. a verdict that is not `keep` changes the status of the thread's open AI finding, as the
 *    system's change (transitions.ts), recorded on the row with it, so that it is made once. It is
 *    never made once the answer is posted (the answer said what the reply changed), and always
 *    before the thread is resolved: decoration reopens a thread Qualor resolved while its finding is
 *    open;
 * 6. the answer is posted once: a note of Qualor's in the thread whose first line names the row is
 *    the answer a post stored though its outcome was lost, and is not posted again;
 * 7. a verdict that is not `keep` resolves the thread, where the provider lets Qualor: a GitHub
 *    App without Contents (write) leaves it open, which one line says;
 * 8. the row ends `done`, with what came of it.
 * The row's issue must be its project's, before the decision and before the thread is acted on (a
 * monorepo's thread of another project's issue never is): otherwise the row ends `failed: internal`.
 *
 * A command row (`qualor review`, `qualor fix`, `qualor stop`) is taken in the same way and makes
 * no model call, and asks no budget: reply-commands.ts answers it.
 *
 * The job's own requests pass the connection's circuit as the `scm` worker's jobs do (scm.md
 * §4.2), in two goes, so that no probe of it waits on the model: the merge request, the thread and
 * the round's rights (3 and 4) before the model is asked, and the status change, the post and the
 * resolution (5 to 7) after it; for a command, the merge request and its discussion before the
 * decision, and the post after it. A circuit that is open, or half-open with another job's probe in
 * flight, puts the row back in the queue for when it lets a job through, with no try spent and
 * nothing changed by that go; the circuit hears what came of the requests it let through. The
 * model provider's circuit, which the calls of the model pass (usage.ts), does the same for a row
 * the model has yet to decide: asked right after the day's budget, before any request to GitLab
 * or GitHub or any masking, it puts the row back unless it would let the job through (closed, or
 * half-open with this job as its probe), and a call it refuses later does the same, with nothing
 * decided. The organisation's slots are the decorations': the job takes none.
 *
 * A stop of the server while the model decides puts the row back in the queue for the next server;
 * AI review switched off meanwhile ends it `skipped: inactive`. Any other error fails the job into
 * its second try, which resumes; a row left running after both is the sweep's (reply-queue.ts).
 * Nothing the people or the model wrote is ever logged: the row's id, codes and counts only.
 */

/** What the model decided on a row: its verdict, and the answer it wrote. */
type Decided = Pick<ReplyDecision, 'verdict' | 'answer'>;

/** The round of a row with no decision yet: the people's notes it answers, and their rights. */
interface PendingRound {
  notes: ThreadNote[];
  /** Whether every author of the notes may change the finding's status. */
  mayChangeStatus: boolean;
}

/**
 * What the job reads before the model is asked: the thread, the answer posted already (on the row,
 * or found in the thread), and the row's decision or, with none yet, its round.
 */
type Seen = { thread: ReadThread; posted: number | null } & (
  { decided: Decided } | { round: PendingRound }
);

/** What a reply that changed no status came to: nothing posted, or an answer, of the AI review's finding or not. */
function unchangedOutcome(noteId: number | null, issue: ReplyIssue): ReplyOutcome {
  if (noteId === null) return 'acknowledged';
  return issue.engine === AI_ENGINE ? 'answered' : 'explained';
}

/**
 * Whether a request is left once the decision is known: the answer to post, or the thread to
 * resolve. A verdict that is not `keep` with no answer posted always has one: the resolution, or,
 * in a thread resolved meanwhile, the post that says what its row changed.
 */
function requestLeft(decision: Decided, seen: Seen): boolean {
  if (decision.verdict === 'keep') return seen.posted === null && decision.answer !== '';
  return seen.posted === null || !seen.thread.resolved;
}

/** What a row in a thread needs, once the checks before the first go are passed. */
interface Ready {
  issue: ReplyIssue;
  side: ThreadSide;
  replyDeps: ReplyDeps;
}

/**
 * The row's issue as the reply conversation is told of it, when it is an issue of the row's
 * project; null when it is not, or is gone. Its lines and line hash are the issue row's, and an AI
 * finding's body, suggestion and reviewed head are its finding row's.
 */
async function issueOf(db: Db, row: ReplyInThread): Promise<ReplyIssue | null> {
  const [found] = await db
    .select({
      projectId: issues.projectId,
      status: issues.status,
      message: issues.message,
      path: issues.path,
      line: issues.startLine,
      endLine: issues.endLine,
      lineHash: issues.lineHash,
      engine: rules.engineId,
      ruleKey: rules.key,
      aiBody: reviewFindings.body,
      suggestion: reviewFindings.suggestion,
      reviewedHeadSha: reviewFindings.reviewedHeadSha,
    })
    .from(issues)
    .innerJoin(rules, eq(rules.id, issues.ruleId))
    .leftJoin(reviewFindings, eq(reviewFindings.issueId, issues.id))
    .where(eq(issues.id, row.issueId));
  if (found === undefined || found.projectId !== row.projectId) return null;
  return {
    engine: found.engine,
    ruleKey: found.ruleKey,
    message: found.message,
    path: found.path,
    line: found.line,
    endLine: found.endLine,
    reviewedHeadSha: found.reviewedHeadSha ?? null,
    lineHash: found.lineHash,
    status: found.status as IssueStatus,
    aiBody: found.aiBody ?? null,
    suggestion: found.suggestion ?? null,
  };
}

/**
 * The newest note of the thread whose round was answered (its row ended `done`) before the row's,
 * or 0: the round's notes are the ones after it. A note whose row was skipped or failed is read
 * again by the next round.
 */
async function lastAnsweredNote(db: Db, row: ReplyInThread): Promise<number> {
  const [found] = await db
    .select({ noteId: max(reviewReplies.noteId) })
    .from(reviewReplies)
    .where(
      and(
        eq(reviewReplies.branchId, row.branchId),
        eq(reviewReplies.threadId, row.threadId),
        eq(reviewReplies.kind, 'reply'),
        eq(reviewReplies.status, 'done'),
        lt(reviewReplies.noteId, row.noteId),
      ),
    );
  return found?.noteId ?? 0;
}

/**
 * Whether a newer round of the row's thread covers its notes: the reply of a later note of the
 * same thread of the same merge request was answered (`done`), or its answer was posted whatever
 * ended it, or it holds a decision and is alive, queued or running with its job there. That round
 * read this row's notes too (they come after the thread's last answered round), so the row is not
 * answered again; and should it fail later, a later round reads them once more, as a superseded row
 * is skipped, not done. A newer row that ended `failed` or `skipped` with its decision kept and
 * nothing posted (the sweep's end, `thread_gone`, `closed` and `inactive` keep it) covers nothing,
 * nor does a running one whose job is gone for good (the sweep's next): its round is never
 * answered, so this row answers its own notes.
 */
async function coveredByNewer(db: Db, row: ReplyInThread): Promise<boolean> {
  const [newer] = await db
    .select({ id: reviewReplies.id })
    .from(reviewReplies)
    .where(
      and(
        eq(reviewReplies.branchId, row.branchId),
        eq(reviewReplies.threadId, row.threadId),
        eq(reviewReplies.kind, 'reply'),
        gt(reviewReplies.noteId, row.noteId),
        or(
          eq(reviewReplies.status, 'done'),
          isNotNull(reviewReplies.answerNoteId),
          and(
            isNotNull(reviewReplies.verdict),
            inArray(reviewReplies.status, ['queued', 'running']),
            withLiveJob(),
          ),
        ),
      ),
    )
    .limit(1);
  return newer !== undefined;
}

/**
 * The snapshot the reply's tools read: the ready one of the branch's newest analysis, else the
 * branch's newest ready one; null when the branch has none, and the model then reads no code.
 */
async function snapshotOf(db: Db, branch: Target['branch']): Promise<SnapshotReader | null> {
  const ready = eq(reviewSnapshots.status, 'ready');
  const [newest] =
    branch.lastAnalysisId === null
      ? []
      : await db
          .select({ id: reviewSnapshots.id })
          .from(reviewSnapshots)
          .where(and(eq(reviewSnapshots.analysisId, branch.lastAnalysisId), ready));
  const [found] =
    newest === undefined
      ? await db
          .select({ id: reviewSnapshots.id })
          .from(reviewSnapshots)
          .where(and(ofBranch(db, branch.id), ready))
          .orderBy(desc(reviewSnapshots.createdAt), desc(reviewSnapshots.id))
          .limit(1)
      : [newest];
  return found === undefined ? null : openSnapshotReader(db, found.id);
}

/** The changelog's comment on a status a reply changed: whose reply decided it. */
const statusComment = (verdict: 'wont_fix' | 'false_positive', author: string): string =>
  `${verdict === 'wont_fix' ? "Won't fix" : 'False positive'} after \`${author}\` replied in the merge request.`;

const SUPERSEDED: ReplyEnd = { status: 'skipped', reason: 'superseded', dropDecision: true };

const EXPIRED: ReplyEnd = { status: 'skipped', reason: 'expired' };

/**
 * Whether a row was queued longer ago than the reply window ({@link REPLY_MAX_AGE_DAYS}): it
 * waited that long for an SCM connection or a model provider that was failing, and is not answered
 * now, as detection queues no note that old.
 */
const pastTheWindow = (row: Pick<ReplyRow, 'createdAt'>): boolean =>
  row.createdAt.getTime() < Date.now() - REPLY_MAX_AGE_DAYS * 86_400_000;

class ReplyJob extends JobSteps {
  constructor(
    deps: ReviewJobDeps,
    private readonly replyId: string,
    /** Whether an earlier try of this job ran: one that took the row and left it running. */
    private readonly retry: boolean,
    /** Whether this is the job's last try (its attempts are spent with it). */
    private readonly lastTry: boolean,
  ) {
    super(deps);
  }

  async run(): Promise<void> {
    try {
      await this.answer();
    } catch (err) {
      this.logFailure('AI reply', { replyId: this.replyId }, err, this.lastTry);
      throw err;
    }
  }

  /**
   * The row to answer, a reply or a command: a queued row, taken now; or, on a retry, the one the
   * first try took and left running. Null for anything else: a row taken by another job, ended, or
   * gone.
   */
  private async take(): Promise<ReplyRow | null> {
    const { db } = this.deps;
    const claimed = await claimReply(db, this.replyId);
    if (claimed !== null || !this.retry) return claimed;
    const [running] = await db
      .select()
      .from(reviewReplies)
      .where(and(eq(reviewReplies.id, this.replyId), eq(reviewReplies.status, 'running')));
    return running ?? null;
  }

  private async answer(): Promise<void> {
    const { db } = this.deps;
    const taken = await this.take();
    if (taken === null) return;
    if (pastTheWindow(taken)) return this.end(taken, EXPIRED);
    const target = await targetOf(db, taken.branchId, taken.projectId);
    if (taken.kind === 'command') {
      return target === null
        ? this.failInternal(taken, 'the row has no merge request')
        : answerCommand(this.deps, taken, target);
    }
    if (taken.threadId === null || taken.issueId === null || target === null) {
      return this.failInternal(taken, 'the row has no thread, no issue or no merge request');
    }
    const row: ReplyInThread = { ...taken, threadId: taken.threadId, issueId: taken.issueId };
    return this.answerInThread(row, target);
  }

  /**
   * Answers a reply in its thread: the checks that can end the row first, then what the first go
   * reads, the model's decision, and the rest of the answer.
   */
  private async answerInThread(row: ReplyInThread, target: Target): Promise<void> {
    const { db } = this.deps;
    const ready = await this.checked(row, target);
    if (ready === null) return;
    const { issue, side, replyDeps } = ready;
    const seen = await this.throughCircuit(row, side, () => this.read(row, target, issue, side));
    if (seen === WAITING) return;
    if (seen === CLOSED) return this.end(row, { status: 'skipped', reason: 'closed' });
    if (seen === null) return this.end(row, THREAD_GONE);
    const decision =
      'decided' in seen
        ? seen.decided
        : await this.decide(row, target, issue, seen.thread, seen.round, replyDeps);
    if (decision === null) return;

    // A row that changed the status or posted its answer finishes, whatever newer rows did: its
    // effect happened, and its answer says so. Any other is superseded by a newer round answered or
    // decided meanwhile, and a thread someone resolved before Qualor answered is closed for it.
    const acted = row.outcome !== null || seen.posted !== null;
    if (!acted && (await coveredByNewer(db, row))) return this.end(row, SUPERSEDED);
    if (!acted && seen.thread.resolved) return this.end(row, THREAD_GONE);

    // The rest posts the answer and resolves the thread, as far as either is left to do. When
    // anything is, the rest goes through the circuit as one go, the status change with it, once the
    // issue is found the project's again: a row that waits for the circuit has changed nothing.
    if (!requestLeft(decision, seen)) return this.finish(row, issue, side, seen, decision);
    if ((await issueOf(db, row)) === null) {
      return this.failInternal(row, 'the issue is not of the project of the row');
    }
    await this.throughCircuit(row, side, () => this.finish(row, issue, side, seen, decision));
  }

  /**
   * The checks before anything is read from the provider: that AI review is on, that the row has
   * tokens and a model that is up, that its issue and thread are still there. The row is ended here
   * when one fails, and the result is null.
   */
  private async checked(row: ReplyInThread, target: Target): Promise<Ready | null> {
    const { db } = this.deps;
    const settings = await readLlmSettings(db);
    const provider = settings.provider;
    if (provider === null || !reviewActive(settings, target.project).active) {
      await this.end(row, { status: 'skipped', reason: 'inactive' });
      return null;
    }
    const replyDeps = this.replyDeps(row, settings, target);
    if (row.verdict === null && (await replyTokensLeft(replyDeps, provider)) <= 0) {
      await this.end(row, { status: 'skipped', reason: 'budget_spent' });
      return null;
    }
    // A row the model has yet to decide waits for a model provider that is failing for every caller
    // before anything is read from GitLab or GitHub or masked. Only a job that can be the probe of
    // a half-open circuit goes on.
    if (row.verdict === null && !this.deps.llmCircuit.wouldPass(provider.baseUrl)) {
      await this.waitForModel(row, provider.baseUrl);
      return null;
    }
    const issue = await issueOf(db, row);
    if (issue === null) {
      await this.failInternal(row, 'the issue is not of the project of the row');
      return null;
    }
    // With no decision yet, nothing is read or sent for a round that a newer one covers.
    if (row.verdict === null && (await coveredByNewer(db, row))) {
      await this.end(row, SUPERSEDED);
      return null;
    }
    const side = this.sideOf(row, target);
    if (side === 'gone') {
      await this.end(row, THREAD_GONE);
      return null;
    }
    if (side === 'unusable') {
      await this.failInternal(row, 'the SCM connection of the project cannot be used');
      return null;
    }
    return { issue, side, replyDeps };
  }

  /**
   * What the first go reads. The merge request's state comes first, read as the review job reads it,
   * through no organisation slot: CLOSED when it is merged or closed, and a state that cannot be
   * read lets the job go on. Then the thread again, through the job's own client: null when it is
   * gone or is not read whole, and, for a row with no decision yet, when someone resolved it (it is
   * closed for the round). With no decision on the row yet, also the round: the people's notes after
   * the thread's last answered round, up to the row's own (null when none is left: they were
   * deleted), and whether every author of them may change the status, asked only in an open AI
   * finding's thread (no other can change).
   */
  private async read(
    row: ReplyInThread,
    target: Target,
    issue: ReplyIssue,
    side: ThreadSide,
  ): Promise<Seen | typeof CLOSED | null> {
    const { db } = this.deps;
    if (await this.closed(row, target)) return CLOSED;
    const thread = await orGone(() => side.read());
    if (thread === GONE || thread === null) return null;
    const posted = row.answerNoteId ?? thread.answered;
    if (row.verdict !== null && row.answer !== null) {
      return { thread, posted, decided: { verdict: row.verdict, answer: row.answer } };
    }
    // With no decision yet nothing was posted: a thread someone resolved is closed for the round.
    if (thread.resolved && posted === null) return null;
    const after = await lastAnsweredNote(db, row);
    const notes = thread.notes.filter((note) => note.id > after && note.id <= row.noteId);
    if (notes.length === 0) return null;
    const changeable = issue.engine === AI_ENGINE && issue.status === 'open';
    const mayChangeStatus = changeable && (await side.mayChangeStatus(notes.map((n) => n.id)));
    return { thread, posted, round: { notes, mayChangeStatus } };
  }

  /**
   * The model's decision on the round, stored on the row; null when the row ended instead, or went
   * back to the queue.
   */
  private async decide(
    row: ReplyInThread,
    target: Target,
    issue: ReplyIssue,
    thread: ReadThread,
    round: PendingRound,
    replyDeps: ReplyDeps,
  ): Promise<Decided | null> {
    const { db } = this.deps;
    const snapshot = await snapshotOf(db, target.branch);
    const decided = await decideReply(
      {
        issue,
        firstNote: thread.firstNote,
        notes: round.notes.map(({ author, body }) => ({ author, body })),
        mayChangeStatus: round.mayChangeStatus,
        snapshot,
        snapshotHead: snapshot?.meta.headSha ?? null,
      },
      replyDeps,
    );
    if ('stopped' in decided) {
      if (this.deps.shutdown.aborted) {
        // Nothing was decided: the next server answers it.
        if (await queueAfterStop(db, row)) {
          this.deps.logger.info({ replyId: row.id }, 'AI reply left for the next server');
        }
      } else {
        await this.end(row, { status: 'skipped', reason: 'inactive' });
      }
      return null;
    }
    if ('circuitOpen' in decided) {
      // The circuit closed to the call after the job had passed it (another job took the probe
      // meanwhile): nothing was decided.
      await this.waitForModel(row, replyDeps.settings.provider?.baseUrl ?? null);
      return null;
    }
    if ('failed' in decided) {
      // The row has no detail column: the log says the window was the reason.
      if (decided.detail !== undefined) {
        this.deps.logger.info(
          { replyId: row.id, reason: decided.failed, detail: decided.detail },
          'AI reply failed',
        );
      }
      // A day without room for it skips it: a later day's decoration offers it again.
      await this.end(
        row,
        decided.failed === 'budget_spent'
          ? { status: 'skipped', reason: 'budget_spent' }
          : { status: 'failed', reason: decided.failed },
      );
      return null;
    }
    await recordDecision(db, row.id, {
      verdict: decided.verdict,
      answer: decided.answer,
      ...decided.usage,
    });
    return { verdict: decided.verdict, answer: decided.answer };
  }

  /**
   * Puts the row back in the queue for when the circuit of its model provider (`baseUrl`) lets a call
   * through again, as it waits for its SCM connection's: the provider is failing for every caller,
   * nothing was decided, and no try is spent.
   */
  private async waitForModel(row: ReplyInThread, baseUrl: string | null): Promise<void> {
    const waitSeconds =
      baseUrl === null
        ? REPLY_CIRCUIT_WAIT_SECONDS
        : circuitWaitSeconds(this.deps.llmCircuit, baseUrl);
    if (await queueAfterCircuit(this.deps.db, row, waitSeconds)) {
      this.deps.logger.info(
        { replyId: row.id, retryInSeconds: waitSeconds },
        'AI reply waits for the circuit of its model provider',
      );
    }
  }

  /**
   * The rest of the answer, in this order: the verdict's status change, the answer posted once, and
   * the thread resolved for a verdict that is not `keep`; then the row ends with what came of it.
   */
  private async finish(
    row: ReplyInThread,
    issue: ReplyIssue,
    side: ThreadSide,
    { thread, posted }: Seen,
    { verdict, answer }: Decided,
  ): Promise<void> {
    const { db } = this.deps;
    const changed = verdict === 'keep' ? null : await this.changeStatus(row, verdict, posted);
    let noteId = posted;
    if (noteId === null && (answer !== '' || changed !== null)) {
      const note = await orGone(() => side.post(replyNote(row.id, answer, changed)));
      if (note === GONE) return this.end(row, THREAD_GONE);
      noteId = note;
    }
    if (noteId !== null && row.answerNoteId === null) await recordAnswerNote(db, row.id, noteId);
    // A thread gone once the answer is posted has nothing left to resolve. One the provider does
    // not let Qualor resolve stays open: what the reply did stands, and the row ends as it would.
    if (verdict !== 'keep' && !thread.resolved) {
      const resolved = await orGone(() => side.resolve());
      if (resolved === 'refused') {
        this.deps.logger.warn(
          { replyId: row.id },
          'AI reply could not resolve the conversation: the GitHub App needs Contents: Read and write',
        );
      }
    }

    const outcome: ReplyOutcome = changed ?? unchangedOutcome(noteId, issue);
    return this.end(row, { status: 'done', outcome });
  }

  /**
   * The verdict's status on the row's issue while it is an open finding of the AI review of the
   * row's project, as the system's change, recorded on the row in the same transaction. Answers the
   * verdict when the reply changed the status, now or in an earlier try (which the row records),
   * else null. A status is changed once for a row, whatever became of it since (a person's change
   * after the reply's stands), and never once its answer is `posted`: the answer settled what the
   * reply changed.
   */
  private async changeStatus(
    row: ReplyInThread,
    verdict: 'wont_fix' | 'false_positive',
    posted: number | null,
  ): Promise<'wont_fix' | 'false_positive' | null> {
    if (row.outcome === verdict) return verdict;
    if (posted !== null) return null;
    const { db, audit } = this.deps;
    const issue = await issueOf(db, row);
    if (issue?.engine !== AI_ENGINE || issue.status !== 'open') return null;
    const changed = await db.transaction(async (tx) => {
      const done = await transitionAsSystem(
        tx,
        row.issueId,
        verdict,
        statusComment(verdict, row.author),
        audit === undefined ? undefined : { recorder: audit, context: SYSTEM_ACTOR },
      );
      if (done) await recordStatusChange(tx, row.id, verdict);
      return done;
    });
    return changed ? verdict : null;
  }

  /**
   * The thread's side on the provider the project is mapped to now: `gone` when that is no longer
   * the row's provider, `unusable` when its client cannot be made (a key that no longer decrypts,
   * an address the rules no longer allow) or the ids are none of the provider's.
   */
  private sideOf(row: ReplyInThread, target: Target): ThreadSide | 'gone' | 'unusable' {
    const { connection } = target;
    if (connection === null || connection.provider !== row.provider) return 'gone';
    const found = providerClientOf(this.deps, target);
    if (found === null) return 'unusable';
    const { logger } = this.deps;
    switch (found.provider) {
      case 'github':
        return githubSide(connection.id, found.client, found.repo, found.number, row, logger);
      case 'gitlab':
        return gitlabSide(connection.id, found.client, found.ref, found.iid, row, logger);
      case 'azure':
        return azureSide(connection.id, found.client, found.repositoryId, found.prId, row, logger);
      default:
        return assertNever(found, 'provider');
    }
  }

  /**
   * What the reply conversation needs: the settings read at the start, the organisation's day, and
   * a stop of its own when AI review is no longer active for the project (the settings read again).
   * The merge request's state is not asked again: the first go did.
   */
  private replyDeps(row: ReplyRow, settings: StoredLlmSettings, target: Target): ReplyDeps {
    const { db } = this.deps;
    return {
      db,
      runtime: { circuit: this.deps.llmCircuit },
      config: this.deps.config,
      settings,
      organizationId: target.project.organizationId,
      reply: { id: row.id, projectId: row.projectId },
      shouldStop: async () => {
        const now = await readLlmSettings(db);
        const [project] = await db
          .select({
            id: projects.id,
            organizationId: projects.organizationId,
            scmConnectionId: projects.scmConnectionId,
          })
          .from(projects)
          .where(eq(projects.id, row.projectId));
        return project === undefined || !reviewActive(now, project).active;
      },
      signal: this.deps.shutdown,
      logger: this.deps.logger,
    };
  }
}

/**
 * The `ai-reply` queue's handler (6I-4), run by the review worker before the reviews' (main.ts),
 * with the review worker's deps: an `answer` job answers its row (`ReplyJob`); a `scan` job is a
 * webhook's, and reads a merge request's notes for the ones nobody has queued yet
 * (reply-scan.ts). A payload that does not parse never will: the job completes. An error fails the
 * job into its second try (`AI_REPLY_MAX_ATTEMPTS`), which resumes the row where the first left it,
 * or scans again.
 */
export function replyHandlers(deps: ReviewJobDeps): JobHandlers {
  return {
    [AI_REPLY_QUEUE]: async (job) => {
      const parsed = replyPayload.safeParse(job.payload);
      if (!parsed.success) {
        deps.logger.warn(
          { jobId: job.id, queue: job.queue },
          'malformed AI reply job payload; completing without retry',
        );
        return;
      }
      if (parsed.data.kind === 'scan') {
        await scanMergeRequest(deps, parsed.data.branchId, job.attempts >= job.maxAttempts);
        return;
      }
      await new ReplyJob(
        deps,
        parsed.data.replyId,
        job.attempts > 1,
        job.attempts >= job.maxAttempts,
      ).run();
    },
  };
}
