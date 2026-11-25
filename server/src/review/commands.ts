import { eq } from 'drizzle-orm';
import type { Db, Tx } from '../db/client';
import { analyses, branches, reviewReplies, reviewRuns, reviewSnapshots } from '../db/schema';
import type { StoredLlmSettings } from '../llm/settings';
import type { WorkerLogger } from '../queue/worker';
import { codeSpan } from '../scm/markdown';
import { lockBranchQueue } from '../scm/queue';
import { recordCommandDecision, type ReplyOutcome, type ReplyRow } from './replies';
import { requestReviewRun } from './runs';
import { reviewActive } from './settings';

/*
 * What a person asks of Qualor in a note of a merge request: `qualor review`, `qualor fix` or
 * `qualor stop`, which `parseCommand` reads (command-parse.ts). `handleCommand` decides what a
 * command row of the replies ledger comes to, for the answer job (reply-commands.ts). A command
 * makes no model call, and every answer is Qualor's fixed text, with a commit in a code span: no
 * word of the person who wrote the note is in it. `qualor review` costs a review, so only someone
 * with the rights a reply needs to change a finding's status may ask for one; `qualor fix` and
 * `qualor stop` are answered for everyone, as they do nothing yet.
 */

/** How a command came out, and the fixed text of Qualor's answer. */
export interface CommandDecision {
  outcome: ReplyOutcome;
  text: string;
}

/**
 * Whether the author of a `qualor review` has the rights it needs; `unreadable` when Qualor's own
 * credential was refused the reads that tell (Azure DevOps: a scope or right its identity lacks).
 */
export type ReviewRight = boolean | 'unreadable';

/** What the answer job has loaded when it asks for a decision. */
export interface CommandContext {
  /** The stored AI settings: whether AI review is active for the project now. */
  settings: StoredLlmSettings;
  project: { id: string; organizationId: string; scmConnectionId: string | null };
  branch: { id: string };
  logger: Pick<WorkerLogger, 'info' | 'warn'>;
  /**
   * Whether the author of the command's note has the SCM rights `qualor review` needs (the ones a
   * reply needs to change a finding's status). The job asks the provider for a `qualor review`
   * that has no decision yet, and says false otherwise: only such a command looks at it.
   * `unreadable`: Qualor's own credential could not read the rights, which blames no author.
   */
  authorMayReview: ReviewRight;
}

/**
 * The merge request has no newest analysis, or it names no commit: there is nothing to review. It
 * cannot happen while the branch has an analysis, so the job ends the row `failed: internal`, with
 * no answer.
 */
export class NothingToReview extends Error {
  constructor() {
    super('the merge request has no analysis to review');
    this.name = 'NothingToReview';
  }
}

const NOT_AVAILABLE = 'Auto-fix is not switched on for this project.';
const NOT_A_MEMBER = 'Only project members can ask for an AI review.';
/**
 * The rights of the author could not be read: Azure DevOps refused Qualor's own identities or
 * permissions read (check 1 of 2026-11-25: a personal access token with Code only answered 401).
 */
const RIGHTS_UNREADABLE =
  'Qualor could not check your rights: its Azure DevOps credential cannot read identities and permissions (a personal access token needs the Identity (Read) scope).';
const REVIEW_OFF = 'AI review is not switched on for this project.';
const IN_PROGRESS = 'A review of this commit is in progress.';
/** A commit as the review summary writes it: its first 12 characters, in a code span. */
const commit = (sha: string): string => codeSpan(sha.slice(0, 12));
const reviewedText = (sha: string): string =>
  `This commit (${commit(sha)}) has been reviewed. Push a new commit to review again.`;
const requestedText = (sha: string): string => `Reviewing this commit (${commit(sha)}).`;

/** What is already stored on the row: the decision a job that ran before made. */
async function storedDecision(tx: Tx, id: string): Promise<CommandDecision | null> {
  const [found] = await tx
    .select({ answer: reviewReplies.answer, outcome: reviewReplies.outcome })
    .from(reviewReplies)
    .where(eq(reviewReplies.id, id));
  return found === undefined || found.answer === null || found.outcome === null
    ? null
    : { outcome: found.outcome, text: found.answer };
}

/**
 * The commit the review of the analysis is about: the run's head when it has one, else the head of
 * the analysis' snapshot, else the commit the analysis was made of.
 */
async function commitOf(tx: Tx, analysisId: string, runHead: string | null): Promise<string> {
  if (runHead !== null) return runHead;
  const [found] = await tx
    .select({ snapshot: reviewSnapshots.headSha, revision: analyses.revision })
    .from(analyses)
    .leftJoin(reviewSnapshots, eq(reviewSnapshots.analysisId, analyses.id))
    .where(eq(analyses.id, analysisId));
  const sha = found?.snapshot ?? found?.revision ?? null;
  if (sha === null) throw new NothingToReview();
  return sha;
}

/**
 * `qualor review`. Someone without the rights is refused, before anything else: no run is made,
 * started again or looked at, and AI review being off is not said; rights Qualor's own credential
 * could not read are refused alike, with a text that names that credential. Otherwise the run of
 * the branch's newest analysis, as it is under the branch's lock: a review that was done (or found
 * the same diff as the last one that was) is not repeated, one that waits or runs is not asked for
 * twice, and any other run (or none) is made or started again for the person who asked.
 */
async function reviewDecision(
  tx: Tx,
  row: ReplyRow,
  ctx: CommandContext,
): Promise<CommandDecision> {
  if (ctx.authorMayReview === 'unreadable') {
    return { outcome: 'not_available', text: RIGHTS_UNREADABLE };
  }
  if (!ctx.authorMayReview) return { outcome: 'not_available', text: NOT_A_MEMBER };
  if (!reviewActive(ctx.settings, ctx.project).active) {
    return { outcome: 'review_off', text: REVIEW_OFF };
  }
  // Read under the lock: an ingestion that held it has committed its analysis by now.
  const [branch] = await tx
    .select({ analysisId: branches.lastAnalysisId })
    .from(branches)
    .where(eq(branches.id, ctx.branch.id));
  const analysisId = branch?.analysisId ?? null;
  if (analysisId === null) throw new NothingToReview();
  const [run] = await tx
    .select({ status: reviewRuns.status, reason: reviewRuns.reason, headSha: reviewRuns.headSha })
    .from(reviewRuns)
    .where(eq(reviewRuns.analysisId, analysisId))
    .for('update');
  if (run?.status === 'waiting' || run?.status === 'running') {
    return { outcome: 'in_progress', text: IN_PROGRESS };
  }
  // Named before the run is started again, which clears the head the earlier try held.
  const sha = await commitOf(tx, analysisId, run?.headSha ?? null);
  if (run?.status === 'done' || (run?.status === 'skipped' && run.reason === 'unchanged')) {
    return { outcome: 'already_reviewed', text: reviewedText(sha) };
  }
  await requestReviewRun(
    tx,
    { analysisId, projectId: ctx.project.id, branchId: ctx.branch.id, requestedBy: row.author },
    ctx.logger,
  );
  return { outcome: 'review_requested', text: requestedText(sha) };
}

/**
 * What the command row comes to, in one transaction: the outcome and the fixed text of the answer,
 * and for `qualor review` the run that is made or started again, which the transaction carries out.
 * The decision is stored on the row (`answer` and `outcome`, written once), so that a job that
 * takes the row again finds it and decides nothing a second time: a row that restarted a run is
 * not answered "in progress" for it by its own retry, and a refusal is not asked again. `qualor
 * review` takes the branch's decoration lock and then the run's row, in the order ingestion and the
 * review job take them, so that the runs of a merge request are never made or restarted twice: the
 * second of two notes written together finds the run waiting. Throws NothingToReview for a branch
 * with no newest analysis.
 */
export async function handleCommand(
  db: Db,
  row: ReplyRow,
  ctx: CommandContext,
): Promise<CommandDecision> {
  const { command } = row;
  if (command === null) throw new Error('the row of the replies ledger is no command');
  return db.transaction(async (tx) => {
    if (command === 'review') await lockBranchQueue(tx, ctx.branch.id);
    const stored = await storedDecision(tx, row.id);
    if (stored !== null) return stored;
    // `qualor fix` and `qualor stop` command an auto-fix that no project has yet.
    const decision: CommandDecision =
      command === 'review'
        ? await reviewDecision(tx, row, ctx)
        : { outcome: 'not_available', text: NOT_AVAILABLE };
    await recordCommandDecision(tx, row.id, decision);
    return decision;
  });
}
