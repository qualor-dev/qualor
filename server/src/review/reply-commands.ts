import { assertNever } from '@qualor/shared';
import { readLlmSettings } from '../llm/settings';
import { handleCommand, NothingToReview, type CommandDecision, type ReviewRight } from './commands';
import type { ReviewJobDeps } from './job';
import { commandNote } from './render';
import { recordAnswerNote, type ReplyRow } from './replies';
import {
  azureCommandSide,
  GONE,
  githubCommandSide,
  gitlabCommandSide,
  orGone,
  providerClientOf,
  type CommandSide,
} from './reply-sides';
import { CLOSED, JobSteps, THREAD_GONE, WAITING, type Target } from './reply-steps';

/*
 * The `ai-reply` job's answer to a command row (6I-4): `qualor review`, `qualor fix` or
 * `qualor stop`, the first words of a note of a merge request, which decoration (or a webhook's
 * scan) wrote as a row of the replies ledger with its job (reply-queue.ts). The row is taken as a
 * reply's is (reply-job.ts) and makes no model call, and asks no budget. The merge request is read,
 * and one that is merged or closed ends the row `skipped: closed`, with no run made and no answer;
 * the command's own note is read too (a GitLab command's discussion, a GitHub command's comment),
 * and one that is gone ends it `skipped: thread_gone`. For a `qualor review` with no decision yet,
 * one more request asks the provider whether the author of that note has the rights a reply needs
 * to change a status (a review costs tokens). Then `handleCommand` (commands.ts) decides, in one
 * transaction that also makes or restarts the run, and stores the fixed text of the answer on the
 * row, so that a retry never decides twice nor asks for the rights again. The answer is posted
 * once, beside the command's note (a note of Qualor's whose first line names the row is the answer
 * a post stored though its outcome was lost), and the row ends `done` with the decision's outcome:
 * a refusal is `not_available`. AI review being off does not skip a command: it is answered so. A
 * branch with no newest analysis ends the row `failed: internal`, with no answer. A row that has
 * its answer note ends `done` with its outcome at once, with no request: what became of the merge
 * request or of the command's note since changes nothing of an answer that was given.
 *
 * The requests pass the connection's circuit in two goes (reply-steps.ts): the merge request and
 * the command's discussion before the decision, and the post after it, so that a row that waits for
 * the circuit before its decision has made no run.
 */

class CommandFlow extends JobSteps {
  /**
   * A command row, in the steps the header gives. The merge request and the command's discussion
   * are read in a go through the circuit, then the decision is made (no request), and the post is
   * another go: a row that waits for the circuit before its decision has made no run. It resumes
   * after the last step the row records: a decision on it is posted, never made again, and an
   * answer note on it ends the row `done` with its outcome, with no request.
   */
  async answerCommand(row: ReplyRow, target: Target): Promise<void> {
    if (row.answerNoteId !== null && row.outcome !== null) {
      return this.end(row, { status: 'done', outcome: row.outcome });
    }
    const side = this.commandSideOf(row, target);
    if (side === 'gone') return this.end(row, THREAD_GONE);
    if (side === 'unusable') {
      return this.failInternal(row, 'the SCM connection of the project cannot be used');
    }
    const seen = await this.throughCircuit(row, side, () => this.readCommand(row, target, side));
    if (seen === WAITING) return;
    if (seen === CLOSED) return this.end(row, { status: 'skipped', reason: 'closed' });
    if (seen === null) return this.end(row, THREAD_GONE);
    const decision = await this.decideCommand(row, target, seen.mayReview);
    if (decision === null) return;
    const posted = row.answerNoteId ?? seen.answered;
    await this.throughCircuit(row, side, () => this.postCommandAnswer(row, side, posted, decision));
  }

  /**
   * What the first go reads for a command: CLOSED when the merge request is merged or closed; null
   * when the command's discussion is gone; else what the provider holds of the answer, and, for a
   * `qualor review` that has no decision yet, whether its author has the rights it needs (one
   * request). A decision on the row has them in it, and `qualor fix` and `qualor stop` are
   * answered for everyone.
   */
  private async readCommand(
    row: ReplyRow,
    target: Target,
    side: CommandSide,
  ): Promise<{ answered: number | null; mayReview: ReviewRight } | typeof CLOSED | null> {
    if (await this.closed(row, target)) return CLOSED;
    const found = await orGone(() => side.read());
    if (found === GONE || found === null) return null;
    const asks = row.command === 'review' && row.answer === null;
    return { ...found, mayReview: asks && (await side.mayReview()) };
  }

  /**
   * What the command comes to (commands.ts), stored on the row; null when the row ended instead: a
   * branch with no newest analysis has nothing to review.
   */
  private async decideCommand(
    row: ReplyRow,
    target: Target,
    authorMayReview: ReviewRight,
  ): Promise<CommandDecision | null> {
    const { db, logger } = this.deps;
    try {
      return await handleCommand(db, row, {
        settings: await readLlmSettings(db),
        project: target.project,
        branch: target.branch,
        logger,
        authorMayReview,
        azureAuth: target.connection?.azureAuth ?? null,
      });
    } catch (err) {
      if (!(err instanceof NothingToReview)) throw err;
      await this.failInternal(row, 'the merge request has no analysis to review');
      return null;
    }
  }

  /**
   * The answer to a command posted once, beside the command's note: not when `posted` says it is
   * (the row's answer note, or the one found in the first go). The row then ends `done`, with the
   * decision's outcome.
   */
  private async postCommandAnswer(
    row: ReplyRow,
    side: CommandSide,
    posted: number | null,
    decision: CommandDecision,
  ): Promise<void> {
    let noteId = posted;
    if (noteId === null) {
      const note = await orGone(() => side.post(commandNote(row.id, decision.text)));
      if (note === GONE) return this.end(row, THREAD_GONE);
      noteId = note;
    }
    if (row.answerNoteId === null) await recordAnswerNote(this.deps.db, row.id, noteId);
    return this.end(row, { status: 'done', outcome: decision.outcome });
  }

  /**
   * Where the answer to a command goes, on the provider the project is mapped to now: `gone` when
   * that is no longer the row's provider, `unusable` when its client cannot be made (a key that no
   * longer decrypts, an address the rules no longer allow) or the ids are none of the provider's. A
   * GitLab command has the discussion its note opened, an Azure DevOps one the thread its comment
   * opened.
   */
  private commandSideOf(row: ReplyRow, target: Target): CommandSide | 'gone' | 'unusable' {
    const { connection } = target;
    if (connection === null || connection.provider !== row.provider) return 'gone';
    const found = providerClientOf(this.deps, target);
    if (found === null) return 'unusable';
    const { logger } = this.deps;
    switch (found.provider) {
      case 'github':
        return githubCommandSide(
          connection.id,
          found.client,
          found.repo,
          found.number,
          row,
          logger,
        );
      case 'gitlab':
        if (row.threadId === null) return 'unusable';
        return gitlabCommandSide(
          connection.id,
          found.client,
          found.ref,
          found.iid,
          row,
          row.threadId,
          logger,
        );
      case 'azure':
        if (row.threadId === null) return 'unusable';
        return azureCommandSide(
          connection.id,
          found.client,
          found.repositoryId,
          found.prId,
          row,
          row.threadId,
          logger,
        );
      default:
        return assertNever(found, 'provider');
    }
  }
}

/** Answers a command row: the merge request it is about, as `targetOf` (reply-job.ts) found it. */
export function answerCommand(deps: ReviewJobDeps, row: ReplyRow, target: Target): Promise<void> {
  return new CommandFlow(deps).answerCommand(row, target);
}
