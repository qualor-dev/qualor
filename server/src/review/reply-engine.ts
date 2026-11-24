import { parseModelJson, type ScmProvider } from '@qualor/shared';
import type { Config } from '../config';
import type { Executor } from '../db/client';
import { REPLY_VERDICTS, type ReplyVerdict } from '../db/schema';
import { costOf, type LlmRuntime } from '../llm/job';
import {
  excludedPathMatcher,
  pricingFor,
  providerApiKey,
  type PricePair,
  type StoredLlmSettings,
  type StoredProvider,
} from '../llm/settings';
import type { WorkerLogger } from '../queue/worker';
import { AI_ENGINE } from '../rules/server-engines';
import { CONVERSATION_TEXTS, type ConversationInput } from './conversation';
import { envelope, newNonce } from './envelope';
import { lineHashOf } from './findings-render';
import { scrubKeyDeep } from './key-scrub';
import { MaskedFiles, type MaskBudget } from './masked-files';
import { Masker, MaskerClosed } from './masker';
import { modelFor, tierOfCall } from './model-tiers';
import { answerCharLimit, CHARS_PER_TOKEN, REVIEW_OUTPUT_TOKENS } from './pipeline';
import {
  REPLY_LIMITS,
  REPLY_PROMPT_VERSION,
  replyData,
  replyRetryText,
  replySystemPrompt,
  type ReplyData,
  type ReplyIssue,
  type ReplyRefusal,
} from './prompts';
import { REPLY_TOKEN_BUDGET } from './replies';
import { replyAnswerSchema, type ReplyAnswer } from './schemas';
import { effectiveReviewBudgets } from './settings';
import type { SnapshotReader } from './snapshot-reader';
import { converseOverTools, newToolPolicy } from './tool-conversation';
import type { ShownLines } from './tools';
import {
  RedactionTally,
  remainingReviewTokens,
  REVIEW_REPLY_FEATURE,
  reviewCallSettings,
  reviewSender,
  reviewUsageToday,
} from './usage';

export type { ReplyIssue } from './prompts';

/*
 * The answer to a person's reply in a thread Qualor started (6I-4, spec §9): one conversation with
 * the model over the finding, Qualor's first note, the people's notes and, when the merge request
 * has a snapshot, the repository through the review's read-only tools. It decides a verdict and
 * the words of the answer. It posts nothing and writes no ledger row: the job that answers does,
 * from what it returns (reply-job.ts).
 *
 * What the people wrote is untrusted data, and so is Qualor's own note, which for a finding of the
 * AI review holds model text: all of it is masked, cut and put in the data envelope (envelope.ts)
 * with the finding's words. Nothing in it can widen what the thread allows. The model is told which
 * verdicts the thread allows, but the code decides: an answer outside them, or a verdict its intent
 * or the conversation does not bear out, is asked for again once, in the same conversation, with a
 * fixed text that says what was wrong, and then given up (`bad_answer`). So a reply that tries to
 * steer the model can change at most the status of its own thread's finding; only when the people
 * who replied may change a status (the rights the caller read, `mayChangeStatus`, never what the
 * model makes of their words); and only as a person's decision of priority, or a claim that the
 * finding's own lines were really read to confirm, allows. A claim of fact is offered only for
 * code that is the code the finding was made for: its lines are those of the head it was reviewed
 * at, and the snapshot may be of a newer one (`sameCode`).
 *
 * `decideReply` is what the job calls: it takes the day's budget, the model of the reply's tier and
 * the provider's calls, each recorded as a `review-reply` row. `runReplyConversation` is the
 * conversation and its checks, which need no database.
 */

/** What the conversation spent, and the model it went to. */
export interface ReplyUsage {
  model: string;
  inputTokens: number;
  outputTokens: number;
  /** The estimated cost of the calls that were counted; null when no prices are set. */
  costMicroUsd: number | null;
}

/**
 * What a conversation came to: a verdict with the words to post (empty when there is nothing to
 * say), and whether the model read the finding's own lines (a `read_file` that showed a line of
 * them, or a `grep` that matched on one); or why it decided nothing; or that it was stopped (the
 * server is stopping, or the caller asked it to), which is no failure of the answer; or that the
 * provider's circuit was open (`circuitOpen`: the provider is failing for every caller), which
 * decided nothing and is no failure of the answer either: it waits for the circuit. The decision
 * the ledger stores (replies.ts) is another type.
 */
export type DecidedReply =
  | { verdict: ReplyVerdict; answer: string; readCode: boolean; usage: ReplyUsage }
  | {
      failed: 'bad_answer' | 'provider_error' | 'provider_no_tools' | 'budget_spent';
      /** `window_full`: a `provider_error` because no call fit the model's context window. */
      detail?: 'window_full';
    }
  | { stopped: true }
  | { circuitOpen: true };

export interface ReplyInput {
  issue: ReplyIssue;
  /** Qualor's first note of the thread, as it was posted. */
  firstNote: string;
  /** The people's notes of the round, oldest first. */
  notes: readonly { author: string; body: string }[];
  /**
   * Whether every person whose note is in the round may change the issue's status: the SCM rights
   * the caller read (reply-sides.ts). On GitLab an active, current membership of the project at
   * Developer or more; on GitHub the role the collaborator permission API names, `admin`,
   * `maintain`, `write` or `triage`, or for a role it does not name the legacy permission `admin` or
   * `write` (`githubMayTriage`). A status change is a triage decision, and on a public repository
   * anyone can reply: the intent the model reads out of a note is no authorisation.
   */
  mayChangeStatus: boolean;
  /** The snapshot the tools read; null when there is none, and the model is then given no tools. */
  snapshot: SnapshotReader | null;
  /**
   * The head commit of `snapshot` (what `snapshot.meta.headSha` says); null without a snapshot. The
   * finding's lines are those of the head it was made for (`issue.reviewedHeadSha`): the same head
   * has the same code, and the lines of any other are checked against `issue.lineHash` before a
   * reply may call the finding wrong.
   */
  snapshotHead: string | null;
  /** The provider of the merge request, whose own noun the prompt uses; absent: GitLab's. */
  scm?: ScmProvider;
}

/** An open finding of the AI review: the one kind of thread a person's reply may change. */
const changeable = (issue: Pick<ReplyIssue, 'engine' | 'status'>): boolean =>
  issue.engine === AI_ENGINE && issue.status === 'open';

/**
 * The verdicts a thread allows: every one for an open finding of the AI review whose people may
 * change its status (`mayChangeStatus`), which Qualor may then close after a person's reply; `keep`
 * alone for any other, a finding an analyzer reported, one that is no longer open, or one whose
 * people may not change it, which Qualor only answers.
 */
export function allowedVerdicts(
  issue: Pick<ReplyIssue, 'engine' | 'status'>,
  mayChangeStatus: boolean,
): readonly ReplyVerdict[] {
  return changeable(issue) && mayChangeStatus ? REPLY_VERDICTS : ['keep'];
}

/**
 * What is wrong with an answer the thread does not bear out, or null when it does: its verdict is
 * not one of those offered, a `wont_fix` is no decision of priority, or a `false_positive` has the
 * finding's own lines unread (which no tool can mend in the retry, whatever its intent: it comes
 * first) or is no claim of fact. `keep` is what any intent leads to.
 */
function refusalOf(
  answer: ReplyAnswer,
  offered: readonly ReplyVerdict[],
  readCode: boolean,
): ReplyRefusal | null {
  if (!offered.includes(answer.verdict)) return 'verdict';
  switch (answer.verdict) {
    case 'wont_fix':
      return answer.intent === 'priority' ? null : 'wont_fix';
    case 'false_positive':
      if (!readCode) return 'unread';
      return answer.intent === 'factual' ? null : 'false_positive';
    case 'keep':
      return null;
  }
}

/**
 * Whether lines a tool showed are the finding's own: a line of its file within its lines (`line` to
 * `endLine`, or `line` alone when it has no end), or any line of its file for a finding that has a
 * file and no line. A finding with no file has none to show: no path of a tool's answer is null.
 */
function showsFinding(
  issue: Pick<ReplyIssue, 'path' | 'line' | 'endLine'>,
  shown: readonly ShownLines[],
): boolean {
  const { path, line } = issue;
  if (line === null) return shown.some((lines) => lines.path === path);
  // An end before the line makes no range: the finding is its line alone.
  const last = Math.max(line, issue.endLine ?? line);
  return shown.some((lines) => lines.path === path && lines.from <= last && lines.to >= line);
}

/**
 * A text is masked up to this many characters, and a longer one is cut there: what is shown of it
 * is cut shorter still (REPLY_LIMITS). A secret the cut splits is not masked (the rule needs all of
 * it), so what is left of one is not shown either (`CUT_TAIL_LINES`).
 */
export const MASK_INPUT_CHARS = 20_000;
/**
 * The last lines of the masked start of a text that was cut, which are not shown. The redaction
 * joins up to four lines to find a secret split over them, so what the cut leaves of a secret it
 * splits is at most the last three lines of the start, and the empty line a cut at a line end leaves
 * is one more: five are left out, with one to spare. Lines, not characters, bound it however long
 * they are. Without this the cut could fall within what is shown: long secrets before it (a private
 * key, a token) are masked to short lines, and the masked start of the text can shrink to less
 * than a note shows.
 */
const CUT_TAIL_LINES = 5;
/** What a text is shown as when it could not be masked, in time or safely. */
const NOT_MASKED = '[not shown: it could not be masked]';
/**
 * What a text that was cut is shown as when nothing is left of it to show: it was masked, but all
 * of its start is in the lines that the cut may have split (`CUT_TAIL_LINES`).
 */
const TOO_LONG = '[not shown: it is too long]';

/** What `runReplyConversation` is given besides the thread: where its calls go, and its limits. */
export interface ReplyConversationIo {
  /** One call to the provider: the sender of the job records it; its model and prices are its own. */
  send: ConversationInput['send'];
  /** Asked before every call to the provider. */
  shouldStop: ConversationInput['shouldStop'];
  /**
   * Masks the text of the thread and what the tools answer (`Masker`, never closed here): a
   * person may paste a secret in a reply, and none of it goes to the provider.
   */
  masker: Masker;
  /**
   * The most tokens, input and output of all its calls, the conversation keeps to (as far as it can
   * tell ahead: conversation.ts). With 0 or less, or less than its first call needs
   * (`firstCallTokens`), it does not start: `budget_spent`.
   */
  tokenBudget: number;
  /** The provider's API key, taken out of the answer; null when there is none. */
  providerKey: string | null;
  /** The administrator's excluded paths, which the tools never show. */
  excludePaths: readonly string[];
  /** The model the calls go to: the decision's usage names it. */
  model: string;
  /** That model's prices, which cost each call; null: no costs. */
  pricing: PricePair | null;
  /** Told the secrets masked in what each call adds: the first message's, then the tools'. */
  redactions?: RedactionTally;
  /**
   * The signal whose abort stops the answer, which the masker and the sender were given and which
   * ends the wait of a retry: an error that is its reason is its stop (`isAbort`). Without one, a
   * masker that was closed and an `AbortError` are the stop. (A call that the signal gave up is the
   * loop's own stop.)
   */
  signal?: AbortSignal;
  /**
   * The model's context window, in tokens: the provider's `contextWindowTokens` (null or absent:
   * the default, `callInputCap`). No call of the answer sends more than it less the reply's answer.
   */
  contextWindowTokens?: number | null;
}

/**
 * A text of the thread made fit to send: masked (and, when it was cut at MASK_INPUT_CHARS, without
 * the end of what was masked), or a fixed note: for one that could not be masked, in time or
 * safely (a hostile text), and for a cut one with nothing left to show. The secrets masked are
 * counted on `io.redactions`.
 */
async function maskedText(io: ReplyConversationIo, text: string): Promise<string> {
  if (text === '') return text;
  const cut = text.length > MASK_INPUT_CHARS;
  const result = await io.masker.mask(cut ? text.slice(0, MASK_INPUT_CHARS) : text);
  if (result.kind !== 'masked') return NOT_MASKED;
  io.redactions?.add(result.count);
  if (!cut) return result.text;
  // The end of what was masked may hold what the cut left of a secret: it is left out, with a mark
  // that the text goes on, and a text with nothing before it is not shown.
  const lines = result.text.split('\n');
  if (lines.length <= CUT_TAIL_LINES) return TOO_LONG;
  return `${lines.slice(0, -CUT_TAIL_LINES).join('\n')}…`;
}

/**
 * The data of the conversation: every text of the thread masked, then cut (`replyData`), the
 * newest notes of the round (the person who is answered wrote the last) and how many older ones
 * are left out. The authors' names are not text of the repository and are not masked.
 */
async function shownData(input: ReplyInput, io: ReplyConversationIo): Promise<ReplyData> {
  const { issue } = input;
  const newest = input.notes.slice(-REPLY_LIMITS.notes);
  const message = await maskedText(io, issue.message);
  const aiBody = issue.aiBody === null ? null : await maskedText(io, issue.aiBody);
  // The lines of a suggestion are masked as the text they make, which keeps as many of them.
  const suggestionLines =
    issue.suggestion === null || issue.suggestion.lines.length === 0
      ? []
      : (await maskedText(io, issue.suggestion.lines.join('\n'))).split('\n');
  const firstNote = await maskedText(io, input.firstNote);
  const notes: { author: string; body: string }[] = [];
  for (const note of newest) {
    notes.push({ author: note.author, body: await maskedText(io, note.body) });
  }
  return replyData({
    issue: {
      ...issue,
      message,
      aiBody,
      suggestion:
        issue.suggestion === null ? null : { ...issue.suggestion, lines: suggestionLines },
    },
    firstNote,
    notes,
    unlistedNotes: input.notes.length - newest.length,
  });
}

/**
 * Whether the finding's lines are the same code at the snapshot as at the head it was made for: the
 * snapshot is of that head (compared without case), or the file at the snapshot, masked as the review
 * masks it, gives the issue's line hash at its lines (`lineHashOf`, the review's own hashing). A file
 * that is not there or cannot be masked, a finding with no line hash, no line or no path, a line
 * past the end of the file and any other hash are not: the lines can only be trusted when they are
 * shown to be the same. A path the tools never show is not read here either. The file is masked
 * through `files`, which the tools read through next: once, under their budget, and the secrets
 * masked in it are counted with the first call's.
 */
async function sameCode(
  input: ReplyInput,
  files: MaskedFiles,
  budget: MaskBudget,
  io: ReplyConversationIo,
): Promise<boolean> {
  const { issue, snapshotHead } = input;
  const { path, line, lineHash } = issue;
  if (issue.reviewedHeadSha !== null && snapshotHead !== null) {
    if (issue.reviewedHeadSha.toLowerCase() === snapshotHead.toLowerCase()) return true;
  }
  if (path === null || line === null || line < 1 || lineHash === null) return false;
  if (excludedPathMatcher(io.excludePaths)(path)) return false;
  const file = await files.file(path, budget);
  if (file.kind !== 'text') return false;
  io.redactions?.add(file.redactions);
  if (line > file.text.lineCount) return false;
  return lineHashOf(file.text, line, Math.max(line, issue.endLine ?? line)) === lineHash;
}

/**
 * The tokens the first call of a reply takes at the least, guessed before it is made: its system
 * prompt and its first message at the review's characters to a token (CHARS_PER_TOKEN), and the most
 * its answer may write. A budget below it cannot pay for one call, so the reply is not started, as a
 * review is not started below its smallest share. What comes after the first call is paid from what
 * the budget has left.
 */
const firstCallTokens = (system: string, user: string): number =>
  Math.ceil((system.length + user.length) / CHARS_PER_TOKEN) + REVIEW_OUTPUT_TOKENS.reply;

/** The conversation and its checks; `runReplyConversation` turns a stop into its result. */
async function decide(input: ReplyInput, io: ReplyConversationIo): Promise<DecidedReply> {
  const { issue, snapshot } = input;
  // The files of the snapshot as the model may see them, which the check of the finding's lines and
  // the tools share, with the budget of the tools.
  const files = snapshot === null ? null : new MaskedFiles(snapshot, { masker: io.masker });
  const policy =
    files === null
      ? null
      : newToolPolicy({ excludePaths: io.excludePaths, masked: files, masker: io.masker });
  // What the model may choose: what the thread allows, and of that only what it has the means for.
  let offered = allowedVerdicts(issue, input.mayChangeStatus).filter(
    (verdict) => verdict !== 'false_positive' || snapshot !== null,
  );
  // A finding's lines are those of the head it was made for, and the snapshot may be of a newer one:
  // a claim that the finding is wrong is offered only for code that is still its code. The tools
  // stay, so the model can still read and explain.
  if (
    files !== null &&
    policy !== null &&
    offered.includes('false_positive') &&
    !(await sameCode(input, files, policy.budget, io))
  ) {
    offered = offered.filter((verdict) => verdict !== 'false_positive');
  }
  // An open finding of the AI review whose people may not change its status: the prompt says why.
  const membersOnly = changeable(issue) && !input.mayChangeStatus;
  const system = replySystemPrompt({ verdicts: offered, tools: snapshot !== null, membersOnly });
  const nonce = newNonce();
  const user = envelope(await shownData(input, io), nonce);
  // A budget that cannot pay for the first call does not start the reply: no call, no row.
  if (io.tokenBudget < firstCallTokens(system, user)) return { failed: 'budget_spent' };

  /**
   * Whether the model has read the finding's own lines: a `read_file` that showed a line within
   * them, or a `grep` that matched on one, as the tools did it (`showsFinding`). Nothing else is a
   * reading: not a refusal, not a path that is not there, not a search with no match, not another
   * file, not the lines of its file that are not the finding's.
   */
  let readCode = false;
  /**
   * What a text is: the answer, when it is one the thread bears out; or what to say to ask again,
   * which is a fixed text for an answer the gate refuses, and for one that is longer than it is
   * read (the loop's own words for an answer cut off), and false for one that is not the JSON asked
   * for (the loop's other words then).
   */
  const judge = (text: string): { answer: ReplyAnswer } | { retry: string | false } => {
    if (text.length > answerCharLimit('reply')) return { retry: CONVERSATION_TEXTS.shorter };
    const parsed = parseModelJson(text, answerCharLimit('reply'));
    if (parsed === undefined) return { retry: false };
    const checked = replyAnswerSchema.safeParse(scrubKeyDeep(parsed, io.providerKey));
    if (!checked.success) return { retry: false };
    const refusal = refusalOf(checked.data, offered, readCode);
    if (refusal === null) return { answer: checked.data };
    // No tool runs after a refusal, so what was not read stays unread: the retry names the verdicts
    // that can still be given, and false_positive is not one of them then.
    const possible = readCode ? offered : offered.filter((verdict) => verdict !== 'false_positive');
    return { retry: replyRetryText(refusal, possible) };
  };
  let cost = 0;
  const send: ConversationInput['send'] = async (conversation) => {
    const turn = await io.send(conversation);
    cost += costOf(io.pricing, turn.usage) ?? 0;
    return turn;
  };

  const result = await converseOverTools(
    {
      role: 'reply',
      system,
      ...(input.scm === undefined ? {} : { scm: input.scm }),
      user,
      nonce,
      tokenBudget: io.tokenBudget,
      accept: (text) => {
        const judged = judge(text);
        return 'answer' in judged ? true : judged.retry;
      },
    },
    snapshot === null || policy === null
      ? {
          reader: null,
          send,
          shouldStop: io.shouldStop,
          signal: io.signal,
          contextWindowTokens: io.contextWindowTokens,
        }
      : {
          reader: snapshot,
          policy,
          send,
          shouldStop: io.shouldStop,
          signal: io.signal,
          contextWindowTokens: io.contextWindowTokens,
          onToolRedactions: (count) => io.redactions?.add(count),
          onToolRead: (shown) => {
            if (showsFinding(issue, shown)) readCode = true;
          },
        },
  );
  if (result.kind === 'stopped') return { stopped: true };
  if (result.kind === 'failed') {
    if (result.circuitOpen === true) return { circuitOpen: true };
    // The model's context window had no room for a call of the answer: the provider would have
    // refused it, and a reply's row has no other reason for it.
    return result.reason === 'window_full'
      ? { failed: 'provider_error', detail: 'window_full' }
      : { failed: result.reason };
  }
  // Checked again: a conversation that gave an answer back is not believed without it.
  const judged = judge(result.text);
  if (!('answer' in judged)) return { failed: 'bad_answer' };
  return {
    verdict: judged.answer.verdict,
    answer: judged.answer.answer,
    readCode,
    usage: {
      model: io.model,
      inputTokens: result.inputTokens,
      outputTokens: result.outputTokens,
      costMicroUsd: io.pricing === null ? null : cost,
    },
  };
}

/**
 * Whether an error is the stop itself and not a failure: a masker that was closed, an `AbortError`,
 * or the reason of the `signal` that aborted, which is what a masker given it rejects with. Anything
 * else, an error of the database too, is a failure. (A call the signal gave up never gets here: the
 * loop turns it into a stop itself, as `LlmCallAborted`.)
 */
function isAbort(err: unknown, signal: AbortSignal | undefined): boolean {
  if (err instanceof MaskerClosed) return true;
  if (err instanceof Error && err.name === 'AbortError') return true;
  return signal?.aborted === true && err === signal.reason;
}

/**
 * Runs the conversation that answers the reply, and checks what it says. The model is told which
 * verdicts the thread allows, without `false_positive` when there is no snapshot, and is given the
 * review's tools over the snapshot when there is one, with a tool budget of its own. Its last
 * message has to be the JSON of `replyAnswerSchema`, the provider's key taken out, and the thread
 * has to bear it out (`refusalOf`); one that does not is asked for again once, with a fixed text
 * that says what was wrong, and then the conversation fails as a `bad_answer`. What it spent is
 * reported, with the model it went to, when it answers; the cost is that of the calls the provider
 * counted, at `io.pricing`.
 *
 * A stop is `stopped`: the caller asks to stop, or an abort (`isAbort`) gives up a masking while it
 * does, or a call is given up (the loop's stop), which is no error of the answer. Any other error is
 * thrown, as it would be without a stop: a failed insert of a call's row is never taken for one.
 */
export async function runReplyConversation(
  input: ReplyInput,
  io: ReplyConversationIo,
): Promise<DecidedReply> {
  // A budget that is no number is none.
  if (Number.isNaN(io.tokenBudget) || io.tokenBudget <= 0) return { failed: 'budget_spent' };
  try {
    return await decide(input, io);
  } catch (err) {
    if (isAbort(err, io.signal) && (await io.shouldStop())) return { stopped: true };
    throw err;
  }
}

// ─── What the job calls ──────────────────────────────────────────────────────

export interface ReplyDeps {
  db: Executor;
  /** The circuit is the `llm` worker's: the reply and its explain, triage and fix share it. */
  runtime: Pick<LlmRuntime, 'circuit'>;
  config: Pick<Config, 'secretKey' | 'llmInternalHosts'>;
  /** The settings the answer is made with: the provider and its key, the budgets and the prices. */
  settings: StoredLlmSettings;
  /** The organisation whose day the answer draws on. */
  organizationId: string;
  /**
   * The ledger row the answer is for: its project owns the rows of the calls, and its id is the
   * key their stored prompts and log lines carry.
   */
  reply: { id: string; projectId: string };
  /**
   * Asked before every call to the provider: whether the answer should stop for a reason of the
   * caller's (review switched off, the merge request closed). The server stopping always stops it.
   */
  shouldStop?: () => Promise<boolean>;
  /** Gives up the call in flight and the masking when it aborts: the server is stopping. */
  signal?: AbortSignal;
  /** Gets one line for each call: the reply, the outcome and the counts, never what was said. */
  logger?: WorkerLogger;
}

/**
 * The tokens the answer may use now: the least of REPLY_TOKEN_BUDGET, in the place of a review's
 * ceiling, and what the organisation's day and its project's have left (`remainingReviewTokens`,
 * for the reviews and the answers to replies together). The job asks it before it reads a thread
 * for a reply the day has nothing left for.
 */
export async function replyTokensLeft(
  deps: Pick<ReplyDeps, 'db' | 'settings' | 'organizationId' | 'reply'>,
  provider: StoredProvider,
): Promise<number> {
  const { db, settings, organizationId } = deps;
  const [organization, project] = await Promise.all([
    reviewUsageToday(db, organizationId),
    reviewUsageToday(db, organizationId, deps.reply.projectId),
  ]);
  return remainingReviewTokens(
    { ...effectiveReviewBudgets(settings, organizationId), maxTokensPerReview: REPLY_TOKEN_BUDGET },
    { organization, project },
    settings.pricing,
    provider,
  );
}

/**
 * Decides the answer to a reply: it asks what the day has left for it (nothing, or less than its
 * first call needs: `budget_spent`, with no call made), then runs `runReplyConversation` on the
 * model of the `reply` tier at that model's prices, with every call sent through the review's sender
 * as a `review-reply` row, written finished, with the review's 300 s floor on the wait for each,
 * and none sending more than the provider's context window less the reply's answer (R46). A
 * stop of the server, or of the caller, is `stopped`. Nothing is posted and no ledger row is
 * written: the caller does that with what comes back.
 */
export async function decideReply(input: ReplyInput, deps: ReplyDeps): Promise<DecidedReply> {
  const { settings } = deps;
  const provider = settings.provider;
  const key = providerApiKey(settings, deps.config.secretKey);
  // No provider, or a key that no longer decrypts (the server's secret key changed): no call can be made.
  if (provider === null || !key.ok) return { failed: 'provider_error' };
  const tokenBudget = await replyTokensLeft(deps, provider);
  const tier = tierOfCall('reply', null);
  const model = modelFor(provider, tier);
  const pricing = pricingFor(settings.pricing, provider, tier);
  const redactions = new RedactionTally();
  const send = reviewSender({
    db: deps.db,
    runtime: deps.runtime,
    config: deps.config,
    settings: reviewCallSettings(settings),
    model,
    pricing,
    feature: REVIEW_REPLY_FEATURE,
    source: { projectId: deps.reply.projectId, promptKey: deps.reply.id },
    promptVersion: REPLY_PROMPT_VERSION,
    redactions,
    logger: deps.logger,
    signal: deps.signal,
  });
  const masker = new Masker({ signal: deps.signal });
  try {
    return await runReplyConversation(input, {
      send,
      shouldStop: async () => deps.signal?.aborted === true || (await deps.shouldStop?.()) === true,
      masker,
      tokenBudget,
      providerKey: key.key,
      excludePaths: settings.excludePaths,
      model,
      pricing,
      redactions,
      signal: deps.signal,
      contextWindowTokens: provider.contextWindowTokens,
    });
  } finally {
    await masker.close();
  }
}
