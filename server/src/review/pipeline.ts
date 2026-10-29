import { parseModelJson } from '@qualor/shared';
import type { z } from 'zod';
import type { ReviewFailureReason, ReviewPhase, ReviewTier } from '../db/schema';
import {
  CONTEXT_MAXIMA,
  type ContextLimits,
  type ContextShape,
  type ReviewableChange,
  type ReviewContext,
} from './context';
import { CHARS_PER_TOKEN, CONVERSATION_TEXTS, type ConversationResult } from './conversation';
import { envelope, newNonce } from './envelope';
import { scrubKeyDeep } from './key-scrub';
import { tierOfCall, type ConversationRole, type ModelTier } from './model-tiers';
import {
  judgeData,
  LIST_CAP_STEPS,
  listedDataChars,
  SPECIALISTS,
  specialistData,
  SYSTEM_PROMPTS,
  verifyData,
  type LabelledFinding,
  type ListCaps,
  type ReviewRole,
  type Specialist,
} from './prompts';
import {
  judgeAnswerSchema,
  reviewFindingOf,
  specialistAnswerSchema,
  verifyAnswerSchema,
  type JudgeAnswer,
  type PriorStatus,
  type ReviewFinding,
  type ReviewNote,
  type VerifyVerdict,
} from './schemas';
// tool-conversation.ts reads REVIEW_OUTPUT_TOKENS of this module: neither reads the other's values
// before a function is called.
import { callInputCap, DEFAULT_CONTEXT_WINDOW_TOKENS } from './tool-conversation';

export type { ReviewRole, Specialist } from './prompts';
export { CHARS_PER_TOKEN } from './conversation';
export { REVIEW_NOTES, type ReviewFinding, type ReviewNote } from './schemas';

/*
 * The review of a merge request, from its context to the findings it stores (spec §6.3). The size
 * of the change picks the specialist reviewers; they report with recall first, one after the other
 * (security first when it is one of them); a judge reads the code behind their findings and keeps,
 * merges or drops each with a reason, re-checks what an earlier review raised and writes the
 * summary; and every serious security finding it keeps is checked again by a conversation given
 * that finding alone.
 *
 * Every conversation is given a check of its answers: parseModelJson, the provider's key taken out,
 * then the role's strict schema (schemas.ts). The conversation asks once more for an answer that
 * does not pass. A reviewer that still does not answer in its JSON adds nothing, and a judge that
 * does not fails the review (fail closed).
 *
 * The review's token budget is shared out between the stages: 55 % for the specialists, 35 % for
 * the judge and 10 % for the verification, shares that add up to the budget. What is left unspent
 * goes forward, and what is spent past what was given is taken from no other: each specialist has
 * an even part of the specialists' share and what the ones before it left of theirs; the judge its
 * share and what the specialists left of theirs; the verification its share and what the judge
 * left, each finding it checks an even part of that and what the ones before it left. A
 * conversation that used up its tokens answers through its wrap-up, and the review notes the token
 * limit (`tokenLimitReached`); one that took all its turns answers through its own, and the review
 * notes the turn limit; one with nothing to spend does not run, and the review notes the token
 * limit. The review goes on: only a judge cannot be done without. What a first message holds is
 * sized to a third of the tokens its conversation is sure of (`reviewLimits`, with a specialist's
 * even part, and the judge's data, with its share): every call sends it again, and a third leaves
 * room for a turn of tools, what the tools answer, and the wrap-up. No call may send more than the
 * model's context window less the room for its answer (`callInputCap`, R46), so the judge's first
 * message is sized within a third of its cap as well: the data the reviewers share in half of what
 * that third leaves after the judge's prompt, the findings in the other half, cut further than its
 * share cuts them when they must (`judgeData`). A conversation that reached the window answers through its
 * wrap-up, and one the window had no room for adds nothing: the review notes either
 * (`context_window_reached`); a judge the window had no room for fails it (`window_full`).
 *
 * The review has its time as well (`deps.deadline`), shared out the same way: the specialists have
 * until 60 % of it, so that a slow one cannot take the judge's, and the judge and the verification
 * until its end. No conversation starts once its stage's time is up, and one that is talking then
 * answers through its wrap-up (conversation.ts). A specialist or a check that did not run for it,
 * or gave no answer, adds nothing, and one that answered through the wrap-up adds what it found:
 * the review notes the time limit (`time_limit_reached`). A judge that has no answer by the end of
 * the time fails the review (`provider_error`, detail `time_limit`).
 *
 * Each conversation runs on the model of a tier (model-tiers.ts): the judge and the verification on
 * the strong one, the specialists on the standard one, and the quality reviewer of a trivial review
 * on the fast one.
 *
 * Nothing here calls a provider: `deps.converse` does, with the role's system prompt, the tools and
 * the first message it is given.
 */

/** The tiers by size: lines added plus removed over the reviewed changes, and their files. */
export const TIER_LIMITS = { trivialLines: 10, liteLines: 300, liteFiles: 20 } as const;
const TIER_SPECIALISTS: Readonly<Record<ReviewTier, readonly Specialist[]>> = {
  trivial: ['quality'],
  lite: ['quality', 'tests'],
  full: SPECIALISTS,
};

/** Percent of the review's token budget each stage may spend. */
export const STAGE_SHARES = { specialists: 55, judge: 35, verification: 10 } as const;
/** The part of the review's time the specialists have: no specialist starts past it. */
export const SPECIALISTS_TIME_SHARE = 0.6;
/** The serious security findings verified in one review, at most. */
export const MAX_VERIFICATIONS = 5;

/**
 * The tokens each role may write in one answer: the cap of the answer itself, which is read up to
 * `ANSWER_CHARS_PER_TOKEN` characters for each of them. A reply's is a verdict and at most 1 200
 * characters of words. A conversation asks the provider for these and, beyond them, the room for the
 * model to think before it answers (`converseOverTools`); a model that takes no limit that large is
 * asked for these alone.
 */
export const REVIEW_OUTPUT_TOKENS: Readonly<Record<ConversationRole, number>> = Object.freeze({
  quality: 12_288,
  tests: 12_288,
  security: 12_288,
  performance: 12_288,
  judge: 16_384,
  verify: 2_048,
  reply: 2_048,
});
export const ANSWER_CHARS_PER_TOKEN = 4;
/** The longest answer of a role that is read, in characters: four for each token it may write. */
export const answerCharLimit = (role: ConversationRole): number =>
  ANSWER_CHARS_PER_TOKEN * REVIEW_OUTPUT_TOKENS[role];

/** A first message holds at most this part of its conversation's tokens (counted at CHARS_PER_TOKEN). */
const FIRST_MESSAGE_PARTS = 3;
/** What an envelope and the keys of its data object add to the data, at most. */
const ENVELOPE_CHARS = 600;
/** A text in JSON takes a tenth more for its escapes (more with many quotes; the token count's slack covers it). */
const JSON_ALLOWANCE = 1.1;
/** The label of an instructions file that is cut. */
const CUT_LABEL_CHARS = 80;
/** Characters of each instructions file shown whatever the budget (or all of it, if it is shorter). */
const INSTRUCTIONS_MIN_CHARS = 16_000;
/** The part of the window's room for the data that the instructions files' floors take, in all. */
const INSTRUCTIONS_WINDOW_SHARE = 0.5;
/** The fewest characters worth showing of an instructions file: a file with a share below is dropped. */
const INSTRUCTIONS_LEAST_CHARS = 1_000;

export interface JudgedFinding extends ReviewFinding {
  /** The ids of the specialist findings it comes from (`s1`, `s2`, …). */
  sources: string[];
  /** The prior finding it is, re-emitted; only an id the judge was given. */
  priorId: string | null;
  /** The independent verification of a serious security finding; null when it was not verified. */
  verification: 'confirmed' | 'needs_validation' | null;
}

export interface PriorVerdict {
  id: string;
  status: PriorStatus;
  reason: string;
}

export type PipelineOutcome =
  | {
      kind: 'reviewed';
      tier: ReviewTier;
      /** The specialists that ran, in their order: one with no tokens left does not run. */
      specialists: Specialist[];
      findings: JudgedFinding[];
      /** The judge's verdicts on the open prior findings it was shown. */
      prior: PriorVerdict[];
      /**
       * The prior findings the judge was shown (at most 50, the open ones first): only these may
       * be closed for being left out of the findings.
       */
      shownPriorIds: string[];
      /**
       * The prior findings the judge named in a finding (its `priorId`, each once), also in one the
       * review dropped itself: of low confidence, or rejected by the verification. A prior finding
       * that is named stays open, whatever becomes of the finding that names it.
       */
      namedPriorIds: string[];
      summary: { verdict: string; walkthrough: string[] };
      tokenLimitReached: boolean;
      notes: ReviewNote[];
    }
  | {
      kind: 'failed';
      reason: ReviewFailureReason;
      /**
       * `window_full`: the judge's call could not be made within the model's context window
       * (`provider_error`, as the provider would have refused it), whatever was cut of its data.
       * `time_limit`: the judge had no answer when the review's time was up (`provider_error`).
       */
      detail?: 'window_full' | 'time_limit';
    }
  | { kind: 'stopped' };

export interface PipelineDeps {
  /**
   * One conversation of a role over the tools. `user` is the envelope built with `nonce`; the
   * job's implementation runs `runConversation` with that nonce for the tool results, with
   * `tokenBudget` (more than 0), REVIEW_OUTPUT_TOKENS of the role and the role's cap in the model's
   * context window (`callInputCap`, the window runReviewPipeline is given), with `deadline` as the
   * time it has (`limits.deadline`, on the clock of `now`), and with `accept` as its check of an
   * answer: `true` takes it, and a text is what to say in asking again (an answer that is too long
   * to be read is told so). Every call of the conversation goes to the model of `modelTier`, which
   * the pipeline picks for the role and the size of the review (`tierOfCall`).
   */
  converse(
    role: ReviewRole,
    user: string,
    nonce: string,
    tokenBudget: number,
    accept: (text: string) => boolean | string,
    modelTier: ModelTier,
    deadline: number,
  ): Promise<ConversationResult>;
  /** The provider's API key, taken out of every answer before it is used; null when there is none. */
  providerKey: string | null;
  /**
   * When the review's time is up, in milliseconds of `now`'s clock: the job's start of the review
   * and its time (REVIEW_TIME_BUDGET_MS, job.ts). Left out: no limit.
   */
  deadline?: number;
  /** The clock of `deadline`, in milliseconds; Date.now when left out. */
  now?: () => number;
}

/** The tier of a review of this many changed lines in this many files. */
function tierOf(changedLines: number, files: number): ReviewTier {
  if (changedLines <= TIER_LIMITS.trivialLines) return 'trivial';
  if (changedLines <= TIER_LIMITS.liteLines && files <= TIER_LIMITS.liteFiles) return 'lite';
  return 'full';
}

/**
 * The tier of a review and its specialists, in their order: by the lines the reviewed changes add
 * and remove, and their number. A reviewed change that looks security-sensitive adds the security
 * reviewer at any tier.
 */
export function planReview(reviewed: readonly ReviewableChange[]): {
  tier: ReviewTier;
  specialists: Specialist[];
  changedLines: number;
  files: number;
} {
  const changedLines = reviewed.reduce((sum, change) => sum + change.changedLines, 0);
  const files = reviewed.length;
  const tier = tierOf(changedLines, files);
  const chosen = new Set<Specialist>(TIER_SPECIALISTS[tier]);
  if (reviewed.some((change) => change.sensitive)) chosen.add('security');
  return { tier, specialists: SPECIALISTS.filter((s) => chosen.has(s)), changedLines, files };
}

/** `percent` of the budget, in whole tokens; nothing of a budget that is not a positive number. */
function shareOf(budget: number, percent: number): number {
  return Number.isFinite(budget) && budget > 0
    ? Math.floor((Math.floor(budget) * percent) / 100)
    : 0;
}

/** The characters a first message may take in a conversation of `tokens`. */
const firstMessageChars = (tokens: number): number =>
  Math.floor(tokens / FIRST_MESSAGE_PARTS) * CHARS_PER_TOKEN;

/**
 * The largest length every text may be cut to, at most `max`, for the texts of these lengths to
 * take at most `total` characters together: a short text keeps all of itself and leaves the rest
 * to the long ones.
 */
function evenCut(lengths: readonly number[], total: number, max: number): number {
  const sorted = [...lengths].sort((a, b) => a - b);
  let left = Math.max(0, total);
  for (const [index, length] of sorted.entries()) {
    const even = Math.floor(left / (sorted.length - index));
    if (length > even) return Math.min(max, even);
    left -= length;
  }
  return max;
}

/**
 * The characters of the data the specialists share that a first message of `tokens` leaves for the
 * instructions files and the slices: a third of them, less the longest system prompt, the envelope
 * and the lists, counted as the change has them. Not positive when the lists alone do not fit.
 */
function roomIn(shape: ContextShape, tokens: number, caps: ListCaps): number {
  const { specialists } = planReview(shape.reviewed);
  const prompt = Math.max(...specialists.map((role) => SYSTEM_PROMPTS[role].length));
  return Math.floor(
    (firstMessageChars(tokens) - prompt - ENVELOPE_CHARS - listedDataChars(shape, caps)) /
      JSON_ALLOWANCE,
  );
}

/**
 * The room of the data the specialists share in the model's context window (R46), for the
 * instructions files and the slices as `roomIn` counts them: the judge, whose cap is the smallest
 * of the roles given this data (`callInputCap`), sends it within a third of its cap, and keeps half
 * of what that third leaves after its own prompt and the envelope for the findings; the data has
 * the other half, less the lists. A reviewer's own third, of a larger cap and after a shorter
 * prompt, is never the smaller once anything fits. `window` Infinity: no window.
 */
function windowRoom(shape: ContextShape, window: number, caps: ListCaps): number {
  const judgeRoom =
    firstMessageChars(callInputCap(window, 'judge')) - SYSTEM_PROMPTS.judge.length - ENVELOPE_CHARS;
  return Math.floor((Math.floor(judgeRoom / 2) - listedDataChars(shape, caps)) / JSON_ALLOWANCE);
}

/**
 * The room of the data the specialists share: the smallest of its room in a third of a
 * specialist's part and half the judge's share (`roomIn`), and its room in the model's context
 * window (`windowRoom`).
 */
function dataRoom(shape: ContextShape, budget: number, window: number, caps: ListCaps): number {
  const { specialists } = planReview(shape.reviewed);
  const part = Math.floor(shareOf(budget, STAGE_SHARES.specialists) / specialists.length);
  const judgeHalf = Math.floor(shareOf(budget, STAGE_SHARES.judge) / 2);
  return Math.min(roomIn(shape, Math.min(part, judgeHalf), caps), windowRoom(shape, window, caps));
}

/**
 * The characters each instructions file is shown on a window too small for their floors
 * (INSTRUCTIONS_MIN_CHARS each): INSTRUCTIONS_WINDOW_SHARE of the window's room for the data, less
 * a label for each file, is cut evenly between them, a short file keeping all of itself and leaving
 * the rest to the long ones, and no file more than INSTRUCTIONS_MIN_CHARS. This is both what they
 * are shown and the most, so the slices keep the other half. A cut under INSTRUCTIONS_LEAST_CHARS
 * is no use: the files longer than it are left out (`dropsLonger`) and the others are whole. An
 * infinite window cuts nothing but INSTRUCTIONS_MIN_CHARS.
 */
export function instructionFloor(shape: ContextShape, window: number, caps: ListCaps): number {
  const { instructionChars: lengths } = shape;
  const room =
    Math.floor(INSTRUCTIONS_WINDOW_SHARE * windowRoom(shape, window, caps)) -
    lengths.length * CUT_LABEL_CHARS;
  return evenCut(lengths, room, INSTRUCTIONS_MIN_CHARS);
}

/** Whether the files longer than `cut` (`instructionFloor`) are left out, their cut being no use. */
const dropsLonger = (shape: ContextShape, cut: number): boolean =>
  cut < INSTRUCTIONS_LEAST_CHARS && shape.instructionChars.some((chars) => chars > cut);

/** The characters a file of `chars` takes at `cut`: whole, cut with its label, or left out. */
const takenAt = (chars: number, cut: number): number => {
  if (chars <= cut) return chars;
  return cut < INSTRUCTIONS_LEAST_CHARS ? 0 : cut + CUT_LABEL_CHARS;
};

/**
 * The characters the instructions files take whatever the room, as `reviewLimits` gives them when
 * the window has room for their floors: each file up to INSTRUCTIONS_MIN_CHARS, and the label of one
 * that is cut there.
 */
const instructionFloors = (shape: ContextShape): number =>
  shape.instructionChars.reduce(
    (sum, chars) =>
      sum +
      Math.min(chars, INSTRUCTIONS_MIN_CHARS) +
      (chars > INSTRUCTIONS_MIN_CHARS ? CUT_LABEL_CHARS : 0),
    0,
  );

/**
 * The characters the files take on a window too small for their floors: `instructionFloor` each,
 * and the label of one that is cut there. A file that is left out takes none.
 */
const windowFloors = (shape: ContextShape, window: number, caps: ListCaps): number => {
  const cut = instructionFloor(shape, window, caps);
  return shape.instructionChars.reduce((sum, chars) => sum + takenAt(chars, cut), 0);
};

/** Whether the lists of `caps` leave room, as `listCapsFor` asks; with the files' floors, or with their window share. */
const fitsWith = (
  shape: ContextShape,
  budget: number,
  window: number,
  caps: ListCaps,
  byWindow: boolean,
): boolean =>
  dataRoom(shape, budget, window, caps) > 0 &&
  windowRoom(shape, window, caps) -
    (byWindow ? windowFloors(shape, window, caps) : instructionFloors(shape)) >
    0;

/**
 * The first rung of LIST_CAP_STEPS, longest first, that fits, and how: with the instructions files'
 * floors (as every review has been sized), or, when no rung does, with what the window's room
 * leaves them (`instructionFloor`), which only a review the window would have skipped is given: the
 * longest rung that leaves every long file 1 000 characters or more, else the longest that fits.
 */
function ladder(
  shape: ContextShape,
  budget: number,
  window: number,
): { caps: ListCaps; byWindow: boolean } | null {
  const whole = LIST_CAP_STEPS.find((c) => fitsWith(shape, budget, window, c, false));
  if (whole !== undefined) return { caps: whole, byWindow: false };
  const fits = LIST_CAP_STEPS.filter((c) => fitsWith(shape, budget, window, c, true));
  const kept = fits.find((c) => !dropsLonger(shape, instructionFloor(shape, window, c)));
  const caps = kept ?? fits[0];
  return caps === undefined ? null : { caps, byWindow: true };
}

/**
 * The lists a review of `budget` tokens shows of a change of this shape, on a model of `window`
 * tokens (DEFAULT_CONTEXT_WINDOW_TOKENS when left out; Infinity: no window, to ask whether the
 * budget alone holds it), or null when none does (R47): the first of LIST_CAP_STEPS, longest
 * first, with which the smallest share of the review, and the judge's cap in the window, have room
 * for the first message, as `reviewLimits` counts it; and the window has room for the instructions
 * files' floors too, which the budget's room does not count, or else for the share of the window's
 * room they are cut to (`instructionFloor`). A change that fits the lists of today is given them,
 * whatever else.
 */
export function listCapsFor(
  shape: ContextShape,
  budget: number,
  window: number = DEFAULT_CONTEXT_WINDOW_TOKENS,
): ListCaps | null {
  return ladder(shape, budget, window)?.caps ?? null;
}

/**
 * Whether a review of `budget` tokens can run on a change of this shape, on a model of `window`
 * tokens (as `listCapsFor` takes them): some step of the ladder of lists has room. When none has,
 * `reviewLimits` still gives the instructions their floors, and the review would send a first
 * message larger than a third of its share or of that cap: the job skips it instead
 * (`budget_spent`, detail `too_large` when the budget is too small for the merge request even
 * with the shortest lists, `window_too_small` when only the window is, never the day's budget
 * spent).
 */
export function reviewFits(
  shape: ContextShape,
  budget: number,
  window: number = DEFAULT_CONTEXT_WINDOW_TOKENS,
): boolean {
  return listCapsFor(shape, budget, window) !== null;
}

/**
 * How much of the slices and of the instructions a review of `budget` tokens shows of a change of
 * this shape, on a model of `window` tokens (as `reviewFits` takes it): what buildReviewContext's
 * `limits` answers (the job passes it this, bound to the budget and the window). The data the
 * specialists share is sized so that a specialist's first message takes at most a third of its
 * part and half of the judge's third, and the judge's, within a third of its cap in the window,
 * half of what its prompt leaves (`dataRoom`). That room goes first to the instructions files,
 * which no tool can stand in for: each at least INSTRUCTIONS_MIN_CHARS (or all of it, if shorter)
 * even past that room, the long ones cut evenly when they do not all fit. The slices have the rest.
 * Only on a window with no room for those floors (the review would have been skipped) are the files
 * held to half of the window's room (`instructionFloor`), and the slices keep the other half;
 * `instructionsShortened` says so, and is not set otherwise. Each part is at most CONTEXT_MAXIMA.
 */
export function reviewLimits(
  shape: ContextShape,
  budget: number,
  window: number = DEFAULT_CONTEXT_WINDOW_TOKENS,
): ContextLimits {
  // The shortest lists when none has room: the job has skipped such a review already.
  const found = ladder(shape, budget, window);
  const lists = found?.caps ?? LIST_CAP_STEPS[LIST_CAP_STEPS.length - 1] ?? LIST_CAP_STEPS[0];
  const room = dataRoom(shape, budget, window, lists);
  const byWindow = found?.byWindow === true;
  const labels = shape.instructionChars.length * CUT_LABEL_CHARS;
  const instructionsChars = byWindow
    ? instructionFloor(shape, window, lists)
    : Math.max(
        INSTRUCTIONS_MIN_CHARS,
        evenCut(shape.instructionChars, room - labels, CONTEXT_MAXIMA.instructionsChars),
      );
  const dropLonger = byWindow && dropsLonger(shape, instructionsChars);
  const shortened =
    byWindow &&
    shape.instructionChars.some(
      (chars) => Math.min(chars, INSTRUCTIONS_MIN_CHARS) > instructionsChars,
    );
  // A file that is left out has no label either.
  const instructions = shape.instructionChars.reduce(
    (sum, chars) =>
      sum +
      (byWindow
        ? takenAt(chars, instructionsChars)
        : Math.min(chars, instructionsChars) + (chars > instructionsChars ? CUT_LABEL_CHARS : 0)),
    0,
  );
  return {
    sliceChars: Math.min(CONTEXT_MAXIMA.sliceChars, Math.max(0, room - instructions)),
    instructionsChars,
    lists,
    ...(shortened ? { instructionsShortened: true } : {}),
    ...(dropLonger ? { instructionsDropLonger: true } : {}),
  };
}

/**
 * The tokens of a stage, given to its conversations one after the other: each is given an even
 * part of them and what the one before it left of what it was given (which holds what the ones
 * before that left). What one spends past what it was given is taken from no other: the next has
 * its even part all the same. What the stage leaves unspent is the next stage's.
 */
class StageTokens {
  private readonly part: number;
  /** What the last conversation left of what it was given: the next one has it besides its part. */
  private carried = 0;

  constructor(
    private readonly tokens: number,
    private readonly slots: number,
  ) {
    this.part = slots > 0 ? Math.floor(tokens / slots) : 0;
  }

  /** What the next conversation is given. */
  next(): number {
    return this.part + this.carried;
  }

  /** Takes note of what a conversation that was given `given` spent: what it left goes forward. */
  settle(given: number, spent: number): void {
    this.carried = Math.max(0, given - spent);
  }

  /** What the stage left unspent: what its last conversation left, and its parts' rounding. */
  unspent(): number {
    return this.carried + this.tokens - this.part * this.slots;
  }
}

/** How one conversation slot ended. */
type Asked<T> =
  | { kind: 'answer'; value: T }
  /** It ran and gave nothing usable: no answer, or none of its schema when asked again. */
  | { kind: 'unread' }
  /** It had no tokens to start with, and did not run. */
  | { kind: 'no_tokens' }
  /**
   * Its call could not be made within the model's context window (`window_full`); `ran` when it
   * made one before.
   */
  | { kind: 'window_full'; ran: boolean }
  /**
   * The review's time was up before it had an answer: it did not start, or it had no answer by
   * the time its last call came back; `ran` when it made a call.
   */
  | { kind: 'time_up'; ran: boolean }
  | { kind: 'stopped' }
  | { kind: 'failed'; reason: 'provider_error' | 'provider_no_tools' };

/** The state of one review: what it has noted of itself. */
class Review {
  tokenLimitReached = false;
  readonly notes: ReviewNote[] = [];
  /** The clock of the review's time (`deps.deadline`). */
  readonly now: () => number;

  constructor(
    private readonly deps: PipelineDeps,
    /** The size of the review, which decides the model tier of its specialists (`tierOfCall`). */
    private readonly sizeTier: ReviewTier,
  ) {
    this.now = deps.now ?? Date.now;
  }

  note(note: ReviewNote): void {
    if (!this.notes.includes(note)) this.notes.push(note);
  }

  limitReached(): void {
    this.tokenLimitReached = true;
    this.note('token_limit_reached');
  }

  /**
   * One slot of a stage: a conversation of `role` over `data` with the tokens `stage` gives it next
   * and the time its stage has (`until`, on the clock of `now`), which asks once more for an answer
   * that does not match `schema` (runConversation's `accept`), and for a shorter one when the
   * answer is longer than it is read. `stage` is told what it spent. Its answer is checked again
   * here: a conversation that gave one back without checking it is not believed. A wrap-up for the
   * tokens is noted as the token limit, one for the turns as the turn limit, one for the model's
   * context window as that, and so is a call the window had no room for; one for the time as the
   * time limit, and so is a conversation that does not start, or ends, because the time is up.
   */
  async ask<T>(
    role: ReviewRole,
    data: unknown,
    schema: z.ZodType<T>,
    stage: StageTokens,
    until: number,
  ): Promise<Asked<T>> {
    const tokens = stage.next();
    if (tokens <= 0) {
      this.limitReached();
      return { kind: 'no_tokens' };
    }
    if (this.now() >= until) {
      // Not started: its tokens go forward, as what a conversation leaves does.
      stage.settle(tokens, 0);
      this.note('time_limit_reached');
      return { kind: 'time_up', ran: false };
    }
    /** What the check read of the answers it took, by their text. */
    const accepted = new Map<string, T>();
    const accept = (text: string): boolean | string => {
      // The room to think lets a model write past the answer's cap, so a text can be too long to
      // be read: it is told so, which the loop's text for JSON that does not match does not say.
      if (text.length > answerCharLimit(role)) return CONVERSATION_TEXTS.shorter;
      const value = this.read(role, text, schema);
      if (value !== undefined) accepted.set(text, value);
      return value !== undefined;
    };
    const nonce = newNonce();
    const result = await this.deps.converse(
      role,
      envelope(data, nonce),
      nonce,
      tokens,
      accept,
      tierOfCall(role, this.sizeTier),
      until,
    );
    stage.settle(tokens, result.inputTokens + result.outputTokens);
    if (result.kind === 'stopped') return { kind: 'stopped' };
    if (result.kind === 'failed') {
      if (result.reason === 'window_full') {
        this.note('context_window_reached');
        return { kind: 'window_full', ran: result.turns > 0 };
      }
      if (result.timeLimit === true) {
        this.note('time_limit_reached');
        return { kind: 'time_up', ran: result.turns > 0 };
      }
      return result.reason === 'bad_answer'
        ? { kind: 'unread' }
        : { kind: 'failed', reason: result.reason };
    }
    if (result.wrappedUp === 'budget') this.limitReached();
    if (result.wrappedUp === 'turns') this.note('turn_limit_reached');
    if (result.wrappedUp === 'window') this.note('context_window_reached');
    if (result.wrappedUp === 'time') this.note('time_limit_reached');
    const value = accepted.get(result.text) ?? this.read(role, result.text, schema);
    return value === undefined ? { kind: 'unread' } : { kind: 'answer', value };
  }

  /**
   * The answer as its schema reads it, with the provider's key taken out first; or undefined. An
   * answer is read up to four characters for each token the role may write.
   */
  private read<T>(role: ReviewRole, text: string, schema: z.ZodType<T>): T | undefined {
    const parsed = parseModelJson(text, answerCharLimit(role));
    if (parsed === undefined) return undefined;
    const checked = schema.safeParse(scrubKeyDeep(parsed, this.deps.providerKey));
    return checked.success ? checked.data : undefined;
  }
}

const STOPPED = { kind: 'stopped' } as const;
const NOT_JUDGED = { kind: 'failed', reason: 'bad_answer' } as const;
/** A judge whose call the model's context window has no room for, whatever was cut of its data. */
const JUDGE_WINDOW_FULL = {
  kind: 'failed',
  reason: 'provider_error',
  detail: 'window_full',
} as const;
/** A judge that had no answer when the review's time was up. */
const JUDGE_TIME_LIMIT = {
  kind: 'failed',
  reason: 'provider_error',
  detail: 'time_limit',
} as const;

/**
 * A finding of the judge as the outcome holds it: its sources are the specialist ids it was given,
 * each once, and its prior id is one it was given, or null.
 */
function judged(
  found: JudgeAnswer['findings'][number],
  sources: ReadonlyMap<string, { full: string; shown: string }>,
  priors: ReadonlySet<string>,
): JudgedFinding {
  const priorId = found.priorId ?? null;
  const given = [...new Set(found.sources)].filter((id) => sources.has(id));
  const first = given.length > 0 ? sources.get(given.at(0) ?? '') : undefined;
  // Under a small window the judge is shown cut bodies, and one kept "as it was given" carries the
  // cut text: the body it was cut from is restored. A body the judge wrote itself is kept.
  const cut =
    first !== undefined &&
    first.shown !== first.full &&
    (found.body === first.shown || found.body === '…');
  return {
    ...reviewFindingOf(found),
    ...(cut ? { body: first.full } : {}),
    sources: given,
    priorId: priorId !== null && priors.has(priorId) ? priorId : null,
    verification: null,
  };
}

/** The judge's verdicts on the open prior findings it was given, the first for each. */
function priorVerdicts(given: JudgeAnswer['prior'], open: ReadonlySet<string>): PriorVerdict[] {
  const verdicts = new Map<string, PriorVerdict>();
  for (const { id, status, reason } of given) {
    if (open.has(id) && !verdicts.has(id)) verdicts.set(id, { id, status, reason });
  }
  return [...verdicts.values()];
}

const isSerious = (finding: JudgedFinding): boolean =>
  finding.category === 'security' &&
  (finding.severity === 'critical' || finding.severity === 'major');

/** How a review ends when a conversation does not give an answer. */
type StageEnd = typeof STOPPED | { kind: 'failed'; reason: 'provider_error' | 'provider_no_tools' };

/** The end of the review that the end of a slot is. */
function endOf(asked: Extract<Asked<unknown>, { kind: 'stopped' | 'failed' }>): StageEnd {
  return asked.kind === 'stopped' ? STOPPED : { kind: 'failed', reason: asked.reason };
}

/**
 * The specialists, one after the other, until `until`: the ones that ran, and the findings they
 * gave, labelled. The review's end when a conversation stopped or failed.
 */
async function runSpecialists(
  context: ReviewContext,
  specialists: readonly Specialist[],
  review: Review,
  stage: StageTokens,
  until: number,
): Promise<{ ran: Specialist[]; labelled: LabelledFinding[] } | StageEnd> {
  const ran: Specialist[] = [];
  const labelled: LabelledFinding[] = [];
  const shown = specialistData(context);
  for (const specialist of specialists) {
    const asked = await review.ask(specialist, shown, specialistAnswerSchema, stage, until);
    if (asked.kind === 'stopped' || asked.kind === 'failed') return endOf(asked);
    if (asked.kind === 'no_tokens') continue;
    if (asked.kind === 'window_full' || asked.kind === 'time_up') {
      // It adds nothing, and the review notes the window or the time (`ask`).
      if (asked.ran) ran.push(specialist);
      continue;
    }
    ran.push(specialist);
    if (asked.kind === 'unread') {
      review.note('reviewer_unreadable');
      continue;
    }
    const first = labelled.length;
    labelled.push(
      ...asked.value.findings.map((found, i) => ({
        id: `s${first + i + 1}`,
        reviewer: specialist,
        finding: reviewFindingOf(found),
      })),
    );
  }
  return { ran, labelled };
}

/**
 * Verifies the serious findings, one conversation each, at most MAX_VERIFICATIONS of them, with
 * `tokens` shared between them, until `until`: the verdicts, by finding. The review's end when a
 * conversation stopped or failed.
 */
async function verifySerious(
  review: Review,
  serious: readonly JudgedFinding[],
  tokens: number,
  until: number,
  onPhase: (phase: ReviewPhase) => Promise<void>,
): Promise<Map<JudgedFinding, VerifyVerdict> | StageEnd> {
  const verdicts = new Map<JudgedFinding, VerifyVerdict>();
  if (serious.length === 0) return verdicts;
  await onPhase('verification');
  if (serious.length > MAX_VERIFICATIONS) review.note('verification_capped');
  const checked = serious.slice(0, MAX_VERIFICATIONS);
  const verification = new StageTokens(tokens, checked.length);
  for (const finding of checked) {
    const told = await review.ask(
      'verify',
      verifyData(finding),
      verifyAnswerSchema,
      verification,
      until,
    );
    if (told.kind === 'stopped' || told.kind === 'failed') return endOf(told);
    // Not verified: the finding stays as the judge left it (a window that had no room for the
    // check, or a time that was up, is noted by `ask`).
    if (told.kind === 'unread') review.note('reviewer_unreadable');
    if (told.kind === 'answer') verdicts.set(finding, told.value.verdict);
  }
  return verdicts;
}

/** The findings after their verdicts: a rejected one is gone, one that needs validation is less certain. */
function withVerdicts(
  kept: readonly JudgedFinding[],
  verdicts: ReadonlyMap<JudgedFinding, VerifyVerdict>,
): JudgedFinding[] {
  return kept.flatMap((finding): JudgedFinding[] => {
    const verdict = verdicts.get(finding);
    if (verdict === undefined) return [finding];
    if (verdict === 'rejected') return [];
    return [
      verdict === 'needs_validation'
        ? { ...finding, confidence: 'medium', verification: verdict }
        : { ...finding, verification: verdict },
    ];
  });
}

/**
 * Reviews the merge request the context is of, with `budget` tokens shared out between its stages
 * (the header above): each conversation is given its tokens, and keeps room in them for its
 * wrap-up. It goes past them only by as much as the loop's guesses fell short, or when its first
 * turn of tools already left no room (conversation.ts), and what it spends past them is taken from
 * no other conversation: the review goes past `budget` by that much at most. `window` is the model's
 * context window, which the judge's data is sized within as the first messages are (`reviewLimits`;
 * `deps.converse` keeps each call within it). The review's time runs from here to `deps.deadline`,
 * the specialists' to SPECIALISTS_TIME_SHARE of it. `onPhase` is told each stage as it starts. The
 * outcome is `stopped` as soon as a conversation is, and `failed` when the provider fails or the
 * judge gives no answer of its schema, or none in time: nothing of a failed review is stored.
 */
export async function runReviewPipeline(
  context: ReviewContext,
  budget: number,
  deps: PipelineDeps,
  onPhase: (phase: ReviewPhase) => Promise<void>,
  window: number = DEFAULT_CONTEXT_WINDOW_TOKENS,
): Promise<PipelineOutcome> {
  const plan = planReview(context.reviewed);
  const review = new Review(deps, plan.tier);
  const deadline = deps.deadline ?? Number.POSITIVE_INFINITY;
  const began = review.now();
  const specialistsUntil = began + SPECIALISTS_TIME_SHARE * (deadline - began);
  const judgeShare = shareOf(budget, STAGE_SHARES.judge);
  // Without a judge nothing can be kept: a budget too small for its share is not spent at all.
  if (judgeShare <= 0) return NOT_JUDGED;
  // Once, whatever the reviewers do: the lists they were shown are the context's.
  if (JSON.stringify(context.listCaps) !== JSON.stringify(LIST_CAP_STEPS[0])) {
    review.note('lists_shortened');
  }
  if (context.instructionsShortened === true) review.note('instructions_shortened');

  // The specialists, one after the other, each with an even part of their share and what the ones
  // before it left of theirs: one that overshoots what it was given takes nothing from the next.
  await onPhase('specialists');
  const specialists = new StageTokens(
    shareOf(budget, STAGE_SHARES.specialists),
    plan.specialists.length,
  );
  const reviewed = await runSpecialists(
    context,
    plan.specialists,
    review,
    specialists,
    specialistsUntil,
  );
  if ('kind' in reviewed) return reviewed;
  const { ran, labelled } = reviewed;

  // The judge, with its own share and what the specialists left of theirs: what they spent past
  // what they were given is not taken from it. Its data takes a third of its share, and of its cap
  // in the window, at most: the bodies of the findings are cut to fit, and within the window
  // further (judgeData, R46).
  await onPhase('judge');
  const judgeCap = callInputCap(window, 'judge');
  const roomOf = (tokens: number): number =>
    firstMessageChars(tokens) - SYSTEM_PROMPTS.judge.length - ENVELOPE_CHARS;
  const judgeShown = judgeData(
    context,
    labelled,
    roomOf(Math.min(judgeShare, judgeCap)),
    roomOf(judgeCap),
  );
  const judge = new StageTokens(judgeShare + specialists.unspent(), 1);
  const asked = await review.ask('judge', judgeShown, judgeAnswerSchema, judge, deadline);
  if (asked.kind === 'stopped' || asked.kind === 'failed') return endOf(asked);
  if (asked.kind === 'window_full') return JUDGE_WINDOW_FULL;
  if (asked.kind === 'time_up') return JUDGE_TIME_LIMIT;
  if (asked.kind !== 'answer') return NOT_JUDGED;
  const answer = asked.value;
  const shownBodies = new Map(judgeShown.specialistFindings.map((f) => [f.id, f.body]));
  const sources = new Map(
    labelled.map(({ id, finding }) => [
      id,
      { full: finding.body, shown: shownBodies.get(id) ?? finding.body },
    ]),
  );
  const shownPriorIds = judgeShown.priorFindings.map((finding) => finding.id);
  const openPriors = new Set(
    judgeShown.priorFindings.filter((finding) => finding.status === 'open').map((f) => f.id),
  );
  const answered = answer.findings.map((found) => judged(found, sources, new Set(shownPriorIds)));
  const namedPriorIds = [
    ...new Set(answered.flatMap(({ priorId }) => (priorId === null ? [] : [priorId]))),
  ];
  // A low-confidence finding is never stored, so it is not verified either.
  const kept = answered.filter((finding) => finding.confidence !== 'low');

  // The serious security findings, critical first, each verified alone, with the verification's
  // own share and what the judge left of its tokens: what the stages before it overspent is not
  // taken from it.
  const serious = kept
    .filter(isSerious)
    .sort((a, b) => Number(b.severity === 'critical') - Number(a.severity === 'critical'));
  const verdicts = await verifySerious(
    review,
    serious,
    shareOf(budget, STAGE_SHARES.verification) + judge.unspent(),
    deadline,
    onPhase,
  );
  if ('kind' in verdicts) return verdicts;
  const findings = withVerdicts(kept, verdicts);
  return {
    kind: 'reviewed',
    tier: plan.tier,
    specialists: ran,
    findings,
    prior: priorVerdicts(answer.prior, openPriors),
    shownPriorIds,
    namedPriorIds,
    summary: { verdict: answer.summary.verdict, walkthrough: [...answer.summary.walkthrough] },
    tokenLimitReached: review.tokenLimitReached,
    notes: [...review.notes],
  };
}
