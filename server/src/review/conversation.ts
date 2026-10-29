import { cutAtGrapheme } from '@qualor/shared';
import {
  LlmCallAborted,
  LlmError,
  type LlmConversation,
  type LlmMessage,
  type LlmToolCall,
  type LlmToolSpec,
  type LlmTurn,
  type ProviderReplay,
} from '../llm/providers';
import { toolResultMessage } from './envelope';

/*
 * The conversation a reviewer has with the model over the read-only tools (llm.md §2.5, review.md
 * §9.1). The provider layer answers one turn at a time and runs nothing; this loop sends a turn,
 * runs the calls the model made, sends the results and goes on, until the model answers in text.
 * It owns what bounds a model: the caps on turns, on calls per turn, on the arguments it sends and
 * on what one call sends (the model's context window, R46), the wrap-up turn when the tokens, the
 * window, the turns or the review's time are used up, the retries, and the stop check before every
 * call to the provider. It does not make a call itself (`send` does, and records it), run a tool
 * (`runTool`) or read an answer's JSON (the pipeline does).
 *
 * The history only grows. A turn joins it as the provider made it: the `replay` its adapter kept
 * goes on the assistant message unchanged (the current Anthropic models sign their thinking, and a
 * provider that does so checks it against the conversation), and no message that has been sent is
 * ever changed or reordered. The loop never reads a replay. A tool answer the window has no room
 * for is replaced by a fixed line before it is first sent, never after.
 *
 * Nothing the model said is logged here, and nothing in the result of a conversation that did not
 * answer carries any of it.
 */

export const CONVERSATION_LIMITS = {
  /** Turns the model may take with tools; the wrap-up turn comes after the last of them. */
  maxTurns: 16,
  maxCallsPerTurn: 8,
  /** The share of the token budget after which the next turn is the wrap-up. */
  wrapUpAt: 0.85,
  /** Arguments of one call, as JSON text. */
  maxArgumentBytes: 16_384,
  /** Levels of objects and lists inside the arguments of one call; the arguments are level 1. */
  maxArgumentDepth: 20,
} as const;

/** How a call the provider failed is tried again; each call of the conversation has its own. */
export const CONVERSATION_RETRIES = {
  /** Retries after a rate limit, each after the provider's Retry-After. */
  rateLimited: 2,
  /** Retries in all after a timeout, a 5xx answer or an unreachable provider. */
  transient: 2,
  /** The waits, in seconds, when the provider named none: llm.md §14's backoff. */
  backoffSeconds: [5, 30],
  minWaitSeconds: 1,
  maxWaitSeconds: 60,
} as const;

/**
 * What a tool answer is sent as when the next call would pass the model's context window with it
 * (`limits.maxCallInputTokens`): each answer of that turn, in its envelope, in its place.
 */
export const CONTEXT_FULL_TEXT =
  "not shown: the model's context window is full; answer now with what you have";

/** What the loop itself says to the model, word for word. */
export const CONVERSATION_TEXTS = {
  wrapUp: 'Token budget reached: answer now, with what you have, in the required JSON.',
  shorter:
    'Your answer was cut off because it was too long: answer again, shorter, in the required JSON.',
  /** After an answer the caller did not accept (`accept`), when it gave no text of its own. */
  retry: 'Your answer did not match the required JSON; answer again with JSON only.',
  tooManyCalls: 'too many calls in one turn; this one was not run',
  badArguments: 'the arguments were not valid JSON; call again',
  contextFull: CONTEXT_FULL_TEXT,
} as const;

/** Characters of a tool's name the envelope shows. */
const TOOL_LABEL_CHARS = 100;
/** The refusals of a request that tools can be the reason for. */
const TOOL_REFUSAL_STATUSES: readonly number[] = [400, 404, 422];

export interface ConversationInput {
  system: string;
  /** The first message: the data under review, already in its envelope (envelope.ts). */
  user: string;
  /** The nonce of that envelope: every tool message is put between the same markers. */
  nonce: string;
  tools: readonly LlmToolSpec[];
  /**
   * Runs one call and answers what to tell the model. It is given the arguments checked and
   * limited here. A rejection (a closed masker, a reader that failed) ends the conversation.
   */
  runTool: (call: LlmToolCall) => Promise<ToolAnswer>;
  limits: {
    maxTurns: number;
    maxCallsPerTurn: number;
    /**
     * The tokens, input and output of all its calls, the conversation stays within as far as it
     * can tell ahead: at 85 % of it, or when another turn of tools would leave no room for the
     * wrap-up after it, the next turn is the wrap-up (`wrapUpDue`). That call can still go past it,
     * by as much as the guesses fell short, and by more when the first turn of tools already left
     * no room for it. More than 0: a caller with nothing to spend does not start a conversation.
     */
    tokenBudget: number;
    /**
     * The tokens the answer of a call may hold: what the loop guesses a call wrote when the
     * provider did not count it, and what it guesses the next call and the wrap-up after it write.
     */
    maxOutputTokens: number;
    /**
     * The room, in tokens, the model is given beyond `maxOutputTokens` to think before it answers
     * (none when absent). Every call carries it apart from `maxOutputTokens`, and the provider layer
     * asks for the two together, and for `maxOutputTokens` alone from a model that refuses that
     * much. It raises only the limit every call asks for: the loop estimates with `maxOutputTokens`
     * alone and counts what each call really used, so a call that thinks may go past the budget by
     * its own thinking, which `maxOutputTokens` plus this bounds.
     */
    reasoningAllowance?: number;
    /**
     * The most tokens one call may send (R46): the model's context window less the room for the
     * answer (`callInputCap`, tool-conversation.ts). Every call is guessed before it is made, at
     * CHARS_PER_TOKEN, never at less than the provider counted (`nextCallInput`), and none whose
     * guess reaches it is made. When the wrap-up after the next call would reach it, the next call
     * is the wrap-up; when the answers of a turn of tools would make the next call reach it, each is
     * sent as CONTEXT_FULL_TEXT and that call is the wrap-up (`wrappedUp: 'window'`); when not even
     * that fits, the model's turn goes and the wrap-up is asked on the history the last call sent,
     * as an answer asked for again is. What does not fit even so, the first call included, ends the
     * conversation `window_full`. The caller sizes the first call (the pipeline gives the first
     * message a third of it). Absent: no cap.
     */
    maxCallInputTokens?: number;
    /**
     * When the review's time is up, in milliseconds of `now`'s clock. It is asked before every call,
     * after the stop check. Once it has passed, a conversation that has had a turn makes one call
     * more, its last: the wrap-up (`wrappedUp: 'time'`) when the model was to have a turn of tools,
     * tried once. One that has had no turn, or has made its last call, ends `provider_error` with
     * `timeLimit`. A retry whose wait would not end before it is not waited for: the time is up
     * then. A call in flight when it passes is not cut. Absent or Infinity: no limit.
     */
    deadline?: number;
  };
  /**
   * One call to the provider, recorded, through its circuit. It throws an `LlmError` for a call
   * the provider did not answer, a `CircuitOpenError` for one it was not asked, which fails the
   * conversation at once and says so (`circuitOpen`), and an `LlmCallAborted` for one its caller
   * gave up (the server is stopping), which stops it. Anything else it throws ends the conversation.
   */
  send: (conversation: LlmConversation) => Promise<LlmTurn>;
  /** Asked before every call to the provider, a retry included. */
  shouldStop: () => Promise<boolean>;
  /**
   * Whether an answer is one the caller can use (its JSON reads as the caller's schema): `true`
   * takes it. One that is not is asked for once more, in the same conversation; without a check
   * every answer is used. A caller that says no with `false` gets the loop's own words (`retry`
   * of CONVERSATION_TEXTS); one that says no with a text gets that text sent in their place, which
   * can say what was wrong. It is fixed text: never a word of the answer that was refused. A blank
   * text is no text.
   */
  accept?: (text: string) => boolean | string;
  /**
   * Wakes the wait of a retry when it aborts (the server is stopping): the wait ends at once, and
   * the stop check that follows it ends the conversation. The calls themselves are given up through
   * `send`'s own signal.
   */
  signal?: AbortSignal;
  /**
   * How a retry waits, in milliseconds, given `signal` to end the wait early.
   * @internal Tests only: nothing else sets it.
   */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  /** The clock `limits.deadline` is on, in milliseconds; Date.now when left out. */
  now?: () => number;
}

/**
 * What a conversation spent and did, whichever way it ended: a conversation that fails after
 * spending its share still counts against the review's ceiling. `turns` counts the provider's
 * answers (retried failures and the stop check not), `toolCalls` the calls that were run. The
 * tokens are the provider's counts; for a count it did not give they are a guess made for the
 * budget (see `tokensOf`). The input of a call that timed out, or whose answer could not be read,
 * is charged as a guess too: the provider most likely billed it, and the day counts it (usage.ts).
 * `inputTokens` is every prompt token, whatever the provider's cache did with it (R49): the budgets
 * and the window count all of it. `cacheReadTokens` and `cacheWriteTokens` are the parts of it the
 * provider counted as read from its cache and written to it (0 for a call that counted none), for
 * the evaluation and the logs only.
 */
export interface ConversationCounts {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  cacheWriteTokens: number;
  turns: number;
  toolCalls: number;
}

/**
 * What a tool answered: the text to tell the model, or the text with `sent`, which the loop calls
 * once it keeps that text for the next call, and `withheld`, which it calls instead when the text
 * is never sent: the window had no room for it (CONTEXT_FULL_TEXT went in its place, or its turn
 * was dropped), and what it showed of a file, or the secrets masked in it, never reached the model.
 * Exactly one of the two is called, unless the conversation ends before it decides.
 */
export type ToolAnswer = string | { text: string; sent: () => void; withheld?: () => void };

/**
 * Why a conversation wrapped up: its tokens (85 % of them used, or no room left for the wrap-up
 * after another turn of tools: `wrapUpDue`), the model's context window (no room in it for the
 * wrap-up after another turn, or for the answers of the last one: `limits.maxCallInputTokens`), or
 * its turns (`maxTurns` taken). When more than one comes at once it is the first of these, in this
 * order, except for answers the window had no room for, which are always the window. The review's
 * time (`limits.deadline`) comes after them: it makes the wrap-up of a call none of them did.
 */
export type WrapUpReason = 'budget' | 'turns' | 'window' | 'time';

/**
 * How a conversation ended. `text` of an answer is the model's: it goes to the parser, never to a
 * log. `wrappedUp` says why the answer came after the wrap-up turn, and is null for one that came
 * before any. A `provider_error` with `circuitOpen` is a call that was not made because the
 * provider's circuit was open: the provider is failing for every caller, and the conversation was
 * not asked to wait for it. `window_full` is a call that was not made because it would have reached
 * the model's context window (`limits.maxCallInputTokens`), even as the wrap-up on the history the
 * last call sent: the first message alone, or what the conversation has grown to. A
 * `provider_error` with `timeLimit` is a conversation whose time was up (`limits.deadline`) before
 * it had an answer: it had no turn, its last call failed, or that call's answer was not one.
 */
export type ConversationResult =
  | ({ kind: 'answer'; text: string; wrappedUp: WrapUpReason | null } & ConversationCounts)
  | ({ kind: 'stopped' } & ConversationCounts)
  | ({
      kind: 'failed';
      reason: 'provider_error' | 'provider_no_tools' | 'bad_answer' | 'window_full';
      circuitOpen?: true;
      timeLimit?: true;
    } & ConversationCounts);

/** How a conversation ends without an answer, before the counts are put to it. */
type FailureReason = Extract<ConversationResult, { kind: 'failed' }>['reason'];
type Ended =
  | { kind: 'stopped' }
  | { kind: 'failed'; reason: FailureReason; circuitOpen?: true; timeLimit?: true };
const failed = (reason: FailureReason): Ended => ({ kind: 'failed', reason });
/** The review's time is up, and the conversation makes no call (`limits.deadline`). */
const TIME_LIMIT: Ended = { kind: 'failed', reason: 'provider_error', timeLimit: true };

/** What `send` throws when it made no call because the provider's circuit is open. */
export class CircuitOpenError extends Error {
  constructor() {
    super('The model provider is failing; Qualor is not calling it for now');
    this.name = 'CircuitOpenError';
  }
}

// ─── The arguments a model sends ─────────────────────────────────────────────

/**
 * Whether objects and lists inside `root` (level 1) go deeper than `limit` levels. It follows the
 * structure with a list of its own, not the call stack, and goes no further than `limit` levels:
 * a model can send arguments that JSON.parse reads and JSON.stringify cannot follow.
 */
function nestedDeeperThan(root: object, limit: number): boolean {
  const pending: { node: object; depth: number }[] = [{ node: root, depth: 1 }];
  for (let item = pending.pop(); item !== undefined; item = pending.pop()) {
    if (item.depth > limit) return true;
    for (const child of Object.values(item.node)) {
      if (typeof child === 'object' && child !== null) {
        pending.push({ node: child, depth: item.depth + 1 });
      }
    }
  }
  return false;
}

/**
 * The arguments to run a call with, and to echo back in the history, or null when they cannot be
 * either. A call with none has `{}`. Text that was not JSON, a list, a number or a boolean is not
 * an object, which every tool takes; arguments nested too deep or too long are refused before
 * they are written out (a strict server refuses the echo of a raw string, and JSON.stringify of
 * a deep value throws a RangeError, which is not an LlmError).
 */
function usableArguments(raw: unknown): Record<string, unknown> | null {
  if (raw === undefined || raw === null) return {};
  if (typeof raw !== 'object' || Array.isArray(raw)) return null;
  if (nestedDeeperThan(raw, CONVERSATION_LIMITS.maxArgumentDepth)) return null;
  let json: string;
  try {
    json = JSON.stringify(raw);
  } catch {
    return null;
  }
  if (Buffer.byteLength(json, 'utf8') > CONVERSATION_LIMITS.maxArgumentBytes) return null;
  return raw as Record<string, unknown>;
}

// ─── One call to the provider, and what a failure of it means ────────────────

/** Waits `ms`, or ends at once when `signal` aborts, or has aborted. */
const sleepFor = (ms: number, signal?: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    if (signal?.aborted === true) {
      resolve();
      return;
    }
    const wake = (): void => {
      clearTimeout(timer);
      signal?.removeEventListener('abort', wake);
      resolve();
    };
    const timer = setTimeout(wake, ms);
    signal?.addEventListener('abort', wake, { once: true });
  });

/**
 * Whether the provider refused a first request because it carried tools: a refusal of the request
 * itself (400, 404 or 422) whose own words named tools or functions (the provider layer says so
 * with `refusedTools`). A server without tool calling cannot review, whatever else is right. The
 * provider test reads a refusal the same way.
 */
export function refusedForTools(err: LlmError, tools: readonly LlmToolSpec[]): boolean {
  return (
    tools.length > 0 &&
    err.failure === 'rejected' &&
    err.refusedTools &&
    err.status !== null &&
    TOOL_REFUSAL_STATUSES.includes(err.status)
  );
}

/**
 * The seconds to wait before trying a failed call again, counted against the retries of that call
 * (`retried`), or null when it is not tried again: a rate limit waits what the provider asked, but
 * never more than a minute and never less than a second, and twice at most; a timeout or an
 * unavailable provider waits what the provider asked (same bounds) or else the backoff, twice in
 * all; anything else is not tried again.
 */
function retryWait(
  err: LlmError,
  retried: { rateLimited: number; transient: number },
): number | null {
  const { backoffSeconds, minWaitSeconds, maxWaitSeconds } = CONVERSATION_RETRIES;
  if (err.failure === 'rate_limited' && retried.rateLimited < CONVERSATION_RETRIES.rateLimited) {
    const asked = err.retryAfterSeconds ?? backoffSeconds[retried.rateLimited] ?? maxWaitSeconds;
    retried.rateLimited += 1;
    return Math.min(maxWaitSeconds, Math.max(minWaitSeconds, asked));
  }
  if (
    (err.failure === 'timeout' || err.failure === 'unavailable') &&
    retried.transient < CONVERSATION_RETRIES.transient
  ) {
    const asked = err.retryAfterSeconds ?? backoffSeconds[retried.transient] ?? maxWaitSeconds;
    retried.transient += 1;
    return Math.min(maxWaitSeconds, Math.max(minWaitSeconds, asked));
  }
  return null;
}

/** A turn of the model, with the conversation that was sent for it. */
interface Taken {
  turn: LlmTurn;
  sent: LlmConversation;
}

/** The bytes of JSON a token is guessed to stand for. The day guesses the same (usage.ts). */
const BYTES_PER_TOKEN = 4;

/** The guess for the tokens of what is sent as JSON: a quarter of a token for each byte. */
const guessedTokens = (value: unknown): number =>
  Math.ceil(Buffer.byteLength(JSON.stringify(value), 'utf8') / BYTES_PER_TOKEN);

/**
 * The guess for the input of a call the provider did not count, which the budgets count: the JSON
 * that is sent, a quarter of a token for each byte (what the server records as its input bytes,
 * usage.ts).
 */
export const guessedInput = (sent: LlmConversation): number => guessedTokens(sent);

/**
 * The characters a token of code or JSON stands for, at the least: a first message is sized with it
 * (pipeline.ts), and the model's window is guarded with it, so that what is guessed is more tokens,
 * not fewer.
 */
export const CHARS_PER_TOKEN = 3;

/**
 * The guess for the tokens of what is sent as JSON, against the model's context window: a token for
 * every CHARS_PER_TOKEN bytes of it, which is never fewer tokens than its characters make. It is
 * a third more than the budgets' guess (`guessedTokens`), whose quarter of a token a byte undercounts
 * code.
 */
const windowTokens = (value: unknown): number =>
  Math.ceil(Buffer.byteLength(JSON.stringify(value), 'utf8') / CHARS_PER_TOKEN);

/**
 * The window's guess for all of what a call sends (`windowTokens`): the least the loop guesses a
 * call to send against the model's window (`nextCallInput`), whatever the provider counted before.
 */
export const windowGuessedInput = (sent: LlmConversation): number => windowTokens(sent);

/**
 * The tokens the wrap-up's message adds to the window's guess for the call it goes with, at the
 * most: its own, and one for the comma that joins it to the history. A turn whose answers are sent
 * because the next call has this much room under the window therefore has room for the wrap-up too.
 */
const WRAP_UP_TOKENS = windowTokens({ role: 'user', text: CONVERSATION_TEXTS.wrapUp }) + 1;

/**
 * What a failed call comes to: the end of the conversation, or the seconds to wait before the call
 * is tried again. An error that is none of the provider's is thrown on.
 */
function afterFailure(
  err: unknown,
  input: ConversationInput,
  sent: LlmConversation,
  first: boolean,
  charge: (inputTokens: number) => void,
  retried: { rateLimited: number; transient: number },
): Ended | number {
  if (err instanceof CircuitOpenError) {
    return { kind: 'failed', reason: 'provider_error', circuitOpen: true };
  }
  if (err instanceof LlmCallAborted) return { kind: 'stopped' };
  if (!(err instanceof LlmError)) throw err;
  if (first && refusedForTools(err, input.tools)) return failed('provider_no_tools');
  if (err.failure === 'timeout' || err.failure === 'bad_answer') charge(guessedInput(sent));
  const wait = retryWait(err, retried);
  return wait === null ? failed('provider_error') : wait;
}

/** How the review's time stands for a conversation (`limits.deadline`): what `Talk` answers. */
interface Timing {
  /**
   * Asked before a call: `in_time`; `last` when the time is up and this call is the last, made
   * once; or the end of a conversation that makes no call.
   */
  beforeCall(): 'in_time' | 'last' | Ended;
  /** Whether a retry may wait `ms`: not when the time is up first, and then it is up. */
  mayWait(ms: number): boolean;
}

/**
 * The model's next turn, or why there is none: the stop check is asked before every call, then
 * the review's time (`timing`); a failed call is tried again as `retryWait` says, unless it was the
 * last call or the time would be up before the wait ends; and the first call refused for its tools
 * ends the conversation as such. A call the provider most likely billed although it gave no turn,
 * one that timed out or whose answer could not be read, is charged its guessed input through
 * `charge`. A call its caller gave up stops the conversation: it is no failure of the provider's,
 * so it is neither tried again nor charged.
 */
async function nextTurn(
  input: ConversationInput,
  conversation: () => LlmConversation,
  first: boolean,
  charge: (inputTokens: number) => void,
  timing: Timing,
): Promise<Taken | Ended> {
  const retried = { rateLimited: 0, transient: 0 };
  for (;;) {
    if (await input.shouldStop()) return { kind: 'stopped' };
    const time = timing.beforeCall();
    if (typeof time !== 'string') return time;
    const sent = conversation();
    try {
      return { turn: await input.send(sent), sent };
    } catch (err) {
      const next = afterFailure(err, input, sent, first, charge, retried);
      if (typeof next !== 'number') return next;
      if (time === 'last') return TIME_LIMIT;
      // A wait the time would be up before is not made: the next call is the last, or none.
      if (!timing.mayWait(next * 1_000)) continue;
      await (input.sleep ?? sleepFor)(next * 1_000, input.signal);
    }
  }
}

// ─── The calls of a turn ─────────────────────────────────────────────────────

/** The replay of a turn, as the field of the message that adds the turn to the history. */
const replayField = (replay: ProviderReplay | undefined): { replay?: ProviderReplay } =>
  replay === undefined ? {} : { replay };

/** The calls of a turn that were answered: how many were run, and their answers' `sent`. */
interface Answered {
  run: number;
  /** What to call once the answers are kept for the next call, each answer's in order. */
  sent: (() => void)[];
  /** What to call instead when they are never sent. */
  withheld: (() => void)[];
}

/**
 * Adds the model's turn to the history, with every call echoed (so that each has its answer), and
 * the answer to each: the first `maxCallsPerTurn` calls are run, in order, unless their arguments
 * are unusable, and the others are told there were too many. Every answer is put in the data
 * envelope. The turn's `replay` goes on its message unchanged.
 */
async function answerCalls(
  input: ConversationInput,
  text: string,
  calls: readonly LlmToolCall[],
  replay: ProviderReplay | undefined,
  messages: LlmMessage[],
): Promise<Answered> {
  const prepared = calls.map((call) => ({ call, args: usableArguments(call.arguments) }));
  messages.push({
    role: 'assistant',
    text,
    toolCalls: prepared.map(({ call, args }) => ({
      id: call.id,
      name: call.name,
      arguments: args ?? {},
    })),
    ...replayField(replay),
  });
  const answered: Answered = { run: 0, sent: [], withheld: [] };
  for (const [index, { call, args }] of prepared.entries()) {
    let answer: string;
    if (index >= input.limits.maxCallsPerTurn) {
      answer = CONVERSATION_TEXTS.tooManyCalls;
    } else if (args === null) {
      answer = CONVERSATION_TEXTS.badArguments;
    } else {
      const ran = await input.runTool({ id: call.id, name: call.name, arguments: args });
      answered.run += 1;
      if (typeof ran === 'string') {
        answer = ran;
      } else {
        answer = ran.text;
        answered.sent.push(ran.sent);
        if (ran.withheld !== undefined) answered.withheld.push(ran.withheld);
      }
    }
    messages.push(toolMessage(input, call, answer));
  }
  return answered;
}

/** The message that answers a call: `answer` in the data envelope. */
const toolMessage = (
  input: Pick<ConversationInput, 'nonce'>,
  call: Pick<LlmToolCall, 'id' | 'name'>,
  answer: string,
): LlmMessage => ({
  role: 'tool',
  callId: call.id,
  name: call.name,
  text: toolResultMessage(cutAtGrapheme(call.name, TOOL_LABEL_CHARS), answer, input.nonce),
});

/**
 * Puts CONTEXT_FULL_TEXT in the place of each answer of the history from `from` on: they have not
 * been sent, and the next call has no room for them.
 */
function withholdAnswers(
  input: Pick<ConversationInput, 'nonce'>,
  messages: LlmMessage[],
  from: number,
): void {
  for (let i = from; i < messages.length; i += 1) {
    const message = messages[i];
    if (message?.role !== 'tool') continue;
    messages[i] = toolMessage(input, { id: message.callId, name: message.name }, CONTEXT_FULL_TEXT);
  }
}

// ─── The conversation ────────────────────────────────────────────────────────

/**
 * What a turn costs the budget: the provider's counts, and for a count it did not give a guess, so
 * that a provider which counts nothing cannot spend without limit. The guess for the input is
 * `guessedInput`, and for the output the longest answer a call may write. The conversation is
 * serialised only when the input count is missing.
 */
function tokensOf(
  turn: LlmTurn,
  sent: LlmConversation,
  maxOutputTokens: number,
): { input: number; output: number } {
  return {
    input: turn.usage.inputTokens ?? guessedInput(sent),
    output: turn.usage.outputTokens ?? maxOutputTokens,
  };
}

/**
 * Whether the turn after a turn of tools must be the wrap-up for the tokens: `used` has reached
 * 85 % of the budget, or another turn of tools would leave no room for the wrap-up after it. Both
 * calls are guessed from the last one (`last`, what it cost) and from what its tools answered
 * (`grown`), since the history only grows:
 * - the next call sends the last one's input, its output and what the tools answered, and writes
 *   as much as the last one wrote;
 * - the wrap-up after it sends that call's input and output again, with as much more from its
 *   tools, and writes at most `maxOutputTokens`.
 * The wrap-up can still go past the budget: by as much as those guesses fall short, or when the
 * first turn of tools, which runs before anything is known of what a turn costs, already left no
 * room for it. A whole turn of tools past it cannot.
 *
 * With a window (`limits.maxCallInputTokens`), the next turn is also the wrap-up when the wrap-up
 * after the next call would send that call's input (`window.nextInput`, as `nextCallInput`
 * guesses it), as much again as the model's turn added to it (`window.carried`) and as its tools
 * answered (`window.grown`, the window's guess), with the wrap-up's own words, and reach the window.
 * The tokens are asked first: when both are due it is the budget.
 */
function wrapUpDue(
  limits: ConversationInput['limits'],
  used: number,
  last: { input: number; output: number },
  grown: number,
  window: { nextInput: number; carried: number; grown: number } | null,
): 'budget' | 'window' | null {
  if (used >= CONVERSATION_LIMITS.wrapUpAt * limits.tokenBudget) return 'budget';
  const counted = last.input + last.output + grown;
  const nextCall = counted + last.output;
  const wrapUpAfter = counted + last.output + grown + limits.maxOutputTokens;
  if (used + nextCall + wrapUpAfter >= limits.tokenBudget) return 'budget';
  const cap = limits.maxCallInputTokens;
  if (
    cap !== undefined &&
    window !== null &&
    window.nextInput + window.carried + window.grown + WRAP_UP_TOKENS >= cap
  ) {
    return 'window';
  }
  return null;
}

/**
 * What an assistant message adds to the next request, by the window's guess: what the request
 * carries for it. A turn with a replay goes back as its provider's blocks or items, which hold what
 * it reasoned when that wire sends the reasoning back (Anthropic's signed thinking, the Responses
 * API's reasoning items): at least `output`, the provider's count of what the turn wrote. A turn
 * without one goes back as its text and its calls alone (Chat Completions sends no reasoning back,
 * though its output count holds it): their guess.
 */
function carriedTokens(message: LlmMessage | undefined, output: number): number {
  if (message?.role !== 'assistant') return 0;
  if (message.replay !== undefined) return Math.max(output, windowTokens(message.replay.items));
  return windowTokens({ text: message.text, toolCalls: message.toolCalls });
}

/**
 * The guess for what the next call sends, in tokens, against the window: the last call's input as
 * the provider counted it (`lastInput`), what the model's turn adds as the request carries it
 * (`carried`, `carriedTokens`), and `added` (the window's guess for the messages that joined the
 * history after it: what its tools answered, the loop's own words); and never less than the window's
 * guess for all of what the call sends (`windowGuessedInput` of `next`), so that a provider that
 * counts low, or nothing, cannot take a call past the window.
 */
function nextCallInput(
  lastInput: number,
  carried: number,
  added: number,
  next: LlmConversation,
): number {
  return Math.max(lastInput + carried + added, windowGuessedInput(next));
}

/**
 * Talks with the model until it answers in text:
 * - the tool list goes with every turn, the wrap-up included (Anthropic refuses tool blocks in the
 *   history without it);
 * - once the model has had `maxTurns` turns, or the calls have used 85 % of the token budget, or
 *   another turn of tools would leave no room for the wrap-up after it, in the budget or in the
 *   model's context window (`wrapUpDue`), the next turn is the wrap-up: a user message that says to
 *   answer now. Calls in its answer are not run, and its text is the answer;
 * - answers of a turn of tools that would make the next call reach the window are each sent as
 *   CONTEXT_FULL_TEXT, and that call is the wrap-up; their `withheld` is called, not their `sent`.
 *   When not even that fits beside what the model's turn wrote, the turn, which was never sent,
 *   goes with its answers, and the wrap-up is asked on the history the last call sent; so is an
 *   answer asked for again that would reach the window. A first call that would reach it, and one
 *   that would even so, is not made: the conversation ends `window_full`
 *   (`limits.maxCallInputTokens`);
 * - a call is told apart by what is there, not by the finish reason: `tool` also comes without
 *   calls, and then text is an answer and no text is none;
 * - an answer cut off at the output limit is asked for again, shorter, once; a refusal, a blank
 *   answer and a call id used twice in a turn end the conversation as a bad answer;
 * - an answer the caller does not accept (`accept`) is asked for again once: the answer stays in
 *   the history (with its replay, unless it had calls, which were not run and go back as text
 *   alone) and a user message says what was wrong with it (the caller's text, or the loop's own).
 *   From then on calls are not run, and that turn may go past the budget, as the wrap-up's may; a
 *   second answer it does not accept ends the conversation as a bad answer.
 *
 * Every end reports what was spent (`ConversationCounts`), the tokens of a call the provider did
 * not count being guessed. The token budget must be more than 0 (see `limits.tokenBudget`).
 */
export async function runConversation(input: ConversationInput): Promise<ConversationResult> {
  return new Talk(input).run();
}

/** The tokens of a turn as the loop counts them. */
type Spent = { input: number; output: number };
type WindowGuess = { nextInput: number; carried: number; grown: number };

/** One conversation: the history, and what it has spent so far. */
class Talk {
  private readonly messages: LlmMessage[];
  private turns = 0;
  private toolCalls = 0;
  private inputTokens = 0;
  private outputTokens = 0;
  private cacheReadTokens = 0;
  private cacheWriteTokens = 0;
  /** Why the next turn is the wrap-up, once it is. */
  private wrapUp: WrapUpReason | null = null;
  private askedForShorter = false;
  /** An answer was not accepted: the model is asked for it again, and runs no more tools. */
  private askedAgain = false;
  private readonly cap: number | undefined;
  /** The review's time (`limits.deadline`): when it is up, on the clock of `now`. */
  private readonly deadline: number;
  private readonly now: () => number;
  /** The time is up: the deadline passed, or a retry would have waited past it. */
  private timeUp = false;
  /** The last call, made once the time was up: no other is made. */
  private lastCallMade = false;
  private readonly timing: Timing = {
    beforeCall: () => this.beforeCall(),
    mayWait: (ms) => this.mayWait(ms),
  };

  constructor(private readonly input: ConversationInput) {
    this.messages = [{ role: 'user', text: input.user }];
    this.cap = input.limits.maxCallInputTokens;
    this.deadline = input.limits.deadline ?? Number.POSITIVE_INFINITY;
    this.now = input.now ?? Date.now;
  }

  // A copy of the history for each call: what `send` is given is not changed after it.
  private readonly conversation = (): LlmConversation => ({
    system: this.input.system,
    messages: [...this.messages],
    tools: this.input.tools,
    maxOutputTokens: this.input.limits.maxOutputTokens,
    ...(this.input.limits.reasoningAllowance
      ? { reasoningAllowance: this.input.limits.reasoningAllowance }
      : {}),
  });

  /**
   * What a call is sent: the history, with the room to think cut to what the window has left of it
   * after the call's input and its answer (`limits.maxCallInputTokens` is the window less the
   * answer, so that is the cap less the window's guess for the input), and none when there is none.
   */
  private readonly callConversation = (): LlmConversation => {
    const base = this.conversation();
    const { reasoningAllowance: allowance } = this.input.limits;
    if (!allowance || this.cap === undefined) return base;
    const room = Math.min(allowance, Math.max(0, this.cap - windowGuessedInput(base)));
    if (room > 0) return { ...base, reasoningAllowance: room };
    const { reasoningAllowance: _none, ...rest } = base;
    void _none;
    return rest;
  };

  private counts(): ConversationCounts {
    return {
      inputTokens: this.inputTokens,
      outputTokens: this.outputTokens,
      cacheReadTokens: this.cacheReadTokens,
      cacheWriteTokens: this.cacheWriteTokens,
      turns: this.turns,
      toolCalls: this.toolCalls,
    };
  }

  /** An end without an answer, with what the conversation spent. */
  private ended(end: Ended): ConversationResult {
    return { ...end, ...this.counts() };
  }

  /**
   * Whether the next call, with the history as it is now, would reach the window (R46): the last
   * call sent the history up to `sentUpTo` and cost `last`; what joined it since is the model's turn,
   * as the request carries it (`carriedTokens`), and the window's guess for the rest.
   */
  private reachesWindow(last: Spent, sentUpTo: number): boolean {
    if (this.cap === undefined) return false;
    const [first, ...rest] = this.messages.slice(sentUpTo);
    const carried = carriedTokens(first, last.output);
    const added = first?.role === 'assistant' ? rest : this.messages.slice(sentUpTo);
    return nextCallInput(last.input, carried, windowTokens(added), this.conversation()) >= this.cap;
  }

  /**
   * The model's last turn was never sent, and the window has no room for it: it goes, with what
   * followed it, and `ask` is made on the history the last call sent (`sentUpTo`). True when that
   * fits the window.
   */
  private askOnSentHistory(last: Spent, sentUpTo: number, ask: string): boolean {
    this.messages.length = sentUpTo;
    this.messages.push({ role: 'user', text: ask });
    return !this.reachesWindow(last, sentUpTo);
  }

  /** Whether `ask`, made after the turn just taken, would leave no room in the window. */
  private askedPastWindow(spent: Spent, sent: LlmConversation, ask: string): boolean {
    return (
      this.reachesWindow(spent, sent.messages.length) &&
      !this.askOnSentHistory(spent, sent.messages.length, ask)
    );
  }

  /**
   * Before a call, as the review's time stands (`limits.deadline`). Once it is up, a conversation
   * that has had a turn makes one call more, its last: when the model was to have a turn of tools,
   * it becomes the wrap-up (`'time'`), with the wrap-up's words after the answers of the last turn;
   * an answer asked for again is asked as it is, and its calls are not run. A wrap-up that was due
   * already keeps its reason, and an answer asked for again after one the caller did not accept
   * runs no tools anyway.
   */
  private beforeCall(): 'in_time' | 'last' | Ended {
    if (!this.timeUp && this.now() < this.deadline) return 'in_time';
    this.timeUp = true;
    if (this.turns === 0 || this.lastCallMade) return TIME_LIMIT;
    this.lastCallMade = true;
    if (this.wrapUp === null && !this.askedAgain) {
      this.wrapUp = 'time';
      if (this.messages.at(-1)?.role === 'tool') {
        this.messages.push({ role: 'user', text: CONVERSATION_TEXTS.wrapUp });
      }
    }
    return 'last';
  }

  /**
   * Whether a retry may wait `ms`: only when the wait ends before the deadline. A wait that does
   * not is not made, and the time is up.
   */
  private mayWait(ms: number): boolean {
    if (ms < this.deadline - this.now()) return true;
    this.timeUp = true;
    return false;
  }

  async run(): Promise<ConversationResult> {
    // The first call is the caller's to size: one that would reach the window is not made.
    if (this.cap !== undefined && windowGuessedInput(this.conversation()) >= this.cap) {
      return this.ended(failed('window_full'));
    }
    for (;;) {
      const next = await nextTurn(
        this.input,
        this.callConversation,
        this.turns === 0,
        (guessed) => {
          this.inputTokens += guessed;
        },
        this.timing,
      );
      if (!('turn' in next)) return this.ended(next);
      const { turn, sent } = next;
      this.turns += 1;
      const spent = tokensOf(turn, sent, this.input.limits.maxOutputTokens);
      this.inputTokens += spent.input;
      this.outputTokens += spent.output;
      this.cacheReadTokens += turn.usage.cacheReadTokens ?? 0;
      this.cacheWriteTokens += turn.usage.cacheWriteTokens ?? 0;
      if (turn.finishReason === 'refusal') return this.ended(failed('bad_answer'));
      const result = await this.settle(turn, sent, spent);
      if (result !== null) return result;
    }
  }

  /** The result the turn ends the conversation with, or null when the conversation goes on. */
  private async settle(
    turn: LlmTurn,
    sent: LlmConversation,
    spent: Spent,
  ): Promise<ConversationResult | null> {
    if (turn.toolCalls.length > 0 && this.wrapUp === null && !this.askedAgain) {
      return this.answerTools(turn, sent, spent);
    }
    if (turn.finishReason === 'length' && turn.toolCalls.length === 0) {
      return this.askForShorter(turn, sent, spent);
    }
    if (turn.text.trim() === '') return this.ended(failed('bad_answer'));
    const accepted = this.input.accept?.(turn.text) ?? true;
    if (accepted !== true) return this.askAgain(turn, sent, spent, accepted);
    return { kind: 'answer', text: turn.text, wrappedUp: this.wrapUp, ...this.counts() };
  }

  /** A turn of tools: its calls are run and answered, and the next turn may be the wrap-up. */
  private async answerTools(
    turn: LlmTurn,
    sent: LlmConversation,
    spent: Spent,
  ): Promise<ConversationResult | null> {
    const ids = new Set(turn.toolCalls.map((call) => call.id));
    if (ids.size !== turn.toolCalls.length) return this.ended(failed('bad_answer'));
    // The model's turn joins the history first, then the answers to its calls.
    const answersFrom = this.messages.length + 1;
    const answered = await answerCalls(
      this.input,
      turn.text,
      turn.toolCalls,
      turn.replay,
      this.messages,
    );
    this.toolCalls += answered.run;
    /** Whether the answers go as they are. */
    let kept = this.chooseWrapUp(spent, answersFrom);
    if (this.wrapUp !== null) {
      this.messages.push({ role: 'user', text: CONVERSATION_TEXTS.wrapUp });
    }
    if (this.reachesWindow(spent, sent.messages.length)) {
      // Not even the fixed lines fit beside what the model's turn wrote (a turn that wrote at
      // length beside its calls): the turn was never sent, and it goes with its answers.
      kept = false;
      this.wrapUp = 'window';
      if (!this.askOnSentHistory(spent, sent.messages.length, CONVERSATION_TEXTS.wrapUp)) {
        for (const told of answered.withheld) told();
        return this.ended(failed('window_full'));
      }
    }
    for (const told of kept ? answered.sent : answered.withheld) told();
    return null;
  }

  /**
   * Whether the next turn is the wrap-up, and why (`this.wrapUp`). The answers of a turn of tools
   * that would make the next call reach the window go as the fixed line instead; the result says
   * whether they go as they are.
   */
  private chooseWrapUp(spent: Spent, answersFrom: number): boolean {
    const { limits } = this.input;
    const grown = guessedTokens(this.messages.slice(answersFrom));
    const window = this.windowGuess(spent, answersFrom);
    if (
      this.cap !== undefined &&
      window !== null &&
      window.nextInput + WRAP_UP_TOKENS >= this.cap
    ) {
      // The next call would reach the window with these answers: each goes as the fixed line,
      // before it is first sent, and that call is the wrap-up (R46).
      withholdAnswers(this.input, this.messages, answersFrom);
      this.wrapUp = 'window';
      return false;
    }
    this.wrapUp =
      wrapUpDue(limits, this.inputTokens + this.outputTokens, spent, grown, window) ??
      (this.turns >= limits.maxTurns ? 'turns' : null);
    return true;
  }

  /** The window's guess for the next call after a turn of tools, null without a window. */
  private windowGuess(spent: Spent, answersFrom: number): WindowGuess | null {
    if (this.cap === undefined) return null;
    const carried = carriedTokens(this.messages[answersFrom - 1], spent.output);
    const grown = windowTokens(this.messages.slice(answersFrom));
    return {
      nextInput: nextCallInput(spent.input, carried, grown, this.conversation()),
      carried,
      grown,
    };
  }

  /** An answer cut off at the output limit is asked for again, shorter, once. */
  private askForShorter(
    turn: LlmTurn,
    sent: LlmConversation,
    spent: Spent,
  ): ConversationResult | null {
    if (this.askedForShorter) return this.ended(failed('bad_answer'));
    this.askedForShorter = true;
    // The API refuses an assistant message with nothing in it; a turn with no message goes
    // without its replay too.
    if (turn.text.trim() !== '') {
      this.messages.push({
        role: 'assistant',
        text: turn.text,
        toolCalls: [],
        ...replayField(turn.replay),
      });
    }
    this.messages.push({ role: 'user', text: CONVERSATION_TEXTS.shorter });
    // Asked for again within the window: without the answer, which was never sent, when it
    // leaves no room.
    if (this.askedPastWindow(spent, sent, CONVERSATION_TEXTS.shorter)) {
      return this.ended(failed('window_full'));
    }
    return null;
  }

  /** An answer the caller does not accept is asked for again once. */
  private askAgain(
    turn: LlmTurn,
    sent: LlmConversation,
    spent: Spent,
    accepted: string | false,
  ): ConversationResult | null {
    if (this.askedAgain) return this.ended(failed('bad_answer'));
    this.askedAgain = true;
    // The calls of this turn, if any, were not run: the answer goes back as text alone, and so
    // without its replay, which holds the calls and has no results to send beside them.
    this.messages.push({
      role: 'assistant',
      text: turn.text,
      toolCalls: [],
      ...(turn.toolCalls.length === 0 ? replayField(turn.replay) : {}),
    });
    const said = typeof accepted === 'string' && accepted.trim() !== '';
    const ask = said ? accepted : CONVERSATION_TEXTS.retry;
    this.messages.push({ role: 'user', text: ask });
    if (this.askedPastWindow(spent, sent, ask)) return this.ended(failed('window_full'));
    return null;
  }
}
