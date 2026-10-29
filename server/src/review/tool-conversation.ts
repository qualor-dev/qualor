import { REASONING_ALLOWANCE_TOKENS } from '../llm/providers';
import {
  CONVERSATION_LIMITS,
  runConversation,
  type ConversationInput,
  type ConversationResult,
} from './conversation';
import type { MaskedFiles } from './masked-files';
import type { Masker } from './masker';
import type { ConversationRole } from './model-tiers';
import { REVIEW_OUTPUT_TOKENS } from './pipeline';
import { SYSTEM_PROMPTS } from './prompts';
import type { SnapshotReader } from './snapshot-reader';
import {
  REVIEW_TOOLS,
  runReviewTool,
  TOOL_LIMITS,
  type ShownLines,
  type ToolPolicy,
} from './tools';

/*
 * The parts of a review's conversations that are the same wherever the review runs: the `ai-review`
 * job (job.ts) records every call in the database, the evaluation set (tools/review) calls the
 * provider and records nothing. Each supplies where a call goes (`send`) and when to stop
 * (`shouldStop`), and the model's context window; the role's prompt, the tools, their budget and
 * the caps of the loop are these.
 * The answer to a person's reply (reply-engine.ts) is one more conversation of the same kind, with
 * a prompt of its own and, for a merge request that has no snapshot, no tools.
 */

/** One conversation the pipeline asks for (`PipelineDeps.converse`), or a reply's. */
export interface RoleCall {
  role: ConversationRole;
  /**
   * The system prompt, when the role's fixed one (`SYSTEM_PROMPTS`) is not it: the prompt of a
   * reply names the verdicts its thread allows, which no fixed text can.
   */
  system?: string;
  /** The first message: the data under review, in its envelope. */
  user: string;
  /** The nonce of that envelope, which the tools' answers are put in too. */
  nonce: string;
  tokenBudget: number;
  /**
   * The caller's check of an answer (`ConversationInput.accept`): `true` takes it; `false`, or a
   * text, asks once more, with the loop's own words or with that text.
   */
  accept: (text: string) => boolean | string;
  /** When the review's time is up, on the io's clock (`limits.deadline`); absent: no limit. */
  deadline?: number;
}

/** The reader a conversation's tools read, with the policy they run under. */
interface ToolsIo {
  /** The snapshot the tools read. */
  reader: SnapshotReader;
  policy: ToolPolicy;
  /** Told the secrets masked in each tool answer that is sent. */
  onToolRedactions?: (count: number) => void;
  /**
   * Told the lines of files a tool answer showed (`ToolAnswer.read`), for each call that showed
   * any: what the model really read, as the tool did it, never as its text says. An answer the
   * model's context window had no room for (CONTEXT_FULL_TEXT went in its place) showed nothing.
   */
  onToolRead?: (shown: readonly ShownLines[]) => void;
}

/**
 * Where a conversation reads, calls and stops. Without a snapshot (`reader: null`) the model is
 * given no tools: a reply can be answered from what its first message holds.
 */
export type ConversationIo = {
  send: ConversationInput['send'];
  shouldStop: ConversationInput['shouldStop'];
  /** Wakes the wait of a retry when it aborts: the server is stopping (`ConversationInput.signal`). */
  signal?: ConversationInput['signal'];
  /** The clock of the call's `deadline` (`ConversationInput.now`); Date.now when left out. */
  now?: ConversationInput['now'];
  /**
   * The model's context window, in tokens: the provider's `contextWindowTokens`, one for every
   * tier. Null or absent: DEFAULT_CONTEXT_WINDOW_TOKENS. No call sends more than it less the role's
   * answer (`callInputCap`).
   */
  contextWindowTokens?: number | null;
} & (ToolsIo | { reader: null });

/** The context window of a model whose provider gives none (R46): the latest models' 1 000 000. */
export const DEFAULT_CONTEXT_WINDOW_TOKENS = 1_000_000;

/**
 * The most tokens one call of `role` may send (R46): the model's context window (`window`, or
 * DEFAULT_CONTEXT_WINDOW_TOKENS when null) less the room for the role's answer
 * (REVIEW_OUTPUT_TOKENS). Not positive for a window too small for that answer. The room to think
 * (REASONING_ALLOWANCE_TOKENS) is not taken from it: a model that refuses that much beside its input
 * is asked again without it (the provider layer).
 */
export function callInputCap(window: number | null, role: ConversationRole): number {
  return (window ?? DEFAULT_CONTEXT_WINDOW_TOKENS) - REVIEW_OUTPUT_TOKENS[role];
}

/** What a call is answered when it is made though the model has no tools. */
const NO_TOOLS_ANSWER = 'no tools are available; answer from what you were given';

/**
 * The policy of one review's tools: all of its budget of calls, searches and bytes to mask
 * (`TOOL_LIMITS`), over its masked files and its masker, which its caller closes. The budget is
 * shared by every conversation of the review.
 */
export function newToolPolicy(o: {
  excludePaths: readonly string[];
  masked: MaskedFiles;
  masker: Masker;
}): ToolPolicy {
  return {
    excludePaths: o.excludePaths,
    budget: {
      calls: TOOL_LIMITS.callsPerReview,
      greps: TOOL_LIMITS.grepsPerReview,
      maskedBytes: TOOL_LIMITS.maskedBytesPerReview,
    },
    masked: o.masked,
    masker: o.masker,
  };
}

/**
 * One conversation of a role over the read-only tools: the role's system prompt, the three tools
 * run over the reader under its policy (none without a reader), the loop's caps, and the role's
 * output limit: its answer's tokens (REVIEW_OUTPUT_TOKENS), which the loop estimates with, and the
 * room for the model to think before it answers (REASONING_ALLOWANCE_TOKENS), which only raises
 * what each call asks for, and which a model that refuses that much is asked without. No call sends
 * more than the io's context window less that answer (`callInputCap`). A tool answer's redactions
 * and the lines it showed are told once the loop keeps the answer for the next call, never for one
 * the window had no room for. The pipeline's contract for `converse` (pipeline.ts).
 */
export function converseOverTools(call: RoleCall, io: ConversationIo): Promise<ConversationResult> {
  // The second check keeps a floor of its own, so it can still look things up after the reviewers
  // used the shared budget; no other role is given more.
  if (call.role === 'verify' && io.reader !== null) {
    const { budget } = io.policy;
    budget.calls = Math.max(budget.calls, TOOL_LIMITS.verifyCallsFloor);
    budget.greps = Math.max(budget.greps, TOOL_LIMITS.verifyGrepsFloor);
  }
  return runConversation({
    system: call.system ?? SYSTEM_PROMPTS[call.role],
    user: call.user,
    nonce: call.nonce,
    tools: io.reader === null ? [] : REVIEW_TOOLS,
    runTool: async (toolCall) => {
      // Nothing is run for a model that asks for a tool it was not given: it is told so.
      if (io.reader === null) return NO_TOOLS_ANSWER;
      const { onToolRedactions, onToolRead, policy } = io;
      const answer = await runReviewTool(io.reader, toolCall, policy);
      // The masked files the call read from: the policy keeps them for the review.
      const files = policy.masked;
      return {
        text: answer.text,
        sent: () => {
          onToolRedactions?.(answer.redactions);
          if (answer.read !== undefined) onToolRead?.(answer.read);
        },
        // Never sent: the files' replacements go to the call that does send them.
        withheld: () => {
          for (const path of answer.masked ?? []) files?.giveBack(path);
        },
      };
    },
    limits: {
      maxTurns: CONVERSATION_LIMITS.maxTurns,
      maxCallsPerTurn: CONVERSATION_LIMITS.maxCallsPerTurn,
      tokenBudget: call.tokenBudget,
      maxOutputTokens: REVIEW_OUTPUT_TOKENS[call.role],
      reasoningAllowance: REASONING_ALLOWANCE_TOKENS.conversation,
      maxCallInputTokens: callInputCap(io.contextWindowTokens ?? null, call.role),
      deadline: call.deadline,
    },
    send: io.send,
    shouldStop: io.shouldStop,
    signal: io.signal,
    now: io.now,
    accept: call.accept,
  });
}
