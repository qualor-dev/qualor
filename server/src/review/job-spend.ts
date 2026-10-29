import { and, eq, sql } from 'drizzle-orm';
import { reviewRuns, type ReviewPhase, type ReviewRunRow } from '../db/schema';
import { costOf } from '../llm/job';
import { LlmError, type LlmConversation, type LlmTurn } from '../llm/providers';
import {
  pricingFor,
  type PricePair,
  type StoredLlmSettings,
  type StoredProvider,
} from '../llm/settings';
import type { ConversationResult } from './conversation';
import type { ReviewContext } from './context';
import type { ReviewJobDeps } from './job';
import type { Running } from './job-start';
import { modelFor, type ModelTier } from './model-tiers';
import { REVIEW_PROMPT_VERSION } from './prompts';
import { startedAtIs, writeRunSpend, type RunSpend } from './run-ends';
import type { SnapshotReader } from './snapshot-reader';
import { converseOverTools, type RoleCall } from './tool-conversation';
import type { ToolPolicy } from './tools';
import { RedactionTally, REVIEW_FEATURE, reviewCallSettings, reviewSender } from './usage';

/** What one conversation of the pipeline works with. */
export interface ConverseContext {
  running: Running;
  /** The provider as the settings store it, with its tier models: not `running.provider`. */
  storedProvider: StoredProvider;
  reader: SnapshotReader;
  policy: ToolPolicy;
  context: ReviewContext;
  shouldStop: () => Promise<boolean>;
  /** The clock of the review's time (`RoleCall.deadline`). */
  now: () => number;
}

/** What the run spends, counted over the calls of its conversations, and where it writes it. */
export class RunLedger {
  /** Provider calls made, the ones that failed included; the tokens and tool calls of the conversations. */
  private calls = 0;
  private toolCalls = 0;
  private inputTokens = 0;
  private outputTokens = 0;
  private cost = 0;
  /**
   * What the run names of its provider, set once the review reaches it: the host, and the standard
   * model, which is all the run records of its models (each call's row names the model it went to).
   * `pricing` only tells a run that has a cost from one that has none; each call is costed at the
   * prices of its own model (`converse`).
   */
  provider: { host: string; model: string; pricing: StoredLlmSettings['pricing'] } | null = null;

  constructor(private readonly deps: ReviewJobDeps) {}

  /**
   * One conversation of the pipeline: its own redaction tally (the context's replacements go with
   * the first message of a reviewer or the judge, each tool answer's with the call after it), the
   * role's output limit, the provider's context window, and every call through the sender that
   * records it, which a stop of the server cuts short. Every call goes to the model of the
   * conversation's tier, and its row and its cost are that model's.
   */
  async converse(
    ctx: ConverseContext,
    call: RoleCall,
    modelTier: ModelTier,
  ): Promise<ConversationResult> {
    const { running, storedProvider, reader, policy, context, shouldStop, now } = ctx;
    const pricing = pricingFor(running.settings.pricing, storedProvider, modelTier);
    const tally = new RedactionTally();
    if (call.role !== 'verify') tally.add(context.redactions);
    const sender = reviewSender({
      db: this.deps.db,
      runtime: { circuit: this.deps.llmCircuit },
      config: this.deps.config,
      settings: reviewCallSettings(running.settings),
      model: modelFor(storedProvider, modelTier),
      pricing,
      feature: REVIEW_FEATURE,
      source: { projectId: running.run.projectId, promptKey: running.run.id },
      promptVersion: REVIEW_PROMPT_VERSION,
      redactions: tally,
      logger: this.deps.logger,
      signal: this.deps.shutdown,
    });
    const result = await converseOverTools(call, {
      reader,
      policy,
      send: (conversation) => this.counted(sender, pricing, conversation),
      shouldStop,
      signal: this.deps.shutdown,
      now,
      onToolRedactions: (count) => tally.add(count),
      // One window for every tier (R46): no call sends more than it less the role's answer.
      contextWindowTokens: storedProvider.contextWindowTokens,
    });
    // Whichever way it ended, what it spent is the run's.
    this.inputTokens += result.inputTokens;
    this.outputTokens += result.outputTokens;
    this.toolCalls += result.toolCalls;
    // Written now, not only at the end: the day's budget reserves what the run has not yet spent.
    // Guarded by `startedAtIs`, like the end's write: a run started again is another job's.
    await writeRunSpend(this.deps.db, running.run.id, this.spend(), running.run.startedAt);
    return result;
  }

  /**
   * One call through the sender, counted: a call the provider answered, with its estimated cost at
   * the `pricing` of the model it went to, and one that failed (the sender recorded it; the key was
   * read before the review began, so every failure it throws as the provider's is a call that was
   * made). A call the stopping server gave up is not counted: the provider answered nothing, and the
   * sender recorded nothing.
   */
  private async counted(
    sender: (conversation: LlmConversation) => Promise<LlmTurn>,
    pricing: PricePair | null,
    conversation: LlmConversation,
  ): Promise<LlmTurn> {
    try {
      const turn = await sender(conversation);
      this.calls += 1;
      this.cost += costOf(pricing, turn.usage) ?? 0;
      return turn;
    } catch (err) {
      if (err instanceof LlmError) this.calls += 1;
      throw err;
    }
  }

  /** The pipeline starts a phase: written on the run while it reviews, if it is still this job's. */
  async phase(run: ReviewRunRow, phase: ReviewPhase): Promise<void> {
    await this.deps.db
      .update(reviewRuns)
      .set({ phase })
      .where(
        and(
          eq(reviewRuns.id, run.id),
          eq(reviewRuns.status, 'running'),
          startedAtIs(run.startedAt),
          sql`${reviewRuns.phase} IS DISTINCT FROM 'storing'`,
        ),
      );
  }

  /** What the run spent: where its calls went, how many, their tokens and their estimated cost. */
  spend(): RunSpend {
    return {
      providerHost: this.provider?.host ?? null,
      model: this.provider?.model ?? null,
      modelCalls: this.calls,
      toolCalls: this.toolCalls,
      inputTokens: this.inputTokens,
      outputTokens: this.outputTokens,
      costMicroUsd: this.provider === null || this.provider.pricing === null ? null : this.cost,
    };
  }

  /**
   * The spend of a run another job or a newer analysis ended: it was spent all the same. Not that
   * of a run that was started again since: it is another job's now.
   */
  async writeSpend(run: ReviewRunRow): Promise<void> {
    if (this.calls === 0) return;
    await writeRunSpend(this.deps.db, run.id, this.spend(), run.startedAt);
  }
}
