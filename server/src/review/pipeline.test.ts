import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { REDACTED } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import type { ReviewPhase } from '../db/schema';
import {
  CONTEXT_MAXIMA,
  SENSITIVE_PATH,
  type ContextShape,
  type ReviewableChange,
  type ReviewContext,
} from './context';
import type { LlmConversation } from '../llm/providers';
import { CONVERSATION_TEXTS, type ConversationResult, type WrapUpReason } from './conversation';
import { envelope, newNonce } from './envelope';
import type { ModelTier } from './model-tiers';
import {
  CHARS_PER_TOKEN,
  planReview,
  REVIEW_OUTPUT_TOKENS,
  instructionFloor,
  listCapsFor,
  reviewFits,
  reviewLimits,
  runReviewPipeline,
  STAGE_SHARES,
  type PipelineDeps,
  type PipelineOutcome,
  type ReviewRole,
} from './pipeline';
import {
  judgeData,
  LIST_CAP_STEPS,
  PROMPT_LIMITS,
  specialistData,
  SYSTEM_PROMPTS,
} from './prompts';
import { callInputCap, converseOverTools } from './tool-conversation';

/** The fake provider key of a test is built at run time, so no scanner takes it for a real one. */
const j = (...parts: string[]) => parts.join('');

function change(path: string, changedLines = 1): ReviewableChange {
  return {
    path,
    oldPath: null,
    status: 'modified',
    since: null,
    hasPatch: true,
    patchUsable: true,
    lines: 40,
    text: null,
    added: new Set([3]),
    removalPoints: [],
    changedLines,
    sensitive: SENSITIVE_PATH.test(path),
    removed: [],
    unshown: null,
  };
}

const META: ReviewContext['meta'] = {
  snapshotId: null,
  headSha: 'a'.repeat(40),
  baseSha: 'b'.repeat(40),
  sinceSha: null,
  targetBranch: 'main',
  mrTitle: 'Add a cart total',
  mrDescription: null,
  instructions: [],
  partial: false,
};

function contextOf(reviewed: ReviewableChange[], over: Partial<ReviewContext> = {}): ReviewContext {
  return {
    meta: META,
    reviewed,
    skipped: [],
    slices:
      '@@ src/cart.ts lines 1–3 of 40 @@\n 1 const a = 1;\n 2 const b = 2;\n 3+const total = a + b;',
    omittedFromSlices: [],
    unlistedFromSlices: 0,
    listCaps: LIST_CAP_STEPS[0],
    analyzer: [],
    prior: [],
    redactions: 0,
    ...over,
  };
}

/** One conversation the pipeline asked for, with the data its first message carried. */
interface Call {
  role: ReviewRole;
  user: string;
  nonce: string;
  tokenBudget: number;
  data: Record<string, unknown>;
  /** The check of an answer the pipeline gave the conversation. */
  accept: (text: string) => boolean | string;
  /** What the check said of each answer a scripted model gave (see `texts`). */
  accepted: (boolean | string)[];
  /** The tier of the model the pipeline asked the conversation to run on. */
  modelTier: ModelTier;
  /** When the conversation's time is up (`limits.deadline`). */
  deadline: number;
}
/**
 * A model that answers these texts in turn, each for `tokens`: the conversation asks again once
 * when the check refuses an answer and ends as a bad answer at the second refusal, as
 * runConversation does.
 */
interface Texts {
  texts: string[];
  tokens: [number, number];
}
type Reply = ConversationResult | Texts | ((call: Call) => ConversationResult);
const texts = (...answers: string[]): Texts => ({ texts: answers, tokens: [100, 10] });

/** The data of a first message: the envelope's line between its markers, and nothing after them. */
function opened(user: string, nonce: string): Record<string, unknown> {
  const lines = user.split('\n');
  expect(lines).toHaveLength(4);
  expect(lines[0]).toContain(nonce);
  expect(lines[1]).toBe(`<<<QUALOR-DATA-${nonce}`);
  expect(lines[3]).toBe(`QUALOR-DATA-${nonce}>>>`);
  return JSON.parse(lines[2] ?? '') as Record<string, unknown>;
}

const spent = (input: number, output: number) => ({
  inputTokens: input,
  outputTokens: output,
  cacheReadTokens: 0,
  cacheWriteTokens: 0,
  turns: 1,
  toolCalls: 0,
});

function asked({ texts: answers, tokens: [input, output] }: Texts, call: Call): ConversationResult {
  for (const [index, text] of answers.slice(0, 2).entries()) {
    const ok = call.accept(text);
    call.accepted.push(ok);
    if (ok === true) {
      return {
        kind: 'answer',
        text,
        wrappedUp: null,
        ...spent(input * (index + 1), output * (index + 1)),
      };
    }
  }
  return { kind: 'failed', reason: 'bad_answer', ...spent(input * 2, output * 2) };
}

/** Deps that answer each role from its list in turn, and record every call. */
function scripted(
  replies: Partial<Record<ReviewRole, Reply[]>>,
  providerKey: string | null = null,
) {
  const calls: Call[] = [];
  const left = new Map<string, Reply[]>(
    Object.entries(replies).map(([role, list]) => [role, [...(list ?? [])]]),
  );
  const deps: PipelineDeps = {
    providerKey,
    converse: (role, user, nonce, tokenBudget, accept, modelTier, deadline) => {
      const call: Call = {
        role,
        user,
        nonce,
        tokenBudget,
        data: opened(user, nonce),
        accept,
        accepted: [],
        modelTier,
        deadline,
      };
      calls.push(call);
      const reply = left.get(role)?.shift();
      if (reply === undefined) throw new Error(`no reply left for ${role}`);
      if (typeof reply === 'function') return Promise.resolve(reply(call));
      return Promise.resolve('texts' in reply ? asked(reply, call) : reply);
    },
  };
  return { deps, calls };
}

const answer = (
  value: unknown,
  [input, output]: [number, number] = [100, 10],
  wrappedUp: WrapUpReason | null = null,
): ConversationResult => ({
  kind: 'answer',
  text: JSON.stringify(value),
  wrappedUp,
  ...spent(input, output),
});
/** An answer that is not JSON, as a conversation that did not check it would give it back. */
const prose = (
  text: string,
  [input, output]: [number, number] = [100, 10],
): ConversationResult => ({
  kind: 'answer',
  text,
  wrappedUp: null,
  ...spent(input, output),
});
const stopped = (): ConversationResult => ({ kind: 'stopped', ...spent(50, 0) });
const failed = (
  reason: 'provider_error' | 'provider_no_tools' | 'bad_answer',
  [input, output]: [number, number] = [50, 0],
): ConversationResult => ({ kind: 'failed', reason, ...spent(input, output) });

/** A finding as a specialist writes it. */
const found = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  category: 'logic',
  severity: 'major',
  confidence: 'high',
  path: 'src/cart.ts',
  line: 3,
  endLine: 3,
  title: 'The total skips the last item',
  body: 'The loop bound is one short. Use `i < n`.',
  assumption: null,
  suggestion: null,
  ...over,
});
/** A finding as the judge writes it. */
const judgedAs = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  ...found(),
  sources: [],
  priorId: null,
  ...over,
});
const judgeSays = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  findings: [],
  dropped: [],
  prior: [],
  summary: { verdict: 'One major problem in the cart total.', walkthrough: ['Totals the cart.'] },
  ...over,
});
/** A judged finding as the outcome holds it. */
const outcomeFinding = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
  ...found(),
  sources: [],
  priorId: null,
  verification: null,
  ...over,
});

async function review(context: ReviewContext, budget: number, deps: PipelineDeps) {
  const phases: ReviewPhase[] = [];
  const outcome: PipelineOutcome = await runReviewPipeline(context, budget, deps, (phase) => {
    phases.push(phase);
    return Promise.resolve();
  });
  return { outcome, phases };
}

const titles = (outcome: PipelineOutcome): unknown[] =>
  outcome.kind === 'reviewed' ? outcome.findings.map((f) => f.title) : [];

const prior = (
  id: string,
  status: 'open' | 'false_positive' | 'wont_fix',
  severity = 'medium',
) => ({
  id,
  category: 'logic' as const,
  severity,
  status,
  path: 'src/cart.ts',
  line: 3,
  endLine: 3,
  title: `Prior ${id}`,
  body: 'The total skips the last item.',
  fingerprint: 'f'.repeat(32),
});

describe('planReview', () => {
  it('planReview picks trivial, lite and full by lines and files', () => {
    const plan = (lines: number[]) => planReview(lines.map((n, i) => change(`src/f${i}.ts`, n)));
    expect(plan([4, 6])).toEqual({
      tier: 'trivial',
      specialists: ['quality'],
      changedLines: 10,
      files: 2,
    });
    // Many files of few lines in all are still trivial.
    expect(plan(Array.from({ length: 10 }, () => 1))).toMatchObject({ tier: 'trivial', files: 10 });
    expect(plan([])).toEqual({
      tier: 'trivial',
      specialists: ['quality'],
      changedLines: 0,
      files: 0,
    });
    expect(plan([11])).toEqual({
      tier: 'lite',
      specialists: ['quality', 'tests'],
      changedLines: 11,
      files: 1,
    });
    expect(plan(Array.from({ length: 20 }, () => 15))).toEqual({
      tier: 'lite',
      specialists: ['quality', 'tests'],
      changedLines: 300,
      files: 20,
    });
    // Security runs first, then the others.
    const full = ['security', 'quality', 'tests', 'performance'];
    expect(plan([301])).toEqual({ tier: 'full', specialists: full, changedLines: 301, files: 1 });
    expect(plan(Array.from({ length: 21 }, () => 1))).toEqual({
      tier: 'full',
      specialists: full,
      changedLines: 21,
      files: 21,
    });
  });

  it('a sensitive path adds security at trivial', () => {
    // The security reviewer runs first, with its whole part, whatever the others spend.
    expect(planReview([change('src/auth/login.ts', 2)]).specialists).toEqual([
      'security',
      'quality',
    ]);
    expect(planReview([change('src/main.ts'), change('lib/bcrypt.ts')])).toMatchObject({
      tier: 'trivial',
      specialists: ['security', 'quality'],
    });
    expect(planReview([change('src/session.ts', 50)]).specialists).toEqual([
      'security',
      'quality',
      'tests',
    ]);
    // A full review has the security reviewer already, once.
    expect(planReview([change('src/session.ts', 301)]).specialists).toEqual([
      'security',
      'quality',
      'tests',
      'performance',
    ]);
    // A short word inside a longer one is no sensitive path.
    expect(planReview([change('src/tokenizer.ts', 2)]).specialists).toEqual(['quality']);
    // What decides is the change's `sensitive`, which the context set from the path.
    expect(planReview([{ ...change('src/main.ts'), sensitive: true }]).specialists).toEqual([
      'security',
      'quality',
    ]);
    expect(planReview([{ ...change('src/auth.ts'), sensitive: false }]).specialists).toEqual([
      'quality',
    ]);
  });
});

describe('runReviewPipeline', () => {
  it('specialists run in order and the judge sees their findings with ids', async () => {
    const { deps, calls } = scripted({
      quality: [
        answer({
          findings: [found({ title: 'Q1' }), found({ title: 'Q2', confidence: 'low', line: 1 })],
        }),
      ],
      tests: [answer({ findings: [found({ category: 'tests', title: 'T1', endLine: null })] })],
      security: [answer({ findings: [] })],
      performance: [
        answer({
          findings: [
            found({
              category: 'performance',
              title: 'P1',
              suggestion: { startLine: 3, endLine: 3, lines: ['const total = sum(items);'] },
            }),
          ],
        }),
      ],
      judge: [
        answer(
          judgeSays({
            findings: [
              judgedAs({ title: 'Q1 and T1', sources: ['s1', 's3'] }),
              judgedAs({ category: 'performance', title: 'P1', sources: ['s4'] }),
            ],
            dropped: [{ source: 's2', reason: 'Checked before.' }],
          }),
        ),
      ],
    });
    const { outcome, phases } = await review(
      contextOf([change('src/cart.ts', 301)]),
      100_000,
      deps,
    );

    expect(calls.map((c) => c.role)).toEqual([
      'security',
      'quality',
      'tests',
      'performance',
      'judge',
    ]);
    expect(phases).toEqual(['specialists', 'judge']);
    // Every reviewer is given the same data, without anyone's findings.
    const [first] = calls;
    for (const call of calls.slice(0, 4)) {
      expect(call.data).toEqual(first?.data);
      expect(call.data).not.toHaveProperty('specialistFindings');
    }
    // Every conversation has a nonce of its own.
    expect(new Set(calls.map((c) => c.nonce)).size).toBe(calls.length);
    // The judge is given every finding, numbered in the order of the reviewers.
    expect(calls[4]?.data.specialistFindings).toEqual([
      { id: 's1', reviewer: 'quality', ...found({ title: 'Q1' }) },
      { id: 's2', reviewer: 'quality', ...found({ title: 'Q2', confidence: 'low', line: 1 }) },
      { id: 's3', reviewer: 'tests', ...found({ category: 'tests', title: 'T1' }) },
      {
        id: 's4',
        reviewer: 'performance',
        ...found({
          category: 'performance',
          title: 'P1',
          suggestion: { startLine: 3, endLine: 3, lines: ['const total = sum(items);'] },
        }),
      },
    ]);
    expect(outcome).toEqual({
      kind: 'reviewed',
      tier: 'full',
      specialists: ['security', 'quality', 'tests', 'performance'],
      findings: [
        outcomeFinding({ title: 'Q1 and T1', sources: ['s1', 's3'] }),
        outcomeFinding({ category: 'performance', title: 'P1', sources: ['s4'] }),
      ],
      prior: [],
      shownPriorIds: [],
      namedPriorIds: [],
      summary: {
        verdict: 'One major problem in the cart total.',
        walkthrough: ['Totals the cart.'],
      },
      tokenLimitReached: false,
      notes: [],
    });
  });

  it('an unreadable specialist after one retry contributes nothing and notes it', async () => {
    const { deps, calls } = scripted({
      quality: [
        texts(
          'I found no problems worth reporting.',
          // JSON, but not of the schema.
          JSON.stringify({ findings: [found({ category: 'style' })] }),
        ),
      ],
      tests: [answer({ findings: [found({ category: 'tests', title: 'T1' })] })],
      judge: [answer(judgeSays())],
    });
    const { outcome } = await review(contextOf([change('src/cart.ts', 50)]), 100_000, deps);

    // One conversation for each: the retry is a turn of its conversation.
    expect(calls.map((c) => c.role)).toEqual(['quality', 'tests', 'judge']);
    expect(calls[0]?.accepted).toEqual([false, false]);
    expect(calls[2]?.data.specialistFindings).toEqual([
      { id: 's1', reviewer: 'tests', ...found({ category: 'tests', title: 'T1' }) },
    ]);
    expect(outcome).toMatchObject({
      kind: 'reviewed',
      specialists: ['quality', 'tests'],
      tokenLimitReached: false,
      notes: ['reviewer_unreadable'],
    });
  });

  it('a specialist that answers in its JSON on the retry contributes its findings', async () => {
    const { deps, calls } = scripted({
      quality: [
        texts(
          '```json\n{"findings": [\n```',
          JSON.stringify({ findings: [found({ title: 'Q1' })] }),
        ),
      ],
      judge: [answer(judgeSays())],
    });
    const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 100_000, deps);
    expect(calls[0]?.accepted).toEqual([false, true]);
    expect(calls[1]?.data.specialistFindings).toEqual([
      { id: 's1', reviewer: 'quality', ...found({ title: 'Q1' }) },
    ]);
    expect(outcome).toMatchObject({ kind: 'reviewed', notes: [] });
  });

  it('an answer a conversation did not check is checked all the same', async () => {
    const { deps, calls } = scripted({
      // Given back as an answer by a conversation that ignored its check: still not used.
      quality: [prose('No problems.')],
      tests: [answer({ findings: [found({ category: 'tests', title: 'T1' })] })],
      judge: [answer(judgeSays())],
    });
    const { outcome } = await review(contextOf([change('src/cart.ts', 50)]), 100_000, deps);
    expect(calls.map((c) => c.role)).toEqual(['quality', 'tests', 'judge']);
    expect(outcome).toMatchObject({ kind: 'reviewed', notes: ['reviewer_unreadable'] });
  });

  it('an unreadable judge after one retry fails with bad_answer', async () => {
    const first = scripted({
      quality: [answer({ findings: [found()] })],
      judge: [texts('Looks good to me.', JSON.stringify({ ...judgeSays(), approved: true }))],
    });
    const { outcome, phases } = await review(
      contextOf([change('src/cart.ts', 2)]),
      100_000,
      first.deps,
    );
    expect(outcome).toEqual({ kind: 'failed', reason: 'bad_answer' });
    expect(first.calls.map((c) => c.role)).toEqual(['quality', 'judge']);
    expect(first.calls[1]?.accepted).toEqual([false, false]);
    expect(phases).toEqual(['specialists', 'judge']);

    // A judge whose conversation ends without an answer fails the review at once.
    const second = scripted({
      quality: [answer({ findings: [] })],
      judge: [failed('bad_answer', [500, 0])],
    });
    expect(
      (await review(contextOf([change('src/cart.ts', 2)]), 100_000, second.deps)).outcome,
    ).toEqual({ kind: 'failed', reason: 'bad_answer' });
    expect(second.calls.map((c) => c.role)).toEqual(['quality', 'judge']);
  });

  it("a conversation's check takes only its role's JSON, within the role's output, without the key", async () => {
    expect(REVIEW_OUTPUT_TOKENS).toEqual({
      quality: 12_288,
      tests: 12_288,
      security: 12_288,
      performance: 12_288,
      judge: 16_384,
      verify: 2_048,
      // The answer to a person's reply: a verdict and at most 1 200 characters.
      reply: 2_048,
    });
    const key = j('sk-test-', '0123456789abcdef');
    const { deps, calls } = scripted(
      {
        quality: [answer({ findings: [] })],
        judge: [
          answer(
            judgeSays({ findings: [judgedAs({ category: 'security', severity: 'critical' })] }),
          ),
        ],
        verify: [answer({ verdict: 'confirmed', reason: 'Input reaches it.' })],
      },
      key,
    );
    await review(contextOf([change('src/cart.ts', 2)]), 100_000, deps);
    const [quality, judge, verify] = calls;
    if (quality === undefined || judge === undefined || verify === undefined) {
      throw new Error('a conversation is missing');
    }
    expect(quality.accept('Here you go.')).toBe(false);
    expect(quality.accept(JSON.stringify({ findings: [found({ category: 'style' })] }))).toBe(
      false,
    );
    expect(quality.accept(JSON.stringify({ findings: [found()] }))).toBe(true);
    // Each role has its own schema.
    expect(quality.accept(JSON.stringify(judgeSays()))).toBe(false);
    expect(judge.accept(JSON.stringify(judgeSays()))).toBe(true);
    expect(verify.accept(JSON.stringify({ verdict: 'confirmed', reason: 'r' }))).toBe(true);
    expect(verify.accept(JSON.stringify({ findings: [] }))).toBe(false);
    // The key is taken out before the schema is checked: an answer with it is read without it.
    expect(quality.accept(JSON.stringify({ findings: [found({ title: `Key ${key}` })] }))).toBe(
      true,
    );
    // An answer is read up to four characters for each token the role may write.
    const padded = (value: unknown, length: number): string => {
      const json = JSON.stringify(value);
      return `${json}${' '.repeat(length - json.length)}`;
    };
    for (const [call, role, valid] of [
      [quality, 'quality', { findings: [] }],
      [judge, 'judge', judgeSays()],
      [verify, 'verify', { verdict: 'rejected', reason: 'r' }],
    ] as const) {
      const limit = 4 * REVIEW_OUTPUT_TOKENS[role];
      expect(call.accept(padded(valid, limit)), role).toBe(true);
      // One more is not read, and what the model is told is that it was too long.
      expect(call.accept(padded(valid, limit + 1)), role).toBe(CONVERSATION_TEXTS.shorter);
    }
    // Only the length is told so: an answer within it that is not the JSON asked for is refused
    // as before, and the loop says its own words.
    expect(quality.accept(`Here you go.${' '.repeat(100)}`)).toBe(false);
  });

  it('asks a role for a shorter answer when its answer is longer than it is read, and for JSON again when it is not JSON', async () => {
    // The conversations run for real here, over a model that gives these texts in turn.
    const sent: Partial<Record<ReviewRole, LlmConversation[]>> = {};
    const left = new Map<ReviewRole, string[]>();
    const json = JSON.stringify({ findings: [] });
    const padded = (length: number) => `${json}${' '.repeat(length - json.length)}`;
    const deps: PipelineDeps = {
      providerKey: null,
      converse: (role, user, nonce, tokenBudget, accept) =>
        converseOverTools(
          { role, user, nonce, tokenBudget, accept },
          {
            reader: null,
            shouldStop: () => Promise.resolve(false),
            send: (conversation) => {
              const sentBefore = sent[role] ?? [];
              sent[role] = sentBefore;
              sentBefore.push(conversation);
              const text = left.get(role)?.shift();
              if (text === undefined) return Promise.reject(new Error(`no text left for ${role}`));
              return Promise.resolve({
                text,
                finishReason: 'stop' as const,
                usage: { inputTokens: 100, outputTokens: 10 },
                model: null,
                toolCalls: [],
              });
            },
          },
        ),
    };
    const run = async (quality: string[]) => {
      left.set('quality', quality);
      left.set('judge', [JSON.stringify(judgeSays())]);
      sent.quality = [];
      const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 1_000_000, deps);
      expect(outcome.kind).toBe('reviewed');
      return sent.quality ?? [];
    };

    // Longer than four characters for each token it may write: asked again, shorter.
    const long = await run([padded(4 * REVIEW_OUTPUT_TOKENS.quality + 1), json]);
    expect(long).toHaveLength(2);
    expect(long[1]?.messages.at(-1)).toEqual({ role: 'user', text: CONVERSATION_TEXTS.shorter });
    // Not JSON, and not long: the loop's own words.
    const prose = await run(['Here you go.', json]);
    expect(prose).toHaveLength(2);
    expect(prose[1]?.messages.at(-1)).toEqual({ role: 'user', text: CONVERSATION_TEXTS.retry });
    // At the limit it is read, and nobody asks again.
    expect(await run([padded(4 * REVIEW_OUTPUT_TOKENS.quality)])).toHaveLength(1);
  });

  it('verification drops rejected, downgrades needs_validation, marks confirmed, and stops after 5', async () => {
    const security = (title: string, severity: string) =>
      judgedAs({ category: 'security', severity, title, sources: ['s1'] });
    const verdicts: Record<string, string> = {
      B: 'rejected',
      E: 'needs_validation',
      A: 'confirmed',
      F: 'confirmed',
      G: 'rejected',
    };
    const byTitle = (call: Call): ConversationResult => {
      const { title } = call.data.finding as { title: string };
      return answer({ verdict: verdicts[title], reason: 'The query is built from the request.' });
    };
    const { deps, calls } = scripted({
      quality: [answer({ findings: [found()] })],
      security: [answer({ findings: [] })],
      judge: [
        answer(
          judgeSays({
            findings: [
              security('A', 'major'),
              security('B', 'critical'),
              judgedAs({ severity: 'critical', title: 'C', sources: ['s1'] }),
              security('D', 'minor'),
              security('E', 'critical'),
              security('F', 'major'),
              security('G', 'major'),
              security('H', 'major'),
              security('I', 'major'),
            ],
          }),
        ),
      ],
      verify: Array.from({ length: 5 }, () => byTitle),
    });
    const { outcome, phases } = await review(contextOf([change('src/auth.ts', 2)]), 100_000, deps);

    expect(phases).toEqual(['specialists', 'judge', 'verification']);
    // The critical ones first, then the major ones in the judge's order, five in all.
    const verified = calls.filter((c) => c.role === 'verify');
    expect(verified.map((c) => (c.data.finding as { title: string }).title)).toEqual([
      'B',
      'E',
      'A',
      'F',
      'G',
    ]);
    // A verifier is given its finding and nothing else.
    for (const call of verified) {
      expect(Object.keys(call.data)).toEqual(['finding']);
      expect(Object.keys(call.data.finding as object)).toEqual([
        'category',
        'severity',
        'path',
        'line',
        'endLine',
        'title',
        'body',
        'assumption',
      ]);
    }
    const sec = (title: string, severity: string, over: Record<string, unknown> = {}) =>
      outcomeFinding({ category: 'security', severity, title, sources: ['s1'], ...over });
    expect(outcome).toMatchObject({
      kind: 'reviewed',
      findings: [
        sec('A', 'major', { verification: 'confirmed' }),
        outcomeFinding({ severity: 'critical', title: 'C', sources: ['s1'] }),
        sec('D', 'minor'),
        sec('E', 'critical', { verification: 'needs_validation', confidence: 'medium' }),
        sec('F', 'major', { verification: 'confirmed' }),
        sec('H', 'major'),
        sec('I', 'major'),
      ],
      tokenLimitReached: false,
      notes: ['verification_capped'],
    });
  });

  it('a verification that cannot be read keeps its finding unverified and says so', async () => {
    const { deps, calls } = scripted({
      quality: [answer({ findings: [] })],
      judge: [
        answer(
          judgeSays({
            findings: [judgedAs({ category: 'security', severity: 'critical', title: 'S' })],
          }),
        ),
      ],
      verify: [texts('It is real.', JSON.stringify({ verdict: 'maybe', reason: 'r' }))],
    });
    const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 100_000, deps);
    expect(calls.map((c) => c.role)).toEqual(['quality', 'judge', 'verify']);
    expect(calls[2]?.accepted).toEqual([false, false]);
    expect(outcome).toMatchObject({
      kind: 'reviewed',
      findings: [outcomeFinding({ category: 'security', severity: 'critical', title: 'S' })],
      notes: ['reviewer_unreadable'],
    });
  });

  it('the judge and the verification run on the strong tier, the specialists on the standard one', async () => {
    const { deps, calls } = scripted({
      security: [answer({ findings: [] })],
      quality: [answer({ findings: [] })],
      tests: [answer({ findings: [] })],
      performance: [answer({ findings: [] })],
      judge: [
        answer(
          judgeSays({
            findings: [judgedAs({ category: 'security', severity: 'critical', title: 'S' })],
          }),
        ),
      ],
      verify: [answer({ verdict: 'confirmed', reason: 'The input reaches it.' })],
    });
    await review(contextOf([change('src/cart.ts', 301)]), 100_000, deps);

    expect(calls.map((c) => [c.role, c.modelTier])).toEqual([
      ['security', 'standard'],
      ['quality', 'standard'],
      ['tests', 'standard'],
      ['performance', 'standard'],
      ['judge', 'strong'],
      ['verify', 'strong'],
    ]);
  });

  it('a lite review’s specialists run on the standard tier', async () => {
    const { deps, calls } = scripted({
      quality: [answer({ findings: [] })],
      tests: [answer({ findings: [] })],
      judge: [answer(judgeSays())],
    });
    await review(contextOf([change('src/cart.ts', 50)]), 100_000, deps);

    expect(calls.map((c) => [c.role, c.modelTier])).toEqual([
      ['quality', 'standard'],
      ['tests', 'standard'],
      ['judge', 'strong'],
    ]);
  });

  it('a trivial review’s quality reviewer runs on the fast tier, its judge and verification on the strong one', async () => {
    const { deps, calls } = scripted({
      quality: [answer({ findings: [] })],
      judge: [
        answer(
          judgeSays({
            findings: [judgedAs({ category: 'security', severity: 'major', title: 'S' })],
          }),
        ),
      ],
      verify: [answer({ verdict: 'confirmed', reason: 'The input reaches it.' })],
    });
    await review(contextOf([change('src/cart.ts', 10)]), 100_000, deps);

    expect(calls.map((c) => [c.role, c.modelTier])).toEqual([
      ['quality', 'fast'],
      ['judge', 'strong'],
      ['verify', 'strong'],
    ]);
  });

  it('the security reviewer a sensitive path adds to a trivial review stays on the standard tier', async () => {
    const { deps, calls } = scripted({
      security: [answer({ findings: [] })],
      quality: [answer({ findings: [] })],
      judge: [answer(judgeSays())],
    });
    await review(contextOf([change('src/auth/login.ts', 2)]), 100_000, deps);

    expect(calls.map((c) => [c.role, c.modelTier])).toEqual([
      ['security', 'standard'],
      ['quality', 'fast'],
      ['judge', 'strong'],
    ]);
  });

  it('low-confidence judged findings are dropped', async () => {
    const { deps, calls } = scripted({
      quality: [answer({ findings: [found({ confidence: 'low' })] })],
      judge: [
        answer(
          judgeSays({
            findings: [
              judgedAs({ title: 'High' }),
              judgedAs({ title: 'Medium', confidence: 'medium' }),
              judgedAs({ title: 'Low', confidence: 'low' }),
              judgedAs({
                title: 'Low security',
                category: 'security',
                severity: 'critical',
                confidence: 'low',
              }),
            ],
          }),
        ),
      ],
    });
    const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 100_000, deps);
    expect(titles(outcome)).toEqual(['High', 'Medium']);
    // A low-confidence finding is not verified either: it is gone before.
    expect(calls.map((c) => c.role)).toEqual(['quality', 'judge']);
  });

  it('a specialist has its part and what the ones before it left of theirs, never what one overspent, and the judge what the specialists left', async () => {
    // Of 10 000 tokens the specialists have 5 500, a part of 2 750 for each of the two of a lite
    // review; the judge 3 500 and the verification 1 000.
    const context = contextOf([change('src/cart.ts', 50)]);
    for (const [spent, tests, judge] of [
      // 500 of its 2 750: the 2 250 it left are the next one's, and what that one leaves the judge's.
      [[400, 100], 5_000, 8_000],
      // Past its part, and past the whole of the specialists' share: the next has its own part
      // still, and the judge its share and what the second left.
      [[4_000, 1_000], 2_750, 5_750],
      [[6_500, 500], 2_750, 5_750],
    ] as [[number, number], number, number][]) {
      const { deps, calls } = scripted({
        quality: [answer({ findings: [] }, spent)],
        tests: [answer({ findings: [] }, [400, 100])],
        judge: [answer(judgeSays())],
      });
      const { outcome } = await review(context, 10_000, deps);
      expect(
        calls.map((c) => [c.role, c.tokenBudget]),
        String(spent),
      ).toEqual([
        ['quality', 2_750],
        ['tests', tests],
        ['judge', judge],
      ]);
      expect(outcome).toMatchObject({
        kind: 'reviewed',
        specialists: ['quality', 'tests'],
        tokenLimitReached: false,
        notes: [],
      });
    }

    // What a conversation that ended without an answer spent is charged all the same.
    const failing = scripted({
      quality: [failed('bad_answer', [2_000, 0])],
      tests: [answer({ findings: [] }, [400, 100])],
      judge: [answer(judgeSays())],
    });
    const three = await review(context, 10_000, failing.deps);
    expect(failing.calls.map((c) => [c.role, c.tokenBudget])).toEqual([
      ['quality', 2_750],
      ['tests', 3_500],
      ['judge', 6_500],
    ]);
    expect(three.outcome).toMatchObject({ kind: 'reviewed', notes: ['reviewer_unreadable'] });

    // A part that rounds to nothing is not run, and the review says the limit was reached; the
    // token of the specialists' share nobody spent is the judge's.
    const none = scripted({ judge: [answer(judgeSays())] });
    const tiny = await review(context, 3, none.deps);
    expect(none.calls.map((c) => [c.role, c.tokenBudget])).toEqual([['judge', 2]]);
    expect(tiny.outcome).toMatchObject({
      kind: 'reviewed',
      specialists: [],
      tokenLimitReached: true,
      notes: ['token_limit_reached'],
    });
  });

  it('with four specialists the last has what the three before it left: one that wrapped up on its part now finishes', async () => {
    // The demo's review: 300 000 tokens and a full review, four specialists of 41 250 each. The first
    // three answer at once; the fourth (performance) reads with its tools for five turns, each
    // sending its growing history again (6 000 tokens, then 360 more each time: 35 213 used after
    // five), and answers in the sixth.
    const play = async (firstThreeSpend: number) => {
      const budgets: [ReviewRole, number][] = [];
      const wrappedUp: ReviewRole[] = [];
      const turns = new Map<ReviewRole, number>();
      const deps: PipelineDeps = {
        providerKey: null,
        converse: (role, user, nonce, tokenBudget, accept) => {
          budgets.push([role, tokenBudget]);
          return converseOverTools(
            { role, user, nonce, tokenBudget, accept },
            {
              reader: null,
              shouldStop: () => Promise.resolve(false),
              send: (conversation) => {
                const n = (turns.get(role) ?? 0) + 1;
                turns.set(role, n);
                const last = conversation.messages.at(-1);
                const wrapUp = last?.role === 'user' && last.text === CONVERSATION_TEXTS.wrapUp;
                if (wrapUp) wrappedUp.push(role);
                const reads = role === 'performance' && !wrapUp && n < 6;
                const usage =
                  role === 'performance'
                    ? { inputTokens: 6_000 + 360 * (n - 1), outputTokens: n === 5 ? 333 : 320 }
                    : { inputTokens: firstThreeSpend - 200, outputTokens: 200 };
                const answer = role === 'judge' ? judgeSays() : { findings: [] };
                return Promise.resolve({
                  text: reads ? '' : JSON.stringify(answer),
                  finishReason: reads ? ('tool' as const) : ('stop' as const),
                  usage,
                  model: null,
                  toolCalls: reads
                    ? [{ id: `c${n}`, name: 'read_file', arguments: { path: 'src/cart.ts' } }]
                    : [],
                });
              },
            },
          );
        },
      };
      const { outcome } = await review(contextOf([change('src/cart.ts', 301)]), 300_000, deps);
      return { outcome, budgets, wrappedUp, turns: turns.get('performance') };
    };

    // The first three spend 7 000 of their 41 250 each: the fourth has its own part and their
    // 102 750, and reads to the end without a wrap-up.
    const rolled = await play(7_000);
    expect(rolled.budgets).toEqual([
      ['security', 41_250],
      ['quality', 75_500],
      ['tests', 109_750],
      ['performance', 144_000],
      // The judge's 105 000, and what the specialists left: 144 000 less the fourth's 43 333.
      ['judge', 205_667],
    ]);
    expect(rolled.wrappedUp).toEqual([]);
    expect(rolled.turns).toBe(6);
    expect(rolled.outcome).toMatchObject({ kind: 'reviewed', tokenLimitReached: false, notes: [] });

    // With nothing left by the three before it, the fourth has its part alone, as every specialist
    // had before: it is asked to wrap up, and the review says it reached its token limit.
    const even = await play(41_250);
    expect(even.budgets.slice(0, 4).map(([, tokens]) => tokens)).toEqual([
      41_250, 41_250, 41_250, 41_250,
    ]);
    expect(even.wrappedUp).toEqual(['performance']);
    expect(even.turns).toBeLessThan(6);
    expect(even.outcome).toMatchObject({
      kind: 'reviewed',
      tokenLimitReached: true,
      notes: ['token_limit_reached'],
    });
  });

  it('never gives out more than the budget: only what a conversation spends past what it was given goes over it', async () => {
    let seed = 20_261_026;
    const next = (): number => {
      seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
      return seed / 2_147_483_648;
    };
    for (let round = 0; round < 300; round += 1) {
      const budget = 1_000 + Math.floor(next() * 999_000);
      const lines = [2, 50, 301][Math.floor(next() * 3)] ?? 2;
      const serious = Math.floor(next() * 8);
      // In half the rounds a conversation may spend up to half again what it was given.
      const most = round % 2 === 0 ? 1 : 1.5;
      const given: number[] = [];
      const spent: number[] = [];
      const deps: PipelineDeps = {
        providerKey: null,
        converse: (role, _user, _nonce, tokenBudget) => {
          const used = Math.floor(tokenBudget * next() * most);
          given.push(tokenBudget);
          spent.push(used);
          const findings = Array.from({ length: serious }, (_, i) =>
            judgedAs({ category: 'security', severity: 'critical', title: `S${i}` }),
          );
          let value: unknown = { findings: [] };
          if (role === 'judge') value = judgeSays({ findings });
          else if (role === 'verify') value = { verdict: 'confirmed', reason: 'r' };
          return Promise.resolve(answer(value, [used, 0]));
        },
      };
      const { outcome } = await review(contextOf([change('src/cart.ts', lines)]), budget, deps);
      const name = `round ${round}: ${budget} tokens, ${lines} lines, ${serious} serious`;
      expect(outcome.kind, name).toBe('reviewed');
      const total = spent.reduce((sum, used) => sum + used, 0);
      const past = spent.reduce((sum, used, i) => sum + Math.max(0, used - (given[i] ?? 0)), 0);
      expect(total, name).toBeLessThanOrEqual(budget + past);
      if (most === 1) expect(total, name).toBeLessThanOrEqual(budget);
    }
  });

  it('an answer given after the wrap-up for the tokens says that the token limit was reached', async () => {
    const { deps } = scripted({
      quality: [answer({ findings: [found()] }, [900, 100], 'budget')],
      judge: [answer(judgeSays({ findings: [judgedAs()] }))],
    });
    const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 100_000, deps);
    expect(outcome).toMatchObject({
      kind: 'reviewed',
      findings: [outcomeFinding()],
      tokenLimitReached: true,
      notes: ['token_limit_reached'],
    });
  });

  it('an answer given after the wrap-up for the turns says that a reviewer reached its turn limit, not the token limit', async () => {
    const { deps } = scripted({
      quality: [answer({ findings: [found()] }, [900, 100], 'turns')],
      judge: [answer(judgeSays({ findings: [judgedAs()] }))],
    });
    const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 100_000, deps);
    expect(outcome).toMatchObject({
      kind: 'reviewed',
      findings: [outcomeFinding()],
      tokenLimitReached: false,
      notes: ['turn_limit_reached'],
    });
    // Both, by two reviewers: each is said once.
    const both = scripted({
      quality: [answer({ findings: [] }, [900, 100], 'turns')],
      tests: [answer({ findings: [] }, [900, 100], 'budget')],
      security: [answer({ findings: [] }, [900, 100], 'turns')],
      judge: [answer(judgeSays())],
    });
    const twice = await review(contextOf([change('src/auth.ts', 50)]), 100_000, both.deps);
    expect(twice.outcome).toMatchObject({
      kind: 'reviewed',
      tokenLimitReached: true,
      notes: ['turn_limit_reached', 'token_limit_reached'],
    });
  });

  it("an answer given after the wrap-up for the window says that a reviewer reached the model's context window, and nothing of the token limit", async () => {
    const { deps } = scripted({
      quality: [answer({ findings: [found()] }, [900, 100], 'window')],
      judge: [answer(judgeSays({ findings: [judgedAs()] }), [900, 100], 'window')],
    });
    const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 100_000, deps);
    expect(outcome).toMatchObject({
      kind: 'reviewed',
      findings: [outcomeFinding()],
      tokenLimitReached: false,
      notes: ['context_window_reached'],
    });
  });

  it("sizes the judge's data within a third of its cap: the bodies of the findings are cut to the window", async () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      found({ title: `F${i}`, body: 'b'.repeat(1_200) }),
    );
    const bodies = async (window?: number): Promise<number[]> => {
      const { deps, calls } = scripted({
        quality: [answer({ findings: many })],
        judge: [answer(judgeSays())],
      });
      await runReviewPipeline(
        contextOf([change('src/cart.ts', 2)]),
        10_000_000,
        deps,
        () => Promise.resolve(),
        window,
      );
      const judgeCall = calls.find((c) => c.role === 'judge');
      return (judgeCall?.data.specialistFindings as { body: string }[]).map((f) => f.body.length);
    };
    // The budget leaves room for every body whole; a window of 32 000 tokens does not.
    expect(new Set(await bodies())).toEqual(new Set([1_200]));
    expect(new Set(await bodies(Number.POSITIVE_INFINITY))).toEqual(new Set([1_200]));
    const cut = await bodies(32_000);
    expect(cut).toHaveLength(30);
    expect(Math.max(...cut)).toBeLessThan(1_200);
  });

  it('restores the body of a finding the judge kept with the cut text it was shown, and keeps one it wrote', async () => {
    const full = (i: number) => `Body ${i}. ${'b'.repeat(1_150)}`;
    const many = Array.from({ length: 30 }, (_, i) => found({ title: `F${i}`, body: full(i) }));
    const run = async (judge: Record<string, unknown>) => {
      const { deps, calls } = scripted({
        quality: [answer({ findings: many })],
        judge: [answer(judge)],
      });
      const outcome = await runReviewPipeline(
        contextOf([change('src/cart.ts', 2)]),
        10_000_000,
        deps,
        () => Promise.resolve(),
        32_000,
      );
      return { outcome, calls };
    };
    const first = await run(judgeSays());
    const shown = (
      first.calls.find((c) => c.role === 'judge')?.data.specialistFindings as { body: string }[]
    ).map((f) => f.body);
    expect(shown[1]!.length).toBeLessThan(full(1).length);
    const { outcome } = await run(
      judgeSays({
        findings: [
          judgedAs({ title: 'F0', body: '…', sources: ['s1'] }),
          judgedAs({ title: 'F1', body: shown[1], sources: ['s2'] }),
          judgedAs({ title: 'F2', body: 'The judge wrote this itself.', sources: ['s3'] }),
        ],
      }),
    );
    expect(outcome.kind).toBe('reviewed');
    if (outcome.kind !== 'reviewed') return;
    expect(outcome.findings.map((f) => f.body)).toEqual([
      full(0),
      full(1),
      'The judge wrote this itself.',
    ]);
  });

  it("keeps the judge's first message within a third of its cap, whatever the findings: their bodies, then the prior ones', then the suggestions go, and no finding", async () => {
    // A re-review: 20 open prior findings, and 24 new ones with long bodies and suggestions (an
    // answer a reviewer's output limit holds).
    const lines = Array.from({ length: 8 }, (_, i) => `const value${i} = compute(${i});`);
    const many = Array.from({ length: 24 }, (_, i) =>
      found({
        title: `Finding ${i}`,
        body: 'b'.repeat(1_200),
        suggestion: { startLine: 3, endLine: 3, lines },
      }),
    );
    const priors = Array.from({ length: 20 }, (_, i) => ({
      ...prior(`p${i}`, 'open'),
      // As long as the judge is shown one.
      body: 'p'.repeat(PROMPT_LIMITS.priorBodyChars),
    }));
    const judged = async (window: number) => {
      const { deps, calls } = scripted({
        quality: [answer({ findings: many })],
        judge: [answer(judgeSays())],
      });
      const context = contextOf([change('src/cart.ts', 2)], { prior: priors });
      await runReviewPipeline(context, 10_000_000, deps, () => Promise.resolve(), window);
      const call = calls.find((c) => c.role === 'judge')!;
      const data = call.data as {
        specialistFindings: { body: string; suggestion: unknown }[];
        priorFindings: { body: string }[];
      };
      return {
        message: SYSTEM_PROMPTS.judge.length + call.user.length,
        bodies: data.specialistFindings.map((f) => f.body.length),
        priorBodies: data.priorFindings.map((f) => f.body.length),
        suggestions: data.specialistFindings.filter((f) => f.suggestion !== null).length,
      };
    };
    const thirdOf = (window: number) =>
      Math.floor(callInputCap(window, 'judge') / 3) * CHARS_PER_TOKEN;
    // A window with room for every body, prior body and suggestion: all whole.
    const ample = await judged(1_000_000);
    expect(new Set(ample.bodies)).toEqual(new Set([1_200]));
    expect(new Set(ample.priorBodies)).toEqual(new Set([PROMPT_LIMITS.priorBodyChars]));
    expect(ample.suggestions).toBe(24);
    // Smaller ones: what goes, goes in that order, and the message keeps to its third.
    const order: string[] = [];
    for (const window of [120_000, 80_000, 60_000, 48_000, 40_000]) {
      const shown = await judged(window);
      expect(shown.message, String(window)).toBeLessThanOrEqual(thirdOf(window));
      expect(shown.bodies, String(window)).toHaveLength(24);
      expect(shown.priorBodies, String(window)).toHaveLength(20);
      // Nothing of a prior body goes while a finding's body is left, nor a suggestion while a
      // prior body is (a body cut to none is the mark of the cut).
      if (Math.max(...shown.priorBodies) < PROMPT_LIMITS.priorBodyChars) {
        expect(Math.max(...shown.bodies)).toBe(1);
      }
      if (shown.suggestions < 24) expect(Math.max(...shown.priorBodies)).toBe(1);
      let step = 'whole';
      if (shown.suggestions < 24) step = 'suggestions';
      else if (Math.max(...shown.priorBodies) < PROMPT_LIMITS.priorBodyChars) step = 'prior bodies';
      else if (Math.max(...shown.bodies) < 1_200) step = 'bodies';
      order.push(step);
    }
    // Each step is reached, a smaller window going further.
    expect(order).toEqual(['whole', 'whole', 'bodies', 'prior bodies', 'suggestions']);
  });

  it("a conversation the window has no room for adds nothing and is noted; a judge's fails the review and names the window", async () => {
    const windowFull = (input: number): ConversationResult => ({
      kind: 'failed',
      reason: 'window_full',
      ...spent(input, 0),
      turns: input === 0 ? 0 : 1,
    });
    // A specialist whose first call had no room, one whose later call had none, and a check of a
    // serious finding that had none: the review goes on, and says the window was reached.
    const serious = judgedAs({ category: 'security', title: 'A' });
    const { deps } = scripted({
      security: [windowFull(0)],
      quality: [windowFull(900)],
      tests: [answer({ findings: [found()] })],
      judge: [answer(judgeSays({ findings: [serious] }))],
      verify: [windowFull(500)],
    });
    const { outcome } = await review(contextOf([change('src/auth.ts', 50)]), 100_000, deps);
    expect(outcome).toMatchObject({
      kind: 'reviewed',
      specialists: ['quality', 'tests'],
      findings: [{ title: 'A', verification: null }],
      notes: ['context_window_reached'],
    });
    // The judge cannot be done without: the review fails, and says it was the window.
    const judgeFull = scripted({
      quality: [answer({ findings: [found()] })],
      judge: [windowFull(0)],
    });
    expect(
      (await review(contextOf([change('src/cart.ts', 2)]), 100_000, judgeFull.deps)).outcome,
    ).toEqual({ kind: 'failed', reason: 'provider_error', detail: 'window_full' });
  });

  describe("the review's time (deps.deadline)", () => {
    /** A conversation whose time ran out (`limits.deadline`) after `turns` turns. */
    const timeUp = (turns: number): ConversationResult => ({
      kind: 'failed',
      reason: 'provider_error',
      timeLimit: true,
      ...spent(turns * 100, 0),
      turns,
    });
    /** `deps` on a clock that reads `clock.at`, with the review's time up at `deadline`. */
    const timed = (deps: PipelineDeps, clock: { at: number }, deadline: number): PipelineDeps => {
      deps.deadline = deadline;
      deps.now = () => clock.at;
      return deps;
    };
    const JUDGE_TIME_LIMIT = { kind: 'failed', reason: 'provider_error', detail: 'time_limit' };

    it('starts no specialist past 60 % of it; the judge still runs, with the tokens they left, and the review notes the time limit', async () => {
      const clock = { at: 0 };
      const { deps, calls } = scripted({
        security: [
          () => {
            clock.at = 60_000;
            return answer({ findings: [] });
          },
        ],
        judge: [answer(judgeSays())],
      });
      const { outcome, phases } = await review(
        contextOf([change('src/auth.ts', 50)]),
        100_000,
        timed(deps, clock, 100_000),
      );
      // The specialists have until 60 % of the time, the judge until its end.
      expect(calls.map((c) => [c.role, c.deadline])).toEqual([
        ['security', 60_000],
        ['judge', 100_000],
      ]);
      // The judge has its share and all the specialists did not spend.
      expect(calls[1]!.tokenBudget).toBe(35_000 + 55_000 - 110);
      expect(phases).toEqual(['specialists', 'judge']);
      expect(outcome).toMatchObject({
        kind: 'reviewed',
        specialists: ['security'],
        tokenLimitReached: false,
        notes: ['time_limit_reached'],
      });
    });

    it('a specialist whose time ran out adds nothing and is noted; one that answered through the wrap-up for the time adds its findings', async () => {
      const { deps } = scripted({
        security: [timeUp(0)],
        quality: [timeUp(1)],
        tests: [answer({ findings: [found()] }, [900, 100], 'time')],
        judge: [answer(judgeSays({ findings: [judgedAs({ sources: ['s1'] })] }))],
      });
      const { outcome } = await review(
        contextOf([change('src/auth.ts', 50)]),
        100_000,
        timed(deps, { at: 0 }, 100_000),
      );
      expect(outcome).toMatchObject({
        kind: 'reviewed',
        specialists: ['quality', 'tests'],
        findings: [outcomeFinding({ sources: ['s1'] })],
        tokenLimitReached: false,
        notes: ['time_limit_reached'],
      });
    });

    it('a judge that cannot answer in time fails the review: provider_error, time_limit; one whose time is up before it starts is not asked', async () => {
      const late = scripted({ quality: [answer({ findings: [] })], judge: [timeUp(1)] });
      expect(
        (
          await review(
            contextOf([change('src/cart.ts', 2)]),
            100_000,
            timed(late.deps, { at: 0 }, 100_000),
          )
        ).outcome,
      ).toEqual(JUDGE_TIME_LIMIT);

      const clock = { at: 0 };
      const over = scripted({
        quality: [
          () => {
            clock.at = 100_000;
            return answer({ findings: [found()] });
          },
        ],
      });
      const { outcome } = await review(
        contextOf([change('src/cart.ts', 2)]),
        100_000,
        timed(over.deps, clock, 100_000),
      );
      expect(outcome).toEqual(JUDGE_TIME_LIMIT);
      expect(over.calls.map((c) => c.role)).toEqual(['quality']);
    });

    it('verifies no finding once the time is up: it stays unverified, and the review is done with the note', async () => {
      const serious = judgedAs({ category: 'security', title: 'A' });
      const clock = { at: 0 };
      const late = scripted({
        quality: [answer({ findings: [] })],
        judge: [
          () => {
            // An answer that comes after the deadline is not cut: it is used.
            clock.at = 100_000;
            return answer(judgeSays({ findings: [serious] }));
          },
        ],
      });
      const { outcome } = await review(
        contextOf([change('src/cart.ts', 2)]),
        100_000,
        timed(late.deps, clock, 100_000),
      );
      expect(late.calls.map((c) => c.role)).toEqual(['quality', 'judge']);
      expect(outcome).toMatchObject({
        kind: 'reviewed',
        findings: [{ title: 'A', verification: null }],
        notes: ['time_limit_reached'],
      });

      // A check whose own time ran out leaves its finding as the judge kept it.
      const ran = scripted({
        quality: [answer({ findings: [] })],
        judge: [answer(judgeSays({ findings: [serious] }))],
        verify: [timeUp(1)],
      });
      const checked = await review(
        contextOf([change('src/cart.ts', 2)]),
        100_000,
        timed(ran.deps, { at: 0 }, 100_000),
      );
      expect(ran.calls.map((c) => [c.role, c.deadline])).toEqual([
        ['quality', 60_000],
        ['judge', 100_000],
        ['verify', 100_000],
      ]);
      expect(checked.outcome).toMatchObject({
        kind: 'reviewed',
        findings: [{ title: 'A', verification: null }],
        notes: ['time_limit_reached'],
      });
    });

    it('a review that ends inside its time is as it was, without a note; without a deadline no conversation has one', async () => {
      const serious = judgedAs({ category: 'security', title: 'A' });
      const replies = (clock: { at: number }) => ({
        security: [
          () => {
            clock.at += 10_000;
            return answer({ findings: [] });
          },
        ],
        quality: [answer({ findings: [] })],
        tests: [answer({ findings: [] })],
        judge: [answer(judgeSays({ findings: [serious] }))],
        verify: [answer({ verdict: 'confirmed', reason: 'r' })],
      });
      const clock = { at: 1_000 };
      const inTime = scripted(replies(clock));
      const { outcome } = await review(
        contextOf([change('src/auth.ts', 50)]),
        100_000,
        timed(inTime.deps, clock, 101_000),
      );
      expect(inTime.calls.map((c) => [c.role, c.deadline])).toEqual([
        ['security', 61_000],
        ['quality', 61_000],
        ['tests', 61_000],
        ['judge', 101_000],
        ['verify', 101_000],
      ]);
      const untimed = scripted(replies({ at: 0 }));
      const before = await review(contextOf([change('src/auth.ts', 50)]), 100_000, untimed.deps);
      expect(untimed.calls.map((c) => c.deadline)).toEqual(Array(5).fill(Infinity));
      expect(outcome).toEqual(before.outcome);
      expect(outcome).toMatchObject({
        kind: 'reviewed',
        findings: [{ title: 'A', verification: 'confirmed' }],
        notes: [],
      });
    });
  });

  it('verification has a share of its own and what the judge left, shared between the findings it checks', async () => {
    const serious = judgeSays({
      findings: [
        judgedAs({ category: 'security', title: 'A' }),
        judgedAs({ category: 'security', title: 'B' }),
      ],
    });
    const confirmed = (): ConversationResult =>
      answer({ verdict: 'confirmed', reason: 'r' }, [200, 50]);
    // Of 10 000 tokens the one specialist of a trivial review has 5 500 and leaves 5 390, the judge
    // has its 3 500 and them, and leaves 8 780, which the verification has with its own 1 000: half
    // for the first finding, and its half and what the first left for the second.
    const shared = scripted({
      quality: [answer({ findings: [] })],
      judge: [answer(serious)],
      verify: [confirmed(), confirmed()],
    });
    await review(contextOf([change('src/cart.ts', 2)]), 10_000, shared.deps);
    expect(shared.calls.map((c) => [c.role, c.tokenBudget])).toEqual([
      ['quality', 5_500],
      ['judge', 8_890],
      ['verify', 4_890],
      ['verify', 9_530],
    ]);

    // What the judge spent past what it was given is not taken from the verification: its share
    // stays its own, and the findings are verified still.
    const overspent = scripted({
      quality: [answer({ findings: [] })],
      judge: [answer(serious, [9_800, 200])],
      verify: [confirmed(), confirmed()],
    });
    const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 10_000, overspent.deps);
    expect(overspent.calls.filter((c) => c.role === 'verify').map((c) => c.tokenBudget)).toEqual([
      500, 750,
    ]);
    // A verification that overspends takes nothing from the next one's half either.
    const greedy = scripted({
      quality: [answer({ findings: [] })],
      judge: [answer(serious, [9_800, 200])],
      verify: [answer({ verdict: 'confirmed', reason: 'r' }, [900, 100]), confirmed()],
    });
    await review(contextOf([change('src/cart.ts', 2)]), 10_000, greedy.deps);
    expect(greedy.calls.filter((c) => c.role === 'verify').map((c) => c.tokenBudget)).toEqual([
      500, 500,
    ]);
    expect(outcome).toMatchObject({
      kind: 'reviewed',
      findings: [
        outcomeFinding({ category: 'security', title: 'A', verification: 'confirmed' }),
        outcomeFinding({ category: 'security', title: 'B', verification: 'confirmed' }),
      ],
      tokenLimitReached: false,
    });

    // A share that rounds to nothing verifies nothing, and the review says so.
    const none = scripted({ quality: [answer({ findings: [] })], judge: [answer(serious)] });
    const tiny = await review(contextOf([change('src/cart.ts', 2)]), 9, none.deps);
    expect(none.calls.map((c) => c.role)).toEqual(['quality', 'judge']);
    expect(tiny.outcome).toMatchObject({
      kind: 'reviewed',
      tokenLimitReached: true,
      notes: ['token_limit_reached'],
    });
  });

  it('a budget too small to give the judge a share runs nothing', async () => {
    const { deps, calls } = scripted({});
    const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 2, deps);
    expect(outcome).toEqual({ kind: 'failed', reason: 'bad_answer' });
    expect(calls).toEqual([]);
  });

  it('a stopped conversation stops the pipeline', async () => {
    const context = contextOf([change('src/auth.ts', 50)]);
    const serious = judgeSays({ findings: [judgedAs({ category: 'security', title: 'S' })] });
    const cases: [Partial<Record<ReviewRole, Reply[]>>, ReviewRole[]][] = [
      [{ security: [stopped()] }, ['security']],
      [{ security: [answer({ findings: [] })], quality: [stopped()] }, ['security', 'quality']],
      [
        {
          security: [answer({ findings: [] })],
          quality: [answer({ findings: [] })],
          tests: [answer({ findings: [] })],
          judge: [stopped()],
        },
        ['security', 'quality', 'tests', 'judge'],
      ],
      [
        {
          security: [answer({ findings: [] })],
          quality: [answer({ findings: [] })],
          tests: [answer({ findings: [] })],
          judge: [answer(serious)],
          verify: [stopped()],
        },
        ['security', 'quality', 'tests', 'judge', 'verify'],
      ],
    ];
    for (const [replies, roles] of cases) {
      const { deps, calls } = scripted(replies);
      const { outcome } = await review(context, 100_000, deps);
      expect(outcome).toEqual({ kind: 'stopped' });
      expect(calls.map((c) => c.role)).toEqual(roles);
    }
  });

  it('a provider that fails ends the review with its reason', async () => {
    const context = contextOf([change('src/auth.ts', 50)]);
    const serious = judgeSays({ findings: [judgedAs({ category: 'security', title: 'S' })] });
    const cases: [Partial<Record<ReviewRole, Reply[]>>, string, ReviewRole[]][] = [
      [{ security: [failed('provider_no_tools')] }, 'provider_no_tools', ['security']],
      [
        { security: [answer({ findings: [] })], quality: [failed('provider_error')] },
        'provider_error',
        ['security', 'quality'],
      ],
      [
        {
          security: [answer({ findings: [] })],
          quality: [answer({ findings: [] })],
          tests: [answer({ findings: [] })],
          judge: [failed('provider_error')],
        },
        'provider_error',
        ['security', 'quality', 'tests', 'judge'],
      ],
      [
        {
          security: [answer({ findings: [] })],
          quality: [answer({ findings: [] })],
          tests: [answer({ findings: [] })],
          judge: [answer(serious)],
          verify: [failed('provider_error')],
        },
        'provider_error',
        ['security', 'quality', 'tests', 'judge', 'verify'],
      ],
    ];
    for (const [replies, reason, roles] of cases) {
      const { deps, calls } = scripted(replies);
      const { outcome } = await review(context, 100_000, deps);
      expect(outcome).toEqual({ kind: 'failed', reason });
      expect(calls.map((c) => c.role)).toEqual(roles);
    }
  });

  it('the provider key is taken out of every answer before it is used', async () => {
    const key = j('sk-test-', '0123456789abcdef');
    // The key as JSON escapes spell it: a parser reads it back.
    const escaped = [...key]
      .map((c) => `\\u${c.charCodeAt(0).toString(16).padStart(4, '0')}`)
      .join('');
    const quality = JSON.stringify({ findings: [found({ title: `Key ${key} in code` })] });
    const judge = JSON.stringify(
      judgeSays({ findings: [judgedAs({ body: 'Rotate KEY now.' })] }),
    ).replace('KEY', escaped);
    const { deps, calls } = scripted({ quality: [texts(quality)], judge: [texts(judge)] }, key);
    const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 100_000, deps);
    const judgeCall = calls.find((c) => c.role === 'judge');
    expect(JSON.stringify(judgeCall?.data)).not.toContain(key);
    expect(judgeCall?.data.specialistFindings).toEqual([
      { id: 's1', reviewer: 'quality', ...found({ title: `Key ${REDACTED} in code` }) },
    ]);
    expect(JSON.stringify(outcome)).not.toContain(key);
    expect(outcome).toMatchObject({
      findings: [outcomeFinding({ body: `Rotate ${REDACTED} now.` })],
    });
  });

  it('cleans the words of every finding as the answer is read, and leaves its code alone', async () => {
    const code = 'const total =​ a + b + c;';
    const dirty = {
      title: 'The total‮skips the la​st item',
      body: 'The loop bound is⁦one short. Use `i < n`.﻿',
      assumption: 'It⁩runs once.',
      suggestion: { startLine: 3, endLine: 3, lines: [code] },
    };
    const clean = {
      title: 'The total skips the last item',
      body: 'The loop bound is one short. Use `i < n`.',
      assumption: 'It runs once.',
      suggestion: { startLine: 3, endLine: 3, lines: [code] },
    };
    const { deps, calls } = scripted({
      quality: [answer({ findings: [found(dirty)] })],
      judge: [answer(judgeSays({ findings: [judgedAs(dirty)] }))],
    });
    const { outcome } = await review(contextOf([change('src/cart.ts', 2)]), 100_000, deps);
    // The judge is shown the specialist's finding cleaned, and the outcome holds its own so: what
    // the findings are matched by (the words of the title) is what a person reads.
    expect(calls.find((c) => c.role === 'judge')?.data.specialistFindings).toEqual([
      { id: 's1', reviewer: 'quality', ...found(clean) },
    ]);
    expect(outcome).toMatchObject({ findings: [outcomeFinding(clean)] });
  });

  it('the judge keeps only the sources, prior findings and verdicts it was given', async () => {
    const context = contextOf([change('src/cart.ts', 2)], {
      prior: [prior('issue-1', 'open'), prior('issue-2', 'wont_fix')],
    });
    const { deps, calls } = scripted({
      quality: [answer({ findings: [found()] })],
      judge: [
        answer(
          judgeSays({
            findings: [
              judgedAs({ title: 'Kept', sources: ['s1', 's9', 's1'], priorId: 'issue-1' }),
              judgedAs({ title: 'Forged', priorId: 'issue-9' }),
            ],
            prior: [
              { id: 'issue-1', status: 'present', reason: 'Still one short.' },
              { id: 'issue-9', status: 'fixed', reason: 'Gone.' },
              { id: 'issue-1', status: 'fixed', reason: 'Said twice.' },
              // A verdict on a finding a person dismissed changes nothing.
              { id: 'issue-2', status: 'fixed', reason: 'Gone.' },
            ],
          }),
        ),
      ],
    });
    const { outcome } = await review(context, 100_000, deps);
    const judgeCall = calls.find((c) => c.role === 'judge');
    expect((judgeCall?.data.priorFindings as { id: string }[]).map((p) => p.id)).toEqual([
      'issue-1',
      'issue-2',
    ]);
    expect(outcome).toMatchObject({
      kind: 'reviewed',
      findings: [
        outcomeFinding({ title: 'Kept', sources: ['s1'], priorId: 'issue-1' }),
        outcomeFinding({ title: 'Forged' }),
      ],
      prior: [{ id: 'issue-1', status: 'present', reason: 'Still one short.' }],
      // The prior findings the judge was shown: only those can be closed for being left out.
      shownPriorIds: ['issue-1', 'issue-2'],
    });
  });

  it('lists the prior findings the judge named, once each, also in findings the review drops itself', async () => {
    const context = contextOf([change('src/cart.ts', 2)], {
      prior: [
        prior('issue-1', 'open'),
        prior('issue-2', 'open'),
        prior('issue-3', 'open'),
        prior('issue-4', 'wont_fix'),
      ],
    });
    const { deps } = scripted({
      quality: [answer({ findings: [found()] })],
      judge: [
        answer(
          judgeSays({
            findings: [
              judgedAs({ title: 'Kept', priorId: 'issue-1' }),
              // Dropped by the review: of low confidence, and rejected by the verification.
              judgedAs({ title: 'Doubtful', confidence: 'low', priorId: 'issue-2' }),
              judgedAs({
                title: 'Rejected',
                category: 'security',
                severity: 'critical',
                priorId: 'issue-3',
              }),
              judgedAs({ title: 'Again', priorId: 'issue-1' }),
              // An id the judge was not given names nothing.
              judgedAs({ title: 'Forged', priorId: 'issue-9' }),
              judgedAs({ title: 'Of a dismissed one', priorId: 'issue-4' }),
              judgedAs({ title: 'Of none' }),
            ],
          }),
        ),
      ],
      verify: [answer({ verdict: 'rejected', reason: 'It is not reachable.' })],
    });
    const { outcome } = await review(context, 100_000, deps);
    if (outcome.kind !== 'reviewed') throw new Error(outcome.kind);
    expect(titles(outcome)).toEqual(['Kept', 'Again', 'Forged', 'Of a dismissed one', 'Of none']);
    expect(outcome.namedPriorIds).toEqual(['issue-1', 'issue-2', 'issue-3', 'issue-4']);
  });

  it('names the prior findings the judge was shown: the open ones first, at most 50', async () => {
    const context = contextOf([change('src/cart.ts', 2)], {
      prior: [
        ...Array.from({ length: 60 }, (_, i) => prior(`dismissed-${i}`, 'false_positive', 'high')),
        prior('open-1', 'open', 'low'),
      ],
    });
    const { deps } = scripted({
      quality: [answer({ findings: [] })],
      judge: [answer(judgeSays())],
    });
    const { outcome } = await review(context, 100_000, deps);
    if (outcome.kind !== 'reviewed') throw new Error(outcome.kind);
    expect(outcome.shownPriorIds).toHaveLength(50);
    expect(outcome.shownPriorIds[0]).toBe('open-1');
    expect(outcome.shownPriorIds).not.toContain('dismissed-49');
  });

  it("cuts the bodies of the specialists' findings when the judge's data would take more than a third of its share", async () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      found({ title: `F${i}`, body: 'b'.repeat(1_200) }),
    );
    const bodies = async (budget: number): Promise<number[]> => {
      const { deps, calls } = scripted({
        quality: [answer({ findings: many })],
        judge: [answer(judgeSays())],
      });
      await review(contextOf([change('src/cart.ts', 2)]), budget, deps);
      const judgeCall = calls.find((c) => c.role === 'judge');
      const message = SYSTEM_PROMPTS.judge.length + (judgeCall?.user.length ?? 0);
      const third =
        Math.floor(Math.floor((budget * STAGE_SHARES.judge) / 100) / 3) * CHARS_PER_TOKEN;
      if (budget < 1_000_000) expect(message).toBeLessThanOrEqual(third);
      return (judgeCall?.data.specialistFindings as { body: string }[]).map((f) => f.body.length);
    };
    // With room, the bodies are whole; with less, each is cut, and every finding is still there.
    expect(new Set(await bodies(10_000_000))).toEqual(new Set([1_200]));
    const cut = await bodies(100_000);
    expect(cut).toHaveLength(30);
    expect(Math.max(...cut)).toBeLessThan(1_200);
  });
});

describe('the note of shortened instructions files', () => {
  it('a context whose instructions files were shortened for the window is noted, once, and others are not', async () => {
    const run = async (over: Partial<ReviewContext>) => {
      const { deps } = scripted({
        quality: [answer({ findings: [] })],
        judge: [answer(judgeSays())],
      });
      const { outcome } = await review(contextOf([change('src/cart.ts', 2)], over), 100_000, deps);
      if (outcome.kind !== 'reviewed') throw new Error(outcome.kind);
      return outcome.notes;
    };
    expect(await run({ instructionsShortened: true })).toEqual(['instructions_shortened']);
    expect(await run({ instructionsShortened: false })).toEqual([]);
    expect(await run({})).toEqual([]);
  });
});

describe('reviewLimits', () => {
  const RULE = 'typescript:S1854';
  const MESSAGE =
    'Remove this useless assignment to variable "total"; it is overwritten before it is read.';
  const TITLE = 'Fix the cart total';
  // As long as a description is shown: what it takes counts.
  const DESCRIPTION = 'd'.repeat(4_000);
  const SKIPPED = Array.from({ length: 5 }, (_, i) => ({
    path: `vendor/lib-${i}.min.js`,
    why: 'minified' as const,
  }));
  /** The instructions files as the snapshot holds them: their names and lengths. */
  type Instructions = [name: string, chars: number][];

  /** A context as buildReviewContext makes it under `limits`, with ordinary lists. */
  function sizedContext(
    reviewed: ReviewableChange[],
    limits: ReturnType<typeof reviewLimits>,
    analyzer: number,
    instructions: Instructions,
  ): ReviewContext {
    const row =
      '  12+    const total = items.reduce((sum, item) => sum + item.price * item.count, 0);';
    const rows: string[] = [];
    for (let size = row.length; size <= limits.sliceChars; size += row.length + 1) rows.push(row);
    const cut = (name: string, text: string) => ({
      name,
      text:
        text.length <= limits.instructionsChars
          ? text
          : `${text.slice(0, limits.instructionsChars)}\n[cut: the text has ${text.length} characters, only the first ${limits.instructionsChars} are shown]`,
    });
    return contextOf(reviewed, {
      meta: {
        ...META,
        mrTitle: TITLE,
        mrDescription: DESCRIPTION,
        instructions: instructions.map(([name, chars]) => cut(name, 'a'.repeat(chars))),
      },
      skipped: SKIPPED,
      slices: rows.join('\n'),
      omittedFromSlices: reviewed.map(
        (c) => `${c.path} (${c.changedLines} changed lines): read it with read_file`,
      ),
      analyzer: Array.from({ length: analyzer }, (_, i) => ({
        ruleKey: RULE,
        severity: 'medium',
        message: MESSAGE,
        path: reviewed[i % reviewed.length]?.path ?? 'src/a.ts',
        line: 120,
      })),
    });
  }
  /** The shape the context would ask its limits with, from the same things. */
  const shapeOf = (
    reviewed: ReviewableChange[],
    analyzer: number,
    instructions: Instructions,
  ): ContextShape => ({
    reviewed,
    skipped: SKIPPED,
    analyzerChars: Array.from(
      { length: analyzer },
      (_, i) => (reviewed[i % reviewed.length]?.path.length ?? 0) + RULE.length + MESSAGE.length,
    ),
    wordsChars: TITLE.length + DESCRIPTION.length,
    instructionChars: instructions.map(([, chars]) => chars),
  });
  const changes = (count: number, lines: number, sensitive = false) =>
    Array.from({ length: count }, (_, i) =>
      change(`server/src/${sensitive ? 'auth' : 'module'}${i}/handlers/some-file-${i}.ts`, lines),
    );
  /** The characters a first message of each specialist may take: a third of its part, and of half the judge's share. */
  const thirdOf = (budget: number, specialists: number): number => {
    const part = Math.floor(Math.floor((budget * STAGE_SHARES.specialists) / 100) / specialists);
    const judgeHalf = Math.floor(Math.floor((budget * STAGE_SHARES.judge) / 100) / 2);
    return Math.floor(Math.min(part, judgeHalf) / 3) * CHARS_PER_TOKEN;
  };

  it("sizes a reviewer's first message to a third of its part, keeping half of the judge's third for the findings", () => {
    const agents: Instructions = [['AGENTS.md', 8_000]];
    for (const budget of [300_000, 1_000_000]) {
      for (const reviewed of [
        changes(2, 2),
        changes(10, 20),
        changes(30, 40),
        changes(2, 2, true),
      ]) {
        for (const analyzer of [0, 10]) {
          const plan = planReview(reviewed);
          const shape = shapeOf(reviewed, analyzer, agents);
          const limits = reviewLimits(shape, budget);
          const data = specialistData(sizedContext(reviewed, limits, analyzer, agents));
          const name = `${budget} ${plan.tier} ${analyzer}`;
          for (const role of plan.specialists) {
            const message = SYSTEM_PROMPTS[role].length + envelope(data, newNonce()).length;
            expect(message, `${name} ${role}`).toBeLessThanOrEqual(
              thirdOf(budget, plan.specialists.length),
            );
          }
          // The instructions are shown whole, and there is room for code still.
          expect(limits.instructionsChars, name).toBeGreaterThanOrEqual(8_000);
          expect(limits.sliceChars, name).toBeGreaterThan(5_000);
        }
      }
    }
  });

  it('counts the lists as the change has them: a small change shows its instructions and its code, whatever the analyzers found', () => {
    // One file of six changed lines with a hundred findings of the analyzers on it, a description
    // as long as one is shown and an AGENTS.md of 8 000 characters: all of them fit its third, and
    // code besides.
    const reviewed = changes(1, 6);
    const agents: Instructions = [['AGENTS.md', 8_000]];
    const limits = reviewLimits(shapeOf(reviewed, 100, agents), 300_000);
    expect(limits.instructionsChars).toBeGreaterThanOrEqual(8_000);
    expect(limits.sliceChars).toBeGreaterThan(5_000);
    // And it is sized to its third, not past it.
    const data = specialistData(sizedContext(reviewed, limits, 100, agents));
    expect(SYSTEM_PROMPTS.quality.length + envelope(data, newNonce()).length).toBeLessThanOrEqual(
      thirdOf(300_000, 1),
    );
  });

  it('gives the instructions files the first claim, at least 16 000 characters each, and the slices what is left', () => {
    const long: Instructions = [
      ['AGENTS.md', 8_000],
      ['REVIEW.md', 40_000],
    ];
    // Plenty of room: each part as large as it may be.
    expect(reviewLimits(shapeOf(changes(30, 40), 10, long), 10_000_000)).toEqual({
      ...CONTEXT_MAXIMA,
      lists: LIST_CAP_STEPS[0],
    });
    // Room for the instructions whole: they take it before the slices.
    const ample = reviewLimits(shapeOf(changes(30, 40), 10, long), 1_000_000);
    expect(ample.instructionsChars).toBe(CONTEXT_MAXIMA.instructionsChars);
    expect(ample.sliceChars).toBeGreaterThan(0);
    // Too little room for them: still 16 000 characters each, and no slices.
    for (const budget of [300_000, 60_000, 0, Number.NaN]) {
      expect(reviewLimits(shapeOf(changes(30, 40), 10, long), budget), String(budget)).toEqual({
        sliceChars: 0,
        instructionsChars: 16_000,
        lists: expect.anything(),
      });
    }
    // Without instructions the slices have the room.
    const none = reviewLimits(shapeOf(changes(30, 40), 10, []), 1_000_000);
    expect(none.sliceChars).toBeGreaterThan(ample.sliceChars);
  });

  it('reviewFits: the smallest share has room before the instructions floors, as reviewLimits counts it', () => {
    // Without instructions files the room is what the slices get: it fits exactly when they get some.
    const bare = shapeOf(changes(1, 6), 0, []);
    for (let budget = 10_000; budget <= 120_000; budget += 2_500) {
      expect(reviewFits(bare, budget), String(budget)).toBe(
        reviewLimits(bare, budget).sliceChars > 0,
      );
    }
    expect(reviewFits(bare, 10_000)).toBe(false);
    expect(reviewFits(bare, 120_000)).toBe(true);
    // The floors of the instructions files are not counted: a long AGENTS.md changes nothing.
    const instructed = shapeOf(changes(1, 6), 0, [['AGENTS.md', 40_000]]);
    for (const budget of [10_000, 60_000, 120_000]) {
      expect(reviewFits(instructed, budget), String(budget)).toBe(reviewFits(bare, budget));
    }
    // The lists count: a hundred findings of the analyzers need a larger budget to be listed whole;
    // with less the ladder lists fewer of them (R47), and the review still runs.
    const listed = shapeOf(changes(1, 6), 100, []);
    const smallest = (shape: ContextShape, whole = false) => {
      let budget = 0;
      while (
        whole ? listCapsFor(shape, budget) !== LIST_CAP_STEPS[0] : !reviewFits(shape, budget)
      ) {
        budget += 1_000;
      }
      return budget;
    };
    expect(smallest(listed, true)).toBeGreaterThan(smallest(bare, true));
    expect(smallest(listed)).toBeLessThan(smallest(listed, true));
    // Nothing to spend fits nothing; a full tier needs more than a trivial one.
    for (const budget of [0, -1, Number.NaN]) expect(reviewFits(bare, budget)).toBe(false);
    expect(smallest(shapeOf(changes(30, 40), 0, []))).toBeGreaterThan(smallest(bare));
  });

  it("sizes the first message within a third of the judge's cap", () => {
    for (const window of [40_000, 64_000, 200_000]) {
      const third = Math.floor(callInputCap(window, 'judge') / 3) * CHARS_PER_TOKEN;
      // What the judge's third leaves after its own prompt: half of it for the data the reviewers
      // share, the other half for the findings (R46).
      const half = Math.floor((third - SYSTEM_PROMPTS.judge.length) / 2);
      for (const budget of [300_000, 1_000_000, 10_000_000]) {
        for (const reviewed of [changes(1, 6), changes(2, 2), changes(2, 2, true)]) {
          const plan = planReview(reviewed);
          const shape = shapeOf(reviewed, 0, []);
          const name = `${window} ${budget} ${plan.tier} ${reviewed.length}`;
          expect(reviewFits(shape, budget, window), name).toBe(true);
          const limits = reviewLimits(shape, budget, window);
          const context = sizedContext(reviewed, limits, 0, []);
          // A reviewer's first message keeps to a third of its own cap.
          const data = specialistData(context);
          for (const role of plan.specialists) {
            const message = SYSTEM_PROMPTS[role].length + envelope(data, newNonce()).length;
            const own = Math.floor(callInputCap(window, role) / 3) * CHARS_PER_TOKEN;
            expect(message, `${name} ${role}`).toBeLessThanOrEqual(own);
          }
          // The judge's message holds its prompt, the shared data in its envelope, and as much again
          // for the findings, within its third: the findings have half of what the prompt leaves.
          const shared = JSON.stringify(data).length;
          const judgeMessage =
            SYSTEM_PROMPTS.judge.length +
            envelope(judgeData(context, [], Number.POSITIVE_INFINITY), newNonce()).length;
          expect(judgeMessage + shared, name).toBeLessThanOrEqual(third);
          // And when the window is what holds it back, the shared data takes nearly all its half.
          const judgeHalf = Math.floor((budget * STAGE_SHARES.judge) / 200);
          if (Math.floor(callInputCap(window, 'judge') / 2) < judgeHalf) {
            expect(shared, name).toBeGreaterThan(Math.floor(half * 0.75));
            // Without the window the slices have the budget's room.
            expect(
              reviewLimits(shape, budget, Number.POSITIVE_INFINITY).sliceChars,
              name,
            ).toBeGreaterThan(limits.sliceChars);
          }
        }
      }
    }
    // A window larger than the budget needs changes nothing: the budget's third is the smaller.
    const shape = shapeOf(changes(10, 20), 10, [['AGENTS.md', 8_000]]);
    expect(reviewLimits(shape, 300_000, 10_000_000)).toEqual(
      reviewLimits(shape, 300_000, Number.POSITIVE_INFINITY),
    );
    expect(reviewLimits(shape, 300_000)).toEqual(reviewLimits(shape, 300_000, 1_000_000));
  });

  /** A change of one line, with a short title and no description. */
  const oneLine: ContextShape = {
    reviewed: [change('src/a.ts', 1)],
    skipped: [],
    analyzerChars: [],
    wordsChars: 20,
    instructionChars: [],
  };

  it('a merge request that fits Tokens per review but not a 32 000-token window does not fit', () => {
    const big = shapeOf(changes(80, 10), 0, []);
    expect(reviewFits(big, 300_000, Number.POSITIVE_INFINITY)).toBe(true);
    // The default window, 1 000 000 tokens, holds it.
    expect(reviewFits(big, 300_000)).toBe(true);
    expect(reviewFits(big, 300_000, 32_000)).toBe(false);
    // A small change fits that window, and no window a judge's answer leaves no room in fits any.
    expect(reviewFits(oneLine, 300_000, 32_000)).toBe(true);
    expect(reviewFits(oneLine, 300_000, 32_768)).toBe(true);
    expect(reviewFits(oneLine, 300_000, 16_384)).toBe(false);
  });

  it('a change of one line with no description needs a window of about 26 600 tokens', () => {
    // The judge's 16 384 tokens of answer, its prompt, and half of what is left of its third for
    // the data the reviewers share (the guide's figure).
    for (const window of [8_000, 24_000, 26_500, 26_570]) {
      expect(reviewFits(oneLine, 300_000, window), String(window)).toBe(false);
    }
    expect(reviewFits(oneLine, 300_000, 26_600)).toBe(true);
  });

  it("counts the instructions files' floors against the window, not against the budget", () => {
    const bare = shapeOf(changes(1, 6), 0, []);
    const instructed = shapeOf(changes(1, 6), 0, [['AGENTS.md', 40_000]]);
    // A window with room for the change fits it with any instructions file: the file is cut to the
    // window's share instead of skipping the review.
    for (const window of [48_000, 64_000, 200_000]) {
      expect(reviewFits(bare, 300_000, window), String(window)).toBe(true);
      expect(reviewFits(instructed, 300_000, window), String(window)).toBe(true);
    }
    // The budget alone counts no floor, as before.
    for (const budget of [10_000, 60_000, 120_000]) {
      expect(reviewFits(instructed, budget, Number.POSITIVE_INFINITY), String(budget)).toBe(
        reviewFits(bare, budget, Number.POSITIVE_INFINITY),
      );
    }
  });

  describe('the instructions files on a small window', () => {
    const withFiles = (...chars: number[]): ContextShape => ({
      ...oneLine,
      instructionChars: chars,
    });

    it('an AGENTS.md of 8 000 characters on a 32 768-token window fits, is cut, and the review says so', () => {
      const shape = withFiles(8_000);
      expect(reviewFits(shape, 300_000, 32_768)).toBe(true);
      const limits = reviewLimits(shape, 300_000, 32_768);
      expect(limits.instructionsChars).toBeGreaterThanOrEqual(1_000);
      expect(limits.instructionsChars).toBeLessThan(8_000);
      expect(limits.instructionsShortened).toBe(true);
      // Never less than its share of the room, which is half the window's.
      const share = instructionFloor(shape, 32_768, limits.lists);
      expect(share).toBeGreaterThanOrEqual(1_000);
      expect(limits.instructionsChars).toBeGreaterThanOrEqual(share);
    });

    it('a file of 40 000 characters on a 64 000-token window fits and is cut to its share or more', () => {
      const shape = withFiles(40_000);
      expect(reviewFits(shape, 300_000, 64_000)).toBe(true);
      const limits = reviewLimits(shape, 300_000, 64_000);
      const share = instructionFloor(shape, 64_000, limits.lists);
      expect(share).toBeGreaterThan(1_000);
      expect(share).toBeLessThan(16_000);
      expect(limits.instructionsChars).toBeGreaterThanOrEqual(share);
      expect(limits.instructionsChars).toBeLessThan(32_000);
    });

    it('a 1 000 000-token window and no window keep 16 000 characters each at least, and say nothing', () => {
      for (const window of [1_000_000, Number.POSITIVE_INFINITY]) {
        const shape = withFiles(200_000, 20_000);
        const limits = reviewLimits(shape, 300_000, window);
        expect(instructionFloor(shape, window, limits.lists), String(window)).toBe(16_000);
        expect(limits.instructionsChars, String(window)).toBeGreaterThanOrEqual(16_000);
        expect(limits.instructionsShortened, String(window)).toBeUndefined();
        // A short file is its own floor.
        expect(instructionFloor(withFiles(5_000), window, limits.lists)).toBe(16_000);
      }
    });

    it('shares the room evenly between the files', () => {
      const one = withFiles(30_000);
      const three = withFiles(30_000, 30_000, 30_000);
      const window = 50_000;
      const caps = reviewLimits(one, 300_000, window).lists;
      const single = instructionFloor(one, window, caps);
      const each = instructionFloor(three, window, caps);
      expect(single).toBeLessThan(16_000);
      expect(each).toBeGreaterThan(1_000);
      expect(each).toBe(Math.floor(single / 3));
    });

    it('drops the files when their share is under 1 000 characters, and says so', () => {
      const shape = withFiles(30_000, 30_000, 30_000);
      let window = 26_600;
      while (!reviewFits(shape, 300_000, window)) window += 100;
      const limits = reviewLimits(shape, 300_000, window);
      expect(instructionFloor(shape, window, limits.lists)).toBe(0);
      expect(limits.instructionsChars).toBe(0);
      expect(limits.instructionsShortened).toBe(true);
    });

    it('still skips a change that does not fit the window, whatever the files', () => {
      for (const shape of [withFiles(), withFiles(8_000), withFiles(40_000)]) {
        expect(reviewFits(shape, 300_000, 24_000)).toBe(false);
      }
      expect(reviewFits(withFiles(40_000), 300_000, 26_600)).toBe(true);
    });

    it('reviewFits and reviewLimits agree on the floors for every window', () => {
      for (const chars of [3_000, 8_000, 40_000]) {
        const shape = withFiles(chars, chars);
        for (let window = 26_000; window <= 80_000; window += 1_000) {
          if (!reviewFits(shape, 300_000, window)) continue;
          const limits = reviewLimits(shape, 300_000, window);
          const floor = instructionFloor(shape, window, limits.lists);
          expect(limits.instructionsChars, `${chars} ${window}`).toBeGreaterThanOrEqual(floor);
          if (floor === 0) expect(limits.instructionsChars).toBe(0);
        }
      }
    });
  });

  describe('the ladder of list caps (R47)', () => {
    const EVAL = fileURLToPath(new URL('../../../fixtures/review-eval', import.meta.url));
    const MODELS = (name: string) => path.join(EVAL, name);
    /** The shape of a case of the evaluation: one change per file of its patch, as the evaluation sizes it. */
    const evalShape = (name: string): ContextShape => {
      const diff = readFileSync(path.join(MODELS(name), 'patch.diff'), 'utf8');
      const files = Math.max(1, (diff.match(/^diff --git /gm) ?? []).length);
      return shapeOf(changes(files, 20), 0, []);
    };

    it("a change that fits today keeps today's lists", () => {
      const cases = readdirSync(EVAL).filter((name) =>
        existsSync(path.join(MODELS(name), 'patch.diff')),
      );
      expect(cases.length).toBeGreaterThanOrEqual(10);
      for (const name of cases) {
        expect(listCapsFor(evalShape(name), 300_000), name).toBe(LIST_CAP_STEPS[0]);
      }
      expect(listCapsFor(shapeOf(changes(100, 10), 0, []), 300_000)).toBe(LIST_CAP_STEPS[0]);
      expect(listCapsFor(oneLine, 300_000)).toBe(LIST_CAP_STEPS[0]);
    });

    it('a 150-file change at 300 000 tokens is reviewed with shortened lists', () => {
      const shape = shapeOf(changes(150, 10), 20, []);
      const caps = listCapsFor(shape, 300_000);
      expect(caps).not.toBeNull();
      expect(caps).not.toBe(LIST_CAP_STEPS[0]);
      expect(LIST_CAP_STEPS).toContain(caps);
      expect(reviewFits(shape, 300_000)).toBe(true);
      // Today's lists left no room; the review is sized to the shorter ones.
      expect(reviewFits(shape, 300_000, Number.POSITIVE_INFINITY)).toBe(true);
      expect(reviewLimits(shape, 300_000).lists).toBe(caps);
      expect(reviewLimits(shape, 300_000).sliceChars).toBeGreaterThanOrEqual(0);
    });

    it('a change too large for the last step does not fit', () => {
      // The last step lists 20 changes whatever their number: what it cannot hold is a budget too
      // small for its first message, or a window.
      const huge = shapeOf(changes(5_000, 10), 20, []);
      expect(listCapsFor(huge, 300_000)).not.toBeNull();
      expect(listCapsFor(huge, 300_000)).not.toBe(LIST_CAP_STEPS[0]);
      expect(listCapsFor(huge, 20_000)).toBeNull();
      expect(reviewFits(huge, 20_000)).toBe(false);
      expect(reviewFits(huge, 20_000, Number.POSITIVE_INFINITY)).toBe(false);
      // The window alone: Tokens per review holds it, a 32 000-token window does not.
      expect(reviewFits(huge, 300_000, Number.POSITIVE_INFINITY)).toBe(true);
      expect(reviewFits(huge, 300_000, 32_000)).toBe(false);
      expect(listCapsFor(oneLine, 0)).toBeNull();
    });

    it('tries the shorter lists against the window too: a change that fits a window only with them is reviewed', () => {
      const shape = shapeOf(changes(150, 10), 20, []);
      // Plenty of tokens per review, a window the long lists do not fit and the shorter ones do.
      let found = false;
      for (const window of [40_000, 60_000, 90_000, 130_000, 200_000, 300_000, 500_000]) {
        const caps = listCapsFor(shape, 2_000_000, window);
        if (caps !== null && caps !== LIST_CAP_STEPS[0]) found = true;
        if (caps !== null) expect(reviewFits(shape, 2_000_000, window)).toBe(true);
      }
      expect(found).toBe(true);
    });
  });
});
