import { REDACTED } from '@qualor/shared';
import { afterAll, afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createFakeLlm, type FakeLlm } from '../../test/fake-llm';
import { memorySnapshot } from '../../test/review';
import {
  converse,
  LlmError,
  REASONING_ALLOWANCE_TOKENS,
  type LlmConversation,
  type LlmToolCall,
  type LlmTurn,
  type ProviderConfig,
} from '../llm/providers';
import { parseInternalHosts } from '../scm/url';
import {
  CONTEXT_FULL_TEXT,
  CONVERSATION_LIMITS,
  CONVERSATION_TEXTS,
  guessedInput,
  windowGuessedInput,
} from './conversation';
import { newNonce } from './envelope';
import { MaskedFiles } from './masked-files';
import { Masker } from './masker';
import { REVIEW_OUTPUT_TOKENS } from './pipeline';
import { SYSTEM_PROMPTS } from './prompts';
import {
  callInputCap,
  converseOverTools,
  DEFAULT_CONTEXT_WINDOW_TOKENS,
  newToolPolicy,
  type RoleCall,
} from './tool-conversation';
import { REVIEW_TOOLS, TOOL_LIMITS, type ShownLines } from './tools';

/** The masker of the tests: one worker for all of them, stopped when they are done. */
const masker = new Masker();
afterAll(() => masker.close());

/** The AWS documentation's example key: the redaction takes it out of a file. */
const AWS_KEY = 'AKIAIOSFODNN7EXAMPLE';

const turn = (over: Partial<LlmTurn>): LlmTurn => ({
  text: '',
  finishReason: 'stop',
  usage: { inputTokens: 100, outputTokens: 10 },
  model: null,
  toolCalls: [],
  ...over,
});

const callOf = (role: RoleCall['role'], over: Partial<RoleCall> = {}): RoleCall => ({
  role,
  user: 'The data',
  nonce: newNonce(),
  tokenBudget: 1_000_000,
  accept: () => true,
  ...over,
});

describe('newToolPolicy', () => {
  it('gives a review the whole of its budget, and the files, masker and exclusions it is given', () => {
    const reader = memorySnapshot();
    const masked = new MaskedFiles(reader, { masker });
    const policy = newToolPolicy({ excludePaths: ['vendor/**'], masked, masker });
    expect(policy).toEqual({
      excludePaths: ['vendor/**'],
      budget: {
        calls: TOOL_LIMITS.callsPerReview,
        greps: TOOL_LIMITS.grepsPerReview,
        maskedBytes: TOOL_LIMITS.maskedBytesPerReview,
      },
      masked,
      masker,
    });
    expect(policy.masked).toBe(masked);
    expect(policy.masker).toBe(masker);
    // Each review has a budget of its own: spending one's calls leaves the next one's.
    policy.budget.calls = 0;
    expect(newToolPolicy({ excludePaths: [], masked, masker }).budget.calls).toBe(
      TOOL_LIMITS.callsPerReview,
    );
  });
});

describe('the room a call leaves for the model to think', () => {
  let fake: FakeLlm;
  let http: { internalHosts: ReadonlySet<string>; version: string };
  const config = (kind: ProviderConfig['kind'], over: Partial<ProviderConfig> = {}) =>
    ({
      kind,
      baseUrl: kind === 'openai' ? fake.openAiBaseUrl : fake.anthropicBaseUrl,
      model: 'm-1',
      auth: 'bearer',
      jsonMode: 'json_object',
      maxTokensField: 'max_tokens',
      temperature: null,
      api: 'chat_completions',
      workspaceId: null,
      timeoutSeconds: 5,
      ...over,
    }) satisfies ProviderConfig;
  beforeEach(async () => {
    fake = await createFakeLlm();
    http = { internalHosts: parseInternalHosts(fake.host), version: '0.0.0' };
  });
  afterEach(async () => {
    await fake.close();
  });

  it('is 16 000 tokens beyond the answer, and the answer caps stay as they were', () => {
    expect(REASONING_ALLOWANCE_TOKENS).toEqual({ conversation: 16_000, singleShot: 4_000 });
    expect(REVIEW_OUTPUT_TOKENS).toEqual({
      quality: 12_288,
      tests: 12_288,
      security: 12_288,
      performance: 12_288,
      judge: 16_384,
      verify: 2_048,
      reply: 2_048,
    });
  });

  it.each([
    ['quality', 28_288],
    ['tests', 28_288],
    ['security', 28_288],
    ['performance', 28_288],
    ['judge', 32_384],
    ['verify', 18_048],
    ['reply', 18_048],
  ] as const)(
    'review and reply calls send the answer tokens plus the reasoning allowance as max_tokens: a %s call asks for %i',
    async (role, tokens) => {
      // The limit goes in the field each provider has for it: OpenAI's chat completions in the one
      // the settings choose, Anthropic's messages in max_tokens.
      const wires = [
        [config('openai'), 'max_tokens'],
        [config('openai', { maxTokensField: 'max_completion_tokens' }), 'max_completion_tokens'],
        [config('anthropic'), 'max_tokens'],
      ] as const;
      for (const [wire, field] of wires) {
        fake.requests.length = 0;
        const result = await converseOverTools(callOf(role), {
          reader: null,
          send: (conversation) => converse(wire, fake.apiKey, conversation, http),
          shouldStop: () => Promise.resolve(false),
        });
        expect(result.kind, `${wire.kind} ${field}`).toBe('answer');
        expect(fake.requests).toHaveLength(1);
        const sent = fake.requests[0]!.json as Record<string, unknown>;
        expect(sent[field], `${wire.kind} ${field}`).toBe(tokens);
        // And the other field is not there.
        expect(sent).not.toHaveProperty(
          field === 'max_tokens' ? 'max_completion_tokens' : 'max_tokens',
        );
      }
    },
  );

  it('raises only the max_tokens sent: the loop estimates with the answer cap, as it did, and a provider that counts nothing is charged the cap', async () => {
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const sent: LlmConversation[] = [];
    const result = await converseOverTools(callOf('verify'), {
      reader,
      policy,
      send: (conversation) => {
        sent.push(conversation);
        return Promise.resolve(
          turn({ text: '{"ok":true}', usage: { inputTokens: null, outputTokens: null } }),
        );
      },
      shouldStop: () => Promise.resolve(false),
    });
    // The call asks for the verification's 2 048 and 16 000 more, apart, and is charged the 2 048.
    expect(sent[0]).toMatchObject({ maxOutputTokens: 2_048, reasoningAllowance: 16_000 });
    expect(result).toMatchObject({ kind: 'answer', outputTokens: REVIEW_OUTPUT_TOKENS.verify });
  });
});

describe('the room to think on a small window', () => {
  it('is what the window has left beside the input and the answer, so no call is refused for it', async () => {
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const window = 28_000;
    const sent: LlmConversation[] = [];
    await converseOverTools(callOf('quality'), {
      reader,
      policy,
      contextWindowTokens: window,
      send: (conversation) => {
        sent.push(conversation);
        return Promise.resolve(turn({ text: '{"findings":[]}' }));
      },
      shouldStop: () => Promise.resolve(false),
    });
    const [call] = sent;
    expect(call?.reasoningAllowance).toBeGreaterThan(0);
    expect(call?.reasoningAllowance).toBeLessThan(REASONING_ALLOWANCE_TOKENS.conversation);
    // Input, answer and room fit the window.
    expect(
      windowGuessedInput(call!) + REVIEW_OUTPUT_TOKENS.quality + (call?.reasoningAllowance ?? 0),
    ).toBeLessThanOrEqual(window);
  });
});

describe('the most one call sends: the context window less the room for the answer (R46)', () => {
  it('is 1 000 000 tokens less the role’s answer unless the provider gives the window', () => {
    expect(DEFAULT_CONTEXT_WINDOW_TOKENS).toBe(1_000_000);
    expect(callInputCap(null, 'judge')).toBe(983_616);
    expect(callInputCap(32_000, 'verify')).toBe(29_952);
    expect(callInputCap(32_000, 'quality')).toBe(32_000 - REVIEW_OUTPUT_TOKENS.quality);
    expect(callInputCap(null, 'reply')).toBe(1_000_000 - REVIEW_OUTPUT_TOKENS.reply);
  });

  it('keeps every call within the window the io gives, and tells nothing of the tool answers it kept back', async () => {
    // 400 lines of 90 characters, a secret on the first: one read is about 10 000 tokens, and three
    // of them pass what a quality reviewer's call may send in a window of 32 000.
    const lines = [
      `const key = "${AWS_KEY}";`,
      ...Array.from({ length: 399 }, (_, i) => `export const v${i} = ${'1'.repeat(70)};`),
    ];
    const reader = memorySnapshot({ files: { 'src/big.ts': `${lines.join('\n')}\n` } });
    const reads = ['c1', 'c2', 'c3'].map((id) => ({
      id,
      name: 'read_file',
      arguments: { path: 'src/big.ts' },
    }));
    const play = async (contextWindowTokens?: number | null) => {
      const policy = newToolPolicy({
        excludePaths: [],
        masked: new MaskedFiles(reader, { masker }),
        masker,
      });
      const sent: LlmConversation[] = [];
      const shown: (readonly ShownLines[])[] = [];
      const redactions: number[] = [];
      const replies = [
        turn({ finishReason: 'tool', toolCalls: reads }),
        turn({ text: '{"findings":[]}' }),
      ];
      const result = await converseOverTools(callOf('quality'), {
        reader,
        policy,
        send: (conversation) => {
          sent.push(conversation);
          return Promise.resolve(replies.shift() ?? turn({ text: 'unexpected' }));
        },
        shouldStop: () => Promise.resolve(false),
        onToolRead: (lines) => shown.push(lines),
        onToolRedactions: (count) => redactions.push(count),
        ...(contextWindowTokens === undefined ? {} : { contextWindowTokens }),
      });
      const answers = sent[1]?.messages.filter((message) => message.role === 'tool') ?? [];
      return { result, sent, shown, redactions, answers, policy };
    };

    const small = await play(32_000);
    expect(small.result).toMatchObject({ kind: 'answer', toolCalls: 3, wrappedUp: 'window' });
    for (const conversation of small.sent) {
      expect(guessedInput(conversation)).toBeLessThanOrEqual(callInputCap(32_000, 'quality'));
    }
    // Each answer is the fixed line, and what the reads showed and masked was never sent.
    expect(small.answers).toHaveLength(3);
    for (const answer of small.answers) {
      const [, line = ''] = answer.text.split('\n');
      expect(JSON.parse(line)).toEqual({ tool: 'read_file', result: CONTEXT_FULL_TEXT });
      expect(answer.text).not.toContain('export const');
    }
    expect(small.shown).toEqual([]);
    expect(small.redactions).toEqual([]);

    // The file stays masked for the review: a later conversation that reads it and sends it tells
    // the secret, which the answers kept back never did.
    const later = await converseOverTools(callOf('judge'), {
      reader,
      policy: small.policy,
      send: (() => {
        const replies = [
          turn({ finishReason: 'tool', toolCalls: [reads[0]!] }),
          turn({ text: '{"findings":[]}' }),
        ];
        return () => Promise.resolve(replies.shift() ?? turn({ text: 'unexpected' }));
      })(),
      shouldStop: () => Promise.resolve(false),
      onToolRedactions: (count) => small.redactions.push(count),
    });
    expect(later).toMatchObject({ kind: 'answer', toolCalls: 1 });
    expect(small.redactions).toEqual([1]);

    // The default window, and a null one, take the three reads: they are sent, and told.
    for (const window of [undefined, null]) {
      const ample = await play(window);
      expect(ample.result, String(window)).toMatchObject({ kind: 'answer', wrappedUp: null });
      expect(ample.answers.map((answer) => answer.text.includes('export const v1 '))).toEqual([
        true,
        true,
        true,
      ]);
      expect(ample.shown).toHaveLength(3);
      // The file is masked once, at its first read: the secret is told with that answer.
      expect(ample.redactions).toEqual([1, 0, 0]);
    }
  });
});

describe('the prompt cache across reviews (R49)', () => {
  let fake: FakeLlm;
  beforeEach(async () => {
    fake = await createFakeLlm({ promptCache: true });
  });
  afterEach(async () => {
    await fake.close();
  });

  it('two reviews of a role send the same tools and system prompt, whatever their nonces, and the second reads them from the cache; the same nonce and data make the same request', async () => {
    const config: ProviderConfig = {
      kind: 'anthropic',
      baseUrl: fake.anthropicBaseUrl,
      model: 'm-cache',
      auth: 'bearer',
      jsonMode: 'json_object',
      maxTokensField: 'max_tokens',
      temperature: null,
      api: 'chat_completions',
      workspaceId: null,
      timeoutSeconds: 5,
    };
    const http = { internalHosts: parseInternalHosts(fake.host), version: '0.0.0' };
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const turns: LlmTurn[] = [];
    const review = async (nonce: string, user: string) =>
      await converseOverTools(callOf('security', { nonce, user }), {
        reader,
        policy,
        send: async (conversation) => {
          const answered = await converse(config, fake.apiKey, conversation, http);
          turns.push(answered);
          return answered;
        },
        shouldStop: () => Promise.resolve(false),
      });
    const nonce = newNonce();
    await review(nonce, 'The data of one review');
    await review(newNonce(), 'The data of another review');
    await review(nonce, 'The data of one review');
    const bodies = fake.requests.map((request) => request.json as Record<string, unknown>);
    expect(bodies).toHaveLength(3);
    // No clock, random id or set order reaches the prompt: the tools and the system prompt are the
    // same text for every review of the role, and the nonce lives in the first message alone.
    for (const field of ['tools', 'system', 'tool_choice', 'model']) {
      expect(JSON.stringify(bodies[1]![field]), field).toBe(JSON.stringify(bodies[0]![field]));
    }
    expect(JSON.stringify(bodies[0]!.system)).not.toContain(nonce);
    expect(fake.requests[2]!.body).toBe(fake.requests[0]!.body);
    // The first review writes the prefix; the second reads the tools and the system prompt.
    expect(turns.map((t) => t.usage.cacheReadTokens ?? 0)[0]).toBe(0);
    expect(turns[1]!.usage.cacheReadTokens).toBeGreaterThan(0);
    expect(turns[1]!.usage.cacheWriteTokens).toBeGreaterThan(0);
    // And every budget counts all of the prompt, the part read from the cache included.
    expect(turns[1]!.usage.inputTokens).toBe(
      431 + turns[1]!.usage.cacheReadTokens! + turns[1]!.usage.cacheWriteTokens!,
    );
  });
});

describe('converseOverTools', () => {
  it("sends the role's prompt and limit with the review tools, and returns the answer", async () => {
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const roles = ['security', 'quality', 'judge', 'verify'] as const;
    for (const role of roles) {
      const sent: LlmConversation[] = [];
      const result = await converseOverTools(callOf(role, { user: `data of ${role}` }), {
        reader,
        policy,
        send: (conversation) => {
          sent.push(conversation);
          return Promise.resolve(turn({ text: '{"ok":true}' }));
        },
        shouldStop: () => Promise.resolve(false),
      });
      expect(result).toMatchObject({ kind: 'answer', text: '{"ok":true}', toolCalls: 0 });
      expect(sent).toHaveLength(1);
      expect(sent[0]).toMatchObject({
        system: SYSTEM_PROMPTS[role],
        tools: REVIEW_TOOLS,
        // The role's answer, and room for the model to think before it, apart.
        maxOutputTokens: REVIEW_OUTPUT_TOKENS[role],
        reasoningAllowance: REASONING_ALLOWANCE_TOKENS.conversation,
        messages: [{ role: 'user', text: `data of ${role}` }],
      });
    }
  });

  it('runs the tool calls over the reader under the policy, and tells the secrets it masked', async () => {
    const reader = memorySnapshot({
      files: { 'src/config.ts': `const region = 'eu';\nconst key = "${AWS_KEY}";\n` },
    });
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const nonce = newNonce();
    const sent: LlmConversation[] = [];
    const redactions: number[] = [];
    const replies = [
      turn({
        finishReason: 'tool',
        toolCalls: [{ id: 'call-1', name: 'read_file', arguments: { path: 'src/config.ts' } }],
      }),
      turn({ text: '{"findings":[]}' }),
    ];
    const result = await converseOverTools(callOf('quality', { nonce }), {
      reader,
      policy,
      send: (conversation) => {
        sent.push(conversation);
        return Promise.resolve(replies.shift() ?? turn({ text: 'unexpected' }));
      },
      shouldStop: () => Promise.resolve(false),
      onToolRedactions: (count) => redactions.push(count),
    });
    expect(result).toMatchObject({
      kind: 'answer',
      text: '{"findings":[]}',
      toolCalls: 1,
      turns: 2,
    });
    // The tool ran over this reader: the model was given the masked file, in the review's envelope.
    const answered = sent[1]?.messages.find((message) => message.role === 'tool');
    expect(answered?.text).toContain(REDACTED);
    expect(answered?.text).not.toContain(AWS_KEY);
    expect(answered?.text).toContain(nonce);
    expect(redactions).toEqual([1]);
    // And it spent the policy's budget, which the next conversation of the review shares.
    expect(policy.budget.calls).toBe(TOOL_LIMITS.callsPerReview - 1);
  });

  describe('the second check keeps tool calls of its own (T21a)', () => {
    const run = async (role: 'verify' | 'judge' | 'reply', calls: number, greps: number) => {
      const reader = memorySnapshot();
      const policy = newToolPolicy({
        excludePaths: [],
        masked: new MaskedFiles(reader, { masker }),
        masker,
      });
      policy.budget.calls = calls;
      policy.budget.greps = greps;
      await converseOverTools(callOf(role), {
        reader,
        policy,
        send: () => Promise.resolve(turn({ text: '{"ok":true}' })),
        shouldStop: () => Promise.resolve(false),
      });
      return policy.budget;
    };

    it('a verification starts with at least 8 tool calls and 3 searches, even after the reviewers used them all', async () => {
      expect(TOOL_LIMITS.verifyCallsFloor).toBe(8);
      expect(TOOL_LIMITS.verifyGrepsFloor).toBe(3);
      const spent = await run('verify', 0, 0);
      expect(spent.calls).toBe(TOOL_LIMITS.verifyCallsFloor);
      expect(spent.greps).toBe(TOOL_LIMITS.verifyGrepsFloor);
      // A little left is raised to the floor, and more than the floor is left as it is.
      const little = await run('verify', 2, 1);
      expect([little.calls, little.greps]).toEqual([8, 3]);
      const plenty = await run('verify', 50, 20);
      expect([plenty.calls, plenty.greps]).toEqual([50, 20]);
    });

    it('leaves the budget of every other role as it is', async () => {
      for (const role of ['judge', 'reply'] as const) {
        const left = await run(role, 0, 0);
        expect([left.calls, left.greps]).toEqual([0, 0]);
      }
    });
  });

  it('runs as many calls of a turn as the loop allows, and asks again for an answer the pipeline refuses', async () => {
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const tooMany = Array.from({ length: CONVERSATION_LIMITS.maxCallsPerTurn + 2 }, (_, i) => ({
      id: `call-${i}`,
      name: 'list_files',
      arguments: {},
    }));
    const asked: string[] = [];
    const replies = [
      turn({ finishReason: 'tool', toolCalls: tooMany }),
      turn({ text: 'not json' }),
      turn({ text: '{"ok":true}' }),
    ];
    const result = await converseOverTools(
      callOf('tests', {
        accept: (text) => {
          asked.push(text);
          return text.startsWith('{');
        },
      }),
      {
        reader,
        policy,
        send: () => Promise.resolve(replies.shift() ?? turn({ text: 'unexpected' })),
        shouldStop: () => Promise.resolve(false),
      },
    );
    expect(result).toMatchObject({
      kind: 'answer',
      text: '{"ok":true}',
      toolCalls: CONVERSATION_LIMITS.maxCallsPerTurn,
    });
    expect(asked).toEqual(['not json', '{"ok":true}']);
  });

  it('wraps up when the token budget it is given is reached', async () => {
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const sent: LlmConversation[] = [];
    const replies = [
      turn({
        finishReason: 'tool',
        toolCalls: [{ id: 'call-1', name: 'list_files', arguments: {} }],
        usage: { inputTokens: 100, outputTokens: 10 },
      }),
      turn({ text: '{"ok":true}' }),
    ];
    const result = await converseOverTools(callOf('security', { tokenBudget: 100 }), {
      reader,
      policy,
      send: (conversation) => {
        sent.push(conversation);
        return Promise.resolve(replies.shift() ?? turn({ text: 'unexpected' }));
      },
      shouldStop: () => Promise.resolve(false),
    });
    expect(result).toMatchObject({ kind: 'answer', wrappedUp: 'budget' });
    expect(sent[1]?.messages.at(-1)).toEqual({ role: 'user', text: CONVERSATION_TEXTS.wrapUp });
  });

  it("a conversation over the tools stops at the loop's 16 turns", async () => {
    // 6I-3 Task 14 (3): a model that calls a tool every turn is asked to wrap up after its 16th
    // turn, and its 17th call (the wrap-up) answers.
    expect(CONVERSATION_LIMITS.maxTurns).toBe(16);
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const sent: LlmConversation[] = [];
    const result = await converseOverTools(callOf('security'), {
      reader,
      policy,
      send: (conversation) => {
        sent.push(conversation);
        return Promise.resolve(
          sent.length <= CONVERSATION_LIMITS.maxTurns
            ? turn({
                finishReason: 'tool',
                toolCalls: [{ id: `call-${sent.length}`, name: 'list_files', arguments: {} }],
              })
            : turn({ text: '{"ok":true}' }),
        );
      },
      shouldStop: () => Promise.resolve(false),
    });
    expect(sent).toHaveLength(CONVERSATION_LIMITS.maxTurns + 1);
    expect(sent[CONVERSATION_LIMITS.maxTurns - 1]?.messages.at(-1)).not.toEqual({
      role: 'user',
      text: CONVERSATION_TEXTS.wrapUp,
    });
    expect(sent[CONVERSATION_LIMITS.maxTurns]?.messages.at(-1)).toEqual({
      role: 'user',
      text: CONVERSATION_TEXTS.wrapUp,
    });
    expect(result).toMatchObject({
      kind: 'answer',
      text: '{"ok":true}',
      wrappedUp: 'turns',
      turns: CONVERSATION_LIMITS.maxTurns + 1,
      toolCalls: CONVERSATION_LIMITS.maxTurns,
    });
  });

  it('serves the reply role with its own prompt and output limit over the review tools', async () => {
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const sent: LlmConversation[] = [];
    const result = await converseOverTools(callOf('reply', { user: 'The thread' }), {
      reader,
      policy,
      send: (conversation) => {
        sent.push(conversation);
        return Promise.resolve(turn({ text: '{"ok":true}' }));
      },
      shouldStop: () => Promise.resolve(false),
    });
    expect(result).toMatchObject({ kind: 'answer', text: '{"ok":true}' });
    expect(sent[0]).toMatchObject({
      system: SYSTEM_PROMPTS.reply,
      tools: REVIEW_TOOLS,
      maxOutputTokens: REVIEW_OUTPUT_TOKENS.reply,
      reasoningAllowance: REASONING_ALLOWANCE_TOKENS.conversation,
      messages: [{ role: 'user', text: 'The thread' }],
    });
  });

  it("sends the prompt a call is given instead of its role's", async () => {
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const sent: LlmConversation[] = [];
    const system = 'Qualor review: reply\nThis thread allows one verdict: "keep".';
    await converseOverTools(callOf('reply', { system }), {
      reader,
      policy,
      send: (conversation) => {
        sent.push(conversation);
        return Promise.resolve(turn({ text: '{"ok":true}' }));
      },
      shouldStop: () => Promise.resolve(false),
    });
    expect(sent[0]?.system).toBe(system);
    expect(sent[0]?.system).not.toBe(SYSTEM_PROMPTS.reply);
  });

  it('gives the model no tools without a snapshot, and answers a call it makes anyway with a fixed text that reads nothing', async () => {
    const nonce = newNonce();
    const sent: LlmConversation[] = [];
    const replies = [
      turn({
        finishReason: 'tool',
        toolCalls: [{ id: 'call-1', name: 'read_file', arguments: { path: 'src/config.ts' } }],
      }),
      turn({ text: '{"ok":true}' }),
    ];
    const result = await converseOverTools(callOf('reply', { nonce }), {
      reader: null,
      send: (conversation) => {
        sent.push(conversation);
        return Promise.resolve(replies.shift() ?? turn({ text: 'unexpected' }));
      },
      shouldStop: () => Promise.resolve(false),
    });
    expect(result).toMatchObject({ kind: 'answer', text: '{"ok":true}' });
    expect(sent).toHaveLength(2);
    expect(sent.map((conversation) => conversation.tools)).toEqual([[], []]);
    const answered = sent[1]?.messages.find((message) => message.role === 'tool');
    expect(answered?.text).toContain('no tools are available');
    // Still between the conversation's markers, like every tool answer.
    expect(answered?.text).toContain(nonce);
  });

  it('does not read a refusal as a lack of tool calling when no tools were sent', async () => {
    const refused = new LlmError('rejected', 'The provider refused the request', {
      status: 400,
      refusedTools: true,
    });
    for (const tools of [true, false]) {
      const reader = memorySnapshot();
      const policy = newToolPolicy({
        excludePaths: [],
        masked: new MaskedFiles(reader, { masker }),
        masker,
      });
      const send = () => Promise.reject(refused);
      const result = await converseOverTools(
        callOf('reply'),
        tools
          ? { reader, policy, send, shouldStop: () => Promise.resolve(false) }
          : { reader: null, send, shouldStop: () => Promise.resolve(false) },
      );
      expect(result).toMatchObject({
        kind: 'failed',
        reason: tools ? 'provider_no_tools' : 'provider_error',
      });
    }
  });

  it('tells the caller the lines a tool call showed, and nothing of a call that showed none', async () => {
    const reader = memorySnapshot({
      files: { 'a.ts': 'const a = 1;\n', 'b.ts': 'const b = 2;\nconst c = 3;\n' },
    });
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const told: (readonly ShownLines[])[] = [];
    const calls: LlmToolCall[] = [
      { id: 'c1', name: 'read_file', arguments: { path: 'a.ts' } },
      { id: 'c2', name: 'grep', arguments: { pattern: 'const' } },
      // None of these shows a line of a file: arguments that cannot be used (the call is not run),
      // a path that is not there, a search with no match, a listing.
      { id: 'c3', name: 'read_file', arguments: 'a.ts' },
      { id: 'c4', name: 'read_file', arguments: { path: 'missing.ts' } },
      { id: 'c5', name: 'grep', arguments: { pattern: 'nothing like this' } },
      { id: 'c6', name: 'list_files', arguments: {} },
      // The loop runs eight calls of a turn: the third of these is told there were too many.
      ...Array.from({ length: 3 }, (_, i) => ({
        id: `read-${i}`,
        name: 'read_file',
        arguments: { path: 'b.ts', from: 2 },
      })),
    ];
    const replies = [
      turn({ finishReason: 'tool', toolCalls: calls }),
      turn({ text: '{"ok":true}' }),
    ];
    await converseOverTools(callOf('reply'), {
      reader,
      policy,
      send: () => Promise.resolve(replies.shift() ?? turn({ text: 'unexpected' })),
      shouldStop: () => Promise.resolve(false),
      onToolRead: (shown) => told.push(shown),
    });
    expect(CONVERSATION_LIMITS.maxCallsPerTurn).toBe(8);
    // The lines each call showed, as the tool made them: a.ts, each line that matches, and the
    // second line of b.ts (twice: the third of these calls was not run).
    expect(told).toEqual([
      [{ path: 'a.ts', from: 1, to: 1 }],
      [
        { path: 'a.ts', from: 1, to: 1 },
        { path: 'b.ts', from: 1, to: 1 },
        { path: 'b.ts', from: 2, to: 2 },
      ],
      [{ path: 'b.ts', from: 2, to: 2 }],
      [{ path: 'b.ts', from: 2, to: 2 }],
    ]);
  });

  it('asks again with the text a rejection brings, and with the loop’s own when it brings none', async () => {
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    const WHY = 'That is not the JSON asked for: answer again with the key ok.';
    for (const [rejection, retry] of [
      [WHY, WHY],
      [false, CONVERSATION_TEXTS.retry],
    ] as const) {
      const sent: LlmConversation[] = [];
      const replies = [turn({ text: 'not json' }), turn({ text: '{"ok":true}' })];
      const result = await converseOverTools(
        callOf('reply', { accept: (text) => (text.startsWith('{') ? true : rejection) }),
        {
          reader,
          policy,
          send: (conversation) => {
            sent.push(conversation);
            return Promise.resolve(replies.shift() ?? turn({ text: 'unexpected' }));
          },
          shouldStop: () => Promise.resolve(false),
        },
      );
      expect(result).toMatchObject({ kind: 'answer', text: '{"ok":true}', turns: 2 });
      expect(sent[1]?.messages.at(-1)).toEqual({ role: 'user', text: retry });
    }
  });

  it('stops where the caller says so', async () => {
    const reader = memorySnapshot();
    const policy = newToolPolicy({
      excludePaths: [],
      masked: new MaskedFiles(reader, { masker }),
      masker,
    });
    let sends = 0;
    const result = await converseOverTools(callOf('judge'), {
      reader,
      policy,
      send: () => {
        sends += 1;
        return Promise.resolve(turn({ text: '{}' }));
      },
      shouldStop: () => Promise.resolve(true),
    });
    expect(result.kind).toBe('stopped');
    expect(sends).toBe(0);
  });

  it('gives the loop its signal, which wakes the wait of a retry', async () => {
    // The provider limits the call for a minute, and the server stops as it says so: the wait that
    // follows is not sat out.
    const controller = new AbortController();
    let sends = 0;
    const began = Date.now();
    const result = await converseOverTools(callOf('judge'), {
      reader: null,
      send: () => {
        sends += 1;
        controller.abort();
        return Promise.reject(
          new LlmError('rate_limited', 'The provider is limiting', {
            status: 429,
            retryAfterSeconds: 60,
          }),
        );
      },
      shouldStop: () => Promise.resolve(controller.signal.aborted),
      signal: controller.signal,
    });
    expect(result.kind).toBe('stopped');
    expect(sends).toBe(1);
    expect(Date.now() - began).toBeLessThan(10_000);
  });
});
