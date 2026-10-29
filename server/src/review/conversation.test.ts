import { getEventListeners } from 'node:events';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  anthropicAnswer,
  anthropicToolUse,
  createFakeLlm,
  llmShape,
  openAiAnswer,
  openAiToolCalls,
  responsesAnswer,
  responsesToolCalls,
  type FakeLlm,
  type LlmReply,
  type LlmResponder,
  type RecordedLlmRequest,
} from '../../test/fake-llm';
import {
  converse,
  type LlmConversation,
  type LlmToolCall,
  type ProviderConfig,
} from '../llm/providers';
import { parseInternalHosts } from '../scm/url';
import {
  CONTEXT_FULL_TEXT,
  CONVERSATION_LIMITS,
  guessedInput,
  runConversation,
  windowGuessedInput,
  type ConversationInput,
} from './conversation';
import { newNonce } from './envelope';

const KINDS = ['openai', 'anthropic'] as const;
type Kind = (typeof KINDS)[number];
/** The wires the loop is run over: the two kinds, and the Responses API of the OpenAI kind. */
type Wire = Kind | 'responses';

const NONCE = newNonce();
const USER_TEXT = 'Review this change';
// The fixed texts of the loop, as the brief spells them: a change here is a change of contract.
const WRAP_UP = 'Token budget reached: answer now, with what you have, in the required JSON.';
const TOO_MANY = 'too many calls in one turn; this one was not run';
const BAD_ARGUMENTS = 'the arguments were not valid JSON; call again';
const CONTEXT_FULL = "not shown: the model's context window is full; answer now with what you have";
const SHORTER =
  'Your answer was cut off because it was too long: answer again, shorter, in the required JSON.';

const TOOLS = [
  {
    name: 'read_file',
    description: 'Read a file',
    parameters: { type: 'object', properties: { path: { type: 'string' } } },
  },
  {
    name: 'grep',
    description: 'Search the repository',
    parameters: { type: 'object', properties: { pattern: { type: 'string' } } },
  },
];
const LIMITS: ConversationInput['limits'] = {
  maxTurns: CONVERSATION_LIMITS.maxTurns,
  maxCallsPerTurn: CONVERSATION_LIMITS.maxCallsPerTurn,
  tokenBudget: 1_000_000,
  maxOutputTokens: 50,
};

// ─── What the model says, on the wire of each kind ───────────────────────────

type Call = { id: string; name?: string; args: unknown };

/**
 * The model asks for tool calls (and says `text` beside them, when given). `tokens` null: the
 * provider sends no usage, as some servers do not.
 */
function toolTurn(
  kind: Kind,
  calls: Call[],
  tokens: number[] | null = [100, 10],
  text?: string,
): LlmReply {
  const [input = 0, output = 0] = tokens ?? [];
  const over = text === undefined ? {} : { text };
  const body =
    kind === 'openai'
      ? openAiToolCalls(
          calls.map(({ id, name = 'read_file', args }) => ({ id, name, arguments: args })),
          {
            usage: tokens === null ? null : { prompt_tokens: input, completion_tokens: output },
            ...over,
          },
        )
      : anthropicToolUse(
          calls.map(({ id, name = 'read_file', args }) => ({ id, name, input: args })),
          {
            usage: tokens === null ? null : { input_tokens: input, output_tokens: output },
            ...over,
          },
        );
  return { status: 200, body };
}

/** The model answers with text and ends its turn the way `finish` says. */
function textTurn(
  kind: Kind,
  text: string,
  tokens: number[] | null = [100, 10],
  finish: 'stop' | 'length' | 'tool' | 'refusal' = 'stop',
): LlmReply {
  const [input = 0, output = 0] = tokens ?? [];
  const body =
    kind === 'openai'
      ? openAiAnswer(text, {
          finishReason: {
            stop: 'stop',
            length: 'length',
            tool: 'tool_calls',
            refusal: 'content_filter',
          }[finish],
          usage: tokens === null ? null : { prompt_tokens: input, completion_tokens: output },
        })
      : anthropicAnswer(text, {
          stopReason: {
            stop: 'end_turn',
            length: 'max_tokens',
            tool: 'tool_use',
            refusal: 'refusal',
          }[finish],
          usage: tokens === null ? null : { input_tokens: input, output_tokens: output },
        });
  return { status: 200, body };
}

/** The provider fails with `status`; the error body says `message` when it is given. */
function failure(
  kind: Kind,
  status: number,
  over: { headers?: Record<string, string>; message?: string } = {},
): LlmReply {
  return {
    status,
    ...(over.headers ? { headers: over.headers } : {}),
    body: failureBody(kind, over.message),
  };
}

function failureBody(kind: Kind, message: string | undefined): unknown {
  if (message === undefined) {
    return llmShape(kind === 'anthropic' ? 'anthropic-error' : 'openai-error');
  }
  if (kind === 'anthropic') {
    return { type: 'error', error: { type: 'invalid_request_error', message } };
  }
  return { error: { message, type: 'invalid_request_error', param: null, code: null } };
}

// ─── What the request says, on the wire of each kind ─────────────────────────

interface WireView {
  /** The names of the tools offered. */
  tools(request: RecordedLlmRequest): string[];
  /** The calls echoed back in the history, in order; `arguments` as the wire carries them. */
  echoes(request: RecordedLlmRequest): { id: string; name: string; arguments: unknown }[];
  /** The tool messages, in order. */
  results(request: RecordedLlmRequest): { id: string; text: string }[];
  /** The text of the last user message ('' when it has none, as a message of tool results). */
  lastUser(request: RecordedLlmRequest): string;
  /** The texts of the assistant messages that are not calls. */
  assistantTexts(request: RecordedLlmRequest): string[];
}

interface OpenAiWire {
  tools?: { function: { name: string } }[];
  messages: {
    role: string;
    content: string | null;
    tool_call_id?: string;
    tool_calls?: { id: string; function: { name: string; arguments: string } }[];
  }[];
}
interface AnthropicWire {
  tools?: { name: string }[];
  messages: {
    role: string;
    content: {
      type: string;
      text?: string;
      id?: string;
      name?: string;
      input?: unknown;
      tool_use_id?: string;
      content?: string;
    }[];
  }[];
}

const WIRES: Record<Kind, WireView> = {
  openai: {
    tools: (r) => (r.json as OpenAiWire).tools?.map((t) => t.function.name) ?? [],
    echoes: (r) =>
      (r.json as OpenAiWire).messages.flatMap((m) =>
        (m.tool_calls ?? []).map((c) => ({
          id: c.id,
          name: c.function.name,
          arguments: c.function.arguments,
        })),
      ),
    results: (r) =>
      (r.json as OpenAiWire).messages
        .filter((m) => m.role === 'tool')
        .map((m) => ({ id: m.tool_call_id ?? '', text: m.content ?? '' })),
    lastUser: (r) =>
      (r.json as OpenAiWire).messages.findLast((m) => m.role === 'user')?.content ?? '',
    assistantTexts: (r) =>
      (r.json as OpenAiWire).messages
        .filter((m) => m.role === 'assistant' && m.tool_calls === undefined)
        .map((m) => m.content ?? ''),
  },
  anthropic: {
    tools: (r) => (r.json as AnthropicWire).tools?.map((t) => t.name) ?? [],
    echoes: (r) =>
      (r.json as AnthropicWire).messages.flatMap((m) =>
        m.content
          .filter((b) => b.type === 'tool_use')
          .map((b) => ({ id: b.id ?? '', name: b.name ?? '', arguments: b.input })),
      ),
    results: (r) =>
      (r.json as AnthropicWire).messages.flatMap((m) =>
        m.content
          .filter((b) => b.type === 'tool_result')
          .map((b) => ({ id: b.tool_use_id ?? '', text: b.content ?? '' })),
      ),
    lastUser: (r) =>
      (r.json as AnthropicWire).messages
        .findLast((m) => m.role === 'user')
        ?.content.filter((b) => b.type === 'text')
        .map((b) => b.text ?? '')
        .join('') ?? '',
    assistantTexts: (r) =>
      (r.json as AnthropicWire).messages
        .filter((m) => m.role === 'assistant' && m.content.every((b) => b.type === 'text'))
        .map((m) => m.content.map((b) => b.text ?? '').join('')),
  },
};

interface ResponsesWire {
  tools?: { name: string }[];
  input: {
    type?: string;
    role?: string;
    call_id?: string;
    name?: string;
    arguments?: string;
    output?: string;
    content?: { type: string; text?: string }[];
  }[];
}

/** The views of every wire: the two kinds', and the Responses API's input items. */
const VIEWS: Record<Wire, WireView> = {
  ...WIRES,
  responses: {
    tools: (r) => (r.json as ResponsesWire).tools?.map((t) => t.name) ?? [],
    echoes: (r) =>
      (r.json as ResponsesWire).input
        .filter((item) => item.type === 'function_call')
        .map((item) => ({
          id: item.call_id ?? '',
          name: item.name ?? '',
          arguments: item.arguments,
        })),
    results: (r) =>
      (r.json as ResponsesWire).input
        .filter((item) => item.type === 'function_call_output')
        .map((item) => ({ id: item.call_id ?? '', text: item.output ?? '' })),
    lastUser: (r) =>
      (r.json as ResponsesWire).input
        .findLast((item) => item.role === 'user')
        ?.content?.map((part) => part.text ?? '')
        .join('') ?? '',
    assistantTexts: (r) =>
      (r.json as ResponsesWire).input
        .filter((item) => item.role === 'assistant')
        .map((item) => (item.content ?? []).map((part) => part.text ?? '').join('')),
  },
};

/** A call's arguments as the model reads them back: parsed, for the wire that sends text. */
const parsedArguments = (value: unknown): unknown =>
  typeof value === 'string' ? (JSON.parse(value) as unknown) : value;

/** What a tool message says: the envelope's marker lines checked, the line inside parsed. */
function unwrap(text: string): { tool: string; result: string } {
  const lines = text.split('\n');
  expect(lines).toHaveLength(3);
  expect(lines[0]).toBe(`<<<QUALOR-DATA-${NONCE}`);
  expect(lines[2]).toBe(`QUALOR-DATA-${NONCE}>>>`);
  return JSON.parse(lines[1]!) as { tool: string; result: string };
}

/** `depth` objects inside one another, as JSON text: `{"a":{"a":…1…}}`. */
const nestedText = (depth: number): string => `${'{"a":'.repeat(depth)}1${'}'.repeat(depth)}`;

describe('runConversation: the tool loop of a review (llm.md §2.5, review.md §9.1)', () => {
  let fake: FakeLlm;
  let configs: Record<Wire, ProviderConfig>;
  let http: { internalHosts: ReadonlySet<string>; version: string };

  // One fake per test: a reply a failing test left in the queue never reaches the next test.
  beforeEach(async () => {
    // As the real API does, it refuses a text block that is empty or only whitespace.
    fake = await createFakeLlm({ refuseBlankText: true });
    http = { internalHosts: parseInternalHosts(fake.host), version: '0.0.0' };
    const base = {
      model: 'm-1',
      auth: 'bearer',
      jsonMode: 'json_object',
      maxTokensField: 'max_tokens',
      temperature: null,
      api: 'chat_completions',
      workspaceId: null,
      timeoutSeconds: 5,
    } as const;
    configs = {
      openai: { kind: 'openai', baseUrl: fake.openAiBaseUrl, ...base },
      anthropic: { kind: 'anthropic', baseUrl: fake.anthropicBaseUrl, ...base },
      responses: { kind: 'openai', baseUrl: fake.openAiBaseUrl, ...base, api: 'responses' },
    };
  });
  afterEach(async () => {
    await fake.close();
  });

  /** The loop over the fake provider of `kind`, with the tools it runs and the waits it makes recorded. */
  function start(kind: Wire, over: Partial<ConversationInput> = {}) {
    const ran: LlmToolCall[] = [];
    const sleeps: number[] = [];
    const input: ConversationInput = {
      system: 'S',
      user: USER_TEXT,
      nonce: NONCE,
      tools: TOOLS,
      runTool: (call) => {
        ran.push(call);
        return Promise.resolve(`${call.name} ${JSON.stringify(call.arguments)}`);
      },
      limits: LIMITS,
      send: (conversation) => converse(configs[kind], fake.apiKey, conversation, http),
      shouldStop: () => Promise.resolve(false),
      sleep: (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
      ...over,
    };
    return { input, ran, sleeps };
  }

  const run = (kind: Wire, over: Partial<ConversationInput> = {}) => {
    const started = start(kind, over);
    return runConversation(started.input).then((result) => ({ result, ...started }));
  };

  describe('the conversation', () => {
    it.each(KINDS)(
      'a three-turn tool loop returns the final text with summed tokens (%s)',
      async (kind) => {
        fake.enqueue(
          toolTurn(
            kind,
            [
              { id: 'c1', args: { path: 'a.ts' } },
              { id: 'c2', name: 'grep', args: { pattern: 'x' } },
            ],
            [100, 10],
          ),
          toolTurn(kind, [{ id: 'c3', args: { path: 'b.ts' } }], [150, 12]),
          textTurn(kind, '{"findings":[]}', [200, 20]),
        );
        const { result, ran } = await run(kind);
        expect(result).toEqual({
          kind: 'answer',
          text: '{"findings":[]}',
          inputTokens: 450,
          outputTokens: 42,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          turns: 3,
          toolCalls: 3,
          wrappedUp: null,
        });
        expect(ran).toEqual([
          { id: 'c1', name: 'read_file', arguments: { path: 'a.ts' } },
          { id: 'c2', name: 'grep', arguments: { pattern: 'x' } },
          { id: 'c3', name: 'read_file', arguments: { path: 'b.ts' } },
        ]);

        const wire = WIRES[kind];
        expect(fake.requests).toHaveLength(3);
        for (const request of fake.requests) {
          // The tool list goes on every turn; the output limit is the one given.
          expect(wire.tools(request)).toEqual(['read_file', 'grep']);
          expect(request.json).toMatchObject({ max_tokens: 50 });
        }
        // The last request holds the whole history, in order, and each result in the data envelope.
        const last = fake.requests[2]!;
        expect(wire.echoes(last).map((c) => c.id)).toEqual(['c1', 'c2', 'c3']);
        expect(wire.results(last).map((r) => [r.id, unwrap(r.text)])).toEqual([
          ['c1', { tool: 'read_file', result: 'read_file {"path":"a.ts"}' }],
          ['c2', { tool: 'grep', result: 'grep {"pattern":"x"}' }],
          ['c3', { tool: 'read_file', result: 'read_file {"path":"b.ts"}' }],
        ]);
        expect(wire.lastUser(fake.requests[0]!)).toBe(USER_TEXT);
      },
    );
  });

  describe('the wrap-up turn', () => {
    it.each(KINDS)(
      'the tool list is sent on the wrap-up turn after tool history, and its calls are not run (%s)',
      async (kind) => {
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }]),
          toolTurn(kind, [{ id: 'c2', args: { path: 'b.ts' } }]),
          // The wrap-up answer calls a tool again, beside its text.
          toolTurn(kind, [{ id: 'c3', args: { path: 'c.ts' } }], [100, 10], '{"findings":[]}'),
        );
        const { result, ran } = await run(kind, { limits: { ...LIMITS, maxTurns: 2 } });
        expect(result).toEqual({
          kind: 'answer',
          text: '{"findings":[]}',
          inputTokens: 300,
          outputTokens: 30,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          turns: 3,
          toolCalls: 2,
          wrappedUp: 'turns',
        });
        expect(ran.map((c) => c.id)).toEqual(['c1', 'c2']);

        const wire = WIRES[kind];
        expect(fake.requests).toHaveLength(3);
        const wrapUp = fake.requests[2]!;
        expect(wire.tools(wrapUp)).toEqual(['read_file', 'grep']);
        // The history the tool list must come with (Anthropic refuses tool blocks without tools).
        expect(wire.echoes(wrapUp).map((c) => c.id)).toEqual(['c1', 'c2']);
        expect(wire.results(wrapUp)).toHaveLength(2);
        expect(wire.lastUser(wrapUp)).toBe(WRAP_UP);
        expect(wire.lastUser(fake.requests[1]!)).not.toContain('Token budget');
      },
    );

    it.each(KINDS)(
      'says why it wrapped up: `turns` at the turn limit, `budget` for the tokens, and `budget` when both are due (%s)',
      async (kind) => {
        // One turn of tools of 3 300 tokens, then the answer.
        const play = async (limits: Partial<ConversationInput['limits']>) => {
          fake.requests.length = 0;
          fake.enqueue(
            toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [3_200, 100]),
            textTurn(kind, '{"findings":[]}', [10, 1]),
          );
          const { result } = await run(kind, { limits: { ...LIMITS, ...limits } });
          expect(result, JSON.stringify(limits)).toMatchObject({ kind: 'answer', turns: 2 });
          return { result, wrapUp: WIRES[kind].lastUser(fake.requests[1]!) === WRAP_UP };
        };
        // The turn limit alone: a million tokens leave room for many more turns.
        const turns = await play({ maxTurns: 1 });
        expect(turns).toMatchObject({ result: { wrappedUp: 'turns' }, wrapUp: true });
        // The tokens alone: another turn as large, and the wrap-up after it, would pass 10 000.
        const budget = await play({ tokenBudget: 10_000 });
        expect(budget).toMatchObject({ result: { wrappedUp: 'budget' }, wrapUp: true });
        // Both at once: the tokens are what it says, which is what the review tells.
        const both = await play({ maxTurns: 1, tokenBudget: 10_000 });
        expect(both).toMatchObject({ result: { wrappedUp: 'budget' }, wrapUp: true });
        // Neither: no wrap-up, and nothing to say.
        const none = await play({});
        expect(none).toMatchObject({ result: { wrappedUp: null }, wrapUp: false });
      },
    );

    it.each(KINDS)(
      'the wrap-up comes once 85 % of the token budget is used, not before (%s)',
      async (kind) => {
        const limits = { ...LIMITS, tokenBudget: 100_000 };
        // Turns of 30 000, 20 000, 14 000, 10 000, 6 500 and 4 500 tokens make 85 000 of the
        // 100 000 after the sixth: 85 % exactly. After each of them another turn as large, and the
        // wrap-up after it, would still fit, so the 85 % alone makes the seventh request the wrap-up.
        const turnsOf = (last: number) =>
          [
            [29_000, 1_000],
            [19_000, 1_000],
            [13_000, 1_000],
            [9_000, 1_000],
            [6_000, 500],
            [last - 100, 100],
          ].map(([input, output], n) =>
            toolTurn(kind, [{ id: `c${n + 1}`, args: { path: 'a.ts' } }], [input!, output!]),
          );
        fake.enqueue(...turnsOf(4_500), textTurn(kind, '{"findings":[]}', [10, 1]));
        const over = await run(kind, { limits });
        expect(over.result).toMatchObject({
          kind: 'answer',
          inputTokens: 29_000 + 19_000 + 13_000 + 9_000 + 6_000 + 4_400 + 10,
          outputTokens: 4 * 1_000 + 500 + 100 + 1,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          turns: 7,
          wrappedUp: 'budget',
        });
        expect(WIRES[kind].lastUser(fake.requests[6]!)).toBe(WRAP_UP);
        expect(WIRES[kind].lastUser(fake.requests[5]!)).not.toContain('Token budget');

        // 84 900 after the sixth turn: not 85 % yet, and another turn and its wrap-up would fit.
        fake.requests.length = 0;
        fake.enqueue(...turnsOf(4_400), textTurn(kind, '{"findings":[]}', [10, 1]));
        const under = await run(kind, { limits });
        expect(under.result).toMatchObject({ kind: 'answer', turns: 7, wrappedUp: null });
        expect(WIRES[kind].lastUser(fake.requests[6]!)).not.toContain('Token budget');
      },
    );

    it.each(KINDS)(
      'the wrap-up comes a turn early when the next turn of tools would fit but not the wrap-up after it, whatever the share used (%s)',
      async (kind) => {
        const limits = { ...LIMITS, tokenBudget: 10_000 };
        // 3 300 used, a third of the budget. Another turn as large (the 3 300 sent again with the
        // results, and 100 written) would make under 7 000; the wrap-up after it sends all that
        // again and may write 50, which would make more than 10 000.
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [3_200, 100]),
          textTurn(kind, '{"findings":[]}', [10, 1]),
        );
        const reached = await run(kind, { limits });
        expect(reached.result).toMatchObject({ kind: 'answer', turns: 2, wrappedUp: 'budget' });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).toBe(WRAP_UP);

        // Three hundred tokens fewer, and the wrap-up after another turn would fit: the model goes on.
        fake.requests.length = 0;
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [2_900, 100]),
          textTurn(kind, '{"findings":[]}', [10, 1]),
        );
        const fits = await run(kind, { limits });
        expect(fits.result).toMatchObject({ kind: 'answer', turns: 2, wrappedUp: null });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).not.toContain('Token budget');
      },
    );

    it.each(KINDS)(
      'the wrap-up after the next turn is counted with the longest answer it may write (%s)',
      async (kind) => {
        // 2 900 used; another turn as large and the wrap-up after it make about 9 100 with the
        // wrap-up's answer counted at 50 tokens, and about 11 100 at 2 000.
        const reply = () => [
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [2_800, 100]),
          textTurn(kind, '{"findings":[]}', [10, 1]),
        ];
        fake.enqueue(...reply());
        const long = await run(kind, {
          limits: { ...LIMITS, tokenBudget: 10_000, maxOutputTokens: 2_000 },
        });
        expect(long.result).toMatchObject({ kind: 'answer', turns: 2, wrappedUp: 'budget' });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).toBe(WRAP_UP);

        fake.requests.length = 0;
        fake.enqueue(...reply());
        const short = await run(kind, { limits: { ...LIMITS, tokenBudget: 10_000 } });
        expect(short.result).toMatchObject({ kind: 'answer', turns: 2, wrappedUp: null });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).not.toContain('Token budget');
      },
    );

    it.each(KINDS)(
      'the room to think raises the max_tokens sent and nothing the loop estimates (%s)',
      async (kind) => {
        // As above: 2 900 used, and another turn with the wrap-up after it make about 9 100 with
        // the answer counted at 50 tokens. Counting the 20 000 of room too would make about 29 000
        // and bring the wrap-up at once; the room is not counted, so the model goes on.
        const limits = { ...LIMITS, tokenBudget: 10_000, reasoningAllowance: 20_000 };
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [2_800, 100]),
          textTurn(kind, '{"findings":[]}', [10, 1]),
        );
        const { result } = await run(kind, { limits });
        expect(result).toMatchObject({ kind: 'answer', turns: 2, wrappedUp: null });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).not.toContain('Token budget');
        // Every call asked for the answer's 50 tokens and the room.
        expect(fake.requests).toHaveLength(2);
        for (const request of fake.requests) {
          expect(request.json).toMatchObject({ max_tokens: 20_050 });
        }
      },
    );

    it.each(KINDS)(
      'what the model wrote beside its calls is counted in the next turn and the wrap-up after it (%s)',
      async (kind) => {
        const limits = { ...LIMITS, tokenBudget: 10_000 };
        // 1 000 read and 1 500 written. The next turn sends the 1 500 again and is guessed to write
        // as much; the wrap-up after it sends both: about 10 700 in all, past the budget.
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [1_000, 1_500]),
          textTurn(kind, '{"findings":[]}', [10, 1]),
        );
        const wordy = await run(kind, { limits });
        expect(wordy.result).toMatchObject({ kind: 'answer', turns: 2, wrappedUp: 'budget' });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).toBe(WRAP_UP);

        // 1 000 written: about 8 200 in all, and the model goes on.
        fake.requests.length = 0;
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [1_000, 1_000]),
          textTurn(kind, '{"findings":[]}', [10, 1]),
        );
        const terse = await run(kind, { limits });
        expect(terse.result).toMatchObject({ kind: 'answer', turns: 2, wrappedUp: null });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).not.toContain('Token budget');
      },
    );

    it.each(KINDS)(
      'the wrap-up counts what the tools just added, in the next turn and in the wrap-up after it (%s)',
      async (kind) => {
        const limits = { ...LIMITS, tokenBudget: 10_000 };
        // 1 100 used, and another turn as large with its wrap-up would make about 3 700 if the tools
        // added little. The file read adds about 2 300 tokens to what both of them send, and the
        // next turn is guessed to read as much again: about 10 500, past the budget.
        const read = (text: string) => () => Promise.resolve(text);
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [1_000, 100]),
          textTurn(kind, '{"findings":[]}', [10, 1]),
        );
        const large = await run(kind, { limits, runTool: read('x'.repeat(9_000)) });
        expect(large.result).toMatchObject({ kind: 'answer', turns: 2, wrappedUp: 'budget' });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).toBe(WRAP_UP);

        // A small result leaves room for another turn: the model goes on.
        fake.requests.length = 0;
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [1_000, 100]),
          textTurn(kind, '{"findings":[]}', [10, 1]),
        );
        const small = await run(kind, { limits, runTool: read('a small file') });
        expect(small.result).toMatchObject({ kind: 'answer', turns: 2, wrappedUp: null });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).not.toContain('Token budget');
      },
    );

    it.each(KINDS)('a wrap-up answer that only calls tools is a bad answer (%s)', async (kind) => {
      fake.enqueue(
        toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }]),
        toolTurn(kind, [{ id: 'c2', args: { path: 'b.ts' } }]),
      );
      const { result, ran } = await run(kind, { limits: { ...LIMITS, maxTurns: 1 } });
      expect(result).toMatchObject({ kind: 'failed', reason: 'bad_answer' });
      expect(ran.map((c) => c.id)).toEqual(['c1']);
      expect(fake.requests).toHaveLength(2);
    });

    describe('a model that keeps calling tools', () => {
      // Answers every request with a call of its own, however it is asked, and the tokens given.
      const insatiable = (kind: Kind, tokens: number[] | null): LlmResponder => {
        return (request) =>
          toolTurn(
            kind,
            [{ id: `call-${fake.requests.indexOf(request)}`, args: { path: 'a.ts' } }],
            tokens,
          );
      };

      it.each(KINDS)(
        'is stopped after maxTurns turns of tools and one wrap-up, however many it asks for (%s)',
        async (kind) => {
          fake.enqueue(...Array.from({ length: 40 }, () => insatiable(kind, [100, 10])));
          const { result, ran } = await run(kind);
          // What it spent is reported although it never answered.
          expect(result).toEqual({
            kind: 'failed',
            reason: 'bad_answer',
            inputTokens: 17 * 100,
            outputTokens: 17 * 10,
            cacheReadTokens: 0,
            cacheWriteTokens: 0,
            turns: 17,
            toolCalls: 16,
          });
          // The 16 turns of the limit, then the wrap-up, which is not answered with a call that runs.
          expect(fake.requests).toHaveLength(CONVERSATION_LIMITS.maxTurns + 1);
          expect(ran).toHaveLength(CONVERSATION_LIMITS.maxTurns);
          expect(WIRES[kind].lastUser(fake.requests.at(-1)!)).toBe(WRAP_UP);
        },
      );

      it.each(KINDS)('is stopped by the token budget too (%s)', async (kind) => {
        fake.enqueue(...Array.from({ length: 40 }, () => insatiable(kind, [4_000, 1_000])));
        const { result, ran } = await run(kind, { limits: { ...LIMITS, tokenBudget: 20_000 } });
        // 2 turns are 10 000 of the 20 000 tokens. A 3rd turn (its 5 000 sent again, with the
        // results, and 1 000 written) would fit, but not the wrap-up after it: the 3rd request is
        // the wrap-up, a turn before the 4th that the next call alone would make it, and so the
        // conversation stays within the budget.
        expect(result).toEqual({
          kind: 'failed',
          reason: 'bad_answer',
          inputTokens: 3 * 4_000,
          outputTokens: 3 * 1_000,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          turns: 3,
          toolCalls: 2,
        });
        expect(fake.requests).toHaveLength(3);
        expect(ran).toHaveLength(2);
        expect(WIRES[kind].lastUser(fake.requests[2]!)).toBe(WRAP_UP);
        expect(WIRES[kind].lastUser(fake.requests[1]!)).not.toBe(WRAP_UP);
      });

      it.each(KINDS)(
        'is stopped by the budget when the provider counts no tokens, on what it was sent (%s)',
        async (kind) => {
          fake.enqueue(...Array.from({ length: 40 }, () => insatiable(kind, null)));
          const limits = { ...LIMITS, tokenBudget: 8_000, maxOutputTokens: 400 };
          const { result, ran } = await run(kind, { limits });
          // Counted as nothing it would call until the turn limit; charged what it was sent and
          // the longest answer it may write, it is asked to answer after a few turns.
          expect(result).toMatchObject({ kind: 'failed', reason: 'bad_answer' });
          expect(fake.requests.length).toBeLessThan(CONVERSATION_LIMITS.maxTurns + 1);
          expect(ran.length).toBeGreaterThan(1);
          expect(WIRES[kind].lastUser(fake.requests.at(-1)!)).toBe(WRAP_UP);
          expect(ran).toHaveLength(fake.requests.length - 1);
          expect(result.turns).toBe(fake.requests.length);
          expect(result.outputTokens).toBe(fake.requests.length * 400);
          expect(result.inputTokens).toBeGreaterThan(0);
        },
      );
    });
  });

  describe("the model's context window (R46)", () => {
    /** The three wires the loop runs over. */
    const ALL_WIRES = ['openai', 'anthropic', 'responses'] as const;
    /** A cap of 10 000 tokens a call, and a budget that never wraps up first. */
    const WINDOW_LIMITS = { ...LIMITS, maxCallInputTokens: 10_000 };
    const usageOf = (tokens: number[] | null) =>
      tokens === null ? null : { input_tokens: tokens[0] ?? 0, output_tokens: tokens[1] ?? 0 };
    /** `toolTurn` on any wire: the Responses API's items, or the kind's own. */
    const callsOn = (
      wire: Wire,
      calls: Call[],
      tokens: number[] | null = [100, 10],
      text?: string,
    ) =>
      wire === 'responses'
        ? {
            status: 200,
            body: responsesToolCalls(
              calls.map(({ id, name = 'read_file', args }) => ({ id, name, arguments: args })),
              { usage: usageOf(tokens), ...(text === undefined ? {} : { text }) },
            ),
          }
        : toolTurn(wire, calls, tokens, text);
    /** `textTurn` on any wire, ending its turn or cut off at its limit. */
    const answerOn = (
      wire: Wire,
      text: string,
      tokens: number[] | null = [100, 10],
      finish: 'stop' | 'length' = 'stop',
    ) =>
      wire === 'responses'
        ? {
            status: 200,
            body: responsesAnswer(text, {
              usage: usageOf(tokens),
              ...(finish === 'length' ? { incomplete: 'max_output_tokens' } : {}),
            }),
          }
        : textTurn(wire, text, tokens, finish);
    /** A tool that answers `text` to every call; what it was asked to run, and what was sent or not. */
    const answering = (text: string) => {
      const ran: string[] = [];
      const told: string[] = [];
      return {
        ran,
        told,
        runTool: (call: LlmToolCall) => {
          ran.push(call.id);
          return Promise.resolve({
            text,
            sent: () => void told.push(`sent ${call.id}`),
            withheld: () => void told.push(`withheld ${call.id}`),
          });
        },
      };
    };
    /** The run of `wire` with every conversation it sent recorded. */
    const recorded = async (wire: Wire, over: Partial<ConversationInput>) => {
      const sent: LlmConversation[] = [];
      const done = await run(wire, {
        send: (conversation) => {
          sent.push(conversation);
          return converse(configs[wire], fake.apiKey, conversation, http);
        },
        ...over,
      });
      return { ...done, sent };
    };
    /** The fake's requests start again from none, and so does its queue: a fake of its own. */
    const freshFake = async () => {
      await fake.close();
      fake = await createFakeLlm({ refuseBlankText: true });
      http = { internalHosts: parseInternalHosts(fake.host), version: '0.0.0' };
      configs = {
        openai: { ...configs.openai, baseUrl: fake.openAiBaseUrl },
        anthropic: { ...configs.anthropic, baseUrl: fake.anthropicBaseUrl },
        responses: { ...configs.responses, baseUrl: fake.openAiBaseUrl },
      };
    };

    it.each(ALL_WIRES)(
      "wraps up before a call would pass the model's context window (%s)",
      async (wire) => {
        // 3 100 tokens sent and written. A read of 12 000 characters, about 4 000 tokens, makes the
        // next call about 7 100: under the cap; the wrap-up after another turn as large would pass it.
        const play = async (text: string, limits: ConversationInput['limits']) => {
          await freshFake();
          fake.enqueue(
            callsOn(wire, [{ id: 'c1', args: { path: 'a.ts' } }], [3_000, 100]),
            answerOn(wire, '{"findings":[]}', [10, 1]),
          );
          const tool = answering(text);
          const { result } = await run(wire, { limits, runTool: tool.runTool });
          expect(fake.requests).toHaveLength(2);
          return { result, next: fake.requests[1]!, told: tool.told };
        };
        const reached = await play('x'.repeat(12_000), WINDOW_LIMITS);
        expect(reached.result).toMatchObject({
          kind: 'answer',
          turns: 2,
          toolCalls: 1,
          wrappedUp: 'window',
        });
        expect(VIEWS[wire].lastUser(reached.next)).toBe(WRAP_UP);
        // What the tool answered fits the call that wraps up: it is sent as it is.
        expect(VIEWS[wire].results(reached.next).map((r) => unwrap(r.text).result)).toEqual([
          'x'.repeat(12_000),
        ]);
        expect(reached.told).toEqual(['sent c1']);

        // Half as much read: another turn and the wrap-up after it fit, and the model goes on.
        const fits = await play('x'.repeat(6_000), WINDOW_LIMITS);
        expect(fits.result).toMatchObject({ kind: 'answer', wrappedUp: null });
        expect(VIEWS[wire].lastUser(fits.next)).not.toBe(WRAP_UP);
        // Without a cap the large read goes on too: the token budget is a million.
        const uncapped = await play('x'.repeat(12_000), LIMITS);
        expect(uncapped.result).toMatchObject({ kind: 'answer', wrappedUp: null });
      },
    );

    it('wraps up for the window at the same point with cache reads as without, given the same total input (Anthropic, R49)', async () => {
      // The same 3 000 tokens of input, 2 000 of them read from the cache and 800 written to it:
      // the window counts every prompt token, as the budgets do.
      const cachedUsage = {
        input_tokens: 200,
        cache_creation_input_tokens: 800,
        cache_read_input_tokens: 2_000,
        output_tokens: 100,
      };
      const play = async (text: string, cached: boolean) => {
        await freshFake();
        const first = toolTurn('anthropic', [{ id: 'c1', args: { path: 'a.ts' } }], [3_000, 100]);
        fake.enqueue(
          cached ? { ...first, body: { ...(first.body as object), usage: cachedUsage } } : first,
          textTurn('anthropic', '{"findings":[]}', [10, 1]),
        );
        const tool = answering(text);
        const { result } = await run('anthropic', {
          limits: WINDOW_LIMITS,
          runTool: tool.runTool,
        });
        expect(fake.requests).toHaveLength(2);
        return { result, last: VIEWS.anthropic.lastUser(fake.requests[1]!), told: tool.told };
      };
      for (const [read, wrappedUp] of [
        ['x'.repeat(12_000), 'window'],
        ['x'.repeat(6_000), null],
      ] as const) {
        const plain = await play(read, false);
        const cached = await play(read, true);
        expect(plain.result, `${read.length} without the cache`).toMatchObject({
          kind: 'answer',
          wrappedUp,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
        });
        expect(cached.result, `${read.length} with the cache`).toMatchObject({
          kind: 'answer',
          wrappedUp,
          inputTokens: plain.result.inputTokens,
          cacheReadTokens: 2_000,
          cacheWriteTokens: 800,
        });
        expect(cached.last).toBe(plain.last);
        expect(cached.told).toEqual(plain.told);
      }
    });

    it.each(ALL_WIRES)(
      'sends tool results that would pass it as the fixed line, and wraps up with reason window (%s)',
      async (wire) => {
        // Two reads of about 4 000 tokens each would make the next call about 11 100: past the cap.
        fake.enqueue(
          callsOn(
            wire,
            [
              { id: 'c1', args: { path: 'a.ts' } },
              { id: 'c2', args: { path: 'b.ts' } },
            ],
            [3_000, 100],
          ),
          answerOn(wire, '{"findings":[]}', [10, 1]),
        );
        const tool = answering('x'.repeat(12_000));
        const { result } = await run(wire, { limits: WINDOW_LIMITS, runTool: tool.runTool });
        expect(result).toMatchObject({
          kind: 'answer',
          text: '{"findings":[]}',
          turns: 2,
          toolCalls: 2,
          wrappedUp: 'window',
        });
        expect(tool.ran).toEqual(['c1', 'c2']);
        // What the reads showed was never sent: each is told so, and none is told it was sent.
        expect(tool.told).toEqual(['withheld c1', 'withheld c2']);
        expect(CONTEXT_FULL_TEXT).toBe(CONTEXT_FULL);

        const view = VIEWS[wire];
        expect(fake.requests).toHaveLength(2);
        const wrapUp = fake.requests[1]!;
        // Each call keeps its answer, which is the fixed line the first time it is sent: what the
        // provider has once seen never changes.
        expect(view.echoes(wrapUp).map((c) => c.id)).toEqual(['c1', 'c2']);
        expect(view.results(wrapUp).map((r) => [r.id, unwrap(r.text)])).toEqual([
          ['c1', { tool: 'read_file', result: CONTEXT_FULL }],
          ['c2', { tool: 'read_file', result: CONTEXT_FULL }],
        ]);
        expect(wrapUp.body).not.toContain('x'.repeat(100));
        expect(view.lastUser(wrapUp)).toBe(WRAP_UP);
      },
    );

    it.each(ALL_WIRES)(
      'guesses what the tools answered at three characters a token, not four (%s)',
      async (wire) => {
        // 3 100 tokens, and two reads of 11 000 characters: about 5 500 tokens at four characters,
        // which would leave the call that sends them under the cap, and about 7 300 at three, which
        // does not.
        fake.enqueue(
          callsOn(
            wire,
            [
              { id: 'c1', args: { path: 'a.ts' } },
              { id: 'c2', args: { path: 'b.ts' } },
            ],
            [3_000, 100],
          ),
          answerOn(wire, '{"findings":[]}', [10, 1]),
        );
        const { result, sent } = await recorded(wire, {
          limits: WINDOW_LIMITS,
          runTool: answering('x'.repeat(11_000)).runTool,
        });
        expect(result).toMatchObject({ kind: 'answer', wrappedUp: 'window' });
        expect(VIEWS[wire].results(fake.requests[1]!).map((r) => unwrap(r.text).result)).toEqual([
          CONTEXT_FULL,
          CONTEXT_FULL,
        ]);
        for (const conversation of sent) {
          expect(windowGuessedInput(conversation)).toBeLessThan(WINDOW_LIMITS.maxCallInputTokens);
        }
      },
    );

    it.each(ALL_WIRES)(
      'counts the turn at what the next request carries for it: what it wrote where its reasoning goes back, its text and calls on Chat Completions (%s)',
      async (wire) => {
        // 3 000 sent, and 8 000 written, nearly all of it thinking. Anthropic's signed thinking and
        // the Responses API's reasoning go back with the turn, so the next call holds them; Chat
        // Completions sends back only the text and the call.
        fake.enqueue(
          callsOn(wire, [{ id: 'c1', args: { path: 'a.ts' } }], [3_000, 8_000]),
          answerOn(wire, '{"findings":[]}', [10, 1]),
        );
        const { result } = await run(wire, {
          limits: WINDOW_LIMITS,
          runTool: answering('a small file').runTool,
        });
        expect(result).toMatchObject({
          kind: 'answer',
          wrappedUp: wire === 'openai' ? null : 'window',
        });
      },
    );

    it.each(ALL_WIRES)(
      'never sends a call whose guess reaches maxCallInputTokens, whatever the provider counts (%s)',
      async (wire) => {
        // A model that reads three files in every turn and never answers, on a provider that counts
        // nothing, or far too little: no call is guessed (`windowGuessedInput`, three characters a
        // token, at least the four of what the server records as its input bytes) at the cap.
        const reads = (request: RecordedLlmRequest) => {
          const n = fake.requests.indexOf(request);
          return [1, 2, 3].map((i) => ({ id: `r${n}-${i}`, args: { path: `f${i}.ts` } }));
        };
        for (const tokens of [null, [10, 1]]) {
          // A fake of its own for each: nothing one queued answers the other.
          await freshFake();
          fake.enqueue(
            ...Array.from(
              { length: 40 },
              (): LlmResponder => (request) => callsOn(wire, reads(request), tokens),
            ),
          );
          const cap = 8_000;
          const { result, sent } = await recorded(wire, {
            limits: { ...LIMITS, maxOutputTokens: 400, maxCallInputTokens: cap },
            runTool: answering('y'.repeat(2_500)).runTool,
          });
          const name = JSON.stringify(tokens);
          // It wrapped up, and its wrap-up answer only called tools: a bad answer.
          expect(result, name).toMatchObject({ kind: 'failed', reason: 'bad_answer' });
          expect(VIEWS[wire].lastUser(fake.requests.at(-1)!), name).toBe(WRAP_UP);
          expect(sent, name).toHaveLength(fake.requests.length);
          expect(sent.length, name).toBeGreaterThan(2);
          for (const [n, conversation] of sent.entries()) {
            expect(windowGuessedInput(conversation), `${name} call ${n + 1}`).toBeLessThan(cap);
            expect(guessedInput(conversation)).toBeLessThan(windowGuessedInput(conversation));
          }
        }
      },
    );

    it.each(ALL_WIRES)(
      'makes no first call whose guess reaches the cap, and makes one a token under it (%s)',
      async (wire) => {
        // The first call's guess, as an uncapped run sends it.
        fake.enqueue(answerOn(wire, '{"findings":[]}'));
        const { sent } = await recorded(wire, {});
        const first = windowGuessedInput(sent[0]!);
        // At the cap exactly: not made.
        await freshFake();
        const refused = await recorded(wire, { limits: { ...LIMITS, maxCallInputTokens: first } });
        expect(refused.result).toEqual({
          kind: 'failed',
          reason: 'window_full',
          inputTokens: 0,
          outputTokens: 0,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          turns: 0,
          toolCalls: 0,
        });
        expect(fake.requests).toHaveLength(0);
        // A token more: made.
        fake.enqueue(answerOn(wire, '{"findings":[]}'));
        const made = await recorded(wire, { limits: { ...LIMITS, maxCallInputTokens: first + 1 } });
        expect(made.result).toMatchObject({ kind: 'answer', turns: 1 });
        expect(fake.requests).toHaveLength(1);
      },
    );

    it.each(ALL_WIRES)(
      'keeps an answer beside the ask for another only when the call stays under the cap: one whose estimate is the cap exactly is not made as it was (%s)',
      async (wire) => {
        // The provider counts next to nothing, so the estimate of the second call is the window's
        // guess for all it sends: what an uncapped run's second call measures.
        const said = 'v'.repeat(3_000);
        const play = async (cap: number | undefined) => {
          await freshFake();
          fake.enqueue(answerOn(wire, said, [1, 1]), answerOn(wire, '{"findings":[]}', [1, 1]));
          return recorded(wire, {
            limits: { ...LIMITS, ...(cap === undefined ? {} : { maxCallInputTokens: cap }) },
            accept: (text) => (text === said ? 'That is not the JSON asked for.' : true),
          });
        };
        const open = await play(undefined);
        expect(open.sent).toHaveLength(2);
        const estimate = windowGuessedInput(open.sent[1]!);
        const view = VIEWS[wire];
        expect(view.assistantTexts(fake.requests[1]!)).toEqual([said]);
        // A token more: the answer stays in the second call.
        const under = await play(estimate + 1);
        expect(under.result).toMatchObject({ kind: 'answer', turns: 2 });
        expect(view.assistantTexts(fake.requests[1]!)).toEqual([said]);
        // At the estimate exactly: that call is not made. The ask is made without the answer.
        const at = await play(estimate);
        expect(at.result).toMatchObject({ kind: 'answer', turns: 2 });
        expect(view.assistantTexts(fake.requests[1]!)).toEqual([]);
        expect(windowGuessedInput(at.sent[1]!)).toBeLessThan(estimate);
      },
    );

    it.each(ALL_WIRES)(
      'drops a turn whose own words leave no room even for the fixed lines, and wraps up on the history the last call sent (%s)',
      async (wire) => {
        // The model writes 36 000 characters beside its call: about 12 000 tokens, past the cap
        // whatever its call is answered. That turn was never sent.
        const wordy = 'z'.repeat(36_000);
        const play = async (cap: number) => {
          await freshFake();
          fake.enqueue(
            callsOn(wire, [{ id: 'c1', args: { path: 'a.ts' } }], [500, 100], wordy),
            answerOn(wire, '{"findings":[]}', [10, 1]),
          );
          const tool = answering('a small file');
          const done = await recorded(wire, {
            limits: { ...LIMITS, maxCallInputTokens: cap },
            runTool: tool.runTool,
          });
          return { ...done, told: tool.told };
        };
        const dropped = await play(10_000);
        expect(dropped.result).toMatchObject({
          kind: 'answer',
          turns: 2,
          toolCalls: 1,
          wrappedUp: 'window',
        });
        expect(dropped.told).toEqual(['withheld c1']);
        const view = VIEWS[wire];
        const wrapUp = fake.requests[1]!;
        // The wrap-up is the first message and the loop's words: no turn, no call, no answer.
        expect(view.echoes(wrapUp)).toEqual([]);
        expect(view.results(wrapUp)).toEqual([]);
        expect(wrapUp.body).not.toContain('z'.repeat(100));
        expect(view.lastUser(wrapUp).endsWith(WRAP_UP)).toBe(true);
        expect(windowGuessedInput(dropped.sent[1]!)).toBeLessThan(10_000);

        // A cap the first call fits and the wrap-up beside it does not: no call is made after it.
        const first = windowGuessedInput(dropped.sent[0]!);
        const full = await play(first + 1);
        expect(full.result).toMatchObject({ kind: 'failed', reason: 'window_full', turns: 1 });
        expect(fake.requests).toHaveLength(1);
        expect(full.told).toEqual(['withheld c1']);
      },
    );

    it.each(ALL_WIRES)(
      'asks again on the history the last call sent when the answer leaves no room, and ends window_full when even that does not fit (%s)',
      async (wire) => {
        // An answer of 30 000 characters, about 10 000 tokens: asked for again beside it, the call
        // would pass the cap; without it, it fits.
        const long = `{"findings":[${'w'.repeat(30_000)}`;
        const play = async (
          cap: number,
          answer: 'cut off' | 'refused',
        ): Promise<Awaited<ReturnType<typeof recorded>>> => {
          await freshFake();
          fake.enqueue(
            answerOn(wire, long, [500, 100], answer === 'cut off' ? 'length' : 'stop'),
            answerOn(wire, '{"findings":[]}', [10, 1]),
          );
          return recorded(wire, {
            limits: { ...LIMITS, maxCallInputTokens: cap },
            accept: (text) => (text === long ? 'That is not the JSON asked for.' : true),
          });
        };
        for (const answer of ['cut off', 'refused'] as const) {
          const again = await play(10_000, answer);
          expect(again.result, answer).toMatchObject({ kind: 'answer', turns: 2 });
          const asked = fake.requests[1]!;
          expect(asked.body, answer).not.toContain('w'.repeat(100));
          expect(VIEWS[wire].assistantTexts(asked), answer).toEqual([]);
          expect(VIEWS[wire].lastUser(asked), answer).toContain(
            answer === 'cut off' ? SHORTER : 'That is not the JSON asked for.',
          );
          // The ask does not fit beside the first call either: it is not made.
          const first = windowGuessedInput(again.sent[0]!);
          const full = await play(first + 1, answer);
          expect(full.result, answer).toMatchObject({
            kind: 'failed',
            reason: 'window_full',
            turns: 1,
          });
          expect(fake.requests, answer).toHaveLength(1);
        }
      },
    );
  });

  describe('the Anthropic wire', () => {
    const rolesOf = (request: RecordedLlmRequest) =>
      (request.json as AnthropicWire).messages.map((message) => message.role);
    /** No request of the conversation has two messages of one role in a row. */
    const expectAlternating = () => {
      for (const request of fake.requests) {
        const roles = rolesOf(request);
        roles.forEach((role, i) => {
          if (i > 0) expect(role, `message ${i} of ${roles.join(', ')}`).not.toBe(roles[i - 1]);
        });
      }
    };

    it('sends the wrap-up as a text block in the user message of the tool results', async () => {
      fake.enqueue(
        toolTurn('anthropic', [
          { id: 'c1', args: { path: 'a.ts' } },
          { id: 'c2', args: { path: 'b.ts' } },
        ]),
        textTurn('anthropic', '{"findings":[]}'),
      );
      await run('anthropic', { limits: { ...LIMITS, maxTurns: 1 } });
      const wrapUp = fake.requests[1]!.json as AnthropicWire;
      expect(wrapUp.messages.map((message) => message.role)).toEqual(['user', 'assistant', 'user']);
      expect(wrapUp.messages[2]!.content.map((block) => block.type)).toEqual([
        'tool_result',
        'tool_result',
        'text',
      ]);
      expect(WIRES.anthropic.lastUser(fake.requests[1]!)).toBe(WRAP_UP);
      expectAlternating();
    });

    it('sends a shorter-answer text after a blank cut-off answer in the user message before it', async () => {
      fake.enqueue(textTurn('anthropic', '', [10, 1], 'length'), textTurn('anthropic', 'done'));
      await run('anthropic');
      const second = fake.requests[1]!.json as AnthropicWire;
      expect(second.messages.map((message) => message.role)).toEqual(['user']);
      expect(second.messages[0]!.content.map((block) => block.text)).toEqual([
        USER_TEXT,
        expect.stringMatching(/shorter/),
      ]);
      expectAlternating();
    });

    it('keeps a shorter-answer text after an answer that has text in a message of its own', async () => {
      fake.enqueue(
        textTurn('anthropic', '{"findings":[{"ti', [10, 1], 'length'),
        textTurn('anthropic', 'done'),
      );
      await run('anthropic');
      expect(rolesOf(fake.requests[1]!)).toEqual(['user', 'assistant', 'user']);
      expectAlternating();
    });

    it('alternates in a conversation that wraps up and then asks for a shorter answer', async () => {
      fake.enqueue(
        toolTurn('anthropic', [{ id: 'c1', args: { path: 'a.ts' } }]),
        textTurn('anthropic', '', [10, 1], 'length'),
        textTurn('anthropic', '{"findings":[]}'),
      );
      const { result } = await run('anthropic', { limits: { ...LIMITS, maxTurns: 1 } });
      expect(result).toMatchObject({ kind: 'answer', wrappedUp: 'turns', turns: 3 });
      expect(rolesOf(fake.requests[2]!)).toEqual(['user', 'assistant', 'user']);
      expectAlternating();
    });
  });

  describe('the calls of a turn', () => {
    it.each(KINDS)('extra calls past the per-turn cap are answered, not run (%s)', async (kind) => {
      const calls = Array.from({ length: 10 }, (_, i) => ({
        id: `c${i + 1}`,
        args: { path: `f${i + 1}.ts` },
      }));
      fake.enqueue(toolTurn(kind, calls), textTurn(kind, '{"findings":[]}'));
      const { result, ran } = await run(kind);
      expect(result).toMatchObject({ kind: 'answer', turns: 2, toolCalls: 8 });
      expect(ran.map((c) => c.id)).toEqual(calls.slice(0, 8).map((c) => c.id));

      const wire = WIRES[kind];
      const second = fake.requests[1]!;
      // Every call is echoed, so that every call has its answer.
      expect(wire.echoes(second).map((c) => c.id)).toEqual(calls.map((c) => c.id));
      const results = wire.results(second);
      expect(results.map((r) => r.id)).toEqual(calls.map((c) => c.id));
      for (const r of results.slice(0, 8)) expect(unwrap(r.text).result).toMatch(/^read_file /);
      for (const r of results.slice(8)) expect(unwrap(r.text).result).toBe(TOO_MANY);
    });

    it.each(KINDS)('a repeated call id fails with bad_answer (%s)', async (kind) => {
      fake.enqueue(
        toolTurn(kind, [
          { id: 'c1', args: { path: 'a.ts' } },
          { id: 'c1', args: { path: 'b.ts' } },
        ]),
      );
      const { result, ran } = await run(kind);
      expect(result).toMatchObject({ kind: 'failed', reason: 'bad_answer' });
      expect(ran).toEqual([]);
      expect(fake.requests).toHaveLength(1);
    });

    it.each(KINDS)(
      'raw-string, oversized and deeply nested arguments are echoed as {} with the retry message (%s)',
      async (kind) => {
        // Far deeper than JSON.stringify can follow: a RangeError if the loop echoed it.
        const deep = nestedText(20_000);
        const calls: Call[] = [
          { id: 'c1', args: '{"path": "a.ts"' },
          { id: 'c2', args: { path: 'x'.repeat(20_000) } },
          { id: 'c3', args: JSON.parse(nestedText(25)) as unknown },
          { id: 'c4', args: 'DEEP' },
          { id: 'c5', args: { path: 'ok.ts' } },
        ];
        const reply = toolTurn(kind, calls);
        // The marker stands for the text of the deep call, which is not a value the fake can write.
        const text = JSON.stringify(reply.body);
        fake.enqueue({
          status: 200,
          body:
            kind === 'openai'
              ? text.replace('"DEEP"', JSON.stringify(deep))
              : text.replace('"DEEP"', deep),
        });
        fake.say('{"findings":[]}');
        const { result, ran } = await run(kind);

        expect(result).toMatchObject({ kind: 'answer', turns: 2, toolCalls: 1 });
        expect(ran).toEqual([{ id: 'c5', name: 'read_file', arguments: { path: 'ok.ts' } }]);
        const wire = WIRES[kind];
        const second = fake.requests[1]!;
        const echoes = wire.echoes(second);
        expect(echoes.map((c) => c.id)).toEqual(['c1', 'c2', 'c3', 'c4', 'c5']);
        expect(echoes.map((c) => parsedArguments(c.arguments))).toEqual([
          {},
          {},
          {},
          {},
          { path: 'ok.ts' },
        ]);
        if (kind === 'openai')
          expect(echoes.slice(0, 4).map((c) => c.arguments)).toEqual(Array(4).fill('{}'));
        const results = wire.results(second).map((r) => unwrap(r.text).result);
        expect(results.slice(0, 4)).toEqual(Array(4).fill(BAD_ARGUMENTS));
        expect(results[4]).toBe('read_file {"path":"ok.ts"}');
      },
    );
  });

  describe('the end of an answer', () => {
    it.each(KINDS)('finish reason tool without calls (%s)', async (kind) => {
      // The provider layer says `tool` whenever there are calls, and sometimes when there are none.
      fake.enqueue(textTurn(kind, '{"findings":[]}', [10, 2], 'tool'));
      const text = await run(kind);
      expect(text.result).toMatchObject({
        kind: 'answer',
        text: '{"findings":[]}',
        turns: 1,
        toolCalls: 0,
      });

      fake.enqueue(textTurn(kind, '  \n', [10, 2], 'tool'));
      const blank = await run(kind);
      expect(blank.result).toMatchObject({ kind: 'failed', reason: 'bad_answer' });
    });

    it.each(KINDS)('a refusal is a bad answer, with text or without (%s)', async (kind) => {
      // A refusal may come with the words of its apology; they are not the answer.
      for (const text of ['', "I can't help with that."]) {
        fake.requests.length = 0;
        fake.enqueue(textTurn(kind, text, [10, 2], 'refusal'));
        const { result } = await run(kind);
        expect(result).toMatchObject({ kind: 'failed', reason: 'bad_answer' });
        expect(fake.requests).toHaveLength(1);
      }
    });

    it.each(KINDS)('length then length fails with bad_answer (%s)', async (kind) => {
      fake.enqueue(
        textTurn(kind, '{"findings":[{"title":"A very', [100, 50], 'length'),
        textTurn(kind, '{"findings":[{"title"', [200, 50], 'length'),
      );
      const { result } = await run(kind);
      expect(result).toMatchObject({ kind: 'failed', reason: 'bad_answer' });

      const wire = WIRES[kind];
      expect(fake.requests).toHaveLength(2);
      const second = fake.requests[1]!;
      // One more turn, asking for a shorter answer, with the tools still offered.
      expect(wire.tools(second)).toEqual(['read_file', 'grep']);
      expect(wire.lastUser(second)).toMatch(/shorter/);
      expect(wire.assistantTexts(second)).toEqual(['{"findings":[{"title":"A very']);
    });

    it.each(KINDS)('length then an answer is that answer (%s)', async (kind) => {
      fake.enqueue(
        textTurn(kind, '{"findings":[{"title":"A very', [100, 50], 'length'),
        textTurn(kind, '{"findings":[]}', [200, 20]),
      );
      const { result } = await run(kind);
      expect(result).toEqual({
        kind: 'answer',
        text: '{"findings":[]}',
        inputTokens: 300,
        outputTokens: 70,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        turns: 2,
        toolCalls: 0,
        wrappedUp: null,
      });
    });
  });

  describe('an answer the caller does not accept', () => {
    const RETRY = 'Your answer did not match the required JSON; answer again with JSON only.';
    const isJson = (text: string): boolean => {
      try {
        JSON.parse(text);
        return true;
      } catch {
        return false;
      }
    };

    it.each(KINDS)('an answer the caller accepts ends the conversation (%s)', async (kind) => {
      fake.enqueue(textTurn(kind, '{"findings":[]}'));
      const seen: string[] = [];
      const { result } = await run(kind, {
        accept: (text) => {
          seen.push(text);
          return true;
        },
      });
      expect(result).toMatchObject({ kind: 'answer', text: '{"findings":[]}', turns: 1 });
      expect(seen).toEqual(['{"findings":[]}']);
      expect(fake.requests).toHaveLength(1);
    });

    it.each(KINDS)(
      'a rejected answer is asked for once more, after it, and no tool runs then (%s)',
      async (kind) => {
        fake.enqueue(
          textTurn(kind, 'Here is my review.', [100, 10]),
          // A call in the answer asked for again is not run: its text is the answer.
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [150, 20], '{"findings":[]}'),
        );
        const { result, ran } = await run(kind, { accept: isJson });
        expect(result).toEqual({
          kind: 'answer',
          text: '{"findings":[]}',
          inputTokens: 250,
          outputTokens: 30,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          turns: 2,
          toolCalls: 0,
          wrappedUp: null,
        });
        expect(ran).toEqual([]);
        const wire = WIRES[kind];
        expect(fake.requests).toHaveLength(2);
        const second = fake.requests[1]!;
        // The answer, then one user turn that asks again; the tools are still offered.
        expect(wire.assistantTexts(second)).toEqual(['Here is my review.']);
        expect(wire.lastUser(second)).toBe(RETRY);
        expect(wire.tools(second)).toEqual(['read_file', 'grep']);
      },
    );

    it.each(KINDS)('a second rejection ends as a bad answer (%s)', async (kind) => {
      fake.enqueue(textTurn(kind, 'First.', [100, 10]), textTurn(kind, 'Second.', [150, 10]));
      const { result } = await run(kind, { accept: isJson });
      expect(result).toEqual({
        kind: 'failed',
        reason: 'bad_answer',
        inputTokens: 250,
        outputTokens: 20,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        turns: 2,
        toolCalls: 0,
      });
      expect(fake.requests).toHaveLength(2);
    });

    it.each(KINDS)(
      'a rejection that brings a text asks again with that text, not the loop’s (%s)',
      async (kind) => {
        const WHY = 'That is no JSON: answer again with a key named findings.';
        fake.enqueue(
          textTurn(kind, 'Here is my review.', [100, 10]),
          textTurn(kind, '{"findings":[]}', [150, 20]),
        );
        const { result } = await run(kind, {
          accept: (text) => (isJson(text) ? true : WHY),
        });
        expect(result).toEqual({
          kind: 'answer',
          text: '{"findings":[]}',
          inputTokens: 250,
          outputTokens: 30,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          turns: 2,
          toolCalls: 0,
          wrappedUp: null,
        });
        const second = fake.requests[1]!;
        // The answer stays in the history, and the one user turn after it is the text given.
        expect(WIRES[kind].assistantTexts(second)).toEqual(['Here is my review.']);
        expect(WIRES[kind].lastUser(second)).toBe(WHY);
      },
    );

    it.each(KINDS)(
      'a rejection that brings a blank text asks with the loop’s own, and a second one is a bad answer (%s)',
      async (kind) => {
        fake.enqueue(textTurn(kind, 'First.', [100, 10]), textTurn(kind, '{"findings":[]}'));
        const blank = await run(kind, { accept: (text) => (isJson(text) ? true : '  ') });
        expect(blank.result).toMatchObject({ kind: 'answer', turns: 2 });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).toBe(RETRY);

        // The question is asked once, whatever it says: a second answer that is rejected ends it.
        fake.requests.length = 0;
        fake.enqueue(textTurn(kind, 'First.', [100, 10]), textTurn(kind, 'Second.', [150, 10]));
        const twice = await run(kind, { accept: () => 'Not that: answer again.' });
        expect(twice.result).toEqual({
          kind: 'failed',
          reason: 'bad_answer',
          inputTokens: 250,
          outputTokens: 20,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          turns: 2,
          toolCalls: 0,
        });
        expect(fake.requests).toHaveLength(2);
        expect(WIRES[kind].lastUser(fake.requests[1]!)).toBe('Not that: answer again.');
      },
    );

    it.each(KINDS)(
      'the turn that asks again may go past the token budget, as the wrap-up may (%s)',
      async (kind) => {
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }], [100, 10]),
          // The answer to the wrap-up, which is not JSON.
          textTurn(kind, 'Not JSON.', [200, 10]),
          textTurn(kind, '{"findings":[]}', [300, 10]),
        );
        const { result } = await run(kind, {
          accept: isJson,
          limits: { ...LIMITS, tokenBudget: 150 },
        });
        expect(result).toMatchObject({
          kind: 'answer',
          text: '{"findings":[]}',
          turns: 3,
          toolCalls: 1,
          wrappedUp: 'budget',
        });
        expect(fake.requests).toHaveLength(3);
        expect(WIRES[kind].lastUser(fake.requests[2]!)).toBe(RETRY);
      },
    );

    it.each(KINDS)(
      'a cut-off answer is asked for shorter before it is checked (%s)',
      async (kind) => {
        fake.enqueue(
          textTurn(kind, '{"findings":[{"title":"A very', [100, 50], 'length'),
          textTurn(kind, 'Shorter, but not JSON.', [200, 20]),
          textTurn(kind, '{"findings":[]}', [300, 20]),
        );
        const { result } = await run(kind, { accept: isJson });
        expect(result).toMatchObject({ kind: 'answer', text: '{"findings":[]}', turns: 3 });
        expect(WIRES[kind].lastUser(fake.requests[1]!)).toMatch(/shorter/);
        expect(WIRES[kind].lastUser(fake.requests[2]!)).toBe(RETRY);
      },
    );
  });

  describe('provider errors', () => {
    it.each(KINDS)(
      'rate limits are retried after Retry-After, at most twice (%s)',
      async (kind) => {
        fake.enqueue(
          failure(kind, 429, { headers: { 'retry-after': '7' } }),
          // A provider that asks for more than a minute is waited for a minute.
          failure(kind, 429, { headers: { 'retry-after': '600' } }),
          textTurn(kind, '{"findings":[]}'),
        );
        const waits = await run(kind);
        expect(waits.result).toMatchObject({ kind: 'answer', turns: 1 });
        expect(waits.sleeps).toEqual([7_000, 60_000]);
        expect(fake.requests).toHaveLength(3);

        // The third limit fails the conversation.
        fake.requests.length = 0;
        fake.enqueue(
          failure(kind, 429, { headers: { 'retry-after': '1' } }),
          failure(kind, 429, { headers: { 'retry-after': '2' } }),
          failure(kind, 429, { headers: { 'retry-after': '3' } }),
        );
        const given = await run(kind);
        expect(given.result).toMatchObject({ kind: 'failed', reason: 'provider_error' });
        expect(given.sleeps).toEqual([1_000, 2_000]);
        expect(fake.requests).toHaveLength(3);
      },
    );

    it.each(KINDS)(
      'a rate limit with no usable Retry-After waits the backoff (%s)',
      async (kind) => {
        fake.enqueue(
          failure(kind, 429),
          failure(kind, 429, { headers: { 'retry-after': '0' } }),
          textTurn(kind, '{"findings":[]}'),
        );
        const { result, sleeps } = await run(kind);
        expect(result).toMatchObject({ kind: 'answer' });
        // 5 s when the provider named none; never less than a second when it said 0.
        expect(sleeps).toEqual([5_000, 1_000]);
      },
    );

    it.each(KINDS)('an unavailable provider is retried twice (%s)', async (kind) => {
      fake.enqueue(failure(kind, 503), failure(kind, 500), failure(kind, 502));
      const failed = await run(kind);
      expect(failed.result).toMatchObject({ kind: 'failed', reason: 'provider_error' });
      expect(failed.sleeps).toEqual([5_000, 30_000]);
      expect(fake.requests).toHaveLength(3);

      fake.requests.length = 0;
      fake.enqueue(failure(kind, 502), textTurn(kind, '{"findings":[]}'));
      const recovered = await run(kind);
      expect(recovered.result).toMatchObject({ kind: 'answer', turns: 1 });
      expect(fake.requests).toHaveLength(2);
    });

    it.each(KINDS)('a refused key or request is not retried (%s)', async (kind) => {
      for (const status of [401, 403, 400, 413]) {
        fake.requests.length = 0;
        fake.enqueue(failure(kind, status));
        const { result, sleeps } = await run(kind);
        expect(result).toMatchObject({ kind: 'failed', reason: 'provider_error' });
        expect(sleeps).toEqual([]);
        expect(fake.requests).toHaveLength(1);
      }
    });

    it.each(KINDS)('retries the call of a later turn as well (%s)', async (kind) => {
      fake.enqueue(
        toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }]),
        failure(kind, 429, { headers: { 'retry-after': '3' } }),
        textTurn(kind, '{"findings":[]}'),
      );
      const { result, sleeps } = await run(kind);
      expect(result).toMatchObject({ kind: 'answer', turns: 2, toolCalls: 1 });
      expect(sleeps).toEqual([3_000]);
      // The retry sends the same history again.
      expect(fake.requests[2]!.body).toBe(fake.requests[1]!.body);
    });

    describe.each([400, 404, 422])('HTTP %i', (status) => {
      it.each(KINDS)(
        'a tools refusal on the first turn is provider_no_tools (%s)',
        async (kind) => {
          fake.enqueue(failure(kind, status, { message: 'This model does not support tools' }));
          const { result, sleeps } = await run(kind);
          expect(result).toMatchObject({ kind: 'failed', reason: 'provider_no_tools' });
          expect(sleeps).toEqual([]);
          expect(fake.requests).toHaveLength(1);
        },
      );

      it.each(KINDS)('a tools refusal on a later turn is a provider error (%s)', async (kind) => {
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }]),
          failure(kind, status, { message: 'This model does not support tools' }),
        );
        const { result } = await run(kind);
        expect(result).toMatchObject({ kind: 'failed', reason: 'provider_error' });
        expect(fake.requests).toHaveLength(2);
      });
    });

    it.each(KINDS)('a refusal that does not name tools is a provider error (%s)', async (kind) => {
      fake.enqueue(failure(kind, 400, { message: 'Model not found' }));
      const { result } = await run(kind);
      expect(result).toMatchObject({ kind: 'failed', reason: 'provider_error' });
    });
  });

  describe('stopping', () => {
    it.each(KINDS)('shouldStop true stops before the next call (%s)', async (kind) => {
      fake.enqueue(
        toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }]),
        textTurn(kind, '{"findings":[]}'),
      );
      let asked = 0;
      const { result, ran } = await run(kind, {
        // Not stopped before the first call, stopped before the second.
        shouldStop: () => Promise.resolve(++asked > 1),
      });
      expect(result).toMatchObject({ kind: 'stopped' });
      expect(fake.requests).toHaveLength(1);
      expect(ran).toHaveLength(1);
      expect(asked).toBe(2);
    });

    it.each(KINDS)('is checked before the first call, and sends nothing (%s)', async (kind) => {
      fake.enqueue(textTurn(kind, '{"findings":[]}'));
      const { result } = await run(kind, { shouldStop: () => Promise.resolve(true) });
      expect(result).toMatchObject({ kind: 'stopped' });
      expect(fake.requests).toHaveLength(0);
    });

    it.each(KINDS)('is checked again before a retry, after the wait (%s)', async (kind) => {
      fake.enqueue(
        failure(kind, 429, { headers: { 'retry-after': '5' } }),
        textTurn(kind, '{"findings":[]}'),
      );
      let asked = 0;
      const { result, sleeps } = await run(kind, {
        shouldStop: () => Promise.resolve(++asked > 1),
      });
      expect(result).toMatchObject({ kind: 'stopped' });
      expect(sleeps).toEqual([5_000]);
      expect(fake.requests).toHaveLength(1);
    });

    it.each(KINDS)('a signal that aborts wakes the wait of a retry at once (%s)', async (kind) => {
      fake.enqueue(
        failure(kind, 429, { headers: { 'retry-after': '60' } }),
        textTurn(kind, '{"findings":[]}'),
      );
      const controller = new AbortController();
      const began = Date.now();
      // The real wait, a minute long: the server stops while the loop sits in it.
      const running = run(kind, {
        sleep: undefined,
        signal: controller.signal,
        shouldStop: () => Promise.resolve(controller.signal.aborted),
      });
      await vi.waitFor(() => expect(fake.requests).toHaveLength(1), { timeout: 10_000 });
      controller.abort();
      const { result } = await running;
      expect(result).toMatchObject({ kind: 'stopped' });
      expect(fake.requests).toHaveLength(1);
      expect(Date.now() - began).toBeLessThan(10_000);
    });

    it.each(KINDS)(
      'a wait that its timer ends leaves no listener on the signal, which outlives it (%s)',
      async (kind) => {
        fake.enqueue(
          failure(kind, 429, { headers: { 'retry-after': '1' } }),
          textTurn(kind, '{"findings":[]}'),
        );
        // The server's stop: it lives as long as the server does.
        const signal = new AbortController().signal;
        // The real wait, a second long, which nothing aborts.
        const { result } = await run(kind, { sleep: undefined, signal });
        expect(result).toMatchObject({ kind: 'answer' });
        expect(fake.requests).toHaveLength(2);
        expect(getEventListeners(signal, 'abort')).toEqual([]);
      },
    );

    it.each(KINDS)('a signal that has aborted already makes no wait at all (%s)', async (kind) => {
      fake.enqueue(
        failure(kind, 503),
        failure(kind, 429, { headers: { 'retry-after': '60' } }),
        textTurn(kind, '{"findings":[]}'),
      );
      const began = Date.now();
      let asked = 0;
      const { result } = await run(kind, {
        sleep: undefined,
        signal: AbortSignal.abort(),
        // Not stopped before the first call: the abort is seen by the wait only.
        shouldStop: () => Promise.resolve(++asked > 1),
      });
      expect(result).toMatchObject({ kind: 'stopped' });
      expect(fake.requests).toHaveLength(1);
      expect(Date.now() - began).toBeLessThan(2_000);
    });

    it.each(KINDS)(
      'hands its signal to the wait it makes, whichever wait it is (%s)',
      async (kind) => {
        fake.enqueue(
          failure(kind, 429, { headers: { 'retry-after': '3' } }),
          failure(kind, 429, { headers: { 'retry-after': '4' } }),
          textTurn(kind, '{"findings":[]}'),
        );
        const controller = new AbortController();
        const given: (AbortSignal | undefined)[] = [];
        const waits = (signals: (AbortSignal | undefined)[]): ConversationInput['sleep'] => {
          return (_ms, signal) => {
            signals.push(signal);
            return Promise.resolve();
          };
        };
        const withSignal = await run(kind, { signal: controller.signal, sleep: waits(given) });
        expect(withSignal.result).toMatchObject({ kind: 'answer' });
        expect(given).toEqual([controller.signal, controller.signal]);

        fake.requests.length = 0;
        fake.enqueue(
          failure(kind, 429, { headers: { 'retry-after': '3' } }),
          textTurn(kind, '{"findings":[]}'),
        );
        const without: (AbortSignal | undefined)[] = [];
        const noSignal = await run(kind, { sleep: waits(without) });
        expect(noSignal.result).toMatchObject({ kind: 'answer' });
        expect(without).toEqual([undefined]);
      },
    );
  });

  describe("the review's time (limits.deadline)", () => {
    /** A clock that stands at `at` ms and moves only when the loop waits, by the wait. */
    function timed(kind: Wire, deadline: number, over: Partial<ConversationInput> = {}) {
      let at = 0;
      const sleeps: number[] = [];
      return run(kind, {
        limits: { ...LIMITS, deadline },
        now: () => at,
        sleep: (ms) => {
          sleeps.push(ms);
          at += ms;
          return Promise.resolve();
        },
        ...over,
      }).then((done) => ({ ...done, sleeps }));
    }

    it.each(KINDS)(
      'a retry that would wait until the deadline or past it is not waited for: a conversation that had a turn wraps up for the time at once (%s)',
      async (kind) => {
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }]),
          failure(kind, 429, { headers: { 'retry-after': '20' } }),
          textTurn(kind, '{"findings":[]}'),
        );
        const { result, sleeps, ran } = await timed(kind, 20_000);
        expect(result).toMatchObject({ kind: 'answer', wrappedUp: 'time', turns: 2, toolCalls: 1 });
        expect(sleeps).toEqual([]);
        expect(ran).toHaveLength(1);
        expect(fake.requests).toHaveLength(3);
        // The call that failed is made again as the wrap-up: the answers, then the words to answer.
        expect(WIRES[kind].lastUser(fake.requests[2]!)).toBe(WRAP_UP);
        expect(WIRES[kind].results(fake.requests[2]!).map((r) => r.id)).toEqual(['c1']);
      },
    );

    it.each(KINDS)(
      'the wrap-up for the time is tried once: when it fails too, the conversation ends with the time limit (%s)',
      async (kind) => {
        fake.enqueue(
          toolTurn(kind, [{ id: 'c1', args: { path: 'a.ts' } }]),
          failure(kind, 429, { headers: { 'retry-after': '30' } }),
          failure(kind, 503),
        );
        const { result, sleeps } = await timed(kind, 20_000);
        expect(result).toMatchObject({
          kind: 'failed',
          reason: 'provider_error',
          timeLimit: true,
          turns: 1,
        });
        expect(sleeps).toEqual([]);
        expect(fake.requests).toHaveLength(3);
      },
    );

    it.each(KINDS)(
      'a conversation that had no turn ends with the time limit, and waits for nothing (%s)',
      async (kind) => {
        fake.enqueue(
          failure(kind, 429, { headers: { 'retry-after': '30' } }),
          textTurn(kind, '{"findings":[]}'),
        );
        const { result, sleeps } = await timed(kind, 20_000);
        expect(result).toMatchObject({
          kind: 'failed',
          reason: 'provider_error',
          timeLimit: true,
          turns: 0,
        });
        expect(sleeps).toEqual([]);
        expect(fake.requests).toHaveLength(1);
      },
    );

    it.each(KINDS)(
      'a wait that ends before the deadline is waited in full; none goes past it (%s)',
      async (kind) => {
        fake.enqueue(
          // 7 s of the 20: waited; then the backoff's 5 s of the 13 left: waited; then 10 s of the
          // 8 left: not waited, and the time is up.
          failure(kind, 429, { headers: { 'retry-after': '7' } }),
          failure(kind, 503),
          failure(kind, 429, { headers: { 'retry-after': '10' } }),
        );
        const { result, sleeps } = await timed(kind, 20_000);
        expect(sleeps).toEqual([7_000, 5_000]);
        expect(result).toMatchObject({ kind: 'failed', timeLimit: true, turns: 0 });
        expect(fake.requests).toHaveLength(3);

        // Time enough for both waits: the call is retried as before.
        fake.requests.length = 0;
        fake.enqueue(
          failure(kind, 429, { headers: { 'retry-after': '7' } }),
          failure(kind, 503),
          textTurn(kind, '{"findings":[]}'),
        );
        const inTime = await timed(kind, 60_000);
        expect(inTime.sleeps).toEqual([7_000, 5_000]);
        expect(inTime.result).toMatchObject({ kind: 'answer', wrappedUp: null, turns: 1 });
      },
    );

    it.each(KINDS)(
      'a deadline passed before the first call sends nothing; the stop check is asked first (%s)',
      async (kind) => {
        fake.enqueue(textTurn(kind, '{"findings":[]}'));
        const late = await timed(kind, 0);
        expect(late.result).toEqual({
          kind: 'failed',
          reason: 'provider_error',
          timeLimit: true,
          inputTokens: 0,
          outputTokens: 0,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          turns: 0,
          toolCalls: 0,
        });
        expect(fake.requests).toHaveLength(0);

        const stopped = await timed(kind, 0, { shouldStop: () => Promise.resolve(true) });
        expect(stopped.result).toMatchObject({ kind: 'stopped' });
        expect(fake.requests).toHaveLength(0);
      },
    );
  });
});
