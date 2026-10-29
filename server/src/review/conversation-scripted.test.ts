import { describe, expect, it, vi } from 'vitest';
import {
  LlmCallAborted,
  LlmError,
  type LlmConversation,
  type LlmMessage,
  type LlmToolCall,
  type LlmTurn,
  type ProviderReplay,
} from '../llm/providers';
import {
  CircuitOpenError,
  CONVERSATION_LIMITS,
  runConversation,
  type ConversationInput,
} from './conversation';
import { newNonce } from './envelope';

const NONCE = newNonce();
const USER_TEXT = 'Review this change';
// The fixed texts of the loop, as the brief spells them: a change here is a change of contract.
const WRAP_UP = 'Token budget reached: answer now, with what you have, in the required JSON.';
const SHORTER =
  'Your answer was cut off because it was too long: answer again, shorter, in the required JSON.';
const TOO_MANY = 'too many calls in one turn; this one was not run';
const BAD_ARGUMENTS = 'the arguments were not valid JSON; call again';

/** How many conversations a `JSON.stringify` spy has been asked to serialise. */
const conversationsSerialised = (stringify: { mock: { calls: unknown[][] } }): number =>
  stringify.mock.calls.filter(
    ([value]) =>
      typeof value === 'object' && value !== null && 'system' in value && 'messages' in value,
  ).length;

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

/** What a tool message says: the envelope's marker lines checked, the line inside parsed. */
function unwrap(text: string): { tool: string; result: string } {
  const lines = text.split('\n');
  expect(lines).toHaveLength(3);
  expect(lines[0]).toBe(`<<<QUALOR-DATA-${NONCE}`);
  expect(lines[2]).toBe(`QUALOR-DATA-${NONCE}>>>`);
  return JSON.parse(lines[1]!) as { tool: string; result: string };
}
/** `depth` objects inside one another, as a value (`{ a: { a: … } }`), built without recursion. */
function nestedValue(depth: number): Record<string, unknown> {
  let value: Record<string, unknown> = {};
  for (let level = 1; level < depth; level += 1) value = { a: value };
  return value;
}

// ─── The loop alone: a scripted provider, for what the wires cannot show ──────

const turn = (text: string, over: Partial<LlmTurn> = {}): LlmTurn => ({
  text,
  finishReason: 'stop',
  toolCalls: [],
  usage: { inputTokens: 10, outputTokens: 5 },
  model: null,
  ...over,
});
const callTurn = (calls: LlmToolCall[], over: Partial<LlmTurn> = {}): LlmTurn =>
  turn('', { finishReason: 'tool', toolCalls: calls, ...over });
const FILE = { path: 'a.ts' };
const call = (id: string, args: unknown = FILE, name = 'read_file'): LlmToolCall => ({
  id,
  name,
  arguments: args,
});

/**
 * What the loop charges for the input it sent, and guesses for a part of it: a quarter of the
 * bytes of its JSON, rounded up.
 */
const quarterOfBytes = (sent: LlmConversation | readonly LlmMessage[]) =>
  Math.ceil(Buffer.byteLength(JSON.stringify(sent), 'utf8') / 4);

describe('runConversation with a scripted provider', () => {
  /** A provider that plays `steps` in order (an Error is thrown) and keeps what it was sent. */
  function scripted(...steps: (LlmTurn | Error)[]) {
    const seen: LlmConversation[] = [];
    const ran: LlmToolCall[] = [];
    const sleeps: number[] = [];
    const queue = [...steps];
    const input: ConversationInput = {
      system: 'S',
      user: USER_TEXT,
      nonce: NONCE,
      tools: TOOLS,
      runTool: (c) => {
        ran.push(c);
        return Promise.resolve('ok');
      },
      limits: LIMITS,
      send: (conversation) => {
        seen.push(conversation);
        const step = queue.shift();
        if (step === undefined) return Promise.reject(new Error('the script ran out'));
        return step instanceof Error ? Promise.reject(step) : Promise.resolve(step);
      },
      shouldStop: () => Promise.resolve(false),
      sleep: (ms) => {
        sleeps.push(ms);
        return Promise.resolve();
      },
    };
    return { input, seen, ran, sleeps };
  }

  it('sends the system prompt, the user message, the tools and the output limit on the first turn', async () => {
    const s = scripted(turn('done'));
    await runConversation(s.input);
    expect(s.seen).toEqual([
      {
        system: 'S',
        messages: [{ role: 'user', text: USER_TEXT }],
        tools: TOOLS,
        maxOutputTokens: 50,
      },
    ]);
  });

  describe('the arguments a model sends', () => {
    /** The result a one-call turn gives for `args`, and what the tool and the history saw of them. */
    async function withArguments(args: unknown) {
      // Built by hand: `call` gives an argument that is not there its default.
      const s = scripted(
        callTurn([{ id: 'c1', name: 'read_file', arguments: args }]),
        turn('done'),
      );
      const result = await runConversation(s.input);
      const history = s.seen[1]!.messages;
      return { result, ran: s.ran, history };
    }
    const echoed = (history: readonly LlmMessage[]) =>
      history.flatMap((m) => (m.role === 'assistant' ? m.toolCalls.map((c) => c.arguments) : []));
    const answer = (history: readonly LlmMessage[]) =>
      history.flatMap((m) => (m.role === 'tool' ? [unwrap(m.text).result] : []));

    it.each([
      ['a string', '{"path": "a.ts"'],
      ['a list', ['a.ts']],
      ['a number', 7],
      ['a boolean', true],
    ])('%s is not arguments: it is echoed as {} and the model is told', async (_name, args) => {
      const { ran, history } = await withArguments(args);
      expect(ran).toEqual([]);
      expect(echoed(history)).toEqual([{}]);
      expect(answer(history)).toEqual([BAD_ARGUMENTS]);
    });

    it.each([
      ['null', null],
      ['undefined', undefined],
    ])('%s is no arguments: the tool is run with {}', async (_name, args) => {
      const { ran, history } = await withArguments(args);
      expect(ran).toEqual([{ id: 'c1', name: 'read_file', arguments: {} }]);
      expect(echoed(history)).toEqual([{}]);
    });

    it('allows arguments nested 20 levels and refuses 21', async () => {
      const ok = await withArguments(nestedValue(CONVERSATION_LIMITS.maxArgumentDepth));
      expect(ok.ran).toHaveLength(1);
      const tooDeep = await withArguments(nestedValue(CONVERSATION_LIMITS.maxArgumentDepth + 1));
      expect(tooDeep.ran).toEqual([]);
      expect(answer(tooDeep.history)).toEqual([BAD_ARGUMENTS]);
    });

    it('refuses nesting that JSON.stringify cannot follow, without a RangeError', async () => {
      const { result, ran, history } = await withArguments(nestedValue(100_000));
      expect(result).toMatchObject({ kind: 'answer' });
      expect(ran).toEqual([]);
      expect(echoed(history)).toEqual([{}]);
    });

    it('allows 16 KiB of arguments and refuses one byte more', async () => {
      const overhead = Buffer.byteLength(JSON.stringify({ path: '' }));
      const size = (bytes: number) => ({ path: 'x'.repeat(bytes - overhead) });
      expect(Buffer.byteLength(JSON.stringify(size(16_384)))).toBe(16_384);
      const ok = await withArguments(size(16_384));
      expect(ok.ran).toHaveLength(1);
      const over = await withArguments(size(16_385));
      expect(over.ran).toEqual([]);
      expect(answer(over.history)).toEqual([BAD_ARGUMENTS]);
    });

    it('measures the size in bytes, not characters', async () => {
      // 6 000 three-byte characters: 18 000 bytes.
      const { ran } = await withArguments({ path: '€'.repeat(6_000) });
      expect(ran).toEqual([]);
    });
  });

  describe('the replay of a turn (the current Anthropic models)', () => {
    /** What an adapter keeps of a turn: opaque to the loop, which never reads it. */
    const replayOf = (label: string): ProviderReplay => ({
      kind: 'anthropic',
      items: [
        { type: 'thinking', thinking: '', signature: `sig-${label}` },
        { type: 'text', text: label },
      ],
    });
    const assistants = (conversation: LlmConversation) =>
      conversation.messages.filter((message) => message.role === 'assistant');

    it('puts the replay of a turn, unchanged, on the assistant message it adds, and sends it again on every later turn', async () => {
      const [one, two] = [replayOf('one'), replayOf('two')];
      const s = scripted(
        callTurn([call('c1')], { text: 'Reading.', replay: one }),
        callTurn([call('c2'), call('c3')], { replay: two }),
        turn('done'),
      );
      await runConversation(s.input);
      expect(assistants(s.seen[0]!)).toEqual([]);
      expect(assistants(s.seen[1]!)).toEqual([
        { role: 'assistant', text: 'Reading.', toolCalls: [call('c1')], replay: one },
      ]);
      expect(
        assistants(s.seen[2]!).map((message) => (message as { replay?: ProviderReplay }).replay),
      ).toEqual([one, two]);
      // The very value the provider gave: the loop reads nothing of it and changes nothing in it.
      expect((assistants(s.seen[2]!)[0] as { replay?: ProviderReplay }).replay).toBe(one);
      expect(JSON.stringify(one)).toBe(JSON.stringify(replayOf('one')));
    });

    it('never changes or reorders the messages before the new ones: the history only grows', async () => {
      const s = scripted(
        callTurn([call('c1')], { replay: replayOf('one') }),
        callTurn([call('c2'), call('c3')], { replay: replayOf('two') }),
        callTurn([call('c4')], { replay: replayOf('three') }),
        turn('done'),
      );
      // The history as each call was given it, written down at once: a later change of a message
      // that was sent would not reach these texts.
      const snapshots: string[] = [];
      const send = s.input.send;
      s.input.send = (conversation) => {
        snapshots.push(JSON.stringify(conversation.messages));
        return send(conversation);
      };
      await runConversation(s.input);
      expect(snapshots).toHaveLength(4);
      for (let n = 1; n < snapshots.length; n += 1) {
        // The earlier history as a list is the start of this one, up to its closing bracket.
        expect(snapshots[n]!.startsWith(snapshots[n - 1]!.slice(0, -1)), `call ${n}`).toBe(true);
        expect(snapshots[n]!.length).toBeGreaterThan(snapshots[n - 1]!.length);
      }
      expect(JSON.parse(snapshots[3]!)).toHaveLength(1 + 2 + 3 + 2);
    });

    it('keeps the replay of a cut-off answer, and of an answer the caller did not accept, on the answer it adds', async () => {
      const [cut, bad] = [replayOf('cut'), replayOf('bad')];
      const s = scripted(
        turn('{"findings":[{"ti', { finishReason: 'length', replay: cut }),
        turn('not json', { replay: bad }),
        turn('{"findings":[]}'),
      );
      s.input.accept = (text) => text.startsWith('{"findings":[]');
      await runConversation(s.input);
      expect(s.seen[1]!.messages[1]).toEqual({
        role: 'assistant',
        text: '{"findings":[{"ti',
        toolCalls: [],
        replay: cut,
      });
      expect(s.seen[2]!.messages[1]).toMatchObject({ replay: cut });
      expect(s.seen[2]!.messages[3]).toEqual({
        role: 'assistant',
        text: 'not json',
        toolCalls: [],
        replay: bad,
      });
    });

    it('adds a turn that was cut off while it had no text to the history with nothing: its replay goes with it', async () => {
      const s = scripted(
        turn('', { finishReason: 'length', replay: replayOf('half') }),
        turn('done'),
      );
      await runConversation(s.input);
      expect(s.seen[1]!.messages.map((message) => message.role)).toEqual(['user', 'user']);
      expect(JSON.stringify(s.seen[1])).not.toContain('sig-half');
    });

    it('sends a turn whose calls were not run as its text alone, without the replay that holds them', async () => {
      // The wrap-up answers with a call and words that are not the answer: the call is not run, so
      // its replay has a call with no result to send beside it.
      const s = scripted(
        callTurn([call('c1')], { replay: replayOf('one') }),
        callTurn([call('c2')], { text: 'Enough.', replay: replayOf('late') }),
        turn('{"findings":[]}'),
      );
      s.input.limits = { ...LIMITS, maxTurns: 1 };
      s.input.accept = (text) => text.startsWith('{');
      await runConversation(s.input);
      const history = s.seen[2]!.messages;
      expect(history.at(-2)).toEqual({ role: 'assistant', text: 'Enough.', toolCalls: [] });
      expect(history.at(-2)).not.toHaveProperty('replay');
      expect(JSON.stringify(history)).not.toContain('sig-late');
      // The turn before it keeps its replay.
      expect(history[1]).toMatchObject({ role: 'assistant', replay: replayOf('one') });
    });

    it('adds no replay to a message when its turn has none, whatever the turn was', async () => {
      const s = scripted(
        callTurn([call('c1')]),
        turn('{"findings":[{"ti', { finishReason: 'length' }),
        turn('not json'),
        turn('{"findings":[]}'),
      );
      s.input.accept = (text) => text.startsWith('{"findings":[]');
      await runConversation(s.input);
      for (const message of s.seen[3]!.messages) expect(message).not.toHaveProperty('replay');
    });

    it('counts the replay with what was sent when the input of a call is guessed', async () => {
      const unknown = { inputTokens: null, outputTokens: null };
      const big: ProviderReplay = {
        kind: 'anthropic',
        items: [{ type: 'thinking', thinking: '', signature: 'x'.repeat(4_000) }],
      };
      const run = async (replay?: ProviderReplay) => {
        const s = scripted(
          callTurn([call('c1')], { usage: unknown, ...(replay ? { replay } : {}) }),
          turn('done', { usage: unknown }),
        );
        return { result: await runConversation(s.input), seen: s.seen };
      };
      const without = await run();
      const withReplay = await run(big);
      // A quarter of the bytes of the JSON, the replay's 4 000 and more among them.
      expect(withReplay.result.inputTokens - without.result.inputTokens).toBeGreaterThanOrEqual(
        1_000,
      );
      expect(withReplay.result.inputTokens).toBe(
        quarterOfBytes(withReplay.seen[0]!) + quarterOfBytes(withReplay.seen[1]!),
      );
    });
  });

  describe('the calls of one turn', () => {
    it('counts the calls past the cap whatever their arguments', async () => {
      const calls = [
        call('c1'),
        call('c2', 'raw'),
        call('c3'),
        // Past the cap of 2: answered as too many, also when the arguments are bad.
        call('c4'),
        call('c5', 'raw'),
      ];
      const s = scripted(callTurn(calls), turn('done'));
      s.input.limits = { ...LIMITS, maxCallsPerTurn: 2 };
      await runConversation(s.input);
      expect(s.ran.map((c) => c.id)).toEqual(['c1']);
      const answers = s.seen[1]!.messages.flatMap((m) =>
        m.role === 'tool' ? [[m.callId, unwrap(m.text).result]] : [],
      );
      expect(answers).toEqual([
        ['c1', 'ok'],
        ['c2', BAD_ARGUMENTS],
        ['c3', TOO_MANY],
        ['c4', TOO_MANY],
        ['c5', TOO_MANY],
      ]);
    });

    it('runs the calls one after the other, in order', async () => {
      const order: string[] = [];
      const s = scripted(callTurn([call('c1'), call('c2')]), turn('done'));
      s.input.runTool = async (c) => {
        order.push(`start ${c.id}`);
        await new Promise((resolve) => setTimeout(resolve, 5));
        order.push(`end ${c.id}`);
        return 'ok';
      };
      await runConversation(s.input);
      expect(order).toEqual(['start c1', 'end c1', 'start c2', 'end c2']);
    });

    it('does not fail on an id used again in a later turn', async () => {
      const s = scripted(callTurn([call('c1')]), callTurn([call('c1')]), turn('done'));
      expect(await runConversation(s.input)).toMatchObject({ kind: 'answer', toolCalls: 2 });
    });

    it('keeps the text a model says beside its calls', async () => {
      const s = scripted(callTurn([call('c1')], { text: 'Looking at the file.' }), turn('done'));
      await runConversation(s.input);
      expect(s.seen[1]!.messages[1]).toEqual({
        role: 'assistant',
        text: 'Looking at the file.',
        toolCalls: [call('c1')],
      });
    });

    it('gives the history to each turn as it was then', async () => {
      const s = scripted(callTurn([call('c1')]), turn('done'));
      await runConversation(s.input);
      expect(s.seen[0]!.messages).toEqual([{ role: 'user', text: USER_TEXT }]);
      expect(s.seen[1]!.messages).toHaveLength(3);
    });

    it('wraps the loop’s own tool messages in the data envelope, under the name of the tool', async () => {
      const s = scripted(callTurn([call('c1', 'raw', 'grep')]), turn('done'));
      await runConversation(s.input);
      const message = s.seen[1]!.messages[2]!;
      expect(message).toMatchObject({ role: 'tool', callId: 'c1', name: 'grep' });
      expect(unwrap((message as { text: string }).text)).toEqual({
        tool: 'grep',
        result: BAD_ARGUMENTS,
      });
    });
  });

  describe('turns, tokens and the wrap-up', () => {
    it('wraps up after maxTurns turns of tools, never sooner', async () => {
      const s = scripted(
        callTurn([call('c1')]),
        callTurn([call('c2')]),
        callTurn([call('c3')]),
        turn('done'),
      );
      s.input.limits = { ...LIMITS, maxTurns: 3 };
      const result = await runConversation(s.input);
      expect(result).toMatchObject({ kind: 'answer', turns: 4, wrappedUp: 'turns' });
      const lastUser = (n: number) => s.seen[n]!.messages.findLast((m) => m.role === 'user');
      expect(lastUser(2)).toEqual({ role: 'user', text: USER_TEXT });
      expect(lastUser(3)).toEqual({ role: 'user', text: WRAP_UP });
    });

    it('wraps up exactly when what was used, the next turn and the wrap-up after it reach the budget', async () => {
      // One turn of tools that was sent 100 tokens and wrote 20, then the answer.
      const play = async (tokenBudget: number) => {
        const s = scripted(
          callTurn([call('c1')], { usage: { inputTokens: 100, outputTokens: 20 } }),
          turn('done'),
        );
        s.input.limits = { ...LIMITS, tokenBudget, maxOutputTokens: 30 };
        return { s, result: await runConversation(s.input) };
      };
      const { s } = await play(1_000_000);
      // What the tool answered, as the next call sends it, at a quarter of its bytes.
      const grown = quarterOfBytes(s.seen[1]!.messages.slice(2));
      // The next turn sends the 100 and the 20 again with what the tool answered, and writes 20;
      // the wrap-up after it sends all that again with 20 and as much from its tools, and may
      // write 30.
      const next = 100 + 20 + grown + 20;
      const wrapUpAfter = 100 + 20 + grown + 20 + grown + 30;
      const due = 100 + 20 + next + wrapUpAfter;
      expect((await play(due)).result).toMatchObject({ kind: 'answer', wrappedUp: 'budget' });
      expect((await play(due + 1)).result).toMatchObject({ kind: 'answer', wrappedUp: null });
    });

    it('sends the tools and the output limit on the wrap-up turn too', async () => {
      const s = scripted(callTurn([call('c1')]), turn('done'));
      s.input.limits = { ...LIMITS, maxTurns: 1 };
      await runConversation(s.input);
      for (const conversation of s.seen) {
        expect(conversation.tools).toEqual(TOOLS);
        expect(conversation.maxOutputTokens).toBe(50);
      }
      expect(s.seen).toHaveLength(2);
    });

    describe('a provider that does not count tokens', () => {
      const unknown = { inputTokens: null, outputTokens: null };

      it('is charged a quarter of the bytes it was sent and the longest answer it may write, and the result says so', async () => {
        const s = scripted(
          callTurn([call('c1')], { usage: unknown }),
          turn('done', { usage: unknown }),
        );
        const result = await runConversation(s.input);
        expect(result).toEqual({
          kind: 'answer',
          text: 'done',
          inputTokens: quarterOfBytes(s.seen[0]!) + quarterOfBytes(s.seen[1]!),
          outputTokens: 2 * LIMITS.maxOutputTokens,
          cacheReadTokens: 0,
          cacheWriteTokens: 0,
          turns: 2,
          toolCalls: 1,
          wrappedUp: null,
        });
      });

      it('is charged for the bytes of the JSON it was sent, not for its characters', async () => {
        const s = scripted(turn('done', { usage: unknown }));
        // Characters of two, three and four bytes.
        s.input.user = 'é€😀'.repeat(100);
        const result = await runConversation(s.input);
        const json = JSON.stringify(s.seen[0]);
        expect(Buffer.byteLength(json, 'utf8')).toBeGreaterThan(json.length);
        expect(result.inputTokens).toBe(Math.ceil(Buffer.byteLength(json, 'utf8') / 4));
      });

      it('is charged the answer cap for the output it did not count, whatever room it was given to think', async () => {
        const s = scripted(turn('done', { usage: unknown }));
        s.input.limits = { ...LIMITS, reasoningAllowance: 16_000 };
        const result = await runConversation(s.input);
        // The call carries the cap and the room apart; the guess is the cap alone.
        expect(s.seen[0]).toMatchObject({
          maxOutputTokens: LIMITS.maxOutputTokens,
          reasoningAllowance: 16_000,
        });
        expect(result.outputTokens).toBe(LIMITS.maxOutputTokens);
      });

      it('is charged only for the count it did not give', async () => {
        const s = scripted(
          callTurn([call('c1')], { usage: { inputTokens: 7, outputTokens: null } }),
          turn('done', { usage: { inputTokens: null, outputTokens: 9 } }),
        );
        const result = await runConversation(s.input);
        expect(result).toMatchObject({
          inputTokens: 7 + quarterOfBytes(s.seen[1]!),
          outputTokens: LIMITS.maxOutputTokens + 9,
        });
      });

      it('is asked to answer once its guessed tokens reach the budget', async () => {
        // Always calls, never counts; 400 tokens are charged for each answer.
        const steps = Array.from({ length: 20 }, (_, i) =>
          callTurn([call(`c${i}`)], { usage: unknown }),
        );
        const s = scripted(...steps);
        s.input.limits = { ...LIMITS, tokenBudget: 8_000, maxOutputTokens: 400 };
        const result = await runConversation(s.input);
        expect(result).toMatchObject({ kind: 'failed', reason: 'bad_answer' });
        // Not the 17 requests of the turn limit: the guess ends the calls far sooner.
        expect(s.seen.length).toBeLessThan(CONVERSATION_LIMITS.maxTurns + 1);
        expect(s.ran.length).toBeGreaterThan(1);
        expect(s.seen.at(-1)!.messages.at(-1)).toEqual({ role: 'user', text: WRAP_UP });
        expect(result.inputTokens).toBe(
          s.seen.reduce((sum, conversation) => sum + quarterOfBytes(conversation), 0),
        );
        expect(result.outputTokens).toBe(s.seen.length * 400);
      });

      it('serialises the conversation only for a call whose input it has to estimate', async () => {
        const stringify = vi.spyOn(JSON, 'stringify');
        const serialisedConversations = () => conversationsSerialised(stringify);
        try {
          await runConversation(scripted(callTurn([call('c1')]), turn('done')).input);
          expect(serialisedConversations()).toBe(0);

          stringify.mockClear();
          await runConversation(
            scripted(
              callTurn([call('c1')], { usage: { inputTokens: null, outputTokens: 5 } }),
              turn('done'),
            ).input,
          );
          expect(serialisedConversations()).toBe(1);

          stringify.mockClear();
          await runConversation(
            scripted(
              callTurn([call('c1')], { usage: { inputTokens: 5, outputTokens: null } }),
              turn('done'),
            ).input,
          );
          expect(serialisedConversations()).toBe(0);
        } finally {
          stringify.mockRestore();
        }
      });
    });

    it('asks for a shorter answer once, also after a wrap-up', async () => {
      const s = scripted(
        callTurn([call('c1')]),
        turn('{"findings":[{"ti', { finishReason: 'length' }),
        turn('{"findings":[]}'),
      );
      s.input.limits = { ...LIMITS, maxTurns: 1 };
      const result = await runConversation(s.input);
      expect(result).toMatchObject({
        kind: 'answer',
        text: '{"findings":[]}',
        wrappedUp: 'turns',
      });
      const last = s.seen[2]!.messages;
      expect(last.at(-1)).toMatchObject({ role: 'user' });
      expect((last.at(-1) as { text: string }).text).toMatch(/shorter/);
      expect(last.at(-2)).toEqual({
        role: 'assistant',
        text: '{"findings":[{"ti',
        toolCalls: [],
      });
    });

    it('does not echo a cut-off answer that has no text', async () => {
      const s = scripted(turn('', { finishReason: 'length' }), turn('done'));
      await runConversation(s.input);
      const messages = s.seen[1]!.messages;
      expect(messages.map((m) => m.role)).toEqual(['user', 'user']);
    });

    it('answers a cut-off call as bad arguments, and goes on', async () => {
      // The provider says `tool` when there are calls, so a cut-off call is a call with raw arguments.
      const s = scripted(
        callTurn([call('c1', '{"path": "a.t')], { text: 'Reading' }),
        turn('done'),
      );
      const result = await runConversation(s.input);
      expect(result).toMatchObject({ kind: 'answer', toolCalls: 0, turns: 2 });
    });
  });

  describe('what a conversation reports, whatever its end', () => {
    // Two turns of 10 + 5 tokens, and three calls run.
    const spent = {
      inputTokens: 20,
      outputTokens: 10,
      cacheReadTokens: 0,
      cacheWriteTokens: 0,
      turns: 2,
      toolCalls: 3,
    };
    const twoTurns = () => [callTurn([call('c1')]), callTurn([call('c2'), call('c3')])];

    it('counts the cache reads and writes of its calls beside the input, which holds them (R49)', async () => {
      const cached = (read: number, written?: number) => ({
        inputTokens: 1_000,
        outputTokens: 10,
        cacheReadTokens: read,
        ...(written === undefined ? {} : { cacheWriteTokens: written }),
      });
      const s = scripted(
        callTurn([call('c1')], { usage: cached(0, 900) }),
        callTurn([call('c2')], { usage: cached(900, 80) }),
        turn('{"done":true}', { usage: { inputTokens: 1_200, outputTokens: 5 } }),
      );
      expect(await runConversation(s.input)).toMatchObject({
        kind: 'answer',
        inputTokens: 3_200,
        outputTokens: 25,
        cacheReadTokens: 900,
        cacheWriteTokens: 980,
      });
      // And so does an end without an answer.
      const stopped = scripted(callTurn([call('c1')], { usage: cached(400, 100) }), turn('never'));
      let asked = 0;
      stopped.input.shouldStop = () => Promise.resolve(++asked > 1);
      expect(await runConversation(stopped.input)).toEqual({
        kind: 'stopped',
        inputTokens: 1_000,
        outputTokens: 10,
        cacheReadTokens: 400,
        cacheWriteTokens: 100,
        turns: 1,
        toolCalls: 1,
      });
    });

    it('a failure carries what was spent before it', async () => {
      const s = scripted(...twoTurns(), new LlmError('rejected', 'refused', { status: 400 }));
      expect(await runConversation(s.input)).toEqual({
        kind: 'failed',
        reason: 'provider_error',
        ...spent,
      });
    });

    it('a bad answer carries the turn that was one', async () => {
      const s = scripted(callTurn([call('c1')]), turn('  '));
      expect(await runConversation(s.input)).toEqual({
        kind: 'failed',
        reason: 'bad_answer',
        inputTokens: 20,
        outputTokens: 10,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        turns: 2,
        toolCalls: 1,
      });
    });

    it('a call id used twice carries the tokens of its turn and runs none of its calls', async () => {
      const s = scripted(callTurn([call('c1')]), callTurn([call('c2'), call('c2')]));
      expect(await runConversation(s.input)).toEqual({
        kind: 'failed',
        reason: 'bad_answer',
        inputTokens: 20,
        outputTokens: 10,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        turns: 2,
        toolCalls: 1,
      });
    });

    it('a stop carries what was spent before it', async () => {
      const s = scripted(...twoTurns(), turn('never asked'));
      let asked = 0;
      // Not stopped before the first call and the second, stopped before the third.
      s.input.shouldStop = () => Promise.resolve(++asked > 2);
      expect(await runConversation(s.input)).toEqual({ kind: 'stopped', ...spent });
    });

    it('an open circuit carries what was spent before it, and says it was the circuit', async () => {
      const s = scripted(...twoTurns(), new CircuitOpenError());
      expect(await runConversation(s.input)).toEqual({
        kind: 'failed',
        reason: 'provider_error',
        circuitOpen: true,
        ...spent,
      });
    });

    it('a stop before the first call, and a first call refused for its tools, carry nothing', async () => {
      const none = {
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        turns: 0,
        toolCalls: 0,
      };
      const stopped = scripted(turn('never asked'));
      stopped.input.shouldStop = () => Promise.resolve(true);
      expect(await runConversation(stopped.input)).toEqual({ kind: 'stopped', ...none });

      const refused = scripted(
        new LlmError('rejected', 'refused', { status: 400, refusedTools: true }),
      );
      expect(await runConversation(refused.input)).toEqual({
        kind: 'failed',
        reason: 'provider_no_tools',
        ...none,
      });
    });

    it('a failure after turns the provider did not count carries the guessed tokens, and the input of the call that timed out', async () => {
      const unknown = { inputTokens: null, outputTokens: null };
      const s = scripted(
        callTurn([call('c1')], { usage: unknown }),
        new LlmError('timeout', 'The model did not answer within 60 s'),
        new LlmError('unavailable', 'The model provider could not be reached'),
        new LlmError('unavailable', 'The model provider could not be reached'),
      );
      const result = await runConversation(s.input);
      expect(result).toMatchObject({ kind: 'failed', reason: 'provider_error', turns: 1 });
      // The output of a call that was not answered is not known and is not charged.
      expect(result.outputTokens).toBe(LIMITS.maxOutputTokens);
      // The call that timed out was sent, and most likely billed for its input; the one that could
      // not be reached cost nothing.
      expect(result.inputTokens).toBe(quarterOfBytes(s.seen[0]!) + quarterOfBytes(s.seen[1]!));
    });
  });

  describe('the input of a call that was not answered', () => {
    const timeout = new LlmError('timeout', 'The model did not answer within 60 s');
    const unreadable = new LlmError('bad_answer', 'The answer of the provider was not understood', {
      status: 200,
    });

    it('is charged for a call that timed out, and again for each retry that timed out', async () => {
      const s = scripted(timeout, timeout, timeout);
      // Characters of two, three and four bytes: the guess is made from the bytes.
      s.input.user = 'é€😀'.repeat(100);
      expect(await runConversation(s.input)).toEqual({
        kind: 'failed',
        reason: 'provider_error',
        inputTokens: [0, 1, 2].reduce((n, i) => n + quarterOfBytes(s.seen[i]!), 0),
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        turns: 0,
        toolCalls: 0,
      });
    });

    it('is charged for a call that timed out, beside what its retry counted', async () => {
      const s = scripted(timeout, turn('done'));
      expect(await runConversation(s.input)).toEqual({
        kind: 'answer',
        text: 'done',
        wrappedUp: null,
        inputTokens: quarterOfBytes(s.seen[0]!) + 10,
        outputTokens: 5,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        turns: 1,
        toolCalls: 0,
      });
    });

    it('is charged for a call that timed out when the conversation is stopped after it', async () => {
      const s = scripted(timeout, turn('never asked'));
      let asked = 0;
      s.input.shouldStop = () => Promise.resolve(++asked > 1);
      expect(await runConversation(s.input)).toEqual({
        kind: 'stopped',
        inputTokens: quarterOfBytes(s.seen[0]!),
        outputTokens: 0,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        turns: 0,
        toolCalls: 0,
      });
    });

    it('is charged for an answer that could not be read, which ends the conversation', async () => {
      const s = scripted(callTurn([call('c1')]), unreadable, turn('never asked'));
      expect(await runConversation(s.input)).toEqual({
        kind: 'failed',
        reason: 'provider_error',
        inputTokens: 10 + quarterOfBytes(s.seen[1]!),
        outputTokens: 5,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        turns: 1,
        toolCalls: 1,
      });
      expect(s.seen).toHaveLength(2);
    });

    it.each([
      [
        'an unreachable provider',
        new LlmError('unavailable', 'The model provider could not be reached'),
      ],
      [
        'a rate limit',
        new LlmError('rate_limited', 'limited', { status: 429, retryAfterSeconds: 1 }),
      ],
      ['a refusal of the key', new LlmError('refused_key', 'refused', { status: 401 })],
      ['a refusal of the request', new LlmError('rejected', 'refused', { status: 400 })],
      ['an address that is not allowed', new LlmError('url_not_allowed', 'not allowed')],
    ])('is not charged for %s', async (_name, error) => {
      // A rate limit is tried twice more and an unreachable provider once; the rest end it at once.
      const s = scripted(error, error, error);
      expect(await runConversation(s.input)).toMatchObject({
        kind: 'failed',
        inputTokens: 0,
        outputTokens: 0,
      });
    });

    it('counts toward the budget, so that the wrap-up comes when the calls that failed made it due', async () => {
      const play = (tokenBudget: number) => {
        // A call with a tool, a call that times out, its retry with another tool, and the answer.
        const s = scripted(callTurn([call('c1')]), timeout, callTurn([call('c2')]), turn('done'));
        // A long first message, so that the call that timed out is charged much more than the
        // turns the provider counted, and than another turn with the wrap-up after it.
        s.input.user = 'x'.repeat(8_000);
        s.input.limits = { ...LIMITS, tokenBudget };
        return { s, result: runConversation(s.input) };
      };
      // What the call that timed out is charged: the rest of the input is that of the three turns.
      const guessed = (await play(1_000_000).result).inputTokens - 30;
      expect(guessed).toBeGreaterThan(2_000);
      // The two turns of tools used 30 tokens, and another turn with the wrap-up after it would
      // take a few hundred more: well short of this budget. With the call that timed out they used
      // 30 and its guess, nearly all of it.
      const { s, result } = play(40 + guessed);
      expect(await result).toMatchObject({ kind: 'answer', wrappedUp: 'budget' });
      expect(s.seen.at(-1)!.messages.at(-1)).toEqual({ role: 'user', text: WRAP_UP });
    });

    it('serialises the conversation for a call that timed out or was unreadable, and for no other failure', async () => {
      const stringify = vi.spyOn(JSON, 'stringify');
      const serialisedConversations = () => conversationsSerialised(stringify);
      const unavailable = new LlmError('unavailable', 'The model provider could not be reached');
      try {
        await runConversation(scripted(timeout, turn('done')).input);
        expect(serialisedConversations()).toBe(1);

        stringify.mockClear();
        await runConversation(scripted(unreadable).input);
        expect(serialisedConversations()).toBe(1);

        stringify.mockClear();
        await runConversation(scripted(unavailable, turn('done')).input);
        expect(serialisedConversations()).toBe(0);
      } finally {
        stringify.mockRestore();
      }
    });
  });

  describe('failures', () => {
    it('an open circuit fails at once, with no retry, and says it was the circuit', async () => {
      const s = scripted(new CircuitOpenError());
      expect(await runConversation(s.input)).toMatchObject({
        kind: 'failed',
        reason: 'provider_error',
        circuitOpen: true,
      });
      expect(s.seen).toHaveLength(1);
      expect(s.sleeps).toEqual([]);
      // A provider that failed is no circuit.
      const failing = scripted(new LlmError('rejected', 'refused', { status: 400 }));
      expect(await runConversation(failing.input)).not.toHaveProperty('circuitOpen');
    });

    it('timeouts and unavailable providers share two retries', async () => {
      const timeout = new LlmError('timeout', 'The model did not answer within 60 s');
      const unavailable = new LlmError('unavailable', 'The model provider could not be reached');
      const both = scripted(timeout, unavailable, timeout, turn('done'));
      expect(await runConversation(both.input)).toMatchObject({
        kind: 'failed',
        reason: 'provider_error',
      });
      expect(both.sleeps).toEqual([5_000, 30_000]);
      expect(both.seen).toHaveLength(3);

      const once = scripted(timeout, turn('done'));
      expect(await runConversation(once.input)).toMatchObject({ kind: 'answer' });
      expect(once.sleeps).toEqual([5_000]);
    });

    it.each([
      [12, 12_000],
      [600, 60_000],
    ])(
      'an unavailable provider is retried after its Retry-After of %i s',
      async (asked, waited) => {
        const unavailable = new LlmError('unavailable', 'busy', {
          status: 503,
          retryAfterSeconds: asked,
        });
        const s = scripted(unavailable, unavailable, turn('done'));
        expect(await runConversation(s.input)).toMatchObject({ kind: 'answer' });
        expect(s.sleeps).toEqual([waited, waited]);
      },
    );

    it('a key that is not scoped to a workspace is not retried, and fails the conversation as a provider error', async () => {
      const s = scripted(
        new LlmError('workspace_required', 'not scoped', { status: 400 }),
        turn('done'),
      );
      expect(await runConversation(s.input)).toMatchObject({
        kind: 'failed',
        reason: 'provider_error',
        turns: 0,
      });
      expect(s.seen).toHaveLength(1);
      expect(s.sleeps).toEqual([]);
    });

    it('rate limits and timeouts have a retry each, in the same call', async () => {
      const limited = new LlmError('rate_limited', 'limited', {
        status: 429,
        retryAfterSeconds: 2,
      });
      const timeout = new LlmError('timeout', 'The model did not answer within 60 s');
      const s = scripted(limited, timeout, limited, turn('done'));
      expect(await runConversation(s.input)).toMatchObject({ kind: 'answer' });
      expect(s.sleeps).toEqual([2_000, 5_000, 2_000]);
    });

    it('gives each call its own retries', async () => {
      const unavailable = new LlmError('unavailable', 'The model provider could not be reached');
      const s = scripted(unavailable, callTurn([call('c1')]), unavailable, turn('done'));
      expect(await runConversation(s.input)).toMatchObject({ kind: 'answer', turns: 2 });
      expect(s.sleeps).toEqual([5_000, 5_000]);
    });

    it('answers provider_no_tools only for a refusal of 400, 404 or 422 that names tools', async () => {
      const refused = (status: number, names: boolean) =>
        new LlmError('rejected', 'The provider refused the request', {
          status,
          refusedTools: names,
        });
      const reasonFor = async (error: LlmError, tools = TOOLS) => {
        const s = scripted(error);
        return runConversation({ ...s.input, tools });
      };
      expect(await reasonFor(refused(400, true))).toMatchObject({
        kind: 'failed',
        reason: 'provider_no_tools',
      });
      expect(await reasonFor(refused(413, true))).toMatchObject({
        kind: 'failed',
        reason: 'provider_error',
      });
      expect(await reasonFor(refused(400, false))).toMatchObject({
        kind: 'failed',
        reason: 'provider_error',
      });
      // A conversation that sent no tools cannot have been refused for them.
      expect(await reasonFor(refused(400, true), [])).toMatchObject({
        kind: 'failed',
        reason: 'provider_error',
      });
      // Only a refusal: a bad answer that happens to say so is not one.
      const badAnswer = new LlmError('bad_answer', 'x', { status: 400, refusedTools: true });
      expect(await reasonFor(badAnswer)).toMatchObject({
        kind: 'failed',
        reason: 'provider_error',
      });
    });

    it('stops at a call its caller gave up, which is not tried again or charged', async () => {
      const s = scripted(callTurn([call('c1')]), new LlmCallAborted(), turn('never asked'));
      // The server stopped while the provider was answering the second call.
      expect(await runConversation(s.input)).toEqual({
        kind: 'stopped',
        inputTokens: 10,
        outputTokens: 5,
        cacheReadTokens: 0,
        cacheWriteTokens: 0,
        turns: 1,
        toolCalls: 1,
      });
      expect(s.seen).toHaveLength(2);
      expect(s.sleeps).toEqual([]);
    });

    it('lets an error that is not the provider’s end the conversation', async () => {
      const broken = new RangeError('Maximum call stack size exceeded');
      await expect(runConversation(scripted(broken).input)).rejects.toBe(broken);
    });

    it('lets a tool that throws end the conversation', async () => {
      const s = scripted(callTurn([call('c1')]), turn('done'));
      const aborted = new Error('the masker was closed');
      s.input.runTool = () => Promise.reject(aborted);
      await expect(runConversation(s.input)).rejects.toBe(aborted);
      expect(s.seen).toHaveLength(1);
    });

    it('lets a stop check that throws end the conversation', async () => {
      const s = scripted(turn('done'));
      const down = new Error('the database is down');
      s.input.shouldStop = () => Promise.reject(down);
      await expect(runConversation(s.input)).rejects.toBe(down);
      expect(s.seen).toHaveLength(0);
    });
  });

  describe("a script that overruns the review's time (limits.deadline)", () => {
    const DEADLINE = 60_000;
    /**
     * `steps` played with a deadline, on a clock that moves only by what the script says: each tool
     * that runs takes `toolMs`, and a `{ ms }` step is the time the call after it takes.
     */
    function overrunning(toolMs: number, ...steps: (LlmTurn | Error | { ms: number })[]) {
      let at = 0;
      const plays: (LlmTurn | Error)[] = [];
      const callMs: number[] = [];
      let taking = 0;
      for (const step of steps) {
        if ('ms' in step) {
          taking += step.ms;
          continue;
        }
        plays.push(step);
        callMs.push(taking);
        taking = 0;
      }
      const s = scripted(...plays);
      const { send, runTool } = s.input;
      s.input.send = (conversation) => {
        at += callMs[s.seen.length] ?? 0;
        return send(conversation);
      };
      s.input.runTool = (c) => {
        at += toolMs;
        return runTool(c);
      };
      s.input.limits = { ...LIMITS, deadline: DEADLINE };
      s.input.now = () => at;
      return s;
    }

    it('makes the call after a turn of tools that went past the deadline the wrap-up, for the time: its calls are not run', async () => {
      const s = overrunning(
        DEADLINE,
        callTurn([call('c1')]),
        turn('done', { finishReason: 'tool', toolCalls: [call('c2')] }),
      );
      expect(await runConversation(s.input)).toMatchObject({
        kind: 'answer',
        text: 'done',
        wrappedUp: 'time',
        turns: 2,
        toolCalls: 1,
      });
      expect(s.ran.map((c) => c.id)).toEqual(['c1']);
      expect(s.seen[1]!.messages.at(-1)).toEqual({ role: 'user', text: WRAP_UP });
    });

    it('lets a call that is in flight when the deadline passes answer: it is not cut', async () => {
      const s = overrunning(0, { ms: DEADLINE * 2 }, turn('done'));
      expect(await runConversation(s.input)).toMatchObject({
        kind: 'answer',
        text: 'done',
        wrappedUp: null,
        turns: 1,
      });
    });

    it('makes no call after the last one: an answer cut off then is not asked for again', async () => {
      const s = overrunning(
        DEADLINE,
        callTurn([call('c1')]),
        turn('{"findings":', { finishReason: 'length' }),
        turn('never asked'),
      );
      expect(await runConversation(s.input)).toMatchObject({
        kind: 'failed',
        reason: 'provider_error',
        timeLimit: true,
        turns: 2,
        toolCalls: 1,
      });
      expect(s.seen).toHaveLength(2);
    });

    it('tries the last call once: a timeout is charged and not tried again', async () => {
      const s = overrunning(
        DEADLINE,
        callTurn([call('c1')]),
        new LlmError('timeout', 'The model did not answer within 60 s'),
        turn('never asked'),
      );
      const result = await runConversation(s.input);
      expect(result).toMatchObject({
        kind: 'failed',
        reason: 'provider_error',
        timeLimit: true,
        turns: 1,
      });
      // The first call's 10, and the guess for the input of the one that timed out.
      expect(result.inputTokens).toBe(10 + quarterOfBytes(s.seen[1]!));
      expect(s.sleeps).toEqual([]);
      expect(s.seen).toHaveLength(2);
    });

    it('asks an answer cut off before the deadline for again past it once, with no tools and no words of the wrap-up', async () => {
      // The clock passes the deadline while the cut answer is written; it is asked for again.
      const s = overrunning(
        0,
        callTurn([call('c1')]),
        { ms: DEADLINE },
        turn('{"findings":', { finishReason: 'length' }),
        turn('done', { finishReason: 'tool', toolCalls: [call('c2')] }),
      );
      expect(await runConversation(s.input)).toMatchObject({
        kind: 'answer',
        text: 'done',
        wrappedUp: 'time',
        turns: 3,
      });
      expect(s.ran.map((c) => c.id)).toEqual(['c1']);
      expect(s.seen[2]!.messages.at(-1)).toEqual({ role: 'user', text: SHORTER });
    });

    it('keeps the reason of a wrap-up that was due already', async () => {
      const s = overrunning(DEADLINE, callTurn([call('c1')]), turn('done'));
      s.input.limits = { ...LIMITS, maxTurns: 1, deadline: DEADLINE };
      expect(await runConversation(s.input)).toMatchObject({
        kind: 'answer',
        wrappedUp: 'turns',
        turns: 2,
      });
      expect(s.seen[1]!.messages.filter((m) => m.role === 'user')).toHaveLength(2);
    });
  });
});

describe('CONVERSATION_LIMITS', () => {
  it('holds the values of the contract', () => {
    expect(CONVERSATION_LIMITS).toEqual({
      maxTurns: 16,
      maxCallsPerTurn: 8,
      wrapUpAt: 0.85,
      maxArgumentBytes: 16_384,
      maxArgumentDepth: 20,
    });
  });
});
