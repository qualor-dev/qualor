import { describe, expect, it } from 'vitest';
import {
  MAX_ANSWER_CHARS,
  MAX_THINK_CHARS,
  parseAnswer,
  parseModelJson,
  safeMultilineText,
} from './output';

const stop = (text: string) => ({ text, finishReason: 'stop' as const });
const explain = {
  summary: 'Loose equality.',
  explanation: 'Use ===.',
  howToFix: 'Replace == with ===.',
};

describe('parseModelJson (llm.md §9.3)', () => {
  it('accepts one object, bare or in one fence', () => {
    expect(parseModelJson('{"a":1}')).toEqual({ a: 1 });
    expect(parseModelJson('  {"a":1}\n')).toEqual({ a: 1 });
    expect(parseModelJson('```json\n{"a":1}\n```')).toEqual({ a: 1 });
    expect(parseModelJson('```\n{"a":1}\n```')).toEqual({ a: 1 });
  });

  it.each([
    'Sure! {"a":1}',
    '{"a":1} Hope this helps.',
    '{"a":1}{"b":2}',
    '[{"a":1}]',
    '{"a":',
    'Here:\n```json\n{"a":1}\n```',
    '```json\n{"a":1}\n```\n```json\n{"b":2}\n```',
    'null',
  ])('refuses %j', (text) => {
    expect(parseModelJson(text)).toBeUndefined();
  });

  it('accepts the fence tag json in any case', () => {
    expect(parseModelJson('```JSON\n{"a":1}\n```')).toEqual({ a: 1 });
    expect(parseModelJson('```Json\n{"a":1}\n```')).toEqual({ a: 1 });
  });

  it("skips one leading <think> block of a local reasoning model's answer", () => {
    expect(parseModelJson('<think>hmm\n{"x":2}</think>\n{"a":1}')).toEqual({ a: 1 });
    expect(parseModelJson('  <think></think>```json\n{"a":1}\n```')).toEqual({ a: 1 });
    const atCap = `<think>${'x'.repeat(MAX_THINK_CHARS)}</think>{"a":1}`;
    expect(parseModelJson(atCap)).toEqual({ a: 1 });
  });

  it.each([
    ['two think blocks', '<think>a</think><think>b</think>{"a":1}'],
    ['a think block after the object', '{"a":1}<think>a</think>'],
    ['an unclosed think block', '<think>{"a":1}'],
    ['prose before the think block', 'Sure <think>a</think>{"a":1}'],
    ['a think block over its cap', `<think>${'x'.repeat(MAX_THINK_CHARS + 1)}</think>{"a":1}`],
  ])('refuses %s', (_name, text) => {
    expect(parseModelJson(text)).toBeUndefined();
  });

  it('refuses an answer over the size cap without parsing it', () => {
    const big = JSON.stringify({ a: 'x'.repeat(MAX_ANSWER_CHARS) });
    expect(parseModelJson(big)).toBeUndefined();
    expect(parseAnswer('explain', { text: big, finishReason: 'stop' })).toEqual({
      ok: false,
      code: 'MALFORMED_OUTPUT',
    });
  });
});

describe('parseAnswer', () => {
  it('validates the explain schema strictly and cleans the text', () => {
    const ok = parseAnswer(
      'explain',
      stop(JSON.stringify({ ...explain, explanation: 'a\u202Eb\u200Bc\r\nd' })),
    );
    expect(ok).toEqual({
      ok: true,
      value: { kind: 'explain', ...explain, explanation: 'a bc\nd' },
    });
    expect(parseAnswer('explain', stop(JSON.stringify({ ...explain, extra: 1 })))).toEqual({
      ok: false,
      code: 'MALFORMED_OUTPUT',
    });
  });

  it('maps finish reasons', () => {
    const text = JSON.stringify(explain);
    expect(parseAnswer('explain', { text, finishReason: 'length' })).toEqual({
      ok: false,
      code: 'OUTPUT_TRUNCATED',
    });
    expect(parseAnswer('explain', { text, finishReason: 'refusal' })).toEqual({
      ok: false,
      code: 'MODEL_REFUSED',
    });
    expect(parseAnswer('explain', { text, finishReason: 'tool' })).toEqual({
      ok: false,
      code: 'MALFORMED_OUTPUT',
    });
  });

  it('reads a triage verdict and refuses an unknown one', () => {
    const triage = { verdict: 'uncertain', confidence: 'low', reasons: ['Not enough code.'] };
    expect(parseAnswer('triage', stop(JSON.stringify(triage)))).toEqual({
      ok: true,
      value: { kind: 'triage', ...triage },
    });
    expect(
      parseAnswer('triage', stop(JSON.stringify({ ...triage, verdict: 'false_positive' }))).ok,
    ).toBe(false);
    expect(parseAnswer('triage', stop(JSON.stringify({ ...triage, reasons: [] }))).ok).toBe(false);
  });

  it('returns a fix answer as given (checked later) with its explanation cleaned', () => {
    const fix = {
      status: 'fixed',
      startLine: 2,
      endLine: 2,
      replacement: ['if (a === 1) {}'],
      explanation: 'Strict.\u0007',
    };
    expect(parseAnswer('fix', stop(JSON.stringify(fix)))).toEqual({
      ok: true,
      value: { ...fix, explanation: 'Strict.' },
    });
  });

  it('accepts not_applicable with missing or any line numbers, and drops them', () => {
    const na = { status: 'not_applicable', replacement: [], explanation: 'Needs other files.' };
    const expected = {
      ok: true,
      value: { status: 'not_applicable', explanation: 'Needs other files.' },
    };
    expect(parseAnswer('fix', stop(JSON.stringify(na)))).toEqual(expected);
    expect(parseAnswer('fix', stop(JSON.stringify({ ...na, startLine: 0, endLine: -1 })))).toEqual(
      expected,
    );
    expect(
      parseAnswer('fix', stop(JSON.stringify({ ...na, startLine: null, endLine: 2.5 }))),
    ).toEqual(expected);
    expect(
      parseAnswer('fix', stop(JSON.stringify({ status: 'not_applicable', explanation: 'x' }))),
    ).toEqual({ ok: true, value: { status: 'not_applicable', explanation: 'x' } });
  });

  it('still refuses a fixed answer without whole positive lines, and unknown keys', () => {
    const fix = { status: 'fixed', startLine: 2, endLine: 2, replacement: ['x'], explanation: '' };
    for (const over of [{ startLine: 0 }, { endLine: 2.5 }, { startLine: undefined }]) {
      expect(parseAnswer('fix', stop(JSON.stringify({ ...fix, ...over }))).ok).toBe(false);
    }
    const na = { status: 'not_applicable', explanation: 'x', extra: 1 };
    expect(parseAnswer('fix', stop(JSON.stringify(na))).ok).toBe(false);
  });

  it('cuts overlong text to the displayed bound instead of refusing it', () => {
    const long = parseAnswer(
      'explain',
      stop(JSON.stringify({ ...explain, summary: 'x'.repeat(500) })),
    );
    expect(
      long.ok &&
        'kind' in long.value &&
        long.value.kind === 'explain' &&
        [...long.value.summary].length,
    ).toBe(300);
  });
});

describe('safeMultilineText (llm.md §9.4)', () => {
  it('keeps line breaks, removes controls and bidi, bounds lines and length', () => {
    expect(safeMultilineText('a\r\nb\rc', 100)).toBe('a\nb\nc');
    expect(safeMultilineText('x\u2066y\u0000z', 100)).toBe('x y z');
    expect(safeMultilineText('a\tb', 100)).toBe('a b');
    expect(
      safeMultilineText(Array.from({ length: 30 }, (_, i) => `l${i}`).join('\n'), 1_000).split(
        '\n',
      ),
    ).toHaveLength(20);
    expect(safeMultilineText('a\n\n\n\nb', 100)).toBe('a\n\nb');
    expect([...safeMultilineText('é'.repeat(50), 10)]).toHaveLength(10);
  });
});
