import { describe, expect, it } from 'vitest';
import { REDACTED } from '../sarif/normalize';
import { checkFix } from './fix';
import { sampleInput } from '../../test/llm';

const answer = (over: Record<string, unknown> = {}) => ({
  status: 'fixed' as const,
  startLine: 2,
  endLine: 2,
  replacement: ['if (a === 1) {}'],
  explanation: 'Strict equality.',
  ...over,
});

describe('checkFix (llm.md §9.5)', () => {
  it('accepts a minimal fix and returns the original lines', () => {
    expect(checkFix(answer(), sampleInput())).toEqual({
      ok: true,
      value: {
        kind: 'fix',
        status: 'fixed',
        startLine: 2,
        endLine: 2,
        original: ['if (a == 1) {}'],
        replacement: ['if (a === 1) {}'],
        explanation: 'Strict equality.',
      },
    });
  });

  it('passes not_applicable through without lines', () => {
    expect(checkFix(answer({ status: 'not_applicable' }), sampleInput())).toEqual({
      ok: true,
      value: { kind: 'fix', status: 'not_applicable', explanation: 'Strict equality.' },
    });
  });

  it.each([
    [{ startLine: 3, endLine: 3 }, 'range'],
    [{ startLine: 1, endLine: 9 }, 'range'],
    [{ endLine: 1 }, 'range'],
    [{ replacement: ['if (a == 1) {}'] }, 'unchanged'],
    [{ replacement: Array(31).fill('x') }, 'size'],
    [{ replacement: ['if (a === 1) {} // \u202E evil'] }, 'control_character'],
    [{ replacement: ['a\u200Bb'] }, 'control_character'],
    [{ replacement: ['```', 'x'] }, 'fence'],
    [{ replacement: ['~~~~'] }, 'fence'],
    [{ replacement: [`const k = "${REDACTED}";`] }, 'redacted'],
    [{ replacement: [['const t = "', 'gh', 'p_', 'b'.repeat(36), '";'].join('')] }, 'secret'],
    [{ replacement: ['  /merge'] }, 'quick_action'],
    [{ replacement: ['/approve now'] }, 'quick_action'],
  ])('refuses %j as %s', (over, problem) => {
    expect(checkFix(answer(over), sampleInput())).toEqual({ ok: false, problem });
  });

  it('allows comments and regex literals that start with a slash', () => {
    for (const line of [
      '// strict equality',
      '/* x */',
      '/ab+c/.test(s)',
      '/usr/bin is fine? no: /usr/bin/x',
    ]) {
      expect(
        checkFix(answer({ replacement: [`if (a === 1) {}`, line] }), sampleInput()).ok,
        line,
      ).toBe(true);
    }
  });

  it('refuses a range with a truncated or redacted source line', () => {
    const truncated = sampleInput({
      snippet: { startLine: 1, lines: ['a', `${'x'.repeat(399)}…`, 'c'] },
    });
    expect(checkFix(answer({ replacement: ['y'] }), truncated)).toEqual({
      ok: false,
      problem: 'source_line_unusable',
    });
    const redacted = sampleInput({
      snippet: { startLine: 1, lines: ['a', `k = "${REDACTED}"`, 'c'] },
    });
    expect(checkFix(answer({ replacement: ['y'] }), redacted)).toEqual({
      ok: false,
      problem: 'source_line_unusable',
    });
  });

  it('refuses when there is no snippet', () => {
    expect(checkFix(answer(), sampleInput({ snippet: null }))).toEqual({
      ok: false,
      problem: 'range',
    });
  });

  // Hardening beyond the brief.
  it('refuses a secret split over two replacement lines', () => {
    const half = 'b'.repeat(18);
    const split = [['const t = "', 'gh', 'p_', half, '" +'].join(''), `  "${half}";`];
    expect(checkFix(answer({ replacement: split }), sampleInput())).toEqual({
      ok: false,
      problem: 'secret',
    });
  });

  it('refuses a range that does not cover the finding, or no start line', () => {
    const wide = sampleInput({ startLine: 3, endLine: 3 });
    expect(checkFix(answer(), wide)).toEqual({ ok: false, problem: 'range' });
    expect(checkFix(answer(), sampleInput({ startLine: null }))).toEqual({
      ok: false,
      problem: 'range',
    });
  });

  it('refuses a range over 15 lines even inside the snippet', () => {
    const lines = Array.from({ length: 20 }, (_, i) => `l${i + 1}`);
    const input = sampleInput({ snippet: { startLine: 1, lines } });
    expect(checkFix(answer({ startLine: 1, endLine: 16, replacement: ['x'] }), input)).toEqual({
      ok: false,
      problem: 'range',
    });
    expect(checkFix(answer({ startLine: 1, endLine: 15, replacement: ['x'] }), input).ok).toBe(
      true,
    );
  });

  it('refuses a line over 400 characters, a C1 control and a lone surrogate; allows a tab', () => {
    expect(checkFix(answer({ replacement: ['x'.repeat(401)] }), sampleInput())).toEqual({
      ok: false,
      problem: 'size',
    });
    expect(checkFix(answer({ replacement: ['a\u0085b'] }), sampleInput())).toEqual({
      ok: false,
      problem: 'control_character',
    });
    expect(checkFix(answer({ replacement: ['a\ud800b'] }), sampleInput())).toEqual({
      ok: false,
      problem: 'control_character',
    });
    expect(checkFix(answer({ replacement: ['\tif (a === 1) {}'] }), sampleInput()).ok).toBe(true);
  });

  it('allows deleting the range (an empty replacement)', () => {
    expect(checkFix(answer({ replacement: [] }), sampleInput()).ok).toBe(true);
  });

  // Fix round 5a: the reviewer's attack cases that were accepted.
  it.each(['/MERGE', '/Close', '  /Approve now', '/h1 x', '/assign_reviewer2 @x', '/Merge\t'])(
    'refuses the quick action %j in any case, with digits',
    (line) => {
      expect(checkFix(answer({ replacement: [line] }), sampleInput())).toEqual({
        ok: false,
        problem: 'quick_action',
      });
    },
  );

  it.each([
    ['a combining grapheme joiner', 'a\u034fb'],
    ['a variation selector', 'a\ufe0fb'],
    ['a variation selector of the supplement', 'a\u{e0100}b'],
    ['a Mongolian free variation selector', 'a\u180bb'],
    ['the Mongolian vowel separator', 'a\u180eb'],
    ['a Khmer inherent vowel', 'a\u17b4b'],
    ['the other Khmer inherent vowel', 'a\u17b5b'],
    ['a zero width joiner', 'a\u200db'],
    ['a zero width non-joiner', 'a\u200cb'],
    ['a musical format character', 'a\u{1d173}b'],
    ['an Arabic number sign', '\u0600a'],
    ['an Arabic end of ayah', 'a\u06ddb'],
    ['a Kaithi number sign', 'a\u{110bd}b'],
    ['an Egyptian hieroglyph format control', 'a\u{13430}b'],
    ['a shorthand format control', 'a\u{1bca0}b'],
    ['an inhibit-swapping format control', 'a\u206ab'],
    ['a Hangul filler', 'a\u3164b'],
  ])('refuses %s (a format or invisible character)', (_name, line) => {
    expect(checkFix(answer({ replacement: [line] }), sampleInput())).toEqual({
      ok: false,
      problem: 'control_character',
    });
  });

  it.each([
    ['a NaN start', { startLine: Number.NaN }],
    ['a NaN end', { endLine: Number.NaN }],
    ['a fractional end', { endLine: 2.5 }],
    ['a fractional start', { startLine: 1.5 }],
    ['infinite lines', { startLine: Number.POSITIVE_INFINITY, endLine: Number.POSITIVE_INFINITY }],
  ])('refuses a range that is not whole numbers: %s', (_name, over) => {
    expect(checkFix(answer(over), sampleInput())).toEqual({ ok: false, problem: 'range' });
  });

  it('counts a line of astral characters in UTF-16 units, the stricter unit', () => {
    // 200 emoji are 200 code points (the schema's unit) but 400 UTF-16 units: still allowed.
    const emoji = '\u{1F600}';
    expect(checkFix(answer({ replacement: [emoji.repeat(200)] }), sampleInput()).ok).toBe(true);
    expect(checkFix(answer({ replacement: [emoji.repeat(201)] }), sampleInput())).toEqual({
      ok: false,
      problem: 'size',
    });
  });
});
