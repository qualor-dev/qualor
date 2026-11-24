import { describe, expect, it } from 'vitest';
import { parseArgs } from './common.js';
import {
  ancestryVerdict,
  descriptionOf,
  DESCRIPTION_LIMIT,
  exactRef,
  sampleBytes,
} from './22-fix-writes.js';
import {
  expectedText,
  judgeApply,
  SIX_LINES,
  SUGGESTIONS,
  suggestionBody,
} from './23-suggestion-ranges.js';

describe('item 22 helpers', () => {
  it('the sample file has a BOM, CRLF lines and a non-ASCII line, and differs by tag', () => {
    const a = sampleBytes('base');
    expect([...a.subarray(0, 3)]).toEqual([0xef, 0xbb, 0xbf]);
    const text = a.toString('utf8');
    expect(text.split('\r\n').length).toBeGreaterThan(3);
    expect(text).not.toMatch(/(^|[^\r])\n/);
    expect(
      text
        .slice(1)
        .split('')
        .some((ch) => ch.charCodeAt(0) > 127),
    ).toBe(true);
    expect(sampleBytes('fix-1').equals(a)).toBe(false);
    expect(sampleBytes('base').equals(a)).toBe(true);
  });

  it('descriptions have exactly the asked length', () => {
    expect(DESCRIPTION_LIMIT).toBe(4000);
    expect(descriptionOf(4000)).toHaveLength(4000);
    expect(descriptionOf(4001)).toHaveLength(4001);
  });

  it('ancestry: the common commit is the base only when the base is an ancestor', () => {
    expect(ancestryVerdict('aaa', 'aaa')).toBe('ancestor');
    expect(ancestryVerdict('bbb', 'aaa')).toBe('diverged');
    expect(ancestryVerdict('bbb', undefined)).toBe('diverged');
  });

  it('exactRef picks the ref of that name, not one the filter matched by prefix', () => {
    const refs = [
      { name: 'refs/heads/probe/x-2', objectId: '2' },
      { name: 'refs/heads/probe/x', objectId: '1' },
    ];
    expect(exactRef(refs, 'refs/heads/probe/x')?.objectId).toBe('1');
    expect(exactRef(refs, 'refs/heads/probe/y')).toBeUndefined();
  });
});

describe('item 23 helpers', () => {
  it('the file has six lines and three suggestions over whole lines', () => {
    expect(SIX_LINES).toHaveLength(6);
    expect(SUGGESTIONS.map((s) => [s.id, s.start, s.end, s.replacement.length])).toEqual([
      ['A', 2, 3, 2],
      ['B', 4, 5, 3],
      ['C', 6, 6, 0],
    ]);
  });

  it('a suggestion body is a fence; a deletion is an empty fence', () => {
    expect(suggestionBody(['x', 'y'])).toBe('```suggestion\nx\ny\n```');
    expect(suggestionBody([])).toBe('```suggestion\n```');
  });

  it('expectedText applies the chosen suggestions to the original lines', () => {
    expect(expectedText([])).toBe(`${SIX_LINES.join('\n')}\n`);
    const all = expectedText(['A', 'B', 'C']).split('\n');
    expect(all).toHaveLength(7); // 1 + 2 + 3 lines and the final newline
    expect(all[0]).toBe(SIX_LINES[0]);
    expect(all.at(-1)).toBe('');
    expect(expectedText(['C'])).toBe(`${SIX_LINES.slice(0, 5).join('\n')}\n`);
  });

  it('judges each thread from the file text', () => {
    const verdicts = (text: string) =>
      Object.fromEntries(judgeApply(text).map((j) => [j.thread, j.verdict]));
    expect(verdicts(expectedText([]))).toEqual({
      A: 'not-applied',
      B: 'not-applied',
      C: 'not-applied',
    });
    expect(verdicts(expectedText(['A', 'B', 'C']))).toEqual({
      A: 'as-expected',
      B: 'as-expected',
      C: 'as-expected',
    });
    expect(verdicts(expectedText(['B']))).toEqual({
      A: 'not-applied',
      B: 'as-expected',
      C: 'not-applied',
    });
  });

  it('a deletion that leaves a blank line is unexpected and says so', () => {
    const withBlank = `${SIX_LINES.slice(0, 5).join('\n')}\n\n`;
    const c = judgeApply(withBlank).find((j) => j.thread === 'C');
    expect(c?.verdict).toBe('unexpected');
    expect(c?.blankLine).toBe(true);
    const clean = judgeApply(expectedText(['C'])).find((j) => j.thread === 'C');
    expect(clean?.blankLine).toBe(false);
  });

  it('a range applied to the wrong lines is unexpected', () => {
    const wrong = `${SIX_LINES[0]}\n${SUGGESTIONS[0]!.replacement[0]}\n${SIX_LINES.slice(2).join('\n')}\n`;
    expect(judgeApply(wrong).find((j) => j.thread === 'A')?.verdict).toBe('unexpected');
  });
});

describe('--verify-apply', () => {
  it('takes a pull request id, with item 23 only', () => {
    expect(parseArgs(['--target', 'services', '--items', '23', '--verify-apply', '77'])).toEqual({
      target: 'services',
      items: [23],
      verifyApply: 77,
    });
    expect(() => parseArgs(['--target', 'services', '--verify-apply', '77'])).toThrow(/23/);
    expect(() =>
      parseArgs(['--target', 'services', '--items', '22', '--verify-apply', '7']),
    ).toThrow(/23/);
    expect(() =>
      parseArgs(['--target', 'services', '--items', '23', '--verify-apply', 'x']),
    ).toThrow(/x/);
  });
});
