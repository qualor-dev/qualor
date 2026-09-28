import { createHash } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  computeFingerprints,
  contextHash,
  filelessHash,
  hex32,
  lineHash,
  normalizeLine,
  splitSourceLines,
  type FingerprintInput,
} from './hash';

const file = [
  'import x from "y";',
  '',
  'export function f(a: number) {',
  '  const unused = 1;',
  '  return a   +  1;',
  '}',
];

describe('hex32 / normalizeLine', () => {
  it('is the first 32 lowercase hex chars of sha256', () => {
    expect(hex32('abc')).toBe(createHash('sha256').update('abc').digest('hex').slice(0, 32));
    expect(hex32('abc')).toMatch(/^[0-9a-f]{32}$/);
  });

  it('removes all unicode whitespace', () => {
    expect(normalizeLine('  return a   +\t1;  ')).toBe('returna+1;');
  });

  it('removes every Unicode White_Space code point, including U+0085 and U+2028', () => {
    expect(normalizeLine('a\u0085b c d e　f﻿g')).toBe('abcdef﻿g');
  });
});

describe('splitSourceLines', () => {
  it('splits LF text and drops the empty string after a final newline', () => {
    expect(splitSourceLines('a\nb\n')).toEqual(['a', 'b']);
  });

  it('splits CRLF text', () => {
    expect(splitSourceLines('a\r\nb\r\n')).toEqual(['a', 'b']);
  });

  it('strips a leading UTF-8 BOM', () => {
    expect(splitSourceLines('﻿a\nb')).toEqual(['a', 'b']);
  });

  it('keeps the last line without a trailing newline', () => {
    expect(splitSourceLines('a\nb')).toEqual(['a', 'b']);
  });

  it('keeps blank lines except the single trailing one', () => {
    expect(splitSourceLines('a\n\n\n')).toEqual(['a', '', '']);
    expect(splitSourceLines('\n')).toEqual(['']);
  });

  it('returns no lines for empty text', () => {
    expect(splitSourceLines('')).toEqual([]);
  });
});

describe('lineHash / contextHash', () => {
  it('ignores whitespace-only reformatting', () => {
    const reformatted = file.map((l) => l.replace(/\s+/g, ' '));
    expect(lineHash(reformatted, 5, 5)).toBe(lineHash(file, 5, 5));
  });

  it('is stable when lines are inserted above (shift by 20)', () => {
    const shifted = [...Array<string>(20).fill(''), ...file];
    expect(lineHash(shifted, 24, 24)).toBe(lineHash(file, 4, 4));
    expect(contextHash(shifted, 24, 24)).toBe(contextHash(file, 4, 4));
  });

  it('hashes at most 5 flagged lines', () => {
    const long = Array.from({ length: 20 }, (_, i) => `line${i}`);
    expect(lineHash(long, 1, 20)).toBe(lineHash(long, 1, 5));
    expect(lineHash(long, 1, 20)).toBe(hex32('line0\nline1\nline2\nline3\nline4'));
  });

  it('uses ±2 lines of context, clamped to the file', () => {
    expect(contextHash(file, 1, 1)).toBe(
      hex32(['importxfrom"y";', '', 'exportfunctionf(a:number){'].join('\n')),
    );
    expect(contextHash(file, 6, 6)).toBe(hex32(['constunused=1;', 'returna+1;', '}'].join('\n')));
  });

  it('context distinguishes identical flagged lines', () => {
    const twice = ['a();', 'log(x);', 'b();', 'c();', 'd();', 'e();', 'log(x);', 'f();'];
    expect(lineHash(twice, 2, 2)).toBe(lineHash(twice, 7, 7));
    expect(contextHash(twice, 2, 2)).not.toBe(contextHash(twice, 7, 7));
  });

  it('rejects out-of-range lines', () => {
    expect(() => lineHash(file, 0, 1)).toThrow(RangeError);
    expect(() => lineHash(file, 7, 7)).toThrow(RangeError);
    expect(() => lineHash(file, 3, 2)).toThrow(RangeError);
  });
});

describe('filelessHash', () => {
  it('is hex32 of ruleKey + message', () => {
    expect(filelessHash('spotbugs:X', 'msg')).toBe(hex32('spotbugs:Xmsg'));
  });

  it('includes the path, NUL-separated, for a located finding whose source is unavailable', () => {
    expect(filelessHash('spotbugs:X', 'msg', 'src/a.ts')).toBe(
      hex32('spotbugs:X\u0000src/a.ts\u0000msg'),
    );
    expect(filelessHash('spotbugs:X', 'msg', 'src/a.ts')).not.toBe(
      filelessHash('spotbugs:X', 'msg', 'src/b.ts'),
    );
  });
});

describe('computeFingerprints', () => {
  const base: FingerprintInput = {
    ruleKey: 'eslint:no-console',
    path: 'src/a.ts',
    lineHash: 'l'.repeat(32),
    contextHash: 'c'.repeat(32),
    startLine: 10,
    startColumn: 1,
  };

  it('matches the documented formula', () => {
    const sep = '\u001f';
    const expected = hex32(
      ['eslint:no-console', 'src/a.ts', base.lineHash, base.contextHash, '0'].join(sep),
    );
    expect(computeFingerprints([base])).toEqual([expected]);
  });

  it('gives identical findings distinct occurrence indexes ordered by position, preserving input order', () => {
    const later = { ...base, startLine: 30 };
    const earlier = { ...base, startLine: 10, startColumn: 5 };
    const [fLater, fEarlier] = computeFingerprints([later, earlier]);
    const [gEarlier, gLater] = computeFingerprints([earlier, later]);
    expect(fLater).toBe(gLater);
    expect(fEarlier).toBe(gEarlier);
    expect(fLater).not.toBe(fEarlier);
  });

  it('is independent of line position for a single occurrence', () => {
    expect(computeFingerprints([{ ...base, startLine: 999 }])).toEqual(computeFingerprints([base]));
  });

  it('treats a null path as empty', () => {
    const sep = '\u001f';
    expect(computeFingerprints([{ ...base, path: null }])).toEqual([
      hex32(['eslint:no-console', '', base.lineHash, base.contextHash, '0'].join(sep)),
    ]);
  });
});
