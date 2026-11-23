import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { addedLineTexts } from './inline.js';
import { addedLines } from './line-diff.js';

const entries = (m: Map<number, string> | null): [number, string][] => [...(m ?? new Map())];

describe('addedLines fixed cases', () => {
  it('insert at start, middle and end', () => {
    expect(entries(addedLines('b\nc\n', 'a\nb\nc\n'))).toEqual([[1, 'a']]);
    expect(entries(addedLines('a\nc\n', 'a\nb\nc\n'))).toEqual([[2, 'b']]);
    expect(entries(addedLines('a\nb\n', 'a\nb\nc\n'))).toEqual([[3, 'c']]);
  });

  it('replace marks only the new line', () => {
    expect(entries(addedLines('a\nx\nc\n', 'a\ny\nc\n'))).toEqual([[2, 'y']]);
  });

  it('CRLF against LF adds nothing, and returned text has no CR', () => {
    expect(addedLines('a\r\nb\r\n', 'a\nb\n')?.size).toBe(0);
    expect(entries(addedLines('a\nb\n', 'a\r\nb\r\nc\r\n'))).toEqual([[3, 'c']]);
  });

  it('a missing final newline alone adds nothing', () => {
    expect(addedLines('a\nb', 'a\nb\n')?.size).toBe(0);
    expect(addedLines('a\nb\n', 'a\nb')?.size).toBe(0);
  });

  it('base null adds every line; empty head adds none', () => {
    expect(entries(addedLines(null, 'a\nb\n'))).toEqual([
      [1, 'a'],
      [2, 'b'],
    ]);
    expect(addedLines('a\n', '')?.size).toBe(0);
    expect(addedLines(null, '')?.size).toBe(0);
  });

  it('keeps interior blank lines', () => {
    expect(entries(addedLines('a\n', 'a\n\nb\n'))).toEqual([
      [2, ''],
      [3, 'b'],
    ]);
  });
});

describe('addedLines limits', () => {
  it('returns null over maxLines on either side', () => {
    expect(addedLines('a\nb\nc\n', 'a\n', { maxLines: 2 })).toBeNull();
    expect(addedLines('a\n', 'a\nb\nc\n', { maxLines: 2 })).toBeNull();
    expect(addedLines(null, 'a\nb\nc\n', { maxLines: 2 })).toBeNull();
    expect(addedLines('a\nb\n', 'a\nb\n', { maxLines: 2 })).not.toBeNull();
  });

  it('returns null when the edit distance exceeds maxEdits', () => {
    expect(addedLines('a\nb\nc\n', 'x\ny\nz\n', { maxEdits: 5 })).toBeNull();
    expect(addedLines('a\nb\nc\n', 'x\ny\nz\n', { maxEdits: 6 })?.size).toBe(3);
  });

  it('stays bounded on large unrelated inputs', () => {
    const a = Array.from({ length: 20000 }, (_, i) => `a${i}`).join('\n');
    const b = Array.from({ length: 20000 }, (_, i) => `b${i}`).join('\n');
    const t = Date.now();
    expect(addedLines(a, b, { maxEdits: 500 })).toBeNull();
    expect(Date.now() - t).toBeLessThan(1000);
  });
});

function prng(seed: number): () => number {
  let s = seed >>> 0;
  return () => {
    s = (s + 0x6d2b79f5) >>> 0;
    let t = s;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function lcs(a: string[], b: string[]): number {
  let prev = new Array<number>(b.length + 1).fill(0);
  for (let i = 1; i <= a.length; i++) {
    const cur = new Array<number>(b.length + 1).fill(0);
    for (let j = 1; j <= b.length; j++) {
      cur[j] = a[i - 1] === b[j - 1] ? prev[j - 1]! + 1 : Math.max(prev[j]!, cur[j - 1]!);
    }
    prev = cur;
  }
  return prev[b.length]!;
}

function isSubsequence(small: string[], big: string[]): boolean {
  let i = 0;
  for (const x of big) if (i < small.length && small[i] === x) i++;
  return i === small.length;
}

describe('addedLines property', () => {
  it('matches head.length - LCS on 500 seeded random pairs', () => {
    const rnd = prng(20261123);
    const started = Date.now();
    for (let n = 0; n < 500; n++) {
      const alphabet = 2 + Math.floor(rnd() * 3);
      const gen = (): string[] =>
        Array.from({ length: Math.floor(rnd() * 25) }, () => 'xyzw'[Math.floor(rnd() * alphabet)]!);
      const base = gen();
      const head = gen();
      const added = addedLines(
        base.length ? base.join('\n') + '\n' : '',
        head.join('\n') + (head.length ? '\n' : ''),
      );
      expect(added).not.toBeNull();
      expect(added!.size).toBe(head.length - lcs(base, head));
      const kept = head.filter((_, i) => !added!.has(i + 1));
      expect(isSubsequence(kept, base)).toBe(true);
      for (const [line, text] of added!) expect(text).toBe(head[line - 1]);
    }
    expect(Date.now() - started).toBeLessThan(2000);
  });
});

const gitOk = spawnSync('git', ['--version']).status === 0;

describe.skipIf(!gitOk)('addedLines against git diff --diff-algorithm=myers', () => {
  const cases: [string, string, string][] = [
    ['insert at start', 'b\nc\nd\n', 'a\nb\nc\nd\n'],
    ['insert in middle', 'a\nb\nd\ne\n', 'a\nb\nc\nd\ne\n'],
    ['append at end', 'a\nb\nc\n', 'a\nb\nc\nd\ne\n'],
    ['single replace', 'one\ntwo\nthree\n', 'one\n2\nthree\n'],
    ['two separate inserts', 'a\nb\nc\nd\ne\nf\n', 'a\nX\nb\nc\nd\ne\nY\nf\n'],
    ['delete and insert', 'a\nb\nc\nd\n', 'a\nc\nd\nz\n'],
    ['block replace', 'h\na\nb\nc\nt\n', 'h\nx\ny\nt\n'],
    ['all new', 'a\nb\n', 'c\nd\ne\n'],
    ['no change', 'a\nb\nc\n', 'a\nb\nc\n'],
    ['interleaved', 'a\nb\nc\nd\ne\nf\ng\n', 'a\nq\nc\nd\nr\nf\ns\ng\n'],
  ];

  it.each(cases)('%s', (_name, base, head) => {
    const dir = mkdtempSync(join(tmpdir(), 'line-diff-'));
    try {
      writeFileSync(join(dir, 'a'), base);
      writeFileSync(join(dir, 'b'), head);
      const r = spawnSync(
        'git',
        ['diff', '--no-index', '-U0', '--diff-algorithm=myers', 'a', 'b'],
        { cwd: dir, encoding: 'utf8' },
      );
      expect(r.status === 0 || r.status === 1).toBe(true);
      expect(entries(addedLines(base, head))).toEqual([...addedLineTexts(r.stdout)]);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
