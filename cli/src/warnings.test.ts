import { describe, expect, it } from 'vitest';
import { Warnings } from './warnings';

describe('Warnings', () => {
  it('aggregates by code, keeping the first message and summing counts', () => {
    const w = new Warnings();
    w.add('FILE_TOO_LARGE', 'first');
    w.add('FILE_TOO_LARGE', 'second', 2);
    w.addAll([
      { code: 'HASH_FALLBACK', message: 'h', count: 4 },
      { code: 'X', message: 'x' },
    ]);
    expect(w.list()).toEqual([
      { code: 'FILE_TOO_LARGE', message: 'first', count: 3 },
      { code: 'HASH_FALLBACK', message: 'h', count: 4 },
      { code: 'X', message: 'x', count: 1 },
    ]);
  });

  it('respects the report bounds: 1000 entries, 64-char codes, 4000-char messages', () => {
    const w = new Warnings();
    for (let i = 0; i < 1_005; i++) w.add(`C${i}`, 'm');
    w.add('Y'.repeat(80), 'z'.repeat(5_000));
    const list = w.list();
    expect(list).toHaveLength(1_000);
    const long = new Warnings();
    long.add('Y'.repeat(80), 'z'.repeat(5_000));
    expect(long.list()[0]!.code).toHaveLength(64);
    expect(long.list()[0]!.message).toHaveLength(4_000);
  });

  it('merges two codes that only differ after the 64-char limit', () => {
    const w = new Warnings();
    const base = 'C'.repeat(64);
    w.add(`${base}-first-suffix`, 'first');
    w.add(`${base}-second-suffix`, 'second', 2);
    expect(w.list()).toEqual([{ code: base, message: 'first', count: 3 }]);
  });
});
