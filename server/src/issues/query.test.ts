import { describe, expect, it } from 'vitest';
import { containsPattern, FACET_CONCURRENCY, mapConcurrent } from './query';

describe('containsPattern', () => {
  it('escapes %, _ and \\ so they match literally', () => {
    expect(containsPattern('100%_a\\b')).toBe('%100\\%\\_a\\\\b%');
  });
});

describe('mapConcurrent', () => {
  it('keeps the input order and never runs more than `limit` calls at once', async () => {
    let running = 0;
    let peak = 0;
    const out = await mapConcurrent([5, 1, 4, 2, 3, 0], FACET_CONCURRENCY, async (n) => {
      running += 1;
      peak = Math.max(peak, running);
      await new Promise((resolve) => setImmediate(resolve));
      for (let i = 0; i < n; i++) await Promise.resolve();
      running -= 1;
      return n * 10;
    });
    expect(out).toEqual([50, 10, 40, 20, 30, 0]);
    expect(FACET_CONCURRENCY).toBe(2);
    expect(peak).toBe(2);
  });

  it('rejects with the first failure and starts nothing after it', async () => {
    const started: number[] = [];
    await expect(
      mapConcurrent([1, 2, 3, 4], 1, async (n) => {
        started.push(n);
        if (n === 2) throw new Error('boom');
        return n;
      }),
    ).rejects.toThrow('boom');
    expect(started).toEqual([1, 2]);
  });

  it('handles an empty list', async () => {
    expect(await mapConcurrent([], 2, async () => 1)).toEqual([]);
  });
});
