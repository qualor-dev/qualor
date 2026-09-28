import { describe, expect, it } from 'vitest';
import { downsample, MAX_HISTORY_POINTS } from './read';

describe('downsample (api.md: at most 1 000 points per metric)', () => {
  it('keeps short series as they are', () => {
    expect(downsample([1, 2, 3], 5)).toEqual([1, 2, 3]);
  });

  it('keeps the first and the last point and spaces the rest evenly', () => {
    const points = Array.from({ length: 10_001 }, (_, i) => i);
    const kept = downsample(points, MAX_HISTORY_POINTS);
    expect(kept).toHaveLength(MAX_HISTORY_POINTS);
    expect(kept[0]).toBe(0);
    expect(kept.at(-1)).toBe(10_000);
    expect(kept).toEqual([...kept].sort((a, b) => a - b));
    expect(downsample(points, 3)).toEqual([0, 5_000, 10_000]);
  });
});
