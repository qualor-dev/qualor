import { linear, niceTicks, tickLabel, timeTicks } from './scale';

describe('niceTicks', () => {
  it('covers the maximum from 0 in clean steps', () => {
    expect(niceTicks(19)).toEqual([0, 5, 10, 15, 20]);
    expect(niceTicks(65.7)).toEqual([0, 20, 40, 60, 80]);
    expect(niceTicks(654)).toEqual([0, 200, 400, 600, 800]);
    expect(niceTicks(1.2)).toEqual([0, 0.5, 1, 1.5]);
  });

  it('keeps whole steps for counts', () => {
    expect(niceTicks(1, 4, true)).toEqual([0, 1]);
    expect(niceTicks(3, 4, true)).toEqual([0, 1, 2, 3]);
    expect(niceTicks(7, 4, true)).toEqual([0, 2, 4, 6, 8]);
  });

  it('gives a unit range when there is nothing to scale', () => {
    expect(niceTicks(0)).toEqual([0, 1]);
    expect(niceTicks(-3)).toEqual([0, 1]);
    expect(niceTicks(Number.NaN)).toEqual([0, 1]);
  });
});

describe('linear', () => {
  it('maps a domain onto a range, and a zero-width domain onto its middle', () => {
    expect(linear([0, 10], [100, 0])(5)).toBe(50);
    expect(linear([2, 2], [0, 40])(2)).toBe(20);
  });
});

describe('timeTicks', () => {
  const day = (s: string) => Date.parse(`${s}T00:00:00Z`);

  it('uses month starts for two months or more', () => {
    const ticks = timeTicks(day('2026-06-02'), day('2026-09-15'));
    expect(ticks.map((t) => new Date(t.at).toISOString().slice(0, 10))).toEqual([
      '2026-07-01',
      '2026-08-01',
      '2026-09-01',
    ]);
    expect(ticks.every((t) => t.month)).toBe(true);
    expect(tickLabel(ticks[0]!, 'en-US')).toBe('Jul');
  });

  it('thins month ticks on a long range and uses days on a short one', () => {
    // 25 month starts, at most 6 ticks: every 5th month.
    const long = timeTicks(day('2024-01-01'), day('2026-01-01'));
    expect(long.map((t) => new Date(t.at).toISOString().slice(0, 7))).toEqual([
      '2024-01',
      '2024-06',
      '2024-11',
      '2025-04',
      '2025-09',
    ]);
    const short = timeTicks(day('2026-09-01'), day('2026-09-21'));
    expect(short.map((t) => new Date(t.at).toISOString().slice(0, 10))).toEqual([
      '2026-09-01',
      '2026-09-08',
      '2026-09-15',
    ]);
    expect(tickLabel(short[1]!, 'en-US')).toBe('Sep 8');
  });

  it('has no ticks for an empty range', () => {
    expect(timeTicks(day('2026-09-01'), day('2026-09-01'))).toEqual([]);
  });
});
