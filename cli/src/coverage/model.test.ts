import { describe, expect, it } from 'vitest';
import { CoverageAccumulator, CoverageRecord, toRanges } from './model';

describe('toRanges', () => {
  it('collapses consecutive lines', () => {
    expect(toRanges([1, 2, 3, 5, 7, 8])).toEqual([
      [1, 3],
      [5, 5],
      [7, 8],
    ]);
    expect(toRanges([])).toEqual([]);
  });
});

describe('CoverageRecord', () => {
  it('keeps the maximum within one report and ignores invalid input', () => {
    const r = new CoverageRecord();
    r.hit(3, 2);
    r.hit(3, 5);
    r.hit(3, 1);
    r.hit(0, 1);
    r.hit(4, Number.NaN);
    r.branch(3, 2, 1);
    r.branch(3, 4, 0);
    r.branch(9, 2, 7);
    r.branch(10, 0, 0);
    expect([...r.lines]).toEqual([[3, 5]]);
    expect([...r.branches]).toEqual([
      [3, { total: 4, covered: 1 }],
      [9, { total: 2, covered: 2 }],
    ]);
  });
});

describe('CoverageAccumulator', () => {
  it('sums hits across reports, takes branch maxima and drops lines past the end', () => {
    const a = new CoverageRecord();
    a.hit(1, 0);
    a.hit(2, 0);
    a.hit(40, 1);
    a.branch(2, 2, 1);
    const b = new CoverageRecord();
    b.hit(1, 3);
    b.branch(2, 2, 2);
    const acc = new CoverageAccumulator();
    acc.add('src/a.ts', a);
    acc.add('src/a.ts', b);
    expect(acc.paths()).toEqual(['src/a.ts']);
    expect(acc.toFileCoverage('src/a.ts', 10)).toEqual({
      coverage: { covered: [[1, 1]], uncovered: [[2, 2]], branches: [[2, 2, 2]] },
      outOfRange: 1,
    });
    expect(acc.toFileCoverage('src/other.ts', 10)).toBeUndefined();
  });
});
