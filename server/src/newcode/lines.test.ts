import type { ReportFile } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { file, reportWith } from '../../test/reports';
import { newCodeClassifier, newLineTest } from './lines';

describe('newLineTest', () => {
  it('treats "all" as every line and a missing or empty list as none', () => {
    expect(newLineTest('all')(123_456)).toBe(true);
    expect(newLineTest(undefined)(1)).toBe(false);
    expect(newLineTest([])(1)).toBe(false);
  });

  it('checks inclusive, unsorted, overlapping and adjacent ranges', () => {
    const test = newLineTest([
      [40, 58],
      [3, 4],
      [50, 60],
      [61, 61],
    ]);
    expect([2, 3, 4, 5, 39, 40, 58, 60, 61, 62].map(test)).toEqual([
      false,
      true,
      true,
      false,
      false,
      true,
      true,
      true,
      true,
      false,
    ]);
  });
});

function withoutNewLines(f: ReportFile): ReportFile {
  const copy = { ...f };
  delete copy.newLines;
  return copy;
}

describe('newCodeClassifier (gates.md §5)', () => {
  const files = [
    file('src/changed.ts', { newLines: [[10, 12]] }),
    file('src/added.ts', { newLines: 'all' }),
    file('src/same.ts', { newLines: [] }),
  ];

  it('puts an issue in new code iff its start line is a new line of its file', () => {
    const c = newCodeClassifier(reportWith({ files }));
    expect(c.available).toBe(true);
    expect(c.inNewCode('src/changed.ts', 11, false)).toBe(true);
    expect(c.inNewCode('src/changed.ts', 13, true)).toBe(false);
    expect(c.inNewCode('src/added.ts', 999, false)).toBe(true);
    expect(c.inNewCode('src/same.ts', 1, true)).toBe(false);
    expect(c.inNewCode('src/not-in-report.ts', 1, true)).toBe(false);
  });

  it('puts a file-less issue in new code iff it was first seen in this analysis', () => {
    const c = newCodeClassifier(reportWith({ files }));
    expect(c.inNewCode(null, null, true)).toBe(true);
    expect(c.inNewCode(null, null, false)).toBe(false);
  });

  it('has no new code on a first analysis or without a baseline', () => {
    const first = newCodeClassifier(
      reportWith({
        files: files.map(withoutNewLines),
        baseline: { revision: null, kind: 'server_baseline', status: 'first_analysis' },
      }),
    );
    const unavailable = newCodeClassifier(
      reportWith({
        files: files.map(withoutNewLines),
        baseline: { revision: null, kind: 'none', status: 'unavailable' },
      }),
    );
    for (const c of [first, unavailable]) {
      expect(c.available).toBe(false);
      expect(c.inNewCode('src/added.ts', 1, true)).toBe(false);
      expect(c.inNewCode(null, null, true)).toBe(false);
    }
  });
});
