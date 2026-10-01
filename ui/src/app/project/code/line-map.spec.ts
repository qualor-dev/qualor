import { buildLineMap, type FileDetail, lineCounts, lineInfo } from './line-map';

const detail = (over: Partial<FileDetail>): FileDetail =>
  ({
    path: 'src/a.ts',
    language: 'typescript',
    kind: 'main',
    analysisId: 'a',
    measures: { lines: 10 },
    coverage: null,
    newLines: null,
    duplications: [],
    duplicationsTruncated: false,
    issues: [],
    issuesTruncated: false,
    ...over,
  }) as FileDetail;

const issue = (id: string, startLine: number | null, severity = 'high') =>
  ({ id, startLine, severity }) as FileDetail['issues'][number];

describe('buildLineMap (spec §4.3)', () => {
  it('merges coverage into runs, partial over covered', () => {
    const map = buildLineMap(
      detail({
        coverage: {
          covered: [[1, 4]],
          uncovered: [[6, 7]],
          branches: [
            [3, 2, 1],
            [4, 2, 2],
          ],
        },
      }),
    );
    expect(map.coverage.runs).toEqual([
      { from: 1, to: 2, value: 'covered' },
      { from: 3, to: 3, value: 'partial' },
      { from: 4, to: 4, value: 'covered' },
      { from: 6, to: 7, value: 'uncovered' },
    ]);
    expect(lineInfo(map, 5).coverage).toBe('none');
  });

  it('treats newLines "all" as the whole file, and clips runs to the file', () => {
    expect(buildLineMap(detail({ newLines: 'all' })).newCode).toEqual([{ from: 1, to: 10 }]);
    expect(
      buildLineMap(
        detail({
          newLines: [
            [8, 40],
            [50, 60],
          ],
        }),
      ).newCode,
    ).toEqual([{ from: 8, to: 10 }]);
  });

  it('handles an empty file and a huge one without per-line output', () => {
    expect(buildLineMap(detail({ measures: { lines: 0 }, newLines: 'all' }))).toMatchObject({
      lines: 0,
      newCode: [],
    });
    const big = buildLineMap(
      detail({
        measures: { lines: 50_000 },
        coverage: { covered: [[1, 50_000]], uncovered: [], branches: [] },
      }),
    );
    expect(big.coverage.runs).toHaveLength(1);
  });

  it('lists duplication blocks and issues by line', () => {
    const map = buildLineMap(
      detail({
        duplications: [{ startLine: 2, endLine: 5, others: [], othersTotal: 1 }],
        issues: [issue('i1', 7)],
      }),
    );
    expect(map.duplication).toEqual([{ from: 2, to: 5 }]);
    expect(map.issues).toEqual([{ line: 7, severity: 'high', id: 'i1' }]);
    expect(lineInfo(map, 3)).toMatchObject({ duplicated: true, issues: 0 });
  });

  it('leaves out issues without a line, and orders the rest by line', () => {
    const map = buildLineMap(detail({ issues: [issue('a', 9), issue('b', null), issue('c', 2)] }));
    expect(map.issues.map((i) => i.id)).toEqual(['c', 'a']);
    expect(lineInfo(map, 9).issues).toBe(1);
  });

  it('reads a missing line count as 0 and draws nothing then', () => {
    const map = buildLineMap(
      detail({
        measures: {},
        coverage: { covered: [[1, 3]], uncovered: [], branches: [] },
        duplications: [{ startLine: 1, endLine: 2, others: [], othersTotal: 0 }],
        issues: [issue('i', 1)],
      }),
    );
    expect(map).toEqual({
      lines: 0,
      coverage: { runs: [] },
      newCode: [],
      duplication: [],
      issues: [],
    });
  });

  it('merges overlapping and adjacent new-code and duplication ranges, whatever their order', () => {
    const map = buildLineMap(
      detail({
        newLines: [
          [6, 7],
          [1, 2],
          [3, 4],
        ],
        duplications: [
          { startLine: 5, endLine: 9, others: [], othersTotal: 0 },
          { startLine: 1, endLine: 6, others: [], othersTotal: 0 },
        ],
      }),
    );
    expect(map.newCode).toEqual([
      { from: 1, to: 4 },
      { from: 6, to: 7 },
    ]);
    expect(map.duplication).toEqual([{ from: 1, to: 9 }]);
    expect(lineInfo(map, 5)).toMatchObject({ newCode: false, duplicated: true });
    expect(lineInfo(map, 7)).toMatchObject({ newCode: true });
  });

  it('marks a partly covered line outside the line lists, and keeps an uncovered line uncovered', () => {
    const map = buildLineMap(
      detail({
        coverage: {
          covered: [[1, 1]],
          uncovered: [[2, 2]],
          branches: [
            [2, 2, 0],
            [3, 4, 1],
            [1, 2, 2],
          ],
        },
      }),
    );
    expect(map.coverage.runs).toEqual([
      { from: 1, to: 1, value: 'covered' },
      { from: 2, to: 2, value: 'uncovered' },
      { from: 3, to: 3, value: 'partial' },
    ]);
  });

  it('counts lines per lane for the summary', () => {
    const map = buildLineMap(
      detail({
        coverage: {
          covered: [[1, 4]],
          uncovered: [[6, 7]],
          branches: [[3, 2, 1]],
        },
        newLines: [[1, 3]],
        issues: [issue('a', 1), issue('b', 1)],
      }),
    );
    expect(lineCounts(map)).toEqual({
      covered: 3,
      uncovered: 2,
      partial: 1,
      newCode: 3,
      issues: 2,
    });
  });
});
