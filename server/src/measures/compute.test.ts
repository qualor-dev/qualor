import { allMetricKeys, type ReportFile } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { file, reportWith, type ReportParts } from '../../test/reports';
import { newCodeClassifier } from '../newcode/lines';
import {
  fileCoverageCounts,
  intersectRanges,
  issueMeasures,
  lineSet,
  reportMeasures,
  subtractRanges,
} from './compute';

const measure = (parts: ReportParts) => {
  const report = reportWith(parts);
  return reportMeasures(report, newCodeClassifier(report));
};

/** fixtures/ts-basic's coverage shape: 13 executable lines (2 uncovered), 8 conditions (2 not). */
const tsBasicCoverage: NonNullable<ReportFile['coverage']> = {
  covered: [
    [1, 5],
    [7, 12],
  ],
  uncovered: [[20, 21]],
  branches: [
    [3, 4, 3],
    [8, 4, 3],
  ],
};

describe('reportMeasures (gates.md §2–§3)', () => {
  it('computes size and coverage over main files only, as Sonar does', () => {
    const m = measure({
      files: [
        file('src/math.ts', {
          lines: 25,
          metrics: {
            ncloc: 22,
            commentLines: 1,
            functions: 3,
            classes: 0,
            statements: 12,
            complexity: 8,
            cognitiveComplexity: 6,
          },
          coverage: tsBasicCoverage,
        }),
        file('src/math.test.ts', {
          kind: 'test',
          lines: 3,
          coverage: { covered: [[1, 3]], uncovered: [], branches: [] },
        }),
      ],
    });
    expect(m).toMatchObject({
      files: 1,
      lines: 25,
      ncloc: 22,
      comment_lines: 1,
      functions: 3,
      complexity: 8,
      cognitive_complexity: 6,
      lines_to_cover: 13,
      uncovered_lines: 2,
      conditions_to_cover: 8,
      uncovered_conditions: 2,
      line_coverage: 84.6,
      branch_coverage: 75,
      coverage: 81,
    });
  });

  it('leaves coverage null when no coverage was imported, and skips uncovered files when some was', () => {
    expect(measure({ files: [file('src/a.ts')] })).toMatchObject({
      coverage: null,
      lines_to_cover: null,
      new_coverage: null,
    });
    expect(
      measure({
        files: [
          file('src/a.ts', { coverage: { covered: [[1, 1]], uncovered: [[2, 2]], branches: [] } }),
          file('src/unknown.ts'),
        ],
      }),
    ).toMatchObject({ lines_to_cover: 2, coverage: 50 });
  });

  it('counts only new lines for new-code coverage, duplication and new_lines', () => {
    const m = measure({
      files: [
        file('src/a.ts', {
          lines: 20,
          newLines: [[3, 6]],
          coverage: { covered: [[1, 4]], uncovered: [[5, 10]], branches: [[4, 2, 1]] },
        }),
        file('src/b.ts', { lines: 10, newLines: 'all' }),
      ],
      duplications: [
        {
          blocks: [
            { path: 'src/a.ts', startLine: 11, endLine: 20 },
            { path: 'src/b.ts', startLine: 1, endLine: 10 },
          ],
        },
      ],
    });
    expect(m).toMatchObject({
      lines: 30,
      new_lines: 14,
      new_lines_to_cover: 4,
      new_uncovered_lines: 2,
      new_conditions_to_cover: 2,
      new_uncovered_conditions: 1,
      new_coverage: 50,
      duplicated_lines: 20,
      duplicated_blocks: 2,
      duplicated_lines_density: 66.7,
      new_duplicated_lines: 10,
      new_duplicated_blocks: 1,
      new_duplicated_lines_density: 71.4,
    });
  });

  it('has null new_* without a baseline, and zero new code on a first analysis', () => {
    const covered = file('src/a.ts', {
      coverage: { covered: [[1, 2]], uncovered: [], branches: [] },
    });
    delete covered.newLines;
    const files = [covered];
    const unavailable = measure({
      files,
      baseline: { revision: null, kind: 'none', status: 'unavailable' },
    });
    for (const key of allMetricKeys().filter((k) => k.startsWith('new_'))) {
      if (key in unavailable) expect(unavailable[key], key).toBeNull();
    }
    expect(
      measure({
        files,
        baseline: { revision: null, kind: 'server_baseline', status: 'first_analysis' },
      }),
    ).toMatchObject({
      new_lines: 0,
      new_lines_to_cover: 0,
      new_coverage: null,
      new_duplicated_lines: 0,
      new_duplicated_lines_density: null,
    });
  });
});

describe('issueMeasures (gates.md §2)', () => {
  it('counts by severity and quality, rates by the worst severity, and splits new code', () => {
    const m = issueMeasures(
      [
        { severity: 'high', quality: 'security', inNewCode: true, count: 2 },
        { severity: 'low', quality: 'reliability', inNewCode: false, count: 3 },
        { severity: 'info', quality: 'maintainability', inNewCode: true, count: 1 },
      ],
      4,
      5,
      false,
    );
    expect(m).toMatchObject({
      issues: 6,
      high_issues: 2,
      low_issues: 3,
      security_issues: 2,
      reliability_issues: 3,
      security_rating: 4,
      reliability_rating: 2,
      new_issues: 3,
      new_security_rating: 4,
      new_reliability_rating: 1,
      accepted_issues: 4,
      false_positive_issues: 5,
    });
  });

  it('nulls new-code issue measures without a baseline', () => {
    const m = issueMeasures([], 0, 0, true);
    expect(m).toMatchObject({
      issues: 0,
      security_rating: 1,
      new_issues: null,
      new_security_rating: null,
    });
  });

  it('together with reportMeasures covers every catalog metric', () => {
    const report = reportWith({ files: [file('src/a.ts')] });
    const keys = Object.keys({
      ...reportMeasures(report, newCodeClassifier(report)),
      ...issueMeasures([], 0, 0, false),
    });
    expect(keys.sort()).toEqual(allMetricKeys().sort());
  });
});

describe('line counting (report line numbers are only bounded by MAX_SAFE_INTEGER)', () => {
  it('counts the lines of a range set by arithmetic', () => {
    const set = lineSet([
      [10, 12],
      [1, 3],
      [3, 5],
      [7, 7],
    ]);
    expect(set.count(1, 100)).toBe(9);
    expect(set.count(4, 10)).toBe(4);
    expect(set.count(6, 6)).toBe(0);
    expect(set.count(12, 11)).toBe(0);
    expect(lineSet('all').count(5, 9)).toBe(5);
    expect(lineSet(undefined).count(1, 9)).toBe(0);
  });

  it('measures a report with huge line numbers without iterating over them', () => {
    const big = 1e12;
    const m = measure({
      files: [
        file('src/a.ts', {
          lines: big,
          newLines: [[1, big]],
          coverage: { covered: [[1, big]], uncovered: [], branches: [[big, 2, 1]] },
        }),
      ],
      duplications: [
        {
          blocks: [
            { path: 'src/a.ts', startLine: 1, endLine: big },
            { path: 'src/a.ts', startLine: 2, endLine: big },
          ],
        },
      ],
    });
    expect(m).toMatchObject({
      lines: big,
      new_lines: big,
      lines_to_cover: big,
      new_lines_to_cover: big,
      new_conditions_to_cover: 2,
      duplicated_lines: big,
      duplicated_blocks: 2,
      new_duplicated_lines: big,
      new_duplicated_blocks: 2,
    });
  });
});

describe('coverage over distinct lines (fix round 1)', () => {
  it('counts each line once, clamps to the file, and lets covered win over uncovered', () => {
    const counts = fileCoverageCounts(
      {
        covered: [
          [1, 5],
          [3, 6],
          [1, 5],
        ],
        uncovered: [
          [5, 8],
          [7, 7],
        ],
        branches: [
          [2, 2, 1],
          [2, 4, 3],
          [9, 2, 0],
        ],
      },
      7,
    );
    expect(counts).toEqual({
      linesToCover: 7,
      uncoveredLines: 1,
      conditionsToCover: 4,
      uncoveredConditions: 1,
    });
    expect(
      fileCoverageCounts({ covered: [[1, 6]], uncovered: [[7, 7]], branches: [[2, 4, 3]] }, 7, [
        [2, 3],
        [7, 9],
      ]),
    ).toEqual({ linesToCover: 3, uncoveredLines: 1, conditionsToCover: 4, uncoveredConditions: 1 });
  });

  it('does not let repeated ranges inflate the report measures', () => {
    const m = measure({
      files: [
        file('src/a.ts', {
          lines: 10,
          newLines: [
            [1, 4],
            [3, 20],
          ],
          coverage: {
            covered: [
              [1, 4],
              [1, 4],
            ],
            uncovered: [
              [4, 6],
              [9, 30],
            ],
            branches: [],
          },
        }),
      ],
    });
    expect(m).toMatchObject({
      lines_to_cover: 8,
      uncovered_lines: 4,
      coverage: 50,
      new_lines: 10,
      new_lines_to_cover: 8,
    });
  });

  it('intersects and subtracts merged ranges', () => {
    const a: [number, number][] = [
      [1, 5],
      [8, 12],
      [20, 30],
    ];
    const b: [number, number][] = [
      [3, 9],
      [11, 25],
    ];
    expect(intersectRanges(a, b)).toEqual([
      [3, 5],
      [8, 9],
      [11, 12],
      [20, 25],
    ]);
    expect(subtractRanges(a, b)).toEqual([
      [1, 2],
      [10, 10],
      [26, 30],
    ]);
    expect(subtractRanges([[1, 10]], [[1, 10]])).toEqual([]);
    expect(subtractRanges([[1, 10]], [])).toEqual([[1, 10]]);
  });
});
