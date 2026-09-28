import { describe, expect, it } from 'vitest';
import {
  allMetricKeys,
  coverageMeasures,
  METRICS,
  ratingFromSeverities,
  ratio,
  resolveMetricKey,
} from './metrics';

describe('metric catalog', () => {
  it('has unique base keys', () => {
    const keys = METRICS.map((m) => m.key);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it('contains every metric named in gates.md §2', () => {
    const expected = [
      'files',
      'lines',
      'ncloc',
      'comment_lines',
      'functions',
      'classes',
      'statements',
      'complexity',
      'cognitive_complexity',
      'issues',
      'blocker_issues',
      'high_issues',
      'medium_issues',
      'low_issues',
      'info_issues',
      'security_issues',
      'reliability_issues',
      'maintainability_issues',
      'accepted_issues',
      'false_positive_issues',
      'security_rating',
      'reliability_rating',
      'lines_to_cover',
      'uncovered_lines',
      'conditions_to_cover',
      'uncovered_conditions',
      'line_coverage',
      'branch_coverage',
      'coverage',
      'duplicated_lines',
      'duplicated_blocks',
      'duplicated_lines_density',
    ];
    expect(METRICS.map((m) => m.key).sort()).toEqual([...expected].sort());
  });

  it('resolves scoped keys', () => {
    expect(resolveMetricKey('new_coverage')).toMatchObject({
      scope: 'new',
      definition: { key: 'coverage' },
    });
    expect(resolveMetricKey('coverage')).toMatchObject({ scope: 'overall' });
    expect(resolveMetricKey('new_lines')).toMatchObject({
      scope: 'new',
      definition: { key: 'lines' },
    });
    expect(resolveMetricKey('new_ncloc')).toBeUndefined();
    expect(resolveMetricKey('new_accepted_issues')).toBeUndefined();
    expect(resolveMetricKey('nope')).toBeUndefined();
  });

  it('lists scoped keys', () => {
    const keys = allMetricKeys();
    expect(keys).toContain('new_issues');
    expect(keys).toContain('ncloc');
    expect(keys).not.toContain('new_ncloc');
  });
});

describe('ratio', () => {
  it('returns a percentage rounded to one decimal, null for empty denominators', () => {
    expect(ratio(1, 3)).toBe(33.3);
    expect(ratio(2, 3)).toBe(66.7);
    expect(ratio(0, 0)).toBeNull();
  });
});

describe('ratingFromSeverities', () => {
  it.each([
    [[], 1],
    [['info'], 1],
    [['low', 'info'], 2],
    [['medium', 'low'], 3],
    [['high'], 4],
    [['low', 'blocker', 'high'], 5],
  ] as const)('%j → %i', (sev, rating) => {
    expect(ratingFromSeverities(sev)).toBe(rating);
  });
});

describe('coverageMeasures', () => {
  it('follows the Sonar formulas', () => {
    expect(
      coverageMeasures({
        linesToCover: 10,
        uncoveredLines: 2,
        conditionsToCover: 4,
        uncoveredConditions: 1,
      }),
    ).toEqual({
      lines_to_cover: 10,
      uncovered_lines: 2,
      conditions_to_cover: 4,
      uncovered_conditions: 1,
      line_coverage: 80,
      branch_coverage: 75,
      coverage: 78.6,
    });
  });

  it('returns nulls when no coverage was imported', () => {
    expect(Object.values(coverageMeasures(null)).every((v) => v === null)).toBe(true);
  });

  it('returns null ratios for zero denominators', () => {
    expect(
      coverageMeasures({
        linesToCover: 0,
        uncoveredLines: 0,
        conditionsToCover: 0,
        uncoveredConditions: 0,
      }),
    ).toMatchObject({
      lines_to_cover: 0,
      line_coverage: null,
      branch_coverage: null,
      coverage: null,
    });
  });
});
