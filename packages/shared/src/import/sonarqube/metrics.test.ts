import { describe, expect, it } from 'vitest';
import { resolveMetricKey } from '../../metrics';
import { mapGateCondition, SONAR_METRIC_TARGETS } from './metrics';

const map = (metric: string, op = 'GT', error = '0') => mapGateCondition({ metric, op, error });

describe('mapGateCondition (import-sonarqube.md §8.2)', () => {
  it("maps the conditions of SonarQube's default gate that Qualor has", () => {
    expect(map('new_violations')).toEqual({
      ok: true,
      metric: 'new_issues',
      operator: 'gt',
      threshold: 0,
      approximate: false,
    });
    expect(map('new_coverage', 'LT', '80')).toMatchObject({
      ok: true,
      metric: 'new_coverage',
      operator: 'lt',
      threshold: 80,
    });
    expect(map('new_duplicated_lines_density', 'GT', '3')).toMatchObject({
      ok: true,
      metric: 'new_duplicated_lines_density',
    });
    expect(map('new_security_hotspots_reviewed', 'LT', '100')).toEqual({
      ok: false,
      reason: 'metric',
    });
  });

  it.each([
    ['critical_violations', 'high_issues'],
    ['new_major_violations', 'new_medium_issues'],
    ['software_quality_blocker_issues', 'blocker_issues'],
    ['new_software_quality_reliability_rating', 'new_reliability_rating'],
    ['open_issues', 'issues'],
    ['wont_fix_issues', 'accepted_issues'],
    ['new_lines', 'new_lines'],
    ['cognitive_complexity', 'cognitive_complexity'],
  ])('maps %s to %s', (sonar, qualor) => {
    expect(map(sonar, 'GT', '1')).toMatchObject({ ok: true, metric: qualor });
  });

  it('flags type-based issue counts as approximate', () => {
    expect(map('new_bugs')).toMatchObject({
      ok: true,
      metric: 'new_reliability_issues',
      approximate: true,
    });
    expect(map('vulnerabilities')).toMatchObject({ metric: 'security_issues', approximate: true });
  });

  it('flags legacy ratings and open_issues as approximate, never the software-quality counts', () => {
    expect(map('reliability_rating', 'GT', '1')).toMatchObject({ ok: true, approximate: true });
    expect(map('new_security_rating', 'GT', '1')).toMatchObject({ ok: true, approximate: true });
    expect(map('open_issues')).toMatchObject({ ok: true, metric: 'issues', approximate: true });
    expect(map('violations')).toMatchObject({ ok: true, approximate: false });
    for (const q of ['reliability', 'security', 'maintainability', 'blocker', 'high', 'info']) {
      expect(map(`software_quality_${q}_issues`)).toMatchObject({ ok: true, approximate: false });
      expect(map(`new_software_quality_${q}_issues`)).toMatchObject({ approximate: false });
    }
    expect(map('software_quality_reliability_rating', 'GT', '1')).toMatchObject({
      approximate: false,
    });
  });

  it('points every table entry at a metric the catalog has overall', () => {
    for (const [sonar, target] of Object.entries(SONAR_METRIC_TARGETS)) {
      expect(resolveMetricKey(target.qualor)?.scope, sonar).toBe('overall');
    }
  });

  it('maps an LT rating condition', () => {
    expect(map('software_quality_security_rating', 'LT', '2')).toEqual({
      ok: true,
      metric: 'security_rating',
      operator: 'lt',
      threshold: 2,
      approximate: false,
    });
  });

  it('takes counts up to 2^53-1 and percentages with decimals, refusing .5 and negatives', () => {
    expect(map('violations', 'GT', String(Number.MAX_SAFE_INTEGER))).toMatchObject({
      ok: true,
      threshold: Number.MAX_SAFE_INTEGER,
    });
    expect(map('violations', 'GT', '9007199254740992')).toEqual({
      ok: false,
      reason: 'threshold_out_of_range',
    });
    expect(map('coverage', 'LT', '80.5')).toMatchObject({ ok: true, threshold: 80.5 });
    expect(map('coverage', 'LT', '.5')).toEqual({ ok: false, reason: 'threshold' });
    expect(map('coverage', 'LT', '-0.5')).toEqual({ ok: false, reason: 'threshold_out_of_range' });
    expect(map('duplicated_lines_density', 'GT', '-3')).toEqual({
      ok: false,
      reason: 'threshold_out_of_range',
    });
  });

  it.each(['constructor', 'new_constructor', '__proto__', 'toString', 'hasOwnProperty'])(
    'does not map the object property %s',
    (metric) => {
      expect(map(metric)).toEqual({ ok: false, reason: 'metric' });
    },
  );

  it('reports an operator it does not know as unmapped', () => {
    expect(map('new_violations', 'NE', '0')).toEqual({ ok: false, reason: 'operator' });
    expect(map('new_violations', 'GTE', '0')).toEqual({ ok: false, reason: 'operator' });
  });

  it('refuses metrics Qualor lacks, and new_ scopes the catalog does not have', () => {
    expect(map('new_maintainability_rating')).toEqual({ ok: false, reason: 'metric' });
    expect(map('sqale_index')).toEqual({ ok: false, reason: 'metric' });
    expect(map('new_accepted_issues')).toEqual({ ok: false, reason: 'metric' });
    expect(map('new_complexity')).toEqual({ ok: false, reason: 'metric' });
  });

  it('refuses other operators and thresholds that are not numbers or do not fit the catalog', () => {
    expect(map('coverage', 'EQ', '80')).toEqual({ ok: false, reason: 'operator' });
    expect(map('coverage', 'LT', '80%')).toEqual({ ok: false, reason: 'threshold' });
    expect(map('coverage', 'LT', '')).toEqual({ ok: false, reason: 'threshold' });
    expect(map('coverage', 'LT', '120')).toEqual({ ok: false, reason: 'threshold_out_of_range' });
    expect(map('security_rating', 'GT', '1.5')).toEqual({
      ok: false,
      reason: 'threshold_out_of_range',
    });
    expect(map('security_rating', 'GT', '6')).toEqual({
      ok: false,
      reason: 'threshold_out_of_range',
    });
    expect(map('violations', 'GT', '-1')).toEqual({ ok: false, reason: 'threshold_out_of_range' });
  });
});
