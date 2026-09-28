import { resolveMetricKey, type MetricDefinition } from '../../metrics';

export interface SonarCondition {
  metric: string;
  op: string;
  error: string;
}

export type ConditionMapping =
  | { ok: true; metric: string; operator: 'gt' | 'lt'; threshold: number; approximate: boolean }
  | { ok: false; reason: 'metric' | 'operator' | 'threshold' | 'threshold_out_of_range' };

export interface SonarMetricTarget {
  qualor: string;
  approximate?: true;
}

/** Spec §8.2, keyed by the SonarQube metric without `new_`; the scope is checked in the catalog. */
export const SONAR_METRIC_TARGETS: Readonly<Record<string, SonarMetricTarget>> = {
  violations: { qualor: 'issues' },
  /** Counts only the OPEN status, not CONFIRMED or REOPENED. */
  open_issues: { qualor: 'issues', approximate: true },
  blocker_violations: { qualor: 'blocker_issues' },
  critical_violations: { qualor: 'high_issues' },
  major_violations: { qualor: 'medium_issues' },
  minor_violations: { qualor: 'low_issues' },
  info_violations: { qualor: 'info_issues' },
  software_quality_blocker_issues: { qualor: 'blocker_issues' },
  software_quality_high_issues: { qualor: 'high_issues' },
  software_quality_medium_issues: { qualor: 'medium_issues' },
  software_quality_low_issues: { qualor: 'low_issues' },
  software_quality_info_issues: { qualor: 'info_issues' },
  bugs: { qualor: 'reliability_issues', approximate: true },
  software_quality_reliability_issues: { qualor: 'reliability_issues' },
  vulnerabilities: { qualor: 'security_issues', approximate: true },
  software_quality_security_issues: { qualor: 'security_issues' },
  code_smells: { qualor: 'maintainability_issues', approximate: true },
  software_quality_maintainability_issues: { qualor: 'maintainability_issues' },
  /** Legacy ratings grade bugs and vulnerabilities (types), Qualor's grade software qualities. */
  reliability_rating: { qualor: 'reliability_rating', approximate: true },
  software_quality_reliability_rating: { qualor: 'reliability_rating' },
  security_rating: { qualor: 'security_rating', approximate: true },
  software_quality_security_rating: { qualor: 'security_rating' },
  accepted_issues: { qualor: 'accepted_issues' },
  wont_fix_issues: { qualor: 'accepted_issues' },
  false_positive_issues: { qualor: 'false_positive_issues' },
  coverage: { qualor: 'coverage' },
  line_coverage: { qualor: 'line_coverage' },
  branch_coverage: { qualor: 'branch_coverage' },
  lines_to_cover: { qualor: 'lines_to_cover' },
  uncovered_lines: { qualor: 'uncovered_lines' },
  conditions_to_cover: { qualor: 'conditions_to_cover' },
  uncovered_conditions: { qualor: 'uncovered_conditions' },
  duplicated_lines: { qualor: 'duplicated_lines' },
  duplicated_blocks: { qualor: 'duplicated_blocks' },
  duplicated_lines_density: { qualor: 'duplicated_lines_density' },
  lines: { qualor: 'lines' },
  ncloc: { qualor: 'ncloc' },
  files: { qualor: 'files' },
  functions: { qualor: 'functions' },
  classes: { qualor: 'classes' },
  statements: { qualor: 'statements' },
  comment_lines: { qualor: 'comment_lines' },
  complexity: { qualor: 'complexity' },
  cognitive_complexity: { qualor: 'cognitive_complexity' },
};

const NUMBER = /^-?\d{1,16}(?:\.\d{1,16})?$/;

/** Ruling G3's bounds, which the gates API enforces too (a 422 otherwise). */
function fits(d: MetricDefinition, t: number): boolean {
  if (d.type === 'rating') return Number.isInteger(t) && t >= 1 && t <= 5;
  if (d.type === 'percent') return t >= 0 && t <= 100;
  if (d.type === 'int') return Number.isInteger(t) && t >= 0 && t <= Number.MAX_SAFE_INTEGER;
  return Number.isFinite(t);
}

export function mapGateCondition(c: SonarCondition): ConditionMapping {
  const isNew = c.metric.startsWith('new_');
  const base = isNew ? c.metric.slice(4) : c.metric;
  const target = Object.hasOwn(SONAR_METRIC_TARGETS, base) ? SONAR_METRIC_TARGETS[base] : undefined;
  if (target === undefined) return { ok: false, reason: 'metric' };
  const metric = isNew ? `new_${target.qualor}` : target.qualor;
  const resolved = resolveMetricKey(metric);
  if (resolved === undefined) return { ok: false, reason: 'metric' };
  const operator = c.op === 'GT' ? 'gt' : c.op === 'LT' ? 'lt' : null;
  if (operator === null) return { ok: false, reason: 'operator' };
  const text = c.error.trim();
  if (!NUMBER.test(text)) return { ok: false, reason: 'threshold' };
  const threshold = Number(text);
  if (!fits(resolved.definition, threshold)) return { ok: false, reason: 'threshold_out_of_range' };
  return { ok: true, metric, operator, threshold, approximate: target.approximate === true };
}
