import type { Severity } from './report/taxonomy';

export type MetricType = 'int' | 'float' | 'percent' | 'rating';
export type MetricScope = 'overall' | 'new';
export type MetricDirection = 'lower_is_better' | 'higher_is_better' | 'none';

export interface MetricDefinition {
  key: string;
  name: string;
  type: MetricType;
  direction: MetricDirection;
  scopes: readonly MetricScope[];
  domain: 'size' | 'complexity' | 'issues' | 'ratings' | 'coverage' | 'duplication';
}

const OVERALL = ['overall'] as const;
const BOTH = ['overall', 'new'] as const;

function m(
  key: string,
  name: string,
  type: MetricType,
  direction: MetricDirection,
  scopes: readonly MetricScope[],
  domain: MetricDefinition['domain'],
): MetricDefinition {
  return { key, name, type, direction, scopes, domain };
}

const issueCount = (key: string, name: string) =>
  m(key, name, 'int', 'lower_is_better', BOTH, 'issues');

export const METRICS: readonly MetricDefinition[] = [
  m('files', 'Files', 'int', 'none', OVERALL, 'size'),
  m('lines', 'Lines', 'int', 'none', BOTH, 'size'),
  m('ncloc', 'Lines of code', 'int', 'none', OVERALL, 'size'),
  m('comment_lines', 'Comment lines', 'int', 'none', OVERALL, 'size'),
  m('functions', 'Functions', 'int', 'none', OVERALL, 'size'),
  m('classes', 'Classes', 'int', 'none', OVERALL, 'size'),
  m('statements', 'Statements', 'int', 'none', OVERALL, 'size'),
  m('complexity', 'Cyclomatic complexity', 'int', 'lower_is_better', OVERALL, 'complexity'),
  m(
    'cognitive_complexity',
    'Cognitive complexity',
    'int',
    'lower_is_better',
    OVERALL,
    'complexity',
  ),
  issueCount('issues', 'Issues'),
  issueCount('blocker_issues', 'Blocker issues'),
  issueCount('high_issues', 'High issues'),
  issueCount('medium_issues', 'Medium issues'),
  issueCount('low_issues', 'Low issues'),
  issueCount('info_issues', 'Info issues'),
  issueCount('security_issues', 'Security issues'),
  issueCount('reliability_issues', 'Reliability issues'),
  issueCount('maintainability_issues', 'Maintainability issues'),
  m('accepted_issues', "Won't fix issues", 'int', 'none', OVERALL, 'issues'),
  m('false_positive_issues', 'False positive issues', 'int', 'none', OVERALL, 'issues'),
  m('security_rating', 'Security rating', 'rating', 'lower_is_better', BOTH, 'ratings'),
  m('reliability_rating', 'Reliability rating', 'rating', 'lower_is_better', BOTH, 'ratings'),
  m('lines_to_cover', 'Lines to cover', 'int', 'none', BOTH, 'coverage'),
  m('uncovered_lines', 'Uncovered lines', 'int', 'lower_is_better', BOTH, 'coverage'),
  m('conditions_to_cover', 'Conditions to cover', 'int', 'none', BOTH, 'coverage'),
  m('uncovered_conditions', 'Uncovered conditions', 'int', 'lower_is_better', BOTH, 'coverage'),
  m('line_coverage', 'Line coverage', 'percent', 'higher_is_better', BOTH, 'coverage'),
  m('branch_coverage', 'Condition coverage', 'percent', 'higher_is_better', BOTH, 'coverage'),
  m('coverage', 'Coverage', 'percent', 'higher_is_better', BOTH, 'coverage'),
  m('duplicated_lines', 'Duplicated lines', 'int', 'lower_is_better', BOTH, 'duplication'),
  m('duplicated_blocks', 'Duplicated blocks', 'int', 'lower_is_better', BOTH, 'duplication'),
  m(
    'duplicated_lines_density',
    'Duplicated lines (%)',
    'percent',
    'lower_is_better',
    BOTH,
    'duplication',
  ),
];

const BY_KEY = new Map(METRICS.map((d) => [d.key, d]));

export function resolveMetricKey(
  key: string,
): { definition: MetricDefinition; scope: MetricScope } | undefined {
  const isNew = key.startsWith('new_');
  const base = isNew ? key.slice(4) : key;
  const scope: MetricScope = isNew ? 'new' : 'overall';
  const definition = BY_KEY.get(base);
  if (!definition || !definition.scopes.includes(scope)) return undefined;
  return { definition, scope };
}

export function allMetricKeys(): string[] {
  return METRICS.flatMap((d) => d.scopes.map((s) => (s === 'new' ? `new_${d.key}` : d.key)));
}

export function ratio(numerator: number, denominator: number): number | null {
  if (denominator === 0) return null;
  return Math.round((numerator / denominator) * 1000) / 10;
}

const RATING: Record<Severity, 1 | 2 | 3 | 4 | 5> = {
  info: 1,
  low: 2,
  medium: 3,
  high: 4,
  blocker: 5,
};

export function ratingFromSeverities(severities: Iterable<Severity>): 1 | 2 | 3 | 4 | 5 {
  let worst: 1 | 2 | 3 | 4 | 5 = 1;
  for (const s of severities) if (RATING[s] > worst) worst = RATING[s];
  return worst;
}

export interface CoverageCounts {
  linesToCover: number;
  uncoveredLines: number;
  conditionsToCover: number;
  uncoveredConditions: number;
}

type CoverageKey =
  | 'lines_to_cover'
  | 'uncovered_lines'
  | 'conditions_to_cover'
  | 'uncovered_conditions'
  | 'line_coverage'
  | 'branch_coverage'
  | 'coverage';

export function coverageMeasures(c: CoverageCounts | null): Record<CoverageKey, number | null> {
  if (c === null) {
    return {
      lines_to_cover: null,
      uncovered_lines: null,
      conditions_to_cover: null,
      uncovered_conditions: null,
      line_coverage: null,
      branch_coverage: null,
      coverage: null,
    };
  }
  const coveredLines = c.linesToCover - c.uncoveredLines;
  const coveredConditions = c.conditionsToCover - c.uncoveredConditions;
  return {
    lines_to_cover: c.linesToCover,
    uncovered_lines: c.uncoveredLines,
    conditions_to_cover: c.conditionsToCover,
    uncovered_conditions: c.uncoveredConditions,
    line_coverage: ratio(coveredLines, c.linesToCover),
    branch_coverage: ratio(coveredConditions, c.conditionsToCover),
    coverage: ratio(coveredLines + coveredConditions, c.linesToCover + c.conditionsToCover),
  };
}
