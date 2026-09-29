/**
 * Which way a metric should move, as the server's metric catalog says
 * (`packages/shared/src/metrics.ts`; `tools/ui/metric-direction.test.ts` keeps the two equal).
 * A delta is green when it moves the good way, red when the bad way, grey without a direction.
 */
export type Direction = 'lower_is_better' | 'higher_is_better' | 'none';

const HIGHER = new Set(['coverage', 'line_coverage', 'branch_coverage']);
const NONE = new Set([
  'files',
  'lines',
  'ncloc',
  'comment_lines',
  'functions',
  'classes',
  'statements',
  'lines_to_cover',
  'conditions_to_cover',
  'accepted_issues',
  'false_positive_issues',
]);
const PERCENT = /(^|_)(coverage|density)$/;

const base = (metric: string) => (metric.startsWith('new_') ? metric.slice(4) : metric);

export function direction(metric: string): Direction {
  const key = base(metric);
  if (HIGHER.has(key)) return 'higher_is_better';
  if (NONE.has(key)) return 'none';
  return 'lower_is_better';
}

/** Coverages and densities, shown as "65.7 %" and changing by "pts". */
export function isPercentMetric(metric: string): boolean {
  return PERCENT.test(base(metric));
}
