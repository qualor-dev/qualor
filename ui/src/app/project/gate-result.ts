/**
 * The `gateResult` of an analysis (gates.md §6). The OpenAPI document types it as an open object,
 * so the UI reads it defensively: anything malformed is left out rather than trusted, and each list
 * is cut to a size a page can show.
 */
export interface ConditionView {
  metric: string;
  operator: 'gt' | 'lt';
  threshold: number;
  value: number | null;
  status: 'passed' | 'failed' | 'no_value';
}

export interface GateResultView {
  status: 'passed' | 'failed' | 'error' | 'none';
  gateName: string | null;
  conditions: ConditionView[];
  ignored: { metric: string; reason: string }[];
  warnings: string[];
}

/** More conditions than any gate has; a larger list is not a gate result worth drawing. */
const MAX_ITEMS = 100;

const record = (v: unknown): Record<string, unknown> | null =>
  typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
const oneOf = <T extends string>(v: unknown, values: readonly T[]): v is T =>
  typeof v === 'string' && (values as readonly string[]).includes(v);
const list = (v: unknown): unknown[] => (Array.isArray(v) ? v : []);

export function readGateResult(raw: unknown): GateResultView | null {
  const r = record(raw);
  if (!r || !oneOf(r['status'], ['passed', 'failed', 'error', 'none'] as const)) return null;
  const gate = record(r['gate']);
  const conditions = list(r['conditions'])
    .flatMap((c) => {
      const x = record(c);
      if (
        !x ||
        typeof x['metric'] !== 'string' ||
        !oneOf(x['operator'], ['gt', 'lt'] as const) ||
        typeof x['threshold'] !== 'number' ||
        !oneOf(x['status'], ['passed', 'failed', 'no_value'] as const)
      ) {
        return [];
      }
      const value = typeof x['value'] === 'number' ? x['value'] : null;
      return [
        {
          metric: x['metric'],
          operator: x['operator'],
          threshold: x['threshold'],
          value,
          status: x['status'],
        },
      ];
    })
    .slice(0, MAX_ITEMS);
  const ignored = list(r['ignoredConditions'])
    .flatMap((c) => {
      const x = record(c);
      return x && typeof x['metric'] === 'string' && typeof x['reason'] === 'string'
        ? [{ metric: x['metric'], reason: x['reason'] }]
        : [];
    })
    .slice(0, MAX_ITEMS);
  const warnings = list(r['warnings'])
    .filter((w): w is string => typeof w === 'string')
    .slice(0, MAX_ITEMS);
  return {
    status: r['status'],
    gateName: gate && typeof gate['name'] === 'string' ? gate['name'] : null,
    conditions,
    ignored,
    warnings,
  };
}

export function operatorLabel(operator: 'gt' | 'lt'): string {
  return operator === 'gt'
    ? $localize`:@@gate.operator.gt:is greater than`
    : $localize`:@@gate.operator.lt:is less than`;
}

export function ignoredReasonLabel(reason: string): string {
  switch (reason) {
    case 'overall_on_branch':
      return $localize`:@@gate.ignored.overallOnBranch:Applies to the main branch only`;
    case 'small_changeset':
      return $localize`:@@gate.ignored.smallChangeset:Skipped for a small change`;
    default:
      return reason;
  }
}

export function conditionStatusLabel(status: ConditionView['status']): string {
  switch (status) {
    case 'passed':
      return $localize`:@@gate.condition.passed:Passed`;
    case 'failed':
      return $localize`:@@gate.condition.failed:Failed`;
    default:
      return $localize`:@@gate.condition.noValue:No value`;
  }
}

/** The badge colour of a condition's result (`no_value` is neutral). */
export function conditionTone(status: ConditionView['status']): string {
  return status === 'no_value' ? 'none' : status;
}
