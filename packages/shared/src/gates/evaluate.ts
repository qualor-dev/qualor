import { resolveMetricKey } from '../metrics';

export interface GateCondition {
  metric: string;
  operator: 'gt' | 'lt';
  threshold: number;
}

export interface Gate {
  id: string;
  name: string;
  conditions: readonly GateCondition[];
}

export type BranchKind = 'main' | 'branch' | 'merge_request';

export interface GateContext {
  branchKind: BranchKind;
  baselineStatus: 'ok' | 'unavailable' | 'first_analysis';
  smallChangesetLines?: number;
  warnings?: readonly string[];
}

export type Measures = Readonly<Record<string, number | null | undefined>>;
export type ConditionStatus = 'passed' | 'failed' | 'no_value';

export interface ConditionResult extends GateCondition {
  value: number | null;
  status: ConditionStatus;
}

export type IgnoreReason = 'overall_on_branch' | 'small_changeset';

export interface GateResult {
  status: 'passed' | 'failed' | 'error' | 'none';
  gate: { id: string; name: string } | null;
  conditions: ConditionResult[];
  ignoredConditions: { metric: string; reason: IgnoreReason }[];
  warnings: string[];
}

export const DEFAULT_SMALL_CHANGESET_LINES = 20;

export const SMALL_CHANGESET_METRICS: readonly string[] = [
  'new_coverage',
  'new_line_coverage',
  'new_branch_coverage',
  'new_duplicated_lines_density',
];

export const QUALOR_WAY_GATE: Gate = {
  id: 'builtin:qualor-way',
  name: 'Qualor way',
  conditions: [
    { metric: 'new_issues', operator: 'gt', threshold: 0 },
    { metric: 'new_coverage', operator: 'lt', threshold: 80 },
    { metric: 'new_duplicated_lines_density', operator: 'gt', threshold: 3 },
  ],
};

export class UnknownMetricError extends Error {
  constructor(readonly metric: string) {
    super(`unknown gate metric: ${metric}`);
    this.name = 'UnknownMetricError';
  }
}

/** One condition judged on the measures: `no_value` when the value is null (gates.md §6 rule 5). */
function judge(c: GateCondition, measures: Measures): ConditionResult {
  const raw = measures[c.metric];
  const value = typeof raw === 'number' ? raw : null;
  const failed =
    value !== null && (c.operator === 'gt' ? value > c.threshold : value < c.threshold);
  return {
    metric: c.metric,
    operator: c.operator,
    threshold: c.threshold,
    value,
    status: value === null ? 'no_value' : failed ? 'failed' : 'passed',
  };
}

/**
 * scm.md §7: a stored gate result judged again on new measure values, after an issue
 * transition. Each evaluated condition is judged on its new value; the ignored conditions, the
 * warnings and the gate stay as evaluated at ingestion (a gate edited since is not applied, gates.md
 * §8), and an `error` or `none` result stays as it is (nothing a transition changes can fix a
 * missing baseline or a missing gate). Pure: no I/O, no clock.
 */
export function reevaluateGate(previous: GateResult, measures: Measures): GateResult {
  if (previous.status === 'error' || previous.status === 'none') return previous;
  const conditions = previous.conditions.map((c) => judge(c, measures));
  return {
    ...previous,
    status: conditions.some((c) => c.status === 'failed') ? 'failed' : 'passed',
    conditions,
  };
}

/** gates.md §6. Pure: no I/O, no clock. */
export function evaluateGate(gate: Gate | null, measures: Measures, ctx: GateContext): GateResult {
  const warnings = [...(ctx.warnings ?? [])];
  if (gate === null) {
    return { status: 'none', gate: null, conditions: [], ignoredConditions: [], warnings };
  }
  const threshold = ctx.smallChangesetLines ?? DEFAULT_SMALL_CHANGESET_LINES;
  const newLines = measures['new_lines'];
  const small = threshold > 0 && typeof newLines === 'number' && newLines < threshold;
  const baselineUnavailable = ctx.baselineStatus === 'unavailable';

  const conditions: ConditionResult[] = [];
  const ignoredConditions: GateResult['ignoredConditions'] = [];
  let hasNewCondition = false;

  for (const c of gate.conditions) {
    const resolved = resolveMetricKey(c.metric);
    if (!resolved) throw new UnknownMetricError(c.metric);
    const isNew = resolved.scope === 'new';
    if (!isNew && ctx.branchKind !== 'main') {
      ignoredConditions.push({ metric: c.metric, reason: 'overall_on_branch' });
      continue;
    }
    if (small && !baselineUnavailable && SMALL_CHANGESET_METRICS.includes(c.metric)) {
      ignoredConditions.push({ metric: c.metric, reason: 'small_changeset' });
      continue;
    }
    if (isNew) hasNewCondition = true;
    conditions.push(judge(c, measures));
  }

  const summary = { id: gate.id, name: gate.name };
  if (baselineUnavailable && hasNewCondition) {
    warnings.push('NEW_CODE_UNAVAILABLE');
    return { status: 'error', gate: summary, conditions, ignoredConditions, warnings };
  }
  const status = conditions.some((c) => c.status === 'failed') ? 'failed' : 'passed';
  return { status, gate: summary, conditions, ignoredConditions, warnings };
}
