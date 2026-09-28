import { describe, expect, it } from 'vitest';
import {
  evaluateGate,
  QUALOR_WAY_GATE,
  reevaluateGate,
  UnknownMetricError,
  type Gate,
  type GateContext,
} from './evaluate';

const main: GateContext = { branchKind: 'main', baselineStatus: 'ok' };
const mr: GateContext = { branchKind: 'merge_request', baselineStatus: 'ok' };
const gate = (conditions: Gate['conditions']): Gate => ({
  id: 'g1',
  name: 'Test',
  conditions,
});

describe('evaluateGate', () => {
  it('returns none without a gate (§6.1)', () => {
    expect(evaluateGate(null, {}, main)).toEqual({
      status: 'none',
      gate: null,
      conditions: [],
      ignoredConditions: [],
      warnings: [],
    });
  });

  it('fails when value op threshold holds, passes otherwise (§4, §6.6)', () => {
    const g = gate([
      { metric: 'new_issues', operator: 'gt', threshold: 0 },
      { metric: 'coverage', operator: 'lt', threshold: 80 },
    ]);
    const r = evaluateGate(g, { new_issues: 0, coverage: 80, new_lines: 100 }, main);
    expect(r.status).toBe('passed');
    expect(r.conditions.map((c) => c.status)).toEqual(['passed', 'passed']);
    const f = evaluateGate(g, { new_issues: 1, coverage: 79.9, new_lines: 100 }, main);
    expect(f.status).toBe('failed');
    expect(f.conditions).toEqual([
      { metric: 'new_issues', operator: 'gt', threshold: 0, value: 1, status: 'failed' },
      { metric: 'coverage', operator: 'lt', threshold: 80, value: 79.9, status: 'failed' },
    ]);
  });

  it('only evaluates new_* conditions on MRs and branches (§6.2)', () => {
    const g = gate([
      { metric: 'coverage', operator: 'lt', threshold: 80 },
      { metric: 'new_issues', operator: 'gt', threshold: 0 },
    ]);
    for (const ctx of [mr, { ...mr, branchKind: 'branch' as const }]) {
      const r = evaluateGate(g, { coverage: 10, new_issues: 0, new_lines: 50 }, ctx);
      expect(r.status).toBe('passed');
      expect(r.conditions.map((c) => c.metric)).toEqual(['new_issues']);
      expect(r.ignoredConditions).toEqual([{ metric: 'coverage', reason: 'overall_on_branch' }]);
    }
  });

  it('ignores coverage/duplication conditions on small changesets (§6.3)', () => {
    const r = evaluateGate(
      QUALOR_WAY_GATE,
      { new_issues: 0, new_coverage: 0, new_duplicated_lines_density: 50, new_lines: 12 },
      mr,
    );
    expect(r.status).toBe('passed');
    expect(r.ignoredConditions).toEqual([
      { metric: 'new_coverage', reason: 'small_changeset' },
      { metric: 'new_duplicated_lines_density', reason: 'small_changeset' },
    ]);
  });

  it('small changeset threshold is configurable and 0 disables it', () => {
    const m = { new_issues: 0, new_coverage: 0, new_duplicated_lines_density: 0, new_lines: 12 };
    expect(evaluateGate(QUALOR_WAY_GATE, m, { ...mr, smallChangesetLines: 0 }).status).toBe(
      'failed',
    );
    expect(evaluateGate(QUALOR_WAY_GATE, m, { ...mr, smallChangesetLines: 10 }).status).toBe(
      'failed',
    );
    expect(evaluateGate(QUALOR_WAY_GATE, { ...m, new_lines: 20 }, mr).status).toBe('failed');
  });

  it('returns error when new-code conditions exist but the baseline is unavailable (§6.4)', () => {
    const r = evaluateGate(
      QUALOR_WAY_GATE,
      { new_issues: null, new_lines: null },
      {
        ...mr,
        baselineStatus: 'unavailable',
      },
    );
    expect(r.status).toBe('error');
    expect(r.warnings).toContain('NEW_CODE_UNAVAILABLE');
    expect(r.ignoredConditions).toEqual([]);
    expect(r.conditions.every((c) => c.status === 'no_value')).toBe(true);
  });

  it('does not error on unavailable baseline when only overall conditions remain', () => {
    const g = gate([{ metric: 'coverage', operator: 'lt', threshold: 50 }]);
    expect(
      evaluateGate(g, { coverage: 60 }, { ...main, baselineStatus: 'unavailable' }).status,
    ).toBe('passed');
  });

  it('treats null/missing values as no_value that does not fail (§6.5)', () => {
    const g = gate([
      { metric: 'new_coverage', operator: 'lt', threshold: 80 },
      { metric: 'new_issues', operator: 'gt', threshold: 0 },
    ]);
    const r = evaluateGate(g, { new_coverage: null, new_issues: 0, new_lines: 100 }, main);
    expect(r.status).toBe('passed');
    expect(r.conditions[0]).toMatchObject({ value: null, status: 'no_value' });
    const missing = evaluateGate(g, { new_lines: 100 }, main);
    expect(missing.conditions.map((c) => c.status)).toEqual(['no_value', 'no_value']);
  });

  it('first analysis on main: new counts are 0 and the gate passes', () => {
    const r = evaluateGate(
      QUALOR_WAY_GATE,
      { new_issues: 0, new_lines: 0, new_coverage: null, new_duplicated_lines_density: null },
      { ...main, baselineStatus: 'first_analysis' },
    );
    expect(r.status).toBe('passed');
  });

  it('passes context warnings through', () => {
    expect(
      evaluateGate(
        QUALOR_WAY_GATE,
        { new_issues: 0, new_lines: 0 },
        {
          ...main,
          warnings: ['NEW_CODE_DEFINITION_FALLBACK'],
        },
      ).warnings,
    ).toEqual(['NEW_CODE_DEFINITION_FALLBACK']);
  });

  it('rejects unknown metrics', () => {
    expect(() =>
      evaluateGate(gate([{ metric: 'new_ncloc', operator: 'gt', threshold: 0 }]), {}, main),
    ).toThrow(UnknownMetricError);
  });

  it('QUALOR_WAY_GATE matches gates.md §7', () => {
    expect(QUALOR_WAY_GATE.conditions).toEqual([
      { metric: 'new_issues', operator: 'gt', threshold: 0 },
      { metric: 'new_coverage', operator: 'lt', threshold: 80 },
      { metric: 'new_duplicated_lines_density', operator: 'gt', threshold: 3 },
    ]);
  });

  it('gates.md §9.6: 12 new lines at 0% coverage pass the default gate', () => {
    expect(
      evaluateGate(QUALOR_WAY_GATE, { new_issues: 0, new_coverage: 0, new_lines: 12 }, mr).status,
    ).toBe('passed');
  });
});

describe('reevaluateGate (scm.md §7)', () => {
  const small: GateContext = { ...mr, smallChangesetLines: 20 };
  const stored = evaluateGate(
    gate([
      { metric: 'new_issues', operator: 'gt', threshold: 0 },
      { metric: 'new_coverage', operator: 'lt', threshold: 80 },
      { metric: 'issues', operator: 'gt', threshold: 10 },
    ]),
    { new_issues: 1, new_coverage: 10, new_lines: 5, issues: 50 },
    small,
  );

  it('judges the evaluated conditions again and keeps what ingestion ignored', () => {
    expect(stored.status).toBe('failed');
    expect(stored.ignoredConditions).toEqual([
      { metric: 'new_coverage', reason: 'small_changeset' },
      { metric: 'issues', reason: 'overall_on_branch' },
    ]);
    const again = reevaluateGate(stored, { new_issues: 0, new_coverage: 10, issues: 50 });
    expect(again).toEqual({
      ...stored,
      status: 'passed',
      conditions: [
        { metric: 'new_issues', operator: 'gt', threshold: 0, value: 0, status: 'passed' },
      ],
    });
    expect(reevaluateGate(again, { new_issues: 2 }).status).toBe('failed');
    expect(reevaluateGate(again, {}).conditions[0]?.status).toBe('no_value');
    expect(reevaluateGate(again, {}).status).toBe('passed');
  });

  it('leaves an error or none result as it is', () => {
    const error = evaluateGate(
      gate([{ metric: 'new_issues', operator: 'gt', threshold: 0 }]),
      { new_issues: null },
      { ...mr, baselineStatus: 'unavailable' },
    );
    expect(error.status).toBe('error');
    expect(reevaluateGate(error, { new_issues: 0 })).toBe(error);
    const none = evaluateGate(null, {}, main);
    expect(reevaluateGate(none, { new_issues: 5 })).toBe(none);
  });
});
