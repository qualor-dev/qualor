import { readGateResult } from './gate-result';

describe('readGateResult', () => {
  it('reads the gate result the server stores (gates.md §6)', () => {
    expect(
      readGateResult({
        gate: { id: 'g', name: 'Qualor way' },
        status: 'failed',
        warnings: ['NEW_CODE_BASELINE_MISSING'],
        conditions: [
          { value: 2, metric: 'new_issues', status: 'failed', operator: 'gt', threshold: 0 },
          {
            value: null,
            metric: 'new_coverage',
            status: 'no_value',
            operator: 'lt',
            threshold: 80,
          },
        ],
        ignoredConditions: [{ metric: 'new_duplicated_lines_density', reason: 'small_changeset' }],
      }),
    ).toEqual({
      status: 'failed',
      gateName: 'Qualor way',
      conditions: [
        { metric: 'new_issues', operator: 'gt', threshold: 0, value: 2, status: 'failed' },
        { metric: 'new_coverage', operator: 'lt', threshold: 80, value: null, status: 'no_value' },
      ],
      ignored: [{ metric: 'new_duplicated_lines_density', reason: 'small_changeset' }],
      warnings: ['NEW_CODE_BASELINE_MISSING'],
    });
  });

  it('drops malformed parts and rejects a result without a known status', () => {
    expect(readGateResult(null)).toBeNull();
    expect(readGateResult({ status: 'maybe' })).toBeNull();
    expect(
      readGateResult({
        status: 'none',
        gate: null,
        conditions: [{ metric: 1 }, 'x'],
        warnings: [3],
      }),
    ).toEqual({ status: 'none', gateName: null, conditions: [], ignored: [], warnings: [] });
  });

  it('keeps a bounded number of conditions and warnings', () => {
    const condition = {
      value: 1,
      metric: 'issues',
      status: 'passed',
      operator: 'gt',
      threshold: 0,
    };
    const result = readGateResult({
      status: 'passed',
      conditions: Array.from({ length: 1000 }, () => condition),
      ignoredConditions: Array.from({ length: 1000 }, () => ({ metric: 'm', reason: 'r' })),
      warnings: Array.from({ length: 1000 }, () => 'W'),
    });
    expect(result?.conditions).toHaveLength(100);
    expect(result?.ignored).toHaveLength(100);
    expect(result?.warnings).toHaveLength(100);
  });
});
