import { describe, expect, it } from 'vitest';
import { METRICS } from '../../packages/shared/src/metrics';
import { direction, isPercentMetric } from '../../ui/src/app/charts/direction';

describe("the UI's metric directions", () => {
  it('match the metric catalog for every metric and its new-code variant', () => {
    for (const m of METRICS) {
      expect([m.key, direction(m.key)]).toEqual([m.key, m.direction]);
      expect([`new_${m.key}`, direction(`new_${m.key}`)]).toEqual([`new_${m.key}`, m.direction]);
    }
  });

  it('know which metrics are percentages', () => {
    for (const m of METRICS) {
      expect([m.key, isPercentMetric(m.key)]).toEqual([m.key, m.type === 'percent']);
    }
  });
});
