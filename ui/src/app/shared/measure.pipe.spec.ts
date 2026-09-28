import { formatMeasure } from './measure.pipe';

describe('formatMeasure', () => {
  it('formats ratings, percentages, counts and missing values', () => {
    expect(formatMeasure(1, 'security_rating')).toBe('A');
    expect(formatMeasure(5, 'new_reliability_rating')).toBe('E');
    expect(formatMeasure(65.74, 'coverage')).toBe('65.7 %');
    expect(formatMeasure(3, 'new_duplicated_lines_density')).toBe('3 %');
    expect(formatMeasure(12345, 'ncloc')).toBe('12,345');
    expect(formatMeasure(null, 'coverage')).toBe('–');
    expect(formatMeasure(undefined, 'issues')).toBe('–');
  });

  it('shows a value it cannot read as missing rather than as NaN', () => {
    expect(formatMeasure(Number.NaN, 'coverage')).toBe('–');
    expect(formatMeasure(Number.POSITIVE_INFINITY, 'ncloc')).toBe('–');
  });
});
