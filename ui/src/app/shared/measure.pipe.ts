import { LOCALE_ID, Pipe, type PipeTransform, inject } from '@angular/core';

const PERCENT = /(^|_)(coverage|density)$/;
const RATINGS = ['A', 'B', 'C', 'D', 'E'];

/**
 * A measure as people read it: ratings 1–5 as A–E, coverage and densities as "65.7 %", counts
 * with grouping, and "–" for no value (never analysed, nothing to measure, or not a number).
 */
export function formatMeasure(
  value: number | null | undefined,
  metric: string,
  locale = 'en-US',
): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return '–';
  if (metric.endsWith('_rating')) return RATINGS[Math.round(value) - 1] ?? String(value);
  if (PERCENT.test(metric)) {
    return `${new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(value)} %`;
  }
  return new Intl.NumberFormat(locale, { maximumFractionDigits: 1 }).format(value);
}

/** `{{ measures['coverage'] | measure: 'coverage' }}` → "65.7 %". */
@Pipe({ name: 'measure' })
export class MeasurePipe implements PipeTransform {
  private readonly locale = inject(LOCALE_ID);

  transform(value: number | null | undefined, metric: string): string {
    return formatMeasure(value, metric, this.locale);
  }
}
