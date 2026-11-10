import { Component, LOCALE_ID, computed, inject, input } from '@angular/core';
import { DateTimePipe } from '../shared/date-time.pipe';
import { direction, isPercentMetric, type Direction } from './direction';

export interface DeltaView {
  text: string;
  tone: 'good' | 'bad' | 'neutral';
}

/** The tone of a non-zero change: good or bad by the metric's direction, neutral without one. */
function changeTone(change: number, way: Direction): DeltaView['tone'] {
  if (way === 'none') return 'neutral';
  return change < 0 === (way === 'lower_is_better') ? 'good' : 'bad';
}

/**
 * The change of a metric since the previous analysis, rounded to one decimal: coloured by the
 * metric's good direction, grey for metrics without one; percentages change by "pts".
 */
export function deltaView(
  metric: string,
  current: number | null,
  previous: number | null,
  locale: string,
): DeltaView | null {
  if (current === null || previous === null) return null;
  if (!Number.isFinite(current) || !Number.isFinite(previous)) return null;
  const change = Math.round((current - previous) * 10) / 10;
  if (change === 0) return { text: $localize`:@@delta.none:No change`, tone: 'neutral' };
  const tone = changeTone(change, direction(metric));
  const number = new Intl.NumberFormat(locale, {
    maximumFractionDigits: 1,
    signDisplay: 'always',
  })
    .format(change)
    .replace('-', '−');
  return {
    text: isPercentMetric(metric) ? $localize`:@@delta.points:${number}:change: pts` : number,
    tone,
  };
}

/** `q-delta`: "−3 since Sep 15, 2026", the number in the tone of its direction. */
@Component({
  selector: 'q-delta',
  imports: [DateTimePipe],
  templateUrl: './delta.html',
  styleUrl: './delta.css',
})
export class Delta {
  private readonly locale = inject(LOCALE_ID);
  readonly metric = input.required<string>();
  readonly current = input<number | null>(null);
  readonly previous = input<number | null>(null);
  readonly since = input<string | null>(null);
  protected readonly view = computed(() =>
    deltaView(this.metric(), this.current(), this.previous(), this.locale),
  );
}
