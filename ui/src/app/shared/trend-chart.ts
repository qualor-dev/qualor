import { Component, LOCALE_ID, computed, inject, input } from '@angular/core';
import { label } from '../i18n/labels';
import { DateTimePipe, formatDate } from './date-time.pipe';
import { formatMeasure, MeasurePipe } from './measure.pipe';

export interface TrendPoint {
  date: string;
  value: number | null;
}

const WIDTH = 240;
const HEIGHT = 64;
const PAD = 4;
/** The API returns at most 1 000 points per metric (api.md); a longer series keeps the latest. */
const MAX_POINTS = 1000;

/**
 * One metric's history as a small SVG line (no chart library): the image has a text summary for
 * screen readers, and the points are also in a table behind a disclosure. The SVG is built from
 * template bindings only; the only computed attribute is the polyline's list of numbers.
 */
@Component({
  selector: 'q-trend-chart',
  imports: [DateTimePipe, MeasurePipe],
  templateUrl: './trend-chart.html',
  styleUrl: './trend-chart.css',
})
export class TrendChart {
  private readonly locale = inject(LOCALE_ID);
  readonly metric = input.required<string>();
  readonly points = input.required<TrendPoint[]>();

  protected readonly viewBox = `0 0 ${WIDTH} ${HEIGHT}`;
  protected readonly title = computed(() => label('metric', this.metric()));
  protected readonly shown = computed(() => this.points().slice(-MAX_POINTS));
  private readonly valued = computed(() =>
    this.shown().filter(
      (p): p is { date: string; value: number } => p.value !== null && Number.isFinite(p.value),
    ),
  );

  protected readonly path = computed(() => {
    const points = this.valued();
    if (points.length === 0) return null;
    // A loop, not Math.min(...values): spreading a long array can overflow the stack.
    let min = Infinity;
    let max = -Infinity;
    for (const p of points) {
      if (p.value < min) min = p.value;
      if (p.value > max) max = p.value;
    }
    const span = max - min || 1;
    const step = points.length > 1 ? (WIDTH - 2 * PAD) / (points.length - 1) : 0;
    const xy = points.map(
      (p, i) =>
        [PAD + i * step, HEIGHT - PAD - ((p.value - min) / span) * (HEIGHT - 2 * PAD)] as const,
    );
    const first = xy[0] ?? ([0, 0] as const);
    const last = xy[xy.length - 1] ?? ([0, 0] as const);
    const line = xy.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
    return {
      line,
      // The line closed along the bottom edge, for the tinted area under it.
      area: `${line} ${last[0].toFixed(1)},${HEIGHT} ${first[0].toFixed(1)},${HEIGHT}`,
      lastX: last[0],
      lastY: last[1],
    };
  });

  /** The latest value, shown large next to the title. */
  protected readonly latest = computed(() => {
    const points = this.valued();
    const last = points[points.length - 1];
    return last ? formatMeasure(last.value, this.metric(), this.locale) : null;
  });

  protected readonly summary = computed(() => {
    const points = this.valued();
    const first = points[0];
    const last = points[points.length - 1];
    if (!first || !last) {
      return $localize`:@@trend.empty:${this.title()}:metric:: no values yet`;
    }
    const at = (date: string) => formatDate(date, this.locale);
    return $localize`:@@trend.summary:${this.title()}:metric: went from ${formatMeasure(first.value, this.metric(), this.locale)}:from: on ${at(first.date)}:start: to ${formatMeasure(last.value, this.metric(), this.locale)}:to: on ${at(last.date)}:end:`;
  });
}
