import {
  Component,
  DestroyRef,
  ElementRef,
  LOCALE_ID,
  afterNextRender,
  computed,
  inject,
  input,
  signal,
} from '@angular/core';
import { label } from '../i18n/labels';
import { DateTimePipe, formatDate } from '../shared/date-time.pipe';
import { formatMeasure, MeasurePipe } from '../shared/measure.pipe';
import { isPercentMetric } from './direction';
import { linear, niceTicks, tickLabel, timeTicks } from './scale';

export interface ChartPoint {
  date: string;
  value: number | null;
}

export interface ChartSeries {
  key: string;
  label: string;
  /** A `.tone-*` class name without its prefix. */
  tone: string;
  points: readonly ChartPoint[];
}

interface Column {
  at: number;
  date: string;
  values: (number | null)[];
  /** The sum of the values (stacked charts), or null when none is known. */
  total: number | null;
}

/** api.md: at most 1 000 points per metric; a longer series keeps the latest. */
const MAX_POINTS = 1000;
const M = { top: 16, right: 24, bottom: 30, left: 48 };
const r1 = (n: number) => Math.round(n * 10) / 10;

/**
 * `q-line-chart` (spec §6.2): a time series with clean y ticks and date ticks, one line with its
 * area wash or a stack of series; a crosshair and tooltip follow the pointer or the arrow keys;
 * the same numbers are in a table behind "Show as a table". No chart library: the SVG is built
 * from template bindings.
 */
@Component({
  selector: 'q-line-chart',
  imports: [DateTimePipe, MeasurePipe],
  templateUrl: './line-chart.html',
  styleUrl: './line-chart.css',
})
export class LineChart {
  private readonly locale = inject(LOCALE_ID);
  readonly series = input.required<readonly ChartSeries[]>();
  readonly metric = input.required<string>();
  readonly stacked = input(false);
  readonly height = input(280);

  protected readonly width = signal(640);
  protected readonly active = signal<number | null>(null);

  constructor() {
    const host = inject<ElementRef<HTMLElement>>(ElementRef).nativeElement;
    const destroy = inject(DestroyRef);
    afterNextRender(() => {
      if (typeof ResizeObserver === 'undefined') return;
      const observer = new ResizeObserver(([entry]) => {
        if (entry) this.width.set(Math.max(280, Math.round(entry.contentRect.width)));
      });
      observer.observe(host);
      destroy.onDestroy(() => observer.disconnect());
    });
  }

  protected readonly columns = computed<Column[]>(() => {
    const series = this.series();
    const byDate = new Map<string, (number | null)[]>();
    series.forEach((s, index) => {
      for (const p of s.points.slice(-MAX_POINTS)) {
        const row = byDate.get(p.date) ?? series.map(() => null);
        row[index] = p.value !== null && Number.isFinite(p.value) ? p.value : null;
        byDate.set(p.date, row);
      }
    });
    return [...byDate.entries()]
      .map(([date, values]) => ({
        at: Date.parse(date),
        date,
        values,
        total: values.some((v) => v !== null)
          ? values.reduce<number>((sum, v) => sum + (v ?? 0), 0)
          : null,
      }))
      .filter((c) => Number.isFinite(c.at))
      .sort((a, b) => a.at - b.at)
      .slice(-MAX_POINTS);
  });

  /** The value a column shows: its total when stacked, else the first series' value. */
  private shown(c: Column): number | null {
    return this.stacked() ? c.total : (c.values[0] ?? null);
  }

  protected readonly viewBox = computed(() => `0 0 ${this.width()} ${this.height()}`);

  protected readonly plot = computed(() => {
    const cols = this.columns();
    const left = M.left;
    const right = this.width() - M.right;
    const top = M.top;
    const bottom = this.height() - M.bottom;
    const metric = this.metric();
    let max = 0;
    for (const c of cols) {
      const v = this.shown(c);
      if (v !== null && v > max) max = v;
    }
    const ticks = niceTicks(max, 4, !isPercentMetric(metric));
    const yTop = ticks[ticks.length - 1] ?? 1;
    const t0 = cols[0]?.at ?? 0;
    const t1 = cols[cols.length - 1]?.at ?? 0;
    const x = linear([t0, t1], [left, right]);
    const y = linear([0, yTop], [bottom, top]);
    const xs = cols.map((c) => r1(x(c.at)));
    const at = (i: number, v: number) => `${xs[i]},${r1(y(v))}`;

    let line: { points: string; area: string } | null = null;
    const bands: { key: string; tone: string; area: string; edge: string }[] = [];
    if (this.stacked()) {
      const valued = cols.flatMap((c, i) => (c.total === null ? [] : [i]));
      const lower = cols.map(() => 0);
      this.series().forEach((s, si) => {
        const upper = cols.map((c, i) => (lower[i] ?? 0) + (c.values[si] ?? 0));
        const topEdge = valued.map((i) => at(i, upper[i] ?? 0));
        const baseEdge = [...valued].reverse().map((i) => at(i, lower[i] ?? 0));
        if (valued.length > 0) {
          bands.push({
            key: s.key,
            tone: s.tone,
            area: [...topEdge, ...baseEdge].join(' '),
            edge: topEdge.join(' '),
          });
        }
        upper.forEach((v, i) => (lower[i] = v));
      });
    } else {
      const valued = cols.flatMap((c, i) => (c.values[0] === null ? [] : [i]));
      const first = valued[0];
      const last = valued[valued.length - 1];
      if (first !== undefined && last !== undefined) {
        const points = valued.map((i) => at(i, cols[i]?.values[0] ?? 0)).join(' ');
        line = { points, area: `${points} ${xs[last]},${r1(bottom)} ${xs[first]},${r1(bottom)}` };
      }
    }

    // A stack of one analysis has bands without area: it is drawn as one stacked column instead.
    let column: {
      x: number;
      width: number;
      segments: { key: string; tone: string; y: number; height: number }[];
    } | null = null;
    const only = cols.length === 1 ? cols[0] : undefined;
    if (this.stacked() && only) {
      let base = 0;
      /** The drawn top of the segment below (the baseline at first). */
      let drawnTop = Infinity;
      const segments: { key: string; tone: string; y: number; height: number }[] = [];
      this.series().forEach((s, si) => {
        const v = only.values[si] ?? 0;
        if (v <= 0) return;
        const top = y(base + v);
        // A 2px surface gap between touching segments (dataviz: gaps, not strokes). A segment too
        // thin for a pixel keeps one, standing on its base rather than hanging below it; the next
        // one stands on what was drawn.
        const floor = Math.min(y(base) - 1, drawnTop - 2);
        const height = Math.max(1, floor - (top + 1));
        drawnTop = floor - height;
        segments.push({ key: s.key, tone: s.tone, y: r1(drawnTop), height: r1(height) });
        base += v;
      });
      column = { x: r1((xs[0] ?? 0) - 12), width: 24, segments };
    }

    // The latest value, marked on a line; on a stack only at zero, where no band shows it.
    let end: { x: number; y: number; text: string; marked: boolean } | null = null;
    for (let i = cols.length - 1; i >= 0 && end === null; i--) {
      const col = cols[i];
      const v = col ? this.shown(col) : null;
      if (v !== null) {
        end = {
          x: xs[i] ?? 0,
          y: r1(y(v)),
          text: formatMeasure(v, metric, this.locale),
          marked: !this.stacked() || v === 0,
        };
      }
    }
    const xTicks = only
      ? [{ at: only.at, x: xs[0] ?? 0, text: formatDate(only.date, this.locale) }]
      : timeTicks(t0, t1).map((t) => ({
          at: t.at,
          x: r1(x(t.at)),
          text: tickLabel(t, this.locale),
        }));
    return {
      left,
      right,
      top,
      bottom,
      xs,
      y,
      line,
      bands,
      column,
      end,
      xTicks,
      yTicks: ticks.map((t) => ({
        value: t,
        y: r1(y(t)),
        text: formatMeasure(t, metric, this.locale),
      })),
    };
  });

  protected readonly tip = computed(() => {
    const index = this.active();
    const col = index === null ? undefined : this.columns()[index];
    if (index === null || !col) return null;
    const plot = this.plot();
    const x = plot.xs[index] ?? 0;
    const shown = this.shown(col);
    return {
      x,
      y: shown === null ? null : r1(plot.y(shown)),
      flip: x > (plot.left + plot.right) / 2,
      date: formatDate(col.date, this.locale),
      total: this.stacked() ? formatMeasure(col.total, this.metric(), this.locale) : null,
      rows: this.series().map((s, i) => ({
        key: s.key,
        label: s.label,
        tone: s.tone,
        text: formatMeasure(col.values[i] ?? null, this.metric(), this.locale),
      })),
    };
  });

  protected readonly summary = computed(() => {
    const title = label('metric', this.metric());
    const cols = this.columns().filter((c) => this.shown(c) !== null);
    const first = cols[0];
    const last = cols[cols.length - 1];
    if (!first || !last) return $localize`:@@trend.empty:${title}:metric:: no values yet`;
    const value = (c: Column) => formatMeasure(this.shown(c), this.metric(), this.locale);
    const at = (c: Column) => formatDate(c.date, this.locale);
    return $localize`:@@trend.summary:${title}:metric: went from ${value(first)}:from: on ${at(first)}:start: to ${value(last)}:to: on ${at(last)}:end:`;
  });

  protected point(event: PointerEvent): void {
    const svg = event.currentTarget as SVGSVGElement;
    const box = svg.getBoundingClientRect();
    const px = box.width > 0 ? ((event.clientX - box.left) * this.width()) / box.width : 0;
    const xs = this.plot().xs;
    let best: number | null = null;
    let distance = Infinity;
    xs.forEach((x, i) => {
      if (Math.abs(x - px) < distance) {
        distance = Math.abs(x - px);
        best = i;
      }
    });
    this.active.set(best);
  }

  protected focusIn(): void {
    const n = this.columns().length;
    if (n > 0 && this.active() === null) this.active.set(n - 1);
  }

  protected key(event: KeyboardEvent): void {
    const n = this.columns().length;
    if (n === 0) return;
    const current = this.active() ?? n - 1;
    const next = new Map<string, number | null>([
      ['ArrowLeft', Math.max(0, current - 1)],
      ['ArrowRight', Math.min(n - 1, current + 1)],
      ['Home', 0],
      ['End', n - 1],
      ['Escape', null],
    ]);
    if (!next.has(event.key)) return;
    event.preventDefault();
    this.active.set(next.get(event.key) ?? null);
  }
}
