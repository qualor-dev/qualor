import { Component, computed, input } from '@angular/core';
import { linear } from './scale';

const round1 = (n: number) => Math.round(n * 10) / 10;

/** A trend in a KPI tile: values by position, the last one marked; gaps keep their place. */
export function sparkline(
  values: readonly (number | null)[],
  width: number,
  height: number,
  pad = 3,
): { points: string; last: { x: number; y: number } | null } {
  const valued = values.flatMap((v, i) =>
    v !== null && Number.isFinite(v) ? [[i, v] as const] : [],
  );
  const lastValued = valued[valued.length - 1];
  if (!lastValued) return { points: '', last: null };
  let min = Infinity;
  let max = -Infinity;
  for (const [, v] of valued) {
    if (v < min) min = v;
    if (v > max) max = v;
  }
  const x = linear([0, Math.max(1, values.length - 1)], [pad, width - pad]);
  const y = max === min ? () => height / 2 : linear([min, max], [height - pad, pad]);
  const points = valued.map(([i, v]) => `${round1(x(i))},${round1(y(v))}`).join(' ');
  return { points, last: { x: round1(x(lastValued[0])), y: round1(y(lastValued[1])) } };
}

/** `q-sparkline`: decoration beside a KPI's printed value and delta, so hidden from AT. */
@Component({
  selector: 'q-sparkline',
  templateUrl: './sparkline.html',
  styleUrl: './sparkline.css',
})
export class Sparkline {
  readonly values = input.required<readonly (number | null)[]>();
  readonly width = input(120);
  readonly height = input(32);
  protected readonly s = computed(() => sparkline(this.values(), this.width(), this.height()));
  protected readonly viewBox = computed(() => `0 0 ${this.width()} ${this.height()}`);
}
