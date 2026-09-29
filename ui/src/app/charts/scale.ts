/**
 * Scales for the SVG charts (spec §6): clean tick values, a linear map and the ticks of a time
 * axis. Pure functions, so every chart's geometry is tested without a DOM.
 */
const DAY = 86_400_000;

/** About `count` ticks from 0 to at least `max`, at 1, 2, 2.5 or 5 × 10ⁿ; [0, 1] for no range. */
export function niceTicks(max: number, count = 4, integer = false): number[] {
  if (!Number.isFinite(max) || max <= 0) return [0, 1];
  const magnitude = 10 ** Math.floor(Math.log10(max / count));
  const candidates = [1, 2, 2.5, 5, 10]
    .map((m) => m * magnitude)
    .filter((s) => !integer || (s >= 1 && Number.isInteger(s)));
  const fallback = integer ? Math.max(1, 10 * magnitude) : 10 * magnitude;
  const step = candidates.find((s) => max / s <= count) ?? fallback;
  const n = Math.ceil(max / step - 1e-9);
  return Array.from({ length: n + 1 }, (_, i) => Number((i * step).toPrecision(12)));
}

/** A linear map from `domain` onto `range`; a zero-width domain maps onto the range's middle. */
export function linear(
  domain: readonly [number, number],
  range: readonly [number, number],
): (value: number) => number {
  const [d0, d1] = domain;
  const [r0, r1] = range;
  const span = d1 - d0;
  return span === 0 ? () => (r0 + r1) / 2 : (value) => r0 + ((value - d0) / span) * (r1 - r0);
}

export interface TimeTick {
  at: number;
  month: boolean;
}

/** Month starts for two months or more (at most `max`), else every 1, 2, 7 or 14 UTC days. */
export function timeTicks(start: number, end: number, max = 6): TimeTick[] {
  if (!(end > start)) return [];
  if (end - start >= 60 * DAY) {
    const first = new Date(start);
    const months: number[] = [];
    for (let i = 0; ; i++) {
      const at = Date.UTC(first.getUTCFullYear(), first.getUTCMonth() + i, 1);
      if (at > end) break;
      if (at >= start) months.push(at);
    }
    const every = Math.ceil(months.length / max);
    return months.filter((_, i) => i % every === 0).map((at) => ({ at, month: true }));
  }
  const step = ([1, 2, 7, 14].find((d) => (end - start) / (d * DAY) <= max) ?? 14) * DAY;
  const ticks: TimeTick[] = [];
  for (let at = Math.ceil(start / DAY) * DAY; at <= end; at += step) {
    ticks.push({ at, month: false });
  }
  return ticks;
}

/** "Jul" for a month start, "Sep 8" for a day, in UTC like every date of the app. */
export function tickLabel(tick: TimeTick, locale: string): string {
  return new Intl.DateTimeFormat(
    locale,
    tick.month
      ? { month: 'short', timeZone: 'UTC' }
      : { month: 'short', day: 'numeric', timeZone: 'UTC' },
  ).format(tick.at);
}
