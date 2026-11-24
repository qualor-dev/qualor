import { Component, computed, input } from '@angular/core';
import { growArc, meterValue, revealDelays, ringGeometry, type RingStyle } from './ring-geometry';

/** What the dot says: a gate's status, or an analysis running; none draws a hollow dot. */
export type RingStatus = 'passed' | 'failed' | 'error' | 'none' | 'running';

/** Numbers each ring, so the ids of two rings on one page never meet. */
let rings = 0;

/**
 * `q-ring` (style C): the brand ring, a ring that reads as Q with a dot set into it, as the
 * product's meter. It is decoration next to a printed number, so it is hidden from assistive
 * technology.
 *
 * - `value` (0 to 100) fills the ring clockwise from just after the dot; the rest is track. No data
 *   (null) is the whole ring as track with a hollow dot: it never reads as 100 %.
 * - Dotted (the default from 64 px) or solid (below). The gate emblem is the solid ring at 100 %
 *   with the status in its dot; the dot is otherwise the flat brand blue.
 * - Running: the dot pulses (and glows on dark surfaces). Under reduced motion the pulse stands
 *   still at full strength.
 * - With `from` (a lower earlier value), what lies between lights up clockwise: the setup
 *   checklist's reveal when a step is done. Under reduced motion the end state shows at once.
 *
 * Its inks are custom properties (`--ring-fill`, `--ring-track`, `--ring-brand`, `--ring-ok`,
 * `--ring-bad`, `--ring-warn`, `--ring-glow`) that a host on another surface may set.
 */
@Component({
  selector: 'q-ring',
  templateUrl: './ring.html',
  styleUrl: './ring.css',
})
export class RingMeter {
  /** 0 to 100; null when there is no data. */
  readonly value = input<number | null>(null);
  readonly size = input(76);
  /** The dot's status (the gate emblem); null draws the flat brand dot. */
  readonly status = input<RingStatus | null>(null);
  /** Dots or a solid ring; null chooses by size. */
  readonly meterStyle = input<RingStyle | null>(null);
  /** The value the ring showed before, for the reveal; null draws it still. */
  readonly from = input<number | null>(null);

  private readonly uid = `ring-${++rings}`;
  protected readonly ids = {
    glow: `${this.uid}-glow`,
    glowFill: `url(#${this.uid}-glow)`,
    clip: `${this.uid}-clip`,
    clipUrl: `url(#${this.uid}-clip)`,
  };

  protected readonly g = computed(() => ringGeometry(this.value(), this.size(), this.meterStyle()));
  protected readonly viewBox = computed(() => `0 0 ${this.size()} ${this.size()}`);

  /** The earlier value while the reveal plays: below the value; null otherwise. */
  private readonly before = computed(() => {
    const from = meterValue(this.from());
    const value = meterValue(this.value());
    return from !== null && value !== null && from < value ? from : null;
  });

  protected readonly unlit = computed(() => this.g().dots.filter((d) => !d.lit));
  /** The lit dots, each with its reveal delay when it lights now; null when it was lit before. */
  protected readonly lit = computed(() => {
    const dots = this.g().dots;
    const before = this.before();
    const delays = before === null ? null : revealDelays(dots, before);
    return dots.flatMap((d, i) => (d.lit ? [{ ...d, delay: delays?.[i] ?? null }] : []));
  });

  /** The solid reveal: the fill grows along this arc from where `from` ended. */
  protected readonly grow = computed(() => {
    const before = this.before();
    const value = meterValue(this.value());
    if (this.g().style !== 'solid' || before === null || value === null) return null;
    return growArc(this.size(), before, value);
  });
  /** The solid ring is drawn filled whole (at 100 %, unless it is still growing there). */
  protected readonly full = computed(() => this.g().full && this.grow() === null);

  /** The dot's look: a status, the brand blue, or hollow for no data. */
  protected readonly tone = computed(() => {
    const status = this.status();
    if (status !== null) return status;
    return meterValue(this.value()) === null ? 'empty' : 'brand';
  });
  protected readonly hollow = computed(() => this.tone() === 'none' || this.tone() === 'empty');
}
