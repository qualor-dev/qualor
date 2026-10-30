import { Component, computed, input } from '@angular/core';
import { lensGeometry } from './lens-geometry';

/** A row of new dots prints this long after the row under it (the setup checklist's reveal). */
const ROW_DELAY_MS = 45;

/**
 * `q-lens` (spec §6.1): coverage and the gate's emblem drawn as the brand's halftone circle. It is
 * decoration next to a printed number, so it is hidden from assistive technology.
 *
 * With `from` (a lower earlier value), the dots above the old level print in row by row from the
 * bottom and the level line rises from where it was: the setup checklist's reveal when a step is
 * done (onboarding notes, Motion). Under reduced motion the stylesheet shows the end state at once.
 */
@Component({
  selector: 'q-lens',
  templateUrl: './lens.html',
  styleUrl: './lens.css',
  host: { '[class.lens-ok]': "tone() === 'ok'", '[class.lens-bad]': "tone() === 'bad'" },
})
export class Lens {
  readonly value = input<number | null>(null);
  readonly size = input(76);
  readonly tone = input<'accent' | 'ok' | 'bad'>('accent');
  readonly mark = input<'check' | 'cross' | null>(null);
  /** The value the lens showed before, for the reveal; null draws it still. */
  readonly from = input<number | null>(null);

  protected readonly g = computed(() => lensGeometry(this.value(), this.size()));
  protected readonly viewBox = computed(() => `0 0 ${this.size()} ${this.size()}`);

  /** The geometry of `from`, when it is lower than `value`: what was already printed. */
  private readonly before = computed(() => {
    const from = this.from();
    const value = this.value();
    if (from === null || value === null || !(from < value)) return null;
    return lensGeometry(from, this.size());
  });

  /** Each dot with the delay of its row when it is new, bottom row first; null when it was there. */
  protected readonly dots = computed(() => {
    const g = this.g();
    const before = this.before();
    if (!before) return g.dots.map((dot) => ({ ...dot, delay: null }));
    const top = before.levelY + g.step * 0.2;
    const rows = [...new Set(g.dots.filter((d) => d.y < top).map((d) => d.y))].sort(
      (a, b) => b - a,
    );
    return g.dots.map((dot) => {
      const row = dot.y < top ? rows.indexOf(dot.y) : -1;
      return { ...dot, delay: row < 0 ? null : row * ROW_DELAY_MS };
    });
  });

  /** How far below its place the level line starts rising, in px; 0 when it does not move. */
  protected readonly rise = computed(() => {
    const before = this.before();
    const level = this.g().level;
    if (!before?.level || !level) return 0;
    return Math.round((before.levelY - level.y) * 100) / 100;
  });

  protected readonly markPath = computed(() => {
    const s = this.size();
    const at = (f: number) => Math.round(s * f * 100) / 100;
    switch (this.mark()) {
      case 'cross':
        return `M${at(0.36)} ${at(0.36)}L${at(0.64)} ${at(0.64)}M${at(0.64)} ${at(0.36)}L${at(0.36)} ${at(0.64)}`;
      case 'check':
        return `M${at(0.3)} ${at(0.52)}L${at(0.44)} ${at(0.66)}L${at(0.71)} ${at(0.37)}`;
      default:
        return null;
    }
  });
}
