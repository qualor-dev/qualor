import { Component, computed, input } from '@angular/core';
import { lensGeometry } from './lens-geometry';

/**
 * `q-lens` (spec §6.1): coverage and the gate's emblem drawn as the brand's halftone circle. It is
 * decoration next to a printed number, so it is hidden from assistive technology.
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

  protected readonly g = computed(() => lensGeometry(this.value(), this.size()));
  protected readonly viewBox = computed(() => `0 0 ${this.size()} ${this.size()}`);
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
