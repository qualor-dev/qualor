import { Component, computed, inject, input, LOCALE_ID } from '@angular/core';
import { Icon } from '../shared/icon';

/**
 * `q-meter` (spec §6.7): a use against its budget as a horizontal track in the chart ramp, with
 * the numbers beside it ("12 of 200") and, beyond colour, words for what the reader must know: the
 * budget reached for today, a budget of 0 that allows none, or no budget set (no track then). The
 * track is a `role="meter"` with the same words for a screen reader.
 */
@Component({
  selector: 'q-meter',
  imports: [Icon],
  templateUrl: './meter.html',
  styleUrl: './meter.css',
})
export class Meter {
  private readonly locale = inject(LOCALE_ID);
  readonly label = input.required<string>();
  readonly value = input.required<number>();
  /** The budget; null when none is set. */
  readonly max = input.required<number | null>();
  /** How the numbers read: a count, or US dollars with cents. */
  readonly unit = input<'count' | 'usd'>('count');

  protected readonly state = computed(() => {
    const max = this.max();
    if (max === null) return 'none';
    if (max === 0) return 'off';
    return this.value() >= max ? 'reached' : 'under';
  });

  protected readonly percent = computed(() => {
    const max = this.max();
    return max !== null && max > 0 ? Math.min(100, Math.round((100 * this.value()) / max)) : 0;
  });

  protected readonly valueText = computed(() => {
    const value = this.format(this.value());
    const max = this.max();
    return max === null
      ? value
      : $localize`:@@meter.of:${value}:value: of ${this.format(max)}:max:`;
  });

  protected readonly note = computed(() => {
    switch (this.state()) {
      case 'reached':
        return $localize`:@@meter.reached:Budget reached for today`;
      case 'off':
        return $localize`:@@meter.off:None allowed: the budget is 0`;
      case 'none':
        return $localize`:@@meter.none:No budget set`;
      default:
        return null;
    }
  });

  /** What a screen reader hears for the track: the numbers, and the reached budget in words. */
  protected readonly spoken = computed(() =>
    this.state() === 'reached'
      ? $localize`:@@meter.reachedSpoken:${this.valueText()}:value:, budget reached for today`
      : this.valueText(),
  );

  private format(n: number): string {
    return this.unit() === 'usd'
      ? new Intl.NumberFormat(this.locale, { style: 'currency', currency: 'USD' }).format(n)
      : new Intl.NumberFormat(this.locale).format(n);
  }
}
