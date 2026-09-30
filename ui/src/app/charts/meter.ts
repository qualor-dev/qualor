import { Component, computed, inject, input, LOCALE_ID } from '@angular/core';
import { Icon } from '../shared/icon';

/** What a meter asks of its reader: attention (amber: renew soon, grace) or a failure (red). */
export type MeterAlert = 'attention' | 'failure';

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
  /** A meter that is no daily budget says its value in its own words ("245 days left")… */
  readonly text = input<string | null>(null);
  /** …and its own note, instead of the budget notes. */
  readonly note = input<string | null>(null);
  /**
   * Draws it as needing attention (amber) or as a failure (red, as a reached budget); the note says
   * why. The failure red is for what already stopped: a reached budget, an expired licence.
   */
  readonly alert = input<MeterAlert | null>(null);

  /** A budget meter: no words of its own were given. */
  private readonly budget = computed(() => this.text() === null && this.note() === null);

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
    const own = this.text();
    if (own !== null) return own;
    const value = this.format(this.value());
    const max = this.max();
    return max === null
      ? value
      : $localize`:@@meter.of:${value}:value: of ${this.format(max)}:max:`;
  });

  protected readonly noteText = computed(() => {
    if (!this.budget()) return this.note();
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

  /** Its tone: what the page says, else a failure once a budget is reached. */
  protected readonly tone = computed<MeterAlert | null>(
    () => this.alert() ?? (this.budget() && this.state() === 'reached' ? 'failure' : null),
  );

  /** What a screen reader hears for the track: the value's words, and why it needs attention. */
  protected readonly spoken = computed(() => {
    if (!this.budget()) {
      const note = this.note();
      return note === null
        ? this.valueText()
        : $localize`:@@meter.spokenNote:${this.valueText()}:value:, ${note}:note:`;
    }
    switch (this.state()) {
      case 'reached':
        return $localize`:@@meter.reachedSpoken:${this.valueText()}:value:, budget reached for today`;
      case 'off':
        return $localize`:@@meter.offSpoken:${this.valueText()}:value:, none allowed: the budget is 0`;
      default:
        return this.valueText();
    }
  });

  /** The track's value within its range; past a budget its words say the real one. */
  protected readonly trackValue = computed(() => {
    const max = this.max();
    return max === null ? this.value() : Math.min(this.value(), max);
  });

  private format(n: number): string {
    return this.unit() === 'usd'
      ? new Intl.NumberFormat(this.locale, { style: 'currency', currency: 'USD' }).format(n)
      : new Intl.NumberFormat(this.locale).format(n);
  }
}
