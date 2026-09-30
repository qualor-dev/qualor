import { Component, computed, input } from '@angular/core';

export interface DistributionItem {
  key: string;
  label: string;
  value: number;
  /** A `.tone-*` class name without its prefix (styles.css): blocker, high, accent… */
  tone: string;
}

/**
 * `q-distribution` (spec §6.5): a 10px stacked bar of the non-empty items (decoration: the rows
 * carry every number) and one row per item with its dot, label, count and a proportional bar.
 * The inline layout keeps the bar and names its items on one line (the issues list's head).
 */
@Component({
  selector: 'q-distribution',
  templateUrl: './distribution.html',
  styleUrl: './distribution.css',
})
export class Distribution {
  readonly items = input.required<readonly DistributionItem[]>();
  readonly bar = input(true);
  readonly layout = input<'rows' | 'inline'>('rows');
  protected readonly filled = computed(() => this.items().filter((i) => i.value > 0));
  private readonly max = computed(() => Math.max(0, ...this.items().map((i) => i.value)));

  protected width(value: number): number {
    const max = this.max();
    return max > 0 ? Math.round((100 * value) / max) : 0;
  }
}
