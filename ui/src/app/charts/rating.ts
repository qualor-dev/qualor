import { Component, computed, input } from '@angular/core';

const LETTERS = ['A', 'B', 'C', 'D', 'E'];

/** `q-rating`: a 1–5 rating as its letter in a tinted circle; the letter carries the meaning. */
@Component({ selector: 'q-rating', templateUrl: './rating.html', styleUrl: './rating.css' })
export class Rating {
  readonly value = input<number | null>(null);
  readonly label = input('');
  protected readonly letter = computed(() => {
    const v = this.value();
    return v === null || !Number.isFinite(v) ? null : (LETTERS[Math.round(v) - 1] ?? null);
  });
}
