import { Component, computed, input } from '@angular/core';
import { ICONS, type IconName } from './icons';

interface IconShape {
  d: readonly string[];
  c?: readonly (readonly [number, number, number])[];
}

/** `q-icon`: one icon of the fixed set; decoration beside text, so hidden from AT. */
@Component({ selector: 'q-icon', templateUrl: './icon.html', host: { class: 'icon' } })
export class Icon {
  readonly name = input.required<IconName>();
  protected readonly icon = computed(() => {
    const icon: IconShape = ICONS[this.name()];
    return { d: icon.d, c: icon.c ?? [] };
  });
}
