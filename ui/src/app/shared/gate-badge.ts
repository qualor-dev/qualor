import { Component, computed, input } from '@angular/core';
import { label } from '../i18n/labels';

const KNOWN = new Set(['passed', 'failed', 'error', 'none']);

/** A quality gate status as a coloured, labelled badge; no status means never analysed. */
@Component({
  selector: 'q-gate-badge',
  templateUrl: './gate-badge.html',
})
export class GateBadge {
  readonly status = input<string | null | undefined>(null);
  protected readonly text = computed(() => {
    const status = this.status();
    return status ? label('gate', status) : null;
  });
  /** Only statuses the stylesheet knows become a class name; a newer server's value is neutral. */
  protected readonly tone = computed(() => {
    const status = this.status();
    return status && KNOWN.has(status) ? status : 'none';
  });
}
