import { Component, computed, input } from '@angular/core';
import { label } from '../i18n/labels';
import { Icon } from './icon';
import type { IconName } from './icons';

const KNOWN = new Set(['passed', 'failed', 'error', 'none']);

/**
 * A quality gate status as an icon and a word (never colour alone, spec §5); no status means
 * never analysed.
 */
@Component({
  selector: 'q-gate-badge',
  imports: [Icon],
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
  protected readonly icon = computed<IconName>(() => {
    switch (this.tone()) {
      case 'passed':
        return 'check';
      case 'failed':
        return 'cross';
      case 'error':
        return 'alert';
      default:
        return 'minus';
    }
  });
}
