import { Component, computed, input } from '@angular/core';

export interface SeverityChip {
  kind: 'critical' | 'high' | 'medium' | 'exploited';
  count: number;
  text: string;
}

/**
 * The open vulnerabilities of a project or a target as count chips ("7 Critical", "23 High",
 * "1 exploited"), in the order a reader weighs them: Critical, High, Medium, then exploited. Only
 * the non-zero ones show; each carries its word, so colour is never the only signal. A count left
 * out (undefined or null) is not shown either: the projects list has no Medium, a server without
 * `vuln.priority` no exploited.
 */
export function severityChips(counts: {
  critical?: number | null;
  high?: number | null;
  medium?: number | null;
  exploited?: number | null;
}): SeverityChip[] {
  const chips: SeverityChip[] = [];
  const add = (
    kind: SeverityChip['kind'],
    count: number | null | undefined,
    text: (n: number) => string,
  ) => {
    if (typeof count === 'number' && count > 0) chips.push({ kind, count, text: text(count) });
  };
  add('critical', counts.critical, (n) => $localize`:@@vulns.chip.critical:${n}:count: Critical`);
  add('high', counts.high, (n) => $localize`:@@vulns.chip.high:${n}:count: High`);
  add('medium', counts.medium, (n) => $localize`:@@vulns.chip.medium:${n}:count: Medium`);
  add(
    'exploited',
    counts.exploited,
    (n) => $localize`:@@vulns.chip.exploited:${n}:count: exploited`,
  );
  return chips;
}

/** {@link severityChips} as badges, on the projects list and beside a target's name. */
@Component({
  selector: 'q-severity-chips',
  templateUrl: './severity-chips.html',
  styleUrl: './severity-chips.css',
})
export class SeverityChips {
  readonly critical = input<number | null | undefined>(undefined);
  readonly high = input<number | null | undefined>(undefined);
  readonly medium = input<number | null | undefined>(undefined);
  readonly exploited = input<number | null | undefined>(undefined);

  protected readonly chips = computed(() =>
    severityChips({
      critical: this.critical(),
      high: this.high(),
      medium: this.medium(),
      exploited: this.exploited(),
    }),
  );
}
