import { Component, effect, inject, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import type { ItemOf } from '../api/types';
import { LabelPipe } from '../i18n/label.pipe';
import { QUALITIES, SEVERITIES } from '../issues/issue-filters';
import { clip } from '../shared/text';
import { OrgContext } from '../org/org-context';
import { inputValue } from '../shared/forms';
import { KeysetList } from '../shared/keyset';
import { safeHelpUri } from '../shared/links';

export type Rule = ItemOf<'/api/v0/rules'>;
type Quality = Rule['quality'];
type Severity = Rule['defaultSeverity'];

interface RuleQuery {
  organizationId: string;
  q: string;
  quality: Quality | '';
  severity: Severity | '';
}

/** The server's bound on a rule search (`ruleQuery`, routes/rules.ts). */
export const RULE_Q_MAX_LENGTH = 200;

/** A search as the rule listings accept it: no U+0000, trimmed, at most 200 characters. */
export function ruleSearch(text: string): string {
  return clip(text.replaceAll('\u0000', '').trim(), RULE_Q_MAX_LENGTH).trim();
}

function oneOf<T extends string>(value: string, values: readonly string[]): T | '' {
  return values.includes(value) ? (value as T) : '';
}

/**
 * The rules the organisation has met (plan 1E ruling X2), searchable by key or name. Rule keys
 * stay in the page, never in the path: a key like `semgrep:javascript.lang…` has dots, and the
 * server's fallback treats a last path segment with a dot as a missing file (api.md §4). Rule
 * descriptions are plain text (ruling Y5); help links only http(s) (`safeHelpUri`).
 */
@Component({
  selector: 'q-rules-page',
  imports: [LabelPipe, RouterLink],
  templateUrl: './rules.page.html',
})
export class RulesPage {
  private readonly api = inject(Api);
  protected readonly org = inject(OrgContext);

  protected readonly q = signal('');
  protected readonly quality = signal<Quality | ''>('');
  protected readonly severity = signal<Severity | ''>('');
  private readonly submitted = signal('');
  protected readonly list = new KeysetList<Rule, RuleQuery>((p, cursor) =>
    ok(
      this.api.client.GET('/api/v0/rules', {
        params: {
          query: {
            organizationId: p.organizationId,
            limit: 100,
            ...(p.q ? { q: p.q } : {}),
            ...(p.quality ? { quality: p.quality } : {}),
            ...(p.severity ? { severity: p.severity } : {}),
            ...(cursor ? { cursor } : {}),
          },
        },
      }),
    ),
  );
  protected readonly qualities = QUALITIES;
  protected readonly severities = SEVERITIES;
  protected readonly qMax = RULE_Q_MAX_LENGTH;
  protected readonly helpUri = safeHelpUri;
  protected readonly inputValue = inputValue;

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      if (!organizationId) return;
      void this.list.reset({
        organizationId,
        q: this.submitted(),
        quality: this.quality(),
        severity: this.severity(),
      });
    });
  }

  protected search(event: Event): void {
    event.preventDefault();
    this.submitted.set(ruleSearch(this.q()));
  }

  protected setQuality(event: Event): void {
    this.quality.set(oneOf<Quality>(inputValue(event), QUALITIES));
  }

  protected setSeverity(event: Event): void {
    this.severity.set(oneOf<Severity>(inputValue(event), SEVERITIES));
  }
}
