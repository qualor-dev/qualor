import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  input,
  resource,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { OrgContext } from '../org/org-context';
import { LabelPipe } from '../i18n/label.pipe';
import { label } from '../i18n/labels';
import { SEVERITIES } from '../issues/issue-filters';
import { keepFocus, rowAt, rowByKey } from '../shared/focus';
import { inputValue, isChecked } from '../shared/forms';
import { KeysetList } from '../shared/keyset';
import { RULE_Q_MAX_LENGTH, ruleSearch } from './rules.page';
import { Icon } from '../shared/icon';
import { type Crumb, PageHeader } from '../shared/page-header';

export type ProfileRule = ItemOf<'/api/v0/quality-profiles/{id}/rules'>;
type Severity = NonNullable<ProfileRule['severityOverride']>;
type Scope = 'default' | 'all';

interface RuleQuery {
  profileId: string;
  q: string;
  scope: Scope;
}

/** The server's bound on a rule key in a path (`ruleKeyParam`: 40 + 1 + 512 characters). */
const RULE_KEY_MAX_LENGTH = 553;
const RULE_KEY = /^[a-z0-9][a-z0-9-]{0,39}:.+$/s;

/**
 * A rule key as `PUT /quality-profiles/{id}/rules/{ruleKey}` takes it: `<engine>:<rule id>`, the
 * engine id as the report format allows it (`ENGINE_ID_PATTERN`), at most 553 characters in all,
 * no U+0000.
 */
export function isRuleKey(key: string): boolean {
  return key.length <= RULE_KEY_MAX_LENGTH && RULE_KEY.test(key) && !key.includes('\u0000');
}

function sourceLabel(source: ProfileRule['source']): string {
  switch (source) {
    case 'profile':
      return $localize`:@@profile.source.profile:Set here`;
    case 'inherited':
      return $localize`:@@profile.source.inherited:Inherited`;
    default:
      return $localize`:@@profile.source.default:Unknown-rule default`;
  }
}

/**
 * One quality profile and the rules it decides, with the activation resolved through its parents
 * (api.md `GET /quality-profiles/{id}/rules`). Org admins switch rules on and off, override their
 * severity, remove the profile's own setting so the rule inherits again, or decide a rule by its
 * key before any report named it (ruling X5). Built-in profiles are read-only (409
 * `BUILTIN_READ_ONLY`). Rule keys go into the API path encoded, never into the page's URL.
 *
 * - A change patches its row in place: the PUT answer replaces it; after "Inherit again" or a
 *   refused change the rule alone is asked for again (`q=<key>`). The pages loaded so far, the
 *   scroll position and the focused control stay; a row that left the list hands the focus to the
 *   next row's checkbox, else to the "Rules" heading.
 * - Controls are never disabled while a change runs (that would drop the focus); input is
 *   ignored instead, and a refused change is put back.
 * - The result is announced in the live region.
 * - The route reuses this component when only `:profileId` changes: the page state is reset then,
 *   and an answer for the previous profile is ignored.
 * - The API cannot set "active here, severity inherited": the nearest row of the chain decides
 *   both (api.md). Switching a rule sends the severity it has now, so the effective severity does
 *   not change; the page says so, and "Inherit again" undoes the setting.
 */
@Component({
  selector: 'q-profile-page',
  imports: [Icon, LabelPipe, PageHeader, RouterLink],
  templateUrl: './profile.page.html',
  styleUrl: './profile.page.css',
  host: { class: 'bleed' },
})
export class ProfilePage {
  private readonly api = inject(Api);
  private readonly org = inject(OrgContext);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  readonly profileId = input.required<string>();

  protected readonly profile = resource({
    params: () => this.profileId(),
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/quality-profiles/{id}', { params: { path: { id: params } } }),
      ),
  });
  /** The profile, or null while loading or after an error (`value()` throws in the error state). */
  protected readonly current = computed(() =>
    this.profile.hasValue() ? this.profile.value() : null,
  );
  protected readonly crumbs: Crumb[] = [
    { label: $localize`:@@profile.crumb:Quality profiles`, link: '/profiles' },
  ];
  /** The parent's id: a string, so a changed profile of the same parent asks nothing again. */
  private readonly parentId = computed(() => this.current()?.parentId ?? undefined);
  /** The parent profile, for its name on the band (spec §7.7: the profile's facts). */
  protected readonly parent = resource({
    params: () => this.parentId(),
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/quality-profiles/{id}', { params: { path: { id: params } } }),
      ),
  });
  protected readonly parentName = computed(() =>
    this.parent.hasValue() ? this.parent.value().name : null,
  );
  protected readonly editable = computed(() => {
    const p = this.current();
    return !!p && !p.isBuiltin && this.org.canChange('org.profiles.manage', p.organizationId);
  });

  protected readonly q = signal('');
  private readonly submitted = signal('');
  protected readonly scope = signal<Scope>('default');
  protected readonly list = new KeysetList<ProfileRule, RuleQuery>((p, cursor) =>
    this.fetchRules(p, cursor),
  );
  protected readonly newKey = signal('');
  protected readonly newActive = signal(true);
  protected readonly keyError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  /** The last change's result, for the live region. */
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly severities = SEVERITIES;
  protected readonly qMax = RULE_Q_MAX_LENGTH;
  protected readonly keyMax = RULE_KEY_MAX_LENGTH;
  protected readonly sourceLabel = sourceLabel;
  protected readonly problemMessage = problemMessage;
  protected readonly inputValue = inputValue;
  /** Incremented per profile: an answer for an older one is ignored. */
  private generation = 0;
  private readonly heading = viewChild<ElementRef<HTMLElement>>('rulesHeading');
  private readonly table = viewChild<ElementRef<HTMLElement>>('table');

  constructor() {
    effect(() => {
      this.profileId();
      untracked(() => {
        this.generation++;
        this.q.set('');
        this.submitted.set('');
        this.scope.set('default');
        this.newKey.set('');
        this.newActive.set(true);
        this.keyError.set(null);
        this.error.set(null);
        this.announcement.set(null);
        this.busy.set(false);
      });
    });
    effect(() => {
      void this.list.reset({
        profileId: this.profileId(),
        q: this.submitted(),
        scope: this.scope(),
      });
    });
  }

  protected activeLabel(rule: ProfileRule): string {
    return $localize`:@@profile.activeLabel:Active: ${rule.rule.key}:key:`;
  }

  protected severityLabel(rule: ProfileRule): string {
    return $localize`:@@profile.severityLabel:Severity: ${rule.rule.key}:key:`;
  }

  protected search(event: Event): void {
    event.preventDefault();
    this.submitted.set(ruleSearch(this.q()));
  }

  protected setScope(event: Event): void {
    this.scope.set(isChecked(event) ? 'all' : 'default');
  }

  protected async setActive(rule: ProfileRule, event: Event): Promise<void> {
    const active = isChecked(event);
    const saved = await this.put(
      rule.rule.key,
      { active, severityOverride: rule.severityOverride },
      () =>
        active
          ? $localize`:@@profile.changed.active:${rule.rule.key}:key: is now active in this profile.`
          : $localize`:@@profile.changed.inactive:${rule.rule.key}:key: is now inactive in this profile.`,
    );
    // The row keeps its element (tracked by key) and its binding did not change, so a refused
    // change is put back by hand.
    if (!saved && event.target instanceof HTMLInputElement) event.target.checked = rule.active;
  }

  protected async setSeverity(rule: ProfileRule, event: Event): Promise<void> {
    const value = inputValue(event);
    const severity = SEVERITIES.includes(value) ? (value as Severity) : null;
    const saved = await this.put(
      rule.rule.key,
      { active: rule.active, severityOverride: severity },
      () =>
        severity
          ? $localize`:@@profile.changed.severity:Severity of ${rule.rule.key}:key: set to ${label('severity', severity)}:severity:.`
          : $localize`:@@profile.changed.severityDefault:${rule.rule.key}:key: has its rule's default severity again.`,
    );
    if (!saved && event.target instanceof HTMLSelectElement) {
      event.target.value = rule.severityOverride ?? '';
    }
  }

  protected setKey(event: Event): void {
    this.newKey.set(inputValue(event));
    this.keyError.set(null);
  }

  protected setNewActive(event: Event): void {
    this.newActive.set(isChecked(event));
  }

  /** Ruling X5: decide a rule by its key, even one no report has named yet. */
  protected async decide(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const key = this.newKey().trim();
    if (!isRuleKey(key)) {
      this.keyError.set($localize`:@@profile.keyInvalid:Enter a rule key such as eslint:no-eval.`);
      return;
    }
    const active = this.newActive();
    await this.run(async (current) => {
      const updated = await ok(
        this.api.client.PUT('/api/v0/quality-profiles/{id}/rules/{ruleKey}', {
          params: { path: { id: this.profileId(), ruleKey: key } },
          body: { active, severityOverride: null },
        }),
      );
      if (!current()) return;
      this.placeRow(updated);
      this.newKey.set('');
      // "Set rule" is disabled once the key is cleared: keep keyboard users in the key field.
      keepFocus(this.injector, this.document, () =>
        this.document.getElementById('profile-rule-key'),
      );
      this.announcement.set(
        active
          ? $localize`:@@profile.decided.active:${key}:key: is now active in this profile.`
          : $localize`:@@profile.decided.inactive:${key}:key: is now inactive in this profile.`,
      );
    }, key);
  }

  protected async reset(rule: ProfileRule): Promise<void> {
    const key = rule.rule.key;
    const index = this.list.items().findIndex((r) => r.rule.key === key);
    await this.run(async (current) => {
      await done(
        this.api.client.DELETE('/api/v0/quality-profiles/{id}/rules/{ruleKey}', {
          params: { path: { id: this.profileId(), ruleKey: key } },
        }),
      );
      if (!current()) return;
      await this.refreshRow(key);
      if (!current()) return;
      this.announcement.set(
        $localize`:@@profile.changed.inherits:${key}:key: follows the parent profile again.`,
      );
      // The "Inherit again" button is gone: go to the same rule's checkbox, or the next row's.
      keepFocus(
        this.injector,
        this.document,
        () => rowByKey(this.table()?.nativeElement, key)?.querySelector('input'),
        () => rowAt(this.table()?.nativeElement, index)?.querySelector('input'),
        () => this.heading()?.nativeElement,
      );
    }, key);
  }

  private fetchRules(p: RuleQuery, cursor: string | null) {
    return ok(
      this.api.client.GET('/api/v0/quality-profiles/{id}/rules', {
        params: {
          path: { id: p.profileId },
          query: {
            limit: 100,
            scope: p.scope,
            ...(p.q ? { q: p.q } : {}),
            ...(cursor ? { cursor } : {}),
          },
        },
      }),
    );
  }

  /**
   * Asks for one rule again and patches its row (or drops it when the list no longer shows it),
   * keeping every page loaded so far. A key the search cannot express, or a search whose first
   * page does not settle the question, refreshes the loaded pages in place instead.
   */
  private async refreshRow(key: string): Promise<void> {
    const q = this.submitted();
    const matchesSearch = !q || key.toLowerCase().includes(q.toLowerCase());
    if (key.length > RULE_Q_MAX_LENGTH || !matchesSearch) {
      await this.list.refresh();
      return;
    }
    const page = await this.fetchRules(
      { profileId: this.profileId(), q: key, scope: this.scope() },
      null,
    );
    const found = page.items.find((r) => r.rule.key === key);
    if (!found && page.nextCursor !== null) {
      await this.list.refresh();
      return;
    }
    this.list.items.update((items) =>
      found
        ? items.map((r) => (r.rule.key === key ? found : r))
        : items.filter((r) => r.rule.key !== key),
    );
  }

  /**
   * A rule set by key: its row is replaced, or inserted in key order when it falls within the
   * pages loaded so far (a later page will bring it otherwise).
   */
  private placeRow(rule: ProfileRule): void {
    this.list.items.update((items) => {
      if (items.some((r) => r.rule.key === rule.rule.key)) {
        return items.map((r) => (r.rule.key === rule.rule.key ? rule : r));
      }
      const last = items.at(-1)?.rule.key;
      const q = this.submitted().toLowerCase();
      const shown = !q || rule.rule.key.toLowerCase().includes(q);
      if (
        !shown ||
        (this.list.nextCursor() !== null && last !== undefined && rule.rule.key > last)
      ) {
        return items;
      }
      const at = items.findIndex((r) => r.rule.key > rule.rule.key);
      return at < 0 ? [...items, rule] : [...items.slice(0, at), rule, ...items.slice(at)];
    });
  }

  private async put(
    key: string,
    body: { active: boolean; severityOverride: Severity | null },
    announce: () => string,
  ): Promise<boolean> {
    return this.run(async (current) => {
      const updated = await ok(
        this.api.client.PUT('/api/v0/quality-profiles/{id}/rules/{ruleKey}', {
          params: { path: { id: this.profileId(), ruleKey: key } },
          body,
        }),
      );
      if (!current()) return;
      this.list.items.update((items) =>
        items.map((r) => (r.rule.key === updated.rule.key ? updated : r)),
      );
      this.announcement.set(announce());
    }, key);
  }

  /**
   * Runs one change for the rule `key`; false when it was refused (or another one was still
   * running). A refusal shows the rule as the server holds it, patched in place.
   */
  private async run(
    action: (current: () => boolean) => Promise<void>,
    key: string,
  ): Promise<boolean> {
    if (this.busy()) return false;
    const generation = this.generation;
    const current = () => generation === this.generation;
    this.busy.set(true);
    this.error.set(null);
    this.keyError.set(null);
    this.announcement.set(null);
    try {
      await action(current);
      return true;
    } catch (err) {
      if (!current()) return false;
      if (fieldErrors(err)['params.ruleKey']) {
        this.keyError.set(
          $localize`:@@profile.keyRefused:This profile cannot decide this rule. A language profile decides the rules of ESLint, PMD and SpotBugs; "Other engines" decides the rest.`,
        );
      } else {
        this.error.set(problemMessage(err));
        try {
          await this.refreshRow(key);
        } catch {
          // The alert already says the change failed; the row keeps what it showed.
        }
      }
      keepFocus(this.injector, this.document, () => this.heading()?.nativeElement);
      return false;
    } finally {
      if (current()) this.busy.set(false);
    }
  }
}
