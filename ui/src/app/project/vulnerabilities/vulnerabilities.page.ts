import { Component, computed, inject, input, resource, signal } from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, type Params, RouterLink } from '@angular/router';
import { Api, ok } from '../../api/api';
import { problemMessage } from '../../api/errors';
import type { RequestBody, ResponseBody } from '../../api/types';
import { SessionStore } from '../../auth/session';
import { DateTimePipe } from '../../shared/date-time.pipe';
import { Icon } from '../../shared/icon';
import { type SeverityFilter, type StatusFilter, VulnerabilityList } from './vulnerability-list';
import { CurrentProject } from '../current-project';

type Summary = ResponseBody<'/api/v0/projects/{id}/vulnerabilities/targets', 'get'>;
type Target = Summary['targets'][number];
type Tracking = RequestBody<'/api/v0/projects/{id}/versions/{versionId}', 'patch'>['tracking'];

/** The labels the fold names before it counts the rest. */
const FOLD_LABELS = 2;

/** The row menu's choices, by what the version is now. */
const CHOICES: Record<'auto' | 'pinned' | 'unsupported', Tracking[]> = {
  pinned: ['auto', 'unsupported'],
  auto: ['pinned', 'unsupported'],
  unsupported: ['auto', 'pinned'],
};

function one(params: Params, key: string): string {
  const value: unknown = params[key];
  return typeof value === 'string' ? value : '';
}

/**
 * Project → Vulnerabilities (vuln 2b §9.3), By version: the tracked branches and released
 * versions with their open Critical, High and Medium vulnerabilities and what is new, the
 * versions no rule tracks folded under the table, and, with `project.settings`, a menu on each
 * version to pin it, stop tracking it or track it by the rule again. `view`, `target` and the
 * other filters are held in the URL (By vulnerability and one target are the VulnerabilityList).
 */
@Component({
  selector: 'q-vulnerabilities-page',
  imports: [DateTimePipe, Icon, NgTemplateOutlet, RouterLink, VulnerabilityList],
  templateUrl: './vulnerabilities.page.html',
  styleUrl: './vulnerabilities.page.css',
})
export class VulnerabilitiesPage {
  private readonly api = inject(Api);
  private readonly route = inject(ActivatedRoute);
  private readonly project = inject(CurrentProject);
  private readonly session = inject(SessionStore);
  readonly projectId = input.required<string>();

  private readonly params = toSignal(this.route.queryParams, { initialValue: {} as Params });
  protected readonly view = computed<'version' | 'vulnerability'>(() =>
    one(this.params(), 'view') === 'vulnerability' ? 'vulnerability' : 'version',
  );
  protected readonly target = computed(() => one(this.params(), 'target') || null);
  protected readonly status = computed<StatusFilter>(() => {
    const value = one(this.params(), 'status');
    return value === 'open' || value === 'false_positive' || value === 'wont_fix' ? value : 'all';
  });
  protected readonly severity = computed<SeverityFilter>(() => {
    const value = one(this.params(), 'severity');
    return value === 'critical' ||
      value === 'high' ||
      value === 'medium' ||
      value === 'low' ||
      value === 'unknown'
      ? value
      : '';
  });
  protected readonly exploited = computed(() => one(this.params(), 'exploited') === 'true');
  protected readonly pageNumber = computed(() => {
    const n = Number(one(this.params(), 'page'));
    return Number.isInteger(n) && n >= 1 ? n : 1;
  });

  protected readonly summary = resource({
    params: () => ({ id: this.projectId() }),
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/projects/{id}/vulnerabilities/targets', {
          params: { path: { id: params.id } },
        }),
      ),
  });
  /** The summary once read; kept while it is read again. */
  protected readonly answer = computed<Summary | null>(() =>
    this.summary.hasValue() ? this.summary.value() : null,
  );
  protected readonly loadError = computed(() => {
    const error = this.summary.error();
    return error ? problemMessage(error) : null;
  });

  /** Main first, then the others as the server lists them. */
  protected readonly targets = computed(() => {
    const all = this.answer()?.targets ?? [];
    return [...all.filter((t) => t.isMain), ...all.filter((t) => !t.isMain)];
  });
  /** The viewed target's name: tracked or not, as the summary names it; else the URL's id. */
  protected readonly targetName = computed(() => {
    const id = (this.target() ?? '').split(':')[1];
    const all = [...(this.answer()?.targets ?? []), ...(this.answer()?.untracked ?? [])];
    return all.find((t) => t.id === id)?.name ?? null;
  });
  /** Nothing open anywhere: every tracked target has zero counts. */
  protected readonly clean = computed(() =>
    this.targets().every((t) => Object.values(t.counts).every((n) => n === 0)),
  );
  protected readonly isInstanceAdmin = computed(
    () => this.session.user()?.isInstanceAdmin === true,
  );
  /** Whether the caller may pin and unpin versions (`project.settings`). */
  protected readonly canPin = computed(() =>
    this.project.canChange(this.projectId(), 'project.settings'),
  );

  protected readonly expanded = signal(false);
  protected readonly untracked = computed(() => this.answer()?.untracked ?? []);
  protected readonly foldLabels = computed(() =>
    this.untracked()
      .slice(0, FOLD_LABELS)
      .map((v) => v.name)
      .join(' · '),
  );
  protected readonly foldMore = computed(() => Math.max(0, this.untracked().length - FOLD_LABELS));

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);

  protected readonly gitlabSnippet = '- if: $CI_COMMIT_TAG';
  protected readonly githubSnippet = "push: tags: ['**']";

  protected targetParam(t: Target): string {
    return `${t.kind}:${t.id}`;
  }

  /** What the menu offers on this version. */
  protected choices(tracking: Target['tracking']): Tracking[] {
    return tracking ? CHOICES[tracking] : [];
  }

  protected menuLabel(name: string): string {
    return $localize`:@@vuln.menu.label:Change tracking of ${name}:name:`;
  }

  protected groupLabel(name: string): string {
    return $localize`:@@vuln.menu.group:Tracking of ${name}:name:`;
  }

  protected choiceLabel(tracking: Tracking, from: Target['tracking']): string {
    if (tracking === 'pinned') return $localize`:@@vuln.menu.pin:Pin`;
    if (tracking === 'unsupported') return $localize`:@@vuln.menu.unsupported:Mark as unsupported`;
    return from === 'pinned'
      ? $localize`:@@vuln.menu.unpin:Unpin`
      : $localize`:@@vuln.menu.auto:Track automatically`;
  }

  /** The popover goes to the top layer, so the table's scroll box cannot clip it: place it. */
  protected place(button: HTMLElement, menu: HTMLElement): void {
    const rect = button.getBoundingClientRect();
    menu.style.top = `${Math.round(rect.bottom + 4)}px`;
    menu.style.right = `${Math.max(0, Math.round(document.documentElement.clientWidth - rect.right))}px`;
  }

  protected async change(menu: HTMLElement, versionId: string, tracking: Tracking): Promise<void> {
    // jsdom has no Popover API.
    const popover = menu as Partial<Pick<HTMLElement, 'hidePopover'>>;
    if (popover.hidePopover && menu.matches(':popover-open')) popover.hidePopover.call(menu);
    if (this.busy()) return;
    this.busy.set(true);
    this.error.set(null);
    try {
      await ok(
        this.api.client.PATCH('/api/v0/projects/{id}/versions/{versionId}', {
          params: { path: { id: this.projectId(), versionId } },
          body: { tracking },
        }),
      );
      this.summary.reload();
    } catch (err) {
      this.error.set(problemMessage(err));
    } finally {
      this.busy.set(false);
    }
  }
}
