import {
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Location } from '@angular/common';
import { Router, RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { ApiError, fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { Distribution, type DistributionItem } from '../charts/distribution';
import { Lens } from '../charts/lens';
import { label } from '../i18n/labels';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { inputValue } from '../shared/forms';
import { GateBadge } from '../shared/gate-badge';
import { Icon } from '../shared/icon';
import { KeysetList } from '../shared/keyset';
import { MeasurePipe } from '../shared/measure.pipe';
import { PageHeader } from '../shared/page-header';

export type Project = ItemOf<'/api/v0/projects'>;
const PAGE_SIZE = 50;
/** The API's limit for `q`, key and name (openapi.json): longer text would only be refused. */
const MAX_TEXT = 255;

/**
 * The current organisation's projects (brief §2.3, spec §7.2) on the ink band: a search that lives
 * in the URL, a summary of the listed projects (gate outcomes, open issues, average coverage, lines
 * of code, from the list itself), the table with keyset pages, and project creation in a dialog for
 * organisation admins.
 */
@Component({
  selector: 'q-projects-page',
  imports: [DateTimePipe, Distribution, GateBadge, Icon, Lens, MeasurePipe, PageHeader, RouterLink],
  templateUrl: './projects.page.html',
  styleUrl: './projects.page.css',
  host: { class: 'bleed' },
})
export class ProjectsPage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly router = inject(Router);
  private readonly location = inject(Location);
  protected readonly org = inject(OrgContext);

  /** `?q=`: a case-insensitive search on key and name (router input binding). */
  readonly q = input<string>();

  protected readonly maxText = MAX_TEXT;
  /** The main-branch measures the table shows, in column order. */
  protected readonly columns = ['issues', 'coverage', 'duplicated_lines_density', 'ncloc'];
  protected readonly search = signal('');
  protected readonly list = new KeysetList<Project, { organizationId: string | null; q: string }>(
    async (params, cursor) =>
      ok(
        this.api.client.GET('/api/v0/projects', {
          params: {
            query: {
              limit: PAGE_SIZE,
              ...(params.organizationId ? { organizationId: params.organizationId } : {}),
              ...(params.q ? { q: params.q } : {}),
              ...(cursor ? { cursor } : {}),
            },
          },
        }),
      ),
  );

  /**
   * The summary strip, over the projects listed so far (a next page may hold more: `partial`).
   * A figure with no value anywhere is null, shown as a dash.
   */
  protected readonly summary = computed(() => {
    const counts = { passed: 0, failed: 0, error: 0, none: 0, never: 0 };
    let issues: number | null = null;
    let ncloc: number | null = null;
    let coverage = 0;
    let covered = 0;
    for (const project of this.list.items()) {
      const status = project.mainBranch?.gateStatus;
      if (status === 'passed' || status === 'failed' || status === 'error' || status === 'none') {
        counts[status]++;
      } else {
        counts.never++;
      }
      const measures = project.mainBranch?.measures ?? {};
      const [i, n, c] = [measures['issues'], measures['ncloc'], measures['coverage']];
      if (typeof i === 'number') issues = (issues ?? 0) + i;
      if (typeof n === 'number') ncloc = (ncloc ?? 0) + n;
      if (typeof c === 'number') {
        coverage += c;
        covered++;
      }
    }
    const gates: DistributionItem[] = [
      { key: 'passed', label: label('gate', 'passed'), value: counts.passed, tone: 'passed' },
      { key: 'failed', label: label('gate', 'failed'), value: counts.failed, tone: 'failed' },
      ...(counts.error > 0
        ? [{ key: 'error', label: label('gate', 'error'), value: counts.error, tone: 'failed' }]
        : []),
      ...(counts.none > 0
        ? [{ key: 'none', label: label('gate', 'none'), value: counts.none, tone: 'none' }]
        : []),
      {
        key: 'never',
        label: $localize`:@@projects.summary.notAnalyzed:Not analyzed`,
        value: counts.never,
        tone: 'none',
      },
    ];
    return {
      gates,
      issues,
      ncloc,
      coverage: covered > 0 ? coverage / covered : null,
      partial: Boolean(this.list.nextCursor()),
    };
  });

  private readonly createDialog = viewChild<ElementRef<HTMLDialogElement>>('createDialog');

  protected readonly newKey = signal('');
  protected readonly newName = signal('');
  protected readonly creating = signal(false);
  protected readonly createError = signal<string | null>(null);
  protected readonly keyError = signal<string | null>(null);
  protected readonly nameError = signal<string | null>(null);
  /** The last creation's result, for the live region. */
  protected readonly announcement = signal<string | null>(null);
  private readonly keyField = viewChild<ElementRef<HTMLInputElement>>('keyField');
  private readonly nameField = viewChild<ElementRef<HTMLInputElement>>('nameField');
  protected readonly inputValue = inputValue;

  constructor() {
    // A notice another page passed along with the navigation (a deleted project). The navigation
    // in flight carries it; the history entry has it after a reload.
    const state: unknown =
      this.router.currentNavigation()?.extras.state ?? this.location.getState();
    const notice = (state as { notice?: unknown } | null)?.notice;
    if (typeof notice === 'string' && notice !== '') this.announcement.set(notice);
    effect(() => {
      const q = (this.q() ?? '').trim().slice(0, MAX_TEXT);
      this.search.set(q);
      if (this.org.organizations.isLoading()) return;
      const organizationId = this.org.currentId();
      // Only the search and the organisation start a new load, not what the request reads.
      untracked(() => void this.list.reset({ organizationId, q }));
    });
  }

  protected submitSearch(event: Event): void {
    event.preventDefault();
    const q = this.search().trim().slice(0, MAX_TEXT);
    void this.router.navigate([], { queryParams: { q: q || null }, replaceUrl: true });
  }

  protected openCreate(): void {
    openAfterRender(this.injector, () => this.createDialog()?.nativeElement);
  }

  protected closeCreate(): void {
    const dialog = this.createDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
  }

  protected setKey(event: Event): void {
    this.newKey.set(inputValue(event));
    this.keyError.set(null);
  }

  protected setName(event: Event): void {
    this.newName.set(inputValue(event));
    this.nameError.set(null);
  }

  /**
   * Creates a project and opens it. Blank fields are refused here; what the server refuses goes to
   * its field (`body.key`, `body.name`, 409 `PROJECT_KEY_TAKEN` on the key), and focus moves to
   * the first refused field. While the request runs the button stays focusable (`aria-disabled`).
   */
  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    const organizationId = this.org.currentId();
    if (!organizationId || !this.org.canChange('org.projects.create') || this.creating()) return;
    const key = this.newKey().trim();
    const name = this.newName().trim();
    this.keyError.set(key ? null : $localize`:@@projects.create.keyRequired:Enter a key.`);
    this.nameError.set(name ? null : $localize`:@@projects.create.nameRequired:Enter a name.`);
    if (!key || !name) {
      this.focusFirstInvalid();
      return;
    }
    this.creating.set(true);
    this.createError.set(null);
    this.announcement.set(null);
    try {
      const project = await ok(
        this.api.client.POST('/api/v0/projects', { body: { organizationId, key, name } }),
      );
      this.announcement.set($localize`:@@projects.created:Project ${project.name}:name: created.`);
      await this.router.navigate(['/projects', project.id]);
    } catch (err) {
      const fields = fieldErrors(err);
      if (err instanceof ApiError && err.code === 'PROJECT_KEY_TAKEN') {
        this.keyError.set(problemMessage(err));
      } else if (fields['body.key'] !== undefined) {
        this.keyError.set(
          $localize`:@@projects.create.badKey:Use letters, digits and . _ - / : for the key.`,
        );
      }
      if (fields['body.name'] !== undefined) {
        this.nameError.set(
          $localize`:@@projects.create.badName:Enter a name of at most 255 characters, without control characters.`,
        );
      }
      if (!this.keyError() && !this.nameError()) this.createError.set(problemMessage(err));
      this.focusFirstInvalid();
    } finally {
      this.creating.set(false);
    }
  }

  private focusFirstInvalid(): void {
    if (this.keyError()) this.keyField()?.nativeElement.focus();
    else if (this.nameError()) this.nameField()?.nativeElement.focus();
  }
}
