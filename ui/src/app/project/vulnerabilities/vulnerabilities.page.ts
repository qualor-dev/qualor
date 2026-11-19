import {
  Component,
  computed,
  effect,
  ElementRef,
  inject,
  Injector,
  input,
  resource,
  signal,
  viewChild,
} from '@angular/core';
import { NgTemplateOutlet } from '@angular/common';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, type Params, RouterLink } from '@angular/router';
import { Api, ok } from '../../api/api';
import { problemMessage } from '../../api/errors';
import type { RequestBody, ResponseBody } from '../../api/types';
import { SessionStore } from '../../auth/session';
import { FixProjectState } from '../../fixes/fix-project';
import { closeModal, openAfterRender } from '../../shared/dialog';
import { keepFocus, rowByKey } from '../../shared/focus';
import { DateTimePipe } from '../../shared/date-time.pipe';
import { Icon } from '../../shared/icon';
import { menuIndex } from '../../shared/menu-keys';
import { closePopover } from '../../shared/popover';
import { SbomUploadDialog } from './sbom-upload-dialog';
import { SeverityChips } from './severity-chips';
import { type SeverityFilter, type StatusFilter, VulnerabilityList } from './vulnerability-list';
import { CurrentProject } from '../current-project';
import { ExportMenu, type ExportKind, type ExportOption } from '../export-menu';

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
  imports: [
    DateTimePipe,
    ExportMenu,
    Icon,
    NgTemplateOutlet,
    RouterLink,
    SbomUploadDialog,
    SeverityChips,
    VulnerabilityList,
  ],
  templateUrl: './vulnerabilities.page.html',
  styleUrl: './vulnerabilities.page.css',
  // The project's fix MR settings are read afresh for each visit.
  providers: [FixProjectState],
  host: {
    '(window:scroll)': 'closeMenus()',
    '(window:resize)': 'closeMenus()',
  },
})
export class VulnerabilitiesPage {
  private readonly api = inject(Api);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly injector = inject(Injector);
  private readonly route = inject(ActivatedRoute);
  private readonly project = inject(CurrentProject);
  private readonly session = inject(SessionStore);
  private readonly fixes = inject(FixProjectState);
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
  /**
   * The viewed target as the summary has it, tracked or not, for its name and the chips beside it
   * (brief §C); null until the summary is read, or for an id it does not know.
   */
  protected readonly viewedTarget = computed(() => {
    const id = (this.target() ?? '').split(':')[1];
    const a = this.answer();
    const tracked = a?.targets.find((t) => t.id === id);
    if (tracked) return tracked;
    const untracked = a?.untracked.find((t) => t.id === id);
    return untracked ? { ...untracked, isMain: false } : null;
  });
  /** The viewed target's name: tracked or not, as the summary names it; else the URL's id. */
  protected readonly targetName = computed(() => this.viewedTarget()?.name ?? null);
  /** Nothing open anywhere: every tracked target has zero counts. */
  protected readonly clean = computed(() =>
    this.targets().every((t) => Object.values(t.counts).every((n) => n === 0)),
  );
  /**
   * Ruling FW10: "3 of 5 fix MRs in progress": the fixes in flight (requested, preparing,
   * committing, open; what the cap counts, R9) against the project's limit, while they are on.
   */
  protected readonly fixLine = computed(() => {
    const state = this.fixes.of(this.projectId())();
    if (state === null || !state.enabled) return null;
    const inProgress = Object.values(state.counts).reduce((sum, n) => sum + n, 0);
    return { inProgress, max: state.maxOpen };
  });
  protected readonly isInstanceAdmin = computed(
    () => this.session.user()?.isInstanceAdmin === true,
  );
  /** Whether the caller may pin and unpin versions (`project.settings`). */
  protected readonly canPin = computed(() =>
    this.project.canChange(this.projectId(), 'project.settings'),
  );

  /** Whether the caller may upload an SBOM (`project.analyze`). */
  protected readonly canUpload = computed(() =>
    this.project.canChange(this.projectId(), 'project.analyze'),
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

  /** Targets the SBOM is available for: tracked first, then the untracked versions. */
  private readonly sbomOptions = computed(() => this.exportOptions((t) => t.hasInventory));
  /** Targets the VEX is available for: checked at least once, while monitoring is on. */
  private readonly vexOptions = computed(() =>
    this.answer()?.monitoring === 'on' ? this.exportOptions((t) => t.checkedAt !== null) : [],
  );
  /** The project's key, which the export routes take; empty until the project is read. */
  protected readonly projectKey = computed(() => this.project.current()?.key ?? '');

  protected readonly busy = signal(false);
  /** The `data-key` of the row a change was made on, until the summary is read again. */
  private readonly pendingFocus = signal<string | null>(null);
  protected readonly table = viewChild<ElementRef<HTMLElement>>('table');
  private readonly foldButton = viewChild<ElementRef<HTMLElement>>('foldButton');
  private readonly panelScroll = viewChild<ElementRef<HTMLElement>>('panelScroll');
  protected readonly uploadDialog = viewChild(SbomUploadDialog);
  private readonly deleteDialog = viewChild<ElementRef<HTMLDialogElement>>('deleteDialog');
  /** The version the delete confirmation is about; null while the dialog is closed. */
  protected readonly toDelete = signal<{ id: string; name: string } | null>(null);
  protected readonly deleting = signal(false);
  protected readonly deleteError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);

  protected readonly gitlabSnippet = '- if: $CI_COMMIT_TAG';
  protected readonly githubSnippet = "push: tags: ['**']";

  private exportOptions(
    offered: (t: { hasInventory: boolean; checkedAt: string | null }) => boolean,
  ): ExportOption[] {
    const toOption = (kind: 'branch' | 'version', t: { id: string; name: string }) => ({
      value: `${kind}:${t.id}`,
      kind,
      name: t.name,
    });
    return [
      ...this.targets()
        .filter(offered)
        .map((t) => toOption(t.kind, t)),
      ...this.untracked()
        .filter(offered)
        .map((t) => toOption('version', t)),
    ];
  }

  constructor() {
    // A change moves a version between the table and the fold, and the row it was made on is gone
    // or kept: once the summary is read again, focus goes to the row's link, else the fold's button,
    // else the table's scroll box. The menu closes and every trigger is disabled while the change
    // runs, so the browser drops focus to the body, a row that stays included: its link takes it.
    // A failed change sets the same key (the summary is still there), and a reload that ends in
    // an error clears it, so it cannot fire at a later read.
    effect(() => {
      const key = this.pendingFocus();
      if (key === null) return;
      if (this.summary.status() === 'error') {
        this.pendingFocus.set(null);
        return;
      }
      if (this.summary.status() !== 'resolved') return;
      this.pendingFocus.set(null);
      keepFocus(
        this.injector,
        document,
        () => rowByKey(this.table()?.nativeElement, key)?.querySelector<HTMLElement>('a.row-link'),
        () => this.foldButton()?.nativeElement,
        () => this.panelScroll()?.nativeElement,
      );
    });
  }

  protected openUpload(): void {
    this.uploadDialog()?.open();
  }

  /** An SBOM was stored: the summary has a new or replaced version. */
  protected uploaded(): void {
    this.summary.reload();
  }

  /** `debian 12.15`; the text of a distribution the SBOM names. */
  protected distributionLabel(d: { family: string; version: string }): string {
    return `${d.family} ${d.version}`;
  }

  protected askDelete(menu: HTMLElement, row: { id: string; name: string }): void {
    if (this.deleting()) return;
    this.close(menu);
    this.toDelete.set({ id: row.id, name: row.name });
    this.deleteError.set(null);
    openAfterRender(
      this.injector,
      () => this.deleteDialog()?.nativeElement,
      () => this.toDelete() !== null,
    );
  }

  protected closeDelete(): void {
    const dialog = this.deleteDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.toDelete.set(null);
  }

  protected async confirmDelete(): Promise<void> {
    const version = this.toDelete();
    if (!version || this.deleting()) return;
    this.deleting.set(true);
    this.deleteError.set(null);
    try {
      await ok(
        this.api.client.DELETE('/api/v0/projects/{id}/versions/{versionId}', {
          params: { path: { id: this.projectId(), versionId: version.id } },
        }),
      );
      this.closeDelete();
      this.pendingFocus.set(`version:${version.id}`);
      this.summary.reload();
    } catch (err) {
      this.deleteError.set(problemMessage(err));
    } finally {
      this.deleting.set(false);
    }
  }

  /** The kinds of export the tab offers: none without the feature or without a target to export. */
  protected exports(): ExportKind[] {
    if (!this.answer()?.sbom) return [];
    return (['sbom', 'vex'] as const).filter((k) => this.optionsOf(k).length > 0);
  }

  protected optionsOf(kind: ExportKind): ExportOption[] {
    return kind === 'sbom' ? this.sbomOptions() : this.vexOptions();
  }

  /**
   * Whether a target gets the quiet "main" tag (brief §C): the main branch, unless its name says it
   * already.
   */
  protected mainTag(t: { isMain: boolean; name: string } | null): boolean {
    return t !== null && t.isMain && t.name !== 'main';
  }

  protected targetParam(t: Target): string {
    return `${t.kind}:${t.id}`;
  }

  /** What the menu offers on this version. */
  protected choices(tracking: Target['tracking']): Tracking[] {
    return tracking ? CHOICES[tracking] : [];
  }

  /** The menu changes the tracking and deletes the version: its names say both. */
  protected menuLabel(name: string): string {
    return $localize`:@@vuln.menu.label:Change tracking of ${name}:name: or delete it`;
  }

  protected groupLabel(name: string): string {
    return $localize`:@@vuln.menu.group:Tracking and deletion of ${name}:name:`;
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

  /** Closes a popover menu; jsdom has no Popover API. */
  protected close(menu: HTMLElement): void {
    closePopover(menu);
  }

  /**
   * The row menus are in the top layer and do not follow a scroll: close them. The export menus
   * close themselves on a scroll of the window, and a scroll of the table leaves them be.
   */
  protected closeMenus(): void {
    for (const menu of this.host.nativeElement.querySelectorAll<HTMLElement>('.row-menu-panel')) {
      this.close(menu);
    }
  }

  /** Arrow keys, Home and End move between the items; Tab leaves the menu and closes it. */
  protected menuKey(event: KeyboardEvent, menu: HTMLElement): void {
    if (event.key === 'Tab') {
      this.close(menu);
      return;
    }
    const items = [...menu.querySelectorAll<HTMLElement>('[role=menuitem]:not(:disabled)')];
    const next = menuIndex(
      event.key,
      items.indexOf(document.activeElement as HTMLElement),
      items.length,
    );
    if (next === null) return;
    event.preventDefault();
    items[next]?.focus();
  }

  /** The popover is shown after the click handlers ran, so its first item takes focus on toggle. */
  protected opened(event: Event, menu: HTMLElement): void {
    if ((event as ToggleEvent).newState !== 'open') return;
    menu.querySelector<HTMLElement>('[role=menuitem]:not(:disabled)')?.focus();
  }

  protected async change(menu: HTMLElement, versionId: string, tracking: Tracking): Promise<void> {
    if (this.busy()) return;
    this.close(menu);
    this.busy.set(true);
    this.error.set(null);
    try {
      await ok(
        this.api.client.PATCH('/api/v0/projects/{id}/versions/{versionId}', {
          params: { path: { id: this.projectId(), versionId } },
          body: { tracking },
        }),
      );
      this.pendingFocus.set(`version:${versionId}`);
      this.summary.reload();
    } catch (err) {
      this.error.set(problemMessage(err));
      // The menu closed and the triggers are disabled: the row's link takes focus at once.
      this.pendingFocus.set(`version:${versionId}`);
    } finally {
      this.busy.set(false);
    }
  }
}
