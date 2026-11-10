import {
  Component,
  computed,
  DestroyRef,
  effect,
  type ElementRef,
  inject,
  Injector,
  input,
  LOCALE_ID,
  linkedSignal,
  resource,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { done, ok } from '../api/api';
import { type ComplianceReport, EeApi } from '../api/ee';
import { ApiError, problemMessage } from '../api/errors';
import { label } from '../i18n/labels';
import { DateTimePipe, formatDateTime } from '../shared/date-time.pipe';
import { closeModal, openAfterRender } from '../shared/dialog';
import { inputValue } from '../shared/forms';

/** Whose reports: an organisation's (organisation reports only) or a project's. */
export type ComplianceScope = { organizationId: string } | { projectId: string };
/** A branch a project report can be made of. */
export interface ComplianceBranch {
  id: string;
  name: string;
  isMain: boolean;
}

/** A version a project report can be made of (its dependencies only). */
export interface ComplianceVersion {
  id: string;
  label: string;
}

const REPORTS = '/api/v0/ee/compliance/reports';
/** 4E-1 §4: a pending report is read again every 3 s until it is ready or failed. */
const POLL_MS = 3_000;
const PAGE_SIZE = 50;
/** The part of the sha256 a row shows; the copy button copies all 64 characters. */
const HASH_PREFIX = 12;
const SEVERITIES = ['blocker', 'high', 'medium', 'low', 'info'] as const;
const FORMATS = ['json', 'csv', 'pdf'] as const;
/**
 * The standards' names (4E-1 §2.2). A report carries only their ids; one this list does not know
 * (a newer server) is shown by its id.
 */
const STANDARD_TITLES: Readonly<Record<string, string>> = {
  'owasp-top10-2021': 'OWASP Top 10 2021',
  'owasp-top10-2025': 'OWASP Top 10 2025',
  'cwe-top25-2025': 'CWE Top 25 2025',
  'asvs-4.0.3': 'OWASP ASVS 4.0.3',
  'pci-dss-4.0.1-6.2.4': 'PCI DSS 4.0.1 requirement 6.2.4',
};

/**
 * Compliance reports (4E-1 §4), of a project (its Compliance tab) or of an organisation (Settings →
 * Compliance reports): the list, newest first, polled every 3 s while a report is being built;
 * **Create report** for those who may (a branch or a version to choose for a project); a ready report's JSON,
 * CSV and PDF as plain download links, as the audit log exports; its sha256 to copy; Delete when
 * the server says the caller may; and a ready report's summary, by standard. The pages around it
 * check the licence; the server decides every action.
 */
@Component({
  selector: 'q-compliance-reports',
  imports: [DateTimePipe],
  templateUrl: './compliance-reports.component.html',
  styleUrl: './compliance-reports.component.css',
})
export class ComplianceReportsComponent {
  private readonly ee = inject(EeApi);
  private readonly injector = inject(Injector);
  private readonly locale = inject(LOCALE_ID);

  readonly scope = input.required<ComplianceScope>();
  readonly canCreate = input(false);
  readonly branches = input<ComplianceBranch[]>([]);
  readonly versions = input<ComplianceVersion[]>([]);

  protected readonly list = resource({
    params: () => this.scope(),
    loader: ({ params }) =>
      ok(this.ee.client.GET(REPORTS, { params: { query: { ...params, limit: PAGE_SIZE } } })),
  });
  /** The rows: the first page, then what this page created, polled, loaded or deleted. */
  protected readonly reports = linkedSignal<ComplianceReport[]>(() =>
    this.list.hasValue() ? this.list.value().items : [],
  );
  protected readonly nextCursor = linkedSignal<string | null>(() =>
    this.list.hasValue() ? this.list.value().nextCursor : null,
  );
  protected readonly loaded = computed(() => this.list.hasValue());
  protected readonly listError = computed(() => {
    if (this.list.status() !== 'error') return null;
    const err = this.list.error();
    // rbac-audit.md §3: a project grant shows a project, never its organisation's reports.
    if (err instanceof ApiError && err.status === 403 && 'organizationId' in this.scope()) {
      return $localize`:@@compliance.membersOnly:Only members of the organisation can see its compliance reports.`;
    }
    return problemMessage(err);
  });
  protected readonly projectScope = computed(() => 'projectId' in this.scope());

  /**
   * What a new project report is made of, as `branch:<id>` or `version:<id>`: the main branch
   * until another target is chosen.
   */
  protected readonly target = linkedSignal(() => {
    const all = this.branches();
    const branch = all.find((b) => b.isMain) ?? all[0];
    return branch ? `branch:${branch.id}` : '';
  });
  protected readonly creating = signal(false);
  protected readonly createError = signal<string | null>(null);
  protected readonly loadingMore = signal(false);
  protected readonly moreError = signal<string | null>(null);
  /** The last change's result, for the live region. */
  protected readonly announcement = signal<string | null>(null);
  /** The report this page created whose build the announcement is about, until it finishes. */
  private readonly building = signal<string | null>(null);
  protected readonly copied = signal<{ hash: string; ok: boolean } | null>(null);

  /** The report the summary is shown for, and the standard chosen in it (else its first). */
  protected readonly selectedId = signal<string | null>(null);
  protected readonly standardId = signal<string | null>(null);
  protected readonly selected = computed(() => {
    const report = this.reports().find((r) => r.id === this.selectedId());
    return report?.status === 'ready' && report.summary ? report : null;
  });
  protected readonly summary = computed(() => this.selected()?.summary ?? null);
  protected readonly standard = computed(() => {
    const standards = this.summary()?.standards ?? [];
    return standards.find((s) => s.id === this.standardId()) ?? standards[0] ?? null;
  });

  /** The report the delete confirmation is about; null while the dialog is closed. */
  protected readonly toDelete = signal<ComplianceReport | null>(null);
  /** Whether any row may be deleted: the confirmation exists only then. */
  protected readonly deletable = computed(() => this.reports().some((r) => r.canDelete));
  protected readonly deleting = signal(false);
  protected readonly deleteError = signal<string | null>(null);
  private readonly deleteDialog = viewChild<ElementRef<HTMLDialogElement>>('deleteDialog');

  protected readonly severities = SEVERITIES;
  protected readonly formats = FORMATS;
  private destroyed = false;

  constructor() {
    inject(DestroyRef).onDestroy(() => (this.destroyed = true));
    // Another organisation or project: nothing of the previous one stays on screen.
    effect(() => {
      this.scope();
      untracked(() => {
        this.selectedId.set(null);
        this.standardId.set(null);
        this.createError.set(null);
        this.moreError.set(null);
        this.announcement.set(null);
        this.building.set(null);
        this.copied.set(null);
      });
    });
    // 4E-1 §4: while a report is pending, read it again in 3 s; the timer goes when nothing is
    // pending any more, when the rows change (a new timer follows) and when the page goes.
    effect((onCleanup) => {
      const pending = this.reports()
        .filter((r) => r.status === 'pending')
        .map((r) => r.id);
      if (pending.length === 0) return;
      const timer = setTimeout(() => void this.poll(pending), POLL_MS);
      onCleanup(() => clearTimeout(timer));
    });
  }

  /** Reads the pending reports again; a report deleted meanwhile leaves the list. */
  private async poll(ids: string[]): Promise<void> {
    const scope = this.scope();
    const answers = await Promise.all(
      ids.map(async (id): Promise<ComplianceReport | 'gone' | null> => {
        try {
          return await ok(
            this.ee.client.GET('/api/v0/ee/compliance/reports/{id}', { params: { path: { id } } }),
          );
        } catch (err) {
          return err instanceof ApiError && err.status === 404 ? 'gone' : null;
        }
      }),
    );
    if (this.destroyed || scope !== this.scope()) return;
    // Always a new array, so the poll goes on while a report stays pending (or the read failed).
    this.reports.update((rows) =>
      rows.flatMap((row) => {
        const answer = answers[ids.indexOf(row.id)];
        if (answer === 'gone') return [];
        return [answer ?? row];
      }),
    );
    this.announceBuilt();
  }

  /**
   * "Being built" no longer holds once that report is ready, failed or gone: a ready one is
   * announced; a failed one's row says why, so the success message just goes.
   */
  private announceBuilt(): void {
    const id = this.building();
    if (id === null) return;
    const report = this.reports().find((r) => r.id === id);
    if (report?.status === 'pending') return;
    this.building.set(null);
    this.announcement.set(
      report?.status === 'ready'
        ? $localize`:@@compliance.ready:The report is ready to download.`
        : null,
    );
  }

  protected setTarget(event: Event): void {
    this.target.set(inputValue(event));
  }

  protected async create(): Promise<void> {
    if (this.creating()) return;
    const scope = this.scope();
    const [kind, targetId] = this.target().split(':');
    const body =
      'projectId' in scope
        ? {
            projectId: scope.projectId,
            ...(targetId && kind === 'branch' ? { branchId: targetId } : {}),
            ...(targetId && kind === 'version' ? { versionId: targetId } : {}),
          }
        : { organizationId: scope.organizationId };
    this.creating.set(true);
    this.createError.set(null);
    this.announcement.set(null);
    this.building.set(null);
    try {
      const report = await ok(this.ee.client.POST(REPORTS, { body }));
      if (scope !== this.scope()) return;
      this.reports.update((rows) => [report, ...rows.filter((r) => r.id !== report.id)]);
      this.announcement.set(
        $localize`:@@compliance.created:The report is being built. It appears here as ready when it is done.`,
      );
      this.building.set(report.id);
      // Built already (a fast worker): say so now, as a poll would.
      this.announceBuilt();
    } catch (err) {
      if (scope === this.scope()) this.createError.set(this.createMessage(err));
    } finally {
      this.creating.set(false);
    }
  }

  private createMessage(err: unknown): string {
    if (err instanceof ApiError && err.code === 'REPORT_PENDING') {
      return $localize`:@@compliance.alreadyPending:A report is already being built here. Wait until it is ready, then create another.`;
    }
    if (err instanceof ApiError && err.code === 'NO_ANALYSIS') {
      return $localize`:@@compliance.noAnalysis:This branch has no successful analysis yet. Analyze it first, then create the report.`;
    }
    if (err instanceof ApiError && err.code === 'MONITORING_OFF') {
      return $localize`:@@compliance.monitoringOff:Vulnerability monitoring is off for this project`;
    }
    if (err instanceof ApiError && err.code === 'NOT_CHECKED') {
      return $localize`:@@compliance.notChecked:This version has not been checked for vulnerabilities yet`;
    }
    return problemMessage(err);
  }

  protected async more(): Promise<void> {
    const cursor = this.nextCursor();
    if (!cursor || this.loadingMore()) return;
    const scope = this.scope();
    this.loadingMore.set(true);
    this.moreError.set(null);
    try {
      const next = await ok(
        this.ee.client.GET(REPORTS, {
          params: { query: { ...scope, limit: PAGE_SIZE, cursor } },
        }),
      );
      if (scope !== this.scope()) return;
      this.reports.update((rows) => [
        ...rows,
        ...next.items.filter((item) => !rows.some((r) => r.id === item.id)),
      ]);
      this.nextCursor.set(next.nextCursor);
    } catch (err) {
      if (scope === this.scope()) this.moreError.set(problemMessage(err));
    } finally {
      this.loadingMore.set(false);
    }
  }

  /** Shows a ready report's summary, or hides it when it is the one shown. */
  protected toggleSummary(report: ComplianceReport): void {
    this.standardId.set(null);
    this.selectedId.update((id) => (id === report.id ? null : report.id));
  }

  protected download(report: ComplianceReport, format: string): string | null {
    return report.status === 'ready' ? `${REPORTS}/${report.id}/download?format=${format}` : null;
  }

  protected hashStart(hash: string): string {
    return hash.slice(0, HASH_PREFIX);
  }

  protected async copyHash(report: ComplianceReport): Promise<void> {
    if (!report.sha256) return;
    try {
      await navigator.clipboard.writeText(report.sha256);
      this.copied.set({ hash: report.sha256, ok: true });
    } catch {
      // No Clipboard API (an insecure context) or permission refused: the page shows the hash.
      this.copied.set({ hash: report.sha256, ok: false });
    }
  }

  protected standardTitle(id: string): string {
    return STANDARD_TITLES[id] ?? id;
  }

  protected severityLabel(severity: string): string {
    return label('severity', severity);
  }

  protected formatLabel(format: string): string {
    return format.toUpperCase();
  }

  /** A row's name for its buttons' labels: its date. */
  protected rowName(report: ComplianceReport): string {
    return formatDateTime(report.createdAt, this.locale);
  }

  // Each row action names its report, starting with the word it shows (WCAG label in name).
  protected copyLabel(report: ComplianceReport): string {
    return $localize`:@@compliance.copyLabel:Copy the SHA-256 of the report of ${this.rowName(report)}:date:`;
  }

  protected downloadLabel(report: ComplianceReport, format: string): string {
    return $localize`:@@compliance.downloadLabel:${this.formatLabel(format)}:format: of the report of ${this.rowName(report)}:date:`;
  }

  protected summaryLabel(report: ComplianceReport): string {
    return $localize`:@@compliance.summaryLabel:Summary of the report of ${this.rowName(report)}:date:`;
  }

  protected deleteLabel(report: ComplianceReport): string {
    return $localize`:@@compliance.deleteLabel:Delete the report of ${this.rowName(report)}:date:`;
  }

  protected askDelete(report: ComplianceReport): void {
    if (this.deleting()) return;
    this.toDelete.set(report);
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
  }

  protected async confirmDelete(): Promise<void> {
    const report = this.toDelete();
    if (!report || this.deleting()) return;
    this.deleting.set(true);
    this.deleteError.set(null);
    try {
      await done(
        this.ee.client.DELETE('/api/v0/ee/compliance/reports/{id}', {
          params: { path: { id: report.id } },
        }),
      );
      this.finishDelete(report);
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Someone else deleted it meanwhile: the page treats it as deleted.
        this.finishDelete(report);
        return;
      }
      this.deleteError.set(problemMessage(err));
      // Closed while the server answered (Escape): the dialog opens again on the refusal.
      openAfterRender(
        this.injector,
        () => this.deleteDialog()?.nativeElement,
        () => this.toDelete() !== null,
      );
    } finally {
      this.deleting.set(false);
    }
  }

  private finishDelete(report: ComplianceReport): void {
    this.closeDelete();
    this.toDelete.set(null);
    if (this.building() === report.id) this.building.set(null);
    if (this.selectedId() === report.id) this.selectedId.set(null);
    this.reports.update((rows) => rows.filter((r) => r.id !== report.id));
    this.announcement.set(
      $localize`:@@compliance.deleted:Deleted the report of ${this.rowName(report)}:date:.`,
    );
  }
}
