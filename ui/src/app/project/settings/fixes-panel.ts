import { Component, computed, effect, inject, input, signal, untracked } from '@angular/core';
import { Api, ok } from '../../api/api';
import { problemMessage } from '../../api/errors';
import type { FixSettingsAnswer, RequestBody } from '../../api/types';
import { can } from '../../auth/permissions';
import { fixPreconditionText } from '../../fixes/fix-text';
import { DateTimePipe } from '../../shared/date-time.pipe';
import { inputValue, isChecked } from '../../shared/forms';
import { Icon } from '../../shared/icon';
import { assertNever, type ScmProvider } from '../../shared/scm-provider';
import type { ProjectDto } from '../current-project';

type Body = RequestBody<'/api/v0/projects/{id}/fixes/settings', 'put'>;
type MinSeverity = Body['autoCreate']['minSeverity'];

/** The guide's section on the fix job; the CLI's messages link the same page. */
const FIX_JOB_GUIDE = 'https://qualor.dev/docs/fix-merge-requests#the-fix-job';
const MAX_OPEN_CHOICES = Array.from({ length: 20 }, (_, i) => i + 1);

/** The provider whose token needs the panel names; none while it is not known. */
function tokenNeedsOf(provider: ScmProvider | null): ScmProvider | null {
  if (provider === null) return null;
  switch (provider) {
    case 'gitlab':
    case 'github':
    case 'azure':
      return provider;
    default:
      return assertNever(provider, 'provider');
  }
}

/** The select's text as a severity; anything else is Off. */
function severityOf(value: string): MinSeverity {
  return value === 'critical' || value === 'high' || value === 'medium' || value === 'low'
    ? value
    : null;
}

/**
 * Project → Settings → Fix MRs (spec §6.9): the switch, the automatic rule and the cap of fix MRs
 * in flight, what still stops a request (the repository, the connection's switch, monitoring), and
 * whether the project's fix job has been seen. The panel reads its own settings (they are not part
 * of the project); after a failed load it shows only the error and Try again, so a Save can never
 * overwrite settings whose state is unknown. Without `project.settings` it shows them read-only.
 */
@Component({
  selector: 'q-project-fixes-panel',
  imports: [DateTimePipe, Icon],
  templateUrl: './fixes-panel.html',
  styleUrl: './fixes-panel.css',
})
export class ProjectFixesPanel {
  private readonly api = inject(Api);
  /** Bumped by every load; an answer of an older one is dropped. */
  private loadSeq = 0;

  readonly project = input.required<ProjectDto>();

  protected readonly guide = FIX_JOB_GUIDE;
  protected readonly maxOpenChoices = MAX_OPEN_CHOICES;

  /** The last state the server gave; null until the first answer. */
  protected readonly loaded = signal<FixSettingsAnswer | null>(null);
  protected readonly loadError = signal<string | null>(null);
  protected readonly loading = signal(false);

  protected readonly enabled = signal(false);
  protected readonly minSeverity = signal<MinSeverity>(null);
  protected readonly exploited = signal(false);
  protected readonly maxOpen = signal(5);

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);

  protected readonly editable = computed(() => can(this.project().permissions, 'project.settings'));

  /** The first precondition that is not met, as a sentence. */
  protected readonly unmet = computed(() => {
    const l = this.loaded();
    return l ? fixPreconditionText(l.preconditions) : null;
  });
  /** Switched on, but no fix job has asked for work yet. */
  protected readonly waitingForJob = computed(() => {
    const l = this.loaded();
    return l !== null && l.settings.enabled && l.preconditions.lastClaimAt === null;
  });
  /**
   * Ruling FW10: the fix MRs in progress, as the cap counts them (R9) and the Vulnerabilities header
   * says them: requested, preparing, being written and open.
   */
  protected readonly inProgress = computed(() => {
    const c = this.loaded()?.counts;
    return c ? c.requested + c.preparing + c.committing + c.open : 0;
  });
  /** The permissions the connection's token needs, for the project's provider (none when unknown). */
  protected readonly needs = computed(() =>
    tokenNeedsOf(this.loaded()?.preconditions.provider ?? null),
  );

  protected readonly body = computed<Body>(() => ({
    enabled: this.enabled(),
    autoCreate: { minSeverity: this.minSeverity(), exploited: this.exploited() },
    maxOpen: this.maxOpen(),
  }));

  protected readonly dirty = computed(() => {
    const stored = this.loaded()?.settings;
    if (!stored) return false;
    const mine = this.body();
    return (
      mine.enabled !== stored.enabled ||
      mine.autoCreate.minSeverity !== stored.autoCreate.minSeverity ||
      mine.autoCreate.exploited !== stored.autoCreate.exploited ||
      mine.maxOpen !== stored.maxOpen
    );
  });

  constructor() {
    // Only the id: the page reads the project again after other panels save, with the same id.
    const projectId = computed(() => this.project().id);
    effect(() => {
      const id = projectId();
      untracked(() => void this.load(id));
    });
  }

  private seed(state: FixSettingsAnswer): void {
    this.loaded.set(state);
    this.enabled.set(state.settings.enabled);
    this.minSeverity.set(state.settings.autoCreate.minSeverity);
    this.exploited.set(state.settings.autoCreate.exploited);
    this.maxOpen.set(state.settings.maxOpen);
  }

  protected async load(id: string, retry = false): Promise<void> {
    const seq = ++this.loadSeq;
    this.loaded.set(null);
    // A retry keeps the alert and its button until the answer, so focus is not dropped.
    if (!retry) this.loadError.set(null);
    this.loading.set(true);
    try {
      const state = await ok(
        this.api.client.GET('/api/v0/projects/{id}/fixes/settings', { params: { path: { id } } }),
      );
      if (seq === this.loadSeq) {
        this.loadError.set(null);
        this.seed(state);
      }
    } catch (err) {
      if (seq === this.loadSeq) this.loadError.set(problemMessage(err));
    } finally {
      if (seq === this.loadSeq) this.loading.set(false);
    }
  }

  protected touched(): void {
    this.announcement.set(null);
    this.error.set(null);
  }

  protected setEnabled(event: Event): void {
    this.touched();
    this.enabled.set(isChecked(event));
  }

  protected setMinSeverity(event: Event): void {
    this.touched();
    this.minSeverity.set(severityOf(inputValue(event)));
  }

  protected setExploited(event: Event): void {
    this.touched();
    this.exploited.set(isChecked(event));
  }

  protected setMaxOpen(event: Event): void {
    this.touched();
    const n = Number(inputValue(event));
    if (Number.isInteger(n) && n >= 1 && n <= 20) this.maxOpen.set(n);
  }

  protected async save(): Promise<void> {
    if (this.busy() || !this.editable() || !this.dirty()) return;
    const id = this.project().id;
    const seq = this.loadSeq;
    const current = () => id === this.project().id && seq === this.loadSeq;
    this.busy.set(true);
    this.touched();
    try {
      const state = await ok(
        this.api.client.PUT('/api/v0/projects/{id}/fixes/settings', {
          params: { path: { id } },
          body: this.body(),
        }),
      );
      if (current()) {
        this.seed(state);
        this.announcement.set($localize`:@@vulnerabilities.saved:Saved.`);
      }
    } catch (err) {
      if (current()) this.error.set(problemMessage(err));
    } finally {
      this.busy.set(false);
    }
  }
}
