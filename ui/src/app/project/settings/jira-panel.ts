import {
  Component,
  computed,
  DestroyRef,
  effect,
  type ElementRef,
  inject,
  Injector,
  input,
  output,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, done, ok } from '../../api/api';
import { ApiError, problemMessage } from '../../api/errors';
import type {
  JiraIssueType,
  JiraPickedProject,
  JiraProjectSettings,
  RequestBody,
} from '../../api/types';
import { SessionStore } from '../../auth/session';
import { jiraProblemFix, jiraProblemText } from '../../jira/jira-text';
import { closeModal, openAfterRender } from '../../shared/dialog';
import { inputValue, isChecked } from '../../shared/forms';
import type { ProjectDto } from '../current-project';

type Body = RequestBody<'/api/v0/projects/{id}/jira', 'put'>;
type MinSeverity = Body['autoCreate']['minSeverity'];
type SearchState = 'idle' | 'loading' | 'results' | 'empty' | 'error';

/** The issue severities a priority can be set for, in the order the panel lists them. */
const SEVERITIES = ['blocker', 'high', 'medium', 'low', 'info'] as const;
type Severity = (typeof SEVERITIES)[number];
type Priorities = Partial<Record<Severity, string>>;

/** The picker asks the server this long after the last keystroke. */
const SEARCH_DELAY_MS = 300;
const MAX_LABELS = 10;
const MAX_LABEL_LENGTH = 100;

/** The label field as labels: trimmed, without empty parts. */
function splitLabels(text: string): string[] {
  return text
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '');
}

/** What decides whether the form differs from the stored mapping (ids, not names). */
function signature(body: Body): string {
  return JSON.stringify([
    body.jiraProject.id,
    body.issueType.id,
    body.labels,
    SEVERITIES.map((s) => body.priorities?.[s] ?? null),
    body.autoCreate.minSeverity,
    body.autoCreate.exploited,
  ]);
}

/** A 502's fixed text, the fields of a refused issue type, else the text of the code. */
function jiraMessage(err: unknown): string {
  if (err instanceof ApiError) {
    if (err.code === 'JIRA_UNAVAILABLE' && err.problem?.detail) return err.problem.detail;
    const fields = err.problem?.missingFields;
    if (err.code === 'JIRA_ISSUE_TYPE_UNSUPPORTED' && fields && fields.length > 0) {
      const list = fields.join(', ');
      return $localize`:@@jira.panel.typeUnsupported:Qualor cannot fill these required fields of the issue type: ${list}:fields:.`;
    }
  }
  return problemMessage(err);
}

/**
 * Project → Settings → Jira (spec §6.9): which Jira project and issue type this project's Jira
 * issues go to, their labels and priorities, and the automatic rule. The panel reads its own state
 * (it is not part of the project) and, beside it, the Azure Boards mapping: a project uses one
 * tracker, so while Boards is mapped the panel says only that. After a failed load it shows only
 * the error and Try again, so a Save can never overwrite a mapping whose state is unknown. Without
 * a connection an organisation admin sees a link to Settings → Jira and everybody else nothing
 * (`shown` tells the page, which hides the panel's index link).
 */
@Component({
  selector: 'q-project-jira-panel',
  imports: [RouterLink],
  templateUrl: './jira-panel.html',
  styleUrl: './jira-panel.css',
})
export class ProjectJiraPanel {
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  private readonly injector = inject(Injector);
  /** Bumped by every load; an answer of an older one is dropped. */
  private loadSeq = 0;
  private otherSeq = 0;
  private searchSeq = 0;
  private typesSeq = 0;
  private searchTimer: ReturnType<typeof setTimeout> | undefined;
  /** The Jira project key the issue types in `types` were read for. */
  private typesFor: string | null = null;

  readonly project = input.required<ProjectDto>();
  /**
   * Bumped by the page when the Azure Boards panel saved or removed its mapping: the panel reads
   * the Boards mapping again (0 is the first render).
   */
  readonly otherTrackerVersion = input(0);
  /** Whether the panel has anything to show; the page hides its index link when not. */
  readonly shown = output<boolean>();
  /** The mapping was saved or removed; the page tells the Azure Boards panel. */
  readonly mappingChanged = output();

  protected readonly severities = SEVERITIES;
  protected readonly loaded = signal<JiraProjectSettings | null>(null);
  protected readonly loadError = signal<string | null>(null);
  protected readonly loading = signal(false);
  /** Whether the project has an Azure Boards mapping: the panel then shows one line. */
  protected readonly boardsMapped = signal(false);

  protected readonly isOrgAdmin = computed(() =>
    this.session.orgCan(this.project().organizationId, 'org.jira.manage'),
  );
  protected readonly isShown = computed(() => {
    const l = this.loaded();
    return (
      this.loadError() !== null || (l !== null && (l.connection !== null || this.isOrgAdmin()))
    );
  });

  protected readonly picked = signal<Pick<JiraPickedProject, 'id' | 'key' | 'name'> | null>(null);
  protected readonly query = signal('');
  protected readonly results = signal<readonly JiraPickedProject[]>([]);
  protected readonly searchState = signal<SearchState>('idle');
  protected readonly searchError = signal<string | null>(null);

  protected readonly types = signal<readonly JiraIssueType[] | null>(null);
  protected readonly typesError = signal<string | null>(null);
  protected readonly typeId = signal('');
  protected readonly labelsText = signal('');
  protected readonly priorities = signal<Priorities>({});
  protected readonly minSeverity = signal<MinSeverity>(null);
  protected readonly exploited = signal(false);

  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly removeError = signal<string | null>(null);
  private readonly dialog = viewChild<ElementRef<HTMLDialogElement>>('dialog');

  protected readonly problem = computed(() => {
    const code = this.loaded()?.connection?.problem?.code;
    return code ? { text: jiraProblemText(code), fix: jiraProblemFix(code) } : null;
  });

  protected readonly selectedType = computed(
    () => this.types()?.find((t) => t.id === this.typeId()) ?? null,
  );
  protected readonly labels = computed(() => splitLabels(this.labelsText()));
  protected readonly labelsError = computed(() => {
    if (this.selectedType()?.labels !== true) return null;
    const labels = this.labels();
    if (labels.some((l) => /\s/.test(l))) {
      return $localize`:@@jira.panel.labelSpace:A label cannot contain a space.`;
    }
    if (labels.some((l) => l.length > MAX_LABEL_LENGTH)) {
      return $localize`:@@jira.panel.labelLength:A label can have at most 100 characters.`;
    }
    if (labels.length > MAX_LABELS) {
      return $localize`:@@jira.panel.labelCount:Use at most 10 labels.`;
    }
    return null;
  });

  /** The priority field of the chosen issue type, when it has one. */
  protected readonly priorityField = computed(() => this.selectedType()?.priority ?? null);
  private readonly prioritiesComplete = computed(() => {
    const field = this.priorityField();
    if (!field?.required) return true;
    const chosen = this.priorities();
    return SEVERITIES.every((s) => (chosen[s] ?? '') !== '');
  });

  /** The body Save would send; null while the form is incomplete or invalid. */
  private readonly payload = computed<Body | null>(() => {
    const project = this.picked();
    const type = this.selectedType();
    if (!project || !type || !type.supported) return null;
    if (this.labelsError() !== null || !this.prioritiesComplete()) return null;
    const chosen: Priorities = {};
    if (type.priority) {
      for (const s of SEVERITIES) {
        const id = this.priorities()[s];
        if (id) chosen[s] = id;
      }
    }
    return {
      jiraProject: { id: project.id, key: project.key, name: project.name },
      issueType: { id: type.id, name: type.name },
      labels: type.labels ? this.labels() : [],
      priorities: Object.keys(chosen).length > 0 ? chosen : null,
      autoCreate: { minSeverity: this.minSeverity(), exploited: this.exploited() },
    };
  });

  protected readonly canSave = computed(() => {
    const body = this.payload();
    if (body === null) return false;
    const stored = this.loaded()?.mapping;
    if (!stored) return true;
    const storedBody: Body = {
      jiraProject: stored.jiraProject,
      issueType: stored.issueType,
      labels: stored.labels,
      priorities: stored.priorities,
      autoCreate: {
        minSeverity: stored.autoCreate.minSeverity,
        exploited: stored.autoCreate.exploited,
      },
    };
    return signature(body) !== signature(storedBody);
  });

  constructor() {
    // Only the id: the page reads the project again after other panels save, with the same id.
    const projectId = computed(() => this.project().id);
    effect(() => {
      const id = projectId();
      untracked(() => void this.load(id));
    });
    effect(() => {
      const version = this.otherTrackerVersion();
      if (version !== 0) untracked(() => void this.loadOther());
    });
    effect(() => {
      const shown = this.isShown();
      untracked(() => this.shown.emit(shown));
    });
    inject(DestroyRef).onDestroy(() => clearTimeout(this.searchTimer));
  }

  private seed(state: JiraProjectSettings): void {
    this.loaded.set(state);
    const m = state.mapping;
    this.query.set('');
    this.results.set([]);
    this.searchState.set('idle');
    this.minSeverity.set(m?.autoCreate.minSeverity ?? null);
    this.exploited.set(m?.autoCreate.exploited ?? false);
    this.labelsText.set(m ? m.labels.join(', ') : '');
    this.priorities.set((m?.priorities ?? {}) as Priorities);
    this.picked.set(m ? m.jiraProject : null);
    this.typeId.set(m ? m.issueType.id : '');
    if (!m) {
      ++this.typesSeq;
      this.types.set(null);
      this.typesFor = null;
    } else if (this.typesFor !== m.jiraProject.key) {
      void this.loadTypes(m.jiraProject.key);
    }
  }

  /**
   * Whether the project has an Azure Boards mapping; an unreadable answer counts as none (the PUT
   * refuses a second tracker anyway).
   */
  private async boardsMappedNow(id: string): Promise<boolean> {
    try {
      const state = await ok(
        this.api.client.GET('/api/v0/projects/{id}/boards', { params: { path: { id } } }),
      );
      return state.mapping !== null;
    } catch {
      return false;
    }
  }

  protected async load(id: string, retry = false): Promise<void> {
    const seq = ++this.loadSeq;
    ++this.otherSeq;
    this.loaded.set(null);
    // A retry keeps the alert and its button until the answer, so focus is not dropped.
    if (!retry) this.loadError.set(null);
    this.loading.set(true);
    try {
      const [state, boardsMapped] = await Promise.all([
        ok(this.api.client.GET('/api/v0/projects/{id}/jira', { params: { path: { id } } })),
        this.boardsMappedNow(id),
      ]);
      if (seq === this.loadSeq) {
        this.loadError.set(null);
        this.boardsMapped.set(boardsMapped);
        this.seed(state);
      }
    } catch (err) {
      if (seq === this.loadSeq) this.loadError.set(problemMessage(err));
    } finally {
      if (seq === this.loadSeq) this.loading.set(false);
    }
  }

  /** Reads the Azure Boards mapping again; the form appears when it went. */
  private async loadOther(): Promise<void> {
    const seq = ++this.otherSeq;
    const mapped = await this.boardsMappedNow(this.project().id);
    if (seq === this.otherSeq) this.boardsMapped.set(mapped);
  }

  protected async loadTypes(key: string): Promise<void> {
    const seq = ++this.typesSeq;
    this.types.set(null);
    this.typesError.set(null);
    this.typesFor = key;
    try {
      const answer = await ok(
        this.api.client.GET('/api/v0/projects/{id}/jira/issue-types', {
          params: { path: { id: this.project().id }, query: { jiraProject: key } },
        }),
      );
      if (seq === this.typesSeq) this.types.set(answer.items);
    } catch (err) {
      if (seq === this.typesSeq) {
        this.typesFor = null;
        this.typesError.set(jiraMessage(err));
      }
    }
  }

  protected touched(): void {
    this.announcement.set(null);
    this.error.set(null);
  }

  // The Jira project picker.

  protected search(event: Event): void {
    const text = inputValue(event);
    this.query.set(text);
    clearTimeout(this.searchTimer);
    ++this.searchSeq;
    this.touched();
    if (text.trim() === '') {
      this.results.set([]);
      this.searchState.set('idle');
      return;
    }
    this.searchState.set('loading');
    this.searchTimer = setTimeout(() => void this.runSearch(text.trim()), SEARCH_DELAY_MS);
  }

  private async runSearch(text: string): Promise<void> {
    const seq = ++this.searchSeq;
    this.searchError.set(null);
    try {
      const answer = await ok(
        this.api.client.GET('/api/v0/projects/{id}/jira/projects', {
          params: { path: { id: this.project().id }, query: { query: text } },
        }),
      );
      if (seq !== this.searchSeq) return;
      this.results.set(answer.items);
      this.searchState.set(answer.items.length > 0 ? 'results' : 'empty');
    } catch (err) {
      if (seq !== this.searchSeq) return;
      this.searchError.set(jiraMessage(err));
      this.searchState.set('error');
    }
  }

  protected choose(project: JiraPickedProject): void {
    this.touched();
    this.picked.set(project);
    this.query.set('');
    this.results.set([]);
    this.searchState.set('idle');
    this.typeId.set('');
    this.priorities.set({});
    void this.loadTypes(project.key);
  }

  protected changeProject(): void {
    this.touched();
    ++this.typesSeq;
    this.picked.set(null);
    this.types.set(null);
    this.typesError.set(null);
    this.typesFor = null;
    this.typeId.set('');
    this.priorities.set({});
  }

  // The issue type, labels and priorities.

  protected typeLabel(type: JiraIssueType): string {
    if (type.supported) return type.name;
    const name = type.name;
    const fields = type.missingFields.join(', ');
    return $localize`:@@jira.panel.typeNeeds:${name}:name: — needs: ${fields}:fields:`;
  }

  protected setType(event: Event): void {
    this.touched();
    this.typeId.set(inputValue(event));
    this.priorities.set({});
  }

  protected setLabels(event: Event): void {
    this.touched();
    this.labelsText.set(inputValue(event));
  }

  protected severityLabel(severity: Severity): string {
    switch (severity) {
      case 'blocker':
        return $localize`:@@jira.panel.severity.blocker:Blocker`;
      case 'high':
        return $localize`:@@jira.panel.severity.high:High`;
      case 'medium':
        return $localize`:@@jira.panel.severity.medium:Medium`;
      case 'low':
        return $localize`:@@jira.panel.severity.low:Low`;
      case 'info':
        return $localize`:@@jira.panel.severity.info:Info`;
    }
  }

  protected priorityId(severity: Severity): string {
    return `jira-priority-${severity}`;
  }

  protected setPriority(severity: Severity, event: Event): void {
    this.touched();
    this.priorities.update((p) => ({ ...p, [severity]: inputValue(event) }));
  }

  // The automatic rule.

  protected setMinSeverity(event: Event): void {
    this.touched();
    const value = inputValue(event);
    this.minSeverity.set(
      value === 'critical' || value === 'high' || value === 'medium' || value === 'low'
        ? value
        : null,
    );
  }

  protected setExploited(event: Event): void {
    this.touched();
    this.exploited.set(isChecked(event));
  }

  // Save and remove.

  protected async save(): Promise<void> {
    const body = this.payload();
    if (this.busy() || body === null || !this.canSave()) return;
    const id = this.project().id;
    const seq = this.loadSeq;
    const current = () => id === this.project().id && seq === this.loadSeq;
    this.busy.set(true);
    this.touched();
    try {
      const state = await ok(
        this.api.client.PUT('/api/v0/projects/{id}/jira', { params: { path: { id } }, body }),
      );
      if (current()) {
        this.seed(state);
        this.announcement.set($localize`:@@vulnerabilities.saved:Saved.`);
      }
      this.mappingChanged.emit();
    } catch (err) {
      if (current()) this.error.set(jiraMessage(err));
    } finally {
      this.busy.set(false);
    }
  }

  protected openRemove(): void {
    this.removeError.set(null);
    openAfterRender(this.injector, () => this.dialog()?.nativeElement);
  }

  protected closeRemove(): void {
    const dialog = this.dialog()?.nativeElement;
    if (dialog) closeModal(dialog);
    this.removeError.set(null);
  }

  protected async remove(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy()) return;
    const id = this.project().id;
    this.busy.set(true);
    this.removeError.set(null);
    try {
      await done(
        this.api.client.DELETE('/api/v0/projects/{id}/jira', { params: { path: { id } } }),
      );
    } catch (err) {
      this.removeError.set(problemMessage(err));
      this.busy.set(false);
      return;
    }
    this.busy.set(false);
    this.closeRemove();
    this.touched();
    this.mappingChanged.emit();
    await this.load(id);
  }
}
