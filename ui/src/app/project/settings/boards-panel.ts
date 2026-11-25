import {
  Component,
  computed,
  DOCUMENT,
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
  BoardsConnection,
  BoardsPaths,
  BoardsPickedProject,
  BoardsProjectSettings,
  BoardsWorkItemType,
  RequestBody,
} from '../../api/types';
import { SessionStore } from '../../auth/session';
import { azureProblemText } from '../../settings/azure-text';
import { closeModal, openAfterRender } from '../../shared/dialog';
import { clearField, inputValue, isChecked } from '../../shared/forms';
import type { ProjectDto } from '../current-project';

type Body = RequestBody<'/api/v0/projects/{id}/boards', 'put'>;
type MinSeverity = Body['autoCreate']['minSeverity'];
type ProblemCode = NonNullable<BoardsConnection['problem']>['code'];

const MAX_TAGS = 10;
const MAX_TAG_LENGTH = 100;
/** Qualor adds this tag to every work item; the mapping may not list it (any case). */
const RESERVED_TAG = 'qualor';
const CONTROL_CHARACTER = /\p{Cc}/u;
/** What ends a typed tag: Azure DevOps separates tags with semicolons, people type commas. */
const TAG_SEPARATOR = /[;,]/;

/**
 * The connection problems that fail every Azure DevOps call, Boards' included: the panel shows them
 * as a banner. Hook and pull request problems belong to decoration and say nothing about Boards.
 */
const CREDENTIAL_PROBLEMS: ReadonlySet<ProblemCode> = new Set<ProblemCode>([
  'undecryptable',
  'url_not_allowed',
  'token_refused',
  'sign_in_required',
  'html_answer',
  'token_endpoint',
]);

/** The problem codes of a failed call that the connection Test's words describe for Boards too. */
const TEST_WORDS: ReadonlySet<string> = new Set<ProblemCode>([
  'undecryptable',
  'url_not_allowed',
  'not_public',
  'unresolved',
  'timeout',
  'unreachable',
  'token_refused',
  'sign_in_required',
  'html_answer',
  'token_endpoint',
  'token_endpoint_unreachable',
  'token_endpoint_timeout',
  'token_endpoint_error',
  'http_error',
  'bad_answer',
]);

/** An error of the panel: our sentence, and Azure DevOps' own words when it refused the mapping. */
interface PanelError {
  text: string;
  /** Azure DevOps' words of `BOARDS_CREATE_REFUSED` (cut to 500 by the server), shown as text. */
  quote: string | null;
  /** `TRACKER_IN_USE`: the sentence links to the Jira section. */
  toJira: boolean;
}

/** A 502 `BOARDS_UNAVAILABLE` in the UI's own words, by its `problemCode`. */
function unavailableText(code: string | undefined): string {
  if (code === 'permission_missing') {
    return $localize`:@@boards.panel.permission:The credential may not read or create work items in Azure DevOps. A personal access token needs Work Items: Read & write, and the identity needs "Edit work items in this node" on the area path.`;
  }
  if (code === 'not_found') {
    return $localize`:@@boards.panel.notFound:Azure DevOps did not find the project, or the credential cannot see it.`;
  }
  if (code !== undefined && TEST_WORDS.has(code)) {
    return azureProblemText({ code: code as ProblemCode });
  }
  return $localize`:@@boards.panel.unavailable:Azure DevOps could not be reached or refused the request. Try again later.`;
}

/** A failed Boards request in the UI's own words, chosen by its code (never the server's text). */
function boardsMessage(err: unknown): string {
  if (err instanceof ApiError) {
    switch (err.code) {
      case 'BOARDS_NOT_CONNECTED':
        return $localize`:@@boards.panel.notConnectedError:This connection is no longer an Azure DevOps connection of the organization. Reload the page.`;
      case 'BOARDS_UNAVAILABLE':
        return unavailableText(err.problem?.problemCode);
      case 'BOARDS_WORK_ITEM_TYPE_UNSUPPORTED': {
        const fields = err.problem?.missingFields ?? [];
        if (fields.length === 0) {
          return $localize`:@@boards.panel.typeGone:The Azure DevOps project no longer offers this work item type. Choose another one.`;
        }
        const list = fields.join(', ');
        return $localize`:@@boards.panel.typeUnsupported:Qualor cannot fill these required fields of the work item type: ${list}:fields:.`;
      }
      case 'BOARDS_PATH_UNKNOWN':
        return $localize`:@@boards.panel.pathUnknown:The Azure DevOps project no longer lists the chosen area path or iteration path. Choose them again.`;
    }
  }
  return problemMessage(err);
}

/** The error of a failed Save: the tracker in use and Azure DevOps' refusal have their own form. */
function saveError(err: unknown): PanelError {
  if (err instanceof ApiError && err.code === 'TRACKER_IN_USE') {
    return {
      text: $localize`:@@boards.panel.trackerInUse:This project uses Jira. Remove its Jira mapping first.`,
      quote: null,
      toJira: true,
    };
  }
  if (err instanceof ApiError && err.code === 'BOARDS_CREATE_REFUSED') {
    const words = err.problem?.detail ?? '';
    return words === ''
      ? {
          text: $localize`:@@boards.panel.refusedPlain:Azure DevOps refused a test work item with this mapping.`,
          quote: null,
          toJira: false,
        }
      : {
          text: $localize`:@@boards.panel.refused:Azure DevOps refused a test work item with this mapping. It said:`,
          quote: words,
          toJira: false,
        };
  }
  return { text: boardsMessage(err), quote: null, toJira: false };
}

/** The paths below the root: "Project root" (null) stands for the root itself. */
function belowRoot(paths: readonly string[]): string[] {
  return paths.filter((p) => p.includes('\\'));
}

/** A list of choices, with the current value added when the list does not hold it. */
function withCurrent(list: readonly string[], current: string): string[] {
  return current === '' || list.includes(current) ? [...list] : [current, ...list];
}

/** What decides whether the form differs from the stored mapping. */
function signature(body: Body): string {
  return JSON.stringify([
    body.connectionId,
    body.azureProject.id.toLowerCase(),
    body.workItemType.referenceName,
    body.areaPath,
    body.iterationPath,
    body.tags,
    body.autoCreate.minSeverity,
    body.autoCreate.exploited,
  ]);
}

/** A connection as the select names it: the organization or collection, and its host. */
function connectionLabel(connection: BoardsConnection): string {
  try {
    return `${connection.name} (${new URL(connection.baseUrl).host})`;
  } catch {
    return connection.name;
  }
}

/**
 * Project → Settings → Azure Boards (azure-devops design §7.8): which Azure DevOps project, work
 * item type, area and iteration path this project's work items go to, their tags, and the automatic
 * rule. It reads its own state and, beside it, the Jira mapping: a project uses one tracker, so
 * while Jira is mapped the panel says only that. After a failed load it shows only the error and
 * Try again. Without an Azure DevOps connection an organisation admin sees a link to Settings →
 * Azure DevOps and everybody else nothing (`shown` tells the page, which hides the index link).
 */
@Component({
  selector: 'q-project-boards-panel',
  imports: [RouterLink],
  templateUrl: './boards-panel.html',
  styleUrl: './boards-panel.css',
})
export class ProjectBoardsPanel {
  private readonly api = inject(Api);
  private readonly session = inject(SessionStore);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  /** Bumped by every load; an answer of an older one is dropped. */
  private loadSeq = 0;
  private otherSeq = 0;
  private projectsSeq = 0;
  private detailsSeq = 0;
  /** The connection the projects in `projects` were read for. */
  private projectsFor: string | null = null;
  /** The connection and Azure DevOps project the types and paths were read for. */
  private detailsFor: string | null = null;

  readonly project = input.required<ProjectDto>();
  /**
   * Bumped by the page when the Jira panel saved or removed its mapping: the panel reads the Jira
   * mapping again (0 is the first render).
   */
  readonly otherTrackerVersion = input(0);
  /** Whether the panel has anything to show; the page hides its index link when not. */
  readonly shown = output<boolean>();
  /** The mapping was saved or removed; the page tells the Jira panel. */
  readonly mappingChanged = output();

  protected readonly loaded = signal<BoardsProjectSettings | null>(null);
  protected readonly loadError = signal<string | null>(null);
  protected readonly loading = signal(false);
  /** Whether the project has a Jira mapping: the panel then shows one line. */
  protected readonly jiraMapped = signal(false);

  protected readonly isOrgAdmin = computed(() =>
    this.session.orgCan(this.project().organizationId, 'org.scm.manage'),
  );
  protected readonly isShown = computed(() => {
    const l = this.loaded();
    return (
      this.loadError() !== null ||
      (l !== null && (l.connections.length > 0 || l.mapping !== null || this.isOrgAdmin()))
    );
  });

  protected readonly connectionId = signal('');
  protected readonly projects = signal<readonly BoardsPickedProject[] | null>(null);
  protected readonly projectsError = signal<string | null>(null);
  protected readonly azureProjectId = signal('');
  protected readonly types = signal<readonly BoardsWorkItemType[] | null>(null);
  protected readonly typesError = signal<string | null>(null);
  protected readonly typeRef = signal('');
  protected readonly paths = signal<BoardsPaths | null>(null);
  protected readonly pathsError = signal<string | null>(null);
  /** '' is the project root (null in the body). */
  protected readonly areaPath = signal('');
  protected readonly iterationPath = signal('');
  protected readonly tags = signal<readonly string[]>([]);
  protected readonly tagText = signal('');
  protected readonly tagError = signal<string | null>(null);
  protected readonly minSeverity = signal<MinSeverity>(null);
  protected readonly exploited = signal(false);

  protected readonly busy = signal(false);
  protected readonly error = signal<PanelError | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly removeError = signal<string | null>(null);
  private readonly dialog = viewChild<ElementRef<HTMLDialogElement>>('dialog');
  private readonly tagField = viewChild<ElementRef<HTMLInputElement>>('tagField');

  protected readonly connections = computed(() => this.loaded()?.connections ?? []);
  protected readonly connection = computed(
    () => this.connections().find((c) => c.id === this.connectionId()) ?? null,
  );
  protected readonly connectionLabel = connectionLabel;

  /** The chosen connection's credential problem, in the Test's words. */
  protected readonly problem = computed(() => {
    const p = this.connection()?.problem;
    return p && CREDENTIAL_PROBLEMS.has(p.code) ? azureProblemText(p) : null;
  });

  /** The Azure DevOps projects to choose from, the stored one included when the list lacks it. */
  protected readonly projectOptions = computed<readonly BoardsPickedProject[]>(() => {
    const list = this.projects();
    if (list === null) return [];
    const stored = this.loaded()?.mapping?.azureProject;
    const id = this.azureProjectId();
    return stored && stored.id === id && !list.some((p) => p.id === id) ? [stored, ...list] : list;
  });
  protected readonly selectedProject = computed(
    () => this.projectOptions().find((p) => p.id === this.azureProjectId()) ?? null,
  );

  /** The work item types to choose from, the stored one included when the list lacks it. */
  protected readonly typeOptions = computed<readonly BoardsWorkItemType[]>(() => {
    const list = this.types();
    if (list === null) return [];
    const stored = this.loaded()?.mapping?.workItemType;
    const ref = this.typeRef();
    if (!stored || stored.referenceName !== ref || list.some((t) => t.referenceName === ref)) {
      return list;
    }
    return [{ ...stored, supported: true, missingFields: [] }, ...list];
  });
  protected readonly selectedType = computed(
    () => this.typeOptions().find((t) => t.referenceName === this.typeRef()) ?? null,
  );

  protected readonly areaOptions = computed(() =>
    withCurrent(belowRoot(this.paths()?.areas ?? []), this.areaPath()),
  );
  protected readonly iterationOptions = computed(() =>
    withCurrent(belowRoot(this.paths()?.iterations ?? []), this.iterationPath()),
  );

  /** The body Save would send; null while the form is incomplete. */
  private readonly payload = computed<Body | null>(() => {
    const connection = this.connection();
    const project = this.selectedProject();
    const type = this.selectedType();
    if (!connection || !project || !type?.supported) return null;
    return {
      connectionId: connection.id,
      azureProject: { id: project.id, name: project.name },
      workItemType: { referenceName: type.referenceName },
      areaPath: this.areaPath() || null,
      iterationPath: this.iterationPath() || null,
      tags: [...this.tags()],
      autoCreate: { minSeverity: this.minSeverity(), exploited: this.exploited() },
    };
  });

  protected readonly canSave = computed(() => {
    const body = this.payload();
    if (body === null) return false;
    const stored = this.loaded()?.mapping;
    if (!stored) return true;
    const storedBody: Body = {
      connectionId: stored.connectionId,
      azureProject: stored.azureProject,
      workItemType: { referenceName: stored.workItemType.referenceName },
      areaPath: stored.areaPath,
      iterationPath: stored.iterationPath,
      tags: stored.tags,
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
  }

  /** Whether the project has a Jira mapping; an unreadable answer counts as none (the PUT checks). */
  private async jiraMappedNow(id: string): Promise<boolean> {
    try {
      const state = await ok(
        this.api.client.GET('/api/v0/projects/{id}/jira', { params: { path: { id } } }),
      );
      return state.mapping !== null;
    } catch {
      return false;
    }
  }

  /** The connection a new mapping starts from: the repository's when it is Azure, else the first. */
  private defaultConnection(state: BoardsProjectSettings): string {
    if (state.mapping) return state.mapping.connectionId;
    const repository = this.project().scmConnectionId;
    if (repository && state.connections.some((c) => c.id === repository)) return repository;
    return state.connections[0]?.id ?? '';
  }

  private seed(state: BoardsProjectSettings): void {
    this.loaded.set(state);
    const m = state.mapping;
    this.connectionId.set(this.defaultConnection(state));
    this.azureProjectId.set(m ? m.azureProject.id : '');
    this.typeRef.set(m ? m.workItemType.referenceName : '');
    this.areaPath.set(m?.areaPath ?? '');
    this.iterationPath.set(m?.iterationPath ?? '');
    this.tags.set(m ? m.tags : []);
    this.tagText.set('');
    this.tagError.set(null);
    this.minSeverity.set(m?.autoCreate.minSeverity ?? null);
    this.exploited.set(m?.autoCreate.exploited ?? false);
    if (this.jiraMapped()) return;
    const connection = this.connectionId();
    if (connection !== '' && this.projectsFor !== connection) void this.loadProjects(connection);
    if (m) {
      if (this.detailsFor !== `${connection} ${m.azureProject.id}`) {
        void this.loadDetails(connection, m.azureProject.id);
      }
    } else {
      this.clearDetails();
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
      const [state, jiraMapped] = await Promise.all([
        ok(this.api.client.GET('/api/v0/projects/{id}/boards', { params: { path: { id } } })),
        this.jiraMappedNow(id),
      ]);
      if (seq === this.loadSeq) {
        this.loadError.set(null);
        this.jiraMapped.set(jiraMapped);
        this.seed(state);
      }
    } catch (err) {
      if (seq === this.loadSeq) this.loadError.set(problemMessage(err));
    } finally {
      if (seq === this.loadSeq) this.loading.set(false);
    }
  }

  /** Reads the Jira mapping again; the form appears (and its pickers load) when it went. */
  private async loadOther(): Promise<void> {
    const seq = ++this.otherSeq;
    const mapped = await this.jiraMappedNow(this.project().id);
    if (seq !== this.otherSeq) return;
    const was = this.jiraMapped();
    this.jiraMapped.set(mapped);
    const state = this.loaded();
    if (was && !mapped && state) this.seed(state);
  }

  private async loadProjects(connection: string): Promise<void> {
    const seq = ++this.projectsSeq;
    this.projects.set(null);
    this.projectsError.set(null);
    this.projectsFor = connection;
    try {
      const answer = await ok(
        this.api.client.GET('/api/v0/projects/{id}/boards/projects', {
          params: { path: { id: this.project().id }, query: { connection } },
        }),
      );
      if (seq === this.projectsSeq) this.projects.set(answer.items);
    } catch (err) {
      if (seq === this.projectsSeq) {
        this.projectsFor = null;
        this.projectsError.set(boardsMessage(err));
      }
    }
  }

  private clearDetails(): void {
    ++this.detailsSeq;
    this.detailsFor = null;
    this.types.set(null);
    this.typesError.set(null);
    this.paths.set(null);
    this.pathsError.set(null);
  }

  /** Reads the work item types and the paths of an Azure DevOps project, side by side. */
  private async loadDetails(connection: string, azureProject: string): Promise<void> {
    this.clearDetails();
    const seq = this.detailsSeq;
    this.detailsFor = `${connection} ${azureProject}`;
    const params = { path: { id: this.project().id }, query: { connection, azureProject } };
    const types = (async () => {
      try {
        const answer = await ok(
          this.api.client.GET('/api/v0/projects/{id}/boards/work-item-types', { params }),
        );
        if (seq === this.detailsSeq) this.types.set(answer.items);
      } catch (err) {
        if (seq === this.detailsSeq) {
          this.detailsFor = null;
          this.typesError.set(boardsMessage(err));
        }
      }
    })();
    const paths = (async () => {
      try {
        const answer = await ok(
          this.api.client.GET('/api/v0/projects/{id}/boards/paths', { params }),
        );
        if (seq === this.detailsSeq) this.paths.set(answer);
      } catch (err) {
        if (seq === this.detailsSeq) {
          this.detailsFor = null;
          this.pathsError.set(boardsMessage(err));
        }
      }
    })();
    await Promise.all([types, paths]);
  }

  protected touched(): void {
    this.announcement.set(null);
    this.error.set(null);
  }

  // The connection, the Azure DevOps project, the type and the paths.

  protected setConnection(event: Event): void {
    this.touched();
    const connection = inputValue(event);
    this.connectionId.set(connection);
    this.azureProjectId.set('');
    this.typeRef.set('');
    this.areaPath.set('');
    this.iterationPath.set('');
    this.clearDetails();
    void this.loadProjects(connection);
  }

  protected setProject(event: Event): void {
    this.touched();
    const azureProject = inputValue(event);
    this.azureProjectId.set(azureProject);
    this.typeRef.set('');
    this.areaPath.set('');
    this.iterationPath.set('');
    if (azureProject === '') this.clearDetails();
    else void this.loadDetails(this.connectionId(), azureProject);
  }

  protected typeLabel(type: BoardsWorkItemType): string {
    if (type.supported || type.missingFields.length === 0) return type.name;
    const name = type.name;
    const fields = type.missingFields.join(', ');
    return $localize`:@@boards.panel.typeNeeds:${name}:name: — Needs: ${fields}:fields:`;
  }

  protected setType(event: Event): void {
    this.touched();
    this.typeRef.set(inputValue(event));
  }

  protected setArea(event: Event): void {
    this.touched();
    this.areaPath.set(inputValue(event));
  }

  protected setIteration(event: Event): void {
    this.touched();
    this.iterationPath.set(inputValue(event));
  }

  // The tags: a chip per tag, typed into one field.

  /** Why `text` cannot be added as a tag; null when it can. */
  private tagProblem(text: string): string | null {
    const lower = text.toLowerCase();
    if (lower === RESERVED_TAG) {
      return $localize`:@@boards.panel.tagReserved:Qualor adds the tag qualor by itself.`;
    }
    if (CONTROL_CHARACTER.test(text)) {
      return $localize`:@@boards.panel.tagControl:A tag cannot contain a control character.`;
    }
    if (text.length > MAX_TAG_LENGTH) {
      return $localize`:@@boards.panel.tagLength:A tag can have at most 100 characters.`;
    }
    if (this.tags().some((t) => t.toLowerCase() === lower)) {
      return $localize`:@@boards.panel.tagTaken:This tag is already in the list.`;
    }
    if (this.tags().length >= MAX_TAGS) {
      return $localize`:@@boards.panel.tagCount:Use at most 10 tags.`;
    }
    return null;
  }

  /** Adds the typed text as a tag; false (with the reason shown) when it cannot be one. */
  private commitTag(raw: string): boolean {
    const text = raw.trim();
    if (text === '') return true;
    const problem = this.tagProblem(text);
    this.tagError.set(problem);
    if (problem !== null) return false;
    this.tags.update((tags) => [...tags, text]);
    return true;
  }

  protected typeTags(event: Event): void {
    this.touched();
    const text = inputValue(event);
    if (!TAG_SEPARATOR.test(text)) {
      this.tagText.set(text);
      return;
    }
    const parts = text.split(TAG_SEPARATOR);
    let rest = parts.pop() ?? '';
    for (const [i, part] of parts.entries()) {
      if (!this.commitTag(part)) {
        // The refused tag and what follows it stay in the field, to correct.
        rest = [...parts.slice(i), rest].join(', ');
        break;
      }
    }
    this.tagText.set(rest);
    if (event.target instanceof HTMLInputElement) event.target.value = rest;
  }

  protected enterTag(event: Event): void {
    event.preventDefault();
    if (this.commitTag(this.tagText())) clearField(this.tagField(), this.tagText);
  }

  /** Leaving the field keeps what was typed: Save never drops a tag the person wrote. */
  protected leaveTags(): void {
    if (this.tagText().trim() !== '' && this.commitTag(this.tagText())) {
      clearField(this.tagField(), this.tagText);
    }
  }

  protected removeTag(tag: string): void {
    this.touched();
    this.tagError.set(null);
    this.tags.update((tags) => tags.filter((t) => t !== tag));
    this.tagField()?.nativeElement.focus();
  }

  protected removeTagLabel(tag: string): string {
    return $localize`:@@boards.panel.removeTag:Remove the tag ${tag}:tag:`;
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

  /** The Jira section of this page: a plain click scrolls to it and focuses its heading. */
  protected goToJira(event: MouseEvent): void {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) {
      return;
    }
    const section = this.document.getElementById('jira');
    if (section?.tagName !== 'SECTION') return;
    section.scrollIntoView();
    section.querySelector<HTMLElement>('h2')?.focus({ preventScroll: true });
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
        this.api.client.PUT('/api/v0/projects/{id}/boards', { params: { path: { id } }, body }),
      );
      if (current()) {
        this.seed(state);
        this.announcement.set($localize`:@@vulnerabilities.saved:Saved.`);
      }
      this.mappingChanged.emit();
    } catch (err) {
      if (current()) {
        this.error.set(saveError(err));
        // The lists may be out of date: read them again, so the choice can be made anew.
        const code = err instanceof ApiError ? err.code : null;
        if (code === 'BOARDS_PATH_UNKNOWN' || code === 'BOARDS_WORK_ITEM_TYPE_UNSUPPORTED') {
          void this.loadDetails(body.connectionId, body.azureProject.id);
        }
      }
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
        this.api.client.DELETE('/api/v0/projects/{id}/boards', { params: { path: { id } } }),
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
