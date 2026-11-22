import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  LOCALE_ID,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf } from '../api/types';
import { OrgContext } from '../org/org-context';
import { keepFocus } from '../shared/focus';
import { inputValue } from '../shared/forms';
import { KeysetList } from '../shared/keyset';
import { assertNever, type ScmProvider } from '../shared/scm-provider';
import { azureCertificateExpiredOn, azureTestText } from './azure-text';
import { githubTestText } from './github-text';
import { gitlabTestText } from './gitlab-text';
import type { Connection } from './gitlab.page';

type Project = ItemOf<'/api/v0/projects'>;

/** An Azure DevOps connection's repositories, as its list shows them. */
interface AzureList {
  state: 'loading' | 'loaded' | 'failed';
  /** More repositories remain than the pages listed. */
  more?: boolean;
  items: { ref: string; label: string }[];
}

/** At most this many pages of 100 repositories are listed for a mapping. */
const AZURE_LIST_PAGES = 10;

/** A project's mapping as edited on the page, before it is saved. */
interface Draft {
  connectionId: string;
  ref: string;
}

/**
 * Settings → Repositories (scm.md §2.3, github.md §2.3), for those whose role manages the SCM
 * connections: each project's repository, where its analyses are reported — a GitLab connection
 * and a GitLab project (its id or `group/project`), or a GitHub App and `owner/repo`. **Save**
 * stores a project's mapping; **Check** tests the connection against the project or repository
 * typed, and says what went wrong in the page's own words. The server checks the reference
 * against the connection's provider (422 on `body.scmProjectRef` / `body.projectRef`) and the
 * connection against the organisation (422 on `body.scmConnectionId`).
 *
 * Step 11 of the redesign (the maintainer's request): the mapping moved here from the GitLab page,
 * whose "Projects" table held the mappings of both providers.
 */
@Component({
  selector: 'q-repositories-page',
  imports: [RouterLink],
  templateUrl: './repositories.page.html',
  styleUrl: './repositories.page.css',
})
export class RepositoriesPage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly locale = inject(LOCALE_ID);
  protected readonly org = inject(OrgContext);
  /** The role manages these (`org.scm.manage`, rbac-audit.md §3.1): the page shows them. */
  protected readonly canRead = computed(() => this.org.can('org.scm.manage'));
  protected readonly canManage = computed(() => this.org.canChange('org.scm.manage'));
  /** Every connection, of both providers: each project may use either. */
  protected readonly connections = new KeysetList<Connection, string>((organizationId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/scm-connections', {
        params: { query: { organizationId, limit: 50, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  protected readonly projects = new KeysetList<Project, string>((organizationId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/projects', {
        params: { query: { organizationId, limit: 50, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** Check answers and saved mappings, in words, by project id. */
  protected readonly results = signal<Record<string, string>>({});
  protected readonly drafts = signal<Record<string, Draft>>({});
  protected readonly refErrors = signal<Record<string, string>>({});
  protected readonly connErrors = signal<Record<string, string>>({});
  /** The repositories of each Azure DevOps connection a mapping names, by connection id. */
  private readonly azureLists = signal<Record<string, AzureList>>({});
  private readonly azureRequested = new Set<string>();
  /** What each project's repository list is searched for, by project id. */
  protected readonly searches = signal<Record<string, string>>({});
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  /** Counts organisation changes: an answer for an earlier organisation is dropped. */
  private orgGeneration = 0;

  constructor() {
    effect(() => {
      const organizationId = this.org.currentId();
      const admin = this.canRead();
      untracked(() => {
        // Whatever belonged to the previous organisation goes, whether or not this one is shown.
        this.orgGeneration++;
        this.announcement.set(null);
        this.error.set(null);
        this.results.set({});
        this.drafts.set({});
        this.refErrors.set({});
        this.connErrors.set({});
        this.azureLists.set({});
        this.azureRequested.clear();
        this.searches.set({});
        if (organizationId && admin) {
          void this.connections.reset(organizationId);
          void this.projects.reset(organizationId);
        }
      });
    });
    // A mapping to an Azure DevOps connection picks from its repositories: listed once, when first named.
    effect(() => {
      const wanted = this.projects
        .items()
        .map((p) => ({ id: this.draft(p).connectionId, filter: this.search(p) }))
        .filter(({ id }) =>
          this.connections.items().some((c) => c.id === id && c.provider === 'azure'),
        ); // provider-guard: only an Azure DevOps mapping lists repositories
      untracked(() => {
        for (const { id, filter } of wanted) void this.loadAzureRepositories(id, filter);
      });
    });
  }

  protected search(project: Project): string {
    return this.searches()[project.id] ?? '';
  }

  protected setSearch(project: Project, event: Event): void {
    this.searches.update((all) => ({ ...all, [project.id]: inputValue(event).trim() }));
  }

  private async loadAzureRepositories(connectionId: string, filter: string): Promise<void> {
    const key = azureKey(connectionId, filter);
    if (this.azureRequested.has(key)) return;
    this.azureRequested.add(key);
    const generation = this.orgGeneration;
    const set = (list: AzureList) => {
      if (generation === this.orgGeneration) {
        this.azureLists.update((all) => ({ ...all, [key]: list }));
      }
    };
    set({ state: 'loading', items: [] });
    const items: AzureList['items'] = [];
    let more = false;
    try {
      for (let pageNumber = 1; pageNumber <= AZURE_LIST_PAGES; pageNumber++) {
        const answer = await ok(
          this.api.client.GET('/api/v0/scm-connections/{id}/repositories', {
            params: {
              path: { id: connectionId },
              query: { page: pageNumber, ...(filter ? { filter } : {}) },
            },
          }),
        );
        for (const r of answer.items) items.push({ ref: r.ref, label: r.name.replace('/', ' / ') });
        more = answer.hasMore;
        if (!more) break;
      }
      set({ state: 'loaded', items, more });
    } catch {
      // Not remembered as asked: choosing the connection or searching again tries again.
      this.azureRequested.delete(key);
      set({ state: 'failed', items: [] });
    }
  }

  /** The repositories a project's Azure DevOps mapping can pick, its saved one always among them. */
  protected azureOptions(project: Project): AzureList['items'] {
    const draft = this.draft(project);
    const items =
      this.azureLists()[azureKey(draft.connectionId, this.search(project))]?.items ?? [];
    if (draft.ref === '' || items.some((r) => r.ref === draft.ref)) return items;
    return [{ ref: draft.ref, label: draft.ref }, ...items];
  }

  /** What the list of an Azure DevOps mapping says while it loads or when it could not load. */
  protected azureHint(project: Project): string {
    const list =
      this.azureLists()[azureKey(this.draft(project).connectionId, this.search(project))];
    switch (list?.state) {
      case 'loading':
        return $localize`:@@azure.loadingRepositories:Loading the repositories…`;
      case 'failed':
        return $localize`:@@azure.repositoriesFailed:The repositories could not be listed. Test the connection under Azure DevOps.`;
      case 'loaded': {
        const shown = list.items.length;
        return list.more
          ? $localize`:@@azure.listTruncated:Showing the first ${shown}:count:; type to search.`
          : '';
      }
      default:
        return '';
    }
  }

  /** The mapping shown for a project: its draft, else what the server has. */
  protected draft(project: Project): Draft {
    return (
      this.drafts()[project.id] ?? {
        connectionId: project.scmConnectionId ?? '',
        ref: project.scmProjectRef ?? '',
      }
    );
  }

  /** The provider of the connection a project's mapping names (its draft), null when none. */
  protected providerOf(project: Project): ScmProvider | null {
    const id = this.draft(project).connectionId;
    return this.connections.items().find((c) => c.id === id)?.provider ?? null;
  }

  /** The example reference of a project's mapping, after its connection's provider. */
  protected refPlaceholder(project: Project): string {
    const provider = this.providerOf(project);
    if (provider === null) return '';
    switch (provider) {
      case 'github':
        return $localize`:@@gitlab.githubRefPlaceholder:owner/repo`;
      case 'gitlab':
        return $localize`:@@gitlab.refPlaceholder:group/project`;
      case 'azure': // a list of the connection's repositories, not a text box
        return '';
      default:
        return assertNever(provider, 'provider');
    }
  }

  /**
   * A connection as the mapping's list names it: its provider and address, and for a GitHub App
   * its App id (two Apps may share an address).
   */
  protected connectionLabel(connection: Connection): string {
    switch (connection.provider) {
      case 'github':
        return $localize`:@@gitlab.optionGitHub:GitHub · ${connection.baseUrl}:url: (App ${connection.github?.appId ?? ''}:appId:)`;
      case 'gitlab':
        return $localize`:@@gitlab.optionGitLab:GitLab · ${connection.baseUrl}:url:`;
      case 'azure':
        return $localize`:@@azure.optionAzure:Azure DevOps · ${connection.baseUrl}:url:`;
      default:
        return assertNever(connection.provider, 'provider');
    }
  }

  protected setConnection(project: Project, event: Event): void {
    const connectionId = inputValue(event);
    const was = this.providerOf(project);
    const draft = { ...this.draft(project), connectionId };
    // A reference of another provider is no reference of the new connection's.
    const now = this.connections.items().find((c) => c.id === connectionId)?.provider ?? null;
    this.setDraft(project, now === was ? draft : { ...draft, ref: '' });
  }

  protected setRef(project: Project, event: Event): void {
    this.setDraft(project, { ...this.draft(project), ref: inputValue(event) });
  }

  private setDraft(project: Project, draft: Draft): void {
    this.drafts.update((all) => ({ ...all, [project.id]: draft }));
    this.refErrors.update((all) => without(all, project.id));
    this.connErrors.update((all) => without(all, project.id));
    this.results.update((all) => without(all, project.id));
  }

  protected async save(project: Project): Promise<void> {
    if (this.busy()) return;
    const draft = this.draft(project);
    const ref = draft.ref.trim();
    const connectionId = draft.connectionId || null;
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const updated = await ok(
          this.api.client.PATCH('/api/v0/projects/{id}', {
            params: { path: { id: project.id } },
            body: { scmConnectionId: connectionId, scmProjectRef: ref === '' ? null : ref },
          }),
        );
        if (generation !== this.orgGeneration) return;
        this.projects.items.update((items) =>
          items.map((p) => (p.id === updated.id ? updated : p)),
        );
        // A mapping edited again while the save was on its way stays as typed.
        if (!this.sameDraft(project, draft)) return;
        this.drafts.update((all) => without(all, project.id));
        this.results.update((all) => ({ ...all, [project.id]: this.savedMapping(updated) }));
      },
      (err) => this.projectFieldError(project, err, 'body.scmProjectRef'),
    );
  }

  /** What a saved mapping says: not decorated without one, else where it decorates. */
  private savedMapping(project: Project): string {
    if (!(project.scmConnectionId && project.scmProjectRef)) {
      return $localize`:@@gitlab.unmapped:Not decorated.`;
    }
    const provider = this.providerOf(project);
    if (provider === null) return mappedAny();
    switch (provider) {
      case 'github':
        return $localize`:@@gitlab.mappedGitHub:Decorated in GitHub.`;
      case 'gitlab':
        return $localize`:@@gitlab.mapped:Decorated in GitLab.`;
      case 'azure':
        return $localize`:@@azure.mapped:Mapped to Azure DevOps.`;
      default:
        return assertNever(provider, 'provider');
    }
  }

  protected async check(project: Project): Promise<void> {
    const draft = this.draft(project);
    const ref = draft.ref.trim();
    if (!draft.connectionId || ref === '' || this.busy()) return;
    const provider = this.providerOf(project);
    // A connection this page does not list is not one to test.
    if (provider === null) return;
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const result = await ok(
          this.api.client.POST('/api/v0/scm-connections/{id}/test', {
            params: { path: { id: draft.connectionId } },
            body: { projectRef: ref },
          }),
        );
        // An answer for another organisation or another mapping than the one on screen is dropped.
        if (generation !== this.orgGeneration || !this.sameDraft(project, draft)) return;
        const text = testText(
          provider,
          result,
          azureCertificateExpiredOn(
            this.connections.items().find((c) => c.id === draft.connectionId),
            this.locale,
          ),
        );
        this.results.update((all) => ({ ...all, [project.id]: text }));
        // A failure reads as one: the error alert, never the green news of a success.
        if (result.ok) this.announcement.set(text);
        else this.error.set(text);
      },
      // A refusal of a mapping edited meanwhile is dropped too (handled, so no page alert).
      (err) =>
        !this.sameDraft(project, draft) || this.projectFieldError(project, err, 'body.projectRef'),
    );
  }

  private sameDraft(project: Project, draft: Draft): boolean {
    const now = this.draft(project);
    return now.connectionId === draft.connectionId && now.ref === draft.ref;
  }

  private projectFieldError(project: Project, err: unknown, refPath: string): boolean {
    const fields = fieldErrors(err);
    if (fields[refPath] !== undefined) {
      const message = badRefOf(this.providerOf(project));
      this.refErrors.update((all) => ({ ...all, [project.id]: message }));
      this.focusById(`ref-${project.id}`);
      return true;
    }
    if (fields['body.scmConnectionId'] !== undefined) {
      this.connErrors.update((all) => ({ ...all, [project.id]: badConnection() }));
      this.focusById(`conn-${project.id}`);
      return true;
    }
    return false;
  }

  private focusById(id: string): void {
    afterNextRender(() => this.document.getElementById(id)?.focus(), {
      injector: this.injector,
    });
  }

  /**
   * Runs one change; while one runs, the buttons stay enabled (and focusable) but do nothing. A
   * refused field goes to its field; anything else to the page's alert.
   */
  private async run(action: () => Promise<void>, field?: (err: unknown) => boolean): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    const generation = this.orgGeneration;
    try {
      await action();
    } catch (err) {
      if (generation !== this.orgGeneration) return;
      if (field?.(err)) return;
      this.error.set(problemMessage(err));
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    } finally {
      this.busy.set(false);
    }
  }
}

/** The key of one connection's list for one search text. */
function azureKey(connectionId: string, filter: string): string {
  return `${connectionId}
${filter}`;
}

function without<T>(all: Record<string, T>, id: string): Record<string, T> {
  return Object.fromEntries(Object.entries(all).filter(([key]) => key !== id));
}

function mappedAny(): string {
  return $localize`:@@gitlab.mappedAny:Decorated.`;
}

function badRef(): string {
  return $localize`:@@gitlab.badRef:Use the GitLab project id or its full path, such as group/project.`;
}

function badGitHubRef(): string {
  return $localize`:@@gitlab.badGitHubRef:Use owner/repo, the GitHub repository's owner and name, such as acme/api.`;
}

function testText(
  provider: ScmProvider,
  result: Parameters<typeof gitlabTestText>[0],
  expiredOn: string | null,
): string {
  switch (provider) {
    case 'github':
      return githubTestText(result);
    case 'gitlab':
      return gitlabTestText(result);
    case 'azure':
      return azureTestText(result, expiredOn);
    default:
      return assertNever(provider, 'provider');
  }
}

function badAnyRef(): string {
  return $localize`:@@gitlab.badAnyRef:Use the repository's id or full path.`;
}

function badRefOf(provider: ScmProvider | null): string {
  if (provider === null) return badAnyRef();
  switch (provider) {
    case 'github':
      return badGitHubRef();
    case 'gitlab':
      return badRef();
    case 'azure':
      return $localize`:@@azure.badRef:Choose one of the repositories in the list.`;
    default:
      return assertNever(provider, 'provider');
  }
}

function badConnection(): string {
  return $localize`:@@gitlab.badConnection:Choose one of this organization's GitLab, GitHub or Azure DevOps connections.`;
}
