import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
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
import { githubTestText } from './github-text';
import { gitlabTestText } from './gitlab-text';
import type { Connection } from './gitlab.page';

type Project = ItemOf<'/api/v0/projects'>;

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
        if (organizationId && admin) {
          void this.connections.reset(organizationId);
          void this.projects.reset(organizationId);
        }
      });
    });
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

  /** The provider of the connection a project's mapping names (its draft), GitLab when none. */
  protected providerOf(project: Project): Connection['provider'] {
    const id = this.draft(project).connectionId;
    return this.connections.items().find((c) => c.id === id)?.provider ?? 'gitlab';
  }

  /** The example reference of a project's mapping, after its connection's provider. */
  protected refPlaceholder(project: Project): string {
    return this.providerOf(project) === 'github'
      ? $localize`:@@gitlab.githubRefPlaceholder:owner/repo`
      : $localize`:@@gitlab.refPlaceholder:group/project`;
  }

  /**
   * A connection as the mapping's list names it: its provider and address, and for a GitHub App
   * its App id (two Apps may share an address).
   */
  protected connectionLabel(connection: Connection): string {
    return connection.provider === 'github'
      ? $localize`:@@gitlab.optionGitHub:GitHub · ${connection.baseUrl}:url: (App ${connection.github?.appId ?? ''}:appId:)`
      : $localize`:@@gitlab.optionGitLab:GitLab · ${connection.baseUrl}:url:`;
  }

  protected setConnection(project: Project, event: Event): void {
    this.setDraft(project, { ...this.draft(project), connectionId: inputValue(event) });
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
        this.results.update((all) => ({
          ...all,
          [project.id]: !(updated.scmConnectionId && updated.scmProjectRef)
            ? $localize`:@@gitlab.unmapped:Not decorated.`
            : this.providerOf(updated) === 'github'
              ? $localize`:@@gitlab.mappedGitHub:Decorated in GitHub.`
              : $localize`:@@gitlab.mapped:Decorated in GitLab.`,
        }));
      },
      (err) => this.projectFieldError(project, err, 'body.scmProjectRef'),
    );
  }

  protected async check(project: Project): Promise<void> {
    const draft = this.draft(project);
    const ref = draft.ref.trim();
    if (!draft.connectionId || ref === '' || this.busy()) return;
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
        const text =
          this.providerOf(project) === 'github' ? githubTestText(result) : gitlabTestText(result);
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
      const message = this.providerOf(project) === 'github' ? badGitHubRef() : badRef();
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

function without<T>(all: Record<string, T>, id: string): Record<string, T> {
  return Object.fromEntries(Object.entries(all).filter(([key]) => key !== id));
}

function badRef(): string {
  return $localize`:@@gitlab.badRef:Use the GitLab project id or its full path, such as group/project.`;
}

function badGitHubRef(): string {
  return $localize`:@@gitlab.badGitHubRef:Use owner/repo, the GitHub repository's owner and name, such as acme/api.`;
}

function badConnection(): string {
  return $localize`:@@gitlab.badConnection:Choose one of this organization's GitLab or GitHub connections.`;
}
