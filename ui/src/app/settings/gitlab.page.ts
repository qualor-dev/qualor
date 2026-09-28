import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  DestroyRef,
  effect,
  type ElementRef,
  inject,
  Injector,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf, ResponseBody } from '../api/types';
import { OrgContext } from '../org/org-context';
import { DateTimePipe } from '../shared/date-time.pipe';
import { keepFocus } from '../shared/focus';
import { clearField, inputValue } from '../shared/forms';
import { KeysetList } from '../shared/keyset';
import { githubTestText } from './github-text';

export type Connection = ItemOf<'/api/v0/scm-connections'>;
type Project = ItemOf<'/api/v0/projects'>;
type TestResult = ResponseBody<'/api/v0/scm-connections/{id}/test', 'post'>;
type ProblemCode = NonNullable<TestResult['problem']>['code'];

/** scm.md §4.4: a failed test in the UI's own words (the server's English text is never shown). */
export function testProblemText(code: ProblemCode): string {
  switch (code) {
    case 'undecryptable':
      return $localize`:@@gitlab.problem.undecryptable:The stored token can no longer be read (the server key changed). Replace the token.`;
    case 'url_not_allowed':
      return $localize`:@@gitlab.problem.urlNotAllowed:The server no longer allows this GitLab address. Ask the operator to list its host and port in QUALOR_SCM_INTERNAL_HOSTS.`;
    case 'not_public':
      return $localize`:@@gitlab.problem.notPublic:This GitLab is on an internal address. Ask the operator to list its host and port in QUALOR_SCM_INTERNAL_HOSTS.`;
    case 'unresolved':
      return $localize`:@@gitlab.problem.unresolved:The GitLab host name could not be found.`;
    case 'timeout':
      return $localize`:@@gitlab.problem.timeout:GitLab did not answer in time.`;
    case 'unreachable':
      return $localize`:@@gitlab.problem.unreachable:GitLab could not be reached.`;
    case 'token_refused':
      return $localize`:@@gitlab.problem.tokenRefused:GitLab refused the token. Check that it is valid, has the api scope and the Developer role.`;
    case 'not_found':
      return $localize`:@@gitlab.problem.notFound:The GitLab project was not found, or the token cannot see it.`;
    case 'http_error':
      return $localize`:@@gitlab.problem.httpError:GitLab answered with an error.`;
    case 'bad_answer':
      return $localize`:@@gitlab.problem.badAnswer:GitLab's answer was not understood. Check the address.`;
    default:
      return $localize`:@@gitlab.problem.unknown:The test failed.`;
  }
}

/** A test answer as the page shows it: fixed sentences and the names GitLab gave, as text only. */
function testText(result: TestResult): string {
  if (!result.ok || !result.user) {
    return result.problem
      ? testProblemText(result.problem.code)
      : $localize`:@@gitlab.problem.unknown:The test failed.`;
  }
  return result.project
    ? $localize`:@@gitlab.testOkProject:Connected as ${result.user.username}:user:; the project ${result.project.pathWithNamespace}:project: is reachable.`
    : $localize`:@@gitlab.testOk:Connected as ${result.user.username}:user:.`;
}

/**
 * A base URL as the server stores it (scm.md §2.1: normalised, without a trailing slash), so that
 * re-typing the same address does not count as a new one. Null when it is not a URL at all.
 */
function normalBaseUrl(raw: string): string | null {
  try {
    return new URL(raw).href.replace(/\/+$/, '');
  } catch {
    return null;
  }
}

/** A project's mapping as edited on the page, before it is saved. */
interface Draft {
  connectionId: string;
  ref: string;
}

/** A refused field of a connection's own form. */
interface RowError {
  field: 'url' | 'token';
  message: string;
}

/**
 * GitLab (scm.md §2), for org admins: the organisation's GitLab connections (a base URL and an
 * access token, which is write-only: it is sent once, never shown, and emptied from the page after
 * every submission), a test of each, and the mapping of each project to a connection of either
 * provider and a GitLab project or GitHub repository (github.md §2.3: `owner/repo`). The server
 * checks the URL (its SSRF rules, 422 on `body.baseUrl`), wants the token again with a new address
 * (422 on `body.token`) and checks the project reference against the connection's provider (422
 * on `body.scmProjectRef`). Test answers are shown in the page's own words per code (§4.4); the
 * GitHub tab lists and changes GitHub connections.
 */
@Component({
  selector: 'q-gitlab-page',
  imports: [DateTimePipe],
  templateUrl: './gitlab.page.html',
})
export class GitLabPage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  protected readonly org = inject(OrgContext);
  /** The role manages these (`org.scm.manage`, rbac-audit.md §3.1): the page shows them. */
  protected readonly canRead = computed(() => this.org.can('org.scm.manage'));
  protected readonly canManage = computed(() => this.org.canChange('org.scm.manage'));
  protected readonly connections = new KeysetList<Connection, string>((organizationId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/scm-connections', {
        params: { query: { organizationId, limit: 50, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  /** The GitLab connections this page lists; the mapping offers every connection. */
  protected readonly gitlabConnections = computed(() =>
    this.connections.items().filter((c) => c.provider === 'gitlab'),
  );
  protected readonly projects = new KeysetList<Project, string>((organizationId, cursor) =>
    ok(
      this.api.client.GET('/api/v0/projects', {
        params: { query: { organizationId, limit: 50, ...(cursor ? { cursor } : {}) } },
      }),
    ),
  );
  protected readonly url = signal('');
  protected readonly token = signal('');
  protected readonly urlError = signal<string | null>(null);
  protected readonly tokenError = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  /** Test results and project messages, by connection or project id. */
  protected readonly results = signal<Record<string, string>>({});
  protected readonly drafts = signal<Record<string, Draft>>({});
  protected readonly refErrors = signal<Record<string, string>>({});
  protected readonly connErrors = signal<Record<string, string>>({});
  /** Refused fields of the connections' own forms, by connection id. */
  protected readonly rowErrors = signal<Record<string, RowError>>({});
  private readonly heading = viewChild.required<ElementRef<HTMLElement>>('heading');
  private readonly urlField = viewChild<ElementRef<HTMLInputElement>>('urlField');
  private readonly tokenField = viewChild<ElementRef<HTMLInputElement>>('tokenField');
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
        this.urlError.set(null);
        this.tokenError.set(null);
        this.results.set({});
        this.drafts.set({});
        this.refErrors.set({});
        this.connErrors.set({});
        this.rowErrors.set({});
        clearField(this.tokenField(), this.token);
        if (organizationId && admin) {
          void this.connections.reset(organizationId);
          void this.projects.reset(organizationId);
        }
      });
    });
    inject(DestroyRef).onDestroy(() => this.token.set(''));
  }

  protected setUrl(event: Event): void {
    this.url.set(inputValue(event));
    this.urlError.set(null);
  }

  protected setToken(event: Event): void {
    this.token.set(inputValue(event));
    this.tokenError.set(null);
  }

  protected clearRowError(connection: Connection): void {
    if (this.rowErrors()[connection.id] === undefined) return;
    this.rowErrors.update((all) => without(all, connection.id));
  }

  protected rowError(connection: Connection, field: RowError['field']): string | null {
    const error = this.rowErrors()[connection.id];
    return error?.field === field ? error.message : null;
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

  protected async create(event: Event): Promise<void> {
    event.preventDefault();
    const organizationId = this.org.currentId();
    if (!organizationId || this.busy()) return;
    const baseUrl = this.url().trim();
    const token = this.token();
    this.urlError.set(baseUrl ? null : badUrl());
    this.tokenError.set(token ? null : badToken());
    if (!baseUrl || !token) {
      this.focusFirstInvalid();
      return;
    }
    const generation = this.orgGeneration;
    try {
      await this.run(async () => {
        await ok(
          this.api.client.POST('/api/v0/scm-connections', {
            body: { organizationId, provider: 'gitlab', baseUrl, token },
          }),
        );
        if (generation !== this.orgGeneration) return;
        clearField(this.urlField(), this.url);
        this.announcement.set($localize`:@@gitlab.created:GitLab connection added.`);
        await this.connections.refresh();
      });
    } finally {
      // The token never stays on the page after a submission, whatever the answer was.
      clearField(this.tokenField(), this.token);
    }
    this.focusFirstInvalid();
  }

  /**
   * A connection's own form: a new token, and with it, optionally, a new address. The token is
   * read from the field and never kept; a new address without a token is refused here, as the
   * server would (scm.md §2.1: the stored token only ever goes to the address it was saved for).
   */
  protected async update(connection: Connection, event: Event): Promise<void> {
    event.preventDefault();
    const form = event.target instanceof HTMLFormElement ? event.target : null;
    const urlField = form?.querySelector<HTMLInputElement>('input[type="url"]') ?? null;
    const tokenField = form?.querySelector<HTMLInputElement>('input[type="password"]') ?? null;
    if (this.busy()) return;
    // The token is read once and the field emptied at once, before any check or request: whatever
    // happens next (a refusal here, a 422, a network error), it never stays on the page.
    const token = tokenField?.value ?? '';
    if (tokenField) tokenField.value = '';
    const typed = (urlField?.value ?? connection.baseUrl).trim();
    const changed = typed !== '' && normalBaseUrl(typed) !== connection.baseUrl;
    const refuse = (field: RowError['field'], message: string) => {
      this.rowErrors.update((all) => ({ ...all, [connection.id]: { field, message } }));
      (field === 'url' ? urlField : tokenField)?.focus();
    };
    if (typed === '' || !token) {
      if (typed === '') refuse('url', badUrl());
      else refuse('token', changed ? tokenForNewUrl() : badToken());
      return;
    }
    this.clearRowError(connection);
    const generation = this.orgGeneration;
    await this.run(
      async () => {
        const updated = await ok(
          this.api.client.PATCH('/api/v0/scm-connections/{id}', {
            params: { path: { id: connection.id } },
            body: changed ? { baseUrl: typed, token } : { token },
          }),
        );
        if (generation !== this.orgGeneration) return;
        this.connections.items.update((items) =>
          items.map((c) => (c.id === updated.id ? updated : c)),
        );
        this.results.update((all) => without(all, connection.id));
        this.announcement.set(
          changed
            ? $localize`:@@gitlab.urlChanged:The connection now points at ${updated.baseUrl}:url:.`
            : $localize`:@@gitlab.tokenReplaced:The token of ${updated.baseUrl}:url: was replaced.`,
        );
      },
      (err) => {
        const fields = fieldErrors(err);
        if (fields['body.baseUrl'] !== undefined) refuse('url', badUrl());
        else if (fields['body.token'] !== undefined) {
          refuse('token', changed ? tokenForNewUrl() : badToken());
        } else return false;
        return true;
      },
    );
  }

  protected async test(connection: Connection): Promise<void> {
    if (this.busy()) return;
    const generation = this.orgGeneration;
    await this.run(async () => {
      const result = await ok(
        this.api.client.POST('/api/v0/scm-connections/{id}/test', {
          params: { path: { id: connection.id } },
          body: {},
        }),
      );
      if (generation !== this.orgGeneration) return;
      const text = testText(result);
      this.results.update((all) => ({ ...all, [connection.id]: text }));
      this.announcement.set(text);
    });
  }

  protected async remove(connection: Connection): Promise<void> {
    if (this.busy()) return;
    if (
      !window.confirm(
        $localize`:@@gitlab.confirmDelete:Delete the GitLab connection to ${connection.baseUrl}:url:? Its projects stop being decorated.`,
      )
    ) {
      return;
    }
    const generation = this.orgGeneration;
    await this.run(async () => {
      await done(
        this.api.client.DELETE('/api/v0/scm-connections/{id}', {
          params: { path: { id: connection.id } },
        }),
      );
      if (generation !== this.orgGeneration) return;
      await this.connections.refresh();
      await this.projects.refresh();
      this.rowErrors.update((all) => without(all, connection.id));
      this.results.update((all) => without(all, connection.id));
      this.announcement.set(
        $localize`:@@gitlab.deleted:GitLab connection ${connection.baseUrl}:url: deleted.`,
      );
      keepFocus(this.injector, this.document, () => this.heading().nativeElement);
    });
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
          this.providerOf(project) === 'github' ? githubTestText(result) : testText(result);
        this.results.update((all) => ({ ...all, [project.id]: text }));
        this.announcement.set(text);
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

  /** A 422 on a project's connection or GitLab project goes to that field, which takes focus. */
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

  private focusFirstInvalid(): void {
    if (this.urlError()) this.urlField()?.nativeElement.focus();
    else if (this.tokenError()) this.tokenField()?.nativeElement.focus();
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
      const fields = fieldErrors(err);
      if (fields['body.baseUrl'] !== undefined) this.urlError.set(badUrl());
      else if (fields['body.token'] !== undefined) this.tokenError.set(badToken());
      else {
        this.error.set(problemMessage(err));
        keepFocus(this.injector, this.document, () => this.heading().nativeElement);
      }
    } finally {
      this.busy.set(false);
    }
  }
}

function without<T>(all: Record<string, T>, id: string): Record<string, T> {
  return Object.fromEntries(Object.entries(all).filter(([key]) => key !== id));
}

function badUrl(): string {
  return $localize`:@@gitlab.badUrl:Use the https address of your GitLab, without a user name, password, query or fragment. An internal GitLab must be listed, with its port, by the operator in QUALOR_SCM_INTERNAL_HOSTS.`;
}

function badToken(): string {
  return $localize`:@@gitlab.badToken:Paste the access token as GitLab shows it (no spaces).`;
}

function tokenForNewUrl(): string {
  return $localize`:@@gitlab.tokenForNewUrl:Changing the address needs the token again: Qualor sends a stored token only to the address it was saved for.`;
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
