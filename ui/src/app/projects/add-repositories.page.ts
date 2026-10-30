import { Location } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  DestroyRef,
  effect,
  type ElementRef,
  inject,
  Injector,
  input,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { Router, RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { ApiError, fieldErrors, isProblem, problemMessage } from '../api/errors';
import { Meter } from '../charts/meter';
import { OrgContext } from '../org/org-context';
import { isChecked } from '../shared/forms';
import { Icon } from '../shared/icon';
import { type Crumb, PageHeader } from '../shared/page-header';
import { Requirement } from '../shared/requirement';
import { RepositoryList } from './repository-list';
import {
  type Connection,
  connectionHost,
  errorText,
  itemState,
  type ItemState,
  MAX_REPOSITORIES,
  pathParts,
  providerName,
  type Repository,
  type RunItem,
  type SetupRun,
} from './repository-setup';
import { SetupBadge } from './setup-badge';
import { SetupResult } from './setup-result';
import { type RevealedToken, SetupTokens } from './setup-tokens';

export type { SetupRun } from './repository-setup';

/** How often a run that is not done is read again (the server answers `Retry-After: 2`). */
const POLL_MS = 2_000;
/**
 * A read that fails is tried again after 2, 4 and 8 poll intervals; the 4th failure in a row stops
 * following the run, and the page offers to check again (the run goes on on the server).
 */
const POLL_FAILURES = 4;
/** The longest wait a `Retry-After` may ask for: it is a hint. */
const MAX_RETRY_AFTER_S = 60;
/** Connections listed at once: an organisation has a handful. */
const CONNECTIONS_LIMIT = 100;

/** What the navigation that starts a run hands its page: the repositories GitHub calls C#. */
interface RunState {
  csharp?: unknown;
}

/** Why CI setup is not available for a connection, as its note says it. */
type WhyNot = 'not_allowed' | 'permissions' | 'unread' | 'url';

/**
 * **Add repositories** (`/projects/add`, onboarding spec "Add repositories"): pick one of the
 * organisation's GitHub or GitLab connections, tick up to 50 of the repositories it reaches, and
 * add them as projects in a background run, with a merge request per repository that adds the
 * Qualor CI job where the connection allows it (`ciSetup.available`). The run's own address
 * (`/projects/add/<run>?connection=<id>`) follows its progress, read every 2 s (or as
 * `Retry-After` says, backing off when a read fails) until it is done, then shows each
 * repository's outcome (`q-setup-result`). A token the server reveals (once) is kept in this page
 * only, never in storage; a later visit points to the project's token settings instead.
 */
@Component({
  selector: 'q-add-repositories-page',
  imports: [
    Icon,
    Meter,
    PageHeader,
    RepositoryList,
    Requirement,
    RouterLink,
    SetupBadge,
    SetupResult,
  ],
  templateUrl: './add-repositories.page.html',
  styleUrl: './add-repositories.page.css',
  host: { class: 'bleed' },
})
export class AddRepositoriesPage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  private readonly location = inject(Location);
  private readonly injector = inject(Injector);
  private readonly org = inject(OrgContext);

  /** The run being followed (`/projects/add/:runId`); none while picking. */
  readonly runId = input<string>();
  /** `?connection=`: the connection to pick first, and the one a run was started on. */
  readonly connection = input<string>();

  protected readonly max = MAX_REPOSITORIES;
  protected readonly crumbs: readonly Crumb[] = [
    { label: $localize`:@@projects.title:Projects`, link: '/projects' },
  ];
  protected readonly pathParts = pathParts;
  protected readonly providerName = providerName;
  protected readonly connectionHost = connectionHost;
  protected readonly isChecked = isChecked;

  // ─── Picking ──────────────────────────────────────────────────────────────────────────────

  protected readonly connections = signal<Connection[] | null>(null);
  protected readonly connectionsError = signal<string | null>(null);
  protected readonly chosenId = signal<string | null>(null);
  protected readonly chosen = computed(
    () => this.connections()?.find((c) => c.id === this.chosenId()) ?? null,
  );
  protected readonly ciAvailable = computed(() => this.chosen()?.ciSetup.available === true);
  /** The switch's own state; CI setup happens only where the connection allows it too. */
  protected readonly ciWanted = signal(true);
  protected readonly ciSetup = computed(() => this.ciAvailable() && this.ciWanted());
  /** The ticked repositories by ref (`q-repository-list`), dropped with another connection. */
  protected readonly selected = signal<ReadonlyMap<string, Repository>>(new Map());
  protected readonly count = computed(() => this.selected().size);
  protected readonly full = computed(() => this.count() >= MAX_REPOSITORIES);
  protected readonly starting = signal(false);
  protected readonly startError = signal<string | null>(null);

  // ─── The run ──────────────────────────────────────────────────────────────────────────────

  protected readonly run = signal<SetupRun | null>(null);
  protected readonly runError = signal<string | null>(null);
  /** The reads gave up: the page offers to read the run again. */
  protected readonly pollStopped = signal(false);
  /**
   * The run's one-time tokens by repository ref, as the server revealed them (once, on the first
   * read after the repository was done), kept by `SetupTokens` for the browser page's life (memory
   * only), so moving to another run and back loses none.
   */
  private readonly setupTokens = inject(SetupTokens);
  protected readonly tokens = computed(() => {
    const runId = this.runId();
    return runId ? this.setupTokens.forRun(runId) : new Map<string, RevealedToken>();
  });
  /** Tokens of this run not copied yet: **Try again** (a new run's page) asks first. */
  protected readonly uncopied = computed(() => [...this.tokens().values()].some((t) => !t.copied));
  /** The repositories GitHub reported as C#, handed over by the navigation that started the run. */
  protected readonly csharp = signal<ReadonlySet<string>>(new Set());
  protected readonly retrying = signal<string | null>(null);
  protected readonly retryError = signal<string | null>(null);
  private runGeneration = 0;
  private pollTimer: ReturnType<typeof setTimeout> | undefined;
  private failures = 0;
  /** The page showed the run done already: focus moves to its heading only the first time. */
  private sawDone = false;
  private readonly heading = viewChild<ElementRef<HTMLElement>>('heading');

  protected readonly finished = computed(
    () => (this.run()?.items ?? []).filter((i) => i.ciOutcome !== 'pending').length,
  );
  /** The run's connection, when the address names it and this person may read it. */
  protected readonly runConnection = computed(() => {
    const id = this.connection();
    return (id && this.connections()?.find((c) => c.id === id)) || null;
  });
  protected readonly counts = computed(() => {
    const items = this.run()?.items ?? [];
    const by = (pred: (i: RunItem) => boolean) => items.filter(pred).length;
    return {
      added: by((i) => i.projectOutcome === 'created' || i.projectOutcome === 'adopted'),
      mergeRequests: by((i) => i.ciOutcome === 'merge_request'),
      jobs: by((i) => i.ciOutcome === 'snippet' || i.ciOutcome === 'skipped'),
      already: by((i) => i.ciOutcome === 'already'),
      failed: by((i) => i.ciOutcome === 'failed'),
    };
  });

  constructor() {
    const state: unknown =
      this.router.currentNavigation()?.extras.state ?? this.location.getState();
    const csharp = (state as RunState | null)?.csharp;
    if (Array.isArray(csharp)) {
      this.csharp.set(new Set(csharp.filter((r): r is string => typeof r === 'string')));
    }
    // The organisation's connections: to pick from, and to name a run's connection.
    effect(() => {
      if (this.org.organizations.isLoading()) return;
      const organizationId = this.org.currentId();
      untracked(() => void this.loadConnections(organizationId));
    });
    // The run: read now, then followed until it is done.
    effect(() => {
      const runId = this.runId();
      untracked(() => this.follow(runId ?? null));
    });
    inject(DestroyRef).onDestroy(() => {
      this.runGeneration++;
      clearTimeout(this.pollTimer);
    });
  }

  // ─── Connections ──────────────────────────────────────────────────────────────────────────

  /**
   * Reads the organisation's connections, then keeps the chosen one when it is still there, else
   * picks the one the address names, else the first.
   */
  private async loadConnections(organizationId: string | null): Promise<void> {
    if (organizationId === null) return;
    this.connectionsError.set(null);
    try {
      const answer = await ok(
        this.api.client.GET('/api/v0/scm-connections', {
          params: { query: { organizationId, limit: CONNECTIONS_LIMIT } },
        }),
      );
      if (organizationId !== this.org.currentId()) return;
      this.connections.set(answer.items);
      if (this.runId() || answer.items.some((c) => c.id === this.chosenId())) return;
      const first = answer.items.find((c) => c.id === this.connection()) ?? answer.items[0];
      this.chosenId.set(null);
      if (first) this.choose(first.id);
    } catch (err) {
      if (organizationId !== this.org.currentId()) return;
      this.connections.set([]);
      // A run's page names its connection when it can; without it the run still shows.
      if (!this.runId()) this.connectionsError.set(problemMessage(err));
    }
  }

  protected choose(id: string): void {
    if (id === this.chosenId()) return;
    this.chosenId.set(id);
    this.ciWanted.set(true);
    this.selected.set(new Map());
    this.startError.set(null);
  }

  protected whyNot(connection: Connection): WhyNot | null {
    const ci = connection.ciSetup;
    if (ci.available) return null;
    switch (ci.reason) {
      case 'no_public_url':
        return 'url';
      case 'missing_permissions':
        // No list: the permissions could not be read.
        return ci.missing.length > 0 ? 'permissions' : 'unread';
      default:
        return 'not_allowed';
    }
  }

  /** "the Workflows and Secrets permissions": only the permissions the App lacks. */
  protected missingText(connection: Connection): string {
    const workflows = connection.ciSetup.missing.includes('workflows_write');
    const secrets = connection.ciSetup.missing.includes('secrets_write');
    if (workflows && secrets) {
      return $localize`:@@addRepos.why.missingBoth:The GitHub App lacks the Workflows and Secrets permissions.`;
    }
    return workflows
      ? $localize`:@@addRepos.why.missingWorkflows:The GitHub App lacks the Workflows permission.`
      : $localize`:@@addRepos.why.missingSecrets:The GitHub App lacks the Secrets permission.`;
  }

  /** "github.com, App 12345": where a connection is, and which App for GitHub. */
  protected connectionMeta(connection: Connection): string {
    const host = connectionHost(connection);
    const appId = connection.github?.appId;
    return appId ? $localize`:@@addRepos.connection.app:${host}:host:, App ${appId}:appId:` : host;
  }

  protected clear(): void {
    this.selected.set(new Map());
  }

  /**
   * Starts the run and opens its page. A 422 on `body.ciSetup` means the connection no longer
   * allows CI setup: the connection is read again (its note then says why), the switch follows it,
   * and the selection stays for a second try.
   */
  protected async start(): Promise<void> {
    const connection = this.chosen();
    const repositories = [...this.selected().keys()];
    if (!connection || repositories.length === 0 || this.starting()) return;
    this.starting.set(true);
    this.startError.set(null);
    try {
      const { id } = await ok(
        this.api.client.POST('/api/v0/repository-setups', {
          body: {
            organizationId: connection.organizationId,
            connectionId: connection.id,
            repositories,
            ciSetup: this.ciSetup(),
          },
        }),
      );
      const csharp = [...this.selected().values()]
        .filter((r) => r.language === 'C#')
        .map((r) => r.ref);
      await this.openRun(id, connection.id, csharp);
    } catch (err) {
      if (fieldErrors(err)['body.ciSetup'] !== undefined) {
        await this.loadConnections(this.org.currentId());
        this.startError.set(
          $localize`:@@addRepos.ciGone:CI setup is no longer available for this connection, so nothing was started. The connection says why. Add the repositories without CI setup, or fix it and try again.`,
        );
      } else {
        this.startError.set(problemMessage(err));
      }
    } finally {
      this.starting.set(false);
    }
  }

  private openRun(id: string, connectionId: string, csharp: string[]): Promise<boolean> {
    return this.router.navigate(['/projects/add', id], {
      queryParams: { connection: connectionId },
      state: { csharp } satisfies RunState,
    });
  }

  // ─── The run ──────────────────────────────────────────────────────────────────────────────

  private follow(runId: string | null): void {
    const generation = ++this.runGeneration;
    clearTimeout(this.pollTimer);
    this.run.set(null);
    this.runError.set(null);
    this.pollStopped.set(false);
    this.failures = 0;
    this.sawDone = false;
    if (runId !== null) void this.read(runId, generation);
  }

  /** One read of the run; while it works, the next is planned. */
  private async read(runId: string, generation: number): Promise<void> {
    try {
      const { data, error, response } = await this.api.client.GET(
        '/api/v0/repository-setups/{id}',
        { params: { path: { id: runId } } },
      );
      // A revealed token is kept even when the page moved on meanwhile: the server shows it once.
      if (data) this.setupTokens.keep(runId, revealedTokens(data));
      if (generation !== this.runGeneration) return;
      const retryAfter = response.headers.get('retry-after');
      if (!response.ok || !data) {
        throw new ApiError(response.status, isProblem(error) ? error : null, retryAfter);
      }
      this.failures = 0;
      this.run.set(data);
      if (data.status !== 'done') {
        this.plan(runId, generation, waitFor(retryAfter) ?? POLL_MS);
      } else if (!this.sawDone) {
        this.sawDone = true;
        this.focusHeading();
      }
    } catch (err) {
      if (generation !== this.runGeneration) return;
      if (err instanceof ApiError && err.status === 404) {
        this.runError.set(problemMessage(err));
        return;
      }
      this.failures++;
      if (this.failures >= POLL_FAILURES) {
        this.pollStopped.set(true);
        return;
      }
      const asked = err instanceof ApiError ? waitFor(err.retryAfter?.toString() ?? null) : null;
      this.plan(runId, generation, asked ?? POLL_MS * 2 ** this.failures);
    }
  }

  private plan(runId: string, generation: number, ms: number): void {
    clearTimeout(this.pollTimer);
    this.pollTimer = setTimeout(() => void this.read(runId, generation), ms);
  }

  protected tokenOf(item: RunItem): string | null {
    return this.tokens().get(item.ref)?.token ?? null;
  }

  /** The person copied a token (Copy, or from its field): **Try again** need not ask for it. */
  protected markCopied(item: RunItem): void {
    const runId = this.runId();
    if (runId) this.setupTokens.markCopied(runId, item.ref);
  }

  protected checkAgain(): void {
    const runId = this.runId();
    if (!runId) return;
    this.pollStopped.set(false);
    this.failures = 0;
    clearTimeout(this.pollTimer);
    void this.read(runId, this.runGeneration);
  }

  /**
   * The run is done (it finished while the page followed it, or the page opened on it): focus
   * moves to the results' heading, as the controls of the progress view are gone.
   */
  private focusHeading(): void {
    afterNextRender(() => this.heading()?.nativeElement.focus(), { injector: this.injector });
  }

  /** "2 of 4": the progress in words, for the meter and a screen reader. */
  protected finishedText(run: SetupRun): string {
    return $localize`:@@meter.of:${this.finished()}:value: of ${run.items.length}:max:`;
  }

  protected stateOf(item: RunItem): ItemState {
    return itemState(item, this.run());
  }

  protected errorOf(item: RunItem): string {
    const connection = this.runConnection();
    return errorText(item, connection ? providerName(connection) : null);
  }

  /** **Try again**: a new run for this one repository, on the same connection. */
  protected async retry(item: RunItem): Promise<void> {
    const connection = this.runConnection();
    const run = this.run();
    if (!connection || !run || this.retrying() !== null) return;
    this.retrying.set(item.ref);
    this.retryError.set(null);
    try {
      const { id } = await ok(
        this.api.client.POST('/api/v0/repository-setups', {
          body: {
            organizationId: connection.organizationId,
            connectionId: connection.id,
            repositories: [item.ref],
            ciSetup: run.ciSetup && connection.ciSetup.available,
          },
        }),
      );
      await this.openRun(id, connection.id, this.csharp().has(item.ref) ? [item.ref] : []);
    } catch (err) {
      this.retryError.set(problemMessage(err));
    } finally {
      this.retrying.set(null);
    }
  }
}

/** The tokens a read of the run revealed, by repository ref. */
function revealedTokens(run: SetupRun): { ref: string; token: string }[] {
  return run.items.flatMap((i) => (i.token === null ? [] : [{ ref: i.ref, token: i.token }]));
}

/** A `Retry-After` of plain seconds as milliseconds, within reason; null without one. */
function waitFor(header: string | null): number | null {
  if (header === null || !/^\d{1,6}$/.test(header)) return null;
  return Math.min(Math.max(Number(header), 1), MAX_RETRY_AFTER_S) * 1000;
}
