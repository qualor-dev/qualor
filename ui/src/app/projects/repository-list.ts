import {
  Component,
  computed,
  DestroyRef,
  effect,
  type ElementRef,
  inject,
  input,
  model,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { ApiError, problemMessage } from '../api/errors';
import { Icon } from '../shared/icon';
import { inputValue } from '../shared/forms';
import { type Connection, MAX_REPOSITORIES, pathParts, type Repository } from './repository-setup';

/** Typing in the filter asks the server once it pauses this long. */
const FILTER_DELAY_MS = 300;
/** The API's limit for the filter. */
const MAX_FILTER = 255;
/**
 * GitHub filters each listed page, so a page may hold no match while more follow: one load reads
 * on through empty pages, at most this many.
 */
const MAX_EMPTY_PAGES = 10;

/**
 * `q-repository-list`: the repositories a connection reaches (`GET /scm-connections/{id}/
 * repositories`, 100 to a page), filtered on the server, with a box each. A repository already in
 * Qualor (`mapped`) or archived cannot be ticked; one an unmapped project would adopt says so.
 * `selected` holds the ticked ones by ref across filters and pages, at most 50; at the limit the
 * other boxes are off. On a phone each row is a card.
 */
@Component({
  selector: 'q-repository-list',
  imports: [Icon, RouterLink],
  templateUrl: './repository-list.html',
  styleUrl: './repository-list.css',
  host: { class: 'card panel', role: 'region', 'aria-labelledby': 'repos-heading' },
})
export class RepositoryList {
  private readonly api = inject(Api);

  readonly connection = input.required<Connection>();
  /** The ticked repositories by ref, with what the list said of them. */
  readonly selected = model.required<ReadonlyMap<string, Repository>>();

  protected readonly maxFilter = MAX_FILTER;
  protected readonly pathParts = pathParts;
  protected readonly inputValue = inputValue;

  protected readonly repos = signal<Repository[]>([]);
  protected readonly hasMore = signal(false);
  protected readonly loading = signal(false);
  protected readonly loaded = signal(false);
  protected readonly error = signal<string | null>(null);
  /** The filter as typed, and as last asked of the server. */
  protected readonly filterText = signal('');
  private readonly filter = signal('');
  private page = 0;
  private generation = 0;
  private filterTimer: ReturnType<typeof setTimeout> | undefined;

  private readonly connectionId = computed(() => this.connection().id);
  /** GitHub names each repository's language, GitLab does not: no column for it there. */
  protected readonly languages = computed(() => this.connection().provider === 'github');
  protected readonly full = computed(() => this.selected().size >= MAX_REPOSITORIES);
  protected readonly selectable = computed(() => this.repos().filter((r) => this.canPick(r)));
  protected readonly pageState = computed(() => {
    const rows = this.selectable();
    const ticked = rows.filter((r) => this.selected().has(r.ref)).length;
    return { all: rows.length > 0 && ticked === rows.length, some: ticked > 0 };
  });
  private readonly selectPage = viewChild<ElementRef<HTMLInputElement>>('selectPage');

  constructor() {
    // Another connection: its first page, unfiltered.
    effect(() => {
      this.connectionId();
      untracked(() => {
        clearTimeout(this.filterTimer);
        this.filterText.set('');
        this.filter.set('');
        void this.load(true);
      });
    });
    // The page's box shows "some" as indeterminate (a property, not an attribute).
    effect(() => {
      const box = this.selectPage()?.nativeElement;
      const { all, some } = this.pageState();
      if (box) box.indeterminate = some && !all;
    });
    inject(DestroyRef).onDestroy(() => {
      this.generation++;
      clearTimeout(this.filterTimer);
    });
  }

  /**
   * Reads the next page (or, with `reset`, the first) under the current filter, reading on past
   * pages the filter left empty.
   */
  private async load(reset: boolean): Promise<void> {
    const connection = this.connection();
    const generation = ++this.generation;
    if (reset) {
      this.page = 0;
      this.repos.set([]);
      this.hasMore.set(false);
      this.loaded.set(false);
    }
    this.loading.set(true);
    this.error.set(null);
    const filter = this.filter();
    try {
      for (let read = 0; read < MAX_EMPTY_PAGES; read++) {
        const answer = await ok(
          this.api.client.GET('/api/v0/scm-connections/{id}/repositories', {
            params: {
              path: { id: connection.id },
              query: { page: this.page + 1, ...(filter ? { filter } : {}) },
            },
          }),
        );
        if (generation !== this.generation) return;
        this.page++;
        this.repos.update((all) => [...all, ...answer.items]);
        this.hasMore.set(answer.hasMore);
        if (answer.items.length > 0 || !answer.hasMore) break;
      }
      this.loaded.set(true);
    } catch (err) {
      if (generation !== this.generation) return;
      this.error.set(listErrorText(err));
    } finally {
      if (generation === this.generation) this.loading.set(false);
    }
  }

  protected more(): void {
    if (!this.loading()) void this.load(false);
  }

  /** The filter asks the server once typing pauses; Enter asks at once. */
  protected setFilter(value: string): void {
    this.filterText.set(value);
    clearTimeout(this.filterTimer);
    this.filterTimer = setTimeout(() => this.applyFilter(), FILTER_DELAY_MS);
  }

  protected submitFilter(event: Event): void {
    event.preventDefault();
    clearTimeout(this.filterTimer);
    this.applyFilter();
  }

  private applyFilter(): void {
    const filter = this.filterText().trim().slice(0, MAX_FILTER);
    if (filter === this.filter() && this.loaded()) return;
    this.filter.set(filter);
    void this.load(true);
  }

  /** A repository can be added: not in Qualor already, and not archived (it runs no CI). */
  protected canPick(repo: Repository): boolean {
    return repo.project?.state !== 'mapped' && !repo.archived;
  }

  protected isSelected(repo: Repository): boolean {
    return this.selected().has(repo.ref);
  }

  /** A box is off for a repository that cannot be added, and for the rest once 50 are ticked. */
  protected boxDisabled(repo: Repository): boolean {
    return !this.canPick(repo) || (this.full() && !this.isSelected(repo));
  }

  protected toggle(repo: Repository, event: Event): void {
    const box = event.target as HTMLInputElement;
    const next = new Map(this.selected());
    if (box.checked && this.canPick(repo) && next.size < MAX_REPOSITORIES) next.set(repo.ref, repo);
    else next.delete(repo.ref);
    this.selected.set(next);
    // A box past the limit stays unticked.
    box.checked = next.has(repo.ref);
  }

  /** The page's box: ticks the listed repositories that can be added, up to the limit, or none. */
  protected toggleAll(event: Event): void {
    const next = new Map(this.selected());
    if (this.pageState().all) {
      for (const repo of this.selectable()) next.delete(repo.ref);
    } else {
      for (const repo of this.selectable()) {
        if (next.size >= MAX_REPOSITORIES) break;
        next.set(repo.ref, repo);
      }
    }
    this.selected.set(next);
    (event.target as HTMLInputElement).checked = this.pageState().all;
  }
}

/** Why the repositories could not be listed. */
function listErrorText(err: unknown): string {
  if (err instanceof ApiError && err.status === 502) {
    return $localize`:@@addRepos.list.unreachable:GitHub or GitLab did not answer as expected. Try again in a moment, or test the connection in the settings.`;
  }
  return problemMessage(err);
}
