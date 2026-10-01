import { signal } from '@angular/core';
import { problemMessage } from '../api/errors';

export interface KeysetPage<T> {
  items: T[];
  nextCursor: string | null;
}

/**
 * A keyset-paginated list (api.md §1: `{ items, nextCursor }`): `reset` loads the first page for
 * new parameters, `more` appends the next one. An answer for parameters that were replaced in the
 * meantime is dropped, so a slow first search can never overwrite a later one. A next cursor equal
 * to the one just answered ends the list, so a faulty server cannot make paging go round in circles.
 * `firstPage` is the first page of the latest accepted answer, for what travels with it (the
 * issue facets); it is set after the stale-answer check, so an old answer never replaces it.
 */
export class KeysetList<T, P, R extends KeysetPage<T> = KeysetPage<T>> {
  readonly items = signal<T[]>([]);
  readonly firstPage = signal<R | null>(null);
  readonly nextCursor = signal<string | null>(null);
  readonly loading = signal(false);
  readonly loaded = signal(false);
  readonly error = signal<string | null>(null);
  private params: P | undefined;
  private generation = 0;
  /** How many pages the items hold, for `refresh`. */
  private pages = 0;

  constructor(private readonly fetchPage: (params: P, cursor: string | null) => Promise<R>) {}

  async reset(params: P): Promise<void> {
    this.params = params;
    this.items.set([]);
    this.nextCursor.set(null);
    this.loaded.set(false);
    await this.load(null);
  }

  /** Empties the list and drops any answer still on its way, until the next `reset`. */
  clear(): void {
    this.generation++;
    this.params = undefined;
    this.pages = 0;
    this.items.set([]);
    this.firstPage.set(null);
    this.nextCursor.set(null);
    this.loading.set(false);
    this.loaded.set(false);
    this.error.set(null);
  }

  async more(): Promise<void> {
    const cursor = this.nextCursor();
    if (cursor === null || this.loading()) return;
    await this.load(cursor);
  }

  /** Reloads the first page with the current parameters (after a change). */
  async reload(): Promise<void> {
    if (this.params !== undefined) await this.reset(this.params);
  }

  /**
   * Loads again as many pages as the list holds and swaps the items in one step when all have
   * answered: the rows stay on screen meanwhile, and rows tracked by key keep their elements (and
   * the focus and scroll position they carry). For a change that may add, drop or reorder rows.
   */
  async refresh(): Promise<void> {
    if (this.params === undefined) return;
    const params = this.params;
    const generation = ++this.generation;
    const want = Math.max(1, this.pages);
    this.loading.set(true);
    this.error.set(null);
    try {
      let items: T[] = [];
      let first: R | null = null;
      let cursor: string | null = null;
      let next: string | null = null;
      let pages = 0;
      do {
        const page: R = await this.fetchPage(params, cursor);
        if (generation !== this.generation) return;
        first ??= page;
        items = [...items, ...page.items];
        next = page.nextCursor && page.nextCursor !== cursor ? page.nextCursor : null;
        cursor = next;
        pages++;
      } while (pages < want && next !== null);
      this.firstPage.set(first);
      this.items.set(items);
      this.nextCursor.set(next);
      this.pages = pages;
      this.loaded.set(true);
    } catch (err) {
      if (generation === this.generation) this.error.set(problemMessage(err));
    } finally {
      if (generation === this.generation) this.loading.set(false);
    }
  }

  /**
   * Follows the next cursors to the end while `current()` holds (a superseded caller stops). While
   * another load is running (a `refresh`, which makes `more` a no-op) it waits a task instead of
   * spinning, then goes on with whatever cursor that load left.
   */
  async loadRest(current: () => boolean): Promise<void> {
    while (current() && this.nextCursor() !== null && !this.error()) {
      if (this.loading()) await new Promise<void>((resolve) => setTimeout(resolve, 0));
      else await this.more();
    }
  }

  /**
   * Reloads the first page, then follows the next cursors to the end (at most `maxPages` pages),
   * so an entry just added at the end of an oldest-first list is on screen.
   */
  async reloadToEnd(maxPages: number): Promise<void> {
    await this.reload();
    for (let pages = 1; pages < maxPages && this.nextCursor() !== null && !this.error(); pages++) {
      await this.more();
    }
  }

  private async load(cursor: string | null): Promise<void> {
    const generation = ++this.generation;
    this.loading.set(true);
    this.error.set(null);
    try {
      const page = await this.fetchPage(this.params as P, cursor);
      if (generation !== this.generation) return;
      if (cursor === null) this.firstPage.set(page);
      this.items.update((items) => (cursor === null ? page.items : [...items, ...page.items]));
      this.pages = cursor === null ? 1 : this.pages + 1;
      this.nextCursor.set(page.nextCursor && page.nextCursor !== cursor ? page.nextCursor : null);
      this.loaded.set(true);
    } catch (err) {
      if (generation === this.generation) this.error.set(problemMessage(err));
    } finally {
      if (generation === this.generation) this.loading.set(false);
    }
  }
}
