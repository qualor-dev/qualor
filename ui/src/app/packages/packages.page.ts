import { Component, computed, effect, inject, linkedSignal, resource, signal } from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, type Params, Router, RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { problemMessage } from '../api/errors';
import type { ResponseBody } from '../api/types';
import { inputValue } from '../shared/forms';
import { PageHeader } from '../shared/page-header';

/** `GET /packages/usages`: one page of the rows where a package is used. */
type UsageAnswer = ResponseBody<'/api/v0/packages/usages', 'get'>;
export type UsageRow = UsageAnswer['rows'][number];

const PAGE_SIZE = 50;
/** The server's limit for `q` (a longer text would only be refused). */
const Q_MAX_LENGTH = 300;
/** The purl types an SBOM or a scan stores (the ecosystem filter's choices). */
export const PURL_TYPES: readonly string[] = [
  'npm',
  'pypi',
  'maven',
  'nuget',
  'golang',
  'cargo',
  'composer',
  'gem',
  'pub',
  'hex',
  'swift',
  'cocoapods',
  'conan',
  'deb',
  'rpm',
  'apk',
];

const one = (params: Params, key: string): string => {
  const value: unknown = params[key];
  const first = Array.isArray(value) ? (value[0] as unknown) : value;
  return typeof first === 'string' ? first : '';
};

/** The Packages page: where is this package used, across every project the user can read. */
@Component({
  selector: 'q-packages-page',
  imports: [PageHeader, RouterLink],
  templateUrl: './packages.page.html',
  styleUrl: './packages.page.css',
  host: { class: 'bleed' },
})
export class PackagesPage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly params = toSignal(this.route.queryParams, { initialValue: {} as Params });

  protected readonly qMax = Q_MAX_LENGTH;
  protected readonly inputValue = inputValue;

  /** What the URL asks for: the search that is shown and sent. */
  protected readonly query = computed(() => {
    const p = this.params();
    const page = Number.parseInt(one(p, 'page'), 10);
    return {
      q: one(p, 'q').trim(),
      ecosystem: one(p, 'ecosystem'),
      version: one(p, 'version').trim(),
      page: Number.isInteger(page) && page >= 1 ? Math.min(page, 100_000) : 1,
    };
  });

  protected readonly search = linkedSignal(() => this.query().q);
  protected readonly ecosystem = linkedSignal(() => this.query().ecosystem);
  protected readonly version = linkedSignal(() => this.query().version);
  protected readonly searchError = signal<string | null>(null);

  /** The ecosystem choices: the known types, and the URL's own when it is not one of them. */
  protected readonly ecosystems = computed(() => {
    const own = this.query().ecosystem;
    return own && !PURL_TYPES.includes(own) ? [...PURL_TYPES, own] : PURL_TYPES;
  });

  protected readonly answer = resource({
    params: () => {
      const q = this.query();
      return q.q === '' ? undefined : q;
    },
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/packages/usages', {
          params: {
            query: {
              q: params.q,
              ...(params.ecosystem ? { ecosystem: params.ecosystem } : {}),
              ...(params.version ? { version: params.version } : {}),
              page: params.page,
              pageSize: PAGE_SIZE,
            },
          },
        }),
      ),
  });
  /** The latest answer, kept while the next page loads so the table does not flash empty. */
  protected readonly current = linkedSignal<
    { value: UsageAnswer | undefined; failed: boolean; idle: boolean },
    UsageAnswer | null
  >({
    source: () => ({
      value: this.answer.hasValue() ? this.answer.value() : undefined,
      failed: this.answer.error() !== undefined,
      idle: this.query().q === '',
    }),
    computation: (source, previous) =>
      source.failed || source.idle ? null : (source.value ?? previous?.value ?? null),
  });
  protected readonly loading = computed(() => this.answer.isLoading());
  protected readonly loadError = computed(() => {
    const error = this.answer.error();
    return error === undefined ? null : problemMessage(error);
  });
  protected readonly searched = computed(() => this.query().q !== '');

  protected readonly pageRange = computed(() => {
    const answer = this.current();
    if (!answer || answer.total === 0) return null;
    const first = (answer.page - 1) * answer.pageSize + 1;
    const last = Math.min(answer.total, answer.page * answer.pageSize);
    return {
      first,
      last,
      total: answer.total,
      capped: answer.totalCapped,
      more: last < answer.total,
      pages: answer.total > answer.pageSize,
    };
  });

  constructor() {
    // A new URL search replaces an earlier error about the empty field.
    effect(() => {
      this.query();
      this.searchError.set(null);
    });
  }

  protected submit(event: Event): void {
    event.preventDefault();
    const q = this.search().trim();
    if (q === '') {
      this.searchError.set($localize`:@@packages.search.empty:Search needs at least one character`);
      return;
    }
    this.searchError.set(null);
    void this.router.navigate([], {
      queryParams: {
        q,
        ecosystem: this.ecosystem() || null,
        version: this.version().trim() || null,
        page: null,
      },
    });
  }

  protected goTo(page: number): void {
    void this.router.navigate([], {
      queryParams: { page: page > 1 ? page : null },
      queryParamsHandling: 'merge',
    });
  }

  /** The Dependencies tab of the row's branch or version, filtered to its package. */
  protected link(row: UsageRow): { commands: string[]; queryParams: Params } {
    const commands = ['/projects', row.project.id, 'dependencies'];
    if (row.target.kind === 'version') {
      return { commands, queryParams: { version: row.target.id, q: row.name } };
    }
    return {
      commands,
      queryParams: row.target.main ? { q: row.name } : { branch: row.target.name, q: row.name },
    };
  }
}
