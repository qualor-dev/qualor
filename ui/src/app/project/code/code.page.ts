import {
  Component,
  computed,
  effect,
  inject,
  input,
  LOCALE_ID,
  resource,
  signal,
  untracked,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Api, ok } from '../../api/api';
import { Icon } from '../../shared/icon';
import { KeysetList } from '../../shared/keyset';
import { codeFileLink } from '../code-links';
import { CurrentProject } from '../current-project';
import { BranchPicker } from './branch-picker';
import { crumbs, sortTree, type TreeItem, type TreeSort } from './tree';

const PAGE_SIZE = 200;

type SortKey = TreeSort['key'];
type Tone = 'a' | 'b' | 'c' | 'd' | 'e';

/** Coverage in the rating scale's colours: A from 80 % up, then one step per ten points. */
export function coverageTone(coverage: number): Tone {
  return coverage >= 80
    ? 'a'
    : coverage >= 70
      ? 'b'
      : coverage >= 60
        ? 'c'
        : coverage >= 50
          ? 'd'
          : 'e';
}

/**
 * The Code tab (spec §4.2): a branch's files and directories with their metrics. The branch and
 * the directory live in the URL (`?branch=`, `?dir=`), always as query params, never in a path,
 * so a name with a space, `#`, `?` or `%` travels intact. The server lists by name; the column
 * headers sort the loaded rows, directories first.
 */
@Component({
  selector: 'q-code-page',
  imports: [BranchPicker, Icon, RouterLink],
  templateUrl: './code.page.html',
  styleUrl: './code.page.css',
})
export class CodePage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly project = inject(CurrentProject);
  private readonly locale = inject(LOCALE_ID);
  readonly projectId = input.required<string>();

  private readonly query = toSignal(this.route.queryParamMap, {
    initialValue: this.route.snapshot.queryParamMap,
  });
  /** The branch in the URL, if any; the link keeps the URL free of it when there is none. */
  protected readonly urlBranch = computed(() => this.query().get('branch') || null);
  protected readonly dir = computed(() => this.query().get('dir') ?? '');
  protected readonly branchId = computed(
    () => this.urlBranch() ?? this.project.current()?.mainBranch?.id ?? null,
  );
  /** The project is read and has no branch yet: nothing was analysed. */
  protected readonly noBranch = computed(() => {
    const p = this.project.current();
    return !this.urlBranch() && p !== null && p.id === this.projectId() && !p.mainBranch;
  });
  protected readonly projectName = computed(() => this.project.current()?.name ?? '');
  protected readonly crumbs = computed(() => crumbs(this.dir()));

  protected readonly sort = signal<TreeSort>({ key: 'name', dir: 'asc' });
  protected readonly list = new KeysetList<TreeItem, { branch: string; dir: string }>(
    (params, cursor) =>
      ok(
        this.api.client.GET('/api/v0/branches/{id}/files', {
          params: {
            path: { id: params.branch },
            query: { dir: params.dir, limit: PAGE_SIZE, ...(cursor ? { cursor } : {}) },
          },
        }),
      ),
  );
  protected readonly rows = computed(() => sortTree(this.list.items(), this.sort()));
  protected readonly empty = computed(
    () => this.noBranch() || (this.list.loaded() && this.list.items().length === 0),
  );

  /** The branch's own measures: the summary of the root. */
  private readonly branchMeasures = resource({
    params: () => (this.dir() === '' ? this.branchId() : null),
    loader: async ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/branches/{id}/measures', {
          params: {
            path: { id: params as string },
            query: { metrics: 'files,ncloc,coverage,issues' },
          },
        }),
      ),
  });

  /** Files, lines of code, coverage and open issues of the directory shown; null when unknown. */
  protected readonly summary = computed(() => {
    if (this.dir() === '') {
      if (!this.branchMeasures.hasValue()) return null;
      const by = new Map(this.branchMeasures.value().map((m) => [m.metric, m.overall]));
      return {
        files: by.get('files') ?? null,
        ncloc: by.get('ncloc') ?? null,
        coverage: by.get('coverage') ?? null,
        issues: by.get('issues') ?? null,
      };
    }
    // A sub-directory: the sums of its rows, only when the listing is whole.
    if (!this.list.loaded() || this.list.nextCursor() !== null || this.list.error()) return null;
    const items = this.list.items();
    const sum = (key: string) => items.reduce((n, i) => n + (i.measures[key] ?? 0), 0);
    return {
      files: items.reduce((n, i) => n + (i.type === 'file' ? 1 : (i.measures['files'] ?? 0)), 0),
      ncloc: sum('ncloc'),
      coverage: null,
      issues: sum('issues'),
    };
  });

  constructor() {
    effect(() => this.project.use(this.projectId()));
    effect(() => {
      const branch = this.branchId();
      const dir = this.dir();
      untracked(() => {
        if (branch) void this.list.reset({ branch, dir });
        else this.list.clear();
      });
    });
  }

  protected dirLink(dir: string) {
    return { queryParams: { branch: this.urlBranch(), dir: dir || null } };
  }

  protected fileLink(path: string) {
    return codeFileLink(this.projectId(), this.branchId() ?? '', path);
  }

  protected issuesParams(path: string) {
    return { branch: this.branchId(), path };
  }

  protected pickBranch(id: string): void {
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: { branch: id, dir: null },
    });
  }

  protected sortBy(key: SortKey): void {
    this.sort.update((s) =>
      s.key === key
        ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' }
        : { key, dir: key === 'name' ? 'asc' : 'desc' },
    );
  }

  protected ariaSort(key: SortKey): 'ascending' | 'descending' | 'none' {
    const s = this.sort();
    return s.key !== key ? 'none' : s.dir === 'asc' ? 'ascending' : 'descending';
  }

  protected count(value: number | null | undefined): string {
    return value === null || value === undefined
      ? '—'
      : new Intl.NumberFormat(this.locale, { maximumFractionDigits: 1 }).format(value);
  }

  protected percent(value: number | null | undefined): string {
    return value === null || value === undefined
      ? '—'
      : `${new Intl.NumberFormat(this.locale, { minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(value)}%`;
  }

  protected readonly tone = coverageTone;

  protected barWidth(value: number): string {
    return `${Math.min(100, Math.max(0, value))}%`;
  }
}
