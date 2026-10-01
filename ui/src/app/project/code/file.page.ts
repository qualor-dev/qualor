import {
  afterRenderEffect,
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  input,
  LOCALE_ID,
  resource,
  viewChild,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, Router, RouterLink } from '@angular/router';
import { Api, ok } from '../../api/api';
import { ApiError, problemMessage } from '../../api/errors';
import { LabelPipe } from '../../i18n/label.pipe';
import { codeFileLink } from '../code-links';
import { CurrentProject } from '../current-project';
import { LineMapComponent } from './line-map.component';
import { buildLineMap, type FileDetail } from './line-map';
import { crumbs } from './tree';

/** `#L<n>` → n; anything else → null. */
export function fragmentLine(fragment: string | null | undefined): number | null {
  const match = /^L(\d+)$/.exec(fragment ?? '');
  const line = match ? Number(match[1]) : NaN;
  return Number.isSafeInteger(line) && line > 0 ? line : null;
}

/**
 * A file of a branch (spec §4.3): its path with crumbs back to the Code tab, tiles of its
 * measures, the line map, its duplicated blocks and its issues. No source text is shown: Qualor
 * never stores it. The branch and the path are query params (never path segments), so a name
 * with a space, `#`, `?` or `%` travels intact; `#L<n>` highlights a line on the map.
 */
@Component({
  selector: 'q-file-page',
  imports: [LabelPipe, LineMapComponent, RouterLink],
  templateUrl: './file.page.html',
  styleUrl: './file.page.css',
})
export class FilePage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly project = inject(CurrentProject);
  private readonly locale = inject(LOCALE_ID);
  readonly projectId = input.required<string>();

  private readonly query = toSignal(this.route.queryParamMap, {
    initialValue: this.route.snapshot.queryParamMap,
  });
  private readonly fragment = toSignal(this.route.fragment, {
    initialValue: this.route.snapshot.fragment,
  });

  /** The branch in the URL, if any; the links keep the URL free of it when there is none. */
  protected readonly urlBranch = computed(() => this.query().get('branch') || null);
  protected readonly branchId = computed(
    () => this.urlBranch() ?? this.project.current()?.mainBranch?.id ?? null,
  );
  protected readonly path = computed(() => this.query().get('path') ?? '');
  protected readonly highlight = computed(() => fragmentLine(this.fragment()));

  /** The file's directory, `''` at the root. */
  protected readonly dir = computed(() => {
    const p = this.path();
    const slash = p.lastIndexOf('/');
    return slash < 0 ? '' : p.slice(0, slash);
  });
  protected readonly name = computed(() => this.path().slice(this.path().lastIndexOf('/') + 1));
  protected readonly crumbs = computed(() => crumbs(this.dir()));
  protected readonly projectName = computed(() => this.project.current()?.name ?? '');

  protected readonly file = resource({
    params: () => {
      const branch = this.branchId();
      const path = this.path();
      return branch && path ? { branch, path } : undefined;
    },
    // openapi-fetch widens the schema's tuples (`[start, end]`) to arrays; the schema's type holds.
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/branches/{id}/file', {
          params: { path: { id: params.branch }, query: { path: params.path } },
        }),
      ) as Promise<FileDetail>,
  });

  protected readonly detail = computed<FileDetail | null>(() =>
    this.file.hasValue() ? this.file.value() : null,
  );
  protected readonly notFound = computed(() => {
    const err = this.file.error();
    return err instanceof ApiError && err.status === 404;
  });
  protected readonly failure = computed(() => {
    const err = this.file.error();
    return err && !this.notFound() ? problemMessage(err) : null;
  });

  protected readonly map = computed(() => {
    const d = this.detail();
    return d ? buildLineMap(d) : null;
  });

  /** Taken conditions of all of them, from the coverage's per-line condition counts. */
  protected readonly conditions = computed(() => {
    const branches = this.detail()?.coverage?.branches ?? [];
    const total = branches.reduce((n, [, t]) => n + t, 0);
    const covered = branches.reduce((n, [, , c]) => n + c, 0);
    return total > 0 ? { covered, total } : null;
  });

  protected readonly tiles = computed(() => {
    const d = this.detail();
    if (!d) return [];
    const m = d.measures;
    const cov = m['coverage'] ?? null;
    const c = this.conditions();
    const coverage =
      cov === null
        ? '—'
        : c
          ? $localize`:@@file.tile.coverageConditions:${this.percent(cov)}:coverage: · ${this.count(c.covered)}:covered: of ${this.count(c.total)}:total: conditions`
          : this.percent(cov);
    return [
      {
        key: 'ncloc',
        label: $localize`:@@file.tile.ncloc:Lines of code`,
        value: this.count(m['ncloc']),
      },
      {
        key: 'complexity',
        label: $localize`:@@file.tile.complexity:Complexity`,
        value: this.count(m['complexity']),
      },
      {
        key: 'cognitive_complexity',
        label: $localize`:@@file.tile.cognitive:Cognitive complexity`,
        value: this.count(m['cognitive_complexity']),
      },
      { key: 'coverage', label: $localize`:@@file.tile.coverage:Coverage`, value: coverage },
      {
        key: 'duplicated_lines',
        label: $localize`:@@file.tile.duplicated:Duplicated lines`,
        value: this.count(m['duplicated_lines']),
      },
      {
        key: 'issues',
        label: $localize`:@@file.tile.issues:Open issues`,
        value: this.count(m['issues']),
      },
    ];
  });

  /** The issues by line; one without a line comes last. */
  protected readonly issues = computed(() =>
    [...(this.detail()?.issues ?? [])].sort(
      (a, b) => (a.startLine ?? Infinity) - (b.startLine ?? Infinity),
    ),
  );

  private readonly mapPanel = viewChild<ElementRef<HTMLElement>>('mapPanel');

  constructor() {
    effect(() => this.project.use(this.projectId()));
    // `#L<n>` brings the map into view (it sits below the tiles; on a phone, far below).
    afterRenderEffect(() => {
      const panel = this.mapPanel()?.nativeElement;
      if (this.highlight() === null || !panel) return;
      // jsdom (the unit tests) does not scroll.
      if (typeof panel.scrollIntoView === 'function') panel.scrollIntoView({ block: 'nearest' });
    });
  }

  protected dirLink(dir: string) {
    return {
      commands: ['/projects', this.projectId(), 'code'],
      queryParams: { branch: this.urlBranch(), dir: dir || null },
    };
  }

  protected otherLink(path: string, line: number) {
    return codeFileLink(this.projectId(), this.branchId() ?? '', path, line);
  }

  protected issuesParams() {
    return { branch: this.branchId(), path: this.path() };
  }

  protected openIssue(id: string): void {
    void this.router.navigate(['/projects', this.projectId(), 'issues', id]);
  }

  protected count(value: number | null | undefined): string {
    return value === null || value === undefined
      ? '—'
      : new Intl.NumberFormat(this.locale, { maximumFractionDigits: 1 }).format(value);
  }

  protected percent(value: number): string {
    return `${new Intl.NumberFormat(this.locale, { minimumFractionDigits: 1, maximumFractionDigits: 1 }).format(value)}%`;
  }
}
