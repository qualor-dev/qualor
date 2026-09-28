import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  DestroyRef,
  type ElementRef,
  effect,
  inject,
  input,
  resource,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, type Params, Router, RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { isRetryable, problemMessage } from '../api/errors';
import type { ItemOf, RequestBody, ResponseBody } from '../api/types';
import { LabelPipe } from '../i18n/label.pipe';
import type { LabelKind } from '../i18n/labels';
import { branchTitle, branchView, findBranch, mainBranchView } from '../project/branches';
import { CurrentProject } from '../project/current-project';
import { DateTimePipe } from '../shared/date-time.pipe';
import { inputValue, isChecked } from '../shared/forms';
import { KeysetList } from '../shared/keyset';
import { RetryOffer } from '../shared/retry';
import {
  apiQuery,
  branchFromParams,
  facetValues,
  filtersFromParams,
  filtersToParams,
  type IssueFilters,
  type IssueSort,
  KINDS,
  type ListFilter,
  Q_MAX_LENGTH,
  QUALITIES,
  SEVERITIES,
  STATUSES,
  toggle,
} from './issue-filters';
import {
  ALL_TARGETS,
  allowedTargets,
  BULK_MAX_IDS,
  COMMENT_MAX_LENGTH,
  needsComment,
  type TransitionTarget,
} from './transitions';

export type Issue = ItemOf<'/api/v0/issues'>;
type IssueListPage = ResponseBody<'/api/v0/issues', 'get'>;
type BulkRequest = RequestBody<'/api/v0/issues/bulk-transition', 'post'>;
type BulkResult = ResponseBody<'/api/v0/issues/bulk-transition', 'post'>;
/** The branch list's first page; a branch past it is looked up on its own. */
const BRANCH_PAGE = 500;

/** "2 issues changed. 1 issue cannot change to this status; it stays selected." */
function bulkSummary(result: BulkResult): string {
  const changed = result.succeeded.length;
  const invalid = result.failed.filter((f) => f.code === 'INVALID_TRANSITION').length;
  const missing = result.failed.filter((f) => f.code === 'NOT_FOUND').length;
  const forbidden = result.failed.filter((f) => f.code === 'FORBIDDEN').length;
  const parts = [
    changed === 1
      ? $localize`:@@issues.bulk.changedOne:1 issue changed.`
      : $localize`:@@issues.bulk.changed:${changed}:count: issues changed.`,
  ];
  if (invalid === 1) {
    parts.push(
      $localize`:@@issues.bulk.invalidOne:1 issue cannot change to this status; it stays selected.`,
    );
  } else if (invalid > 1) {
    parts.push(
      $localize`:@@issues.bulk.invalid:${invalid}:count: issues cannot change to this status; they stay selected.`,
    );
  }
  if (forbidden === 1) {
    parts.push(
      $localize`:@@issues.bulk.forbiddenOne:1 issue cannot be changed with your role in its project.`,
    );
  } else if (forbidden > 1) {
    parts.push(
      $localize`:@@issues.bulk.forbidden:${forbidden}:count: issues cannot be changed with your role in their project.`,
    );
  }
  if (missing === 1) {
    parts.push(
      $localize`:@@issues.bulk.notFoundOne:1 issue no longer exists or is no longer visible to you.`,
    );
  } else if (missing > 1) {
    parts.push(
      $localize`:@@issues.bulk.notFound:${missing}:count: issues no longer exist or are no longer visible to you.`,
    );
  }
  return parts.join(' ');
}

/**
 * A branch's issues (api.md `GET /issues`): filters and facets in the URL, keyset pages, and
 * status changes for a selection (`POST /issues/bulk-transition`, at most 500 ids). The URL is
 * read through `filtersFromParams`, which clamps it to what the API accepts. Facets come from the
 * first page of the latest accepted answer, never from an answer a newer query replaced. A 503
 * `CONCURRENCY_CONFLICT` (an analysis held the issues; nothing was written) offers to send the
 * same change again once its `Retry-After` has passed. After a change, focus moves to the result
 * (an always-present live region), since the control that was used may be gone or disabled.
 */
@Component({
  selector: 'q-issues-page',
  imports: [DateTimePipe, LabelPipe, RouterLink],
  templateUrl: './issues.page.html',
  styleUrl: './issues.page.css',
})
export class IssuesPage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  private readonly document = inject(DOCUMENT);
  private readonly project = inject(CurrentProject);
  readonly projectId = input.required<string>();
  /**
   * Whether the caller may change issue statuses here (`issue.triage`): otherwise the selection
   * and the bulk change are not shown (rbac-audit.md §17).
   */
  protected readonly canTriage = computed(() =>
    this.project.canChange(this.projectId(), 'issue.triage'),
  );

  private readonly params = toSignal(this.route.queryParams, { initialValue: {} as Params });
  protected readonly filters = computed(() => filtersFromParams(this.params()));
  private readonly urlBranch = computed(() => branchFromParams(this.params()));
  protected readonly branches = resource({
    params: () => this.projectId(),
    loader: async ({ params }) =>
      (
        await ok(
          this.api.client.GET('/api/v0/projects/{id}/branches', {
            params: { path: { id: params }, query: { limit: BRANCH_PAGE } },
          }),
        )
      ).items,
  });
  private readonly branchList = computed(() =>
    this.branches.hasValue() ? this.branches.value() : [],
  );
  /** The branch in use when it is not on the first page of branches (or the main one is not). */
  protected readonly extraBranch = resource({
    params: () => {
      if (!this.branches.hasValue()) return undefined;
      const list = this.branches.value();
      const wanted = this.urlBranch();
      const projectId = this.projectId();
      if (wanted) return list.some((b) => b.id === wanted) ? undefined : { projectId, wanted };
      return list.some((b) => b.isMain) ? undefined : { projectId, wanted: null };
    },
    loader: async ({ params }) =>
      params.wanted
        ? branchView(await findBranch(this.api, params.projectId, params.wanted))
        : mainBranchView(this.api, params.projectId),
  });
  protected readonly branchOptions = computed(() => {
    const options = this.branchList().map((b) => ({ id: b.id, title: branchTitle(b) }));
    const extra = this.extraBranch.hasValue() ? this.extraBranch.value() : undefined;
    return extra && !options.some((o) => o.id === extra.id)
      ? [...options, { id: extra.id, title: extra.title }]
      : options;
  });
  protected readonly branchId = computed(
    () =>
      this.urlBranch() ??
      this.branchList().find((b) => b.isMain)?.id ??
      (this.extraBranch.hasValue() ? this.extraBranch.value()?.id : undefined) ??
      null,
  );
  protected readonly branchError = computed(() => {
    const error = this.branches.error() ?? this.extraBranch.error();
    return error ? problemMessage(error) : null;
  });

  protected readonly list = new KeysetList<
    Issue,
    { branchId: string; filters: IssueFilters },
    IssueListPage
  >((p, cursor) =>
    ok(
      this.api.client.GET('/api/v0/issues', {
        params: { query: apiQuery(p.filters, p.branchId, cursor) },
      }),
    ),
  );
  protected readonly facets = computed(() => this.list.firstPage()?.facets ?? {});

  protected readonly search = signal('');
  /** The `q` last copied into the search box, so typed but unsent text survives other filters. */
  private shownQuery: string | null = null;
  protected readonly selected = signal<ReadonlySet<string>>(new Set());
  protected readonly target = signal<TransitionTarget>('resolved');
  protected readonly comment = signal('');
  protected readonly busy = signal(false);
  protected readonly bulkMessage = signal<string | null>(null);
  protected readonly bulkError = signal<string | null>(null);
  /** The change a 503 refused, to send again as it was. */
  protected readonly retryOffer = new RetryOffer<BulkRequest>();
  private readonly bulkStatus = viewChild<ElementRef<HTMLElement>>('bulkStatus');

  protected readonly facetGroups = computed(() => {
    const f = this.filters();
    const facets: Partial<Record<string, { value: string; count: number }[]>> = this.facets();
    const group = (filter: ListFilter, known: string[], labelKind: LabelKind | null) => ({
      filter,
      labelKind,
      values: facetValues(known, facets[filter], f[filter]),
    });
    return [
      group('severity', SEVERITIES, 'severity'),
      group('status', STATUSES, 'status'),
      group('quality', QUALITIES, 'quality'),
      group('engine', [], null),
      group('rule', [], null),
      // Paths have no facet here; a shared URL's path filters are listed so they can be removed.
      ...(f.path.length > 0 ? [group('path', [], null)] : []),
    ];
  });
  protected readonly kinds = computed(() =>
    KINDS.map((value) => ({ value, selected: this.filters().kind.includes(value) })),
  );
  /** The statuses the listed issues can go to (table I2): no "Reopen" on an open-only list. */
  protected readonly targets = computed(() => {
    const allowed = new Set(this.filters().status.flatMap((s) => allowedTargets(s)));
    return ALL_TARGETS.filter((t) => allowed.has(t));
  });
  protected readonly bulkTarget = computed(() => {
    const targets = this.targets();
    return targets.includes(this.target()) ? this.target() : (targets[0] ?? null);
  });
  protected readonly allSelected = computed(
    () => this.list.items().length > 0 && this.list.items().every((i) => this.selected().has(i.id)),
  );
  protected readonly commentRequired = computed(() => {
    const target = this.bulkTarget();
    return target !== null && needsComment(target);
  });
  protected readonly overLimit = computed(() => this.selected().size > BULK_MAX_IDS);
  protected readonly canApply = computed(
    () =>
      !this.busy() &&
      this.bulkTarget() !== null &&
      this.selected().size > 0 &&
      !this.overLimit() &&
      !(this.commentRequired() && !this.comment().trim()),
  );

  protected readonly commentMax = COMMENT_MAX_LENGTH;
  protected readonly bulkMax = BULK_MAX_IDS;
  protected readonly qMax = Q_MAX_LENGTH;
  protected readonly inputValue = inputValue;

  constructor() {
    effect(() => this.project.use(this.projectId()));
    effect(() => {
      const branchId = this.branchId();
      const filters = this.filters();
      untracked(() => {
        if (filters.q !== this.shownQuery) {
          this.search.set(filters.q);
          this.shownQuery = filters.q;
        }
        this.selected.set(new Set());
        this.retryOffer.clear();
        if (branchId) void this.list.reset({ branchId, filters });
      });
    });
    inject(DestroyRef).onDestroy(() => this.retryOffer.clear());
  }

  private navigate(params: Params): void {
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: params,
      queryParamsHandling: 'merge',
      replaceUrl: true,
    });
  }

  protected toggleFilter(filter: ListFilter, value: string): void {
    this.navigate(filtersToParams(toggle(this.filters(), filter, value)));
  }

  protected setNewCode(event: Event): void {
    this.navigate(filtersToParams({ ...this.filters(), inNewCode: isChecked(event) }));
  }

  protected setDuplicates(event: Event): void {
    this.navigate(filtersToParams({ ...this.filters(), includeDuplicates: isChecked(event) }));
  }

  protected setSort(event: Event): void {
    const sort = inputValue(event) as IssueSort;
    this.navigate(filtersToParams({ ...this.filters(), sort }));
  }

  protected setBranch(event: Event): void {
    this.navigate({ branch: inputValue(event) || null });
  }

  protected submitSearch(event: Event): void {
    event.preventDefault();
    this.navigate(filtersToParams({ ...this.filters(), q: this.search() }));
  }

  protected toggleOne(id: string, event: Event): void {
    const next = new Set(this.selected());
    if (isChecked(event)) next.add(id);
    else next.delete(id);
    this.selected.set(next);
  }

  protected toggleAll(event: Event): void {
    this.selected.set(isChecked(event) ? new Set(this.list.items().map((i) => i.id)) : new Set());
  }

  protected setTarget(event: Event): void {
    this.target.set(inputValue(event) as TransitionTarget);
  }

  protected async applyBulk(event: Event): Promise<void> {
    event.preventDefault();
    const to = this.bulkTarget();
    if (!this.canApply() || to === null) return;
    const comment = this.comment().trim();
    await this.send({ ids: [...this.selected()], to, ...(comment ? { comment } : {}) });
  }

  protected async retry(): Promise<void> {
    if (this.busy()) return;
    const request = this.retryOffer.take();
    if (request) await this.send(request);
  }

  private async send(request: BulkRequest): Promise<void> {
    this.busy.set(true);
    this.bulkError.set(null);
    this.bulkMessage.set(null);
    this.retryOffer.clear();
    let succeeded = false;
    try {
      const result = await ok(
        this.api.client.POST('/api/v0/issues/bulk-transition', { body: request }),
      );
      this.bulkMessage.set(bulkSummary(result));
      this.comment.set('');
      await this.list.reload();
      // Issues that could not change stay selected (when still listed), to try another status.
      const kept = new Set(
        result.failed.filter((f) => f.code === 'INVALID_TRANSITION').map((f) => f.id),
      );
      this.selected.set(
        new Set(
          this.list
            .items()
            .filter((i) => kept.has(i.id))
            .map((i) => i.id),
        ),
      );
      succeeded = true;
    } catch (err) {
      this.bulkError.set(problemMessage(err));
      if (isRetryable(err)) this.retryOffer.offer(request, err.retryAfter);
    } finally {
      this.busy.set(false);
    }
    // The button used may be disabled or gone now: keep keyboard users on the result.
    const active = this.document.activeElement;
    if (succeeded || active === null || active === this.document.body) {
      this.bulkStatus()?.nativeElement.focus();
    }
  }
}
