import {
  Component,
  computed,
  effect,
  inject,
  input,
  linkedSignal,
  resource,
  signal,
} from '@angular/core';
import { toSignal } from '@angular/core/rxjs-interop';
import { ActivatedRoute, type Params, Router, RouterLink } from '@angular/router';
import { Api, ok } from '../../api/api';
import { problemMessage } from '../../api/errors';
import type { paths } from '../../api/schema';
import type { ResponseBody } from '../../api/types';
import { LabelPipe } from '../../i18n/label.pipe';
import { label } from '../../i18n/labels';
import { inputValue, isChecked } from '../../shared/forms';
import { isUuid } from '../../shared/ids';
import { Icon } from '../../shared/icon';
import { clip } from '../../shared/text';
import { type Branch, branchTitle, findBranch } from '../branches';
import { codeFileLink } from '../code-links';

type DependencyQuery = NonNullable<
  paths['/api/v0/projects/{id}/dependencies']['get']['parameters']['query']
>;
/** `GET /projects/{id}/dependencies` (6M §8): a page of the inventory, its summary and flags. */
export type DependencyAnswer = ResponseBody<'/api/v0/projects/{id}/dependencies', 'get'>;
/** One inventory entry; `verdict` only while the answer's `verdicts` is true. */
export type DependencyRow = DependencyAnswer['rows'][number];
export type LicenseGroupFilter = NonNullable<DependencyQuery['group']>;

export const LICENSE_GROUP_IDS: readonly LicenseGroupFilter[] = [
  'network-copyleft',
  'strong-copyleft',
  'weak-copyleft',
  'non-commercial-or-source-available',
];
const PAGE_SIZE = 50;
/** The branch list's first page; a branch past it is looked up on its own. */
const BRANCH_PAGE = 500;
/** The version list's one page: the newest 100 are what the selector offers. */
const VERSION_PAGE = 100;
/** A version's value in the selector, apart from the branch ids. */
const VERSION_PREFIX = 'version:';
const Q_MAX_LENGTH = 200;
/** api.md: what `ecosystem` may be (the report format's rule). */
const ECOSYSTEM = /^[a-z0-9-]{1,32}$/;
/** The server's limits: a licence string of at most 256 characters, at most 100 000 pages. */
const LICENSE_MAX_LENGTH = 256;
const MAX_PAGE = 100_000;

/** The tab's filters, as the URL carries them (so a filtered list can be shared). */
export interface DependencyFilters {
  q: string;
  ecosystem: string;
  license: string;
  group: LicenseGroupFilter | '';
  unknown: boolean;
  direct: boolean;
  /** Only the forbidden entries; applied only while the answer carries verdicts. */
  forbidden: boolean;
  page: number;
}

function one(params: Params, key: string): string {
  const value: unknown = params[key];
  return typeof value === 'string' ? value.replaceAll('\u0000', '') : '';
}

/** The filters a URL asks for, clamped to what the route accepts (a crafted URL loses the rest). */
export function dependencyFilters(params: Params): DependencyFilters {
  const ecosystem = one(params, 'ecosystem');
  const group = one(params, 'group');
  const page = Number(one(params, 'page'));
  return {
    q: clip(one(params, 'q').trim(), Q_MAX_LENGTH),
    ecosystem: ECOSYSTEM.test(ecosystem) ? ecosystem : '',
    license: one(params, 'license').slice(0, LICENSE_MAX_LENGTH),
    group: LICENSE_GROUP_IDS.find((g) => g === group) ?? '',
    unknown: params['unknown'] === 'true',
    direct: params['direct'] === 'true',
    forbidden: params['verdict'] === 'forbidden',
    page: Number.isInteger(page) && page >= 1 && page <= MAX_PAGE ? page : 1,
  };
}

/** The URL's query for a branch or a version (never both) and filters; defaults are left out. */
function filterParams(
  scope: { branch?: string | null; version?: string | null },
  f: DependencyFilters,
): Params {
  return {
    ...(scope.version ? { version: scope.version } : scope.branch ? { branch: scope.branch } : {}),
    ...(f.q ? { q: f.q } : {}),
    ...(f.ecosystem ? { ecosystem: f.ecosystem } : {}),
    ...(f.license ? { license: f.license } : {}),
    ...(f.group ? { group: f.group } : {}),
    ...(f.unknown ? { unknown: 'true' } : {}),
    ...(f.direct ? { direct: 'true' } : {}),
    ...(f.forbidden ? { verdict: 'forbidden' } : {}),
    ...(f.page > 1 ? { page: String(f.page) } : {}),
  };
}

/**
 * The branch part of the route's query: none for the main branch (the route's default), a merge
 * request by its number, another branch by its name.
 */
function branchQuery(branch: Branch): { branch: string } | { mr: number } | Record<never, never> {
  if (branch.isMain) return {};
  const mr = Number(branch.name);
  return branch.kind === 'merge_request' && Number.isSafeInteger(mr) && mr >= 1
    ? { mr }
    : { branch: branch.name };
}

/** The branch is the one shown: the URL's branch when it names one, else the main branch. */
function isShown(branch: Branch, wanted: string | null): boolean {
  return wanted ? branch.id === wanted : branch.isMain;
}

/**
 * Project → Dependencies (6M §8), in every edition: the dependency inventory the last scan of a
 * branch or merge request reported, with how many entries have a known licence, filters (licence,
 * group, ecosystem, unknown only, direct only, a name search) and pages, all in the URL. While the
 * enterprise feature license-policy is active and the organisation has a policy, the rows carry the
 * policy's verdict: a Policy column and a Forbidden filter appear, and a forbidden entry links to
 * its issues. The branch is chosen as on the Issues tab (`?branch=<id>`).
 */
@Component({
  selector: 'q-dependencies-page',
  imports: [Icon, LabelPipe, RouterLink],
  templateUrl: './dependencies.page.html',
  styleUrl: './dependencies.page.css',
})
export class DependenciesPage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
  private readonly route = inject(ActivatedRoute);
  readonly projectId = input.required<string>();

  private readonly params = toSignal(this.route.queryParams, { initialValue: {} as Params });
  protected readonly filters = computed(() => dependencyFilters(this.params()));
  /** A released version (`?version=<id>`) is shown instead of a branch; it wins over `?branch=`. */
  protected readonly urlVersion = computed(() => {
    const version: unknown = this.params()['version'];
    return isUuid(version) ? version : null;
  });
  private readonly urlBranch = computed(() => {
    if (this.urlVersion()) return null;
    const branch: unknown = this.params()['branch'];
    return isUuid(branch) ? branch : null;
  });

  private readonly versions = resource({
    params: () => this.projectId(),
    loader: async ({ params }) =>
      (
        await ok(
          this.api.client.GET('/api/v0/projects/{id}/versions', {
            params: { path: { id: params }, query: { limit: VERSION_PAGE } },
          }),
        )
      ).items,
  });
  /** The versions the selector offers, newest first; the URL's own when it is not among them. */
  protected readonly versionOptions = computed(() => {
    const list = this.versions.hasValue() ? this.versions.value() : [];
    const options = list.map((v) => ({
      id: v.id,
      title: v.tracked ? $localize`:@@deps.versionTracked:${v.label}:label: (tracked)` : v.label,
    }));
    const wanted = this.urlVersion();
    return wanted && !options.some((o) => o.id === wanted)
      ? [...options, { id: wanted, title: wanted }]
      : options;
  });

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
  /**
   * The branch in use when it is not on the first page of branches (or the main one is not). A
   * project without branches has no main branch to look for: it was never analysed.
   */
  private readonly extraBranch = resource({
    params: () => {
      if (this.urlVersion() || !this.branches.hasValue()) return undefined;
      const list = this.branches.value();
      const wanted = this.urlBranch();
      const projectId = this.projectId();
      if (wanted) return list.some((b) => b.id === wanted) ? undefined : { projectId, wanted };
      return list.length === 0 || list.some((b) => b.isMain)
        ? undefined
        : { projectId, wanted: undefined };
    },
    loader: ({ params }) => findBranch(this.api, params.projectId, params.wanted),
  });
  /** The branch shown: the URL's, else the main one; null until known. */
  protected readonly branch = computed<Branch | null>(() => {
    if (this.urlVersion()) return null;
    const wanted = this.urlBranch();
    const listed = this.branchList().find((b) => isShown(b, wanted));
    if (listed) return listed;
    const extra = this.extraBranch.hasValue() ? this.extraBranch.value() : undefined;
    return extra && isShown(extra, wanted) ? extra : null;
  });
  protected readonly branchOptions = computed(() => {
    const options = this.branchList().map((b) => ({ id: b.id, title: branchTitle(b) }));
    const shown = this.branch();
    return shown && !options.some((o) => o.id === shown.id)
      ? [...options, { id: shown.id, title: branchTitle(shown) }]
      : options;
  });
  protected readonly versionPrefix = VERSION_PREFIX;
  protected readonly branchError = computed(() => {
    const error = this.branches.error() ?? this.extraBranch.error() ?? this.versions.error();
    return error ? problemMessage(error) : null;
  });

  protected readonly answer = resource({
    params: () => {
      const projectId = this.projectId();
      const filters = this.filters();
      const version = this.urlVersion();
      if (version) return { projectId, branch: { version }, filters };
      // The main branch is the route's default: it is asked for at once, found or not.
      if (!this.urlBranch()) return { projectId, branch: {}, filters };
      const branch = this.branch();
      return branch ? { projectId, branch: branchQuery(branch), filters } : undefined;
    },
    loader: ({ params }) => {
      const f = params.filters;
      return ok(
        this.api.client.GET('/api/v0/projects/{id}/dependencies', {
          params: {
            path: { id: params.projectId },
            query: {
              ...params.branch,
              ...(f.q ? { q: f.q } : {}),
              ...(f.ecosystem ? { ecosystem: f.ecosystem } : {}),
              ...(f.license ? { license: f.license } : {}),
              ...(f.group ? { group: f.group } : {}),
              ...(f.unknown ? { unknown: 'true' as const } : {}),
              ...(f.direct ? { direct: 'true' as const } : {}),
              ...(f.forbidden ? { verdict: 'forbidden' as const } : {}),
              page: f.page,
              pageSize: PAGE_SIZE,
            },
          },
        }),
      );
    },
  });
  /** The latest answer, kept while the next one loads so the table does not flash empty. */
  protected readonly current = linkedSignal<
    { value: DependencyAnswer | undefined; failed: boolean },
    DependencyAnswer | null
  >({
    source: () => ({
      value: this.answer.hasValue() ? this.answer.value() : undefined,
      failed: this.answer.error() !== undefined,
    }),
    computation: (source, previous) =>
      source.failed ? null : (source.value ?? previous?.value ?? null),
  });
  protected readonly loading = computed(() => this.answer.isLoading());
  protected readonly verdictLabels = {
    allowed: label('verdict', 'allowed'),
    forbidden: label('verdict', 'forbidden'),
    unknown: label('verdict', 'unknown'),
  };
  protected readonly loadError = computed(() => {
    const error = this.answer.error();
    return error ? problemMessage(error) : null;
  });
  /** The rows carry the policy's verdict: the Policy column and the Forbidden filter. */
  protected readonly verdicts = computed(() => this.current()?.verdicts === true);
  /** The licence filter's choices: the most frequent licences, and the URL's own when not among them. */
  protected readonly licenseOptions = computed(() => {
    const top = this.current()?.summary.byLicense ?? [];
    // In the server's order: the most frequent first.
    const options = top.map((l) => ({ value: l.license, label: `${l.license} (${l.count})` }));
    const chosen = this.filters().license;
    return chosen && !options.some((o) => o.value === chosen)
      ? [...options, { value: chosen, label: chosen }]
      : options;
  });
  protected readonly groups = LICENSE_GROUP_IDS;
  /** The ecosystems seen in this branch's rows, offered while typing one. */
  private readonly seen = signal<{ branch: string | null; ecosystems: ReadonlySet<string> }>({
    branch: null,
    ecosystems: new Set(),
  });
  protected readonly ecosystems = computed(() => [...this.seen().ecosystems].sort());
  protected readonly pageRange = computed(() => {
    const answer = this.current();
    if (!answer || answer.total === 0) return null;
    const first = (answer.page - 1) * answer.pageSize + 1;
    const last = Math.min(answer.total, answer.page * answer.pageSize);
    // Previous and Next only when there is more than one page.
    return {
      first,
      last,
      total: answer.total,
      more: last < answer.total,
      pages: answer.total > answer.pageSize,
    };
  });

  protected readonly search = signal('');
  protected readonly ecosystem = signal('');
  protected readonly ecosystemError = signal<string | null>(null);
  protected readonly qMax = Q_MAX_LENGTH;
  protected readonly inputValue = inputValue;
  /** The search fields' values last copied from the URL, so typed but unsent text survives. */
  private shown: { q: string; ecosystem: string } | null = null;

  constructor() {
    effect(() => {
      const f = this.filters();
      if (this.shown?.q !== f.q) this.search.set(f.q);
      if (this.shown?.ecosystem !== f.ecosystem) this.ecosystem.set(f.ecosystem);
      this.shown = { q: f.q, ecosystem: f.ecosystem };
    });
    effect(() => {
      const answer = this.current();
      const branch = this.branch()?.id ?? this.urlVersion();
      if (!answer) return;
      const before = this.seen();
      const ecosystems = new Set(before.branch === branch ? before.ecosystems : []);
      const size = ecosystems.size;
      for (const row of answer.rows) ecosystems.add(row.ecosystem);
      if (before.branch !== branch || ecosystems.size !== size) {
        this.seen.set({ branch, ecosystems });
      }
    });
  }

  protected fileLink(row: DependencyRow) {
    return codeFileLink(this.projectId(), this.branch()?.id ?? '', row.path, row.line);
  }

  /** The Issues tab filtered to the forbidden-licence issues of a package on this branch. */
  protected issuesParams(row: DependencyRow): Params {
    return { branch: this.branch()?.id, rule: 'license:forbidden', q: row.name };
  }

  /** "Issues of gpl-money 2.1.0": the link's name starts with its visible word (WCAG label in name). */
  protected issuesLabel(row: DependencyRow): string {
    return $localize`:@@deps.issuesLabel:Issues of ${row.name}:name: ${row.version}:version:`;
  }

  private apply(changes: Partial<DependencyFilters>): void {
    // Any change but the page's own starts again on the first page.
    const next = { ...this.filters(), page: 1, ...changes };
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: filterParams({ branch: this.urlBranch(), version: this.urlVersion() }, next),
      replaceUrl: true,
    });
  }

  protected setBranch(event: Event): void {
    const chosen = inputValue(event);
    const scope = chosen.startsWith(VERSION_PREFIX)
      ? { version: chosen.slice(VERSION_PREFIX.length) }
      : { branch: chosen || null };
    void this.router.navigate([], {
      relativeTo: this.route,
      queryParams: filterParams(scope, { ...this.filters(), page: 1 }),
      replaceUrl: true,
    });
  }

  protected setLicense(event: Event): void {
    this.apply({ license: inputValue(event) });
  }

  protected setGroup(event: Event): void {
    const value = inputValue(event);
    this.apply({ group: LICENSE_GROUP_IDS.find((g) => g === value) ?? '' });
  }

  protected setUnknown(event: Event): void {
    this.apply({ unknown: isChecked(event) });
  }

  protected setDirect(event: Event): void {
    this.apply({ direct: isChecked(event) });
  }

  protected setForbidden(event: Event): void {
    this.apply({ forbidden: isChecked(event) });
  }

  protected setEcosystem(event: Event): void {
    this.ecosystem.set(inputValue(event));
    this.ecosystemError.set(null);
  }

  protected submitSearch(event: Event): void {
    event.preventDefault();
    const ecosystem = this.ecosystem().trim();
    if (ecosystem && !ECOSYSTEM.test(ecosystem)) {
      this.ecosystemError.set(
        $localize`:@@deps.badEcosystem:An ecosystem is a lowercase name such as npm or gomod.`,
      );
      return;
    }
    this.ecosystemError.set(null);
    this.apply({ q: clip(this.search().trim(), Q_MAX_LENGTH), ecosystem });
  }

  protected goTo(page: number): void {
    this.apply({ page });
  }
}
