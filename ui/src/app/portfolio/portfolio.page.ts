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
import { Router, RouterLink } from '@angular/router';
import type {
  PortfolioAggregate,
  PortfolioProjectRow,
  PortfolioSort,
  PortfolioTrendPoint,
} from '../api/ee';
import { ApiError, problemMessage } from '../api/errors';
import { Distribution, type DistributionItem } from '../charts/distribution';
import { type ChartSeries, LineChart } from '../charts/line-chart';
import { Meter } from '../charts/meter';
import { Rating } from '../charts/rating';
import { label } from '../i18n/labels';
import { OrgContext } from '../org/org-context';
import { DateTimePipe, formatDate } from '../shared/date-time.pipe';
import { GateBadge } from '../shared/gate-badge';
import { KeysetList } from '../shared/keyset';
import { formatMeasure, MeasurePipe } from '../shared/measure.pipe';
import { PageHeader } from '../shared/page-header';
import { SystemInfo } from '../shell/system-info';
import {
  PortfolioApi,
  type PortfolioFormat,
  type PortfolioGranularity,
  type PortfolioScope,
} from './portfolio-api';

type Letter = 'A' | 'B' | 'C' | 'D' | 'E';
const LETTERS: readonly Letter[] = ['A', 'B', 'C', 'D', 'E'];
const SEVERITIES = ['blocker', 'high', 'medium', 'low', 'info'] as const;
/** A share in percent: the measure pipe formats a `…_density` as "50 %". */
const SHARE = 'gate_pass_density';
/** No value (nothing analyzed, no measures): the measure pipe's dash, never "0". */
const NO_VALUE = formatMeasure(null, SHARE);

/**
 * The projects table's sorts (4E-2 §2), in column order, with the order the server sorts in: the
 * worst first (failed gates, E ratings, the most issues, the lowest coverage, the oldest
 * analysis), keys A to Z.
 */
const COLUMNS: readonly {
  sort: PortfolioSort;
  label: string;
  order: 'ascending' | 'descending';
  num: boolean;
}[] = [
  {
    sort: 'key',
    label: $localize`:@@portfolio.col.project:Project`,
    order: 'ascending',
    num: false,
  },
  {
    sort: 'gate',
    label: $localize`:@@portfolio.col.gate:Quality gate`,
    order: 'ascending',
    num: false,
  },
  {
    sort: 'security',
    label: $localize`:@@portfolio.col.security:Security`,
    order: 'descending',
    num: false,
  },
  {
    sort: 'reliability',
    label: $localize`:@@portfolio.col.reliability:Reliability`,
    order: 'descending',
    num: false,
  },
  {
    sort: 'issues',
    label: $localize`:@@portfolio.col.issues:Issues`,
    order: 'descending',
    num: true,
  },
  {
    sort: 'ncloc',
    label: $localize`:@@portfolio.col.ncloc:Lines of code`,
    order: 'descending',
    num: true,
  },
  {
    sort: 'coverage',
    label: $localize`:@@portfolio.col.coverage:Coverage`,
    order: 'ascending',
    num: true,
  },
  {
    sort: 'vulnerableReleases',
    label: $localize`:@@portfolio.col.vulnerableReleases:Vulnerable releases`,
    order: 'descending',
    num: true,
  },
  {
    sort: 'exploited',
    label: $localize`:@@portfolio.col.exploited:Exploited`,
    order: 'descending',
    num: true,
  },
  {
    sort: 'lastAnalysis',
    label: $localize`:@@portfolio.col.lastAnalysis:Last analysis`,
    order: 'ascending',
    num: false,
  },
];

const sameScope = (a: PortfolioScope | null, b: PortfolioScope | null): boolean =>
  a === b ||
  (a !== null &&
    b !== null &&
    a.scope === b.scope &&
    (a.scope === 'all' || (b.scope === 'organization' && a.organizationId === b.organizationId)));

/** Blocker and high findings of a project, null when it has no measures. */
const severe = (row: PortfolioProjectRow): number | null =>
  row.bySeverity === null ? null : row.bySeverity.blocker + row.bySeverity.high;

/**
 * Portfolio (4E-2 §4, feature `portfolio`): the quality of every project the caller can read, of
 * the header's organisation or of all of them (`?scope=`), with 12-week or 12-month trends
 * (`?granularity=`): totals as cards, trend charts with their tables, the organisations (all
 * scope), the projects that need attention, and every project in a table the server sorts and
 * pages. CSV and PDF are plain download links. Without the feature the page says so and asks the
 * enterprise API nothing.
 */
@Component({
  selector: 'q-portfolio-page',
  imports: [
    DateTimePipe,
    Distribution,
    GateBadge,
    LineChart,
    MeasurePipe,
    Meter,
    PageHeader,
    Rating,
    RouterLink,
  ],
  templateUrl: './portfolio.page.html',
  styleUrl: './portfolio.page.css',
  host: { class: 'bleed' },
})
export class PortfolioPage {
  private readonly api = inject(PortfolioApi);
  private readonly info = inject(SystemInfo);
  private readonly router = inject(Router);
  private readonly org = inject(OrgContext);
  private readonly locale = inject(LOCALE_ID);

  /** `?scope=`: `all`, else the header's organisation (router input binding). */
  readonly scope = input<string>();
  /** `?granularity=`: `month`, else weeks. */
  readonly granularity = input<string>();

  protected readonly scopeKind = computed(() => (this.scope() === 'all' ? 'all' : 'organization'));
  protected readonly period = computed<PortfolioGranularity>(() =>
    this.granularity() === 'month' ? 'month' : 'week',
  );

  protected readonly licensed = computed(() => this.info.features().includes('portfolio'));
  protected readonly infoLoaded = computed(() => this.info.info() !== null);
  /** A failed `GET /system/info`, shown instead of an empty page. */
  protected readonly infoError = computed(() => {
    const err = this.info.error();
    return err === null ? null : problemMessage(err);
  });

  /** What the page asks for; null without the feature or while the organisations load. */
  private readonly request = computed<PortfolioScope | null>(
    () => {
      if (!this.licensed()) return null;
      if (this.scopeKind() === 'all') return { scope: 'all' };
      const organizationId = this.org.currentId();
      return organizationId ? { scope: 'organization', organizationId } : null;
    },
    { equal: sameScope },
  );
  /** The organisation scope after a failed organisations load: an error, not an empty page. */
  private readonly organizationsFailure = computed(() =>
    this.licensed() &&
    this.scopeKind() === 'organization' &&
    this.org.organizations.status() === 'error'
      ? problemMessage(this.org.organizations.error())
      : null,
  );
  /** The organisation scope of a user who sees no organisation: nothing to read. */
  private readonly noOrganization = computed(
    () =>
      this.licensed() &&
      this.scopeKind() === 'organization' &&
      this.org.organizations.status() === 'resolved' &&
      this.org.currentId() === null,
  );

  protected readonly overview = resource({
    params: () => {
      const scope = this.request();
      return scope ? { scope, granularity: this.period() } : undefined;
    },
    loader: ({ params }) => this.api.overview(params.scope, params.granularity),
  });
  protected readonly data = computed(() =>
    this.overview.hasValue() ? this.overview.value() : null,
  );
  protected readonly failure = computed(() => {
    const organizations = this.organizationsFailure();
    if (organizations !== null) return organizations;
    if (this.overview.status() !== 'error') return null;
    const err = this.overview.error();
    if (err instanceof ApiError && err.code === 'PORTFOLIO_TIMEOUT') {
      return $localize`:@@portfolio.timeout:The portfolio took too long to compute; try one organisation.`;
    }
    return problemMessage(err);
  });
  protected readonly empty = computed(
    () => this.noOrganization() || this.data()?.totals.projects === 0,
  );

  /** `attention.exploited` is null without `vuln.priority`: then nothing about KEV shows. */
  protected readonly prioritised = computed(
    () => (this.data()?.attention.exploited ?? null) !== null,
  );
  protected readonly columns = computed(() =>
    this.prioritised() ? COLUMNS : COLUMNS.filter((c) => c.sort !== 'exploited'),
  );
  protected readonly sort = signal<PortfolioSort>('gate');
  protected readonly projects = new KeysetList<
    PortfolioProjectRow,
    { scope: PortfolioScope; sort: PortfolioSort }
  >((params, cursor) => this.api.projects(params.scope, params.sort, cursor));
  /** The scope and sort the projects table holds, so another granularity keeps its pages. */
  private projectsOf: { scope: PortfolioScope; sort: PortfolioSort } | null = null;

  constructor() {
    // The table follows the overview: it loads once the overview answered with projects, again
    // for another scope or sort, and goes with an empty or failed overview.
    effect(() => {
      const scope = this.request();
      const sort = this.sort();
      const state = this.tableState();
      untracked(() => {
        if (scope === null || state === 'none') {
          this.projectsOf = null;
          this.projects.clear();
          return;
        }
        if (state === null) return;
        const held = this.projectsOf;
        if (held && sameScope(held.scope, scope) && held.sort === sort) return;
        this.projectsOf = { scope, sort };
        void this.projects.reset({ scope, sort });
      });
    });
  }

  /**
   * What the projects table does for the overview: goes ('none') with an empty or failed one,
   * loads ('ready') once it answered, and waits (null) while it loads.
   */
  private tableState(): 'none' | 'ready' | null {
    if (this.empty() || this.failure() !== null) return 'none';
    return this.data() ? 'ready' : null;
  }

  protected choose(change: { scope?: 'organization' | 'all'; granularity?: PortfolioGranularity }) {
    void this.router.navigate([], {
      queryParams: {
        scope: change.scope ?? this.scopeKind(),
        granularity: change.granularity ?? this.period(),
      },
    });
  }

  protected sortBy(sort: PortfolioSort): void {
    this.sort.set(sort);
  }

  protected ariaSort(column: (typeof COLUMNS)[number]): 'ascending' | 'descending' | 'none' {
    return this.sort() === column.sort ? column.order : 'none';
  }

  protected exportHref(format: PortfolioFormat): string | null {
    const scope = this.request();
    return scope ? this.api.exportHref(scope, this.period(), format) : null;
  }

  /** A gate pass share (0–1) in percent, or a dash when no project was analyzed. */
  protected share(value: number | null): string {
    return formatMeasure(value === null ? null : value * 100, SHARE, this.locale);
  }

  /** A count in a note, grouped as the measure pipe groups it ("1,234"). */
  private count(value: number | null): string {
    return formatMeasure(value, 'projects', this.locale);
  }

  protected passedNote(passed: number, analyzed: number): string {
    return $localize`:@@portfolio.card.gateNote:${this.count(passed)}:passed: of ${this.count(analyzed)}:analyzed: analyzed projects passed`;
  }

  protected readonly noAnalysisNote = $localize`:@@portfolio.card.gateNone:No project analyzed yet`;

  protected ratingValue(letter: Letter | null): number | null {
    return letter === null ? null : LETTERS.indexOf(letter) + 1;
  }

  protected ratings(counts: PortfolioAggregate['securityRating']): DistributionItem[] {
    return LETTERS.map((l) => ({
      key: l,
      label: l,
      value: counts[l],
      tone: `rating-${l.toLowerCase()}`,
    }));
  }

  protected readonly severities = computed<DistributionItem[]>(() => {
    const counts = this.data()?.totals.bySeverity;
    return SEVERITIES.map((s) => ({
      key: s,
      label: label('severity', s),
      value: counts?.[s] ?? 0,
      tone: s,
    }));
  });

  protected readonly trends = computed(() => {
    const trend = this.data()?.trend ?? [];
    const chart = (
      id: string,
      title: string,
      metric: string,
      value: (p: PortfolioTrendPoint) => number | null,
    ) => ({
      id,
      title,
      metric,
      series: [
        {
          key: id,
          label: title,
          tone: 'accent',
          points: trend.map((p) => ({ date: p.start, value: value(p) })),
        },
      ] satisfies ChartSeries[],
    });
    return [
      chart('gate', $localize`:@@portfolio.trend.gate:Gate pass share`, SHARE, (p) =>
        p.passedShare === null ? null : p.passedShare * 100,
      ),
      chart('coverage', label('metric', 'coverage'), 'coverage', (p) => p.coverage),
      chart('ncloc', label('metric', 'ncloc'), 'ncloc', (p) => p.ncloc),
      chart('issues', $localize`:@@portfolio.trend.issues:Open issues`, 'issues', (p) => p.issues),
      chart(
        'analyses',
        $localize`:@@portfolio.trend.analyses:Analyses`,
        'analyses',
        (p) => p.analyses,
      ),
      chart(
        'triage',
        $localize`:@@portfolio.trend.triage:Triage decisions`,
        'triage',
        (p) => p.triage,
      ),
    ];
  });

  /** The attention lists (4E-2 §1, plan 5 V2), each row with the figure it is listed for. */
  protected readonly attention = computed(() => {
    const lists = this.data()?.attention;
    if (!lists) return [];
    // A project with no measures has no count: a dash, never "0 blocker and high".
    const severeNote = (r: PortfolioProjectRow) => {
      const count = severe(r);
      return count === null
        ? NO_VALUE
        : $localize`:@@portfolio.attention.severe:${this.count(count)}:count: blocker and high`;
    };
    const exploited = lists.exploited;
    return [
      ...(exploited
        ? [
            {
              id: 'exploited',
              title: $localize`:@@portfolio.attention.exploited:Exploited vulnerabilities`,
              rows: exploited.map((row) => ({
                row,
                note: $localize`:@@portfolio.attention.exploitedCount:${this.count(row.exploited)}:count: exploited`,
              })),
            },
          ]
        : []),
      {
        id: 'failingGates',
        title: $localize`:@@portfolio.attention.failingGates:Failing quality gates`,
        rows: lists.failingGates.map((row) => ({ row, note: severeNote(row) })),
      },
      {
        id: 'worstSecurity',
        title: $localize`:@@portfolio.attention.worstSecurity:Worst security ratings`,
        rows: lists.worstSecurity.map((row) => ({
          row,
          note: $localize`:@@portfolio.attention.security:Security rating ${row.securityRating ?? NO_VALUE}:rating:`,
        })),
      },
      {
        id: 'mostSevere',
        title: $localize`:@@portfolio.attention.mostSevere:Most blocker and high issues`,
        rows: lists.mostSevere.map((row) => ({ row, note: severeNote(row) })),
      },
      {
        id: 'abandoned',
        title: $localize`:@@portfolio.attention.abandoned:Not analyzed in 30 days`,
        rows: lists.abandoned.map((row) => ({
          row,
          note: row.lastAnalysisAt
            ? $localize`:@@portfolio.attention.lastAnalysed:Last analyzed ${formatDate(row.lastAnalysisAt, this.locale)}:date:`
            : $localize`:@@portfolio.attention.never:Never analyzed`,
        })),
      },
    ];
  });
}
