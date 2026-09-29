import { SlicePipe } from '@angular/common';
import { Component, computed, inject, input, resource, signal } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { problemMessage } from '../api/errors';
import { Delta } from '../charts/delta';
import { Distribution, type DistributionItem } from '../charts/distribution';
import { Lens } from '../charts/lens';
import { LineChart, type ChartSeries } from '../charts/line-chart';
import { Rating } from '../charts/rating';
import { Sparkline } from '../charts/sparkline';
import { LabelPipe } from '../i18n/label.pipe';
import { label } from '../i18n/labels';
import { DateTimePipe } from '../shared/date-time.pipe';
import { GateBadge } from '../shared/gate-badge';
import { MeasurePipe } from '../shared/measure.pipe';
import { branchView, findBranch, mainBranchView } from './branches';
import {
  conditionStatusLabel,
  conditionTone,
  ignoredReasonLabel,
  operatorLabel,
  readGateResult,
} from './gate-result';

const SEVERITIES = ['blocker', 'high', 'medium', 'low', 'info'] as const;
const QUALITIES = ['security', 'reliability', 'maintainability'] as const;
/** The history the overview draws (api.md: at most 20 metrics per history request). */
const HISTORY_METRICS = [
  'issues',
  ...SEVERITIES.map((s) => `${s}_issues`),
  'coverage',
  'duplicated_lines_density',
  'ncloc',
];
const KPI_METRICS = ['coverage', 'issues', 'duplicated_lines_density', 'ncloc'] as const;
export type HistoryView = 'severity' | 'coverage' | 'duplicated_lines_density' | 'ncloc';
const RECENT = 5;
const TOP_RULES = 5;
const SPARK_POINTS = 12;

/**
 * A branch or merge request (brief §2.3, spec §7.1): the quality gate's verdict with every
 * condition, the new code, the overall KPIs with their change since the previous analysis, the
 * history, the open issues by severity and software quality, the recent analyses and where the
 * issues come from. The project overview is this page for the main branch, found through
 * `GET /projects/{id}`. The gate comes from the branch's last succeeded analysis
 * (`lastAnalysisId`), never from the newest one listed, which may be a failed or stale upload; the
 * analyses list only feeds the recent-analyses panel. Every resource is read through `hasValue()`:
 * `value()` throws in the error state.
 */
@Component({
  selector: 'q-branch-overview-page',
  imports: [
    DateTimePipe,
    Delta,
    Distribution,
    GateBadge,
    LabelPipe,
    Lens,
    LineChart,
    MeasurePipe,
    Rating,
    RouterLink,
    SlicePipe,
    Sparkline,
  ],
  templateUrl: './branch-overview.page.html',
  styleUrl: './branch-overview.page.css',
})
export class BranchOverviewPage {
  private readonly api = inject(Api);
  readonly projectId = input.required<string>();
  /** Absent on the project overview: the main branch. */
  readonly branchId = input<string>();

  protected readonly branch = resource({
    params: () => ({ projectId: this.projectId(), branchId: this.branchId() }),
    loader: async ({ params }) =>
      params.branchId
        ? branchView(await findBranch(this.api, params.projectId, params.branchId))
        : mainBranchView(this.api, params.projectId),
  });
  protected readonly current = computed(() =>
    this.branch.hasValue() ? this.branch.value() : null,
  );
  private readonly branchKey = computed(() => this.current()?.id);

  /** The last succeeded analysis; `null` when the branch has none yet. */
  protected readonly analysis = resource({
    params: () => {
      const branch = this.current();
      return branch ? { analysisId: branch.lastAnalysisId } : undefined;
    },
    loader: async ({ params }) =>
      params.analysisId
        ? ok(
            this.api.client.GET('/api/v0/analyses/{id}', {
              params: { path: { id: params.analysisId } },
            }),
          )
        : null,
  });
  protected readonly measures = resource({
    params: () => this.branchKey(),
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/branches/{id}/measures', { params: { path: { id: params } } }),
      ),
  });
  protected readonly history = resource({
    params: () => this.branchKey(),
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/branches/{id}/measures/history', {
          params: { path: { id: params }, query: { metrics: HISTORY_METRICS.join(',') } },
        }),
      ),
  });
  /** The branch's analyses, newest first: the recent-analyses panel only. */
  protected readonly analyses = resource({
    params: () => this.branchKey(),
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/branches/{id}/analyses', {
          params: { path: { id: params }, query: { limit: 20 } },
        }),
      ),
  });
  /** The analyzer and rule facets of the open issues: where the issues come from. */
  protected readonly sources = resource({
    params: () => this.branchKey(),
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/issues', {
          params: {
            query: { branchId: params, status: 'open', facets: 'engine,rule', limit: 1 },
          },
        }),
      ),
  });

  /** The latest analysis, `null` when the branch has none, `undefined` while unknown. */
  protected readonly latest = computed(() =>
    this.analysis.hasValue() ? this.analysis.value() : undefined,
  );
  protected readonly gate = computed(() => readGateResult(this.latest()?.gateResult));
  /** The gate status to explain: the result's own, else the branch's. */
  protected readonly gateStatus = computed(
    () => this.gate()?.status ?? this.current()?.gateStatus ?? null,
  );
  /** The gate's emblem: the lens in the status colour with its mark. */
  protected readonly emblem = computed(() => {
    switch (this.gateStatus()) {
      case 'passed':
        return { tone: 'ok' as const, mark: 'check' as const };
      case 'failed':
        return { tone: 'bad' as const, mark: 'cross' as const };
      case 'error':
        return { tone: 'bad' as const, mark: null };
      default:
        return { tone: 'accent' as const, mark: null };
    }
  });
  private readonly byMetric = computed(
    () =>
      new Map((this.measures.hasValue() ? this.measures.value() : []).map((m) => [m.metric, m])),
  );
  private readonly points = computed(() => {
    const history = this.history.hasValue() ? this.history.value() : [];
    return new Map(history.map((h) => [h.metric, h.points]));
  });

  private overallOf(metric: string): number | null {
    return this.byMetric().get(metric)?.overall ?? null;
  }
  /** The open issues of the branch, in the Open issues panel's head. */
  protected readonly issueTotal = computed(() => this.overallOf('issues'));

  protected readonly newCode = computed(() => ({
    coverage: this.byMetric().get('coverage')?.new ?? null,
    issues: this.byMetric().get('issues')?.new ?? null,
    duplications: this.byMetric().get('duplicated_lines_density')?.new ?? null,
    lines: this.byMetric().get('lines')?.new ?? null,
  }));
  protected readonly kpis = computed(() =>
    KPI_METRICS.map((metric) => {
      const points = this.points().get(metric) ?? [];
      // The previous analysis: the history's second-to-last point.
      const previous = points[points.length - 2];
      return {
        metric,
        value: this.overallOf(metric),
        previous: previous?.value ?? null,
        since: previous?.date ?? null,
        spark: points.slice(-SPARK_POINTS).map((p) => p.value),
      };
    }),
  );
  protected readonly ratings = computed(() => [
    {
      metric: 'security_rating',
      value: this.overallOf('security_rating'),
      label: label('quality', 'security'),
    },
    {
      metric: 'reliability_rating',
      value: this.overallOf('reliability_rating'),
      label: label('quality', 'reliability'),
    },
  ]);
  protected readonly severityItems = computed<DistributionItem[]>(() =>
    SEVERITIES.map((s) => ({
      key: s,
      label: label('severity', s),
      value: this.overallOf(`${s}_issues`) ?? 0,
      tone: s,
    })),
  );
  protected readonly qualityItems = computed<DistributionItem[]>(() =>
    QUALITIES.map((q) => ({
      key: q,
      label: label('quality', q),
      value: this.overallOf(`${q}_issues`) ?? 0,
      tone: 'accent',
    })),
  );

  protected readonly view = signal<HistoryView>('severity');
  protected readonly views: { id: HistoryView; label: string }[] = [
    { id: 'severity', label: $localize`:@@overview.history.severity:Issues by severity` },
    { id: 'coverage', label: label('metric', 'coverage') },
    {
      id: 'duplicated_lines_density',
      label: $localize`:@@overview.history.duplications:Duplications`,
    },
    { id: 'ncloc', label: label('metric', 'ncloc') },
  ];
  protected readonly historySeries = computed<ChartSeries[]>(() => {
    const view = this.view();
    if (view === 'severity') {
      return SEVERITIES.map((s) => ({
        key: s,
        label: label('severity', s),
        tone: s,
        points: this.points().get(`${s}_issues`) ?? [],
      }));
    }
    return [
      {
        key: view,
        label: label('metric', view),
        tone: 'accent',
        points: this.points().get(view) ?? [],
      },
    ];
  });
  protected readonly historyMetric = computed(() =>
    this.view() === 'severity' ? 'issues' : this.view(),
  );

  protected readonly recent = computed(() => {
    const list = this.analyses.hasValue() ? this.analyses.value().items : [];
    const at = (metric: string) =>
      new Map((this.points().get(metric) ?? []).map((p) => [p.analysisId, p.value]));
    const issues = at('issues');
    const coverage = at('coverage');
    const done = list.filter((a) => a.status === 'succeeded');
    return done.slice(0, RECENT).map((a, i) => {
      const older = done[i + 1];
      const count = issues.get(a.id) ?? null;
      const before = older ? (issues.get(older.id) ?? null) : null;
      return {
        id: a.id,
        date: a.analysisDate,
        revision: a.revision,
        gate: a.gateStatus,
        issues: count,
        // A row shows a change only: "No change" on every quiet analysis is noise.
        issuesBefore: before === count ? null : before,
        coverage: coverage.get(a.id) ?? null,
      };
    });
  });
  private readonly facets = computed(() =>
    this.sources.hasValue() ? (this.sources.value().facets ?? {}) : {},
  );
  protected readonly engines = computed<DistributionItem[]>(() =>
    (this.facets().engine ?? []).map((f) => ({
      key: f.value,
      label: f.value,
      value: f.count,
      tone: 'accent',
    })),
  );
  protected readonly topRules = computed(() =>
    [...(this.facets().rule ?? [])].sort((a, b) => b.count - a.count).slice(0, TOP_RULES),
  );

  /**
   * Metric names the template shows; computed here because `templates.test.ts` rejects a string
   * literal inside an interpolation (`{{ 'coverage' | label: 'metric' }}`).
   */
  protected readonly names = {
    issues: label('metric', 'issues'),
    coverage: label('metric', 'coverage'),
    newCoverage: label('metric', 'new_coverage'),
    newIssues: label('metric', 'new_issues'),
    newDuplications: label('metric', 'new_duplicated_lines_density'),
    newLines: label('metric', 'new_lines'),
  };

  /** A failed secondary load: the page still shows what it has, and says what is missing. */
  protected readonly loadError = computed(() => {
    const error = this.analysis.error() ?? this.measures.error() ?? this.history.error();
    return error ? problemMessage(error) : null;
  });
  protected readonly recentError = computed(() => {
    const error = this.analyses.error();
    return error ? problemMessage(error) : null;
  });
  protected readonly sourcesError = computed(() => {
    const error = this.sources.error();
    return error ? problemMessage(error) : null;
  });

  protected readonly problemMessage = problemMessage;
  protected readonly operatorLabel = operatorLabel;
  protected readonly ignoredReasonLabel = ignoredReasonLabel;
  protected readonly conditionStatusLabel = conditionStatusLabel;
  protected readonly conditionTone = conditionTone;
}
