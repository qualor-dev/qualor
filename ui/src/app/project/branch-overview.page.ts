import { SlicePipe } from '@angular/common';
import { Component, computed, inject, input, resource } from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { problemMessage } from '../api/errors';
import { LabelPipe } from '../i18n/label.pipe';
import { DateTimePipe } from '../shared/date-time.pipe';
import { GateBadge } from '../shared/gate-badge';
import { MeasurePipe } from '../shared/measure.pipe';
import { TrendChart } from '../shared/trend-chart';
import { branchView, findBranch, mainBranchView } from './branches';
import {
  conditionStatusLabel,
  conditionTone,
  ignoredReasonLabel,
  operatorLabel,
  readGateResult,
} from './gate-result';

/** The trends every overview draws (api.md: at most 20 metrics per history request). */
const TREND_METRICS = ['issues', 'coverage', 'duplicated_lines_density', 'ncloc'];
const NEW_CODE = ['issues', 'coverage', 'duplicated_lines_density', 'lines'];
const OVERALL = [
  'issues',
  'security_rating',
  'reliability_rating',
  'coverage',
  'duplicated_lines_density',
  'ncloc',
];

/**
 * A branch or merge request (brief §2.3): its quality gate with every condition, the new-code and
 * overall measures, and the trends of its analyses. The project overview is this page for the
 * main branch, found through `GET /projects/{id}`. The gate comes from the branch's last succeeded
 * analysis (`lastAnalysisId`), never from the newest one listed, which may be a failed or stale
 * upload. Every resource is read through `hasValue()`: `value()` throws in the error state.
 */
@Component({
  selector: 'q-branch-overview-page',
  imports: [DateTimePipe, GateBadge, LabelPipe, MeasurePipe, RouterLink, SlicePipe, TrendChart],
  templateUrl: './branch-overview.page.html',
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
          params: { path: { id: params }, query: { metrics: TREND_METRICS.join(',') } },
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
  private readonly byMetric = computed(
    () =>
      new Map((this.measures.hasValue() ? this.measures.value() : []).map((m) => [m.metric, m])),
  );
  protected readonly newCode = computed(() =>
    NEW_CODE.map((metric) => ({
      metric,
      key: `new_${metric}`,
      value: this.byMetric().get(metric)?.new ?? null,
    })),
  );
  protected readonly overall = computed(() =>
    OVERALL.map((metric) => ({ metric, value: this.byMetric().get(metric)?.overall ?? null })),
  );
  protected readonly trends = computed(() => {
    const history = this.history.hasValue() ? this.history.value() : [];
    return TREND_METRICS.map((metric) => ({
      metric,
      points: history.find((h) => h.metric === metric)?.points ?? [],
    }));
  });
  /** A failed secondary load: the page still shows what it has, and says what is missing. */
  protected readonly loadError = computed(() => {
    const error = this.analysis.error() ?? this.measures.error() ?? this.history.error();
    return error ? problemMessage(error) : null;
  });

  protected readonly problemMessage = problemMessage;
  protected readonly operatorLabel = operatorLabel;
  protected readonly ignoredReasonLabel = ignoredReasonLabel;
  protected readonly conditionStatusLabel = conditionStatusLabel;
  protected readonly conditionTone = conditionTone;
}
