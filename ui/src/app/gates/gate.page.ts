import { DOCUMENT } from '@angular/common';
import {
  Component,
  computed,
  effect,
  type ElementRef,
  inject,
  Injector,
  input,
  resource,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ResponseBody } from '../api/types';
import { OrgContext } from '../org/org-context';
import { LabelPipe } from '../i18n/label.pipe';
import { label } from '../i18n/labels';
import { operatorLabel } from '../project/gate-result';
import { keepFocus, rowAt } from '../shared/focus';
import { inputValue } from '../shared/forms';
import { formatMeasure, MeasurePipe } from '../shared/measure.pipe';

type Gate = ResponseBody<'/api/v0/quality-gates/{id}', 'get'>;
type Condition = Gate['conditions'][number];
type Operator = 'gt' | 'lt';
type Catalog = ResponseBody<'/api/v0/metrics', 'get'>;

interface MetricOption {
  key: string;
  label: string;
  /** The operator that fails a gate when the value gets worse. */
  operator: Operator;
}

/** Condition keys from the metric catalog: `coverage` and `new_coverage` for a metric with both scopes. */
export function metricOptions(catalog: Catalog): MetricOption[] {
  return catalog
    .flatMap((m) =>
      m.scopes.map((scope) => {
        const key = scope === 'new' ? `new_${m.key}` : m.key;
        const operator: Operator = m.direction === 'higher_is_better' ? 'lt' : 'gt';
        return { key, label: label('metric', key), operator };
      }),
    )
    .sort((a, b) => a.label.localeCompare(b.label));
}

/**
 * The thresholds the server accepts for a condition key (gates.md §4, ruling G3; server
 * routes/gates.ts `validateCondition`): ratings 1–5, percentages 0–100, anything else from 0.
 * Null for a key the catalog does not name. The server checks again; its 422 is shown too.
 */
export function thresholdRange(catalog: Catalog, key: string): { min: number; max: number } | null {
  const metric =
    catalog.find((m) => m.key === key) ??
    (key.startsWith('new_') ? catalog.find((m) => m.key === key.slice(4)) : undefined);
  if (!metric) return null;
  if (metric.type === 'rating') return { min: 1, max: 5 };
  if (metric.type === 'percent') return { min: 0, max: 100 };
  return { min: 0, max: Number.MAX_SAFE_INTEGER };
}

/**
 * One quality gate and its conditions; org admins edit custom gates (the built-in is read-only).
 *
 * - The route reuses this component when only `:gateId` changes: the form is reset then, and an
 *   answer for the previous gate is ignored.
 * - After a change the result is announced in the live region; the conditions table is patched
 *   in place (then loaded again), and when the Remove button used is gone focus moves to the next
 *   row's, else to the "Conditions" heading. Buttons are never disabled while a change runs (that
 *   would drop the focus); a second press is ignored instead.
 */
@Component({
  selector: 'q-gate-page',
  imports: [LabelPipe, MeasurePipe, RouterLink],
  templateUrl: './gate.page.html',
})
export class GatePage {
  private readonly api = inject(Api);
  private readonly org = inject(OrgContext);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  readonly gateId = input.required<string>();

  protected readonly gate = resource({
    params: () => this.gateId(),
    loader: ({ params }) =>
      ok(this.api.client.GET('/api/v0/quality-gates/{id}', { params: { path: { id: params } } })),
  });
  /** The gate, or null while loading or after an error (`value()` throws in the error state). */
  protected readonly current = computed(() => (this.gate.hasValue() ? this.gate.value() : null));
  protected readonly catalog = resource({
    loader: () => ok(this.api.client.GET('/api/v0/metrics')),
  });
  private readonly metrics = computed<Catalog>(() =>
    this.catalog.hasValue() ? this.catalog.value() : [],
  );
  protected readonly catalogError = computed(() => {
    const error = this.catalog.error();
    return error ? problemMessage(error) : null;
  });
  protected readonly options = computed(() => metricOptions(this.metrics()));
  protected readonly editable = computed(() => {
    const gate = this.current();
    return !!gate && !gate.isBuiltin && this.org.canChange('org.gates.manage', gate.organizationId);
  });

  protected readonly metric = signal('');
  protected readonly operator = signal<Operator>('gt');
  protected readonly threshold = signal('');
  protected readonly error = signal<string | null>(null);
  protected readonly metricError = signal<string | null>(null);
  protected readonly thresholdError = signal<string | null>(null);
  /** The last change's result, for the live region. */
  protected readonly announcement = signal<string | null>(null);
  protected readonly busy = signal(false);
  protected readonly operatorLabel = operatorLabel;
  protected readonly operators: readonly Operator[] = ['gt', 'lt'];
  protected readonly problemMessage = problemMessage;
  protected readonly inputValue = inputValue;
  /** Incremented per gate: an answer for an older one is ignored. */
  private generation = 0;
  private readonly heading = viewChild<ElementRef<HTMLElement>>('conditionsHeading');
  private readonly table = viewChild<ElementRef<HTMLElement>>('table');

  constructor() {
    effect(() => {
      this.gateId();
      untracked(() => {
        this.generation++;
        this.metric.set('');
        this.operator.set('gt');
        this.threshold.set('');
        this.error.set(null);
        this.metricError.set(null);
        this.thresholdError.set(null);
        this.announcement.set(null);
        this.busy.set(false);
      });
    });
  }

  protected chooseMetric(event: Event): void {
    const key = inputValue(event);
    this.metric.set(key);
    this.metricError.set(null);
    this.thresholdError.set(null);
    const option = this.options().find((m) => m.key === key);
    if (option) this.operator.set(option.operator);
  }

  protected chooseOperator(event: Event): void {
    this.operator.set(inputValue(event) === 'lt' ? 'lt' : 'gt');
  }

  protected setThreshold(event: Event): void {
    this.threshold.set(inputValue(event));
    this.thresholdError.set(null);
  }

  protected async add(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy() || !this.metric()) return;
    const text = this.threshold().trim();
    const threshold = Number(text);
    if (text === '' || !Number.isFinite(threshold)) {
      this.thresholdError.set($localize`:@@gate.thresholdRequired:Enter a number.`);
      return;
    }
    const range = thresholdRange(this.metrics(), this.metric());
    if (range && (threshold < range.min || threshold > range.max)) {
      this.thresholdError.set(
        range.max === Number.MAX_SAFE_INTEGER
          ? $localize`:@@gate.thresholdAtLeast:Enter a number of ${range.min}:min: or more.`
          : $localize`:@@gate.thresholdRange:Enter a number from ${range.min}:min: to ${range.max}:max:.`,
      );
      return;
    }
    const gateId = this.gateId();
    const body = { metric: this.metric(), operator: this.operator(), threshold };
    await this.run(async (current) => {
      const created = await ok(
        this.api.client.POST('/api/v0/quality-gates/{id}/conditions', {
          params: { path: { id: gateId } },
          body,
        }),
      );
      if (!current()) return;
      this.gate.update((g) =>
        g
          ? {
              ...g,
              conditions: [...g.conditions, created].sort((a, b) =>
                a.metric.localeCompare(b.metric),
              ),
            }
          : g,
      );
      this.threshold.set('');
      this.announcement.set(
        $localize`:@@gate.conditionAdded:Condition added: ${label('metric', created.metric)}:metric: ${operatorLabel(created.operator)}:operator: ${formatMeasure(created.threshold, created.metric)}:threshold:.`,
      );
    });
  }

  protected async remove(condition: Condition, index: number): Promise<void> {
    const gateId = this.gateId();
    await this.run(async (current) => {
      await done(
        this.api.client.DELETE('/api/v0/quality-gates/{id}/conditions/{condId}', {
          params: { path: { id: gateId, condId: condition.id } },
        }),
      );
      if (!current()) return;
      this.gate.update((g) =>
        g ? { ...g, conditions: g.conditions.filter((c) => c.id !== condition.id) } : g,
      );
      this.announcement.set(
        $localize`:@@gate.conditionRemoved:Condition removed: ${label('metric', condition.metric)}:metric:.`,
      );
      keepFocus(
        this.injector,
        this.document,
        () => rowAt(this.table()?.nativeElement, index)?.querySelector('button'),
        () => this.heading()?.nativeElement,
      );
    });
  }

  private async run(action: (current: () => boolean) => Promise<void>): Promise<void> {
    if (this.busy()) return;
    const generation = this.generation;
    const current = () => generation === this.generation;
    this.busy.set(true);
    this.error.set(null);
    this.metricError.set(null);
    this.thresholdError.set(null);
    this.announcement.set(null);
    try {
      await action(current);
      if (current()) this.gate.reload();
    } catch (err) {
      if (!current()) return;
      const fields = fieldErrors(err);
      if (fields['body.threshold']) {
        this.thresholdError.set(
          $localize`:@@gate.thresholdInvalid:This value is outside what the metric allows (ratings 1–5, percentages 0–100).`,
        );
      } else if (fields['body.metric']) {
        this.metricError.set(
          $localize`:@@gate.metricInvalid:This server does not know this metric. Reload the page and choose another.`,
        );
      } else {
        this.error.set(problemMessage(err));
      }
      keepFocus(this.injector, this.document, () => this.heading()?.nativeElement);
    } finally {
      if (current()) this.busy.set(false);
    }
  }
}
