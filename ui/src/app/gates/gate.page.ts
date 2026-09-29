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
import { Router } from '@angular/router';
import { closeModal, openModal } from '../shared/dialog';
import { copyName } from '../shared/names';
import { type Crumb, PageHeader } from '../shared/page-header';
import { Api, done, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ResponseBody } from '../api/types';
import { OrgContext } from '../org/org-context';
import { LabelPipe } from '../i18n/label.pipe';
import { label } from '../i18n/labels';
import { operatorLabel } from '../project/gate-result';
import { keepFocus, rowAt, rowByKey } from '../shared/focus';
import { inputValue } from '../shared/forms';
import { formatMeasure, MeasurePipe } from '../shared/measure.pipe';

type Gate = ResponseBody<'/api/v0/quality-gates/{id}', 'get'>;
type Condition = Gate['conditions'][number];
type Operator = 'gt' | 'lt';
/** A condition's row while its operator or threshold are being changed. */
interface Draft {
  operator: Operator;
  threshold: string;
}
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
 * The number a threshold field holds, or NaN. The fields take text: a number field empties
 * itself at "80." while a decimal is typed (UI redesign, step 6 review). A comma counts as the
 * decimal point, as a phone's keypad offers it in many languages.
 */
export function parseThreshold(text: string): number {
  const t = text.trim().replace(',', '.');
  return /^[+-]?(\d+(\.\d*)?|\.\d+)(e[+-]?\d+)?$/i.test(t) ? Number(t) : NaN;
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
 *
 * Step 6 of the redesign (spec §7.6): the gate on the ink band with its actions (Copy; Rename and
 * Delete for a custom gate; Make default), rename and the delete confirmation in dialogs, each
 * condition's operator and threshold edited in place (`PATCH …/conditions/{condId}`, Save only
 * once changed, a refusal stays in its row), and "Add condition" as the panel's last row.
 */
@Component({
  selector: 'q-gate-page',
  imports: [LabelPipe, MeasurePipe, PageHeader],
  templateUrl: './gate.page.html',
  styleUrl: './gate.page.css',
  host: { class: 'bleed' },
})
export class GatePage {
  private readonly api = inject(Api);
  private readonly router = inject(Router);
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
  protected readonly crumbs: Crumb[] = [
    { label: $localize`:@@gate.crumb:Quality gates`, link: '/gates' },
  ];
  /** Whether the caller manages the gate's organisation's gates (the built-in one included). */
  protected readonly canManage = computed(() => {
    const gate = this.current();
    return !!gate && this.org.canChange('org.gates.manage', gate.organizationId);
  });
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
  private readonly actions = viewChild<ElementRef<HTMLElement>>('actions');
  private readonly renameDialog = viewChild<ElementRef<HTMLDialogElement>>('renameDialog');
  private readonly confirmDialog = viewChild<ElementRef<HTMLDialogElement>>('confirmDialog');
  protected readonly newName = signal('');
  protected readonly renameError = signal<string | null>(null);
  /** Operator and threshold typed into a condition's row, by condition id, until saved. */
  protected readonly drafts = signal<Readonly<Record<string, Draft>>>({});
  /** Why a row's change was refused, shown in that row. */
  protected readonly rowError = signal<{ id: string; message: string } | null>(null);
  protected readonly deleteQuestion = computed(() => {
    const gate = this.current();
    if (!gate) return '';
    return gate.isDefault
      ? $localize`:@@gates.confirmDeleteDefault:Delete the default quality gate "${gate.name}:name:"? The organization is then left without a default gate: every project that uses the default is no longer gated until you make another gate the default.`
      : $localize`:@@gates.confirmDelete:Delete the quality gate "${gate.name}:name:"? Its projects fall back to the default gate.`;
  });

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
        this.drafts.set({});
        this.rowError.set(null);
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

  /** Why `text` is no threshold for `metric` (the server's ranges), or null. */
  private thresholdProblem(metric: string, text: string): string | null {
    const threshold = parseThreshold(text);
    if (!Number.isFinite(threshold)) {
      return $localize`:@@gate.thresholdRequired:Enter a number.`;
    }
    const range = thresholdRange(this.metrics(), metric);
    if (range && (threshold < range.min || threshold > range.max)) {
      return range.max === Number.MAX_SAFE_INTEGER
        ? $localize`:@@gate.thresholdAtLeast:Enter a number of ${range.min}:min: or more.`
        : $localize`:@@gate.thresholdRange:Enter a number from ${range.min}:min: to ${range.max}:max:.`;
    }
    return null;
  }

  /** "%" after a percentage's threshold. */
  protected unit(metric: string): string {
    const key = metric.startsWith('new_') ? metric.slice(4) : metric;
    return this.metrics().find((m) => m.key === key)?.type === 'percent' ? '%' : '';
  }

  protected async add(event: Event): Promise<void> {
    event.preventDefault();
    if (this.busy() || !this.metric()) return;
    const text = this.threshold().trim();
    const threshold = parseThreshold(text);
    const problem = this.thresholdProblem(this.metric(), text);
    if (problem) {
      this.thresholdError.set(problem);
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

  protected draftOperator(condition: Condition): Operator {
    return this.drafts()[condition.id]?.operator ?? condition.operator;
  }

  protected draftThreshold(condition: Condition): string {
    return this.drafts()[condition.id]?.threshold ?? String(condition.threshold);
  }

  /** Whether a row differs from the stored condition, so that Save has something to do. */
  protected changed(condition: Condition): boolean {
    const draft = this.drafts()[condition.id];
    return (
      !!draft &&
      (draft.operator !== condition.operator ||
        draft.threshold.trim() !== String(condition.threshold))
    );
  }

  protected editOperator(condition: Condition, event: Event): void {
    const operator: Operator = inputValue(event) === 'lt' ? 'lt' : 'gt';
    this.setDraft(condition, { operator, threshold: this.draftThreshold(condition) });
  }

  protected editThreshold(condition: Condition, event: Event): void {
    this.setDraft(condition, {
      operator: this.draftOperator(condition),
      threshold: inputValue(event),
    });
  }

  private setDraft(condition: Condition, draft: Draft): void {
    this.drafts.update((all) => ({ ...all, [condition.id]: draft }));
    if (this.rowError()?.id === condition.id) this.rowError.set(null);
  }

  protected saveLabel(condition: Condition): string {
    return $localize`:@@gate.saveLabel:Save the condition on ${label('metric', condition.metric)}:metric:`;
  }

  protected async save(condition: Condition): Promise<void> {
    const draft = this.drafts()[condition.id];
    if (!draft || this.busy()) return;
    const text = draft.threshold.trim();
    const problem = this.thresholdProblem(condition.metric, text);
    if (problem) {
      this.rowError.set({ id: condition.id, message: problem });
      return;
    }
    const gateId = this.gateId();
    const generation = this.generation;
    this.busy.set(true);
    this.rowError.set(null);
    this.announcement.set(null);
    try {
      const saved = await ok(
        this.api.client.PATCH('/api/v0/quality-gates/{id}/conditions/{condId}', {
          params: { path: { id: gateId, condId: condition.id } },
          body: { operator: draft.operator, threshold: parseThreshold(text) },
        }),
      );
      if (generation !== this.generation) return;
      this.gate.update((g) =>
        g ? { ...g, conditions: g.conditions.map((c) => (c.id === saved.id ? saved : c)) } : g,
      );
      this.drafts.update((all) =>
        Object.fromEntries(Object.entries(all).filter(([id]) => id !== condition.id)),
      );
      this.announcement.set(
        $localize`:@@gate.conditionChanged:Condition changed: ${label('metric', saved.metric)}:metric: ${operatorLabel(saved.operator)}:operator: ${formatMeasure(saved.threshold, saved.metric)}:threshold:.`,
      );
      // Save is gone with the change: focus stays in the row, on its threshold.
      keepFocus(this.injector, this.document, () =>
        rowByKey(this.table()?.nativeElement, condition.id)?.querySelector('input'),
      );
    } catch (err) {
      if (generation !== this.generation) return;
      this.rowError.set({
        id: condition.id,
        message: fieldErrors(err)['body.threshold']
          ? $localize`:@@gate.thresholdInvalid:This value is outside what the metric allows (ratings 1–5, percentages 0–100).`
          : problemMessage(err),
      });
    } finally {
      if (generation === this.generation) this.busy.set(false);
    }
  }

  protected async copy(): Promise<void> {
    const gate = this.current();
    if (!gate || this.busy()) return;
    const name = copyName(gate.name, (n) => $localize`:@@gates.copyName:${n}:name: (copy)`);
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      const copy = await ok(
        this.api.client.POST('/api/v0/quality-gates/{id}/copy', {
          params: { path: { id: gate.id } },
          body: { name },
        }),
      );
      await this.router.navigate(['/gates', copy.id]);
    } catch (err) {
      this.error.set(
        fieldErrors(err)['body.name'] !== undefined
          ? $localize`:@@gates.copyNameInvalid:The copy could not be named after this gate. Create a new gate instead.`
          : problemMessage(err),
      );
    } finally {
      this.busy.set(false);
    }
  }

  protected async makeDefault(): Promise<void> {
    const gate = this.current();
    if (!gate) return;
    await this.run(async (current) => {
      await ok(
        this.api.client.POST('/api/v0/quality-gates/{id}/set-default', {
          params: { path: { id: gate.id } },
        }),
      );
      if (!current()) return;
      // Shown before the reload answers, so "Make default" leaves the band on the next render,
      // where keepFocus sees the focus lost and moves it (else it drops to the page later).
      this.gate.update((g) => (g ? { ...g, isDefault: true } : g));
      this.announcement.set(
        $localize`:@@gates.madeDefault:${gate.name}:name: is now the default quality gate.`,
      );
      // "Make default" goes once the gate is the default: focus moves to the first action.
      keepFocus(this.injector, this.document, () =>
        this.actions()?.nativeElement.querySelector('button'),
      );
    });
  }

  protected openRename(): void {
    this.newName.set(this.current()?.name ?? '');
    this.renameError.set(null);
    const dialog = this.renameDialog()?.nativeElement;
    if (dialog) openModal(dialog);
  }

  protected closeRename(): void {
    const dialog = this.renameDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
  }

  protected setNewName(event: Event): void {
    this.newName.set(inputValue(event));
    this.renameError.set(null);
  }

  protected async rename(event: Event): Promise<void> {
    event.preventDefault();
    const name = this.newName().trim();
    const gateId = this.gateId();
    if (!name || this.busy()) return;
    this.busy.set(true);
    this.renameError.set(null);
    this.announcement.set(null);
    try {
      const saved = await ok(
        this.api.client.PATCH('/api/v0/quality-gates/{id}', {
          params: { path: { id: gateId } },
          body: { name },
        }),
      );
      if (gateId !== this.gateId()) return;
      this.gate.update((g) => (g ? { ...g, name: saved.name } : g));
      this.closeRename();
      this.announcement.set($localize`:@@gate.renamed:Renamed to ${saved.name}:name:.`);
    } catch (err) {
      this.renameError.set(
        fieldErrors(err)['body.name'] !== undefined
          ? $localize`:@@gates.nameInvalid:Enter a name of at most 100 characters, without control characters.`
          : problemMessage(err),
      );
    } finally {
      this.busy.set(false);
    }
  }

  protected askDelete(): void {
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog) openModal(dialog);
  }

  protected closeDelete(): void {
    const dialog = this.confirmDialog()?.nativeElement;
    if (dialog) closeModal(dialog);
  }

  protected async confirmDelete(): Promise<void> {
    const gate = this.current();
    if (!gate || this.busy()) return;
    this.closeDelete();
    this.busy.set(true);
    this.error.set(null);
    try {
      await done(
        this.api.client.DELETE('/api/v0/quality-gates/{id}', { params: { path: { id: gate.id } } }),
      );
      await this.router.navigate(['/gates']);
    } catch (err) {
      this.error.set(problemMessage(err));
      keepFocus(this.injector, this.document, () => this.heading()?.nativeElement);
    } finally {
      this.busy.set(false);
    }
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
