import {
  Component,
  computed,
  inject,
  input,
  linkedSignal,
  output,
  resource,
  signal,
} from '@angular/core';
import { Api, ok } from '../../api/api';
import { fieldErrors, problemMessage } from '../../api/errors';
import { RouterLink } from '@angular/router';
import { inputValue } from '../../shared/forms';
import { formatDate } from '../../shared/date-time.pipe';
import type { ProjectDto } from '../current-project';
import {
  definitionFromForm,
  DEFAULT_DAYS,
  formFromDefinition,
  sameDefinition,
  type NewCodeChoice,
  type NewCodeForm,
} from './new-code';

/** How many recent analyses the select offers. */
const ANALYSES_SHOWN = 20;
const ANALYSIS_PATH = 'body.newCodeDefinition.analysisId';
const DAYS_PATH = 'body.newCodeDefinition.value';

interface AnalysisOption {
  id: string;
  label: string;
}

/**
 * Project → Settings → New code (spec §3.1): which analysis the main branch's new code is
 * measured from. Four radio cards (the default, the last N days, since the previous version, from
 * a specific analysis), the current baseline below them for whoever may analyse, and its own Save.
 * It tells the page with `saved` when the project changed.
 */
@Component({
  selector: 'q-new-code-panel',
  imports: [RouterLink],
  templateUrl: './new-code-panel.html',
  styleUrl: './new-code-panel.css',
})
export class NewCodePanel {
  private readonly api = inject(Api);
  readonly project = input.required<ProjectDto>();
  /** `project.analyze`: the baseline endpoint needs it. */
  readonly canSeeBaseline = input.required<boolean>();
  readonly saved = output();

  /** The form, started again from the project whenever the project is read again. */
  protected readonly form = linkedSignal<NewCodeForm>(() =>
    formFromDefinition(this.project().newCodeDefinition),
  );
  protected readonly busy = signal(false);
  protected readonly error = signal<string | null>(null);
  protected readonly daysError = signal<string | null>(null);
  protected readonly analysisError = signal<string | null>(null);
  protected readonly announcement = signal<string | null>(null);
  /** Counts saves: the baseline is read again after each. */
  private readonly savedCount = signal(0);
  protected readonly defaultDays = DEFAULT_DAYS;

  protected readonly dirty = computed(() => {
    const result = definitionFromForm(this.form());
    return 'error' in result || !sameDefinition(result.value, this.project().newCodeDefinition);
  });

  private readonly analyses = resource({
    params: () => {
      const branchId = this.project().mainBranch?.id;
      return this.form().choice === 'analysis' && branchId ? { branchId } : undefined;
    },
    loader: async ({ params }): Promise<AnalysisOption[]> => {
      const page = await ok(
        this.api.client.GET('/api/v0/branches/{id}/analyses', {
          params: { path: { id: params.branchId }, query: { limit: ANALYSES_SHOWN } },
        }),
      );
      return page.items
        .filter((a) => a.status === 'succeeded')
        .map((a) => ({ id: a.id, label: analysisLabel(a) }));
    },
  });

  /** The options, with the saved analysis kept when it is older than the ones listed. */
  protected readonly analysisOptions = computed<AnalysisOption[]>(() => {
    const listed = this.analyses.hasValue() ? this.analyses.value() : [];
    const chosen = this.form().analysisId;
    return chosen && !listed.some((o) => o.id === chosen)
      ? [
          {
            id: chosen,
            label: $localize`:@@newCode.analysis.other:Analysis ${chosen.slice(0, 7)}:id:`,
          },
          ...listed,
        ]
      : listed;
  });
  protected readonly analysesFailed = computed(() => this.analyses.status() === 'error');

  protected readonly baseline = resource({
    params: () => {
      const p = this.project();
      return this.canSeeBaseline()
        ? { key: p.key, branch: p.mainBranchName, rev: this.savedCount() }
        : undefined;
    },
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/projects/new-code-baseline', {
          params: { query: { projectKey: params.key, branch: params.branch } },
        }),
      ),
  });
  protected readonly baselineView = computed(() => {
    if (!this.baseline.hasValue()) return null;
    const b = this.baseline.value();
    return {
      revision: b.revision ? b.revision.slice(0, 7) : null,
      date: formatDate(b.analysisDate),
      fallback: b.warnings.includes('NEW_CODE_DEFINITION_FALLBACK'),
      missing: b.warnings.includes('NEW_CODE_BASELINE_MISSING'),
    };
  });

  protected choose(choice: NewCodeChoice): void {
    this.edit({ choice });
  }

  protected setDays(event: Event): void {
    this.edit({ days: inputValue(event) });
  }

  protected setAnalysis(event: Event): void {
    this.edit({ analysisId: inputValue(event) });
  }

  private edit(change: Partial<NewCodeForm>): void {
    this.form.update((f) => ({ ...f, ...change }));
    this.announcement.set(null);
    this.error.set(null);
    this.daysError.set(null);
    this.analysisError.set(null);
  }

  protected async save(): Promise<void> {
    if (this.busy() || !this.dirty()) return;
    const result = definitionFromForm(this.form());
    this.error.set(null);
    this.announcement.set(null);
    if ('error' in result) {
      if (result.error === 'days') {
        this.daysError.set(
          $localize`:@@newCode.daysInvalid:Enter a whole number of days from 1 to 3650.`,
        );
      } else {
        this.analysisError.set($localize`:@@newCode.analysisRequired:Choose an analysis.`);
      }
      return;
    }
    this.busy.set(true);
    try {
      await ok(
        this.api.client.PATCH('/api/v0/projects/{id}', {
          params: { path: { id: this.project().id } },
          body: { newCodeDefinition: result.value },
        }),
      );
      this.announcement.set($localize`:@@newCode.saved:New code definition saved.`);
      this.savedCount.update((n) => n + 1);
      this.saved.emit();
    } catch (err) {
      const fields = fieldErrors(err);
      const analysis = fields[ANALYSIS_PATH];
      const days = fields[DAYS_PATH];
      if (analysis !== undefined) this.analysisError.set(analysis);
      if (days !== undefined) this.daysError.set(days);
      if (analysis === undefined && days === undefined) this.error.set(problemMessage(err));
    } finally {
      this.busy.set(false);
    }
  }
}

function analysisLabel(a: { analysisDate: string | null; revision: string | null }): string {
  const revision = a.revision ? a.revision.slice(0, 7) : '—';
  return `${formatDate(a.analysisDate)} · ${revision}`;
}
