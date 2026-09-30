import { DOCUMENT } from '@angular/common';
import {
  afterNextRender,
  Component,
  computed,
  DestroyRef,
  effect,
  ElementRef,
  inject,
  Injector,
  resource,
  signal,
  untracked,
  viewChild,
} from '@angular/core';
import { RouterLink } from '@angular/router';
import { Api, ok } from '../api/api';
import { fieldErrors, problemMessage } from '../api/errors';
import type { ItemOf, Organization, RequestBody, ResponseBody } from '../api/types';
import { SessionStore } from '../auth/session';
import { Meter } from '../charts/meter';
import { OrgContext } from '../org/org-context';
import { inputValue, isChecked } from '../shared/forms';
import { llmProblemText } from './ai-text';

type Settings = ResponseBody<'/api/v0/system/llm', 'get'>;
type SettingsBody = RequestBody<'/api/v0/system/llm', 'put'>;
type OrgSettings = Settings['organizations'][string];
type Feature = keyof OrgSettings['features'];
type Kind = '' | 'openai' | 'anthropic';
type Project = ItemOf<'/api/v0/projects'>;
/** A project an organisation may exclude: a listed one, or an excluded id the list did not have. */
interface ExcludableProject {
  id: string;
  name: string | null;
}

/** The form's fields a refusal can point at; each is the input `#ai-<field>`. */
const FIELDS = [
  'kind',
  'url',
  'model',
  'key',
  'timeout',
  'temperature',
  'exclude',
  'budget-explain',
  'budget-triage',
  'budget-fix',
  'budget-tokens',
  'budget-cost',
  'budget-user',
  'price-input',
  'price-output',
  'retention',
] as const;
type Field = (typeof FIELDS)[number];

/** The server's 422 paths (llm.md §16) and the field each one refuses. */
const SERVER_PATHS: [string, Field][] = [
  ['body.provider.kind', 'kind'],
  ['body.provider.baseUrl', 'url'],
  ['body.provider.model', 'model'],
  ['body.provider.apiKey', 'key'],
  ['body.provider.timeoutSeconds', 'timeout'],
  ['body.provider.temperature', 'temperature'],
  ['body.excludePaths', 'exclude'],
  ['body.budgets.explainPerDay', 'budget-explain'],
  ['body.budgets.triagePerDay', 'budget-triage'],
  ['body.budgets.fixPerDay', 'budget-fix'],
  ['body.budgets.tokensPerDay', 'budget-tokens'],
  ['body.budgets.costPerDayUsd', 'budget-cost'],
  ['body.budgets.perUserPerHour', 'budget-user'],
  ['body.pricing.inputUsdPerMTok', 'price-input'],
  ['body.pricing.outputUsdPerMTok', 'price-output'],
  ['body.pricing', 'price-input'],
  ['body.promptRetentionDays', 'retention'],
];

/** llm.md §3.2: at most 100 excluded path globs. */
const MAX_EXCLUDE_PATHS = 100;
/** The organisations an instance admin sees (ruling R11), read page by page up to this bound. */
const ORG_PAGES = 10;
/** The projects offered for exclusion (all of the instance's), read page by page up to this bound. */
const PROJECT_PAGES = 20;

/**
 * The AI assistant (llm.md §3, §18), for instance admins: the one provider of the instance (its
 * kind, address, model and options, and an API key that is write-only: read from its field once
 * at a submission, emptied at once whatever happens next, never kept in the page's state, never
 * shown), each organisation's enablement and features, the excluded paths, the budgets (the fix
 * budget capped at this edition's ceiling, enterprise.md §7.2), prices, prompt storage, and a Test of the saved
 * provider. Refusals and test problems are shown in the page's own words (plan 1F ruling Y3).
 *
 * Step 8 of the redesign (spec §7.8): today's use of the current organisation against its budgets
 * as meters (`GET /organizations/{id}/ai`; a failed read leaves an alert in its panel), then the
 * settings in setting rows, panel by panel; the fields keep their ids.
 */
@Component({
  selector: 'q-ai-settings-page',
  imports: [Meter, RouterLink],
  templateUrl: './ai.page.html',
  styleUrl: './ai.page.css',
})
export class AiSettingsPage {
  private readonly api = inject(Api);
  private readonly injector = inject(Injector);
  private readonly document = inject(DOCUMENT);
  private readonly host = inject<ElementRef<HTMLElement>>(ElementRef);
  private readonly session = inject(SessionStore);
  protected readonly org = inject(OrgContext);
  protected readonly instanceAdmin = computed(() => this.session.user()?.isInstanceAdmin === true);
  /** Today's use and the budgets of the organisation chosen in the header (llm.md §12.1). */
  protected readonly today = resource({
    params: () => (this.instanceAdmin() ? (this.org.currentId() ?? undefined) : undefined),
    loader: ({ params }) =>
      ok(
        this.api.client.GET('/api/v0/organizations/{id}/ai', { params: { path: { id: params } } }),
      ),
  });
  protected readonly todayValue = computed(() =>
    this.today.hasValue() ? this.today.value() : null,
  );
  /** Whether today's token or cost budget is spent: every feature waits then, not only one. */
  protected readonly budgetHold = computed(() => {
    const t = this.todayValue();
    if (!t?.enabled) return false;
    const { tokensPerDay, costPerDayUsd } = t.budgets;
    const cost = t.usage.costUsd;
    return (
      (tokensPerDay !== null && t.usage.tokens >= tokensPerDay) ||
      (costPerDayUsd !== null && cost !== null && cost >= costPerDayUsd)
    );
  });

  protected readonly settings = signal<Settings | null>(null);
  protected readonly organizations = signal<Organization[]>([]);
  /** Each organisation's projects, by organisation id. */
  protected readonly projects = signal<Record<string, Project[]>>({});
  protected readonly loadError = signal<string | null>(null);

  protected readonly kind = signal<Kind>('');
  protected readonly url = signal('');
  protected readonly model = signal('');
  protected readonly auth = signal<'bearer' | 'api-key'>('bearer');
  protected readonly jsonMode = signal<'json_object' | 'none'>('json_object');
  protected readonly maxTokensField = signal<'max_tokens' | 'max_completion_tokens'>('max_tokens');
  protected readonly timeout = signal('60');
  protected readonly temperature = signal('');
  protected readonly removeKey = signal(false);
  protected readonly orgSettings = signal<Record<string, OrgSettings>>({});
  protected readonly exclude = signal('');
  protected readonly budgets = signal<Record<string, string>>({});
  protected readonly priceInput = signal('');
  protected readonly priceOutput = signal('');
  protected readonly storePrompts = signal(false);
  protected readonly retention = signal('7');

  protected readonly errors = signal<Partial<Record<Field, string>>>({});
  protected readonly announcement = signal<string | null>(null);
  protected readonly error = signal<string | null>(null);
  protected readonly busy = signal(false);

  protected readonly maxFixPerDay = computed(() => this.settings()?.maxFixPerDay ?? 25);
  /** The saved fix budget, which may be above the ceiling after a licence lapsed. */
  protected readonly storedFixPerDay = computed(() => this.settings()?.budgets.fixPerDay ?? 0);
  /**
   * The highest fix budget the server takes (enterprise.md §7.2): the ceiling, or the saved budget
   * when that is higher, which may be kept or lowered but not raised.
   */
  protected readonly maxFixAllowed = computed(() =>
    Math.max(this.maxFixPerDay(), this.storedFixPerDay()),
  );
  protected readonly maxTemperature = computed(() => (this.kind() === 'anthropic' ? 1 : 2));
  protected readonly provider = computed(() => this.settings()?.provider ?? null);
  protected readonly enabledCount = computed(
    () => Object.values(this.settings()?.organizations ?? {}).filter((o) => o.enabled).length,
  );
  /** The host the data would go to: the address typed, else the saved one. */
  protected readonly targetHost = computed(() => {
    for (const raw of [this.url(), this.provider()?.baseUrl ?? '']) {
      try {
        return new URL(raw.trim()).host;
      } catch {
        // Not a URL (yet): try the saved one.
      }
    }
    return null;
  });

  private readonly heading = viewChild<ElementRef<HTMLElement>>('heading');
  private readonly keyField = viewChild<ElementRef<HTMLInputElement>>('keyField');

  constructor() {
    effect(() => {
      const admin = this.instanceAdmin();
      untracked(() => {
        if (admin) void this.load();
      });
    });
    // Nothing typed into the key field outlives the page.
    inject(DestroyRef).onDestroy(() => this.emptyKey());
  }

  protected set(field: Field, target: { set(value: string): void }, event: Event): void {
    target.set(inputValue(event));
    this.clearError(field);
  }

  protected setKind(event: Event): void {
    const value = inputValue(event);
    this.kind.set(value === 'openai' || value === 'anthropic' ? value : '');
    this.clearError('kind');
  }

  protected setAuth(event: Event): void {
    this.auth.set(inputValue(event) === 'api-key' ? 'api-key' : 'bearer');
  }

  protected setJsonMode(event: Event): void {
    this.jsonMode.set(inputValue(event) === 'none' ? 'none' : 'json_object');
  }

  protected setMaxTokensField(event: Event): void {
    this.maxTokensField.set(
      inputValue(event) === 'max_completion_tokens' ? 'max_completion_tokens' : 'max_tokens',
    );
  }

  protected setBudget(name: string, field: Field, event: Event): void {
    const value = inputValue(event);
    this.budgets.update((all) => ({ ...all, [name]: value }));
    this.clearError(field);
  }

  protected budget(name: string): string {
    return this.budgets()[name] ?? '';
  }

  protected orgOf(id: string): OrgSettings {
    return (
      this.orgSettings()[id] ?? {
        enabled: false,
        features: { explain: false, triage: false, fix: false },
        excludedProjectIds: [],
      }
    );
  }

  protected setOrgEnabled(id: string, event: Event): void {
    const enabled = isChecked(event);
    this.orgSettings.update((all) => ({ ...all, [id]: { ...this.orgOf(id), enabled } }));
  }

  protected setOrgFeature(id: string, feature: Feature, event: Event): void {
    const on = isChecked(event);
    this.orgSettings.update((all) => {
      const current = this.orgOf(id);
      return { ...all, [id]: { ...current, features: { ...current.features, [feature]: on } } };
    });
  }

  /**
   * The projects an organisation's "Excluded projects" offers: its own, then any excluded id the
   * project list did not include (past the list's bound), so that it too can be removed.
   */
  protected excludable(orgId: string): ExcludableProject[] {
    const listed = this.projects()[orgId] ?? [];
    const known = new Set(listed.map((p) => p.id));
    return [
      ...listed.map((p) => ({ id: p.id, name: p.name })),
      ...this.orgOf(orgId)
        .excludedProjectIds.filter((id) => !known.has(id))
        .map((id) => ({ id, name: null })),
    ];
  }

  protected excludedCount(orgId: string): number {
    return this.orgOf(orgId).excludedProjectIds.length;
  }

  protected isExcluded(orgId: string, projectId: string): boolean {
    return this.orgOf(orgId).excludedProjectIds.includes(projectId);
  }

  protected setExcluded(orgId: string, projectId: string, event: Event): void {
    const excluded = isChecked(event);
    this.orgSettings.update((all) => {
      const current = this.orgOf(orgId);
      const others = current.excludedProjectIds.filter((id) => id !== projectId);
      return {
        ...all,
        [orgId]: { ...current, excludedProjectIds: excluded ? [...others, projectId] : others },
      };
    });
  }

  protected setRemoveKey(event: Event): void {
    this.removeKey.set(isChecked(event));
    this.clearError('key');
  }

  protected setStorePrompts(event: Event): void {
    this.storePrompts.set(isChecked(event));
  }

  protected clearError(field: Field): void {
    if (this.errors()[field] === undefined) return;
    this.errors.update((all) =>
      Object.fromEntries(Object.entries(all).filter(([key]) => key !== field)),
    );
  }

  protected fieldError(field: Field): string | null {
    return this.errors()[field] ?? null;
  }

  protected async save(event: Event): Promise<void> {
    event.preventDefault();
    // The key is read once and its field emptied at once, before any check or request: whatever
    // happens next (an ignored submit, a refusal here, a 422, a network error), it never stays.
    const apiKey = this.keyField()?.nativeElement.value ?? '';
    this.emptyKey();
    if (this.busy() || this.settings() === null) return;
    const errors: Partial<Record<Field, string>> = {};
    const body = this.body(apiKey, errors);
    this.errors.set(errors);
    if (!body) {
      this.focusFirstInvalid();
      return;
    }
    await this.run(
      async () => {
        const saved = await ok(this.api.client.PUT('/api/v0/system/llm', { body }));
        this.fill(saved);
        // Budgets and the organisation's switch may have changed: the meters read them again.
        this.today.reload();
        this.announcement.set(
          $localize`:@@ai.settings.saved:The AI assistant settings were saved.`,
        );
      },
      (err) => {
        const fields = fieldErrors(err);
        const refused: Partial<Record<Field, string>> = {};
        for (const path of Object.keys(fields)) {
          const match = SERVER_PATHS.find(
            ([prefix]) => path === prefix || path.startsWith(`${prefix}.`),
          );
          if (match && refused[match[1]] === undefined) refused[match[1]] = refusal(match[1]);
        }
        if (Object.keys(refused).length === 0) return false;
        this.errors.set(refused);
        this.focusFirstInvalid();
        return true;
      },
    );
  }

  /** llm.md §16: sends a fixed prompt holding no repository data to the saved provider. */
  protected async test(): Promise<void> {
    if (this.busy()) return;
    await this.run(async () => {
      const result = await ok(this.api.client.POST('/api/v0/system/llm/test'));
      // A failed Test is an error (role="alert"), a successful one a status.
      if (result.problem) {
        this.error.set(llmProblemText(result.problem.code, result.problem.providerStatus));
      } else {
        this.announcement.set(
          $localize`:@@ai.settings.testOk:Connected to ${result.model ?? this.provider()?.model ?? ''}:model: in ${result.latencyMs}:latency: ms.`,
        );
      }
    });
  }

  private async load(): Promise<void> {
    this.loadError.set(null);
    try {
      const [settings, organizations, projects] = await Promise.all([
        ok(this.api.client.GET('/api/v0/system/llm')),
        this.allOrganizations(),
        this.allProjects(),
      ]);
      this.organizations.set(organizations);
      const byOrg: Record<string, Project[]> = {};
      for (const project of projects) (byOrg[project.organizationId] ??= []).push(project);
      this.projects.set(byOrg);
      this.fill(settings);
    } catch (err) {
      this.loadError.set(problemMessage(err));
    }
  }

  private async allOrganizations(): Promise<Organization[]> {
    const all: Organization[] = [];
    let cursor: string | null = null;
    for (let i = 0; i < ORG_PAGES; i++) {
      const answer: { items: Organization[]; nextCursor: string | null } = await ok(
        this.api.client.GET('/api/v0/organizations', {
          params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } },
        }),
      );
      all.push(...answer.items);
      if (answer.nextCursor === null || answer.nextCursor === cursor) break;
      cursor = answer.nextCursor;
    }
    return all;
  }

  private async allProjects(): Promise<Project[]> {
    const all: Project[] = [];
    let cursor: string | null = null;
    for (let i = 0; i < PROJECT_PAGES; i++) {
      const answer: { items: Project[]; nextCursor: string | null } = await ok(
        this.api.client.GET('/api/v0/projects', {
          params: { query: { limit: 100, ...(cursor ? { cursor } : {}) } },
        }),
      );
      all.push(...answer.items);
      if (answer.nextCursor === null || answer.nextCursor === cursor) break;
      cursor = answer.nextCursor;
    }
    return all;
  }

  /** Puts saved settings into the form (never a key: the server has none to give). */
  private fill(settings: Settings): void {
    this.settings.set(settings);
    const p = settings.provider;
    this.kind.set(p?.kind ?? '');
    this.url.set(p?.baseUrl ?? '');
    this.model.set(p?.model ?? '');
    this.auth.set(p?.auth ?? 'bearer');
    this.jsonMode.set(p?.jsonMode ?? 'json_object');
    this.maxTokensField.set(p?.maxTokensField ?? 'max_tokens');
    this.timeout.set(String(p?.timeoutSeconds ?? 60));
    this.temperature.set(p?.temperature === null || p === null ? '' : String(p.temperature));
    this.removeKey.set(false);
    this.orgSettings.set(structuredClone(settings.organizations));
    this.exclude.set(settings.excludePaths.join('\n'));
    const b = settings.budgets;
    this.budgets.set({
      explainPerDay: String(b.explainPerDay),
      triagePerDay: String(b.triagePerDay),
      fixPerDay: String(b.fixPerDay),
      tokensPerDay: String(b.tokensPerDay),
      costPerDayUsd: b.costPerDayUsd === null ? '' : String(b.costPerDayUsd),
      perUserPerHour: String(b.perUserPerHour),
    });
    this.priceInput.set(settings.pricing ? String(settings.pricing.inputUsdPerMTok) : '');
    this.priceOutput.set(settings.pricing ? String(settings.pricing.outputUsdPerMTok) : '');
    this.storePrompts.set(settings.storePrompts);
    this.retention.set(String(settings.promptRetentionDays));
    this.errors.set({});
  }

  /** The whole `PUT` body from the form, or null with `errors` filled. */
  private body(apiKey: string, errors: Partial<Record<Field, string>>): SettingsBody | null {
    const refuse = (field: Field) => {
      errors[field] ??= refusal(field);
      return 0;
    };
    const int = (field: Field, raw: string, min: number, max: number): number => {
      const value = raw.trim();
      if (!/^\d{1,10}$/.test(value)) return refuse(field);
      const n = Number(value);
      return n >= min && n <= max ? n : refuse(field);
    };
    const decimal = (field: Field, raw: string, min: number, max: number): number => {
      const value = raw.trim();
      const n = value === '' ? Number.NaN : Number(value);
      return Number.isFinite(n) && n >= min && n <= max ? n : refuse(field);
    };

    let provider: SettingsBody['provider'] = null;
    const kind = this.kind();
    // A key typed with no provider would be dropped silently: refuse it instead.
    if (kind === '' && apiKey !== '') errors.key = keyWithoutKind();
    if (kind !== '') {
      const baseUrl = this.url().trim();
      const model = this.model().trim();
      if (baseUrl === '') refuse('url');
      if (!/^[A-Za-z0-9._:/@+-]{1,200}$/.test(model)) refuse('model');
      if (apiKey !== '' && this.removeKey()) errors.key = keyAndRemove();
      else if (apiKey !== '' && !/^[\x21-\x7e]{1,4096}$/.test(apiKey)) errors.key = keyFormat();
      const temperature =
        this.temperature().trim() === ''
          ? null
          : decimal('temperature', this.temperature(), 0, this.maxTemperature());
      provider = {
        kind,
        baseUrl,
        model,
        ...(kind === 'openai'
          ? { auth: this.auth(), jsonMode: this.jsonMode(), maxTokensField: this.maxTokensField() }
          : {}),
        temperature,
        timeoutSeconds: int('timeout', this.timeout(), 5, 600),
        ...(apiKey !== '' ? { apiKey } : this.removeKey() ? { apiKey: null } : {}),
      };
    }

    const excludePaths = this.exclude()
      .split('\n')
      .map((line) => line.trim())
      .filter((line) => line !== '');
    if (excludePaths.length > MAX_EXCLUDE_PATHS) refuse('exclude');

    const costRaw = this.budget('costPerDayUsd').trim();
    const budgets = {
      explainPerDay: int('budget-explain', this.budget('explainPerDay'), 0, 100_000),
      triagePerDay: int('budget-triage', this.budget('triagePerDay'), 0, 100_000),
      fixPerDay: int('budget-fix', this.budget('fixPerDay'), 0, this.maxFixAllowed()),
      tokensPerDay: int('budget-tokens', this.budget('tokensPerDay'), 0, 1_000_000_000),
      costPerDayUsd: costRaw === '' ? null : decimal('budget-cost', costRaw, 0, 1_000_000),
      perUserPerHour: int('budget-user', this.budget('perUserPerHour'), 1, 10_000),
    };

    const inputPrice = this.priceInput().trim();
    const outputPrice = this.priceOutput().trim();
    const pricing =
      inputPrice === '' && outputPrice === ''
        ? null
        : {
            inputUsdPerMTok: decimal('price-input', inputPrice, 0, 10_000),
            outputUsdPerMTok: decimal('price-output', outputPrice, 0, 10_000),
          };

    const body: SettingsBody = {
      provider,
      organizations: this.orgSettings(),
      excludePaths,
      budgets,
      pricing,
      storePrompts: this.storePrompts(),
      promptRetentionDays: int('retention', this.retention(), 1, 90),
    };
    return Object.keys(errors).length === 0 ? body : null;
  }

  private emptyKey(): void {
    const field = this.keyField()?.nativeElement;
    if (field) field.value = '';
  }

  private focusFirstInvalid(): void {
    const errors = this.errors();
    const first = FIELDS.find((field) => errors[field] !== undefined);
    if (!first) return;
    // After the render that marks it invalid (and, for the key, shows its error text).
    afterNextRender(
      () => this.host.nativeElement.querySelector<HTMLElement>(`#ai-${first}`)?.focus(),
      { injector: this.injector },
    );
  }

  /**
   * Runs one request; while one runs, the buttons stay enabled (and focusable) but do nothing. A
   * refused field goes to its field; anything else to the page's alert.
   */
  private async run(action: () => Promise<void>, field?: (err: unknown) => boolean): Promise<void> {
    this.busy.set(true);
    this.error.set(null);
    this.announcement.set(null);
    try {
      await action();
    } catch (err) {
      if (field?.(err)) return;
      this.error.set(problemMessage(err));
      const active = this.document.activeElement;
      if (active === null || active === this.document.body) this.heading()?.nativeElement.focus();
    } finally {
      this.busy.set(false);
    }
  }
}

/** The page's own words for a refused field (the server's text is never shown). */
function refusal(field: Field): string {
  switch (field) {
    case 'kind':
      return $localize`:@@ai.settings.badKind:Choose OpenAI-compatible or Anthropic.`;
    case 'url':
      return $localize`:@@ai.settings.badUrl:Use the provider's http(s) address, such as https://api.openai.com/v1. An internal host must be listed, with its port, by the operator in QUALOR_LLM_INTERNAL_HOSTS.`;
    case 'model':
      return $localize`:@@ai.settings.badModel:Use the model's name as the provider spells it: letters, digits and . _ : / @ + - only.`;
    case 'key':
      return $localize`:@@ai.settings.keyForNewUrl:Enter the API key again for a new address, or check Remove the key. The key is 1 to 4096 printable characters without spaces.`;
    case 'timeout':
      return $localize`:@@ai.settings.badTimeout:Use a whole number of seconds from 5 to 600.`;
    case 'temperature':
      return $localize`:@@ai.settings.badTemperature:Use a number from 0 to 2 (Anthropic: 0 to 1), or leave it empty.`;
    case 'exclude':
      return $localize`:@@ai.settings.badExclude:Use at most 100 globs, one per line, relative to the repository root.`;
    case 'budget-explain':
    case 'budget-triage':
    case 'budget-tokens':
      return $localize`:@@ai.settings.badBudget:Use a whole number, 0 or more.`;
    case 'budget-fix':
      return $localize`:@@ai.settings.badFixBudget:Use a whole number from 0 to this edition's ceiling. A saved budget above it can be kept or lowered, not raised.`;
    case 'budget-user':
      return $localize`:@@ai.settings.badUserBudget:Use a whole number, 1 or more.`;
    case 'budget-cost':
      return $localize`:@@ai.settings.badCost:Use an amount in US dollars, or leave it empty for no cost budget.`;
    case 'price-input':
    case 'price-output':
      return $localize`:@@ai.settings.badPrice:Give both prices, in US dollars per million tokens (0 to 10000), or neither.`;
    case 'retention':
      return $localize`:@@ai.settings.badRetention:Use a whole number of days from 1 to 90.`;
  }
}

function keyWithoutKind(): string {
  return $localize`:@@ai.settings.keyWithoutKind:Choose a provider kind before typing an API key; with None no key is kept.`;
}

function keyFormat(): string {
  return $localize`:@@ai.settings.keyFormat:This is not an API key: a key is 1 to 4096 printable characters without spaces.`;
}

function keyAndRemove(): string {
  return $localize`:@@ai.settings.keyAndRemove:Type a new API key or check Remove the key, not both.`;
}
