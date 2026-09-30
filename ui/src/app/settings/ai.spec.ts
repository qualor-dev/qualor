import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  expectNoPasswordManager,
  FakeServer,
  me,
  ORG_ID,
  page,
  problem,
  provideFakeServer,
  settle,
} from '../../testing/fake-server';
import { SessionStore } from '../auth/session';
import { OrgContext } from '../org/org-context';
import { AiSettingsPage } from './ai.page';

const KEY = ['fake', 'ui', 'key', '0123456789'].join('-');
const EMPTY = {
  provider: null,
  organizations: {},
  excludePaths: [],
  budgets: {
    explainPerDay: 200,
    triagePerDay: 100,
    fixPerDay: 25,
    tokensPerDay: 1_000_000,
    costPerDayUsd: null,
    perUserPerHour: 30,
  },
  pricing: null,
  storePrompts: false,
  promptRetentionDays: 7,
  maxFixPerDay: 25,
};
const CONFIGURED = {
  ...EMPTY,
  provider: {
    kind: 'openai',
    baseUrl: 'http://ollama:11434/v1',
    model: 'qwen2.5-coder',
    auth: 'bearer',
    jsonMode: 'json_object',
    maxTokensField: 'max_tokens',
    temperature: null,
    timeoutSeconds: 60,
    apiKeySet: true,
    apiKeyReadable: true,
  },
  organizations: {
    [ORG_ID]: {
      enabled: true,
      features: { explain: true, triage: true, fix: false },
      excludedProjectIds: [],
    },
  },
};

const PROJECTS = [
  { id: 'p1', organizationId: ORG_ID, key: 'acme/payments', name: 'Payments' },
  { id: 'p2', organizationId: ORG_ID, key: 'acme/web', name: 'Web' },
  { id: 'p3', organizationId: 'other-org', key: 'other/api', name: 'Other API' },
];

/** The organisation's view of the assistant (`GET /organizations/{id}/ai`): today's use and budgets. */
function orgAi(overrides: { enabled?: boolean; usage?: object; budgets?: object } = {}) {
  return {
    enabled: overrides.enabled ?? true,
    features: { explain: true, triage: true, fix: false },
    provider: { kind: 'openai', host: 'ollama:11434', model: 'qwen2.5-coder' },
    dataSent: ['rule', 'message', 'path', 'language', 'snippet'],
    usage: { explain: 0, triage: 0, fix: 0, tokens: 0, costUsd: null, ...overrides.usage },
    budgets: { ...EMPTY.budgets, ...overrides.budgets },
  };
}

function setup(settings: object = EMPTY): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/system/llm', { body: settings });
  server.on('GET', `/api/v0/organizations/${ORG_ID}/ai`, { body: orgAi({ enabled: false }) });
  server.on('GET', '/api/v0/projects', { body: page(PROJECTS) });
  server.on('GET', '/api/v0/organizations', {
    body: page([{ id: ORG_ID, key: 'default', name: 'Default', createdAt: '', updatedAt: '' }]),
  });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: true }));
  return server;
}
async function render() {
  const fixture = TestBed.createComponent(AiSettingsPage);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement };
}
function type(root: HTMLElement, selector: string, value: string): void {
  const input = root.querySelector<HTMLInputElement | HTMLSelectElement>(selector)!;
  input.value = value;
  input.dispatchEvent(new Event(input.tagName === 'SELECT' ? 'change' : 'input'));
}
function submit(root: HTMLElement): void {
  root.querySelector<HTMLFormElement>('form#ai-settings')!.dispatchEvent(new Event('submit'));
}

describe('AiSettingsPage (llm.md §3, §18)', () => {
  it('says the assistant is off and names what would be sent', async () => {
    setup();
    const { root } = await render();
    expect(root.textContent).toContain('Off: no provider is configured');
    const sent = root.querySelector('#ai-data-sent')!.textContent!;
    for (const field of ['rule', 'message', 'file path', 'language', 'code around the issue'])
      expect(sent).toContain(field);
  });

  it('sends the key once in a password field and never shows it', async () => {
    const server = setup();
    server.on('PUT', '/api/v0/system/llm', { body: CONFIGURED });
    const { fixture, root } = await render();
    expect(root.querySelector<HTMLInputElement>('#ai-key')!.type).toBe('password');
    type(root, '#ai-kind', 'openai');
    type(root, '#ai-url', 'http://ollama:11434/v1');
    type(root, '#ai-model', 'qwen2.5-coder');
    type(root, '#ai-key', KEY);
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')[0]?.body).toMatchObject({
      provider: {
        kind: 'openai',
        baseUrl: 'http://ollama:11434/v1',
        model: 'qwen2.5-coder',
        apiKey: KEY,
      },
    });
    expect(root.querySelector<HTMLInputElement>('#ai-key')!.value).toBe('');
    expect(root.textContent).not.toContain(KEY);
    expect(root.textContent).toContain('An API key is set');
  });

  // OpenAI's current models refuse max_tokens; other OpenAI-compatible servers want it.
  it.each([
    ['https://api.openai.com/v1', 'max_completion_tokens'],
    ['https://acme.openai.azure.com/openai/v1', 'max_completion_tokens'],
    ['http://ollama:11434/v1', 'max_tokens'],
  ])('picks the output limit field for %s', async (url, field) => {
    const server = setup();
    server.on('PUT', '/api/v0/system/llm', { body: CONFIGURED });
    const { fixture, root } = await render();
    type(root, '#ai-kind', 'openai');
    await settle(fixture);
    type(root, '#ai-url', url);
    await settle(fixture);
    expect(root.querySelector<HTMLSelectElement>('#ai-max-tokens-field')!.value).toBe(field);
    type(root, '#ai-model', 'm');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')[0]?.body).toMatchObject({
      provider: { maxTokensField: field },
    });
  });

  it('keeps an output limit field the admin chose, and a saved one while the host stays', async () => {
    setup({
      ...CONFIGURED,
      provider: { ...CONFIGURED.provider, baseUrl: 'https://api.openai.com/v1' },
    });
    const { fixture, root } = await render();
    const field = () => root.querySelector<HTMLSelectElement>('#ai-max-tokens-field')!.value;
    // Saved as max_tokens for an OpenAI URL (an older model): editing the path keeps it.
    type(root, '#ai-url', 'https://api.openai.com/v1/');
    await settle(fixture);
    expect(field()).toBe('max_tokens');
    // Another kind of server, then OpenAI again: the default follows the host.
    type(root, '#ai-url', 'http://vllm:8000/v1');
    await settle(fixture);
    expect(field()).toBe('max_tokens');
    type(root, '#ai-url', 'https://api.openai.com/v1');
    await settle(fixture);
    expect(field()).toBe('max_completion_tokens');
    // Chosen by hand: the host no longer changes it.
    type(root, '#ai-max-tokens-field', 'max_tokens');
    type(root, '#ai-url', 'http://vllm:8000/v1');
    type(root, '#ai-url', 'https://api.openai.com/v1');
    await settle(fixture);
    expect(field()).toBe('max_tokens');
  });

  it('says which models need max_completion_tokens', async () => {
    setup();
    const { fixture, root } = await render();
    type(root, '#ai-kind', 'openai');
    await settle(fixture);
    expect(root.querySelector('#ai-max-tokens-field-hint')!.textContent).toContain(
      "OpenAI's current models need max_completion_tokens",
    );
    expect(root.querySelector('#ai-max-tokens-field')!.getAttribute('aria-describedby')).toBe(
      'ai-max-tokens-field-hint',
    );
  });

  it('keeps the stored key when the field is empty, and maps a refused address to the key field', async () => {
    const server = setup(CONFIGURED);
    server.on('PUT', '/api/v0/system/llm', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.provider.apiKey', message: 'server text' },
      ]),
    });
    const { fixture, root } = await render();
    type(root, '#ai-url', 'http://vllm:8000/v1');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')[0]?.body).not.toHaveProperty(
      'provider.apiKey',
    );
    expect(root.querySelector('#ai-key')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#ai-key-error')?.textContent).toContain(
      'Enter the API key again for a new address',
    );
    expect(root.textContent).not.toContain('server text');
  });

  it("caps the fix budget at this edition's ceiling", async () => {
    setup(CONFIGURED);
    const { root } = await render();
    expect(root.querySelector<HTMLInputElement>('#ai-budget-fix')!.max).toBe('25');
    expect(root.querySelector('#ai-budget-fix-hint')?.textContent?.trim()).toBe(
      'At most 25 a day in this edition',
    );
    expect(root.textContent).not.toContain('community');
  });

  it('names the enterprise ceiling without calling it the community edition', async () => {
    const server = setup({
      ...CONFIGURED,
      budgets: { ...CONFIGURED.budgets, fixPerDay: 500 },
      maxFixPerDay: 100_000,
    });
    server.on('PUT', '/api/v0/system/llm', { body: CONFIGURED });
    const { fixture, root } = await render();
    expect(root.querySelector<HTMLInputElement>('#ai-budget-fix')!.max).toBe('100000');
    expect(root.querySelector('#ai-budget-fix-hint')?.textContent?.trim()).toBe(
      'At most 100000 a day in this edition',
    );
    expect(root.textContent).not.toContain('community');
    type(root, '#ai-budget-fix', '100000');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')[0]?.body).toMatchObject({
      budgets: { fixPerDay: 100_000 },
    });
  });

  it('keeps or lowers a saved fix budget above the ceiling, and refuses only a raise (enterprise.md §7.2)', async () => {
    // After a licence lapse: 60 was saved under the enterprise ceiling, the ceiling is 25 again.
    const lapsed = { ...CONFIGURED, budgets: { ...CONFIGURED.budgets, fixPerDay: 60 } };
    const server = setup(lapsed);
    server.on('PUT', '/api/v0/system/llm', (request) => ({
      body: { ...lapsed, budgets: (request.body as typeof lapsed).budgets },
    }));
    const { fixture, root } = await render();
    expect(root.querySelector<HTMLInputElement>('#ai-budget-fix')!.max).toBe('60');
    expect(root.querySelector('#ai-budget-fix-hint')?.textContent).toContain(
      'At most 25 a day in this edition. The saved 60 can be kept or lowered, not raised',
    );

    // Unchanged: the rest of the form can still be saved.
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')).toHaveLength(1);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')[0]?.body).toMatchObject({
      budgets: { fixPerDay: 60 },
    });

    // A raise is refused before anything is sent.
    type(root, '#ai-budget-fix', '61');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')).toHaveLength(1);
    expect(root.querySelector('#ai-budget-fix')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#ai-budget-fix-error')?.textContent).toContain(
      "Use a whole number from 0 to this edition's ceiling. A saved budget above it can be kept or lowered, not raised.",
    );

    // Lowered, still above the ceiling: accepted.
    type(root, '#ai-budget-fix', '40');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')).toHaveLength(2);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')[1]?.body).toMatchObject({
      budgets: { fixPerDay: 40 },
    });
    expect(root.querySelector<HTMLInputElement>('#ai-budget-fix')!.max).toBe('40');
  });

  it('tests the provider and shows the problem in its own words', async () => {
    const server = setup(CONFIGURED);
    server.on('POST', '/api/v0/system/llm/test', {
      body: {
        ok: false,
        model: null,
        latencyMs: 12,
        problem: { code: 'PROVIDER_REJECTED_REQUEST', message: 'server text', providerStatus: 404 },
      },
    });
    const { fixture, root } = await render();
    [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Test')!.click();
    await settle(fixture);
    // A failed Test is an error, not a success message.
    const alert = root.querySelector('.alert-error[role="alert"]');
    expect(alert?.textContent).toContain(
      'The provider refused the request; check the base URL and the model.',
    );
    expect(root.querySelector('[role="status"]')?.textContent?.trim()).toBe('');
    expect(root.textContent).not.toContain('server text');
  });

  it.each([
    [401, 'The provider refused the API key (HTTP 401).'],
    [
      403,
      'The provider refused the request (HTTP 403): the key lacks access to this model, or the account has no credit.',
    ],
  ])('tells a refused key (HTTP %i) apart by the provider status', async (status, text) => {
    const server = setup(CONFIGURED);
    server.on('POST', '/api/v0/system/llm/test', {
      body: {
        ok: false,
        model: null,
        latencyMs: 12,
        problem: { code: 'PROVIDER_REFUSED_KEY', message: 'server text', providerStatus: status },
      },
    });
    const { fixture, root } = await render();
    [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Test')!.click();
    await settle(fixture);
    expect(root.querySelector('.alert-error[role="alert"]')?.textContent).toContain(text);
  });

  it('shows a successful Test in the status region', async () => {
    const server = setup(CONFIGURED);
    server.on('POST', '/api/v0/system/llm/test', {
      body: { ok: true, model: 'qwen2.5-coder', latencyMs: 12, problem: null },
    });
    const { fixture, root } = await render();
    [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Test')!.click();
    await settle(fixture);
    expect(root.querySelector('[role="status"] .alert-success')?.textContent).toContain(
      'Connected to qwen2.5-coder in 12 ms.',
    );
    expect(root.querySelector('.alert-error')).toBeNull();
  });

  it('counts organisations and excluded projects in the singular and the plural', async () => {
    setup({
      ...CONFIGURED,
      organizations: {
        [ORG_ID]: { ...CONFIGURED.organizations[ORG_ID], excludedProjectIds: ['p1'] },
      },
    });
    const { root } = await render();
    expect(root.textContent).toContain('On for 1 organisation');
    expect(root.textContent).not.toContain('1 organisations');
    expect(root.textContent).toContain('1 project excluded');
  });

  it('edits the excluded projects of an organisation, keeping one it does not list', async () => {
    const server = setup({
      ...CONFIGURED,
      organizations: {
        [ORG_ID]: { ...CONFIGURED.organizations[ORG_ID], excludedProjectIds: ['p1', 'p9'] },
      },
    });
    server.on('PUT', '/api/v0/system/llm', { body: CONFIGURED });
    const { fixture, root } = await render();
    const payments = root.querySelector<HTMLInputElement>(`#ai-org-${ORG_ID}-exclude-p1`)!;
    const web = root.querySelector<HTMLInputElement>(`#ai-org-${ORG_ID}-exclude-p2`)!;
    expect(payments.checked).toBe(true);
    expect(web.checked).toBe(false);
    expect(root.querySelector(`label[for="ai-org-${ORG_ID}-exclude-p2"]`)?.textContent).toContain(
      'Web',
    );
    // Another organisation's project is not offered here.
    expect(root.querySelector(`#ai-org-${ORG_ID}-exclude-p3`)).toBeNull();
    payments.click();
    web.click();
    submit(root);
    await settle(fixture);
    const body = server.requestsTo('PUT', '/api/v0/system/llm')[0]?.body as {
      organizations: Record<string, { excludedProjectIds: string[] }>;
    };
    expect(body.organizations[ORG_ID]?.excludedProjectIds.sort()).toEqual(['p2', 'p9']);
  });

  it('refuses a key typed while the kind is None, and says so', async () => {
    const server = setup();
    const { fixture, root } = await render();
    type(root, '#ai-key', KEY);
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')).toHaveLength(0);
    expect(root.querySelector('#ai-key')?.getAttribute('aria-invalid')).toBe('true');
    expect(root.querySelector('#ai-key-error')?.textContent).toContain(
      'Choose a provider kind before typing an API key',
    );
    expect(root.querySelector<HTMLInputElement>('#ai-key')!.value).toBe('');
  });

  it('refuses a malformed key with a text about its format', async () => {
    const server = setup(CONFIGURED);
    const { fixture, root } = await render();
    type(root, '#ai-key', 'two words');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')).toHaveLength(0);
    const message = root.querySelector('#ai-key-error')?.textContent ?? '';
    expect(message).toContain('1 to 4096 printable characters without spaces');
    expect(message).not.toContain('new address');
  });

  it('separates the sentences of the key hint', async () => {
    setup(CONFIGURED);
    const { root } = await render();
    expect(root.querySelector('#ai-key-hint')?.textContent?.replace(/\s+/g, ' ')).toContain(
      'keep it. Stored encrypted',
    );
  });

  it('enables an organisation and its features', async () => {
    const server = setup(CONFIGURED);
    server.on('PUT', '/api/v0/system/llm', { body: CONFIGURED });
    const { fixture, root } = await render();
    root.querySelector<HTMLInputElement>(`#ai-org-${ORG_ID}-fix`)!.click();
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')[0]?.body).toMatchObject({
      organizations: {
        [ORG_ID]: { enabled: true, features: { explain: true, triage: true, fix: true } },
      },
    });
  });

  it('empties the key field after a refused save too', async () => {
    const server = setup(CONFIGURED);
    server.on('PUT', '/api/v0/system/llm', { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root } = await render();
    type(root, '#ai-key', KEY);
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('PUT', '/api/v0/system/llm')[0]?.body).toMatchObject({
      provider: { apiKey: KEY },
    });
    expect(root.querySelector<HTMLInputElement>('#ai-key')!.value).toBe('');
    expect(root.querySelector<HTMLInputElement>('#ai-key')!.getAttribute('autocomplete')).toBe(
      'new-password',
    );
    expectNoPasswordManager(root.querySelector('#ai-key')!);
    expect(root.querySelector('[role="alert"]')).not.toBeNull();
    expect(root.textContent).not.toContain(KEY);
  });

  it("shows the current organisation's use of today against its budgets, as meters with words", async () => {
    const server = setup(CONFIGURED);
    server.on('GET', `/api/v0/organizations/${ORG_ID}/ai`, {
      body: orgAi({
        usage: { explain: 200, triage: 3, tokens: 1234, costUsd: 0.5 },
        budgets: { costPerDayUsd: 2 },
      }),
    });
    const { root } = await render();
    const today = root.querySelector('#ai-today')!;
    expect(today.querySelector('h3')?.textContent?.trim()).toBe('Today in Default (UTC)');
    const meters = [...today.querySelectorAll('q-meter')].map((m) =>
      m.textContent?.replace(/\s+/g, ' ').trim(),
    );
    expect(meters).toEqual([
      'Explanations 200 of 200 Budget reached for today',
      'Triage suggestions 3 of 100',
      'Fix suggestions 0 of 25',
      'Tokens 1,234 of 1,000,000',
      'Cost $0.50 of $2.00',
    ]);
  });

  it("reads today's use again after a save, so the meters show the saved budgets", async () => {
    const server = setup(CONFIGURED);
    let explainPerDay = 200;
    server.on('GET', `/api/v0/organizations/${ORG_ID}/ai`, () => ({
      body: orgAi({ usage: { explain: 3 }, budgets: { explainPerDay } }),
    }));
    server.on('PUT', '/api/v0/system/llm', () => {
      explainPerDay = 999;
      return { body: { ...CONFIGURED, budgets: { ...CONFIGURED.budgets, explainPerDay } } };
    });
    const { fixture, root } = await render();
    const explain = () =>
      root.querySelector('#ai-today q-meter')?.textContent?.replace(/\s+/g, ' ').trim();
    expect(explain()).toBe('Explanations 3 of 200');
    submit(root);
    await settle(fixture);
    expect(server.requestsTo('GET', `/api/v0/organizations/${ORG_ID}/ai`)).toHaveLength(2);
    expect(explain()).toBe('Explanations 3 of 999');
  });

  it("says when the assistant is off for the organisation, and when today's use cannot be read", async () => {
    const off = setup(CONFIGURED);
    const first = await render();
    expect(first.root.querySelector('#ai-today')?.textContent).toContain(
      'The assistant is off for Default: nothing is sent.',
    );
    expect(first.root.querySelector('#ai-today q-meter')).toBeNull();
    expect(off.requestsTo('GET', `/api/v0/organizations/${ORG_ID}/ai`)).toHaveLength(1);
    TestBed.resetTestingModule();
    const failing = setup(CONFIGURED);
    failing.on('GET', `/api/v0/organizations/${ORG_ID}/ai`, {
      status: 500,
      body: problem(500, 'INTERNAL'),
    });
    const second = await render();
    expect(second.root.querySelector('#ai-today .alert-error')?.textContent).toContain(
      "Today's use could not be read.",
    );
    // The rest of the page renders.
    expect(second.root.querySelector('form#ai-settings')).not.toBeNull();
  });

  it('asks nothing of the server for a user who is not an instance admin', async () => {
    const server = setup(CONFIGURED);
    TestBed.inject(SessionStore).set(me());
    const { root } = await render();
    expect(root.textContent).toContain('Only instance administrators configure the AI assistant.');
    expect(server.requestsTo('GET', '/api/v0/system/llm')).toHaveLength(0);
  });
});

describe('AiSettingsPage: step 11', () => {
  it('says that a reached token or cost budget holds back every feature', async () => {
    const server = setup(CONFIGURED);
    server.on('GET', `/api/v0/organizations/${ORG_ID}/ai`, {
      body: orgAi({ usage: { tokens: 1_000_000 }, budgets: { tokensPerDay: 1_000_000 } }),
    });
    const { root } = await render();
    expect(root.querySelector('#ai-today')?.textContent).toContain(
      'Every feature waits until midnight UTC: the token or cost budget for today is reached.',
    );
  });

  it('says so when there is no organization to show, instead of loading forever', async () => {
    const server = setup(CONFIGURED);
    server.on('GET', '/api/v0/organizations', { body: page([]) });
    const { root } = await render();
    const today = root.querySelector('#ai-today')!;
    expect(today.querySelector('h3')?.textContent?.trim()).toBe('Today (UTC)');
    expect(today.textContent).toContain('There is no organization yet.');
    expect(today.textContent).not.toContain('Loading');
  });

  it('says what is sent once, under its heading', async () => {
    setup(CONFIGURED);
    const { root } = await render();
    const sent = root.querySelector('#ai-data-sent .panel-body p')?.textContent?.trim() ?? '';
    expect(sent.startsWith('The rule, the finding')).toBe(true);
  });
});

describe('AiSettingsPage: final review', () => {
  it('says the organizations could not be loaded, never that there are none', async () => {
    const server = setup(CONFIGURED);
    const { fixture, root } = await render();
    // The header's list fails when read again; the page's own list stays loaded.
    server.on('GET', '/api/v0/organizations', { status: 500, body: problem(500, 'INTERNAL') });
    TestBed.inject(OrgContext).organizations.reload();
    await settle(fixture);
    const today = root.querySelector('#ai-today')!;
    expect(today.textContent).not.toContain('There is no organization yet');
    expect(today.textContent).toContain('The organizations could not be loaded.');
  });

  it('says nothing waits for midnight when a budget of 0 allows none', async () => {
    const server = setup(CONFIGURED);
    server.on('GET', `/api/v0/organizations/${ORG_ID}/ai`, {
      body: orgAi({ usage: { tokens: 0 }, budgets: { tokensPerDay: 0 } }),
    });
    const { root } = await render();
    expect(root.querySelector('#ai-today')?.textContent).not.toContain('midnight');
  });
});
