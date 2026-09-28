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

function setup(settings: object = EMPTY): FakeServer {
  const server = new FakeServer();
  server.on('GET', '/api/v0/system/llm', { body: settings });
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
        problem: { code: 'PROVIDER_REJECTED_REQUEST', message: 'server text' },
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

  it('asks nothing of the server for a user who is not an instance admin', async () => {
    const server = setup(CONFIGURED);
    TestBed.inject(SessionStore).set(me());
    const { root } = await render();
    expect(root.textContent).toContain('Only instance administrators configure the AI assistant.');
    expect(server.requestsTo('GET', '/api/v0/system/llm')).toHaveLength(0);
  });
});
