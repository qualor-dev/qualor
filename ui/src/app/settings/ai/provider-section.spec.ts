import { TestBed } from '@angular/core/testing';
import { provideRouter } from '@angular/router';
import {
  CONFIGURED,
  EMPTY,
  KEY,
  organizationsFixture,
  type TestAnswer,
  testAnswer,
  type,
} from '../../../testing/ai-settings';
import {
  expectNoPasswordManager,
  type FakeReply,
  FakeServer,
  me,
  ORG_ID,
  problem,
  provideFakeServer,
  settle,
} from '../../../testing/fake-server';
import { Api, ok } from '../../api/api';
import type { Organization, ResponseBody } from '../../api/types';
import { SessionStore } from '../../auth/session';
import type { LlmBody } from './llm-body';
import { defaultOutputLimitField } from './provider-draft';
import { ProviderSection, type SaveProvider } from './provider-section';

type LlmSettings = ResponseBody<'/api/v0/system/llm', 'get'>;
type Provider = NonNullable<LlmSettings['provider']>;
type TestModel = TestAnswer['models'][number];
interface PutBody {
  provider: (Record<string, unknown> & { baseUrl: string; apiKey?: string | null }) | null;
  pricing: Record<string, unknown> | null;
}
type Fixture = { whenStable(): Promise<unknown> };

const DEFAULT: Organization = {
  id: ORG_ID,
  key: 'default',
  name: 'Default',
  deleting: false,
  createdAt: '2026-09-01T00:00:00.000Z',
  updatedAt: '2026-09-01T00:00:00.000Z',
};
// Fictional prices, as the server answers them: no cached input price (null, the input price).
const PRICES = { inputUsdPerMTok: 0.3, outputUsdPerMTok: 1.2, cachedInputUsdPerMTok: null };
const STRONG_PRICES = { inputUsdPerMTok: 2, outputUsdPerMTok: 8, cachedInputUsdPerMTok: null };
const FAST_PRICES = { inputUsdPerMTok: 0.1, outputUsdPerMTok: 0.4, cachedInputUsdPerMTok: null };
/** A provider with a model of each tier, and the prices of the three. */
const THREE_MODELS = {
  ...CONFIGURED,
  provider: { ...CONFIGURED.provider, strongModel: 'qwen3-max', fastModel: 'qwen2.5-small' },
  pricing: { ...PRICES, strong: STRONG_PRICES, fast: FAST_PRICES },
};
/** A provider of kind Anthropic, as the server shows it: its temperature is always null. */
const ANTHROPIC = {
  ...CONFIGURED,
  provider: {
    ...CONFIGURED.provider,
    kind: 'anthropic',
    baseUrl: 'https://api.anthropic.com',
    model: 'claude-sonnet-5-5',
  },
};
/** The same, with a cached input price for the standard and the strong model, and none for the fast. */
const CACHED_THREE = {
  ...THREE_MODELS,
  pricing: {
    ...PRICES,
    cachedInputUsdPerMTok: 0.03,
    strong: { ...STRONG_PRICES, cachedInputUsdPerMTok: 0.2 },
    fast: FAST_PRICES,
  },
};
const WORKSPACE = 'wrkspc_01AbCdEf';

/** The settings the server holds: what the section was given, then what each save stored. */
let stored: LlmSettings;

/** What `PUT /system/llm` stores of a body, as `GET` answers it (a changed provider: no Test). */
function storedAfter(body: PutBody): LlmSettings {
  const before = stored.provider;
  let provider: Provider | null = null;
  if (body.provider !== null) {
    const { apiKey, ...given } = body.provider;
    provider = {
      api: 'chat_completions',
      strongModel: null,
      fastModel: null,
      auth: 'bearer',
      jsonMode: 'json_object',
      maxTokensField: 'max_tokens',
      temperature: null,
      workspaceId: null,
      timeoutSeconds: 60,
      contextWindowTokens: null,
      ...given,
      baseUrl: given.baseUrl.replace(/\/+$/, ''),
      apiKeySet: apiKey === undefined ? (before?.apiKeySet ?? false) : apiKey !== null,
      apiKeyReadable: true,
    } as Provider;
  }
  const pricing =
    body.pricing === null
      ? null
      : ({ strong: null, fast: null, ...body.pricing } as LlmSettings['pricing']);
  return { ...stored, provider, pricing, lastTest: null };
}

const OK_ANSWER = testAnswer({
  ok: true,
  model: 'qwen2.5-coder',
  latencyMs: 812,
  toolCalling: 'supported',
  problem: null,
});

function setup(): FakeServer {
  const server = new FakeServer();
  server.on('PUT', '/api/v0/system/llm', (request) => ({
    body: storedAfter(request.body as PutBody),
  }));
  server.on('POST', '/api/v0/system/llm/test', { body: OK_ANSWER });
  TestBed.configureTestingModule({
    providers: [provideRouter([{ path: '**', children: [] }]), provideFakeServer(server)],
  });
  TestBed.inject(SessionStore).set(me({ admin: true }));
  return server;
}

/**
 * The section with the settings given. Its save does what the page does: the stored settings with
 * the section's provider and prices go to the server, whose answer becomes the section's settings.
 */
async function render(
  given: {
    settings?: object;
    organizations?: readonly Organization[];
    saveProvider?: SaveProvider;
  } = {},
) {
  const fixture = TestBed.createComponent(ProviderSection);
  stored = (given.settings ?? CONFIGURED) as LlmSettings;
  const api = TestBed.inject(Api);
  const saveProvider: SaveProvider =
    given.saveProvider ??
    (async (change) => {
      const body = { ...stored, provider: change.provider, pricing: change.pricing } as LlmBody;
      const saved = await ok(api.client.PUT('/api/v0/system/llm', { body }));
      stored = saved;
      fixture.componentRef.setInput('settings', saved);
      return saved;
    });
  let tested = 0;
  fixture.componentInstance.tested.subscribe(() => tested++);
  fixture.componentRef.setInput('settings', stored);
  fixture.componentRef.setInput('organizations', given.organizations ?? [DEFAULT]);
  fixture.componentRef.setInput('saveProvider', saveProvider);
  await settle(fixture);
  return { fixture, root: fixture.nativeElement as HTMLElement, tested: () => tested };
}

const field = (root: HTMLElement, id: string) => root.querySelector<HTMLInputElement>(`#${id}`)!;
const buttonNamed = (root: HTMLElement, name: string) =>
  [...root.querySelectorAll('button')].find((b) => b.textContent?.trim() === name);
/** Presses the button of that name, as the admin does; in `scope` (a dialog) when given. */
async function press(fixture: Fixture, root: HTMLElement, name: string, scope?: string) {
  buttonNamed(scope ? root.querySelector<HTMLElement>(scope)! : root, name)!.click();
  await settle(fixture);
}
const saveAndTest = (fixture: Fixture, root: HTMLElement) => press(fixture, root, 'Save and test');
/** Clicks a radio or a switch. */
async function pick(fixture: Fixture, root: HTMLElement, selector: string): Promise<void> {
  root.querySelector<HTMLInputElement>(selector)!.click();
  await settle(fixture);
}
/** Types into a field and lets the section render. */
async function fill(fixture: Fixture, root: HTMLElement, selector: string, value: string) {
  type(root, selector, value);
  await settle(fixture);
}
/** A change of the timeout, so that a save can be pressed without touching what a test checks. */
const touch = (fixture: Fixture, root: HTMLElement) => fill(fixture, root, '#ai-timeout', '90');
const puts = (server: FakeServer) =>
  server.requestsTo('PUT', '/api/v0/system/llm').map((r) => r.body as PutBody);
const testsRun = (server: FakeServer) => server.requestsTo('POST', '/api/v0/system/llm/test');
const lines = (root: HTMLElement) =>
  [...root.querySelectorAll('#ai-test-models li')].map((li) =>
    li.textContent?.replace(/\s+/g, ' ').trim(),
  );
const tones = (root: HTMLElement) =>
  [...root.querySelectorAll('#ai-test-models li')].map((li) => li.getAttribute('data-tone'));
const priceIds = (root: HTMLElement) =>
  [...root.querySelectorAll('input[id^="ai-price-"]')].map((input) => input.id);
/** The price fields of each row: its input, its output and its cached input (R49). */
const STANDARD_IDS = ['ai-price-input', 'ai-price-output', 'ai-price-cached-input'];
const STRONG_IDS = [
  'ai-price-strong-input',
  'ai-price-strong-output',
  'ai-price-strong-cached-input',
];
const FAST_IDS = ['ai-price-fast-input', 'ai-price-fast-output', 'ai-price-fast-cached-input'];
const labelOf = (root: HTMLElement, id: string) =>
  root.querySelector(`label[for="${id}"]`)?.textContent?.replace(/\s+/g, ' ').trim();
const textOf = (root: HTMLElement, selector: string) =>
  root.querySelector(selector)?.textContent?.replace(/\s+/g, ' ').trim();
const chips = (root: HTMLElement) =>
  [...root.querySelectorAll('#ai-options .fold-values .chip')].map((chip) => ({
    text: chip.textContent?.trim(),
    set: chip.classList.contains('set'),
  }));
/** A model's line of a Test answer of several models. */
const line = (
  tier: TestModel['tier'],
  model: string,
  over: Partial<TestModel> = {},
): TestModel => ({
  tier,
  model,
  ok: true,
  reportedModel: `reported-${model}`,
  latencyMs: 12,
  toolCalling: 'supported',
  problem: null,
  hint: null,
  ...over,
});
/** A Test answer of several models: its own fields are those of the first, the standard model. */
const answer = (standard: TestModel, ...others: TestModel[]): TestAnswer => ({
  ok: standard.ok,
  model: standard.reportedModel,
  latencyMs: standard.latencyMs,
  toolCalling: standard.toolCalling,
  problem: standard.problem,
  hint: standard.hint,
  models: [standard, ...others],
});

describe('ProviderSection: the kind and the address', () => {
  it('shows only the kind until one is chosen, then the fields', async () => {
    setup();
    const { fixture, root } = await render({ settings: EMPTY });
    const group = root.querySelector('[role="radiogroup"]')!;
    expect(textOf(root, `#${group.getAttribute('aria-labelledby')}`)).toBe('Provider');
    expect(
      [...group.querySelectorAll<HTMLInputElement>('input[type="radio"]')].map((r) => [
        r.id,
        r.checked,
      ]),
    ).toEqual([
      ['ai-kind-openai', false],
      ['ai-kind-anthropic', false],
    ]);
    expect(textOf(root, '#ai-kind-openai + .choice-text')).toBe(
      'OpenAI-compatible OpenAI, Azure OpenAI, vLLM, Ollama, LM Studio, LiteLLM',
    );
    expect(textOf(root, '#ai-kind-anthropic + .choice-text')).toBe(
      'Anthropic Claude models at api.anthropic.com',
    );
    // First setup: the way to keep code on the network, and nothing else yet.
    expect(textOf(root, '#ai-local')).toBe(
      'To keep code on your own network, run a local model: A local model with Ollama (guide).',
    );
    expect(root.querySelector('#ai-local a')?.getAttribute('href')).toBe(
      '/docs/ai-assistant#a-local-model-with-ollama',
    );
    for (const id of ['ai-url', 'ai-key', 'ai-model', 'ai-tiers', 'ai-prices', 'ai-options']) {
      expect(root.querySelector(`#${id}`), id).toBeNull();
    }
    expect(root.querySelector('q-section-foot')).toBeNull();

    await pick(fixture, root, '#ai-kind-openai');
    for (const id of ['ai-url', 'ai-key', 'ai-model', 'ai-tiers', 'ai-prices', 'ai-options']) {
      expect(root.querySelector(`#${id}`), id).not.toBeNull();
    }
    expect(field(root, 'ai-url').value).toBe('');
    expect(field(root, 'ai-url').classList).toContain('mono');
    expect(root.querySelector('#ai-workspace-id')).toBeNull();
    expect(root.querySelector('q-section-foot')).not.toBeNull();
    expect(textOf(root, '#ai-url-hint')).toBe(
      'With the version path, such as https://<resource>.openai.azure.com/openai/v1 or http://ollama:11434/v1. A host on your network must be listed by the operator in QUALOR_LLM_INTERNAL_HOSTS.',
    );
  });

  it('fills the Anthropic address into an empty field only', async () => {
    setup();
    const { fixture, root } = await render({ settings: EMPTY });
    await pick(fixture, root, '#ai-kind-anthropic');
    expect(field(root, 'ai-url').value).toBe('https://api.anthropic.com');
    await fill(fixture, root, '#ai-url', 'https://proxy.example/anthropic');
    await pick(fixture, root, '#ai-kind-openai');
    await pick(fixture, root, '#ai-kind-anthropic');
    expect(field(root, 'ai-url').value).toBe('https://proxy.example/anthropic');
  });

  it('says what changing the address does, naming the organizations whose review it pauses', async () => {
    setup();
    const reviewing = {
      ...CONFIGURED,
      organizations: {
        [ORG_ID]: {
          ...CONFIGURED.organizations[ORG_ID],
          reviewStatus: { enabled: true, consentCurrent: true },
        },
      },
    };
    const { root } = await render({ settings: reviewing });
    expect(textOf(root, '#ai-url-note')).toBe(
      'Changing the address needs the API key again, and pauses AI review in Default until an organization admin confirms the new address.',
    );
    expect(field(root, 'ai-url').getAttribute('aria-describedby')).toBe('ai-url-hint ai-url-note');
    TestBed.resetTestingModule();
    setup();
    const quiet = await render();
    expect(textOf(quiet.root, '#ai-url-note')).toBe(
      'Changing the address needs the API key again.',
    );
  });

  it('refuses an address that is not one on its field, and sends nothing', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await fill(fixture, root, '#ai-url', 'ollama');
    await saveAndTest(fixture, root);
    expect(puts(server)).toHaveLength(0);
    expect(field(root, 'ai-url').getAttribute('aria-invalid')).toBe('true');
    expect(textOf(root, '#ai-url-error')).toContain("Use the provider's http(s) address");
    expect(document.activeElement).toBe(field(root, 'ai-url'));
    // The foot names the field, as a link to it.
    expect(textOf(root, '.foot-status')).toBe('1 field needs attention: Base URL');
  });

  it('maps a refused address to its field and names it in the foot', async () => {
    const server = setup();
    server.on('PUT', '/api/v0/system/llm', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.provider.baseUrl', message: 'server text' },
      ]),
    });
    const { fixture, root } = await render();
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(field(root, 'ai-url').getAttribute('aria-invalid')).toBe('true');
    expect(textOf(root, '.foot-status')).toBe('1 field needs attention: Base URL');
    expect(root.textContent).not.toContain('server text');
    expect(testsRun(server)).toHaveLength(0);
  });
});

describe('ProviderSection: the API key', () => {
  it('sends the key once in a password field and never shows it', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: EMPTY });
    await pick(fixture, root, '#ai-kind-openai');
    expect(field(root, 'ai-key').type).toBe('password');
    await fill(fixture, root, '#ai-url', 'http://ollama:11434/v1');
    await fill(fixture, root, '#ai-model', 'qwen2.5-coder');
    await fill(fixture, root, '#ai-key', KEY);
    await saveAndTest(fixture, root);
    expect(puts(server)[0]).toMatchObject({
      provider: {
        kind: 'openai',
        baseUrl: 'http://ollama:11434/v1',
        model: 'qwen2.5-coder',
        apiKey: KEY,
      },
    });
    expect(root.querySelector<HTMLInputElement>('#ai-key')?.value ?? '').toBe('');
    expect(root.textContent).not.toContain(KEY);
    expect(textOf(root, '#ai-key-state')).toContain('An API key is set.');
  });

  it('sends that there is no key for a new local provider saved without one', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: EMPTY });
    await pick(fixture, root, '#ai-kind-openai');
    await fill(fixture, root, '#ai-url', 'http://ollama:11434/v1');
    await fill(fixture, root, '#ai-model', 'qwen2.5-coder');
    await saveAndTest(fixture, root);
    // A new address needs a key or null: none was typed, and none is kept.
    expect(puts(server)[0]?.provider).toHaveProperty('apiKey', null);
  });

  it('sends that there is no key for a new address of a provider without one', async () => {
    const server = setup();
    const { fixture, root } = await render({
      settings: { ...CONFIGURED, provider: { ...CONFIGURED.provider, apiKeySet: false } },
    });
    await fill(fixture, root, '#ai-url', 'http://vllm:8000/v1');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toHaveProperty('apiKey', null);
  });

  it.each([
    ['a stored key', true],
    ['no stored key', false],
  ])(
    'leaves the key out for the same address with %s and nothing typed: a key set meanwhile stays',
    async (_what, apiKeySet) => {
      const server = setup();
      const { fixture, root } = await render({
        settings: { ...CONFIGURED, provider: { ...CONFIGURED.provider, apiKeySet } },
      });
      await touch(fixture, root);
      await saveAndTest(fixture, root);
      expect(puts(server)[0]?.provider).not.toHaveProperty('apiKey');
    },
  );

  it('keeps a pasted key through a refusal on the page, and empties it once the request left (Review Focus 1)', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await press(fixture, root, 'Replace the key');
    await fill(fixture, root, '#ai-key', KEY);
    await fill(fixture, root, '#ai-price-strong-input', 'two');
    await saveAndTest(fixture, root);
    // Refused here: nothing left, and the key is still in its field.
    expect(puts(server)).toHaveLength(0);
    expect(field(root, 'ai-price-strong-input').getAttribute('aria-invalid')).toBe('true');
    expect(field(root, 'ai-key').value).toBe(KEY);

    await fill(fixture, root, '#ai-price-strong-input', '2');
    const key = field(root, 'ai-key');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider?.apiKey).toBe(KEY);
    expect(key.value).toBe('');
    expect(root.textContent).not.toContain(KEY);

    // A refusal by the server empties it as well: the request had left.
    server.on('PUT', '/api/v0/system/llm', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.provider.timeoutSeconds', message: 'server text' },
      ]),
    });
    await press(fixture, root, 'Replace the key');
    await fill(fixture, root, '#ai-key', KEY);
    await saveAndTest(fixture, root);
    expect(puts(server)[1]?.provider?.apiKey).toBe(KEY);
    expect(field(root, 'ai-key').value).toBe('');
    expect(field(root, 'ai-timeout').getAttribute('aria-invalid')).toBe('true');
  });

  it('shows a stored key as a line with Replace and Remove, and asks for it again for a new address', async () => {
    const server = setup();
    const { fixture, root } = await render();
    const state = root.querySelector('#ai-key-state')!;
    expect(state.classList).toContain('state-line');
    expect(state.querySelector('.badge')?.textContent?.trim()).toBe('Set');
    expect(state.querySelector('.badge q-icon')).not.toBeNull();
    expect(textOf(root, '#ai-key-state')).toBe(
      'Set An API key is set. Replace the key Remove the key',
    );
    expect(root.querySelector('#ai-key')).toBeNull();

    // Replace opens the field.
    await press(fixture, root, 'Replace the key');
    expect(field(root, 'ai-key').type).toBe('password');
    expect(textOf(root, '#ai-key-hint')).toBe('Stored encrypted; never shown again.');
    expect(document.activeElement).toBe(field(root, 'ai-key'));

    // Remove says what a save does, and Undo takes it back.
    TestBed.resetTestingModule();
    const removing = setup();
    const second = await render();
    await press(second.fixture, second.root, 'Remove the key');
    expect(textOf(second.root, '#ai-key-removing')).toBe('The key is removed when you save. Undo');
    expect(second.root.querySelector('#ai-key')).toBeNull();
    await press(second.fixture, second.root, 'Undo');
    expect(textOf(second.root, '#ai-key-state')).toContain('An API key is set.');
    await press(second.fixture, second.root, 'Remove the key');
    await saveAndTest(second.fixture, second.root);
    expect(puts(removing)[0]?.provider).toHaveProperty('apiKey', null);
    expect(puts(server)).toHaveLength(0);
  });

  it('asks for the key again once the address differs from the saved one', async () => {
    setup();
    const { fixture, root } = await render();
    // The same address with a trailing slash is no new address.
    await fill(fixture, root, '#ai-url', 'http://ollama:11434/v1/');
    expect(root.querySelector('#ai-key')).toBeNull();
    await fill(fixture, root, '#ai-url', 'http://vllm:8000/v1');
    expect(field(root, 'ai-key').type).toBe('password');
    expect(textOf(root, '#ai-key-hint')).toBe(
      'You changed the address: enter the key again. Qualor sends a key only to the address it was entered for.',
    );
    // A key typed there stays, whatever the address becomes.
    await fill(fixture, root, '#ai-key', KEY);
    await fill(fixture, root, '#ai-url', 'http://ollama:11434/v1');
    expect(field(root, 'ai-key').value).toBe(KEY);
  });

  it('asks for the key again on the page for a new address, and sends nothing without it', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await fill(fixture, root, '#ai-url', 'http://vllm:8000/v1');
    await saveAndTest(fixture, root);
    expect(puts(server)).toHaveLength(0);
    expect(field(root, 'ai-key').getAttribute('aria-invalid')).toBe('true');
    expect(textOf(root, '#ai-key-error')).toContain('Enter the API key again for a new address');
    expect(field(root, 'ai-key').getAttribute('aria-describedby')).toBe('ai-key-error ai-key-hint');
    expect(textOf(root, '.foot-status')).toBe('1 field needs attention: API key');
    expect(document.activeElement).toBe(field(root, 'ai-key'));
    // Remove the key instead: a local model at the new address needs none.
    await press(fixture, root, 'Remove the key');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toMatchObject({
      baseUrl: 'http://vllm:8000/v1',
      apiKey: null,
    });
  });

  it('drops the request for the key once the address is the saved one again', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await fill(fixture, root, '#ai-url', 'http://vllm:8000/v1');
    await saveAndTest(fixture, root);
    // Remove the key is a button: the words say to press it.
    expect(textOf(root, '#ai-key-error')).toBe(
      'Enter the API key again for a new address, or press Remove the key. The key is 1 to 4096 printable characters without spaces.',
    );
    await fill(fixture, root, '#ai-url', 'http://ollama:11434/v1/');
    expect(root.querySelector('#ai-key-error')).toBeNull();
    expect(root.querySelector('#ai-key')).toBeNull();
    expect(textOf(root, '.foot-status')).toBe('No unsaved changes');
    expect(puts(server)).toHaveLength(0);
    // A key typed meanwhile keeps the refusal of its own: it is about the key, not the address.
    await press(fixture, root, 'Replace the key');
    await fill(fixture, root, '#ai-key', 'two words');
    await saveAndTest(fixture, root);
    await fill(fixture, root, '#ai-url', 'http://vllm:8000/v1');
    await fill(fixture, root, '#ai-url', 'http://ollama:11434/v1');
    expect(textOf(root, '#ai-key-error')).toContain('This is not an API key');
  });

  it('maps the server’s refusal of the key to the key field, in the page’s words', async () => {
    const server = setup();
    server.on('PUT', '/api/v0/system/llm', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.provider.apiKey', message: 'server text' },
      ]),
    });
    const { fixture, root } = await render();
    await press(fixture, root, 'Replace the key');
    await fill(fixture, root, '#ai-key', KEY);
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider?.apiKey).toBe(KEY);
    expect(field(root, 'ai-key').value).toBe('');
    expect(field(root, 'ai-key').getAttribute('aria-invalid')).toBe('true');
    expect(textOf(root, '#ai-key-error')).toContain('Enter the API key again for a new address');
    expect(textOf(root, '.foot-status')).toBe('1 field needs attention: API key');
    expect(root.textContent).not.toContain('server text');
  });

  it('refuses a malformed key with a text about its format, and keeps it in its field', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await press(fixture, root, 'Replace the key');
    await fill(fixture, root, '#ai-key', 'two words');
    await saveAndTest(fixture, root);
    expect(puts(server)).toHaveLength(0);
    const message = textOf(root, '#ai-key-error') ?? '';
    expect(message).toContain('1 to 4096 printable characters without spaces');
    expect(message).not.toContain('new address');
    expect(field(root, 'ai-key').value).toBe('two words');
    expect(document.activeElement).toBe(field(root, 'ai-key'));
  });

  it('separates the sentences of the key hint', async () => {
    setup();
    const { fixture, root } = await render({ settings: EMPTY });
    await pick(fixture, root, '#ai-kind-openai');
    expect(textOf(root, '#ai-key-hint')).toBe(
      'No API key. A local model may need none. Stored encrypted; never shown again.',
    );
  });

  it('empties the key field after a failed save too', async () => {
    const server = setup();
    server.on('PUT', '/api/v0/system/llm', { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root } = await render();
    await press(fixture, root, 'Replace the key');
    await fill(fixture, root, '#ai-key', KEY);
    await saveAndTest(fixture, root);
    expect(puts(server)[0]).toMatchObject({ provider: { apiKey: KEY } });
    const key = field(root, 'ai-key');
    expect(key.value).toBe('');
    expectNoPasswordManager(key);
    expect(root.querySelector('.foot-status')?.classList).toContain('bad');
    expect(root.textContent).not.toContain(KEY);
    expect(testsRun(server)).toHaveLength(0);
  });

  it('empties the key field when the section goes', async () => {
    setup();
    const { fixture, root } = await render();
    await press(fixture, root, 'Replace the key');
    await fill(fixture, root, '#ai-key', KEY);
    const key = field(root, 'ai-key');
    fixture.destroy();
    expect(key.value).toBe('');
  });

  it('counts a typed key as an unsaved change without holding it', async () => {
    setup();
    const { fixture, root } = await render();
    const section = fixture.componentInstance;
    expect(section.dirtyLabel).toBe('Provider');
    expect(section.dirty()).toBe(false);
    await press(fixture, root, 'Replace the key');
    expect(section.dirty()).toBe(false);
    await fill(fixture, root, '#ai-key', KEY);
    expect(section.dirty()).toBe(true);
    expect(textOf(root, '.foot-status')).toBe('1 unsaved change');
    await fill(fixture, root, '#ai-key', '');
    expect(section.dirty()).toBe(false);
  });
});

describe('ProviderSection: the workspace ID', () => {
  const rowOf = (root: HTMLElement, id: string) => field(root, id).closest('.setting-row');

  it('is a field of an Anthropic provider only, right after the API key, with its hint', async () => {
    setup();
    const { fixture, root } = await render({ settings: EMPTY });
    await pick(fixture, root, '#ai-kind-openai');
    expect(root.querySelector('#ai-workspace-id')).toBeNull();
    await pick(fixture, root, '#ai-kind-anthropic');
    const input = field(root, 'ai-workspace-id');
    expect(labelOf(root, 'ai-workspace-id')).toBe('Workspace ID');
    expect(textOf(root, '#ai-workspace-id-hint')).toBe(
      'For an organization-wide key that is not scoped to a workspace (wrkspc_…).',
    );
    expect([input.type, input.maxLength, input.value, input.required]).toEqual([
      'text',
      71,
      '',
      false,
    ]);
    expect(input.classList).toContain('mono');
    expect(input.getAttribute('aria-describedby')).toBe('ai-workspace-id-hint');
    expect(rowOf(root, 'ai-key')?.nextElementSibling).toBe(rowOf(root, 'ai-workspace-id'));
    await pick(fixture, root, '#ai-kind-openai');
    expect(root.querySelector('#ai-workspace-id')).toBeNull();
  });

  it('shows the stored workspace ID as it was entered', async () => {
    setup();
    const { root } = await render({
      settings: { ...ANTHROPIC, provider: { ...ANTHROPIC.provider, workspaceId: WORKSPACE } },
    });
    expect(field(root, 'ai-workspace-id').value).toBe(WORKSPACE);
  });

  it('sends it trimmed, and null when the field is empty', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: ANTHROPIC });
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toMatchObject({ kind: 'anthropic', workspaceId: null });
    await fill(fixture, root, '#ai-workspace-id', `  ${WORKSPACE} `);
    await saveAndTest(fixture, root);
    expect(puts(server)[1]?.provider).toMatchObject({ kind: 'anthropic', workspaceId: WORKSPACE });
  });

  it('sends none for another kind, whatever was typed under Anthropic', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: ANTHROPIC });
    await fill(fixture, root, '#ai-workspace-id', WORKSPACE);
    await pick(fixture, root, '#ai-kind-openai');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toMatchObject({ kind: 'openai' });
    expect(puts(server)[0]?.provider).not.toHaveProperty('workspaceId');
  });

  it.each([
    ['without the prefix', '01AbCdEf'],
    ['the prefix alone', 'wrkspc_'],
    ['another prefix', 'workspace_01AbCd'],
    ['with a space in it', 'wrkspc_01 AbCd'],
    ['with a dash in it', 'wrkspc_01-AbCd'],
    ['over 64 characters after the prefix', `wrkspc_${'a'.repeat(65)}`],
  ])(
    'refuses one %s on its own field, in the page’s words, and sends nothing',
    async (_w, value) => {
      const server = setup();
      const { fixture, root } = await render({ settings: ANTHROPIC });
      await fill(fixture, root, '#ai-workspace-id', value);
      await saveAndTest(fixture, root);
      expect(puts(server)).toHaveLength(0);
      const input = field(root, 'ai-workspace-id');
      expect(input.getAttribute('aria-invalid')).toBe('true');
      expect(textOf(root, '#ai-workspace-id-error')).toContain(
        'Use the workspace ID as the console shows it: wrkspc_ and then letters and digits',
      );
      expect(input.getAttribute('aria-describedby')).toBe(
        'ai-workspace-id-error ai-workspace-id-hint',
      );
      expect(document.activeElement).toBe(input);
      await fill(fixture, root, '#ai-workspace-id', WORKSPACE);
      expect(root.querySelector('#ai-workspace-id-error')).toBeNull();
      expect(input.getAttribute('aria-invalid')).toBeNull();
    },
  );

  it('drops its refusal when another kind takes it away', async () => {
    setup();
    const { fixture, root } = await render({ settings: ANTHROPIC });
    await fill(fixture, root, '#ai-workspace-id', 'nope');
    await saveAndTest(fixture, root);
    expect(textOf(root, '.foot-status')).toBe('1 field needs attention: Workspace ID');
    await pick(fixture, root, '#ai-kind-openai');
    // The kind is the one change: the workspace is no OpenAI-compatible setting.
    expect(textOf(root, '.foot-status')).toBe('1 unsaved change');
  });

  it('maps the server’s refusal at body.provider.workspaceId to its field, in the page’s words', async () => {
    const server = setup();
    server.on('PUT', '/api/v0/system/llm', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.provider.workspaceId', message: 'server text' },
      ]),
    });
    const { fixture, root } = await render({ settings: ANTHROPIC });
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(field(root, 'ai-workspace-id').getAttribute('aria-invalid')).toBe('true');
    expect(textOf(root, '#ai-workspace-id-error')).toContain(
      'Use the workspace ID as the console shows it',
    );
    expect(root.textContent).not.toContain('server text');
  });
});

describe('ProviderSection: the models', () => {
  it('puts the tier models under their switch, and a price row beside each model of its own', async () => {
    const server = setup();
    const { fixture, root } = await render();
    const tiers = field(root, 'ai-tiers');
    expect([tiers.type, tiers.getAttribute('role'), tiers.checked]).toEqual([
      'checkbox',
      'switch',
      false,
    ]);
    expect(textOf(root, `#${tiers.getAttribute('aria-labelledby')}`)).toBe(
      'Use a stronger and a faster model for parts of AI review',
    );
    expect(tiers.getAttribute('aria-describedby')).toBe('ai-tiers-help');
    expect(textOf(root, '#ai-tiers-help')).toBe('Off: AI review runs on the model above.');
    expect(root.querySelector('#ai-strong-model')).toBeNull();

    await pick(fixture, root, '#ai-tiers');
    const dep = root.querySelector('.dep#ai-tiers-models')!;
    expect(dep.querySelector('#ai-strong-model')).not.toBeNull();
    expect(dep.querySelector('#ai-fast-model')).not.toBeNull();
    expect(textOf(root, '#ai-tiers-note')).toBe(
      "Each organization's AI review confirmation names these models and the address. Changing, adding or removing one pauses AI review until its admins confirm again.",
    );
    expect(dep.querySelector('#ai-tiers-note')?.classList).toContain('note');
    expect(tiers.getAttribute('aria-describedby')).toBe('ai-tiers-help ai-tiers-note');

    await fill(fixture, root, '#ai-strong-model', 'qwen-strong');
    await fill(fixture, root, '#ai-fast-model', 'qwen2.5-coder');
    await pick(fixture, root, '#ai-prices');
    const rows = [...root.querySelectorAll('.prices tbody tr')].map((tr) => [
      tr.querySelector('th code')?.textContent?.trim(),
      tr.querySelector('th .tier')?.textContent?.trim(),
    ]);
    // No row for a tier set to the standard model: its prices are the standard ones.
    expect(rows).toEqual([
      ['qwen2.5-coder', 'Standard'],
      ['qwen-strong', 'Strong'],
    ]);
    await fill(fixture, root, '#ai-price-input', '0.3');
    await fill(fixture, root, '#ai-price-output', '1.2');
    await fill(fixture, root, '#ai-price-strong-input', '2');
    await fill(fixture, root, '#ai-price-strong-output', '8');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]).toMatchObject({
      provider: { strongModel: 'qwen-strong', fastModel: 'qwen2.5-coder' },
      pricing: { ...PRICES, strong: STRONG_PRICES, fast: null },
    });
  });

  it('has an optional Strong model and an optional Fast model under the switch, with their hints', async () => {
    setup();
    const { root } = await render({ settings: THREE_MODELS });
    expect(field(root, 'ai-tiers').checked).toBe(true);
    expect(labelOf(root, 'ai-strong-model')).toBe('Strong model');
    expect(labelOf(root, 'ai-fast-model')).toBe('Fast model');
    expect(textOf(root, '#ai-strong-model-hint')).toBe(
      "AI review's final check of the findings, and its second look at serious security findings. Empty: the model above.",
    );
    expect(textOf(root, '#ai-fast-model-hint')).toBe(
      'AI review of small changes (10 changed lines or fewer). Empty: the model above.',
    );
    for (const id of ['ai-strong-model', 'ai-fast-model']) {
      const input = field(root, id);
      expect([input.type, input.maxLength, input.required]).toEqual(['text', 200, false]);
      expect(input.classList).toContain('mono');
      expect(input.getAttribute('aria-describedby')).toBe(`${id}-hint`);
      expect(input.getAttribute('aria-invalid')).toBeNull();
    }
    expect(textOf(root, '#ai-model-hint')).toBe(
      'Used for every AI feature unless you choose other models for parts of AI review.',
    );
  });

  it('shows the stored tier models', async () => {
    setup();
    const { root } = await render({ settings: THREE_MODELS });
    expect(field(root, 'ai-model').value).toBe('qwen2.5-coder');
    expect(field(root, 'ai-strong-model').value).toBe('qwen3-max');
    expect(field(root, 'ai-fast-model').value).toBe('qwen2.5-small');
  });

  it('sends an empty tier model as null, and a typed one trimmed', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toMatchObject({ strongModel: null, fastModel: null });
    await pick(fixture, root, '#ai-tiers');
    await fill(fixture, root, '#ai-strong-model', '  qwen3-max ');
    await saveAndTest(fixture, root);
    expect(puts(server)[1]?.provider).toMatchObject({
      model: 'qwen2.5-coder',
      strongModel: 'qwen3-max',
      fastModel: null,
    });
  });

  it('takes a tier model back to null when its field is emptied', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await fill(fixture, root, '#ai-fast-model', '');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toMatchObject({ strongModel: 'qwen3-max', fastModel: null });
  });

  it('brings the tier models back with their switch, and sends both as null while it is off', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await pick(fixture, root, '#ai-tiers');
    expect(root.querySelector('#ai-strong-model')).toBeNull();
    // No tier has a model of its own then: only the standard prices.
    expect(priceIds(root)).toEqual(STANDARD_IDS);
    await pick(fixture, root, '#ai-tiers');
    expect(field(root, 'ai-strong-model').value).toBe('qwen3-max');
    expect(field(root, 'ai-fast-model').value).toBe('qwen2.5-small');
    await pick(fixture, root, '#ai-tiers');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]).toMatchObject({
      provider: { strongModel: null, fastModel: null },
      pricing: { ...PRICES, strong: null, fast: null },
    });
  });

  it.each([['strong'], ['fast']] as const)(
    'refuses a %s model that is not a model name on its own field, and sends nothing',
    async (tier) => {
      const server = setup();
      const { fixture, root } = await render({ settings: THREE_MODELS });
      const id = `ai-${tier}-model`;
      await fill(fixture, root, `#${id}`, 'two words');
      await saveAndTest(fixture, root);
      expect(puts(server)).toHaveLength(0);
      expect(field(root, id).getAttribute('aria-invalid')).toBe('true');
      expect(textOf(root, `#${id}-error`)).toContain(
        "Use the model's name as the provider spells it",
      );
      expect(field(root, id).getAttribute('aria-describedby')).toBe(`${id}-error ${id}-hint`);
      expect(document.activeElement).toBe(field(root, id));
      await fill(fixture, root, `#${id}`, 'qwen3-max');
      expect(root.querySelector(`#${id}-error`)).toBeNull();
      expect(field(root, id).getAttribute('aria-invalid')).toBeNull();
    },
  );

  it.each([
    ['body.provider.model', 'ai-model'],
    ['body.provider.strongModel', 'ai-strong-model'],
    ['body.provider.fastModel', 'ai-fast-model'],
  ])('maps the server’s refusal at %s to its field, in the page’s words', async (path, id) => {
    const server = setup();
    server.on('PUT', '/api/v0/system/llm', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path, message: 'server text' }]),
    });
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(field(root, id).getAttribute('aria-invalid')).toBe('true');
    expect(textOf(root, `#${id}-error`)).toContain(
      "Use the model's name as the provider spells it",
    );
    expect(root.textContent).not.toContain('server text');
    expect(root.querySelector('.foot-status')?.textContent).toContain('1 field needs attention');
  });
});

describe('ProviderSection: the prices', () => {
  it('is a switch, on while prices are stored, with a row named by each model it prices', async () => {
    setup();
    const { fixture, root } = await render();
    const prices = field(root, 'ai-prices');
    expect([prices.getAttribute('role'), prices.checked]).toEqual(['switch', false]);
    expect(textOf(root, `#${prices.getAttribute('aria-labelledby')}`)).toBe(
      "Count costs with these models' prices",
    );
    expect(textOf(root, '#ai-prices-help')).toBe('Off: tokens are counted, costs are not.');
    expect(priceIds(root)).toEqual([]);
    await pick(fixture, root, '#ai-prices');
    expect(textOf(root, '#ai-prices-help')).toBe('US dollars per million tokens.');
    expect(
      [...root.querySelectorAll('.prices thead th')].map((th) => th.textContent?.trim()),
    ).toEqual(['Model', 'Input', 'Output', 'Cached input']);
    expect(priceIds(root)).toEqual(STANDARD_IDS);
  });

  it('shows a price row for a tier only while it has a model of its own', async () => {
    setup();
    const { fixture, root } = await render();
    await pick(fixture, root, '#ai-prices');
    await pick(fixture, root, '#ai-tiers');
    expect(priceIds(root)).toEqual(STANDARD_IDS);
    await fill(fixture, root, '#ai-strong-model', 'qwen3-max');
    expect(priceIds(root)).toEqual([...STANDARD_IDS, ...STRONG_IDS]);
    await fill(fixture, root, '#ai-fast-model', 'qwen2.5-small');
    expect(priceIds(root)).toHaveLength(9);
    // The same model as Model is no model of its own: the standard prices are its prices.
    await fill(fixture, root, '#ai-fast-model', ' qwen2.5-coder ');
    expect(priceIds(root)).toEqual([...STANDARD_IDS, ...STRONG_IDS]);
    await fill(fixture, root, '#ai-strong-model', '');
    await fill(fixture, root, '#ai-model', 'qwen2.5-small');
    await fill(fixture, root, '#ai-fast-model', 'qwen2.5-small');
    expect(priceIds(root)).toEqual(STANDARD_IDS);
  });

  it('names each price after its model and the currency, as money fields', async () => {
    setup();
    const { root } = await render({ settings: THREE_MODELS });
    expect(labelOf(root, 'ai-price-input')).toBe('qwen2.5-coder: input, US$ per million tokens');
    expect(labelOf(root, 'ai-price-output')).toBe('qwen2.5-coder: output, US$ per million tokens');
    expect(labelOf(root, 'ai-price-strong-input')).toBe('qwen3-max: input, US$ per million tokens');
    expect(labelOf(root, 'ai-price-fast-output')).toBe(
      'qwen2.5-small: output, US$ per million tokens',
    );
    expect(priceIds(root)).toEqual([...STANDARD_IDS, ...STRONG_IDS, ...FAST_IDS]);
    for (const id of priceIds(root)) {
      const input = field(root, id);
      expect([input.type, input.getAttribute('inputmode')]).toEqual(['text', 'decimal']);
      expect(input.closest('q-number-field')?.querySelector('.pre')?.textContent).toBe('US$');
    }
  });

  it('shows the stored prices of the tiers', async () => {
    setup();
    const { root } = await render({ settings: THREE_MODELS });
    expect(priceIds(root).map((id) => [id, field(root, id).value])).toEqual([
      ['ai-price-input', '0.30'],
      ['ai-price-output', '1.20'],
      ['ai-price-cached-input', ''],
      ['ai-price-strong-input', '2.00'],
      ['ai-price-strong-output', '8.00'],
      ['ai-price-strong-cached-input', ''],
      ['ai-price-fast-input', '0.10'],
      ['ai-price-fast-output', '0.40'],
      ['ai-price-fast-cached-input', ''],
    ]);
  });

  it('the prices table has a Cached input column, empty for the input price', async () => {
    setup();
    const { fixture, root } = await render();
    await pick(fixture, root, '#ai-prices');
    const cached = field(root, 'ai-price-cached-input');
    expect(cached.value).toBe('');
    expect(labelOf(root, 'ai-price-cached-input')).toBe(
      'qwen2.5-coder: cached input, US$ per million tokens',
    );
    expect(cached.closest('td')?.getAttribute('data-label')).toBe('Cached input');
    expect([cached.type, cached.getAttribute('inputmode')]).toEqual(['text', 'decimal']);
    expect(cached.closest('q-number-field')?.querySelector('.pre')?.textContent).toBe('US$');
    expect(textOf(root, '#ai-prices-cached-help')).toBe(
      'Cached input is what the provider charges for input it read from its cache. Leave it empty to count that input at the input price.',
    );
    expect(cached.getAttribute('aria-describedby')).toBe('ai-prices-cached-help');
  });

  it('shows the stored cached input prices of the tiers, each in its row', async () => {
    setup();
    const { root } = await render({ settings: CACHED_THREE });
    expect(labelOf(root, 'ai-price-strong-cached-input')).toBe(
      'qwen3-max: cached input, US$ per million tokens',
    );
    expect(
      ['ai-price-cached-input', 'ai-price-strong-cached-input', 'ai-price-fast-cached-input'].map(
        (id) => field(root, id).value,
      ),
    ).toEqual(['0.03', '0.20', '']);
  });

  it('saving sends cachedInputUsdPerMTok, null when empty', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await pick(fixture, root, '#ai-prices');
    await fill(fixture, root, '#ai-price-input', '0.3');
    await fill(fixture, root, '#ai-price-output', '1.2');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.pricing).toEqual({ ...PRICES, strong: null, fast: null });
    expect(puts(server)[0]?.pricing).toHaveProperty('cachedInputUsdPerMTok', null);
    await fill(fixture, root, '#ai-price-cached-input', '0.03');
    await saveAndTest(fixture, root);
    expect(puts(server)[1]?.pricing).toEqual({
      ...PRICES,
      cachedInputUsdPerMTok: 0.03,
      strong: null,
      fast: null,
    });
    // Emptied again, it is null: the input price.
    await fill(fixture, root, '#ai-price-cached-input', '');
    await saveAndTest(fixture, root);
    expect(puts(server)[2]?.pricing).toHaveProperty('cachedInputUsdPerMTok', null);
  });

  it("saving sends each tier's own cached input price, and keeps a stored one through a save that does not touch it", async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: CACHED_THREE });
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.pricing).toEqual(CACHED_THREE.pricing);
    await fill(fixture, root, '#ai-price-fast-cached-input', '0.01');
    await fill(fixture, root, '#ai-price-strong-cached-input', '');
    await saveAndTest(fixture, root);
    expect(puts(server)[1]?.pricing).toEqual({
      ...CACHED_THREE.pricing,
      strong: { ...STRONG_PRICES, cachedInputUsdPerMTok: null },
      fast: { ...FAST_PRICES, cachedInputUsdPerMTok: 0.01 },
    });
  });

  it('refuses a cached input price that is not one, on its field, and sends nothing', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: THREE_MODELS });
    for (const bad of ['cheap', '10001', '-1']) {
      await fill(fixture, root, '#ai-price-strong-cached-input', bad);
      await saveAndTest(fixture, root);
      expect(puts(server), bad).toHaveLength(0);
      const input = field(root, 'ai-price-strong-cached-input');
      expect(input.getAttribute('aria-invalid'), bad).toBe('true');
      expect(textOf(root, '#ai-price-strong-cached-input-error')).toBe(
        'Use a price in US dollars per million tokens (0 to 10000), or leave it empty.',
      );
      expect(input.getAttribute('aria-describedby')).toBe(
        'ai-price-strong-cached-input-error ai-prices-cached-help',
      );
      expect(document.activeElement).toBe(input);
    }
    // Only that field: the others are as they were.
    expect(field(root, 'ai-price-strong-input').getAttribute('aria-invalid')).toBeNull();
    await fill(fixture, root, '#ai-price-strong-cached-input', '0.2');
    expect(root.querySelector('#ai-price-strong-cached-input-error')).toBeNull();
  });

  it('a cached input price alone is no price pair: the input and output prices are asked for', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await pick(fixture, root, '#ai-prices');
    await fill(fixture, root, '#ai-price-cached-input', '0.03');
    await saveAndTest(fixture, root);
    expect(puts(server)).toHaveLength(0);
    expect(field(root, 'ai-price-input').getAttribute('aria-invalid')).toBe('true');
    expect(field(root, 'ai-price-cached-input').getAttribute('aria-invalid')).toBeNull();
  });

  it('marks the server’s refusal of a cached input price on its field', async () => {
    const server = setup();
    server.on('PUT', '/api/v0/system/llm', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [
        { path: 'body.pricing.fast.cachedInputUsdPerMTok', message: 'server text' },
      ]),
    });
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(field(root, 'ai-price-fast-cached-input').getAttribute('aria-invalid')).toBe('true');
    expect(field(root, 'ai-price-fast-input').getAttribute('aria-invalid')).toBeNull();
    expect(root.textContent).not.toContain('server text');
  });

  it('takes a price typed with a trailing point as that number', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await pick(fixture, root, '#ai-prices');
    await fill(fixture, root, '#ai-price-input', '5.');
    await fill(fixture, root, '#ai-price-output', '.5');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.pricing).toEqual({
      inputUsdPerMTok: 5,
      outputUsdPerMTok: 0.5,
      cachedInputUsdPerMTok: null,
      strong: null,
      fast: null,
    });
  });

  it('takes a price as the field groups it, and one with more decimals', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await pick(fixture, root, '#ai-prices');
    await fill(fixture, root, '#ai-price-input', '1000');
    field(root, 'ai-price-input').dispatchEvent(new Event('blur'));
    await settle(fixture);
    expect(field(root, 'ai-price-input').value).toBe('1,000.00');
    await fill(fixture, root, '#ai-price-output', '0.075');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.pricing).toEqual({
      inputUsdPerMTok: 1000,
      outputUsdPerMTok: 0.075,
      cachedInputUsdPerMTok: null,
      strong: null,
      fast: null,
    });
  });

  it('sends the prices of the tiers with the standard ones, and none for a tier without a model of its own', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await pick(fixture, root, '#ai-prices');
    await fill(fixture, root, '#ai-price-input', '0.3');
    await fill(fixture, root, '#ai-price-output', '1.2');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.pricing).toEqual({ ...PRICES, strong: null, fast: null });

    await pick(fixture, root, '#ai-tiers');
    await fill(fixture, root, '#ai-strong-model', 'qwen3-max');
    await fill(fixture, root, '#ai-price-strong-input', '2');
    await fill(fixture, root, '#ai-price-strong-output', '8');
    await saveAndTest(fixture, root);
    expect(puts(server)[1]?.pricing).toEqual({ ...PRICES, strong: STRONG_PRICES, fast: null });
  });

  it('sends every pair of three models, and no price of a tier whose model was taken away', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.pricing).toEqual({
      ...PRICES,
      strong: STRONG_PRICES,
      fast: FAST_PRICES,
    });
    await fill(fixture, root, '#ai-fast-model', '');
    await saveAndTest(fixture, root);
    expect(puts(server)[1]?.pricing).toEqual({ ...PRICES, strong: STRONG_PRICES, fast: null });
  });

  it('sends no prices at all when none is given, whatever the models', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: THREE_MODELS });
    for (const id of priceIds(root)) await fill(fixture, root, `#${id}`, '');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]).toMatchObject({ pricing: null });
  });

  it('brings the prices back as they were with their switch, and sends none while it is off', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await pick(fixture, root, '#ai-prices');
    expect(priceIds(root)).toEqual([]);
    await pick(fixture, root, '#ai-prices');
    expect(priceIds(root).map((id) => field(root, id).value)).toEqual([
      '0.30',
      '1.20',
      '',
      '2.00',
      '8.00',
      '',
      '0.10',
      '0.40',
      '',
    ]);
    await pick(fixture, root, '#ai-prices');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]).toMatchObject({ pricing: null });
  });

  it.each([
    ['strong', "Give the strong model's prices too"],
    ['fast', "Give the fast model's prices too"],
  ] as const)(
    'refuses prices given without those of the %s model, on its fields, and sends nothing',
    async (tier, text) => {
      const server = setup();
      const { fixture, root } = await render({ settings: THREE_MODELS });
      await fill(fixture, root, `#ai-price-${tier}-input`, '');
      await fill(fixture, root, `#ai-price-${tier}-output`, '');
      await saveAndTest(fixture, root);
      expect(puts(server)).toHaveLength(0);
      for (const side of ['input', 'output']) {
        const id = `ai-price-${tier}-${side}`;
        expect(field(root, id).getAttribute('aria-invalid')).toBe('true');
        expect(textOf(root, `#${id}-error`)).toContain(text);
        expect(field(root, id).getAttribute('aria-describedby')).toBe(`${id}-error`);
      }
      const other = tier === 'strong' ? 'fast' : 'strong';
      expect(field(root, `ai-price-${other}-input`).getAttribute('aria-invalid')).toBeNull();
      expect(field(root, 'ai-price-input').getAttribute('aria-invalid')).toBeNull();
      expect(document.activeElement).toBe(field(root, `ai-price-${tier}-input`));
      await fill(fixture, root, `#ai-price-${tier}-input`, '1');
      expect(root.querySelector(`#ai-price-${tier}-input-error`)).toBeNull();
    },
  );

  it('refuses a price of a tier outside 0 to 10 000, in the same words', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await fill(fixture, root, '#ai-price-strong-output', '10001');
    await saveAndTest(fixture, root);
    expect(puts(server)).toHaveLength(0);
    expect(textOf(root, '#ai-price-strong-output-error')).toContain(
      'in US dollars per million tokens (0 to 10000)',
    );
  });

  it('asks for the standard prices when only a tier’s are typed', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await fill(fixture, root, '#ai-price-input', '');
    await fill(fixture, root, '#ai-price-output', '');
    await saveAndTest(fixture, root);
    expect(puts(server)).toHaveLength(0);
    expect(field(root, 'ai-price-input').getAttribute('aria-invalid')).toBe('true');
    expect(field(root, 'ai-price-output').getAttribute('aria-invalid')).toBe('true');
    expect(textOf(root, '#ai-price-input-error')).toContain('Give both prices');
    expect(document.activeElement).toBe(field(root, 'ai-price-input'));
  });

  it.each([
    ['body.pricing.strong', 'ai-price-strong-input'],
    ['body.pricing.strong.inputUsdPerMTok', 'ai-price-strong-input'],
    ['body.pricing.strong.outputUsdPerMTok', 'ai-price-strong-output'],
    ['body.pricing.fast', 'ai-price-fast-input'],
    ['body.pricing.fast.inputUsdPerMTok', 'ai-price-fast-input'],
    ['body.pricing.fast.outputUsdPerMTok', 'ai-price-fast-output'],
    ['body.pricing.outputUsdPerMTok', 'ai-price-output'],
    ['body.pricing', 'ai-price-input'],
  ])('maps the server’s refusal at %s to %s', async (path, id) => {
    const server = setup();
    server.on('PUT', '/api/v0/system/llm', {
      status: 422,
      body: problem(422, 'VALIDATION_FAILED', [{ path, message: 'server text' }]),
    });
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(field(root, id).getAttribute('aria-invalid')).toBe('true');
    expect(
      priceIds(root).filter((other) => field(root, other).getAttribute('aria-invalid')),
    ).toEqual([id]);
    expect(root.textContent).not.toContain('server text');
  });
});

describe('ProviderSection: the connection options', () => {
  const openOptions = (root: HTMLElement) => root.querySelector<HTMLDetailsElement>('#ai-options')!;
  const radio = (root: HTMLElement, name: string, value: string) =>
    root.querySelector<HTMLInputElement>(`input[name="${name}"][value="${value}"]`)!;
  const checkedOf = (root: HTMLElement, name: string) =>
    root.querySelector<HTMLInputElement>(`input[name="${name}"]:checked`)?.value;

  it('folds the connection options, lists them while closed, and opens for a Responses hint', async () => {
    const server = setup();
    server.on('POST', '/api/v0/system/llm/test', {
      body: testAnswer({
        ok: true,
        model: 'qwen2.5-coder',
        latencyMs: 12,
        toolCalling: 'not_supported',
        problem: null,
        hint: { code: 'USE_RESPONSES_API', message: 'server text' },
      }),
    });
    const { fixture, root } = await render();
    const fold = openOptions(root);
    expect(fold.tagName).toBe('DETAILS');
    expect(fold.classList).toContain('fold');
    expect(fold.open).toBe(false);
    expect(chips(root)).toEqual([
      { text: 'Chat Completions', set: false },
      { text: 'Authorization: Bearer', set: false },
      { text: 'JSON mode on', set: false },
      { text: 'max_tokens', set: false },
      { text: 'Timeout 60 s', set: false },
      { text: 'Context window 1,000,000 tokens', set: false },
      { text: 'No temperature', set: false },
    ]);
    expect(textOf(root, '#ai-options > summary')).toContain('Connection options');
    await press(fixture, root, 'Test again');
    expect(openOptions(root).open).toBe(true);
    expect(textOf(root, '#ai-test-use-responses')).toBe(
      'This model takes tools only through the Responses API: choose Responses in Connection options.',
    );
  });

  it('marks each value other than the default, and lists only the timeout for Anthropic', async () => {
    setup();
    const { root } = await render({
      settings: {
        ...CONFIGURED,
        provider: {
          ...CONFIGURED.provider,
          api: 'responses',
          auth: 'api-key',
          jsonMode: 'none',
          temperature: 0.7,
          timeoutSeconds: 120,
        },
      },
    });
    expect(chips(root)).toEqual([
      { text: 'Responses', set: true },
      { text: 'api-key (Azure)', set: true },
      { text: 'JSON mode off', set: true },
      { text: 'Timeout 120 s', set: true },
      { text: 'Context window 1,000,000 tokens', set: false },
      { text: 'Temperature 0.7', set: true },
    ]);
    TestBed.resetTestingModule();
    setup();
    const anthropic = await render({ settings: ANTHROPIC });
    expect(chips(anthropic.root)).toEqual([
      { text: 'Timeout 60 s', set: false },
      { text: 'Context window 1,000,000 tokens', set: false },
      { text: 'No temperature', set: false },
    ]);
  });

  it('opens by itself on a refused field inside it', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await fill(fixture, root, '#ai-timeout', '700');
    await saveAndTest(fixture, root);
    expect(puts(server)).toHaveLength(0);
    expect(openOptions(root).open).toBe(true);
    expect(field(root, 'ai-timeout').getAttribute('aria-invalid')).toBe('true');
    expect(textOf(root, '#ai-timeout-error')).toBe('Use a whole number of seconds from 5 to 600.');
    expect(document.activeElement).toBe(field(root, 'ai-timeout'));
  });

  it('has a timeout in seconds, from 5 to 600', async () => {
    const server = setup();
    const { fixture, root } = await render();
    expect(labelOf(root, 'ai-timeout')).toBe('Timeout');
    expect(field(root, 'ai-timeout').value).toBe('60');
    expect(textOf(root, '#ai-timeout-unit')).toBe('seconds');
    expect(textOf(root, '#ai-timeout-hint')).toBe(
      '5 to 600. AI review calls always wait at least 300 seconds.',
    );
    expect(field(root, 'ai-timeout').getAttribute('aria-describedby')).toBe(
      'ai-timeout-hint ai-timeout-unit',
    );
    await fill(fixture, root, '#ai-timeout', '120');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toMatchObject({ timeoutSeconds: 120 });
  });

  it('the Connection options show Context window, empty for 1 000 000', async () => {
    setup();
    const { root } = await render();
    expect(labelOf(root, 'ai-context-window')).toBe('Context window');
    expect(field(root, 'ai-context-window').value).toBe('');
    expect(textOf(root, '#ai-context-window-unit')).toBe('tokens');
    expect(textOf(root, '#ai-context-window-hint')).toBe(
      'The most the model reads in one call, in tokens. Empty means 1,000,000. With several models, give the smallest of their windows.',
    );
    expect(field(root, 'ai-context-window').getAttribute('aria-describedby')).toBe(
      'ai-context-window-hint ai-context-window-unit',
    );
    const ids = [...root.querySelectorAll('#ai-options input[id]')].map((i) => i.id);
    expect(ids.indexOf('ai-context-window')).toBe(ids.indexOf('ai-timeout') + 1);
  });

  it('shows a stored context window', async () => {
    setup();
    const { root } = await render({
      settings: {
        ...CONFIGURED,
        provider: { ...CONFIGURED.provider, contextWindowTokens: 32_000 },
      },
    });
    expect(field(root, 'ai-context-window').value).toBe('32,000');
  });

  it('lists a set context window among the chips while the fold is closed', async () => {
    setup();
    const { root } = await render({
      settings: {
        ...CONFIGURED,
        provider: { ...CONFIGURED.provider, contextWindowTokens: 32_000 },
      },
    });
    expect(openOptions(root).open).toBe(false);
    expect(chips(root)).toContainEqual({ text: 'Context window 32,000 tokens', set: true });
  });

  it('a value outside 8,000–10,000,000 is refused before saving', async () => {
    const server = setup();
    const { fixture, root } = await render();
    for (const bad of ['7999', '10000001', '12.5', 'many']) {
      await fill(fixture, root, '#ai-context-window', bad);
      await saveAndTest(fixture, root);
      expect(puts(server)).toHaveLength(0);
      expect(field(root, 'ai-context-window').getAttribute('aria-invalid')).toBe('true');
      expect(textOf(root, '#ai-context-window-error')).toBe(
        'Enter a whole number of tokens from 8,000 to 10,000,000, or leave it empty.',
      );
      expect(openOptions(root).open).toBe(true);
      expect(document.activeElement).toBe(field(root, 'ai-context-window'));
    }
  });

  it('saving sends contextWindowTokens', async () => {
    const server = setup();
    const { fixture, root } = await render();
    await fill(fixture, root, '#ai-context-window', '200000');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toMatchObject({ contextWindowTokens: 200_000 });
    await fill(fixture, root, '#ai-context-window', '8,000');
    await saveAndTest(fixture, root);
    expect(puts(server)[1]?.provider).toMatchObject({ contextWindowTokens: 8000 });
    await fill(fixture, root, '#ai-context-window', '');
    await saveAndTest(fixture, root);
    expect(puts(server)[2]?.provider).toMatchObject({ contextWindowTokens: null });
  });

  it('keeps a stored context window through a save that does not touch the field', async () => {
    const server = setup();
    const { fixture, root } = await render({
      settings: {
        ...CONFIGURED,
        provider: { ...CONFIGURED.provider, contextWindowTokens: 32_000 },
      },
    });
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toMatchObject({ contextWindowTokens: 32_000 });
  });

  it('asks for a JSON object unless its switch is off', async () => {
    const server = setup();
    const { fixture, root } = await render();
    const json = field(root, 'ai-json');
    expect([json.getAttribute('role'), json.checked]).toEqual(['switch', true]);
    expect(textOf(root, `#${json.getAttribute('aria-labelledby')}`)).toBe('Ask for a JSON object');
    expect(textOf(root, `#${json.getAttribute('aria-describedby')}`)).toBe(
      'Turn it off for a server that refuses JSON mode.',
    );
    await pick(fixture, root, '#ai-json');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toMatchObject({ jsonMode: 'none' });
  });

  // OpenAI's current models refuse max_tokens; other OpenAI-compatible servers want it.
  it.each([
    ['https://api.openai.com/v1', 'max_completion_tokens'],
    ['https://acme.openai.azure.com/openai/v1', 'max_completion_tokens'],
    ['http://ollama:11434/v1', 'max_tokens'],
  ])('picks the output limit parameter for %s', async (url, value) => {
    const server = setup();
    const { fixture, root } = await render({ settings: EMPTY });
    await pick(fixture, root, '#ai-kind-openai');
    await fill(fixture, root, '#ai-url', url);
    // A new provider at api.openai.com asks through Responses, which has no such parameter.
    if (url.includes('api.openai.com')) await pick(fixture, root, '#ai-api-chat-completions');
    expect(checkedOf(root, 'ai-max-tokens-field')).toBe(value);
    expect(defaultOutputLimitField(url)).toBe(value);
    await fill(fixture, root, '#ai-model', 'm');
    await saveAndTest(fixture, root);
    expect(puts(server)[0]?.provider).toMatchObject({ maxTokensField: value });
  });

  it('keeps an output limit parameter the admin chose, and a saved one while the host stays', async () => {
    setup();
    const { fixture, root } = await render({
      settings: {
        ...CONFIGURED,
        provider: { ...CONFIGURED.provider, baseUrl: 'https://api.openai.com/v1' },
      },
    });
    const value = () => checkedOf(root, 'ai-max-tokens-field');
    // Saved as max_tokens for an OpenAI URL (an older model): editing the path keeps it.
    await fill(fixture, root, '#ai-url', 'https://api.openai.com/v1/');
    expect(value()).toBe('max_tokens');
    // Another kind of server, then OpenAI again: the default follows the host.
    await fill(fixture, root, '#ai-url', 'http://vllm:8000/v1');
    expect(value()).toBe('max_tokens');
    await fill(fixture, root, '#ai-url', 'https://api.openai.com/v1');
    expect(value()).toBe('max_completion_tokens');
    // Chosen by hand: the host no longer changes it.
    await pick(fixture, root, '#ai-max-tokens-field-max-tokens');
    await fill(fixture, root, '#ai-url', 'http://vllm:8000/v1');
    await fill(fixture, root, '#ai-url', 'https://api.openai.com/v1');
    expect(value()).toBe('max_tokens');
  });

  it('says which servers want which output limit parameter', async () => {
    setup();
    const { root } = await render();
    const group = root
      .querySelector('#ai-max-tokens-field-max-tokens')!
      .closest('[role="radiogroup"]')!;
    expect(textOf(root, `#${group.getAttribute('aria-labelledby')}`)).toBe(
      'Output limit parameter',
    );
    expect(group.classList).toContain('mono');
    expect(group.getAttribute('aria-describedby')).toBe('ai-max-tokens-field-hint');
    expect(textOf(root, '#ai-max-tokens-field-hint')).toBe(
      'OpenAI and Azure OpenAI want max_completion_tokens; vLLM, Ollama and most others want max_tokens. Set from the address until you choose.',
    );
  });

  describe('the API', () => {
    const RESPONSES = { ...CONFIGURED, provider: { ...CONFIGURED.provider, api: 'responses' } };

    it('is a choice of an OpenAI-compatible provider, with its two APIs and its hint', async () => {
      setup();
      const { root } = await render();
      const group = radio(root, 'ai-api', 'responses').closest('[role="radiogroup"]')!;
      expect(group.classList).toContain('segmented');
      expect(textOf(root, `#${group.getAttribute('aria-labelledby')}`)).toBe('API');
      expect(group.getAttribute('aria-describedby')).toBe('ai-api-hint');
      expect(textOf(root, '#ai-api-hint')).toBe(
        "OpenAI's newest models call tools, which AI review needs, only through Responses. vLLM, Ollama, LM Studio and Azure use Chat Completions. Set from the address until you choose.",
      );
      expect(
        [...group.querySelectorAll('label')].map((l) => [
          l.querySelector('input')?.value,
          l.textContent?.trim(),
        ]),
      ).toEqual([
        ['chat_completions', 'Chat Completions'],
        ['responses', 'Responses'],
      ]);
      expect(checkedOf(root, 'ai-api')).toBe('chat_completions');
    });

    it('is a setting of the OpenAI kind alone, as the key header, the JSON mode and the output limit parameter', async () => {
      setup();
      const { fixture, root } = await render();
      const OPENAI_ONLY = [
        'input[name="ai-api"]',
        'input[name="ai-auth"]',
        '#ai-json',
        'input[name="ai-max-tokens-field"]',
      ];
      for (const [kind, shown] of [
        ['anthropic', false],
        ['openai', true],
      ] as const) {
        await pick(fixture, root, `#ai-kind-${kind}`);
        for (const selector of OPENAI_ONLY) {
          expect(root.querySelector(selector) !== null, `${selector}, ${kind}`).toBe(shown);
        }
      }
      await pick(fixture, root, '#ai-kind-anthropic');
      expect(textOf(root, '#ai-temperature-anthropic')).toBe(
        "Not used: Anthropic's current models take no temperature.",
      );
      expect(root.textContent).not.toContain('Chat Completions');
    });

    it('shows the stored API, and Chat Completions for a provider saved before it', async () => {
      setup();
      const responses = await render({ settings: RESPONSES });
      expect(checkedOf(responses.root, 'ai-api')).toBe('responses');
      TestBed.resetTestingModule();
      setup();
      const old = Object.fromEntries(
        Object.entries(CONFIGURED.provider).filter(([name]) => name !== 'api'),
      );
      const before = await render({ settings: { ...CONFIGURED, provider: old } });
      expect(checkedOf(before.root, 'ai-api')).toBe('chat_completions');
    });

    it('sends the API that is chosen, for an OpenAI-compatible provider', async () => {
      const server = setup();
      const { fixture, root } = await render();
      await touch(fixture, root);
      await saveAndTest(fixture, root);
      expect(puts(server)[0]?.provider).toMatchObject({ kind: 'openai', api: 'chat_completions' });
      await pick(fixture, root, '#ai-api-responses');
      await saveAndTest(fixture, root);
      expect(puts(server)[1]?.provider).toMatchObject({ kind: 'openai', api: 'responses' });
      await pick(fixture, root, '#ai-api-chat-completions');
      await saveAndTest(fixture, root);
      expect(puts(server)[2]?.provider).toMatchObject({ api: 'chat_completions' });
    });

    it('sends none for Anthropic, whatever was chosen under OpenAI', async () => {
      const server = setup();
      const { fixture, root } = await render({ settings: RESPONSES });
      await pick(fixture, root, '#ai-kind-anthropic');
      await saveAndTest(fixture, root);
      expect(puts(server)[0]?.provider).toMatchObject({ kind: 'anthropic' });
      expect(puts(server)[0]?.provider).not.toHaveProperty('api');
    });

    it('takes the output limit parameter away while the Responses API is chosen: its limit is always max_output_tokens', async () => {
      setup();
      const { fixture, root } = await render();
      expect(root.querySelector('input[name="ai-max-tokens-field"]')).not.toBeNull();
      await pick(fixture, root, '#ai-api-responses');
      expect(root.querySelector('input[name="ai-max-tokens-field"]')).toBeNull();
      expect(root.querySelector('#ai-max-tokens-field-hint')).toBeNull();
      expect(root.querySelector('input[name="ai-auth"]')).not.toBeNull();
      expect(root.querySelector('#ai-json')).not.toBeNull();
      expect(chips(root).map((chip) => chip.text)).not.toContain('max_tokens');
      await pick(fixture, root, '#ai-api-chat-completions');
      expect(checkedOf(root, 'ai-max-tokens-field')).toBe('max_tokens');
    });

    it('shows none of the OpenAI options for Anthropic, and brings them back as they were with OpenAI', async () => {
      setup();
      const { fixture, root } = await render();
      await pick(fixture, root, '#ai-api-responses');
      await pick(fixture, root, '#ai-auth-api-key');
      await pick(fixture, root, '#ai-kind-anthropic');
      expect(root.querySelector('input[name="ai-api"]')).toBeNull();
      await pick(fixture, root, '#ai-kind-openai');
      expect(checkedOf(root, 'ai-api')).toBe('responses');
      expect(checkedOf(root, 'ai-auth')).toBe('api-key');
      expect(root.querySelector('input[name="ai-max-tokens-field"]')).toBeNull();
    });

    it('keeps the output limit parameter the admin set, and sends it, while another API is chosen', async () => {
      const server = setup();
      const { fixture, root } = await render();
      await pick(fixture, root, '#ai-max-tokens-field-max-completion-tokens');
      await pick(fixture, root, '#ai-api-responses');
      await pick(fixture, root, '#ai-api-chat-completions');
      expect(checkedOf(root, 'ai-max-tokens-field')).toBe('max_completion_tokens');
      await pick(fixture, root, '#ai-api-responses');
      await saveAndTest(fixture, root);
      expect(puts(server)[0]?.provider).toMatchObject({
        api: 'responses',
        maxTokensField: 'max_completion_tokens',
      });
    });

    it('asks a new provider at api.openai.com through Responses until the admin chooses', async () => {
      setup();
      const { fixture, root } = await render({ settings: EMPTY });
      await pick(fixture, root, '#ai-kind-openai');
      expect(checkedOf(root, 'ai-api')).toBe('chat_completions');
      await fill(fixture, root, '#ai-url', 'https://api.openai.com/v1');
      expect(checkedOf(root, 'ai-api')).toBe('responses');
      await fill(fixture, root, '#ai-url', 'http://ollama:11434/v1');
      expect(checkedOf(root, 'ai-api')).toBe('chat_completions');
      await pick(fixture, root, '#ai-api-responses');
      await fill(fixture, root, '#ai-url', 'http://vllm:8000/v1');
      expect(checkedOf(root, 'ai-api')).toBe('responses');
      TestBed.resetTestingModule();
      // A saved provider keeps its API, whatever its address becomes.
      setup();
      const saved = await render();
      await fill(saved.fixture, saved.root, '#ai-url', 'https://api.openai.com/v1');
      expect(checkedOf(saved.root, 'ai-api')).toBe('chat_completions');
    });

    it('changes the key header', async () => {
      const server = setup();
      const { fixture, root } = await render();
      expect(checkedOf(root, 'ai-auth')).toBe('bearer');
      await pick(fixture, root, '#ai-auth-api-key');
      await saveAndTest(fixture, root);
      expect(puts(server)[0]?.provider).toMatchObject({ auth: 'api-key' });
    });
  });

  describe('the temperature', () => {
    const WARM = { ...CONFIGURED, provider: { ...CONFIGURED.provider, temperature: 0.7 } };

    it('is not used for an Anthropic provider, and says so', async () => {
      setup();
      const { root } = await render({ settings: ANTHROPIC });
      expect(root.querySelector('#ai-temperature-set')).toBeNull();
      expect(root.querySelector('#ai-temperature')).toBeNull();
      expect(textOf(root, '#ai-temperature-anthropic')).toBe(
        "Not used: Anthropic's current models take no temperature.",
      );
    });

    it('is a switch of OpenAI-compatible providers, with a field up to 2 under it', async () => {
      setup();
      const { fixture, root } = await render();
      const toggle = field(root, 'ai-temperature-set');
      expect([toggle.getAttribute('role'), toggle.checked]).toEqual(['switch', false]);
      expect(textOf(root, `#${toggle.getAttribute('aria-labelledby')}`)).toBe('Set a temperature');
      expect(textOf(root, `#${toggle.getAttribute('aria-describedby')}`)).toBe(
        'Off: none is sent, and the model uses its own.',
      );
      expect(root.querySelector('#ai-temperature')).toBeNull();
      await pick(fixture, root, '#ai-temperature-set');
      expect(field(root, 'ai-temperature').getAttribute('inputmode')).toBe('decimal');
      TestBed.resetTestingModule();
      setup();
      const warm = await render({ settings: WARM });
      expect(field(warm.root, 'ai-temperature-set').checked).toBe(true);
      expect(field(warm.root, 'ai-temperature').value).toBe('0.7');
      expect(warm.root.querySelector('#ai-temperature-anthropic')).toBeNull();
    });

    it('brings the value back with OpenAI after Anthropic', async () => {
      setup();
      const { fixture, root } = await render({ settings: WARM });
      await pick(fixture, root, '#ai-kind-anthropic');
      expect(root.querySelector('#ai-temperature')).toBeNull();
      await pick(fixture, root, '#ai-kind-openai');
      expect(field(root, 'ai-temperature').value).toBe('0.7');
    });

    it('sends none for an Anthropic provider, whatever was typed under another kind', async () => {
      const server = setup();
      const { fixture, root } = await render({ settings: WARM });
      await fill(fixture, root, '#ai-temperature', '0.5');
      await pick(fixture, root, '#ai-kind-anthropic');
      await saveAndTest(fixture, root);
      expect(puts(server)[0]?.provider).toMatchObject({ kind: 'anthropic', temperature: null });
    });

    it('sends none while its switch is off', async () => {
      const server = setup();
      const { fixture, root } = await render({ settings: WARM });
      await pick(fixture, root, '#ai-temperature-set');
      await saveAndTest(fixture, root);
      expect(puts(server)[0]?.provider).toMatchObject({ temperature: null });
    });

    it('sends the temperature of an OpenAI-compatible provider, and refuses one over 2 in the page’s words', async () => {
      const server = setup();
      const { fixture, root } = await render();
      await pick(fixture, root, '#ai-temperature-set');
      await fill(fixture, root, '#ai-temperature', '1.5');
      await saveAndTest(fixture, root);
      expect(puts(server)[0]?.provider).toMatchObject({ kind: 'openai', temperature: 1.5 });
      await fill(fixture, root, '#ai-temperature', '2.5');
      await saveAndTest(fixture, root);
      expect(puts(server)).toHaveLength(1);
      expect(textOf(root, '#ai-temperature-error')).toBe(
        'Use a number from 0 to 2, or leave it empty.',
      );
    });
  });
});

describe('ProviderSection: Save and test', () => {
  const failed = (code: string, status: number | null = null) => ({
    ok: false,
    reportedModel: null,
    toolCalling: 'not_checked' as const,
    problem: { code, message: 'server text', providerStatus: status } as TestModel['problem'],
  });

  it('runs the Test after a save, lists each model, and keeps the last Test (A2)', async () => {
    const server = setup();
    const { fixture, root, tested } = await render();
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(puts(server)).toHaveLength(1);
    expect(testsRun(server)).toHaveLength(1);
    expect(lines(root)).toEqual(['qwen2.5-coder: connected in 812 ms · can call tools']);
    expect(root.querySelector('#ai-test-models li code')?.textContent).toBe('qwen2.5-coder');
    expect(tones(root)).toEqual(['ok']);
    expect(textOf(root, '#ai-test-when')).toMatch(
      /^Tested \w{3} \d{1,2}, \d{4}, .+ UTC, by you\.$/,
    );
    expect(tested()).toBe(1);
    expect(textOf(root, '.foot-status')).toMatch(/^Saved at .+ UTC\.$/);

    // The stored Test, as the page reads it again later: by the viewer, or another admin.
    const lastTest = (userId: string) => ({
      ...CONFIGURED,
      lastTest: {
        at: '2026-10-26T14:02:00.000Z',
        userId,
        models: [
          {
            tier: 'standard',
            model: 'qwen2.5-coder',
            ok: true,
            toolCalling: 'supported',
            problemCode: null,
          },
          {
            tier: 'strong',
            model: 'qwen3-max',
            ok: true,
            toolCalling: 'not_supported',
            problemCode: null,
          },
          {
            tier: 'fast',
            model: 'qwen2.5-small',
            ok: false,
            toolCalling: 'not_checked',
            problemCode: 'PROVIDER_TIMEOUT',
          },
        ],
      },
    });
    TestBed.resetTestingModule();
    setup();
    const mine = await render({ settings: lastTest(me({ admin: true }).user.id) });
    expect(textOf(mine.root, '#ai-test-when')).toBe('Tested Oct 26, 2026, 2:02 PM UTC, by you.');
    expect(lines(mine.root)).toEqual([
      'qwen2.5-coder: connected · can call tools',
      'qwen3-max: connected · cannot call tools, so AI review would fail',
      'qwen2.5-small: The model did not answer in time; raise the timeout in the AI provider settings.',
    ]);
    expect(tones(mine.root)).toEqual(['ok', 'bad', 'bad']);
    expect(textOf(mine.root, '#ai-test-failed')).toBe('The test failed for 1 of 3 models.');
    TestBed.resetTestingModule();
    setup();
    // Who ran it is not looked up: a user deleted since is "an instance admin" too.
    const theirs = await render({ settings: lastTest('0190a6c2-0000-7000-8000-0000000000ff') });
    expect(textOf(theirs.root, '#ai-test-when')).toBe(
      'Tested Oct 26, 2026, 2:02 PM UTC, by an instance admin.',
    );
  });

  it('offers Test again only while nothing is changed', async () => {
    const server = setup();
    const { fixture, root, tested } = await render();
    const again = () => root.querySelector('q-section-foot #ai-test-again');
    expect(again()).not.toBeNull();
    await fill(fixture, root, '#ai-model', 'qwen3-coder');
    expect(again()).toBeNull();
    await fill(fixture, root, '#ai-model', 'qwen2.5-coder');
    expect(again()).not.toBeNull();
    await press(fixture, root, 'Test again');
    expect(testsRun(server)).toHaveLength(1);
    expect(puts(server)).toHaveLength(0);
    expect(lines(root)).toEqual(['qwen2.5-coder: connected in 812 ms · can call tools']);
    expect(tested()).toBe(1);
    await fixture.componentInstance.test();
    await settle(fixture);
    expect(testsRun(server)).toHaveLength(2);
    // Nothing saved yet: nothing to test.
    TestBed.resetTestingModule();
    setup();
    const empty = await render({ settings: EMPTY });
    await pick(empty.fixture, empty.root, '#ai-kind-openai');
    expect(buttonNamed(empty.root, 'Test again')).toBeUndefined();
  });

  it('tests the provider and shows the problem in its own words', async () => {
    const server = setup();
    server.on('POST', '/api/v0/system/llm/test', {
      body: testAnswer({
        ok: false,
        model: null,
        latencyMs: 12,
        toolCalling: 'not_checked',
        problem: { code: 'PROVIDER_REJECTED_REQUEST', message: 'server text', providerStatus: 404 },
      }),
    });
    const { fixture, root } = await render();
    await press(fixture, root, 'Test again');
    expect(lines(root)).toEqual([
      'qwen2.5-coder: The provider refused the request; check the base URL and the model.',
    ]);
    expect(tones(root)).toEqual(['bad']);
    const alert = root.querySelector('#ai-test-failed')!;
    expect(alert.getAttribute('role')).toBe('alert');
    expect(alert.textContent?.trim()).toBe('The test failed for the model.');
    expect(alert.closest('[role="status"]')).toBeNull();
    expect(root.textContent).not.toContain('server text');
  });

  it.each([
    [401, 'The provider refused the API key (HTTP 401).'],
    [
      403,
      'The provider refused the request (HTTP 403): the key lacks access to this model, or the account has no credit.',
    ],
  ])('tells a refused key (HTTP %i) apart by the provider status', async (status, text) => {
    const server = setup();
    server.on('POST', '/api/v0/system/llm/test', {
      body: answer(line('standard', 'qwen2.5-coder', failed('PROVIDER_REFUSED_KEY', status))),
    });
    const { fixture, root } = await render();
    await press(fixture, root, 'Test again');
    expect(lines(root)).toEqual([`qwen2.5-coder: ${text}`]);
  });

  it.each([
    ['supported', 'qwen2.5-coder: connected in 12 ms · can call tools', 'ok'],
    [
      'not_supported',
      'qwen2.5-coder: connected in 12 ms · cannot call tools, so AI review would fail',
      'bad',
    ],
    ['not_checked', 'qwen2.5-coder: connected in 12 ms', 'unknown'],
  ] as const)('says whether the model can call tools (%s)', async (toolCalling, text, tone) => {
    const server = setup();
    server.on('POST', '/api/v0/system/llm/test', {
      body: testAnswer({
        ok: true,
        model: 'qwen2.5-coder',
        latencyMs: 12,
        toolCalling,
        problem: null,
      }),
    });
    const { fixture, root } = await render();
    await press(fixture, root, 'Test again');
    expect(lines(root)).toEqual([text]);
    expect(tones(root)).toEqual([tone]);
    // In the live region; a tool check that did not pass is not a failed Test.
    expect(root.querySelector('[role="status"] #ai-test-models')).not.toBeNull();
    expect(root.querySelector('[role="alert"]')).toBeNull();
  });

  it('shows a line for each model, in the answer’s order', async () => {
    const server = setup();
    server.on('POST', '/api/v0/system/llm/test', {
      body: answer(
        line('standard', 'qwen2.5-coder', { latencyMs: 120 }),
        line('strong', 'qwen3-max', { latencyMs: 640, toolCalling: 'not_supported' }),
        line('fast', 'qwen2.5-small', { latencyMs: 35, toolCalling: 'not_checked' }),
      ),
    });
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await press(fixture, root, 'Test again');
    expect(lines(root)).toEqual([
      'qwen2.5-coder: connected in 120 ms · can call tools',
      'qwen3-max: connected in 640 ms · cannot call tools, so AI review would fail',
      'qwen2.5-small: connected in 35 ms',
    ]);
    expect(root.querySelector('[role="alert"]')).toBeNull();
  });

  it('shows a model that failed as its problem in the page’s words, beside the lines of the others', async () => {
    const server = setup();
    server.on('POST', '/api/v0/system/llm/test', {
      body: answer(
        line('standard', 'qwen2.5-coder'),
        line('strong', 'qwen3-max'),
        line('fast', 'qwen2.5-small', failed('PROVIDER_REJECTED_REQUEST', 404)),
      ),
    });
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await press(fixture, root, 'Test again');
    expect(lines(root)).toEqual([
      'qwen2.5-coder: connected in 12 ms · can call tools',
      'qwen3-max: connected in 12 ms · can call tools',
      'qwen2.5-small: The provider refused the request; check the base URL and the model.',
    ]);
    expect(root.textContent).not.toContain('server text');
    const alerts = root.querySelectorAll('[role="alert"]');
    expect(alerts).toHaveLength(1);
    expect(alerts[0]?.textContent?.trim()).toBe('The test failed for 1 of 3 models.');
    expect(alerts[0]?.classList).toContain('alert-error');
  });

  it('tells a refused key apart by the provider status on the line of the model', async () => {
    const server = setup();
    server.on('POST', '/api/v0/system/llm/test', {
      body: answer(
        line('standard', 'qwen2.5-coder'),
        line('strong', 'qwen3-max', failed('PROVIDER_REFUSED_KEY', 403)),
      ),
    });
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await press(fixture, root, 'Test again');
    expect(lines(root)[1]).toBe(
      'qwen3-max: The provider refused the request (HTTP 403): the key lacks access to this model, or the account has no credit.',
    );
  });

  it('shows every line as a problem when the key cannot be read', async () => {
    const server = setup();
    const unreadable = (tier: TestModel['tier'], model: string) =>
      line(tier, model, { ...failed('KEY_UNDECRYPTABLE'), latencyMs: 0 });
    server.on('POST', '/api/v0/system/llm/test', {
      body: answer(
        unreadable('standard', 'qwen2.5-coder'),
        unreadable('strong', 'qwen3-max'),
        unreadable('fast', 'qwen2.5-small'),
      ),
    });
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await press(fixture, root, 'Test again');
    expect(tones(root)).toEqual(['bad', 'bad', 'bad']);
    expect(lines(root)[0]).toBe(
      'qwen2.5-coder: The stored API key can no longer be read; set it again.',
    );
    expect(textOf(root, '[role="alert"]')).toBe('The test failed for 3 of 3 models.');
  });

  it('replaces the lines, and a failure, with those of the next Test', async () => {
    const server = setup();
    server.on('POST', '/api/v0/system/llm/test', {
      body: answer(
        line('standard', 'qwen2.5-coder'),
        line('strong', 'qwen3-max', failed('PROVIDER_TIMEOUT')),
      ),
    });
    const { fixture, root } = await render({ settings: THREE_MODELS });
    await press(fixture, root, 'Test again');
    expect(textOf(root, '[role="alert"]')).toBe('The test failed for 1 of 2 models.');
    server.on('POST', '/api/v0/system/llm/test', {
      body: answer(line('standard', 'qwen2.5-coder'), line('strong', 'qwen3-max')),
    });
    await touch(fixture, root);
    await saveAndTest(fixture, root);
    expect(root.querySelector('[role="alert"]')).toBeNull();
    expect(lines(root)).toHaveLength(2);
  });

  it('drops the answer of a Test that a save overtook, and shows the save’s own Test', async () => {
    const server = setup();
    const held: ((reply: FakeReply) => void)[] = [];
    server.on('POST', '/api/v0/system/llm/test', () => {
      // The first Test waits; the one after the save answers at once.
      if (testsRun(server).length === 1) return new Promise<FakeReply>((r) => held.push(r));
      return { body: OK_ANSWER };
    });
    const { fixture, root, tested } = await render();
    await press(fixture, root, 'Test again');
    expect(textOf(root, '#ai-test-status')).toBe('Testing…');
    await fill(fixture, root, '#ai-model', 'qwen3-coder');
    await saveAndTest(fixture, root);
    expect(puts(server)).toHaveLength(1);
    expect(testsRun(server)).toHaveLength(2);
    expect(lines(root)).toEqual(['qwen2.5-coder: connected in 812 ms · can call tools']);
    // The first answer comes last, about the provider before the save: it is not shown.
    held[0]!({
      body: answer(line('standard', 'qwen2.5-coder', failed('PROVIDER_TIMEOUT'))),
    });
    await settle(fixture);
    expect(lines(root)).toEqual(['qwen2.5-coder: connected in 812 ms · can call tools']);
    expect(root.querySelector('#ai-test-failed')).toBeNull();
    expect(root.querySelector('#ai-test-status')?.textContent).not.toContain('Testing');
    expect(tested()).toBe(1);
  });

  it('says the Test could not run when its request fails', async () => {
    const server = setup();
    server.on('POST', '/api/v0/system/llm/test', { status: 500, body: problem(500, 'INTERNAL') });
    const { fixture, root, tested } = await render();
    await press(fixture, root, 'Test again');
    expect(root.querySelector('#ai-test-error')?.getAttribute('role')).toBe('alert');
    expect(tested()).toBe(0);
  });

  describe('the Responses hint', () => {
    const HINT =
      'This model takes tools only through the Responses API: choose Responses in Connection options.';
    const needsResponses = { code: 'USE_RESPONSES_API', message: 'server text' } as const;

    it('is said under the lines for a model that refused tools through Chat Completions, in the page’s words', async () => {
      const server = setup();
      server.on('POST', '/api/v0/system/llm/test', {
        body: testAnswer({
          ok: true,
          model: 'qwen2.5-coder',
          latencyMs: 12,
          toolCalling: 'not_supported',
          problem: null,
          hint: needsResponses,
        }),
      });
      const { fixture, root } = await render();
      await press(fixture, root, 'Test again');
      expect(lines(root)).toEqual([
        'qwen2.5-coder: connected in 12 ms · cannot call tools, so AI review would fail',
      ]);
      expect(textOf(root, '#ai-test-use-responses')).toBe(HINT);
      expect(root.textContent).not.toContain('server text');
    });

    it('is not said for a model refused for another reason', async () => {
      const server = setup();
      server.on('POST', '/api/v0/system/llm/test', {
        body: testAnswer({
          ok: true,
          model: 'qwen2.5-coder',
          latencyMs: 12,
          toolCalling: 'not_supported',
          problem: null,
        }),
      });
      const { fixture, root } = await render();
      await press(fixture, root, 'Test again');
      expect(root.querySelector('#ai-test-use-responses')).toBeNull();
      expect(root.querySelector<HTMLDetailsElement>('#ai-options')?.open).toBe(false);
    });

    it('goes once a save tests again', async () => {
      const server = setup();
      server.on('POST', '/api/v0/system/llm/test', {
        body: answer(
          line('standard', 'qwen2.5-coder'),
          line('strong', 'qwen3-max', { toolCalling: 'not_supported', hint: needsResponses }),
        ),
      });
      const { fixture, root } = await render({ settings: THREE_MODELS });
      await press(fixture, root, 'Test again');
      expect(lines(root)[1]).toBe(
        'qwen3-max: connected in 12 ms · cannot call tools, so AI review would fail',
      );
      expect(textOf(root, '#ai-test-use-responses')).toBe(HINT);
      server.on('POST', '/api/v0/system/llm/test', { body: OK_ANSWER });
      await pick(fixture, root, '#ai-api-responses');
      await saveAndTest(fixture, root);
      expect(root.querySelector('#ai-test-use-responses')).toBeNull();
    });
  });

  describe('a key that is not scoped to a workspace', () => {
    const WORDS = 'This key is not scoped to a workspace: give its workspace ID above.';

    it('is the line of each model the key was refused for, in the page’s words', async () => {
      const server = setup();
      server.on('POST', '/api/v0/system/llm/test', {
        body: answer(
          line('standard', 'claude-sonnet-5-5', failed('PROVIDER_WORKSPACE_REQUIRED', 400)),
          line('strong', 'claude-opus-5-5', failed('PROVIDER_WORKSPACE_REQUIRED', 400)),
        ),
      });
      const { fixture, root } = await render({
        settings: {
          ...ANTHROPIC,
          provider: { ...ANTHROPIC.provider, strongModel: 'claude-opus-5-5' },
        },
      });
      await press(fixture, root, 'Test again');
      expect(lines(root)).toEqual([`claude-sonnet-5-5: ${WORDS}`, `claude-opus-5-5: ${WORDS}`]);
      expect(root.textContent).not.toContain('server text');
    });
  });

  it('keeps edits made while the save is on its way, and empties a key typed meanwhile', async () => {
    const server = setup();
    const held: (() => void)[] = [];
    server.on(
      'PUT',
      '/api/v0/system/llm',
      (request) =>
        new Promise<FakeReply>((resolve) => {
          held.push(() => resolve({ body: storedAfter(request.body as PutBody) }));
        }),
    );
    const { fixture, root } = await render();
    await fill(fixture, root, '#ai-model', 'qwen3-coder');
    await saveAndTest(fixture, root);
    expect(textOf(root, '.foot-status')).toBe('Saving…');
    // Nothing is disabled while the save is on its way.
    expect(field(root, 'ai-model').disabled).toBe(false);
    await fill(fixture, root, '#ai-timeout', '120');
    await press(fixture, root, 'Replace the key');
    await fill(fixture, root, '#ai-key', KEY);
    held[0]!();
    await settle(fixture);
    expect(field(root, 'ai-model').value).toBe('qwen3-coder');
    expect(field(root, 'ai-timeout').value).toBe('120');
    expect(textOf(root, '.foot-status')).toBe('1 unsaved change');
    expect(root.querySelector<HTMLInputElement>('#ai-key')?.value ?? '').toBe('');
  });
});

describe('ProviderSection: before pausing AI review (Review Focus 3)', () => {
  /** Default reviews merge requests, confirmed for this provider and its fast model. */
  const REVIEWED = {
    ...CONFIGURED,
    provider: { ...CONFIGURED.provider, fastModel: 'qwen-fast' },
    organizations: {
      [ORG_ID]: {
        ...CONFIGURED.organizations[ORG_ID],
        reviewStatus: { enabled: true, consentCurrent: true },
      },
    },
  };
  const dialog = (root: HTMLElement) => root.querySelector<HTMLDialogElement>('#ai-pause-dialog')!;

  it('asks before pausing AI review, only for a change of address or models (Review Focus 3)', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: REVIEWED });
    expect(dialog(root).open).toBe(false);
    await fill(fixture, root, '#ai-fast-model', '');
    await saveAndTest(fixture, root);
    expect(dialog(root).open).toBe(true);
    expect(textOf(root, '#ai-pause-dialog h2')).toBe('Pause AI review in Default?');
    expect(textOf(root, '#ai-pause-was')).toBe(
      'Default confirmed sending code to ollama:11434 (qwen-fast, qwen2.5-coder).',
    );
    expect(textOf(root, '#ai-pause-now')).toBe(
      'After this change, AI review stops there until an organization admin confirms the new provider: ollama:11434 (qwen2.5-coder).',
    );
    expect(textOf(root, '#ai-pause-assistant')).toBe(
      'Explain, Suggest triage and Suggest a fix carry on as before.',
    );
    // Cancel sends nothing, and the edit stays.
    await press(fixture, root, 'Cancel', '#ai-pause-dialog');
    expect(dialog(root).open).toBe(false);
    expect(puts(server)).toHaveLength(0);
    expect(field(root, 'ai-fast-model').value).toBe('');
    // Confirmed: one save, then the Test.
    await saveAndTest(fixture, root);
    await press(fixture, root, 'Save and pause AI review', '#ai-pause-dialog');
    expect(dialog(root).open).toBe(false);
    expect(puts(server)).toHaveLength(1);
    expect(puts(server)[0]?.provider).toMatchObject({ fastModel: null });
    expect(testsRun(server)).toHaveLength(1);
  });

  it.each([
    ['a timeout', '#ai-timeout', '120'],
    ['the key header', '#ai-auth-api-key', null],
  ])('saves %s at once: it pauses nothing', async (_what, selector, value) => {
    const server = setup();
    const { fixture, root } = await render({ settings: REVIEWED });
    if (value === null) await pick(fixture, root, selector);
    else await fill(fixture, root, selector, value);
    await saveAndTest(fixture, root);
    expect(dialog(root).open).toBe(false);
    expect(puts(server)).toHaveLength(1);
  });

  it('saves the API at once too', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: REVIEWED });
    await pick(fixture, root, '#ai-api-responses');
    await saveAndTest(fixture, root);
    expect(dialog(root).open).toBe(false);
    expect(puts(server)).toHaveLength(1);
  });

  it('asks for the key of a new address first, and nothing about pausing until it is typed', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: REVIEWED });
    await fill(fixture, root, '#ai-url', 'http://ollama:11434/api/v1');
    await saveAndTest(fixture, root);
    expect(dialog(root).open).toBe(false);
    expect(puts(server)).toHaveLength(0);
    expect(field(root, 'ai-key').getAttribute('aria-invalid')).toBe('true');
    expect(textOf(root, '#ai-key-error')).toContain('Enter the API key again for a new address');
    expect(document.activeElement).toBe(field(root, 'ai-key'));
    await fill(fixture, root, '#ai-key', KEY);
    await saveAndTest(fixture, root);
    expect(dialog(root).open).toBe(true);
  });

  it('sends the key typed once the question is confirmed, in one save, and empties its field', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: REVIEWED });
    await fill(fixture, root, '#ai-url', 'http://ollama:11434/api/v1');
    await fill(fixture, root, '#ai-key', KEY);
    await saveAndTest(fixture, root);
    expect(dialog(root).open).toBe(true);
    const key = field(root, 'ai-key');
    expect(key.value).toBe(KEY);
    await press(fixture, root, 'Save and pause AI review', '#ai-pause-dialog');
    expect(puts(server)).toHaveLength(1);
    expect(puts(server)[0]?.provider).toMatchObject({
      baseUrl: 'http://ollama:11434/api/v1',
      apiKey: KEY,
    });
    expect(key.value).toBe('');
    expect(root.querySelector<HTMLInputElement>('#ai-key')?.value ?? '').toBe('');
    expect(root.textContent).not.toContain(KEY);
  });

  it('asks nothing where review is paused already', async () => {
    const server = setup();
    const paused = {
      ...REVIEWED,
      organizations: {
        [ORG_ID]: {
          ...REVIEWED.organizations[ORG_ID],
          reviewStatus: { enabled: true, consentCurrent: false },
        },
      },
    };
    const { fixture, root } = await render({ settings: paused });
    await fill(fixture, root, '#ai-fast-model', '');
    await saveAndTest(fixture, root);
    expect(dialog(root).open).toBe(false);
    expect(puts(server)).toHaveLength(1);
  });

  it('names at most three organizations, then how many more', async () => {
    setup();
    const orgs = organizationsFixture(5);
    const settings = {
      ...REVIEWED,
      organizations: Object.fromEntries(
        orgs.map((o) => [o.id, { ...REVIEWED.organizations[ORG_ID] }]),
      ),
    };
    const { fixture, root } = await render({ settings, organizations: orgs });
    expect(textOf(root, '#ai-url-note')).toBe(
      'Changing the address needs the API key again, and pauses AI review in Org 1, Org 2, Org 3, and 2 more until an organization admin confirms the new address.',
    );
    await fill(fixture, root, '#ai-url', 'http://ollama:11434/api/v1');
    await fill(fixture, root, '#ai-key', KEY);
    await saveAndTest(fixture, root);
    expect(textOf(root, '#ai-pause-dialog h2')).toBe(
      'Pause AI review in Org 1, Org 2, Org 3, and 2 more?',
    );
    // The key stays in its field while the question is open.
    expect(field(root, 'ai-key').value).toBe(KEY);
  });

  it('counts the organizations it cannot name, and still asks', async () => {
    const server = setup();
    // The page could not read the organisations: it knows none of them by name.
    const { fixture, root } = await render({ settings: REVIEWED, organizations: [] });
    expect(textOf(root, '#ai-url-note')).toBe(
      'Changing the address needs the API key again, and pauses AI review in 1 organization until an organization admin confirms the new address.',
    );
    await fill(fixture, root, '#ai-model', 'qwen3-coder');
    await saveAndTest(fixture, root);
    expect(dialog(root).open).toBe(true);
    expect(textOf(root, '#ai-pause-dialog h2')).toBe('Pause AI review in 1 organization?');
    expect(textOf(root, '#ai-pause-was')).toBe(
      '1 organization confirmed sending code to ollama:11434 (qwen-fast, qwen2.5-coder).',
    );
    expect(puts(server)).toHaveLength(0);
    await press(fixture, root, 'Save and pause AI review', '#ai-pause-dialog');
    expect(puts(server)[0]?.provider).toMatchObject({ model: 'qwen3-coder' });
  });
});

describe('ProviderSection: removing the provider', () => {
  it('removes the provider after its confirmation', async () => {
    const server = setup();
    const { fixture, root } = await render({ settings: THREE_MODELS });
    const dialog = () => root.querySelector<HTMLDialogElement>('#ai-remove-dialog')!;
    const remove = buttonNamed(root, 'Remove the provider…')!;
    expect(remove.classList).toContain('btn-danger');
    expect(textOf(root, '#ai-remove-help')).toBe(
      'Every AI feature stops in every organization, and the key is deleted.',
    );
    await press(fixture, root, 'Remove the provider…');
    expect(dialog().open).toBe(true);
    expect(textOf(root, '#ai-remove-dialog h2')).toBe('Remove the AI provider?');
    expect(textOf(root, '#ai-remove-text')).toBe(
      'Every AI feature stops in every organization: Explain, Suggest triage and Suggest a fix, AI review and automatic fix suggestions. The API key is deleted. Organizations keep their settings.',
    );
    await press(fixture, root, 'Cancel', '#ai-remove-dialog');
    expect(dialog().open).toBe(false);
    expect(puts(server)).toHaveLength(0);

    await press(fixture, root, 'Remove the provider…');
    await press(fixture, root, 'Remove the provider', '#ai-remove-dialog');
    expect(puts(server)).toEqual([expect.objectContaining({ provider: null, pricing: null })]);
    expect(testsRun(server)).toHaveLength(0);
    // First setup again: the kinds, and nothing chosen.
    expect(field(root, 'ai-kind-openai').checked).toBe(false);
    expect(root.querySelector('#ai-url')).toBeNull();
    expect(root.querySelector('#ai-local')).not.toBeNull();
    expect(buttonNamed(root, 'Remove the provider…')).toBeUndefined();
  });

  it('is offered only while a provider is saved', async () => {
    setup();
    const { fixture, root } = await render({ settings: EMPTY });
    await pick(fixture, root, '#ai-kind-openai');
    expect(buttonNamed(root, 'Remove the provider…')).toBeUndefined();
  });
});
