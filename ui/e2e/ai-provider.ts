import { type APIRequestContext, expect } from '@playwright/test';

/** The models of the instance's AI provider besides the standard one: the strong and the fast tier. */
export interface TierModels {
  strongModel: string | null;
  fastModel: string | null;
}

/**
 * The instance admin's save of the AI provider settings with the models of the strong and the
 * fast tier set (or none), everything else as it is stored: the API, as the AI provider page's
 * sections send it. The key is left out, so the stored one stays. `admin` is a request context
 * signed in as the instance admin. The tests that set tier models put the seed's one model back
 * with it in an `afterEach`, so that a failure midway never leaves them in the shared e2e database,
 * and a failure of that never hides the test's own.
 */
export async function setTierModels(admin: APIRequestContext, models: TierModels): Promise<void> {
  await saveStored(admin, (provider) => ({ provider: { ...provider, ...models } }));
}

/**
 * The instance admin's save of the AI provider settings with the provider's context window set (or
 * none), everything else as it is stored: what a test that set the window puts back in its
 * `finally`.
 */
export async function setContextWindow(
  admin: APIRequestContext,
  contextWindowTokens: number | null,
): Promise<void> {
  await saveStored(admin, (provider) => ({ provider: { ...provider, contextWindowTokens } }));
}

/**
 * The instance admin's save of the AI provider settings with the limits given, everything else as
 * it is stored, as `setTierModels` saves: what a test that changed the limits puts back in its
 * `finally`, so that a failure midway never leaves them changed in the shared e2e database.
 */
export async function setBudgets(admin: APIRequestContext, budgets: object): Promise<void> {
  await saveStored(admin, () => ({ budgets }));
}

/**
 * The instance admin's save of the AI provider settings with the prices given (null: none),
 * everything else as it is stored: what a test that saved prices puts back in its `finally`, so that
 * a failure midway never leaves prices in the shared e2e database, whose other tests expect none.
 */
export async function setPricing(admin: APIRequestContext, pricing: object | null): Promise<void> {
  await saveStored(admin, () => ({ pricing }));
}

/** The stored provider as the `PUT` takes it: the answer's fields without its key's state. */
interface ProviderBody {
  kind: string;
  api: string;
  baseUrl: string;
  model: string;
  strongModel: string | null;
  fastModel: string | null;
  auth: string;
  jsonMode: string;
  maxTokensField: string;
  temperature: number | null;
  timeoutSeconds: number;
  contextWindowTokens: number | null;
}

/**
 * Saves the stored settings with `change` in place of their fields, as the AI provider page's
 * sections send them. The key is left out, so the stored one stays.
 */
async function saveStored(
  admin: APIRequestContext,
  change: (provider: ProviderBody) => object,
): Promise<void> {
  const me = (await (await admin.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  const stored = (await (await admin.get('/api/v0/system/llm')).json()) as {
    provider: ProviderBody;
  };
  const p = stored.provider;
  const provider: ProviderBody = {
    kind: p.kind,
    api: p.api,
    baseUrl: p.baseUrl,
    model: p.model,
    strongModel: p.strongModel,
    fastModel: p.fastModel,
    auth: p.auth,
    jsonMode: p.jsonMode,
    maxTokensField: p.maxTokensField,
    temperature: p.temperature,
    timeoutSeconds: p.timeoutSeconds,
    contextWindowTokens: p.contextWindowTokens,
  };
  const saved = await admin.put('/api/v0/system/llm', {
    headers: { 'x-qualor-csrf': me.csrfToken },
    data: { ...stored, provider, ...change(provider) },
  });
  expect(saved.status(), await saved.text()).toBe(200);
}

/** An OpenAI-compatible provider as the API takes one: its address, model and key. */
export interface ProviderSetup {
  baseUrl: string;
  model: string;
  apiKey: string;
  /** The API the model speaks; left out, the server's default (Chat Completions) stays. */
  api?: 'chat_completions' | 'responses';
}

/**
 * The instance admin's save of a provider through the API, everything else as it is stored: what
 * a test that is not about the provider sets up with, so no Test of it runs. `admin` is a
 * request context signed in as the instance admin.
 */
export async function setProvider(
  admin: APIRequestContext,
  provider: ProviderSetup,
): Promise<void> {
  const me = (await (await admin.get('/api/v0/auth/me')).json()) as { csrfToken: string };
  const stored = (await (await admin.get('/api/v0/system/llm')).json()) as object;
  const saved = await admin.put('/api/v0/system/llm', {
    headers: { 'x-qualor-csrf': me.csrfToken },
    data: { ...stored, provider: { kind: 'openai', ...provider } },
  });
  expect(saved.status(), await saved.text()).toBe(200);
}
