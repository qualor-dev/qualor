import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { createFakeLlm, openAiAnswer, type FakeLlm } from '../../test/fake-llm';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { instanceSettings } from '../db/schema';
import { DEFAULT_LLM_SETTINGS, writeLlmSettings } from '../llm/settings';
import { parseInternalHosts } from '../scm/url';

describe('/system/llm (llm.md §3, §16)', () => {
  let ctx: TestContext;
  let fake: FakeLlm;
  let admin: Session;
  let orgAdmin: Session;
  let org: string;
  const provider = (over: Record<string, unknown> = {}) => ({
    kind: 'openai',
    baseUrl: fake.openAiBaseUrl,
    model: 'fake-model',
    apiKey: fake.apiKey,
    ...over,
  });
  const body = (over: Record<string, unknown> = {}) => ({
    provider: provider(),
    organizations: {
      [org]: {
        enabled: true,
        features: { explain: true, triage: true, fix: true },
        excludedProjectIds: [],
      },
    },
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
    ...over,
  });
  const put = (payload: unknown, session = admin) =>
    ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/system/llm',
      headers: session.headers,
      payload: payload as object,
    });
  const get = (session = admin) =>
    ctx.app.inject({ method: 'GET', url: '/api/v0/system/llm', headers: session.headers });
  const test = (session = admin) =>
    ctx.app.inject({ method: 'POST', url: '/api/v0/system/llm/test', headers: session.headers });

  beforeAll(async () => {
    fake = await createFakeLlm();
    ctx = await createTestContext({
      config: { llmInternalHosts: parseInternalHosts(fake.host) },
    });
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    org = await organizationId(ctx, 'default');
    const u = await createUser(ctx, { username: 'llm-org-admin' });
    await addMember(ctx, org, u.id, 'admin');
    orgAdmin = await login(ctx, u.username, u.password);
  });
  afterAll(async () => {
    await ctx.close();
    await fake.close();
  });
  beforeEach(() => {
    fake.requests.length = 0;
  });

  it('is off by default and for instance admins only (an org admin gets 403)', async () => {
    const res = await get();
    expect(res.statusCode).toBe(200);
    expect(res.json()).toMatchObject({ provider: null, maxFixPerDay: 25 });
    expect((await get(orgAdmin)).statusCode).toBe(403);
    expect((await put(body(), orgAdmin)).statusCode).toBe(403);
    expect((await test(orgAdmin)).statusCode).toBe(403);
    const anonymous = await ctx.app.inject({ method: 'GET', url: '/api/v0/system/llm' });
    expect(anonymous.statusCode).toBe(401);
  });

  it('stores the key write-only and encrypted, and never logs or returns it', async () => {
    const res = await put(body());
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json().provider).toMatchObject({
      kind: 'openai',
      baseUrl: fake.openAiBaseUrl,
      apiKeySet: true,
      apiKeyReadable: true,
    });
    expect(res.json().provider).not.toHaveProperty('apiKey');
    expect(res.json().provider).not.toHaveProperty('apiKeyEnc');
    expect(res.body).not.toContain(fake.apiKey);
    expect((await get()).body).not.toContain(fake.apiKey);
    const [row] = await ctx.db
      .select()
      .from(instanceSettings)
      .where(eq(instanceSettings.key, 'llm'));
    expect(JSON.stringify(row?.value)).not.toContain(fake.apiKey);
    expect(ctx.logs.join('\n')).not.toContain(fake.apiKey);
    const changed = ctx.logs.filter((l) => l.includes('LLM settings changed'));
    expect(changed.length).toBeGreaterThan(0);
    expect(changed.at(-1)).toContain('provider.apiKey');
  });

  it('keeps the key when apiKey is absent, and needs it again for a new address', async () => {
    const withoutKey: Record<string, unknown> = provider();
    delete withoutKey.apiKey;
    expect((await put(body({ provider: withoutKey }))).json().provider.apiKeySet).toBe(true);
    // The same address spelt with a trailing slash is not a new address.
    const slash = await put(
      body({ provider: { ...withoutKey, baseUrl: `${fake.openAiBaseUrl}/` } }),
    );
    expect(slash.statusCode, slash.body).toBe(200);
    const moved = await put(body({ provider: { ...withoutKey, baseUrl: `${fake.url}/other/v1` } }));
    expect(moved.statusCode).toBe(422);
    expect(moved.json().errors[0].path).toBe('body.provider.apiKey');
    expect((await get()).json().provider.baseUrl).toBe(fake.openAiBaseUrl);
    const movedWithKey = await put(
      body({ provider: provider({ baseUrl: `${fake.url}/other/v1` }) }),
    );
    expect(movedWithKey.json().provider).toMatchObject({
      baseUrl: `${fake.url}/other/v1`,
      apiKeySet: true,
    });
    expect(
      (await put(body({ provider: provider({ apiKey: null }) }))).json().provider.apiKeySet,
    ).toBe(false);
    const removed = await put(body({ provider: null }));
    expect(removed.json().provider).toBeNull();
    // A first provider needs the key (or null) too.
    expect((await put(body({ provider: withoutKey }))).statusCode).toBe(422);
    expect((await put(body())).statusCode).toBe(200);
  });

  it('stores the base URL without a trailing slash', async () => {
    const res = await put(body({ provider: provider({ baseUrl: `${fake.openAiBaseUrl}/` }) }));
    expect(res.json().provider.baseUrl).toBe(fake.openAiBaseUrl);
  });

  it('refuses a key that is not printable ASCII without spaces, never echoing it', async () => {
    for (const apiKey of ['has space-0123456789', 'ключ-0123456789', 'tab\tkey-0123456789', '']) {
      const res = await put(body({ provider: provider({ apiKey }) }));
      expect(res.statusCode).toBe(422);
      expect(res.json().errors.map((e: { path: string }) => e.path)).toContain(
        'body.provider.apiKey',
      );
      if (apiKey !== '') expect(res.body).not.toContain(apiKey);
    }
  });

  it.each([
    [
      { provider: { kind: 'openai', baseUrl: 'http://10.1.2.3/v1', model: 'm', apiKey: 'k' } },
      'body.provider.baseUrl',
    ],
    [
      {
        provider: {
          kind: 'openai',
          baseUrl: 'https://api.example.com/v1',
          model: 'bad model',
          apiKey: 'k',
        },
      },
      'body.provider.model',
    ],
    [
      {
        provider: {
          kind: 'anthropic',
          baseUrl: 'https://api.example.com',
          model: 'm',
          apiKey: 'k',
          temperature: 1.5,
        },
      },
      'body.provider.temperature',
    ],
    [
      {
        budgets: {
          explainPerDay: 1,
          triagePerDay: 1,
          fixPerDay: 26,
          tokensPerDay: 1,
          costPerDayUsd: null,
          perUserPerHour: 1,
        },
      },
      'body.budgets.fixPerDay',
    ],
    [
      {
        organizations: {
          '00000000-0000-7000-8000-000000000000': {
            enabled: true,
            features: { explain: true, triage: false, fix: false },
            excludedProjectIds: [],
          },
        },
      },
      'body.organizations.00000000-0000-7000-8000-000000000000',
    ],
    [{ excludePaths: ['/abs/**'] }, 'body.excludePaths.0'],
  ])('refuses %j at %s', async (over, path) => {
    const res = await put(body(over));
    expect(res.statusCode).toBe(422);
    expect(res.json().errors.map((e: { path: string }) => e.path)).toContain(path);
  });

  it('names the ceiling of this edition, not "the community edition" (enterprise.md §7.2)', async () => {
    const res = await put(body({ budgets: { ...body().budgets, fixPerDay: 26 } }));
    expect(res.statusCode).toBe(422);
    expect(res.json().errors).toContainEqual({
      path: 'body.budgets.fixPerDay',
      message: 'At most 25 in this edition',
    });
  });

  it('keeps a stored fix budget above the ceiling of this edition, and refuses only a raise above it (enterprise.md §7.2)', async () => {
    // Saved while a licence allowed more; the licence lapsed since (this app is community: 25).
    await writeLlmSettings(ctx.db, {
      ...DEFAULT_LLM_SETTINGS,
      budgets: { ...DEFAULT_LLM_SETTINGS.budgets, fixPerDay: 500 },
    });
    const fix = (fixPerDay: number) => put(body({ budgets: { ...body().budgets, fixPerDay } }));
    expect((await fix(500)).statusCode).toBe(200); // unchanged
    expect((await fix(400)).statusCode).toBe(200); // lowered, still above 25
    const raised = await fix(401);
    expect(raised.statusCode).toBe(422);
    expect(raised.json().errors).toContainEqual({
      path: 'body.budgets.fixPerDay',
      message: 'At most 25 in this edition',
    });
    expect((await fix(25)).statusCode).toBe(200);
    expect((await fix(26)).statusCode).toBe(422); // the stored value is 25 now
  });

  it('accepts an Anthropic temperature of 0 to 1 and OpenAI up to 2', async () => {
    const anthropic = await put(
      body({
        provider: {
          kind: 'anthropic',
          baseUrl: fake.anthropicBaseUrl,
          model: 'm',
          apiKey: fake.apiKey,
          temperature: 1,
        },
      }),
    );
    expect(anthropic.statusCode, anthropic.body).toBe(200);
    expect((await put(body({ provider: provider({ temperature: 2 }) }))).statusCode).toBe(200);
  });

  it('refuses excluded projects of another organisation, and keeps its own', async () => {
    const other = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/organizations',
      headers: admin.headers,
      payload: { key: 'llm-other', name: 'Other' },
    });
    expect(other.statusCode, other.body).toBe(201);
    const otherId = other.json().id as string;
    const foreign = await createProject(ctx, admin, {
      organizationId: otherId,
      key: 'llm-foreign',
    });
    const own = await createProject(ctx, admin, { organizationId: org, key: 'llm-own' });
    const res = await put(
      body({
        organizations: {
          [org]: {
            enabled: true,
            features: { explain: true, triage: false, fix: false },
            excludedProjectIds: [own.id, foreign.id],
          },
        },
      }),
    );
    expect(res.statusCode).toBe(422);
    expect(res.json().errors.map((e: { path: string }) => e.path)).toEqual([
      `body.organizations.${org}.excludedProjectIds.1`,
    ]);
    const ok = await put(
      body({
        organizations: {
          [org]: {
            enabled: true,
            features: { explain: true, triage: false, fix: false },
            excludedProjectIds: [own.id],
          },
          [otherId]: {
            enabled: false,
            features: { explain: false, triage: false, fix: false },
            excludedProjectIds: [foreign.id],
          },
        },
      }),
    );
    expect(ok.statusCode, ok.body).toBe(200);
    expect(ok.json().organizations[org].excludedProjectIds).toEqual([own.id]);
    expect(ok.json().organizations[otherId].enabled).toBe(false);
  });

  it('drops an excluded project that was deleted: GET leaves it out and a save is 200', async () => {
    const gone = await createProject(ctx, admin, { organizationId: org, key: 'llm-gone' });
    const kept = await createProject(ctx, admin, { organizationId: org, key: 'llm-kept' });
    const settings = body({
      organizations: {
        [org]: {
          enabled: true,
          features: { explain: true, triage: false, fix: false },
          excludedProjectIds: [gone.id, kept.id],
        },
      },
    });
    const saved = await put(settings);
    expect(saved.statusCode, saved.body).toBe(200);
    const deleted = await ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/projects/${gone.id}?confirm=llm-gone`,
      headers: admin.headers,
    });
    expect(deleted.statusCode, deleted.body).toBe(204);
    expect((await get()).json().organizations[org].excludedProjectIds).toEqual([kept.id]);
    // The settings page saves back what it last read, the deleted id included.
    const again = await put(settings);
    expect(again.statusCode, again.body).toBe(200);
    expect(again.json().organizations[org].excludedProjectIds).toEqual([kept.id]);
    const [row] = await ctx.db
      .select()
      .from(instanceSettings)
      .where(eq(instanceSettings.key, 'llm'));
    expect(JSON.stringify(row?.value)).not.toContain(gone.id);
  });

  it('tests the saved provider with a fixed prompt that holds no repository data', async () => {
    await put(body());
    const res = await test();
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({ ok: true, model: 'fake-openai-model', problem: null });
    expect(fake.requests).toHaveLength(1);
    const sent = fake.requests[0]!;
    expect(sent.body).not.toMatch(/QUALOR-DATA/);
    expect(sent.json).toEqual({
      model: 'fake-model',
      messages: [
        {
          role: 'system',
          content: 'Answer with the JSON object {"ok": true} and nothing else.',
        },
        { role: 'user', content: 'ping' },
      ],
      max_tokens: 20,
      response_format: { type: 'json_object' },
    });
    expect(sent.headers.authorization).toBe(`Bearer ${fake.apiKey}`);
    expect(res.body).not.toContain(fake.apiKey);
  });

  it('tests an Anthropic provider through its adapter', async () => {
    await put(
      body({
        provider: {
          kind: 'anthropic',
          baseUrl: fake.anthropicBaseUrl,
          model: 'claude-x',
          apiKey: fake.apiKey,
        },
      }),
    );
    expect((await test()).json()).toMatchObject({ ok: true, problem: null });
    expect(fake.requests[0]!.path).toBe('/v1/messages');
    expect(fake.requests[0]!.headers['x-api-key']).toBe(fake.apiKey);
    await put(body());
  });

  it('names the base URL and model in the test result on a 404', async () => {
    fake.enqueue({ status: 404, body: { error: { message: 'x' } } });
    expect((await test()).json()).toMatchObject({
      ok: false,
      problem: {
        code: 'PROVIDER_REJECTED_REQUEST',
        message: 'The provider refused the request (HTTP 404); check the base URL and model',
        providerStatus: 404,
      },
    });
  });

  it('reports a refused key and an unusable answer, never logging the key', async () => {
    fake.enqueue({ status: 401, body: { error: { message: `bad key ${fake.apiKey}` } } });
    const refused = await test();
    expect(refused.json()).toMatchObject({
      ok: false,
      problem: {
        code: 'PROVIDER_REFUSED_KEY',
        message: 'The provider refused the API key (HTTP 401)',
        providerStatus: 401,
      },
    });
    expect(refused.body).not.toContain(fake.apiKey);
    // A 403 keeps the code, and says the key may not do this rather than that it is wrong.
    fake.enqueue({ status: 403, body: { error: { message: `no credit ${fake.apiKey}` } } });
    const forbidden = await test();
    expect(forbidden.json()).toMatchObject({
      ok: false,
      problem: {
        code: 'PROVIDER_REFUSED_KEY',
        message:
          'The provider refused the request (HTTP 403): the key lacks access to this model, or the account has no credit',
        providerStatus: 403,
      },
    });
    expect(forbidden.body).not.toContain(fake.apiKey);
    fake.say('Sure! Here it is: {"ok": true}');
    expect((await test()).json()).toMatchObject({
      ok: false,
      problem: { code: 'MALFORMED_OUTPUT' },
    });
    expect(ctx.logs.join('\n')).not.toContain(fake.apiKey);
  });

  it('reports KEY_UNDECRYPTABLE for a key that no longer decrypts, and says so in GET', async () => {
    const key = encryptionKey(ctx.config.secretKey);
    await writeLlmSettings(ctx.db, {
      ...DEFAULT_LLM_SETTINGS,
      provider: {
        kind: 'openai',
        baseUrl: fake.openAiBaseUrl,
        model: 'fake-model',
        auth: 'bearer',
        jsonMode: 'json_object',
        maxTokensField: 'max_tokens',
        temperature: null,
        timeoutSeconds: 60,
        apiKeyEnc: encryptSecret(key, fake.apiKey, 'scm_connections.token_enc'),
      },
    });
    expect((await get()).json().provider).toMatchObject({ apiKeySet: true, apiKeyReadable: false });
    expect((await test()).json()).toMatchObject({
      ok: false,
      problem: { code: 'KEY_UNDECRYPTABLE', message: 'Set the API key again' },
    });
    expect(fake.requests).toHaveLength(0);
    await put(body());
  });

  it('allows at most 10 tests a minute per admin (429 RATE_LIMITED)', async () => {
    const u = await createUser(ctx, { username: 'llm-second-admin', isInstanceAdmin: true });
    const second = await login(ctx, u.username, u.password);
    for (let i = 0; i < 10; i += 1) expect((await test(second)).statusCode).toBe(200);
    const limited = await test(second);
    expect([limited.statusCode, limited.json().code]).toEqual([429, 'RATE_LIMITED']);
    expect(Number(limited.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('lets an admin-scoped token of an instance admin in; a write token and a project token get 403', async () => {
    const tokenOf = async (scopes: string[]) => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: admin.headers,
        payload: { name: `llm-${scopes.join('-')}`, scopes },
      });
      expect(res.statusCode, res.body).toBe(201);
      return bearer((res.json() as { token: string }).token);
    };
    const project = await createProject(ctx, admin, { organizationId: org, key: 'llm-token' });
    const projectToken = bearer(await createProjectToken(ctx, admin, project.id));
    for (const headers of [await tokenOf(['read', 'write']), projectToken]) {
      for (const method of ['GET', 'PUT'] as const) {
        const res = await ctx.app.inject({
          method,
          url: '/api/v0/system/llm',
          headers,
          ...(method === 'PUT' ? { payload: body() } : {}),
        });
        expect(res.statusCode, res.body).toBe(403);
      }
      const tested = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/system/llm/test',
        headers,
      });
      expect(tested.statusCode).toBe(403);
    }
    const adminToken = await tokenOf(['admin']);
    const read = await ctx.app.inject({
      method: 'GET',
      url: '/api/v0/system/llm',
      headers: adminToken,
    });
    expect(read.statusCode, read.body).toBe(200);
    const saved = await ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/system/llm',
      headers: adminToken,
      payload: body(),
    });
    expect(saved.statusCode, saved.body).toBe(200);
  });

  it('stores the openai-only fields at their defaults for an Anthropic provider', async () => {
    const res = await put(
      body({
        provider: {
          kind: 'anthropic',
          baseUrl: fake.anthropicBaseUrl,
          model: 'claude-x',
          apiKey: fake.apiKey,
          auth: 'api-key',
          jsonMode: 'none',
          maxTokensField: 'max_completion_tokens',
        },
      }),
    );
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json().provider).toMatchObject({
      kind: 'anthropic',
      auth: 'bearer',
      jsonMode: 'json_object',
      maxTokensField: 'max_tokens',
    });
    await put(body());
  });

  it('names a missing /v1 on a 404 from an OpenAI-compatible base URL without a version path', async () => {
    const root = new URL(fake.openAiBaseUrl).origin;
    expect((await put(body({ provider: provider({ baseUrl: root }) }))).statusCode).toBe(200);
    try {
      // The fake has nothing at /chat/completions of its root: a 404, as a real server gives.
      const res = (await test()).json();
      expect(fake.requests[0]!.path).toBe('/chat/completions');
      expect(res.problem.code).toBe('PROVIDER_REJECTED_REQUEST');
      expect(res.problem.message).toContain('/v1');
    } finally {
      await put(body());
    }
  });

  it('runs one test at a time per admin, and cuts a long model name at a whole character', async () => {
    const u = await createUser(ctx, { username: 'llm-one-test', isInstanceAdmin: true });
    const s = await login(ctx, u.username, u.password);
    await put(body());
    fake.enqueue(async () => {
      await new Promise((r) => setTimeout(r, 500));
      return {
        status: 200,
        body: { ...(openAiAnswer('{"ok": true}') as object), model: `${'m'.repeat(199)}😀x` },
      };
    });
    const [a, b] = await Promise.all([test(s), test(s)]);
    const codes = [a.statusCode, b.statusCode].sort();
    expect(codes).toEqual([200, 429]);
    const ok = a.statusCode === 200 ? a : b;
    expect(ok.json().model).toBe('m'.repeat(199));
    expect(fake.requests).toHaveLength(1);
    // Done: the next one runs.
    expect((await test(s)).statusCode).toBe(200);
  });

  it('is 409 AI_DISABLED to test without a provider', async () => {
    await put(body({ provider: null }));
    const res = await test();
    expect(res.statusCode).toBe(409);
    expect(res.json().code).toBe('AI_DISABLED');
  });
});

describe('/system/llm and QUALOR_SCM_INTERNAL_HOSTS (llm.md §4)', () => {
  let ctx: TestContext;
  let fake: FakeLlm;

  beforeAll(async () => {
    fake = await createFakeLlm();
    ctx = await createTestContext({
      config: { scmInternalHosts: parseInternalHosts(fake.host) },
    });
  });
  afterAll(async () => {
    await ctx.close();
    await fake.close();
  });

  it('does not let the SCM list open a base URL to the model', async () => {
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/system/llm',
      headers: admin.headers,
      payload: {
        provider: { kind: 'openai', baseUrl: fake.openAiBaseUrl, model: 'm', apiKey: null },
        organizations: {},
        excludePaths: [],
        budgets: DEFAULT_LLM_SETTINGS.budgets,
        pricing: null,
        storePrompts: false,
        promptRetentionDays: 7,
      },
    });
    expect(res.statusCode).toBe(422);
    expect(res.json().errors[0]).toMatchObject({
      path: 'body.provider.baseUrl',
      message: expect.stringMatching(/QUALOR_LLM_INTERNAL_HOSTS/),
    });
    expect(fake.requests).toHaveLength(0);
  });
});
