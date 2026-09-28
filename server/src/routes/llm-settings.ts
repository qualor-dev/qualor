import { sql } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import { parseModelJson } from '@qualor/shared';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { requireInstanceAdmin } from '../auth/access';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Executor } from '../db/client';
import { uuidList } from '../db/bulk';
import { LOCKS } from '../db/locks';
import { organizations, projects, type EncryptedValue } from '../db/schema';
import { conflict, ProblemError, validationFailed, type FieldError } from '../http/problem';
import { noNul } from '../http/schemas';
import { VERSION } from '../index';
import { IssueChangeLimiter } from '../issues/rate-limit';
import type { LlmLimits } from '../limits';
import { ERROR_TEXTS, errorCodeOf, LLM_ERROR_CODES, type LlmErrorCode } from '../llm/errors';
import { callProvider, LlmError, PROVIDER_KINDS } from '../llm/providers';
import {
  ANTHROPIC_TEMPERATURE_TEXT,
  budgetsSchema,
  globSchema,
  LLM_API_KEY_AAD,
  MAX_LLM_ORGANIZATIONS,
  MAX_TEMPERATURE,
  MODEL_PATTERN,
  orgLlmSettingsSchema,
  pricingSchema,
  providerApiKey,
  providerConfig,
  readLlmSettings,
  writeLlmSettings,
  type OrgLlmSettings,
  type StoredLlmSettings,
  type StoredProvider,
} from '../llm/settings';
import { llmBaseUrlProblem } from '../llm/url';
import { normalBaseUrl } from '../scm/url';

/** llm.md §16: at most this many Test button presses per admin and minute. */
const TESTS_PER_MINUTE = 10;

/**
 * llm.md §3.2: 1–4 096 printable ASCII characters without spaces (header-safe). The message never
 * repeats the value.
 */
const API_KEY_PATTERN = /^[\x21-\x7e]{1,4096}$/;

const providerBody = z.strictObject({
  kind: z.enum(PROVIDER_KINDS),
  baseUrl: noNul(z.string().min(1).max(2_048)),
  model: z.string().regex(MODEL_PATTERN, 'Letters, digits and . _ : / @ + - only, at most 200'),
  auth: z.enum(['bearer', 'api-key']).default('bearer'),
  jsonMode: z.enum(['json_object', 'none']).default('json_object'),
  maxTokensField: z.enum(['max_tokens', 'max_completion_tokens']).default('max_tokens'),
  temperature: z.number().min(0).max(2).nullable().default(null),
  timeoutSeconds: z.number().int().min(5).max(600).default(60),
  apiKey: z
    .string()
    .regex(API_KEY_PATTERN, '1–4 096 printable ASCII characters without spaces')
    .nullable()
    .optional()
    .meta({
      description:
        'Write-only. A string sets the key, null removes it (a local model), absent keeps it; a new base URL needs it again',
    }),
});

const settingsBody = z.strictObject({
  provider: providerBody.nullable(),
  organizations: z
    .record(z.uuid(), orgLlmSettingsSchema)
    .refine(
      (o) => Object.keys(o).length <= MAX_LLM_ORGANIZATIONS,
      `At most ${MAX_LLM_ORGANIZATIONS} organisations`,
    ),
  excludePaths: z.array(globSchema).max(100),
  budgets: budgetsSchema,
  pricing: pricingSchema,
  storePrompts: z.boolean(),
  promptRetentionDays: z.number().int().min(1).max(90),
});
type SettingsBody = z.infer<typeof settingsBody>;

const settingsDto = z.object({
  provider: z
    .object({
      kind: z.enum(PROVIDER_KINDS),
      baseUrl: z.string(),
      model: z.string(),
      auth: z.enum(['bearer', 'api-key']),
      jsonMode: z.enum(['json_object', 'none']),
      maxTokensField: z.enum(['max_tokens', 'max_completion_tokens']),
      temperature: z.number().nullable(),
      timeoutSeconds: z.number().int(),
      /** A key is stored (never the key itself). */
      apiKeySet: z.boolean(),
      /** False when the stored key no longer decrypts (QUALOR_SECRET_KEY changed). */
      apiKeyReadable: z.boolean(),
    })
    .nullable(),
  organizations: z.record(z.string(), orgLlmSettingsSchema),
  excludePaths: z.array(z.string()),
  budgets: budgetsSchema,
  pricing: pricingSchema,
  storePrompts: z.boolean(),
  promptRetentionDays: z.number().int(),
  /** The community ceiling of `budgets.fixPerDay` (llm.md §13), for the settings page's note. */
  maxFixPerDay: z.number().int(),
});

const testResult = z.object({
  ok: z.boolean(),
  model: z.string().nullable(),
  latencyMs: z.number().int(),
  problem: z.object({ code: z.enum(LLM_ERROR_CODES), message: z.string() }).nullable(),
});
type TestResult = z.infer<typeof testResult>;

/**
 * llm.md §3.2: the model name as the provider gave it, at most 200 UTF-16 units, never cut inside
 * a surrogate pair.
 */
function modelName(model: string): string {
  if (model.length <= 200) return model;
  const cut = model.slice(0, 200);
  return /[\uD800-\uDBFF]$/.test(cut) ? cut.slice(0, -1) : cut;
}

/**
 * llm.md §16, Review Focus 1: a 404 from an OpenAI-compatible base URL without a version path is
 * almost always a missing `/v1`: the Test result names it.
 */
function missingV1Hint(provider: StoredProvider, status: number | null): string {
  if (status !== 404 || provider.kind !== 'openai') return '';
  const path = new URL(provider.baseUrl).pathname;
  return /\/v\d+(?:beta)?(?:\/|$)/.test(path)
    ? ''
    : ' (the base URL has no version path: most OpenAI-compatible servers need /v1 at its end)';
}

/** llm.md §16: the Test button's prompt holds no repository data. */
const TEST_CALL = {
  system: 'Answer with the JSON object {"ok": true} and nothing else.',
  user: 'ping',
  maxOutputTokens: 20,
};

/**
 * The owner of each project id still in the database (a deleted project is absent). Used to drop
 * the excluded ids of projects deleted since the settings were saved (llm.md §3.3): an id that no
 * longer exists excludes nothing, and must not stop an admin from saving.
 */
async function projectOwners(db: Executor, ids: readonly string[]): Promise<Map<string, string>> {
  const owners = new Map<string, string>();
  if (ids.length === 0) return owners;
  const rows = await db
    .select({ id: projects.id, organizationId: projects.organizationId })
    .from(projects)
    .where(sql`${projects.id} IN ${uuidList([...new Set(ids)])}`);
  for (const r of rows) owners.set(r.id, r.organizationId);
  return owners;
}

const excludedIdsOf = (organizations: Record<string, OrgLlmSettings>) =>
  Object.values(organizations).flatMap((o) => o.excludedProjectIds);

/** `organizations` without the excluded ids of projects that no longer exist. */
function withoutDeletedProjects(
  organizations: Record<string, OrgLlmSettings>,
  owners: ReadonlyMap<string, string>,
): Record<string, OrgLlmSettings> {
  return Object.fromEntries(
    Object.entries(organizations).map(([id, o]) => [
      id,
      { ...o, excludedProjectIds: o.excludedProjectIds.filter((p) => owners.has(p)) },
    ]),
  );
}

function dto(
  s: StoredLlmSettings,
  secretKey: string,
  limits: LlmLimits,
): z.infer<typeof settingsDto> {
  return {
    provider: s.provider && {
      ...providerConfig(s.provider),
      apiKeySet: s.provider.apiKeyEnc !== null,
      apiKeyReadable: providerApiKey(s, secretKey).ok,
    },
    organizations: s.organizations,
    excludePaths: s.excludePaths,
    budgets: s.budgets,
    pricing: s.pricing,
    storePrompts: s.storePrompts,
    promptRetentionDays: s.promptRetentionDays,
    maxFixPerDay: limits.maxFixPerOrganizationPerDay,
  };
}

/**
 * llm.md §3.2: a stored key is only ever sent to the address it was entered for. `baseUrl` is
 * already normalised; `'needs_key'` when the address is new and no key (or null) came with it.
 */
function nextKey(
  current: StoredProvider | null,
  incoming: { baseUrl: string; apiKey?: string | null | undefined },
  key: Buffer,
): EncryptedValue | null | 'needs_key' {
  const moved = current === null || incoming.baseUrl !== current.baseUrl;
  if (incoming.apiKey === undefined) return moved ? 'needs_key' : current.apiKeyEnc;
  return incoming.apiKey === null ? null : encryptSecret(key, incoming.apiKey, LLM_API_KEY_AAD);
}

/** The names of the fields a write changed (never a value), for the audit log line. */
function changedFields(
  current: StoredLlmSettings,
  next: StoredLlmSettings,
  keySent: boolean,
): string[] {
  const fields: string[] = [];
  const differs = (a: unknown, b: unknown) => JSON.stringify(a) !== JSON.stringify(b);
  if (current.provider === null || next.provider === null) {
    if (current.provider !== next.provider) fields.push('provider');
  } else {
    const before = providerConfig(current.provider);
    const after = providerConfig(next.provider);
    for (const k of Object.keys(after) as (keyof typeof after)[]) {
      if (differs(before[k], after[k])) fields.push(`provider.${k}`);
    }
  }
  if (keySent) fields.push('provider.apiKey');
  for (const k of [
    'organizations',
    'excludePaths',
    'budgets',
    'pricing',
    'storePrompts',
    'promptRetentionDays',
  ] as const) {
    if (differs(current[k], next[k])) fields.push(k);
  }
  return fields;
}

/** The top-level settings keys whose JSON differs (the provider without its key envelope). */
function changedTopLevelKeys(current: StoredLlmSettings, next: StoredLlmSettings): string[] {
  const provider = (s: StoredLlmSettings) => (s.provider ? providerConfig(s.provider) : null);
  // Keys sorted at every level: a row read back from jsonb has another key order than a body.
  const sorted = (_key: string, value: unknown): unknown =>
    value !== null && typeof value === 'object' && !Array.isArray(value)
      ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)))
      : value;
  const differs = (a: unknown, b: unknown) =>
    JSON.stringify(a, sorted) !== JSON.stringify(b, sorted);
  const fields: string[] = [];
  if (differs(provider(current), provider(next))) fields.push('provider');
  for (const k of [
    'organizations',
    'excludePaths',
    'budgets',
    'pricing',
    'storePrompts',
    'promptRetentionDays',
  ] as const) {
    if (differs(current[k], next[k])) fields.push(k);
  }
  return fields;
}

export const llmSettingsRoutes: FastifyPluginAsyncZod<{ deps: RouteDeps }> = async (
  app,
  { deps },
) => {
  const key = encryptionKey(deps.config.secretKey);
  const tests = new IssueChangeLimiter({ perMinute: TESTS_PER_MINUTE, burst: TESTS_PER_MINUTE });
  /** llm.md §16: one Test in flight per admin (a slow model must not pile up requests). */
  const testing = new Set<string>();

  /**
   * The checks the schema cannot make (llm.md §3–§4), every failing field at once. An excluded
   * project of another organisation is refused; one that no longer exists is dropped (`owners`).
   */
  const fieldProblems = (
    body: SettingsBody,
    known: ReadonlySet<string>,
    owners: ReadonlyMap<string, string>,
    storedFixPerDay: number,
  ): FieldError[] => {
    const errors: FieldError[] = [];
    if (body.provider) {
      const problem = llmBaseUrlProblem(body.provider.baseUrl, deps.config.llmInternalHosts);
      if (problem) errors.push({ path: 'body.provider.baseUrl', message: problem });
      const temperature = body.provider.temperature;
      if (temperature !== null && temperature > MAX_TEMPERATURE[body.provider.kind]) {
        errors.push({ path: 'body.provider.temperature', message: ANTHROPIC_TEMPERATURE_TEXT });
      }
    }
    // enterprise.md §7.2: a budget saved while a licence allowed more is kept (and clamped at
    // use); only a raise above this edition's ceiling is refused, so the form still saves.
    const ceiling = deps.edition.limits().llm.maxFixPerOrganizationPerDay;
    const fixPerDay = body.budgets.fixPerDay;
    if (fixPerDay > ceiling && fixPerDay > storedFixPerDay) {
      errors.push({
        path: 'body.budgets.fixPerDay',
        message: `At most ${ceiling} in this edition`,
      });
    }
    for (const [id, o] of Object.entries(body.organizations)) {
      if (!known.has(id)) {
        errors.push({ path: `body.organizations.${id}`, message: 'No such organisation' });
        continue;
      }
      o.excludedProjectIds.forEach((projectId, i) => {
        const owner = owners.get(projectId);
        if (owner !== undefined && owner !== id) {
          errors.push({
            path: `body.organizations.${id}.excludedProjectIds.${i}`,
            message: 'Not a project of this organisation',
          });
        }
      });
    }
    return errors;
  };

  /** The organisations of `ids` that exist. */
  const knownOrganizations = async (ids: readonly string[]): Promise<Set<string>> => {
    if (ids.length === 0) return new Set();
    const found = await deps.db
      .select({ id: organizations.id })
      .from(organizations)
      .where(sql`${organizations.id} IN ${uuidList(ids)}`);
    return new Set(found.map((r) => r.id));
  };

  /** The settings as stored, without excluded projects deleted since they were saved. */
  const readForAdmin = async (): Promise<StoredLlmSettings> => {
    const settings = await readLlmSettings(deps.db);
    const owners = await projectOwners(deps.db, excludedIdsOf(settings.organizations));
    return {
      ...settings,
      organizations: withoutDeletedProjects(settings.organizations, owners),
    };
  };

  app.get(
    '/system/llm',
    {
      schema: {
        tags: ['llm'],
        summary: 'The AI assistant settings (instance admins); never the API key',
        response: { 200: settingsDto },
      },
    },
    async (request) => {
      requireInstanceAdmin(request);
      return dto(await readForAdmin(), deps.config.secretKey, deps.edition.limits().llm);
    },
  );

  app.put(
    '/system/llm',
    {
      schema: {
        tags: ['llm'],
        summary:
          'Replace the AI assistant settings (instance admins); the API key is write-only, and a new base URL needs it again',
        body: settingsBody,
        response: { 200: settingsDto },
      },
    },
    async (request) => {
      const principal = requireInstanceAdmin(request);
      const body = request.body;
      const owners = await projectOwners(deps.db, excludedIdsOf(body.organizations));
      const known = await knownOrganizations(Object.keys(body.organizations));
      const stored = await readLlmSettings(deps.db);
      const errors = fieldProblems(body, known, owners, stored.budgets.fixPerDay);
      if (errors.length > 0) throw validationFailed(errors);
      const { current, next } = await deps.db.transaction(async (tx) => {
        await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.llmSettings})`);
        const current = await readLlmSettings(tx);
        let provider: StoredProvider | null = null;
        if (body.provider) {
          const { apiKey, ...given } = body.provider;
          // llm.md §3.2: `auth`, `jsonMode` and `maxTokensField` are the `openai` adapter's; an
          // Anthropic provider stores their defaults, whatever the form sent.
          const rest =
            given.kind === 'anthropic'
              ? {
                  ...given,
                  auth: 'bearer' as const,
                  jsonMode: 'json_object' as const,
                  maxTokensField: 'max_tokens' as const,
                }
              : given;
          const baseUrl = normalBaseUrl(rest.baseUrl);
          const apiKeyEnc = nextKey(current.provider, { baseUrl, apiKey }, key);
          if (apiKeyEnc === 'needs_key') {
            throw validationFailed([
              {
                path: 'body.provider.apiKey',
                message: 'Enter the API key again for a new address (null for none)',
              },
            ]);
          }
          provider = { ...rest, baseUrl, apiKeyEnc };
        }
        const next: StoredLlmSettings = {
          v: 1,
          provider,
          // A project deleted meanwhile (or since the page read the settings) is dropped.
          organizations: withoutDeletedProjects(body.organizations, owners),
          excludePaths: body.excludePaths,
          budgets: body.budgets,
          pricing: body.pricing,
          storePrompts: body.storePrompts,
          promptRetentionDays: body.promptRetentionDays,
        };
        await writeLlmSettings(tx, next);
        // rbac-audit.md §8: names of the top-level keys that changed and what became of the key,
        // never a value.
        const given = body.provider?.apiKey;
        await deps.audit.record(tx, actorOf(request), [
          {
            action: 'ai.settings_updated',
            target: { type: 'ai_settings', id: 'llm' },
            details: {
              changed: changedTopLevelKeys(current, next),
              apiKey:
                typeof given === 'string'
                  ? 'set'
                  : (given === null || body.provider === null) && current.provider?.apiKeyEnc
                    ? 'removed'
                    : 'kept',
            },
          },
        ]);
        return { current, next };
      });
      const keySent = body.provider !== null && body.provider.apiKey !== undefined;
      request.log.info(
        { userId: principal.user.id, fields: changedFields(current, next, keySent) },
        'LLM settings changed',
      );
      return dto(next, deps.config.secretKey, deps.edition.limits().llm);
    },
  );

  app.post(
    '/system/llm/test',
    {
      config: {
        openapi: {
          problems: [409, 429],
          problemDescriptions: {
            409: 'No LLM provider is configured (AI_DISABLED)',
            429: 'More than 10 tests a minute by this user, or one of theirs still running (RATE_LIMITED); see Retry-After',
          },
        },
      },
      schema: {
        tags: ['llm'],
        summary:
          'Send a fixed prompt holding no repository data to the saved provider (instance admins); no audit row, no quota',
        response: { 200: testResult },
      },
    },
    async (request): Promise<TestResult> => {
      const principal = requireInstanceAdmin(request);
      const userId = principal.user.id;
      if (testing.has(userId)) {
        throw new ProblemError(429, 'RATE_LIMITED', 'A test of the provider is already running', {
          headers: { 'retry-after': '5' },
        });
      }
      const wait = tests.take(userId, 1);
      if (wait !== null) {
        throw new ProblemError(429, 'RATE_LIMITED', `Too many tests; retry in ${wait} s`, {
          headers: { 'retry-after': String(wait) },
        });
      }
      testing.add(userId);
      try {
        return await runTest();
      } finally {
        testing.delete(userId);
      }
    },
  );

  async function runTest(): Promise<TestResult> {
    const settings = await readLlmSettings(deps.db);
    if (!settings.provider) throw conflict('AI_DISABLED', 'No LLM provider is configured');
    const apiKey = providerApiKey(settings, deps.config.secretKey);
    const failed = (code: LlmErrorCode, message: string, latencyMs: number): TestResult => ({
      ok: false,
      model: null,
      latencyMs,
      problem: { code, message },
    });
    if (!apiKey.ok) return failed('KEY_UNDECRYPTABLE', ERROR_TEXTS.KEY_UNDECRYPTABLE, 0);
    const started = Date.now();
    try {
      const answer = await callProvider(providerConfig(settings.provider), apiKey.key, TEST_CALL, {
        internalHosts: deps.config.llmInternalHosts,
        version: VERSION,
      });
      const latencyMs = Date.now() - started;
      // The model name is the provider's text: bounded, and never anything holding the key.
      const model =
        answer.model === null || (apiKey.key !== null && answer.model.includes(apiKey.key))
          ? null
          : modelName(answer.model);
      const code: LlmErrorCode | null =
        answer.finishReason === 'length'
          ? 'OUTPUT_TRUNCATED'
          : answer.finishReason === 'refusal'
            ? 'MODEL_REFUSED'
            : answer.finishReason === 'tool' || parseModelJson(answer.text) === undefined
              ? 'MALFORMED_OUTPUT'
              : null;
      return {
        ok: code === null,
        model,
        latencyMs,
        problem: code === null ? null : { code, message: ERROR_TEXTS[code] },
      };
    } catch (err) {
      if (!(err instanceof LlmError)) throw err;
      return failed(
        errorCodeOf(err),
        err.message + missingV1Hint(settings.provider, err.status),
        Date.now() - started,
      );
    }
  }
};
