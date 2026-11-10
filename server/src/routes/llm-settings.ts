import { sql } from 'drizzle-orm';
import type { FastifyPluginAsyncZod } from 'fastify-type-provider-zod';
import { z } from 'zod';
import { parseModelJson } from '@qualor/shared';
import type { RouteDeps } from '../app';
import { actorOf } from '../audit/recorder';
import { requireInstanceAdmin } from '../auth/access';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { uuidList } from '../db/bulk';
import type { Executor } from '../db/client';
import { LOCKS } from '../db/locks';
import { organizations, type EncryptedValue } from '../db/schema';
import { conflict, ProblemError, validationFailed, type FieldError } from '../http/problem';
import { noNul } from '../http/schemas';
import { VERSION } from '../index';
import { IssueChangeLimiter } from '../issues/rate-limit';
import { ERROR_TEXTS, errorCodeOf, LLM_ERROR_CODES, type LlmErrorCode } from '../llm/errors';
import {
  freshTest,
  readStoredTest,
  storedTestSchema,
  testFingerprint,
  writeStoredTest,
  type StoredTest,
} from '../llm/last-test';
import {
  callProvider,
  converse,
  LlmError,
  PROVIDER_APIS,
  PROVIDER_KINDS,
  REASONING_ALLOWANCE_TOKENS,
  type LlmConversation,
  type LlmToolSpec,
  type ProviderConfig,
  type ProviderHttpOptions,
} from '../llm/providers';
import {
  ANTHROPIC_NO_TEMPERATURE_TEXT,
  autoFixSettingsSchema,
  budgetsSchema,
  comparedProvider,
  CONTEXT_WINDOW_MAX_TOKENS,
  CONTEXT_WINDOW_MIN_TOKENS,
  DEFAULT_AUTO_FIX,
  DISABLED_ORGANIZATION,
  globSchema,
  LLM_API_KEY_AAD,
  MAX_LLM_ORGANIZATIONS,
  MAX_ORGANIZATION_PROJECT_IDS,
  MODEL_PATTERN,
  organizationSettings,
  orgLlmSettingsSchema,
  ownModel,
  pricingSchema,
  projectOwners,
  providerApiKey,
  providerConfig,
  readLlmSettings,
  WORKSPACE_ID_PATTERN,
  writeLlmSettings,
  type OrgLlmSettings,
  type StoredLlmSettings,
  type StoredProvider,
} from '../llm/settings';
import { llmBaseUrlProblem } from '../llm/url';
import { refusedForTools } from '../review/conversation';
import { queueSnapshotPurge } from '../review/jobs';
import { tierModels } from '../review/model-tiers';
import { consentCurrent, isDefaultReview } from '../review/settings';
import { normalBaseUrl } from '../scm/url';

/** llm.md §16: at most this many Test button presses per admin and minute. */
const TESTS_PER_MINUTE = 10;

/**
 * llm.md §3.2: 1–4 096 printable ASCII characters without spaces (header-safe). The message never
 * repeats the value.
 */
const API_KEY_PATTERN = /^[\x21-\x7e]{1,4096}$/;

const modelField = z
  .string()
  .regex(MODEL_PATTERN, 'Letters, digits and . _ : / @ + - only, at most 200');

const providerBody = z.strictObject({
  kind: z.enum(PROVIDER_KINDS),
  api: z.enum(PROVIDER_APIS).default('chat_completions').meta({
    description:
      "OpenAI-compatible providers only: `chat_completions` (the default; what vLLM, Ollama, LiteLLM and Azure deployments serve) or `responses`, OpenAI's Responses API, which its newest models need for function tools. Stored as `chat_completions` for another kind",
  }),
  baseUrl: noNul(z.string().min(1).max(2_048)),
  model: modelField.meta({
    description:
      'The standard model: explain, triage and fix use it, and so does a step of an AI review whose tier has no model of its own',
  }),
  strongModel: modelField.nullable().default(null).meta({
    description:
      "The model of AI review's strong tier (the judge and the verification of findings). Null or absent: the standard model",
  }),
  fastModel: modelField.nullable().default(null).meta({
    description:
      "The model of AI review's fast tier (the quality reviewer of a small merge request). Null or absent: the standard model",
  }),
  auth: z.enum(['bearer', 'api-key']).default('bearer'),
  jsonMode: z.enum(['json_object', 'none']).default('json_object'),
  maxTokensField: z.enum(['max_tokens', 'max_completion_tokens']).default('max_tokens'),
  temperature: z.number().min(0).max(2).nullable().default(null).meta({
    description:
      "OpenAI-compatible providers only (0 to 2). Anthropic's current models take none: one for an Anthropic provider is a 422",
  }),
  workspaceId: z
    .string()
    .regex(WORKSPACE_ID_PATTERN, 'wrkspc_ and then 1 to 64 letters or digits')
    .nullable()
    .default(null)
    .meta({
      description:
        'Anthropic only: the workspace that an organisation-wide key, which is not scoped to one, names in every request (the header anthropic-workspace-id). Not a secret. Null or absent: none; stored as null for another kind',
    }),
  timeoutSeconds: z.number().int().min(5).max(600).default(60),
  contextWindowTokens: z
    .number()
    .int()
    .min(CONTEXT_WINDOW_MIN_TOKENS)
    .max(CONTEXT_WINDOW_MAX_TOKENS)
    .nullable()
    .default(null)
    .meta({
      description:
        "The model's context window, in tokens, for every model of the provider: no call of an AI review or of an answer to a reply sends more than it less the room for the answer. Null or absent: 1 000 000. A change of it keeps the last Test and the organisations' consent",
    }),
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

/**
 * An organisation as this route reads and writes it. 6I-2: without its `review` block, which only
 * `PUT /organizations/{id}/ai/review` changes: AI review is the organisation admin's to switch on,
 * and acknowledging the data-sharing notice is theirs to give, so the instance admin's save neither
 * shows nor sets it and always keeps what is stored. The answer shows a derived, read-only view of
 * it instead: `reviewStatus`.
 */
const orgSettingsWithoutReview = orgLlmSettingsSchema.omit({ review: true });

/**
 * An organisation in the body. 4E-3a §2: the auto-fix fields may be left out (a form that does not
 * know them), which keeps what is stored, so a save never undoes an organisation admin's choice.
 * `reviewStatus` is the answer's read-only field: a body that is the answer put back carries it, and
 * it is neither checked nor stored.
 */
const orgBody = orgSettingsWithoutReview.extend({
  autoFix: autoFixSettingsSchema.optional().meta({ description: 'Absent keeps the stored value' }),
  autoFixDisabledProjectIds: z
    .array(z.uuid())
    .max(MAX_ORGANIZATION_PROJECT_IDS)
    .optional()
    .meta({ description: 'Absent keeps the stored value' }),
  reviewStatus: z
    .unknown()
    .optional()
    .meta({ description: 'Read-only, as GET answers it: ignored' }),
});
type OrgBody = z.infer<typeof orgBody>;

/**
 * An entry that says no more than an absent one (llm.md §3.3: disabled, nothing excluded, the
 * auto-fix defaults). The organisation and project auto-fix routes create such entries, so they
 * do not count towards MAX_LLM_ORGANIZATIONS.
 */
function isDisabledDefault(o: OrgBody): boolean {
  const autoFix = o.autoFix ?? DEFAULT_AUTO_FIX;
  return (
    !o.enabled &&
    !o.features.explain &&
    !o.features.triage &&
    !o.features.fix &&
    o.excludedProjectIds.length === 0 &&
    autoFix.enabled === DEFAULT_AUTO_FIX.enabled &&
    autoFix.minSeverity === DEFAULT_AUTO_FIX.minSeverity &&
    autoFix.maxPerAnalysis === DEFAULT_AUTO_FIX.maxPerAnalysis &&
    (o.autoFixDisabledProjectIds ?? []).length === 0
  );
}

/**
 * The budgets in the body. The instance ceiling on AI review may be left out, which keeps the
 * stored one (null removes it): a form that does not know it never undoes the administrator's
 * choice. Unlike the budgets the settings are stored with, it has no default.
 */
const budgetsBody = budgetsSchema.extend({
  reviewTokensPerOrganizationPerDay: budgetsSchema.shape.reviewTokensPerOrganizationPerDay
    .removeDefault()
    .optional()
    .meta({ description: 'Absent keeps the stored ceiling, null removes it' }),
});

const settingsBody = z.strictObject({
  provider: providerBody.nullable(),
  organizations: z
    .record(z.uuid(), orgBody)
    .refine(
      (o) =>
        Object.values(o).filter((entry) => !isDisabledDefault(entry)).length <=
        MAX_LLM_ORGANIZATIONS,
      `At most ${MAX_LLM_ORGANIZATIONS} organisations`,
    ),
  excludePaths: z.array(globSchema).max(100),
  budgets: budgetsBody,
  pricing: pricingSchema.meta({
    description:
      'USD per million tokens of the standard model, and of the strong and fast models (`strong`, `fast`), or null for no prices. With prices, a tier that has a model of its own needs its prices, and a tier without one takes none: either is a 422 at `pricing.strong` or `pricing.fast` ("Give the strong model\'s prices too", "Set the strong model first"). Each pair\'s `cachedInputUsdPerMTok` is the price of the input the provider read from its prompt cache; null or absent counts that input at the input price. What Anthropic writes to its cache is counted at 1.25 times the input price.',
  }),
  storePrompts: z.boolean(),
  promptRetentionDays: z.number().int().min(1).max(90),
  // The answer's read-only field, like an organisation's `reviewStatus`: a body that is the answer
  // put back carries it, and it is neither checked nor stored.
  lastTest: z.unknown().optional().meta({ description: 'Read-only, as GET answers it: ignored' }),
});
type SettingsBody = z.infer<typeof settingsBody>;

/**
 * The organisation's AI review as the instance admin sees it: the organisation's own switch and
 * consent (`PUT /organizations/{id}/ai/review`), shown here and never set here.
 */
const reviewStatusSchema = z.object({ enabled: z.boolean(), consentCurrent: z.boolean() }).meta({
  description:
    "Read-only: whether the organisation's admins switched AI review on, and whether their consent covers the provider configured now. The consent stays theirs",
});

/**
 * The last Test of the provider: who pressed Test, when, and what it found for each model, as codes
 * and never as the provider's words.
 */
const lastTestSchema = z.object({
  at: storedTestSchema.shape.at,
  userId: storedTestSchema.shape.userId,
  models: storedTestSchema.shape.models,
});

const settingsDto = z.object({
  provider: z
    .object({
      kind: z.enum(PROVIDER_KINDS),
      /** The API of an OpenAI-compatible provider; always `chat_completions` for Anthropic. */
      api: z.enum(PROVIDER_APIS),
      baseUrl: z.string(),
      /** The standard model. */
      model: z.string(),
      /** The model of AI review's strong tier; null: the standard model. */
      strongModel: z.string().nullable(),
      /** The model of AI review's fast tier; null: the standard model. */
      fastModel: z.string().nullable(),
      auth: z.enum(['bearer', 'api-key']),
      jsonMode: z.enum(['json_object', 'none']),
      maxTokensField: z.enum(['max_tokens', 'max_completion_tokens']),
      /** Always null for an Anthropic provider, whatever older settings hold: it takes none. */
      temperature: z.number().nullable(),
      /** The workspace an Anthropic provider's key is scoped to, as entered; not a secret. */
      workspaceId: z.string().nullable(),
      timeoutSeconds: z.number().int(),
      /** The model's context window, in tokens; null: 1 000 000. */
      contextWindowTokens: z.number().int().nullable(),
      /** A key is stored (never the key itself). */
      apiKeySet: z.boolean(),
      /** False when the stored key no longer decrypts (QUALOR_SECRET_KEY changed). */
      apiKeyReadable: z.boolean(),
    })
    .nullable(),
  organizations: z.record(
    z.string(),
    orgSettingsWithoutReview.extend({ reviewStatus: reviewStatusSchema }),
  ),
  excludePaths: z.array(z.string()),
  budgets: budgetsSchema,
  pricing: pricingSchema,
  storePrompts: z.boolean(),
  promptRetentionDays: z.number().int(),
  lastTest: lastTestSchema.nullable().meta({
    description:
      "Read-only. The outcome of the last `POST /system/llm/test` for each model of the provider, kept until the provider changes: another address, model or setting, or the key set again. `problemCode` is the code of the model's `problem` in the Test's answer. Null when there is no provider, or none has been tested since it changed",
  }),
});

/**
 * Whether the model can call tools, which AI review needs: `supported` when the check asked for a
 * call and got one, `not_supported` when it did not (the model answered in text, or the server
 * refused the tools), `not_checked` when the check could not tell (the plain test failed, the check
 * itself failed, or the model was cut off before it called the tool).
 */
const TOOL_CALLING = ['supported', 'not_supported', 'not_checked'] as const;
type ToolCalling = (typeof TOOL_CALLING)[number];

const testProblem = z.object({
  code: z.enum(LLM_ERROR_CODES),
  message: z.string(),
  /** The provider's HTTP status when it answered with an error (401 and 403 read apart). */
  providerStatus: z.number().int().nullable(),
});

/**
 * What the Test suggests changing, when it can tell: `USE_RESPONSES_API`, for a model that refused
 * tools through Chat Completions in words that say it takes them only through the Responses API.
 * The message is a fixed text, for API clients; the page words a hint itself.
 */
const TEST_HINT_CODES = ['USE_RESPONSES_API'] as const;
const testHint = z.object({ code: z.enum(TEST_HINT_CODES), message: z.string() });
type TestHint = z.infer<typeof testHint>;

/**
 * The Test's answer: the standard model's own fields (`ok`, `model`, `latencyMs`, `toolCalling`,
 * `problem`, which the answer had before the tiers, and `hint`), and the same for every model of the
 * provider.
 */
const testResult = z.object({
  ok: z.boolean(),
  /** The standard model's name as the provider gave it; null when it gave none, or the call failed. */
  model: z.string().nullable(),
  latencyMs: z.number().int(),
  toolCalling: z.enum(TOOL_CALLING),
  problem: testProblem.nullable(),
  hint: testHint.nullable().meta({
    description:
      'What to change, when the Test can tell: `USE_RESPONSES_API` says the model takes function tools only through the Responses API. Null: nothing to suggest',
  }),
  models: z
    .array(
      z.object({
        /** The first tier that uses the model. */
        tier: z.enum(['standard', 'strong', 'fast']),
        /** The model as configured. */
        model: z.string(),
        ok: z.boolean(),
        /**
         * The model's name as the provider gave it, at most 200 characters; null when it gave
         * none or one that holds the API key, or the call failed.
         */
        reportedModel: z.string().nullable(),
        latencyMs: z.number().int(),
        toolCalling: z.enum(TOOL_CALLING),
        problem: testProblem.nullable(),
        hint: testHint.nullable(),
      }),
    )
    .meta({
      description:
        "Every model of the provider, once each: the standard model first (its line repeats the answer's own fields), then the strong and the fast model unless they name a model already listed. Each is checked on its own, so one that fails never fails another",
    }),
});
type TestResult = z.infer<typeof testResult>;
type ModelTest = TestResult['models'][number];

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

/**
 * The tokens the answer of each call of the Test may hold: a short JSON object, or a sentence
 * before a tool call.
 */
const TEST_MAX_OUTPUT_TOKENS = 256;
/**
 * Both calls of the Test ask for those tokens and the room of the one-shot allowance besides, for a
 * model that thinks before it answers. Its thinking counts against the limit (with JSON mode,
 * OpenAI refuses a request whose limit the reasoning used up), so a model that thinks by default
 * would otherwise be cut off before its answer and fail a Test it passes in use. A model that
 * takes no limit that large is asked again without the room, as in use.
 */
const TEST_ROOM_TOKENS = REASONING_ALLOWANCE_TOKENS.singleShot;

/**
 * llm.md §16: the Test button's prompt holds no repository data. Its user message says JSON too:
 * the Responses API looks for that word in its input messages only, with JSON mode on, and does not
 * count its instructions, so the adapter has nothing to add to it.
 */
const TEST_CALL = {
  system: 'Answer with the JSON object {"ok": true} and nothing else.',
  user: 'Reply in JSON.',
  maxOutputTokens: TEST_MAX_OUTPUT_TOKENS,
  reasoningAllowance: TEST_ROOM_TOKENS,
};

/**
 * The tool-calling check that follows a passing Test, because only the review calls tools: a fixed
 * prompt holding no repository data and one read-only tool.
 */
const ECHO_TOOL: LlmToolSpec = {
  name: 'echo',
  description: 'Returns the text it is given.',
  parameters: { type: 'object', properties: { text: { type: 'string' } }, required: ['text'] },
};
const TOOL_CHECK: LlmConversation = {
  system: 'This is a connection check. Call the echo tool with the text ok.',
  messages: [{ role: 'user', text: 'Call the echo tool with the text ok.' }],
  tools: [ECHO_TOOL],
  maxOutputTokens: TEST_MAX_OUTPUT_TOKENS,
  reasoningAllowance: TEST_ROOM_TOKENS,
};

/** What the tool-calling check found, and what it suggests changing (the `hint`). */
interface ToolCheck {
  toolCalling: ToolCalling;
  hint: TestHint | null;
}
const UNCHECKED: ToolCheck = { toolCalling: 'not_checked', hint: null };

/**
 * Asks the model to call the echo tool. `supported`: the turn asks for a call. `not_supported`:
 * it asks for none (the model answered in text, or the server dropped the tools), or the provider
 * refused the request in words that name tools; when those words say that the model takes tools
 * only through the Responses API (asked through Chat Completions), the hint says so. `not_checked`:
 * the check failed in any other way, which says nothing of tools (a timeout, an unreachable or
 * rate-limiting provider, a refused key, an address that is not allowed, an answer that cannot be
 * read, a refusal that names no tools), or the output limit cut the model off before it called the
 * tool (a model that says what it will do first may use the limit up before it does it).
 * Like the plain test it leaves no usage row and no audit row and takes no quota.
 */
async function checkToolCalling(
  config: ProviderConfig,
  apiKey: string | null,
  http: ProviderHttpOptions,
): Promise<ToolCheck> {
  try {
    const turn = await converse(config, apiKey, TOOL_CHECK, http);
    if (turn.toolCalls.length > 0) return { toolCalling: 'supported', hint: null };
    return turn.finishReason === 'length'
      ? UNCHECKED
      : { toolCalling: 'not_supported', hint: null };
  } catch (err) {
    if (!(err instanceof LlmError)) throw err;
    // The error's own text is the fixed hint: never the provider's words.
    if (err.needsResponses) {
      return {
        toolCalling: 'not_supported',
        hint: { code: 'USE_RESPONSES_API', message: err.message },
      };
    }
    return refusedForTools(err, TOOL_CHECK.tools)
      ? { toolCalling: 'not_supported', hint: null }
      : UNCHECKED;
  }
}

/** What the Test found out about one model: a line of `models` without its tier and its model. */
type ModelCheck = Omit<ModelTest, 'tier' | 'model'>;

const failedCheck = (
  code: LlmErrorCode,
  message: string,
  latencyMs: number,
  providerStatus: number | null = null,
): ModelCheck => ({
  ok: false,
  reportedModel: null,
  latencyMs,
  ...UNCHECKED,
  problem: { code, message, providerStatus },
});

/**
 * The Test of one model, `provider`'s own settings with `model` in place of its standard model:
 * the plain call, and when it passes, the tool-calling check. Whatever goes wrong with it is that
 * model's failure alone.
 */
async function checkModel(
  provider: StoredProvider,
  model: string,
  apiKey: ReturnType<typeof providerApiKey>,
  http: ProviderHttpOptions,
): Promise<ModelCheck> {
  if (!apiKey.ok) return failedCheck('KEY_UNDECRYPTABLE', ERROR_TEXTS.KEY_UNDECRYPTABLE, 0);
  const config = { ...providerConfig(provider), model };
  const started = Date.now();
  try {
    const answer = await callProvider(config, apiKey.key, TEST_CALL, http);
    const latencyMs = Date.now() - started;
    // The model name is the provider's text: bounded, and never anything holding the key.
    const reportedModel =
      answer.model === null || (apiKey.key !== null && answer.model.includes(apiKey.key))
        ? null
        : modelName(answer.model);
    let code: LlmErrorCode | null = null;
    if (answer.finishReason === 'length') code = 'OUTPUT_TRUNCATED';
    else if (answer.finishReason === 'refusal') code = 'MODEL_REFUSED';
    else if (answer.finishReason === 'tool' || parseModelJson(answer.text) === undefined) {
      code = 'MALFORMED_OUTPUT';
    }
    return {
      ok: code === null,
      reportedModel,
      latencyMs,
      problem: code === null ? null : { code, message: ERROR_TEXTS[code], providerStatus: null },
      // Only a provider that answered the plain test is asked whether it calls tools.
      ...(code === null ? await checkToolCalling(config, apiKey.key, http) : UNCHECKED),
    };
  } catch (err) {
    if (!(err instanceof LlmError)) throw err;
    return failedCheck(
      errorCodeOf(err),
      err.message + missingV1Hint(provider, err.status),
      Date.now() - started,
      err.status,
    );
  }
}

/** Every project id the organisations list (excluded, or opted out of auto-fix). */
const listedProjectIdsOf = (
  organizations: Record<string, Pick<OrgBody, 'excludedProjectIds' | 'autoFixDisabledProjectIds'>>,
) =>
  Object.values(organizations).flatMap((o) => [
    ...o.excludedProjectIds,
    ...(o.autoFixDisabledProjectIds ?? []),
  ]);

/** `organizations` without the listed ids of projects that no longer exist (llm.md §3.3). */
function withoutDeletedProjects(
  organizations: Record<string, OrgLlmSettings>,
  owners: ReadonlyMap<string, string>,
): Record<string, OrgLlmSettings> {
  return Object.fromEntries(
    Object.entries(organizations).map(([id, o]) => [
      id,
      {
        ...o,
        excludedProjectIds: o.excludedProjectIds.filter((p) => owners.has(p)),
        // Each id once (a body may repeat one).
        autoFixDisabledProjectIds: [
          ...new Set(o.autoFixDisabledProjectIds.filter((p) => owners.has(p))),
        ],
      },
    ]),
  );
}

/** Which of the organisations still exist. */
async function existingOrganizations(db: Executor, ids: readonly string[]): Promise<Set<string>> {
  if (ids.length === 0) return new Set();
  const found = await db
    .select({ id: organizations.id })
    .from(organizations)
    .where(sql`${organizations.id} IN ${uuidList(ids)}`);
  return new Set(found.map((r) => r.id));
}

/** Whether a stored entry holds an auto-fix choice: a value other than the defaults. */
const hasAutoFixChoice = (o: OrgLlmSettings) =>
  o.autoFix.enabled !== DEFAULT_AUTO_FIX.enabled ||
  o.autoFix.minSeverity !== DEFAULT_AUTO_FIX.minSeverity ||
  o.autoFix.maxPerAnalysis !== DEFAULT_AUTO_FIX.maxPerAnalysis ||
  o.autoFixDisabledProjectIds.length > 0;

/** Whether a stored entry holds an AI review setting other than the defaults (6I-2). */
const hasReviewChoice = (o: OrgLlmSettings) => !isDefaultReview(o.review);

/**
 * The body's organisations, an auto-fix field left out keeping the stored one (4E-3a §2), and the
 * AI review block always the stored one (6I-2: the body cannot carry it). An organisation the body
 * leaves out loses its switches and exclusions, as before, but keeps its auto-fix choice and its AI
 * review: a form loaded before an organisation admin made them must not undo them. Its entry is
 * then the one the organisation's own routes create (disabled, the choices kept; review then
 * reports `organization_disabled`). `kept`: those organisations ({@link omittedWithChoice}) that
 * still exist.
 */
function withStoredChoices(
  organizations: Record<string, OrgBody>,
  current: StoredLlmSettings,
  kept: ReadonlySet<string>,
): Record<string, OrgLlmSettings> {
  return Object.fromEntries([
    ...[...kept].map((id): [string, OrgLlmSettings] => {
      const stored = organizationSettings(current, id);
      return [
        id,
        {
          ...DISABLED_ORGANIZATION,
          features: { ...DISABLED_ORGANIZATION.features },
          excludedProjectIds: [],
          autoFix: stored.autoFix,
          autoFixDisabledProjectIds: stored.autoFixDisabledProjectIds,
          review: stored.review,
        },
      ];
    }),
    ...Object.entries(organizations).map(([id, o]): [string, OrgLlmSettings] => {
      const stored = organizationSettings(current, id);
      // Field by field, never the body's entry spread: the settings row holds exactly the fields of
      // `OrgLlmSettings`, so a field the answer shows and the row does not store (`reviewStatus`)
      // never reaches it, where the row's schema would refuse it and read the whole row as none.
      return [
        id,
        {
          enabled: o.enabled,
          features: o.features,
          excludedProjectIds: o.excludedProjectIds,
          autoFix: o.autoFix ?? stored.autoFix,
          autoFixDisabledProjectIds:
            o.autoFixDisabledProjectIds ?? stored.autoFixDisabledProjectIds,
          review: stored.review,
        },
      ];
    }),
  ]);
}

/**
 * The ids of the organisations the body leaves out whose stored entry holds an auto-fix choice or
 * an AI review setting.
 */
const omittedWithChoice = (
  organizations: Record<string, OrgBody>,
  current: StoredLlmSettings,
): string[] =>
  Object.entries(current.organizations)
    .filter(
      ([id, o]) => !Object.hasOwn(organizations, id) && (hasAutoFixChoice(o) || hasReviewChoice(o)),
    )
    .map(([id]) => id);

/** 4E-3a §2: the organisations without their auto-fix fields, and with only those. */
const withoutAutoFix = (organizations: Record<string, OrgLlmSettings>) =>
  Object.fromEntries(
    Object.entries(organizations).map(([id, o]) => [
      id,
      { enabled: o.enabled, features: o.features, excludedProjectIds: o.excludedProjectIds },
    ]),
  );
const autoFixOf = (organizations: Record<string, OrgLlmSettings>) =>
  Object.fromEntries(
    Object.entries(organizations).map(([id, o]) => [
      id,
      { autoFix: o.autoFix, autoFixDisabledProjectIds: o.autoFixDisabledProjectIds },
    ]),
  );

/** The organisation as this route shows it: all of it but its AI review block (6I-2). */
const withoutReview = (o: OrgLlmSettings): z.infer<typeof orgSettingsWithoutReview> => ({
  enabled: o.enabled,
  features: o.features,
  excludedProjectIds: o.excludedProjectIds,
  autoFix: o.autoFix,
  autoFixDisabledProjectIds: o.autoFixDisabledProjectIds,
});

/**
 * The settings as the answers show them, with the last Test while it still describes the provider
 * (`test` is the stored one, fresh or not).
 */
function dto(
  s: StoredLlmSettings,
  secretKey: string,
  test: StoredTest | null,
): z.infer<typeof settingsDto> {
  const lastTest = freshTest(s, test);
  return {
    provider: s.provider && {
      ...providerConfig(s.provider),
      strongModel: s.provider.strongModel,
      fastModel: s.provider.fastModel,
      contextWindowTokens: s.provider.contextWindowTokens,
      apiKeySet: s.provider.apiKeyEnc !== null,
      apiKeyReadable: providerApiKey(s, secretKey).ok,
    },
    organizations: Object.fromEntries(
      Object.entries(s.organizations).map(([id, o]) => [
        id,
        {
          ...withoutReview(o),
          reviewStatus: { enabled: o.review.enabled, consentCurrent: consentCurrent(s, o.review) },
        },
      ]),
    ),
    excludePaths: s.excludePaths,
    budgets: s.budgets,
    pricing: s.pricing,
    storePrompts: s.storePrompts,
    promptRetentionDays: s.promptRetentionDays,
    // Field by field: the stored record also holds its fingerprint, which no answer shows.
    lastTest: lastTest && { at: lastTest.at, userId: lastTest.userId, models: lastTest.models },
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

/**
 * The provider's settings a write can change, without its key envelope: what the Test is tied to
 * (`comparedProvider`), and the model's context window, which it is not (R46).
 */
const changeableProvider = (p: StoredProvider) => ({
  ...comparedProvider(p),
  contextWindowTokens: p.contextWindowTokens,
});

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
    const before = changeableProvider(current.provider);
    const after = changeableProvider(next.provider);
    for (const k of Object.keys(after) as (keyof typeof after)[]) {
      if (differs(before[k], after[k])) fields.push(`provider.${k}`);
    }
  }
  if (keySent) fields.push('provider.apiKey');
  return [...fields, ...settingsFieldsChanged(current, next, differs)];
}

/**
 * The names of the settings outside the provider that differ. `organizations` names a change of an
 * organisation's switches or exclusions, `autoFix` one of its automatic fix suggestions or
 * opt-outs (4E-3a §2).
 */
function settingsFieldsChanged(
  current: StoredLlmSettings,
  next: StoredLlmSettings,
  differs: (a: unknown, b: unknown) => boolean,
): string[] {
  const fields: string[] = [];
  if (differs(withoutAutoFix(current.organizations), withoutAutoFix(next.organizations))) {
    fields.push('organizations');
  }
  if (differs(autoFixOf(current.organizations), autoFixOf(next.organizations))) {
    fields.push('autoFix');
  }
  for (const k of [
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

/** Code-unit order of two object keys (not locale-dependent). */
function compareKeys(a: string, b: string): number {
  if (a === b) return 0;
  return a < b ? -1 : 1;
}

/**
 * What an update did to the stored API key, for the audit log (never the key): a string sets it,
 * null (or no provider) removes a stored one, anything else keeps it.
 */
function apiKeyChange(
  given: string | null | undefined,
  providerRemoved: boolean,
  current: StoredLlmSettings,
): 'set' | 'removed' | 'kept' {
  if (typeof given === 'string') return 'set';
  return (given === null || providerRemoved) && current.provider?.apiKeyEnc ? 'removed' : 'kept';
}

/** The top-level settings keys whose JSON differs (the provider without its key envelope). */
function changedTopLevelKeys(current: StoredLlmSettings, next: StoredLlmSettings): string[] {
  const provider = (s: StoredLlmSettings) => (s.provider ? changeableProvider(s.provider) : null);
  // Keys sorted at every level: a row read back from jsonb has another key order than a body.
  const sorted = (_key: string, value: unknown): unknown =>
    value !== null && typeof value === 'object' && !Array.isArray(value)
      ? Object.fromEntries(Object.entries(value).sort(([a], [b]) => compareKeys(a, b)))
      : value;
  const differs = (a: unknown, b: unknown) =>
    JSON.stringify(a, sorted) !== JSON.stringify(b, sorted);
  const fields: string[] = [];
  if (differs(provider(current), provider(next))) fields.push('provider');
  return [...fields, ...settingsFieldsChanged(current, next, differs)];
}

/**
 * The prices of the tiers. With prices set, a tier with a model of its own is costed at that
 * model's price and so needs its pair; a pair for a tier without a model of its own prices nothing.
 */
function tierPriceProblems(
  provider: SettingsBody['provider'],
  pricing: NonNullable<SettingsBody['pricing']>,
): FieldError[] {
  const errors: FieldError[] = [];
  for (const tier of ['strong', 'fast'] as const) {
    const hasModel = provider !== null && ownModel(provider, tier) !== null;
    if (hasModel && pricing[tier] === null) {
      errors.push({ path: `body.pricing.${tier}`, message: `Give the ${tier} model's prices too` });
    } else if (!hasModel && pricing[tier] !== null) {
      errors.push({ path: `body.pricing.${tier}`, message: `Set the ${tier} model first` });
    }
  }
  return errors;
}

/** The projects an organisation's lists name that belong to another organisation (`owners`). */
function foreignProjectProblems(
  id: string,
  o: SettingsBody['organizations'][string],
  owners: ReadonlyMap<string, string>,
): FieldError[] {
  const errors: FieldError[] = [];
  for (const list of ['excludedProjectIds', 'autoFixDisabledProjectIds'] as const) {
    (o[list] ?? []).forEach((projectId, i) => {
      const owner = owners.get(projectId);
      if (owner !== undefined && owner !== id) {
        errors.push({
          path: `body.organizations.${id}.${list}.${i}`,
          message: 'Not a project of this organisation',
        });
      }
    });
  }
  return errors;
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
    stored: StoredLlmSettings,
  ): FieldError[] => {
    const errors: FieldError[] = [];
    if (body.provider) {
      const problem = llmBaseUrlProblem(body.provider.baseUrl, deps.config.llmInternalHosts);
      if (problem) errors.push({ path: 'body.provider.baseUrl', message: problem });
      // Anthropic's current models refuse a temperature (and every sampling parameter) with a 400.
      if (body.provider.kind === 'anthropic' && body.provider.temperature !== null) {
        errors.push({
          path: 'body.provider.temperature',
          message: ANTHROPIC_NO_TEMPERATURE_TEXT,
        });
      }
    }
    if (body.pricing !== null) errors.push(...tierPriceProblems(body.provider, body.pricing));
    for (const [id, o] of Object.entries(body.organizations)) {
      if (!known.has(id)) {
        errors.push({ path: `body.organizations.${id}`, message: 'No such organisation' });
        continue;
      }
      errors.push(...foreignProjectProblems(id, o, owners));
      // 4E-3a §2: only switching the automatic fix on needs the enterprise feature `llm.auto-fix`.
      // A switch-on saved while the licence allowed it is kept, so the form still saves after the
      // licence lapses.
      if (
        o.autoFix?.enabled === true &&
        !organizationSettings(stored, id).autoFix.enabled &&
        !deps.edition.limits().llm.automaticFixSuggestions
      ) {
        errors.push({
          path: `body.organizations.${id}.autoFix.enabled`,
          message: 'Needs the enterprise feature llm.auto-fix',
        });
      }
    }
    return errors;
  };

  /** The organisations of `ids` that exist. */
  const knownOrganizations = (ids: readonly string[]) => existingOrganizations(deps.db, ids);

  /** The settings as stored, without excluded projects deleted since they were saved. */
  const readForAdmin = async (): Promise<StoredLlmSettings> => {
    const settings = await readLlmSettings(deps.db);
    const owners = await projectOwners(deps.db, listedProjectIdsOf(settings.organizations));
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
        summary: 'The AI provider settings (instance admins); never the API key',
        response: { 200: settingsDto },
      },
    },
    async (request) => {
      requireInstanceAdmin(request);
      const [settings, test] = await Promise.all([readForAdmin(), readStoredTest(deps.db)]);
      return dto(settings, deps.config.secretKey, test);
    },
  );

  app.put(
    '/system/llm',
    {
      schema: {
        tags: ['llm'],
        summary:
          'Replace the AI provider settings (instance admins); the API key is write-only, and a new base URL needs it again',
        body: settingsBody,
        response: { 200: settingsDto },
      },
    },
    async (request) => {
      const principal = requireInstanceAdmin(request);
      const body = request.body;
      const owners = await projectOwners(deps.db, listedProjectIdsOf(body.organizations));
      const known = await knownOrganizations(Object.keys(body.organizations));
      const stored = await readLlmSettings(deps.db);
      const errors = fieldProblems(body, known, owners, stored);
      if (errors.length > 0) throw validationFailed(errors);
      const { current, next } = await deps.db.transaction(async (tx) => {
        await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.llmSettings})`);
        const current = await readLlmSettings(tx);
        let provider: StoredProvider | null = null;
        if (body.provider) {
          const { apiKey, ...given } = body.provider;
          // llm.md §3.2: `api`, `auth`, `jsonMode` and `maxTokensField` are the `openai` adapter's; an
          // Anthropic provider stores their defaults, whatever the form sent. The workspace is
          // the Anthropic adapter's: an OpenAI provider stores none.
          const rest =
            given.kind === 'anthropic'
              ? {
                  ...given,
                  api: 'chat_completions' as const,
                  auth: 'bearer' as const,
                  jsonMode: 'json_object' as const,
                  maxTokensField: 'max_tokens' as const,
                }
              : { ...given, workspaceId: null };
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
        const kept = await existingOrganizations(
          tx,
          omittedWithChoice(body.organizations, current),
        );
        const organizations = withStoredChoices(body.organizations, current, kept);
        // A project deleted meanwhile (or since the page read the settings) is dropped, a stored
        // opt-out the body left out included.
        const listed = await projectOwners(tx, listedProjectIdsOf(organizations));
        const next: StoredLlmSettings = {
          v: 1,
          provider,
          organizations: withoutDeletedProjects(organizations, listed),
          excludePaths: body.excludePaths,
          budgets: {
            ...body.budgets,
            reviewTokensPerOrganizationPerDay:
              body.budgets.reviewTokensPerOrganizationPerDay === undefined
                ? current.budgets.reviewTokensPerOrganizationPerDay
                : body.budgets.reviewTokensPerOrganizationPerDay,
          },
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
              apiKey: apiKeyChange(given, body.provider === null, current),
            },
          },
        ]);
        // Any of the settings can change which projects AI review covers (the provider, an
        // organisation's switches and exclusions): the snapshots of those it no longer covers are
        // deleted by a job, after this commit.
        await queueSnapshotPurge(tx, null);
        return { current, next };
      });
      const keySent = body.provider !== null && body.provider.apiKey !== undefined;
      request.log.info(
        { userId: principal.user.id, fields: changedFields(current, next, keySent) },
        'LLM settings changed',
      );
      return dto(next, deps.config.secretKey, await readStoredTest(deps.db));
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
          'Send a fixed prompt holding no repository data to each model of the saved provider at once, and when one answers, a second one that asks that model to call a tool (instance admins); no audit row, no quota. Its outcome is kept as `lastTest` of `GET /system/llm` until the provider changes',
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
        const { result, provider } = await runTest();
        // The record is of the provider that was tested, not of the one saved by now: a save while
        // the Test ran leaves it stale instead of passing it off as the new provider's.
        await writeStoredTest(deps.db, {
          v: 1,
          at: new Date().toISOString(),
          userId,
          fingerprint: testFingerprint(provider),
          models: result.models.map((m) => ({
            tier: m.tier,
            model: m.model,
            ok: m.ok,
            toolCalling: m.toolCalling,
            problemCode: m.problem?.code ?? null,
          })),
        });
        return result;
      } finally {
        testing.delete(userId);
      }
    },
  );

  /**
   * Tests every model of the saved provider at once, each on its own (the standard model, then the
   * strong and the fast model where they name another). The answer's own fields are the standard
   * model's. With it, the provider it tested.
   */
  async function runTest(): Promise<{ result: TestResult; provider: StoredProvider }> {
    const settings = await readLlmSettings(deps.db);
    const provider = settings.provider;
    if (!provider) throw conflict('AI_DISABLED', 'No LLM provider is configured');
    const apiKey = providerApiKey(settings, deps.config.secretKey);
    const http = { internalHosts: deps.config.llmInternalHosts, version: VERSION };
    const lineOf = async ({
      tier,
      model,
    }: Pick<ModelTest, 'tier' | 'model'>): Promise<ModelTest> => ({
      tier,
      model,
      ...(await checkModel(provider, model, apiKey, http)),
    });
    const [standard, ...others] = await Promise.all([
      lineOf({ tier: 'standard', model: provider.model }),
      ...tierModels(provider)
        .filter(({ tier }) => tier !== 'standard')
        .map(lineOf),
    ]);
    return {
      provider,
      result: {
        ok: standard.ok,
        model: standard.reportedModel,
        latencyMs: standard.latencyMs,
        toolCalling: standard.toolCalling,
        problem: standard.problem,
        hint: standard.hint,
        models: [standard, ...others],
      },
    };
  }
};
