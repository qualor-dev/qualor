import { SEVERITIES } from '@qualor/shared';
import { sql } from 'drizzle-orm';
import picomatch from 'picomatch';
import { z } from 'zod';
import { decryptSecret, encryptionKey } from '../crypto/secrets';
import type { Executor } from '../db/client';
import { uuidList } from '../db/bulk';
import { LOCKS } from '../db/locks';
import { instanceSettings, projects } from '../db/schema';
import type { ModelTier } from '../review/model-tiers';
import { defaultReview, MODEL_NAME_PATTERN, reviewSettingsSchema } from '../review/schema';
import { dropOrganizationEntry, instanceSetting } from '../settings';
import { PROVIDER_APIS, PROVIDER_KINDS, type ProviderConfig } from './providers';

export const LLM_SETTINGS_KEY = 'llm';
/** llm.md §3.2: the key's envelope decrypts only under this AAD. */
export const LLM_API_KEY_AAD = 'instance_settings.llm.apiKey';

const encrypted = z.strictObject({
  v: z.literal(1),
  iv: z.string(),
  ct: z.string(),
  tag: z.string(),
});

export const budgetsSchema = z.strictObject({
  explainPerDay: z.number().int().min(0).max(100_000),
  triagePerDay: z.number().int().min(0).max(100_000),
  fixPerDay: z.number().int().min(0).max(100_000),
  tokensPerDay: z.number().int().min(0).max(1_000_000_000),
  costPerDayUsd: z.number().min(0).max(1_000_000).nullable(),
  perUserPerHour: z.number().int().min(1).max(10_000),
  /**
   * 6I-2: the instance ceiling on an organisation's AI review tokens per UTC day; the effective
   * budget of an organisation is the smaller of this and its own. Null: no ceiling. A row stored
   * before it reads with null.
   */
  reviewTokensPerOrganizationPerDay: z
    .number()
    .int()
    .min(0)
    .max(1_000_000_000)
    .nullable()
    .default(null),
});
export type Budgets = z.infer<typeof budgetsSchema>;
export const DEFAULT_BUDGETS: Budgets = {
  explainPerDay: 200,
  triagePerDay: 100,
  fixPerDay: 25,
  tokensPerDay: 1_000_000,
  costPerDayUsd: null,
  perUserPerHour: 30,
  reviewTokensPerOrganizationPerDay: null,
};

/** 4E-3a §2: at most this many automatic fix suggestions per analysis. */
export const MAX_AUTO_FIX_PER_ANALYSIS = 25;
/** llm.md §3.3: at most this many ids in an organisation's project lists. */
export const MAX_ORGANIZATION_PROJECT_IDS = 1_000;

/**
 * 4E-3a §2 (llm.md §3.3): the organisation's automatic fix suggestions, for its new findings of
 * a merge request at or above `minSeverity`.
 */
export const autoFixSettingsSchema = z.strictObject({
  enabled: z.boolean(),
  minSeverity: z.enum(SEVERITIES),
  maxPerAnalysis: z.number().int().min(1).max(MAX_AUTO_FIX_PER_ANALYSIS),
});
export type AutoFixSettings = z.infer<typeof autoFixSettingsSchema>;
export const DEFAULT_AUTO_FIX: Readonly<AutoFixSettings> = Object.freeze({
  enabled: false,
  minSeverity: 'high',
  maxPerAnalysis: 10,
});

const projectIds = z.array(z.uuid()).max(MAX_ORGANIZATION_PROJECT_IDS);

/**
 * llm.md §3.3: an organisation's switches; at most 1 000 excluded and 1 000 opted-out projects. A
 * row stored before 4E-3 has neither auto-fix field and reads with the defaults, and one stored
 * before 6I-2 has no `review` block (its AI review: off, no consent).
 */
export const orgLlmSettingsSchema = z.strictObject({
  enabled: z.boolean(),
  features: z.strictObject({ explain: z.boolean(), triage: z.boolean(), fix: z.boolean() }),
  excludedProjectIds: projectIds,
  autoFix: autoFixSettingsSchema.default(() => ({ ...DEFAULT_AUTO_FIX })),
  autoFixDisabledProjectIds: projectIds.default(() => []),
  review: reviewSettingsSchema.default(() => defaultReview()),
});
export type OrgLlmSettings = z.infer<typeof orgLlmSettingsSchema>;
export const DISABLED_ORGANIZATION: OrgLlmSettings = {
  enabled: false,
  features: { explain: false, triage: false, fix: false },
  excludedProjectIds: [],
  autoFix: { ...DEFAULT_AUTO_FIX },
  autoFixDisabledProjectIds: [],
  review: defaultReview(),
};

/** llm.md §3.3: at most this many organisations in the map. */
export const MAX_LLM_ORGANIZATIONS = 1_000;

/** A model name as the settings store one: the pattern the review's consent stores its models by. */
export const MODEL_PATTERN = MODEL_NAME_PATTERN;

/**
 * A workspace of an Anthropic organisation as the console names it: `wrkspc_` and up to 64 letters
 * and digits. An organisation-wide key that is not scoped to a workspace sends it in the header
 * `anthropic-workspace-id`.
 */
export const WORKSPACE_ID_PATTERN = /^wrkspc_[A-Za-z0-9]{1,64}$/;

/** What a save of an Anthropic provider with a temperature is told: its current models take none. */
export const ANTHROPIC_NO_TEMPERATURE_TEXT =
  "Anthropic's current models take no temperature: leave it empty";

/** The smallest and the largest context window a provider may be given, in tokens. */
export const CONTEXT_WINDOW_MIN_TOKENS = 8_000;
export const CONTEXT_WINDOW_MAX_TOKENS = 10_000_000;

export const storedProviderSchema = z.strictObject({
  kind: z.enum(PROVIDER_KINDS),
  /**
   * The wire of an OpenAI provider: Chat Completions, which the OpenAI-compatible servers serve and
   * which an older row reads as, or OpenAI's Responses API, which its newest models need for
   * function tools. An Anthropic provider stores the default.
   */
  api: z.enum(PROVIDER_APIS).default('chat_completions'),
  baseUrl: z.string().min(1).max(2_048),
  /** The standard model: explain, triage and fix use it, and so does a tier without a model of its own. */
  model: z.string().regex(MODEL_PATTERN),
  /**
   * The model of the review's strong tier (the judge and the verification), and of its fast tier
   * (the quality reviewer of a trivial review). Null: the tier uses `model`. A row stored before
   * the tiers reads with null.
   */
  strongModel: z.string().regex(MODEL_PATTERN).nullable().default(null),
  fastModel: z.string().regex(MODEL_PATTERN).nullable().default(null),
  auth: z.enum(['bearer', 'api-key']),
  jsonMode: z.enum(['json_object', 'none']),
  maxTokensField: z.enum(['max_tokens', 'max_completion_tokens']),
  /**
   * OpenAI's. Anthropic's current models refuse a temperature, so a call to an Anthropic provider
   * never carries one (`providerConfig`), and one that older settings hold is read and ignored.
   */
  temperature: z.number().min(0).max(2).nullable(),
  /**
   * Anthropic's: the workspace an organisation-wide key that is not scoped to one names in every
   * request. Not a secret. A row stored before it reads with null.
   */
  workspaceId: z.string().regex(WORKSPACE_ID_PATTERN).nullable().default(null),
  timeoutSeconds: z.number().int().min(5).max(600),
  /**
   * The model's context window, in tokens (R46): the most one call of a review or of an answer to a
   * reply sends and has answered. One window for every tier. Null: 1 000 000 tokens
   * (`DEFAULT_CONTEXT_WINDOW_TOKENS`, review/tool-conversation.ts). No call receives it
   * (`providerConfig`), so it is no part of the Test's fingerprint, and a change of it changes no
   * consent and pauses nothing. A row stored before it reads with null.
   */
  contextWindowTokens: z
    .number()
    .int()
    .min(CONTEXT_WINDOW_MIN_TOKENS)
    .max(CONTEXT_WINDOW_MAX_TOKENS)
    .nullable()
    .default(null),
  apiKeyEnc: encrypted.nullable(),
});
export type StoredProvider = z.infer<typeof storedProviderSchema>;

/**
 * The model tiers in the order their models are listed: the standard model comes first. The
 * `ModelTier` union is made of this list, so a tier is never missing from it.
 */
export const MODEL_TIERS = ['standard', 'strong', 'fast'] as const;

/** The part of a provider that names the models of its tiers. */
type TierModels = Pick<StoredProvider, 'model' | 'strongModel' | 'fastModel'>;

/**
 * The model a tier has of its own: the strong or fast model when it is set and is not the
 * standard model. Null for the standard tier, and for a tier that uses the standard model, whether
 * it is empty or set to it: such a tier has the standard model's prices too.
 */
export function ownModel(provider: TierModels, tier: ModelTier): string | null {
  let model: string | null = null;
  if (tier === 'strong') model = provider.strongModel;
  else if (tier === 'fast') model = provider.fastModel;
  return model === null || model === provider.model ? null : model;
}

/**
 * The output limit parameter an OpenAI-compatible base URL needs (llm.md §2.2): OpenAI's and Azure
 * OpenAI's current models refuse `max_tokens`; vLLM, Ollama and the others want it. The AI
 * settings page chooses by the same rule (`defaultOutputLimitField`), pinned equal by
 * tools/ui/output-limit.test.ts; Anthropic's adapter has its own and ignores it.
 */
export function outputLimitFieldFor(baseUrl: string): 'max_tokens' | 'max_completion_tokens' {
  let host: string;
  try {
    host = new URL(baseUrl.trim()).hostname.toLowerCase();
  } catch {
    return 'max_tokens';
  }
  return host === 'api.openai.com' || host.endsWith('.openai.azure.com')
    ? 'max_completion_tokens'
    : 'max_tokens';
}

/** An `excludePaths` entry: a picomatch glob relative to the repository root. */
export const globSchema = z
  .string()
  .min(1)
  .max(200)
  .refine(
    (g) => !g.includes('\u0000') && !g.startsWith('/'),
    'A glob relative to the repository root',
  );

/**
 * A model's prices: US dollars for a million tokens of input and of output, and of the input the
 * provider read from its prompt cache (R49), which is null, or absent from a row stored before it,
 * for the input price: a cost is never understated. What the provider writes to its cache costs
 * the input price times CACHE_WRITE_PRICE_FACTOR (llm/job.ts), which no setting changes.
 */
export const pricePairSchema = z.strictObject({
  inputUsdPerMTok: z.number().min(0).max(10_000),
  outputUsdPerMTok: z.number().min(0).max(10_000),
  cachedInputUsdPerMTok: z.number().min(0).max(10_000).nullable().default(null),
});
export type PricePair = z.infer<typeof pricePairSchema>;

/**
 * The instance's prices: the standard model's, and, with their own models, the strong and the fast
 * model's. Null: no prices, so no costs. A row stored before the tiers reads with none for them.
 */
export const pricingSchema = pricePairSchema
  .extend({
    strong: pricePairSchema.nullable().default(null),
    fast: pricePairSchema.nullable().default(null),
  })
  .nullable();
export type StoredPricing = z.infer<typeof pricingSchema>;

export const storedLlmSettingsSchema = z.strictObject({
  v: z.literal(1),
  provider: storedProviderSchema.nullable(),
  organizations: z.record(z.uuid(), orgLlmSettingsSchema),
  excludePaths: z.array(globSchema).max(100),
  budgets: budgetsSchema,
  pricing: pricingSchema,
  storePrompts: z.boolean(),
  promptRetentionDays: z.number().int().min(1).max(90),
});
export type StoredLlmSettings = z.infer<typeof storedLlmSettingsSchema>;

export const DEFAULT_LLM_SETTINGS: StoredLlmSettings = {
  v: 1,
  provider: null,
  organizations: {},
  excludePaths: [],
  budgets: DEFAULT_BUDGETS,
  pricing: null,
  storePrompts: false,
  promptRetentionDays: 7,
};

/** A row that does not parse reads as "not configured" (fail closed, llm.md §11.2). */
export function readLlmSettings(db: Executor): Promise<StoredLlmSettings> {
  return instanceSetting(db, LLM_SETTINGS_KEY, storedLlmSettingsSchema, DEFAULT_LLM_SETTINGS);
}

export async function writeLlmSettings(tx: Executor, value: StoredLlmSettings): Promise<void> {
  await tx
    .insert(instanceSettings)
    .values({ key: LLM_SETTINGS_KEY, value })
    .onConflictDoUpdate({ target: instanceSettings.key, set: { value, updatedAt: sql`now()` } });
}

/**
 * Removes the organisation's switches from the row, under the lock every write of the row takes
 * (llm.md §3.2), for the delete of the organisation (0.16 issue #37). The row is changed as it is
 * stored, never through the schema: one that does not parse is not overwritten with the defaults,
 * and the other organisations' entries stay as they are. A missing row or entry is left as it is.
 * Call it inside a transaction.
 */
export async function dropOrganizationLlmSettings(
  tx: Executor,
  organizationId: string,
): Promise<void> {
  await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.llmSettings})`);
  await dropOrganizationEntry(tx, LLM_SETTINGS_KEY, organizationId);
}

/** The stored key: `key: null` for a provider without one; `ok: false` when it no longer decrypts. */
export function providerApiKey(
  settings: StoredLlmSettings,
  secretKey: string,
): { ok: true; key: string | null } | { ok: false } {
  const enc = settings.provider?.apiKeyEnc ?? null;
  if (enc === null) return { ok: true, key: null };
  const key = decryptSecret(encryptionKey(secretKey), enc, LLM_API_KEY_AAD);
  return key === null ? { ok: false } : { ok: true, key };
}

/**
 * What a provider call needs, without the key's envelope. An Anthropic provider has no
 * temperature, whatever older settings hold: its current models refuse one.
 */
export function providerConfig(stored: StoredProvider): ProviderConfig {
  return {
    kind: stored.kind,
    api: stored.api,
    baseUrl: stored.baseUrl,
    model: stored.model,
    auth: stored.auth,
    jsonMode: stored.jsonMode,
    maxTokensField: stored.maxTokensField,
    temperature: stored.kind === 'anthropic' ? null : stored.temperature,
    workspaceId: stored.workspaceId,
    timeoutSeconds: stored.timeoutSeconds,
  };
}

/**
 * The provider as a write is compared, and as the last Test is tied to it: what a call receives,
 * and the models of the tiers, which a call does not.
 */
export const comparedProvider = (p: StoredProvider) => ({
  ...providerConfig(p),
  strongModel: p.strongModel,
  fastModel: p.fastModel,
});

/**
 * The prices a call of the tier is costed at: the standard pair for the standard tier and for
 * a tier that uses the standard model, a tier's own pair for a tier with a model of its own, each
 * with its cached input price (R49). Null without prices, and for a model of its own that has none
 * (a row the API does not store): never the standard pair, which is another model's price.
 */
export function pricingFor(
  pricing: StoredPricing,
  provider: TierModels,
  tier: ModelTier,
): PricePair | null {
  if (pricing === null) return null;
  if (tier === 'standard' || ownModel(provider, tier) === null) {
    return {
      inputUsdPerMTok: pricing.inputUsdPerMTok,
      outputUsdPerMTok: pricing.outputUsdPerMTok,
      cachedInputUsdPerMTok: pricing.cachedInputUsdPerMTok,
    };
  }
  return pricing[tier];
}

/**
 * R49: what a token written to the provider's prompt cache costs, as a multiple of the input price
 * (Anthropic's 5-minute cache, the one the markers ask for). OpenAI bills no write.
 */
export const CACHE_WRITE_PRICE_FACTOR = 1.25;

/**
 * The most that one token of a call of the provider may cost, in micro-USD (a price is dollars for
 * a million tokens, which is micro-USD for a token): the highest, over every tier's pair
 * (`pricingFor`), of the input price times CACHE_WRITE_PRICE_FACTOR (a token written to the cache),
 * the cached input price (a token read from it; none counts as nothing) and the output price. A
 * token of input at the plain input price is below the first. A cost that is left to spend is
 * turned into tokens at this price, since the cost of a call is not known before it is made and any
 * tier's may be the next. Every tier counts, though two may name the same model: a call is costed
 * at the pair of its tier. A tier with no pair is left out, and with no pair at all, or no prices,
 * there is none. When every output price is at least CACHE_WRITE_PRICE_FACTOR times its input price
 * and no cached price is above the output price, as it is for the mainstream prices, this is the
 * dearest output price.
 */
export function dearestTokenPrice(pricing: StoredPricing, provider: TierModels): number | null {
  const prices = MODEL_TIERS.flatMap((tier) => {
    const pair = pricingFor(pricing, provider, tier);
    return pair === null
      ? []
      : [
          pair.inputUsdPerMTok * CACHE_WRITE_PRICE_FACTOR,
          pair.cachedInputUsdPerMTok ?? 0,
          pair.outputUsdPerMTok,
        ];
  });
  return prices.length === 0 ? null : Math.max(...prices);
}

/** llm.md §3.3: an organisation absent from the map is disabled. */
export function organizationSettings(
  settings: StoredLlmSettings,
  organizationId: string,
): OrgLlmSettings {
  return Object.hasOwn(settings.organizations, organizationId)
    ? (settings.organizations[organizationId] ?? DISABLED_ORGANIZATION)
    : DISABLED_ORGANIZATION;
}

/**
 * The owner of each project id still in the database (a deleted project is absent). Used to drop
 * the excluded and opted-out ids of projects deleted since the settings were saved (llm.md §3.3):
 * an id that no longer exists changes nothing, and must not stop anyone from saving.
 */
export async function projectOwners(
  db: Executor,
  ids: readonly string[],
): Promise<Map<string, string>> {
  const owners = new Map<string, string>();
  if (ids.length === 0) return owners;
  const rows = await db
    .select({ id: projects.id, organizationId: projects.organizationId })
    .from(projects)
    .where(sql`${projects.id} IN ${uuidList([...new Set(ids)])}`);
  for (const r of rows) owners.set(r.id, r.organizationId);
  return owners;
}

/**
 * llm.md §3.2: the matcher of `excludePaths`, picomatch with dotfiles, for code that tests many
 * paths against one list.
 */
export function excludedPathMatcher(excludePaths: readonly string[]): (path: string) => boolean {
  if (excludePaths.length === 0) return () => false;
  return picomatch([...excludePaths], { dot: true });
}

/** llm.md §3.2: `excludePaths`, picomatch with dotfiles. */
export function pathExcluded(settings: StoredLlmSettings, path: string | null): boolean {
  return path !== null && excludedPathMatcher(settings.excludePaths)(path);
}
