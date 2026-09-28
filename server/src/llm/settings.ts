import { sql } from 'drizzle-orm';
import picomatch from 'picomatch';
import { z } from 'zod';
import { decryptSecret, encryptionKey } from '../crypto/secrets';
import type { Executor } from '../db/client';
import { instanceSettings } from '../db/schema';
import { instanceSetting } from '../settings';
import { PROVIDER_KINDS, type ProviderConfig } from './providers';

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
});
export type Budgets = z.infer<typeof budgetsSchema>;
export const DEFAULT_BUDGETS: Budgets = {
  explainPerDay: 200,
  triagePerDay: 100,
  fixPerDay: 25,
  tokensPerDay: 1_000_000,
  costPerDayUsd: null,
  perUserPerHour: 30,
};

/** llm.md §3.3: an organisation's switches; at most 1 000 excluded projects. */
export const orgLlmSettingsSchema = z.strictObject({
  enabled: z.boolean(),
  features: z.strictObject({ explain: z.boolean(), triage: z.boolean(), fix: z.boolean() }),
  excludedProjectIds: z.array(z.uuid()).max(1_000),
});
export type OrgLlmSettings = z.infer<typeof orgLlmSettingsSchema>;
export const DISABLED_ORGANIZATION: OrgLlmSettings = {
  enabled: false,
  features: { explain: false, triage: false, fix: false },
  excludedProjectIds: [],
};

/** llm.md §3.3: at most this many organisations in the map. */
export const MAX_LLM_ORGANIZATIONS = 1_000;

export const MODEL_PATTERN = /^[A-Za-z0-9._:/@+-]{1,200}$/;

/** llm.md §3.2: the Anthropic Messages API takes a temperature of 0–1, OpenAI's 0–2. */
export const MAX_TEMPERATURE = { openai: 2, anthropic: 1 } as const;
export const ANTHROPIC_TEMPERATURE_TEXT = 'Anthropic takes a temperature of 0 to 1';

export const storedProviderSchema = z
  .strictObject({
    kind: z.enum(PROVIDER_KINDS),
    baseUrl: z.string().min(1).max(2_048),
    model: z.string().regex(MODEL_PATTERN),
    auth: z.enum(['bearer', 'api-key']),
    jsonMode: z.enum(['json_object', 'none']),
    maxTokensField: z.enum(['max_tokens', 'max_completion_tokens']),
    temperature: z.number().min(0).max(2).nullable(),
    timeoutSeconds: z.number().int().min(5).max(600),
    apiKeyEnc: encrypted.nullable(),
  })
  .refine((p) => p.temperature === null || p.temperature <= MAX_TEMPERATURE[p.kind], {
    message: ANTHROPIC_TEMPERATURE_TEXT,
    path: ['temperature'],
  });
export type StoredProvider = z.infer<typeof storedProviderSchema>;

/** An `excludePaths` entry: a picomatch glob relative to the repository root. */
export const globSchema = z
  .string()
  .min(1)
  .max(200)
  .refine(
    (g) => !g.includes('\u0000') && !g.startsWith('/'),
    'A glob relative to the repository root',
  );

export const pricingSchema = z
  .strictObject({
    inputUsdPerMTok: z.number().min(0).max(10_000),
    outputUsdPerMTok: z.number().min(0).max(10_000),
  })
  .nullable();

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

/** What a provider call needs, without the key's envelope. */
export function providerConfig(stored: StoredProvider): ProviderConfig {
  return {
    kind: stored.kind,
    baseUrl: stored.baseUrl,
    model: stored.model,
    auth: stored.auth,
    jsonMode: stored.jsonMode,
    maxTokensField: stored.maxTokensField,
    temperature: stored.temperature,
    timeoutSeconds: stored.timeoutSeconds,
  };
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

/** llm.md §3.2: `excludePaths`, picomatch with dotfiles. */
export function pathExcluded(settings: StoredLlmSettings, path: string | null): boolean {
  if (path === null || settings.excludePaths.length === 0) return false;
  return picomatch(settings.excludePaths, { dot: true })(path);
}
