import { describe, expect, it } from 'vitest';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import {
  DEFAULT_LLM_SETTINGS,
  LLM_API_KEY_AAD,
  organizationSettings,
  pathExcluded,
  providerApiKey,
  providerConfig,
  storedLlmSettingsSchema,
  type StoredLlmSettings,
} from './settings';

const SECRET = 'test-secret-key-that-is-at-least-32-characters';
const provider = {
  kind: 'openai' as const,
  baseUrl: 'https://api.example.com/v1',
  model: 'm',
  auth: 'bearer' as const,
  jsonMode: 'json_object' as const,
  maxTokensField: 'max_tokens' as const,
  temperature: null,
  timeoutSeconds: 60,
};

describe('LLM settings (llm.md §3)', () => {
  it('reads the defaults as not configured', () => {
    expect(storedLlmSettingsSchema.parse(DEFAULT_LLM_SETTINGS).provider).toBeNull();
  });

  it('decrypts the key only under its own AAD', () => {
    const key = encryptionKey(SECRET);
    const s: StoredLlmSettings = {
      ...DEFAULT_LLM_SETTINGS,
      provider: { ...provider, apiKeyEnc: encryptSecret(key, 'k-1', LLM_API_KEY_AAD) },
    };
    expect(providerApiKey(s, SECRET)).toEqual({ ok: true, key: 'k-1' });
    const other: StoredLlmSettings = {
      ...s,
      provider: {
        ...provider,
        apiKeyEnc: encryptSecret(key, 'k-1', 'webhook_subscriptions.secret_enc'),
      },
    };
    expect(providerApiKey(other, SECRET)).toEqual({ ok: false });
    expect(providerApiKey(s, `${SECRET}-rotated`)).toEqual({ ok: false });
    expect(providerApiKey({ ...s, provider: { ...provider, apiKeyEnc: null } }, SECRET)).toEqual({
      ok: true,
      key: null,
    });
  });

  it('keeps the key out of the provider config', () => {
    const key = encryptionKey(SECRET);
    const config = providerConfig({
      ...provider,
      apiKeyEnc: encryptSecret(key, 'k-1', LLM_API_KEY_AAD),
    });
    expect(config).toEqual(provider);
    expect(JSON.stringify(config)).not.toContain('"ct"');
  });

  it('refuses a stored Anthropic temperature above 1 (fails closed as not configured)', () => {
    const anthropic = { ...provider, kind: 'anthropic' as const, apiKeyEnc: null };
    const ok = { ...DEFAULT_LLM_SETTINGS, provider: { ...anthropic, temperature: 1 } };
    expect(storedLlmSettingsSchema.safeParse(ok).success).toBe(true);
    const hot = { ...DEFAULT_LLM_SETTINGS, provider: { ...anthropic, temperature: 1.5 } };
    expect(storedLlmSettingsSchema.safeParse(hot).success).toBe(false);
    const openai = {
      ...DEFAULT_LLM_SETTINGS,
      provider: { ...provider, temperature: 1.5, apiKeyEnc: null },
    };
    expect(storedLlmSettingsSchema.safeParse(openai).success).toBe(true);
  });

  it('reads an organisation absent from the map as disabled', () => {
    const id = '00000000-0000-7000-8000-000000000001';
    expect(organizationSettings(DEFAULT_LLM_SETTINGS, id)).toEqual({
      enabled: false,
      features: { explain: false, triage: false, fix: false },
      excludedProjectIds: [],
    });
  });

  it('matches excluded paths, dotfiles included', () => {
    const s = { ...DEFAULT_LLM_SETTINGS, excludePaths: ['secrets/**', '**/*.gen.ts'] };
    expect(pathExcluded(s, 'secrets/a/b.ts')).toBe(true);
    expect(pathExcluded(s, 'src/.hidden/x.gen.ts')).toBe(true);
    expect(pathExcluded(s, 'src/a.ts')).toBe(false);
    expect(pathExcluded(s, null)).toBe(false);
  });
});
