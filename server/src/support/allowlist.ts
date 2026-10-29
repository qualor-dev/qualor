import type { Config } from '../config';

/**
 * 4E-3b §2: how an allowlisted value is copied into the support bundle. `value`: as it is (a set
 * becomes a sorted array); `url`: scheme, host and port only; `text`: free text, through the
 * bundle's cleaning (secret values redacted, cut to 500 characters). Anything not listed is
 * `"[set]"` or `"[unset]"`.
 */
export type SupportRule = 'value' | 'url' | 'text';

export const SET = '[set]';
export const UNSET = '[unset]';

/**
 * 4E-3b §2: the configuration keys (paths into {@link Config}) copied as values. Every other key,
 * a new one included, is `"[set]"` or `"[unset]"`: the secret key, the bootstrap password and the
 * licence key text are never listed.
 */
export const SUPPORT_CONFIG_ALLOWLIST: Readonly<Record<string, SupportRule>> = Object.freeze({
  databaseUrl: 'url',
  'embedded.dataDir': 'value',
  'embedded.postgresDir': 'value',
  host: 'value',
  port: 'value',
  logLevel: 'value',
  trustProxy: 'value',
  'bootstrapAdmin.username': 'value',
  sessionTtlHours: 'value',
  'upload.maxCompressedBytes': 'value',
  'upload.maxDecompressedBytes': 'value',
  'reviewSnapshot.maxCompressedBytes': 'value',
  'reviewSnapshot.maxDecompressedBytes': 'value',
  workerConcurrency: 'value',
  reviewWorkerConcurrency: 'value',
  aiReviewMaxMinutes: 'value',
  requestTimeoutMs: 'value',
  maxConcurrentUploads: 'value',
  uiDir: 'value',
  publicUrl: 'url',
  scmInternalHosts: 'value',
  llmInternalHosts: 'value',
  ssoInternalHosts: 'value',
  chatTestHosts: 'value',
  forcePasswordSignIn: 'value',
  'license.file': 'value',
  pluginPaths: 'value',
  demoUser: 'value',
  'telemetry.enabled': 'value',
  'telemetry.url': 'url',
});

/**
 * 4E-3b §2: per `instance_settings` key, the paths copied as values (`*` stands for any one key,
 * such as an organisation id; `''` is the whole value). A key not listed here (`telemetry`, a new
 * one) is `"[set]"` as a whole; a path not listed is `"[set]"` or `"[unset]"`. Never an API key,
 * a stream secret or the licence key; a stream URL is its host.
 */
export const SUPPORT_SETTINGS_ALLOWLIST: Readonly<
  Record<string, Readonly<Record<string, SupportRule>>>
> = Object.freeze({
  audit: { retentionDays: 'value', 'stream.url': 'url', 'stream.active': 'value' },
  'audit-chain': { throughSeq: 'value', throughHash: 'value' },
  'audit-stream': {
    cursorSeq: 'value',
    lastSuccessAt: 'value',
    lastError: 'text',
    failingSince: 'value',
    consecutiveFailures: 'value',
    nextAttemptAt: 'value',
    skipped: 'value',
  },
  'gate.smallChangesetLines': { '': 'value' },
  license: { savedAt: 'value', savedBy: 'value' },
  llm: {
    v: 'value',
    'provider.kind': 'value',
    'provider.api': 'value',
    'provider.baseUrl': 'url',
    'provider.model': 'value',
    'provider.strongModel': 'value',
    'provider.fastModel': 'value',
    'provider.auth': 'value',
    'provider.jsonMode': 'value',
    'provider.maxTokensField': 'value',
    'provider.temperature': 'value',
    'provider.timeoutSeconds': 'value',
    'provider.contextWindowTokens': 'value',
    'organizations.*.enabled': 'value',
    'organizations.*.features': 'value',
    'organizations.*.autoFix': 'value',
    excludePaths: 'value',
    budgets: 'value',
    pricing: 'value',
    storePrompts: 'value',
    promptRetentionDays: 'value',
  },
  retention: { '*': 'value' },
  'sign-in': { passwordSignIn: 'value', breakGlassUserIds: 'value' },
  webhooks: { allowHttp: 'value', allowInternalHosts: 'value' },
});

/** A URL as scheme, host and port: no user, password, path, query or fragment. */
export function urlHost(value: string): string {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}`;
  } catch {
    return SET;
  }
}

function isUnset(value: unknown): boolean {
  return value === null || value === undefined || value === '';
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return (
    typeof value === 'object' && value !== null && !Array.isArray(value) && !(value instanceof Set)
  );
}

/** Byte order, never the locale's: the files compare the same on every machine. */
function byteOrder(a: string, b: string): number {
  if (a < b) return -1;
  return a > b ? 1 : 0;
}

function plain(value: unknown): unknown {
  if (value instanceof Set) return [...value].map(String).sort(byteOrder);
  return value;
}

function segmentsMatch(rule: readonly string[], path: readonly string[], prefix: boolean): boolean {
  if (prefix ? rule.length <= path.length : rule.length !== path.length) return false;
  return path.every((segment, i) => rule[i] === '*' || rule[i] === segment);
}

/**
 * `value` through `rules`: a listed path is copied by its rule; an object some listed path goes
 * into is walked, its keys in byte order; anything else is `"[set]"` or `"[unset]"`.
 */
export function applyAllowlist(
  value: unknown,
  rules: Readonly<Record<string, SupportRule>>,
  clean: (text: string) => string,
): unknown {
  const parsed = Object.entries(rules).map(
    ([path, rule]) => [path === '' ? [] : path.split('.'), rule] as const,
  );
  const walk = (node: unknown, path: string[]): unknown => {
    const exact = parsed.find(([segments]) => segmentsMatch(segments, path, false));
    if (exact) {
      const rule = exact[1];
      if (rule === 'value') return plain(node);
      if (isUnset(node)) return node ?? null;
      if (typeof node !== 'string') return SET;
      return rule === 'url' ? urlHost(node) : clean(node);
    }
    if (isPlainObject(node) && parsed.some(([segments]) => segmentsMatch(segments, path, true))) {
      return Object.fromEntries(
        Object.keys(node)
          .sort(byteOrder)
          .map((key) => [key, walk(node[key], [...path, key])]),
      );
    }
    return isUnset(node) ? UNSET : SET;
  };
  return walk(value, []);
}

/** `config.json`: the effective configuration through {@link SUPPORT_CONFIG_ALLOWLIST}. */
export function allowlistedConfig(config: Config, clean: (text: string) => string): unknown {
  return applyAllowlist(config, SUPPORT_CONFIG_ALLOWLIST, clean);
}

/** One `instance_settings` row through {@link SUPPORT_SETTINGS_ALLOWLIST}; an unknown key is `"[set]"`. */
export function allowlistedSetting(
  key: string,
  value: unknown,
  clean: (text: string) => string,
): unknown {
  const rules = Object.hasOwn(SUPPORT_SETTINGS_ALLOWLIST, key)
    ? SUPPORT_SETTINGS_ALLOWLIST[key]
    : undefined;
  return rules ? applyAllowlist(value, rules, clean) : SET;
}
