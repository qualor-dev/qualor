import { stringify } from 'yaml';
import type { Settings } from './settings';

export const REDACTED_VALUE = '«redacted»';

/** Below this length a "token" redacts too many unrelated short strings to be worth it. */
const MIN_REDACTED_TOKEN_LENGTH = 8;

/** Hides URL credentials and query strings (which may carry tokens). */
export function redactUrl(url: string): string {
  return url
    .replace(/^([a-z][a-z0-9+.-]*:\/\/)[^/@?#]*@/i, `$1${REDACTED_VALUE}@`)
    .replace(/\?[^#]*/, `?${REDACTED_VALUE}`);
}

/**
 * Defence in depth, independent of `denySecretRefs` (settings.ts): whatever path put the
 * literal token value into the resolved config — a bypass, a coincidence, a field neither of
 * us thought of — this redacts every string in the document that contains it, not just
 * `server.token`.
 */
function redactByValue(value: unknown, token: string | null): unknown {
  if (token === null || token.length < MIN_REDACTED_TOKEN_LENGTH) return value;
  if (typeof value === 'string') return value.includes(token) ? REDACTED_VALUE : value;
  if (Array.isArray(value)) return value.map((v) => redactByValue(v, token));
  if (value !== null && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, redactByValue(v, token)]));
  }
  return value;
}

/** `qualor validate` output: the resolved config as YAML, secrets redacted (config.md §8.3). */
export function renderSettings(settings: Settings): string {
  const { server } = settings.config;
  const doc = {
    ...settings.config,
    server: {
      ...server,
      ...(server.url !== undefined && { url: redactUrl(server.url) }),
      token: settings.token === null ? null : REDACTED_VALUE,
    },
  };
  const header =
    `# qualor.yml: ${settings.configPath ?? 'none found, built-in defaults'}\n` +
    `# CI: ${settings.ci.provider}\n`;
  return header + stringify(redactByValue(doc, settings.token));
}
