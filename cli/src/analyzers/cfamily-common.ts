import { realpathSync } from 'node:fs';
import path from 'node:path';
import { isUrl } from '@qualor/shared';
import { deadProxyEnv } from './offline';
import { shown } from './reason';

/** The languages both C/C++ engines analyse (plan 9D). */
export const C_LANGUAGES: ReadonlySet<string> = new Set(['c', 'cpp']);

const LINE_BREAK = /[\r\n\x85\u2028\u2029]/;
/** A path no file list or response file can carry (config.md §6.2): left out with a warning. */
export function hasLineBreak(p: string): boolean {
  return LINE_BREAK.test(p);
}

/**
 * config.md §6.2: the only inherited variables cppcheck and clang-tidy see (matched without case),
 * so no `CCC_OVERRIDE_OPTIONS`, `CPATH` or CI secret reaches them.
 */
export const C_FAMILY_KEPT_ENV: ReadonlySet<string> = new Set([
  'PATH',
  'TMPDIR',
  'TEMP',
  'TMP',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'SYSTEMROOT',
  'WINDIR',
]);

/** The variables Qualor sets for both C/C++ tools. */
export function cFamilyEnv(workDir: string): Record<string, string> {
  return { ...deadProxyEnv(), HOME: workDir, LC_ALL: 'C.UTF-8' };
}

/** `AnalyzerCommand.dropEnv` of both tools: every inherited variable but the allowlist. */
export function cFamilyDropEnv(own: Readonly<Record<string, string>>): (name: string) => boolean {
  return (name) => !Object.hasOwn(own, name) && !C_FAMILY_KEPT_ENV.has(name.toUpperCase());
}

/**
 * config.md §6.2 (exit 2, ruling F3): a configured repository file (`compileCommands`,
 * `configFile`) that is a URL, or outside the repository as written. `key` is the settings path
 * (`analyzers.cppcheck`), `name` the setting.
 */
export function checkRepoFileSetting(key: string, name: string, value: string): string | null {
  const label = `${key}.${name} ${shown(value)}`;
  if (isUrl(value)) return `${label} is a URL (only repository files)`;
  const p = value.replaceAll('\\', '/');
  if (p.startsWith('/') || /^[A-Za-z]:/.test(p) || p.split('/').includes('..')) {
    return `${label} is outside the repository`;
  }
  return null;
}

/** The repository root with its links resolved, or as written when it cannot be resolved. */
export function realRootOf(root: string): string {
  try {
    return realpathSync(root);
  } catch {
    return path.resolve(root);
  }
}
