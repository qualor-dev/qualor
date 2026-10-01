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

/** What an absolute path outside the repository becomes in a kept message (ruling D9-11). */
export const OUTSIDE_PLACEHOLDER = '<outside the repository>';

/**
 * An absolute path in a tool's message: POSIX (`/usr/include/x.h`) or Windows (`C:\x`, `C:/x`),
 * not inside a word, a number or a URL (`a/b`, `1/0`, `https://…`), and not a lone `/`.
 */
const ABSOLUTE_PATH = /(?<![A-Za-z0-9_.~:/\\-])(?:[A-Za-z]:[\\/]|[\\/])[^\s'"`<>|]+/g;
/** Punctuation that ends a sentence or a quote rather than the path. */
const TRAILING = /[.,;:)\]}]+$/;

/**
 * Ruling D9-11 (completing D9-9): a kept message or note text with every absolute path outside
 * `bases` (the repository root and its resolved spelling, or the checked copy) replaced by
 * `OUTSIDE_PLACEHOLDER`, and every path inside one made relative to it (`src/a.h:3`), so no host
 * path (a system or CI header, the runner's directories) reaches the report.
 */
export function redactForeignPaths(text: string, bases: readonly string[]): string {
  const roots = bases.map((b) => path.resolve(b));
  return text.replace(ABSOLUTE_PATH, (match) => {
    const tail = TRAILING.exec(match)?.[0] ?? '';
    const p = match.slice(0, match.length - tail.length);
    if (p.length <= 1) return match;
    const abs = path.resolve(p);
    for (const root of roots) {
      const rel = path.relative(root, abs);
      if (rel === '') return `.${tail}`;
      if (rel !== '..' && !rel.startsWith(`..${path.sep}`) && !path.isAbsolute(rel)) {
        return `${rel.split(path.sep).join('/')}${tail}`;
      }
    }
    return `${OUTSIDE_PLACEHOLDER}${tail}`;
  });
}

/** The repository root with its links resolved, or as written when it cannot be resolved. */
export function realRootOf(root: string): string {
  try {
    return realpathSync(root);
  } catch {
    return path.resolve(root);
  }
}
