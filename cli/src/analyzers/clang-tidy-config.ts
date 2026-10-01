import {
  CLANG_TIDY_BUILTIN_CHECKS,
  CLANG_TIDY_DEFAULT_CHECKS,
  type QualorConfig,
} from '@qualor/shared';
import path from 'node:path';
import { parseDocument } from 'yaml';
import { checkRepoFileSetting } from './cfamily-common';
import { checkCompileCommandsSetting } from './compile-commands';
import { shown } from './reason';
import { readRepoConfigBytes, repoEntryExists, WeblintConfigError } from './weblint';

/** config.md §6.2: a `.clang-tidy` larger than this is not read. */
export const MAX_CLANG_TIDY_CONFIG_BYTES = 1024 * 1024;
export const CLANG_TIDY_QUALOR_DEFAULT = 'qualor-default';
const MAX_ALIASES = 100;

export interface ClangTidyPlan {
  /** The configuration Qualor writes to its work directory and passes as `--config-file`. */
  json: string;
  /** Keys left out, for one log line. */
  dropped: string[];
  /** `qualor-default`, or the repository-relative path of the file read. */
  source: string;
}

/**
 * The only keys that reach clang-tidy (config.md §6.2): no `ExtraArgs`/`ExtraArgsBefore` (they
 * would bypass the compile database's allowlist), no `InheritParentConfig` (a parent directory's
 * file), no `WarningsAsErrors`, `HeaderFilterRegex`, `SystemHeaders` (Qualor's scope),
 * `CustomChecks` or anything newer.
 */
const KEPT = new Set([
  'Checks',
  'CheckOptions',
  'HeaderFileExtensions',
  'ImplementationFileExtensions',
]);
const CHECK_GLOBS = /^[A-Za-z0-9*.,_-]*$/;
const OPTION_KEY = /^[A-Za-z0-9._-]+$/;
const EXTENSION = /^[A-Za-z0-9+_-]*$/;

function scalar(v: unknown): string | null {
  return typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean'
    ? String(v)
    : null;
}

function optionPairs(value: unknown): [unknown, unknown][] {
  if (Array.isArray(value)) {
    return value.map((e: unknown) =>
      e !== null && typeof e === 'object'
        ? [(e as Record<string, unknown>)['key'], (e as Record<string, unknown>)['value']]
        : [null, null],
    );
  }
  return value !== null && typeof value === 'object' ? Object.entries(value) : [[null, null]];
}

/** The configuration Qualor writes from a parsed `.clang-tidy` (null: Qualor's default checks). */
export function planClangTidyConfig(
  parsed: Record<string, unknown> | null,
  source: string,
): ClangTidyPlan | { skip: string } {
  if (parsed === null) {
    return {
      json: JSON.stringify({ Checks: CLANG_TIDY_DEFAULT_CHECKS }),
      dropped: [],
      source: CLANG_TIDY_QUALOR_DEFAULT,
    };
  }
  const name = shown(source);
  const out: Record<string, unknown> = {};
  const dropped: string[] = [];
  for (const [key, value] of Object.entries(parsed)) {
    if (!KEPT.has(key)) {
      dropped.push(shown(key));
    } else if (key === 'Checks') {
      const list = Array.isArray(value) ? value.map(scalar) : [scalar(value)];
      if (list.some((s) => s === null)) {
        return { skip: `${name}: Checks must be a string or a list of strings` };
      }
      const globs = (list as string[])
        .join(',')
        .replace(/\s+/g, '')
        .replace(/,+/g, ',')
        .replace(/^,|,$/g, '');
      if (!CHECK_GLOBS.test(globs))
        return { skip: `${name}: Checks holds characters no check name uses` };
      out['Checks'] = globs;
    } else if (key === 'CheckOptions') {
      const options: Record<string, string> = {};
      for (const [k, v] of optionPairs(value)) {
        const s = scalar(v);
        if (typeof k !== 'string' || !OPTION_KEY.test(k) || s === null) {
          return { skip: `${name}: CheckOptions must be a mapping or a list of key/value pairs` };
        }
        options[k] = s;
      }
      out['CheckOptions'] = options;
    } else {
      if (
        !Array.isArray(value) ||
        !value.every((e) => typeof e === 'string' && EXTENSION.test(e))
      ) {
        return { skip: `${name}: ${key} must be a list of extensions` };
      }
      out[key] = value;
    }
  }
  if (!('Checks' in out)) out['Checks'] = CLANG_TIDY_BUILTIN_CHECKS;
  // `Checks` first, as clang-tidy's own --dump-config writes it.
  const { Checks, ...rest } = out;
  return { json: JSON.stringify({ Checks, ...rest }), dropped, source };
}

/**
 * config.md §6.2: the repository's `.clang-tidy` (root only: clang-tidy never sees the checkout's
 * nested or parent files, as Qualor passes `--config-file`), or `configFile`, filtered by
 * `planClangTidyConfig`. `{ error }` only for what `checkClangTidyConfig` already refuses.
 */
export function loadClangTidyConfig(
  root: string,
  configFile: string | null,
): ClangTidyPlan | { skip: string } | { error: string } {
  if (configFile === CLANG_TIDY_QUALOR_DEFAULT)
    return planClangTidyConfig(null, CLANG_TIDY_QUALOR_DEFAULT);
  let rel: string;
  if (configFile !== null) {
    const bad = checkRepoFileSetting('analyzers.clang-tidy', 'configFile', configFile);
    if (bad !== null) return { error: bad };
    if (!repoEntryExists(path.resolve(root, configFile))) {
      return { skip: `configFile ${shown(configFile)} does not exist` };
    }
    rel = configFile;
  } else {
    if (!repoEntryExists(path.join(root, '.clang-tidy'))) {
      return planClangTidyConfig(null, CLANG_TIDY_QUALOR_DEFAULT);
    }
    rel = '.clang-tidy';
  }
  let text: string;
  try {
    const bytes = readRepoConfigBytes(root, rel, MAX_CLANG_TIDY_CONFIG_BYTES, rel);
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch (err) {
    if (err instanceof WeblintConfigError) return { skip: shown(err.message) };
    return { skip: `${shown(rel)} is not UTF-8` };
  }
  let value: unknown;
  try {
    const doc = parseDocument(text, { uniqueKeys: true, prettyErrors: false });
    if (doc.errors.length > 0) return { skip: `${shown(rel)} cannot be parsed as YAML` };
    value = doc.toJS({ maxAliasCount: MAX_ALIASES });
  } catch {
    return { skip: `${shown(rel)} cannot be parsed as YAML` };
  }
  if (value === null || value === undefined) return planClangTidyConfig({}, rel);
  if (typeof value !== 'object' || Array.isArray(value)) {
    return { skip: `${shown(rel)} is not a YAML mapping` };
  }
  return planClangTidyConfig(value as Record<string, unknown>, rel);
}

/** config.md §6.2 (exit 2): a URL or a path outside the repository as written (ruling F3). */
export function checkClangTidyConfig(_root: string, config: QualorConfig): string | null {
  const s = config.analyzers['clang-tidy'];
  if (s.configFile !== null && s.configFile !== CLANG_TIDY_QUALOR_DEFAULT) {
    const bad = checkRepoFileSetting('analyzers.clang-tidy', 'configFile', s.configFile);
    if (bad !== null) return bad;
  }
  return checkCompileCommandsSetting(s.compileCommands, 'analyzers.clang-tidy');
}
