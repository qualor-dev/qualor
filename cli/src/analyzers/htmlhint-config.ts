import path from 'node:path';
import { readRepoConfig, repoEntryExists, WeblintConfigError } from './weblint';

/**
 * Qualor's HTMLHint rules when the project has no .htmlhintrc (design decision 4): rules that
 * fire on real mistakes in full pages and stay silent on framework templates. Rules needing
 * <html> or <head> only fire when that tag is present (verified facts F10).
 */
export const QUALOR_DEFAULT_HTMLHINT_RULES: Readonly<Record<string, boolean>> = Object.freeze({
  'tag-pair': true,
  'attr-no-duplication': true,
  'src-not-empty': true,
  'alt-require': true,
  'attr-unsafe-chars': true,
  'doctype-html5': true,
  'html-lang-require': true,
  'title-require': true,
  'meta-charset-require': true,
  'tag-no-obsolete': true,
  'frame-title-require': true,
});

const MAX_CONFIG_BYTES = 1024 * 1024;
const ESCAPE = "set analyzers.htmlhint.configFile: qualor-default to use Qualor's own rules";

/** JSON with `//` and `/* *\/` comments, as HTMLHint reads .htmlhintrc (strip-json-comments). */
export function parseJsonc(text: string): unknown {
  const src = text.replace(/^\uFEFF/, '');
  let out = '';
  let inString = false;
  for (let i = 0; i < src.length;) {
    const c = src.charAt(i);
    if (inString) {
      out += c;
      if (c === '\\') {
        out += src[i + 1] ?? '';
        i += 2;
        continue;
      }
      if (c === '"') inString = false;
      i += 1;
    } else if (c === '"') {
      inString = true;
      out += c;
      i += 1;
    } else if (c === '/' && src[i + 1] === '/') {
      while (i < src.length && src[i] !== '\n') i += 1;
    } else if (c === '/' && src[i + 1] === '*') {
      const end = src.indexOf('*/', i + 2);
      if (end < 0) throw new SyntaxError('unterminated comment');
      out += src.slice(i, end + 2).replace(/[^\n]/g, ' ');
      i = end + 2;
    } else {
      out += c;
      i += 1;
    }
  }
  return JSON.parse(out);
}

/** HTMLHint rule ids are lower-case kebab words (`tag-pair`, `h1-require`). */
const RULE_ID = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
/** Names of the command line's code loaders and of other tools' config keys: never rules. */
const LOADER_KEYS = new Set([
  'rulesdir',
  'rules-dir',
  'plugins',
  'extends',
  'config',
  'format',
  'formatter',
]);

/**
 * The rule ids and their options, as data. HTMLHint's core API only looks up its own rule ids in
 * this object, so nothing here can load code; a key that is not a rule id (a command-line loader
 * such as `rulesdir`, `__proto__`, a path) is refused rather than passed on. `$schema` is dropped.
 */
function ruleset(raw: Record<string, unknown>, rel: string): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(raw)) {
    if (key === '$schema') continue;
    if (LOADER_KEYS.has(key))
      throw new WeblintConfigError(
        `${rel} sets "${key}", which Qualor does not support (it loads code)`,
      );
    if (!RULE_ID.test(key))
      throw new WeblintConfigError(`${rel} sets "${key}", which is not an HTMLHint rule id`);
    out[key] = value;
  }
  return out;
}

/** config.md §6: the HTMLHint rules Qualor runs, or the reason HTMLHint is skipped. */
export function resolveHtmlhintRules(
  root: string,
  configFile: string | null,
): { rules: Record<string, unknown>; source: string } | { skip: string } {
  if (configFile === 'qualor-default')
    return { rules: QUALOR_DEFAULT_HTMLHINT_RULES, source: 'qualor-default' };
  const rel = configFile ?? '.htmlhintrc';
  if (configFile === null && !repoEntryExists(path.join(root, rel))) {
    return { rules: QUALOR_DEFAULT_HTMLHINT_RULES, source: 'qualor-default' };
  }
  try {
    const text = readRepoConfig(root, rel, MAX_CONFIG_BYTES);
    let rules: unknown;
    try {
      rules = parseJsonc(text);
    } catch {
      throw new WeblintConfigError(`${rel} is not valid JSON`);
    }
    if (typeof rules !== 'object' || rules === null || Array.isArray(rules)) {
      throw new WeblintConfigError(`${rel} is not an object of HTMLHint rules`);
    }
    return { rules: ruleset(rules as Record<string, unknown>, rel), source: rel };
  } catch (err) {
    if (!(err instanceof WeblintConfigError)) throw err;
    return { skip: `${err.message}; ${ESCAPE}` };
  }
}
