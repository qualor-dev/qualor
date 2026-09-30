import { lstatSync } from 'node:fs';
import path from 'node:path';
import { isUrl, SWIFTLINT_RULES, type QualorConfig } from '@qualor/shared';
import { parseDocument, stringify, visit, type Tags } from 'yaml';
import { within } from './binary';
import { shown } from './reason';
import { readRepoConfigBytes, WeblintConfigError } from './weblint';

/** config.md §6: a SwiftLint configuration larger than this is not read. */
export const MAX_SWIFTLINT_CONFIG_BYTES = 1024 * 1024;
/** At most this many YAML aliases, as for detekt (ruling F9, E14 parity). */
export const MAX_SWIFTLINT_CONFIG_ALIASES = 50;
/** `analyzers.swiftlint.configFile: qualor-default` forces Qualor's default configuration. */
export const QUALOR_DEFAULT = 'qualor-default';

/**
 * Ruling F5: what SwiftLint gets when the project has no configuration (or `configFile:
 * qualor-default`), in place of SwiftLint's bare defaults, which flag code the Xcode and SwiftUI
 * defaults produce: whitespace Xcode leaves on blank lines, every `// TODO`, loop and geometry
 * names (`i`, `x`), SwiftUI's `Button(action:) { … }`, and long URLs or comments. A project
 * configuration replaces it entirely. `"y"` is quoted: a bare `y` is a boolean in YAML 1.1.
 */
export const QUALOR_SWIFTLINT_DEFAULTS = `# Qualor's defaults for a project without a SwiftLint configuration (config.md §6).
disabled_rules:
  - todo
  - multiple_closures_with_trailing_closure
trailing_whitespace:
  ignores_empty_lines: true
identifier_name:
  excluded: [i, j, k, x, "y", z, id]
line_length:
  ignores_urls: true
  ignores_comments: true
`;

/**
 * SwiftLint reads its configuration with Yams, a YAML 1.1 reader: `yes`/`on` are booleans there.
 * Qualor reads and writes YAML 1.1 too, so each value it keeps means to SwiftLint what it meant in
 * the project's file. Timestamps are left as text both ways (Yams decides what a date is).
 */
const YAML_OPTIONS = {
  version: '1.1' as const,
  customTags: (tags: Tags) =>
    tags.filter((t) =>
      typeof t === 'string' ? t !== 'timestamp' : t.tag !== 'tag:yaml.org,2002:timestamp',
    ),
};

/** Characters libyaml (Yams) reads as a line break, which the yaml package writes as they are. */
const YAML11_BREAKS = /[\u0085\u2028\u2029]/;

export interface SwiftlintPlan {
  /** The configuration Qualor writes to its work directory and passes as `--config`. */
  yaml: string;
  /** Repository-relative picomatch globs: a file must match one of them (none: every file). */
  included: string[];
  excluded: string[];
  /** Keys and path entries left out, for one log line. */
  dropped: string[];
  /** Rules the configuration asks for that the bundled SwiftLint cannot run (SourceKit). */
  notRun: string[];
  /** `qualor-default`, or the repository-relative path of the file read. */
  source: string;
}

const RULE_LISTS = ['only_rules', 'opt_in_rules', 'enabled_rules', 'disabled_rules'] as const;
/**
 * Global keys that write files, fetch URLs, change severities or the exit code, or apply only to
 * `swiftlint analyze` (config.md §6).
 */
const LEFT_OUT = new Set([
  'reporter',
  'strict',
  'lenient',
  'warning_threshold',
  'baseline',
  'write_baseline',
  'cache_path',
  'check_for_updates',
  'allow_zero_lintable_files',
  'swiftlint_version',
  'remote_timeout',
  'remote_timeout_if_cached',
  'analyzer_rules',
]);
const NOT_FOLLOWED = ['parent_config', 'child_config'] as const;
const SOURCEKIT_RULES = [...SWIFTLINT_RULES].filter(([, r]) => r.sourceKit).map(([id]) => id);
const needsSourceKit = (id: string) => SWIFTLINT_RULES.get(id)?.sourceKit === true;

/** SwiftLint reads a single string where it expects a list (`[String].array(of:)`). */
function stringList(value: unknown): string[] | null {
  if (typeof value === 'string') return [value];
  if (Array.isArray(value) && value.every((v) => typeof v === 'string')) return value as string[];
  return null;
}

function plainData(value: unknown): boolean {
  if (value === null || ['string', 'number', 'boolean'].includes(typeof value)) return true;
  if (Array.isArray(value)) return value.every(plainData);
  if (typeof value !== 'object') return false;
  const proto = Object.getPrototypeOf(value) as unknown;
  return (proto === Object.prototype || proto === null) && Object.values(value).every(plainData);
}

/**
 * A SwiftLint configuration's bytes as a plain mapping, or why it cannot be one. Any exception of
 * the parser (a RangeError on a document nested past the stack) is "cannot be parsed", never a
 * crash (ruling F9).
 */
export function parseSwiftlintYaml(
  bytes: Uint8Array,
): { ok: Record<string, unknown> } | { error: string } {
  let text: string;
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  } catch {
    return { error: 'is not UTF-8' };
  }
  let value: unknown;
  try {
    const doc = parseDocument(text, {
      ...YAML_OPTIONS,
      merge: true,
      uniqueKeys: true,
      prettyErrors: false,
    });
    if (doc.errors.length > 0) return { error: 'cannot be parsed as YAML' };
    // An unknown tag is only a warning for the yaml package; Yams would not read it as we do.
    if (doc.warnings.length > 0) return { error: 'holds a YAML value SwiftLint cannot read' };
    let aliases = 0;
    visit(doc, {
      Alias() {
        aliases += 1;
      },
    });
    // Counted here, because the yaml package's own limit weighs aliases by what they expand to.
    if (aliases > MAX_SWIFTLINT_CONFIG_ALIASES) {
      return { error: `has more than ${MAX_SWIFTLINT_CONFIG_ALIASES} YAML aliases` };
    }
    try {
      value = doc.toJS({ maxAliasCount: 100 });
    } catch (err) {
      // The yaml package's resource-exhaustion guard: a few aliases that expand exponentially.
      if (err instanceof ReferenceError) return { error: 'expands too many YAML aliases' };
      throw err;
    }
  } catch {
    return { error: 'cannot be parsed as YAML' };
  }
  if (value === null || value === undefined) return { ok: {} };
  if (typeof value !== 'object' || Array.isArray(value)) return { error: 'is not a YAML mapping' };
  if (!plainData(value)) return { error: 'holds a YAML value SwiftLint cannot read' };
  return { ok: value as Record<string, unknown> };
}

/** `included`/`excluded` (relative to the configuration's directory) as picomatch globs. */
function pathGlobs(
  key: string,
  value: unknown,
  dir: string,
  dropped: string[],
): string[] | { skip: string } {
  const entries = stringList(value);
  if (entries === null) return { skip: `${key} must be a list of paths` };
  const globs: string[] = [];
  for (const raw of entries) {
    const entry = raw.replace(/^(\.\/)+/, '').replace(/\/+$/, '');
    const escapes =
      entry === '' ||
      entry.startsWith('!') ||
      entry.startsWith('~') ||
      entry.includes('\\') ||
      path.posix.isAbsolute(entry) ||
      path.win32.isAbsolute(entry) ||
      /^[A-Za-z]:/.test(entry) ||
      entry.split('/').includes('..');
    if (escapes) {
      dropped.push(`${key}: ${shown(raw)}`);
      continue;
    }
    const glob = dir === '' ? entry : `${dir}/${entry}`;
    globs.push(glob, `${glob}/**`);
  }
  return globs;
}

/**
 * The configuration SwiftLint gets (config.md §6): the project's rule choices and rule settings,
 * the SourceKit rules disabled, and nothing that writes, fetches or changes the exit code. Every
 * problem is a skip reason (ruling F3). `dir` is the configuration's repository-relative
 * directory (`''` for the root, `/`-separated).
 */
export function planSwiftlintConfig(
  parsed: Record<string, unknown>,
  dir: string,
  source: string,
): SwiftlintPlan | { skip: string } {
  const name = shown(source);
  for (const key of NOT_FOLLOWED) {
    if (Object.hasOwn(parsed, key)) {
      return {
        skip: `${name} uses ${key}, which Qualor does not follow (config.md §6); make it self-contained, or set analyzers.swiftlint.configFile: qualor-default`,
      };
    }
  }
  const lists: Partial<Record<(typeof RULE_LISTS)[number], string[]>> = {};
  for (const key of RULE_LISTS) {
    if (!Object.hasOwn(parsed, key)) continue;
    const list = stringList(parsed[key]);
    if (list === null) return { skip: `${name}: ${key} must be a list of rule identifiers` };
    lists[key] = list;
  }
  const only = lists.only_rules ?? [];
  const optIn = [...(lists.opt_in_rules ?? []), ...(lists.enabled_rules ?? [])];
  const disabled = lists.disabled_rules ?? [];
  if (
    only.length > 0 &&
    (optIn.length > 0 || disabled.length > 0 || Object.hasOwn(parsed, 'enabled_rules'))
  ) {
    return {
      skip: `${name}: only_rules cannot be combined with disabled_rules, opt_in_rules or enabled_rules (SwiftLint refuses such a configuration)`,
    };
  }
  const out: Record<string, unknown> = {};
  const dropped: string[] = [];
  const notRun: string[] = [];
  if (only.length > 0) {
    notRun.push(...only.filter(needsSourceKit));
    const kept = only.filter((id) => !needsSourceKit(id));
    if (kept.length === 0) {
      return {
        skip: `${name}: every rule in only_rules needs SourceKit, which the bundled SwiftLint does not have`,
      };
    }
    out['only_rules'] = kept;
  } else {
    notRun.push(...optIn.filter(needsSourceKit));
    const kept = optIn.filter((id) => !needsSourceKit(id));
    if (kept.length > 0) out['opt_in_rules'] = kept;
    out['disabled_rules'] = [...new Set([...disabled, ...SOURCEKIT_RULES])];
  }
  const included: string[] = [];
  const excluded: string[] = [];
  for (const [key, value] of Object.entries(parsed)) {
    if ((RULE_LISTS as readonly string[]).includes(key)) continue;
    if (key === 'included' || key === 'excluded') {
      const globs = pathGlobs(key, value, dir, dropped);
      if (!Array.isArray(globs)) return { skip: `${name}: ${globs.skip}` };
      (key === 'included' ? included : excluded).push(...globs);
    } else if (key === 'custom_rules') {
      notRun.push('custom_rules');
    } else if (key === 'indentation' || (SWIFTLINT_RULES.has(key) && !LEFT_OUT.has(key))) {
      // Rule settings are kept as they are, regular expressions included (ruling F11).
      out[key] = value;
    } else {
      dropped.push(shown(key));
    }
  }
  const header = `# Written by Qualor from ${name.replace(/[\u2028\u2029]/g, '?')} (config.md §6).\n`;
  let yaml: string;
  try {
    yaml = header + stringify(out, YAML_OPTIONS);
  } catch {
    return { skip: `${name} cannot be parsed as YAML` };
  }
  if (YAML11_BREAKS.test(yaml)) {
    return {
      skip: `${name} holds U+0085, U+2028 or U+2029, which SwiftLint reads as a line break`,
    };
  }
  return { yaml, included, excluded, dropped, notRun, source };
}

function qualorDefault(): SwiftlintPlan {
  const parsed = parseSwiftlintYaml(new TextEncoder().encode(QUALOR_SWIFTLINT_DEFAULTS));
  if ('error' in parsed) throw new Error(`QUALOR_SWIFTLINT_DEFAULTS ${parsed.error}`);
  const plan = planSwiftlintConfig(parsed.ok, '', QUALOR_DEFAULT);
  if ('skip' in plan) throw new Error(`QUALOR_SWIFTLINT_DEFAULTS: ${plan.skip}`);
  return plan;
}

function exists(file: string): boolean {
  try {
    lstatSync(file);
    return true;
  } catch {
    return false;
  }
}

/** An explicit `configFile` that is a URL or outside the repository as written, or null. */
function configFileError(root: string, named: string): string | null {
  if (named === QUALOR_DEFAULT) return null;
  if (isUrl(named)) return `configFile ${shown(named)} is a URL (only repository files)`;
  // A link out of the repository on the way is the checkout's problem: a skip (ruling F3).
  return within(path.resolve(root), path.resolve(root, named))
    ? null
    : `configFile ${shown(named)} is outside the repository`;
}

/**
 * The plan for `root` (config.md §6): `configFile`, else a root `.swiftlint.yml`, else Qualor's
 * defaults layer. `error` only for a `configFile` that is a URL or outside the repository as
 * written; every problem of the file itself is a `skip` reason (ruling F3).
 */
export function loadSwiftlintConfig(
  root: string,
  configFile: string | null,
): SwiftlintPlan | { error: string } | { skip: string } {
  if (configFile === QUALOR_DEFAULT) return qualorDefault();
  let rel: string;
  if (configFile !== null) {
    const error = configFileError(root, configFile);
    if (error !== null) return { error };
    const abs = path.resolve(root, configFile);
    if (!exists(abs)) return { skip: `configFile ${shown(configFile)} does not exist` };
    rel = path.relative(root, abs);
  } else {
    rel = '.swiftlint.yml';
    if (!exists(path.join(root, rel))) return qualorDefault();
  }
  const posixRel = rel.split(path.sep).join('/');
  const name = shown(posixRel);
  let bytes: Buffer;
  try {
    // Opened once, non-blocking, type and size from the descriptor; a link must stay inside.
    bytes = readRepoConfigBytes(root, rel, MAX_SWIFTLINT_CONFIG_BYTES, name);
  } catch (err) {
    if (err instanceof WeblintConfigError) return { skip: err.message };
    return { skip: `${name} cannot be read` };
  }
  const parsed = parseSwiftlintYaml(bytes);
  if ('error' in parsed) return { skip: `${name} ${parsed.error}` };
  const dir = path.posix.dirname(posixRel);
  return planSwiftlintConfig(parsed.ok, dir === '.' ? '' : dir, posixRel);
}

/**
 * `qualor scan` stops with exit 2 on this before any analyzer runs (config.md §6, ruling F3): only
 * a `configFile` that is a URL or outside the repository. Every problem of the file is a skip.
 */
export function checkSwiftlintConfig(root: string, config: QualorConfig): string | null {
  const named = config.analyzers.swiftlint.configFile;
  return named === null ? null : configFileError(root, named);
}
