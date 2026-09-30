import { lstatSync } from 'node:fs';
import path from 'node:path';
import { isUrl, SWIFTLINT_RULES, type QualorConfig } from '@qualor/shared';
import { parseDocument, visit, type ScalarTag, type Tags } from 'yaml';
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
 * Yams's booleans (its `Resolver`): yes/no, true/false and on/off in three casings. The yaml
 * package's YAML 1.1 schema also reads `y`/`n` as booleans, which Yams reads as strings, so
 * `excluded: [x, y]` would change meaning (fix round 1, Important 1).
 */
const YAMS_BOOLS: ScalarTag[] = [
  [true, /^(?:yes|Yes|YES|true|True|TRUE|on|On|ON)$/] as const,
  [false, /^(?:no|No|NO|false|False|FALSE|off|Off|OFF)$/] as const,
].map(([value, test]) => ({
  identify: (v: unknown) => v === value,
  default: true,
  tag: 'tag:yaml.org,2002:bool',
  test,
  resolve: () => value,
}));

/** Yams's decimal float with a point: `1.5`, `5.`, `.5`, never a bare `.`. */
const YAMS_DECIMAL = /^(?:[-+]?[0-9][0-9_]*\.[0-9_]*|\.[0-9_]+)$/;

/**
 * The yaml package's 1.1 float reads a bare `.` as NaN; Yams's float needs a digit, so
 * `included: [.]` is the directory for both (fix round 1, Minor 3).
 */
function yamsDecimal(t: Tags[number]): Tags[number] {
  if (typeof t === 'string' || t.collection !== undefined) return t;
  const scalar = t as ScalarTag;
  return scalar.test?.test('.') === true ? { ...scalar, test: YAMS_DECIMAL } : t;
}

/**
 * SwiftLint reads its configuration with Yams, a YAML 1.1 reader: `yes`/`on` are booleans there.
 * Qualor reads YAML 1.1 with Yams's booleans, so each value it keeps means to SwiftLint what it
 * meant in the project's file. Timestamps are left as text (Yams decides what a date is).
 */
const YAML_OPTIONS = {
  version: '1.1' as const,
  customTags: (tags: Tags) => [
    ...YAMS_BOOLS,
    ...tags
      .filter((t) =>
        typeof t === 'string'
          ? t !== 'timestamp' && t !== 'bool'
          : t.tag !== 'tag:yaml.org,2002:timestamp' && t.tag !== 'tag:yaml.org,2002:bool',
      )
      .map(yamsDecimal),
  ],
};

/** The yaml package's own guard against aliases that expand exponentially (its default). */
const MAX_ALIAS_EXPANSION = 100;

/** Thrown by `quoted` for a string libyaml cannot hold (a lone UTF-16 surrogate). */
class UnwritableString extends Error {}

/**
 * A double-quoted YAML scalar holding only printable ASCII: every other character is an escape
 * (`\xHH`, `\uHHHH`, `\UHHHHHHHH`), which libyaml decodes after reading. So no raw control, C1,
 * U+0085/U+2028/U+2029 line break or U+FEFF reaches libyaml, which refuses or re-reads them (fix
 * round 1, Important 2), and `$` is written as `\x24`: SwiftLint replaces `${VAR}` in the text of
 * its configuration before parsing it, so no kept value can read the environment (Minor 2).
 * A string is always quoted, so Yams reads it as a string whatever it looks like (Minor 1).
 */
function quoted(s: string): string {
  let out = '"';
  for (const ch of s) {
    const cp = ch.codePointAt(0) ?? 0;
    if (cp >= 0xd800 && cp <= 0xdfff) throw new UnwritableString();
    const hex = (width: number) => cp.toString(16).padStart(width, '0');
    if (ch === '"' || ch === '\\') out += `\\${ch}`;
    else if (cp >= 0x20 && cp < 0x7f && ch !== '$') out += ch;
    else if (cp <= 0xff) out += `\\x${hex(2)}`;
    else if (cp <= 0xffff) out += `\\u${hex(4)}`;
    else out += `\\U${hex(8)}`;
  }
  return `${out}"`;
}

function scalar(value: unknown): string {
  if (typeof value === 'string') return quoted(value);
  if (typeof value === 'boolean') return value ? 'true' : 'false';
  if (typeof value === 'number') {
    if (Number.isNaN(value)) return '.nan';
    if (!Number.isFinite(value)) return value > 0 ? '.inf' : '-.inf';
    return String(value);
  }
  return 'null';
}

const isEmpty = (v: object) => (Array.isArray(v) ? v.length === 0 : Object.keys(v).length === 0);

/** Block-style YAML lines for a plain value (`parseSwiftlintYaml` checked it is plain data). */
function emit(value: unknown, indent: string, lines: string[], head: string): void {
  if (value === null || typeof value !== 'object') {
    lines.push(`${head} ${scalar(value)}`);
  } else if (isEmpty(value)) {
    lines.push(`${head} ${Array.isArray(value) ? '[]' : '{}'}`);
  } else {
    lines.push(head);
    if (Array.isArray(value)) {
      for (const item of value) emit(item, `${indent}  `, lines, `${indent}  -`);
    } else {
      for (const [k, v] of Object.entries(value)) {
        emit(v, `${indent}  `, lines, `${indent}  ${quoted(k)}:`);
      }
    }
  }
}

/** The written configuration's body: top-level keys at column 0. */
function writeYaml(out: Record<string, unknown>): string {
  const lines: string[] = [];
  for (const [k, v] of Object.entries(out)) emit(v, '', lines, `${quoted(k)}:`);
  return lines.map((l) => `${l}\n`).join('');
}

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
      value = doc.toJS({ maxAliasCount: MAX_ALIAS_EXPANSION });
    } catch (err) {
      // The yaml package's resource-exhaustion guard: a few aliases that expand exponentially.
      if (err instanceof ReferenceError) return { error: 'expands too many YAML aliases' };
      throw err;
    }
    if (value === null || value === undefined) return { ok: {} };
    if (typeof value !== 'object' || Array.isArray(value)) {
      return { error: 'is not a YAML mapping' };
    }
    // Recursive, so inside the try as well.
    if (!plainData(value)) return { error: 'holds a YAML value SwiftLint cannot read' };
    return { ok: value as Record<string, unknown> };
  } catch {
    return { error: 'cannot be parsed as YAML' };
  }
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
      raw === '' ||
      raw.startsWith('!') ||
      raw.startsWith('~') ||
      raw.includes('\\') ||
      path.posix.isAbsolute(raw) ||
      path.win32.isAbsolute(raw) ||
      /^[A-Za-z]:/.test(raw) ||
      raw.split('/').includes('..');
    if (escapes) {
      dropped.push(`${key}: ${shown(raw)}`);
      continue;
    }
    // `.` and `./` name the configuration's directory itself (fix round 1, Minor 3).
    if (entry === '' || entry === '.') {
      globs.push(...(dir === '' ? ['**'] : [dir, `${dir}/**`]));
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
  // The name is shown as printable ASCII: a comment ends at any line break libyaml knows.
  const header = `# Written by Qualor from ${name.replace(/[^\x20-\x7e]/g, '?')} (config.md §6).\n`;
  let yaml: string;
  try {
    yaml = header + writeYaml(out);
  } catch (err) {
    if (err instanceof UnwritableString) {
      return { skip: `${name} holds a lone UTF-16 surrogate, which SwiftLint cannot read` };
    }
    // A value nested past the stack (fix round 1, Minor 4).
    return { skip: `${name} cannot be written as YAML` };
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
