import path from 'node:path';
import { parseDocument } from 'yaml';
import { readRepoConfig, repoEntryExists, WeblintConfigError } from './weblint';

/**
 * The stylelint packages Qualor bundles, by the config key that may name them (plan 8D).
 * tools/analyzers/weblint/bundled.mjs holds the same lists for the pass (its run.test.ts checks).
 */
export const STYLELINT_BUNDLED = {
  extends: [
    'stylelint-config-recommended',
    'stylelint-config-recommended-scss',
    'stylelint-config-standard',
    'stylelint-config-standard-scss',
  ],
  plugins: ['stylelint-scss'],
  customSyntax: ['postcss-scss'],
} as const satisfies Record<'extends' | 'plugins' | 'customSyntax', readonly string[]>;

export type StylelintConfig = Record<string, unknown>;

/**
 * Framework syntax stylelint-config-recommended would report as unknown (final review, ruling
 * D13): Angular `::ng-deep`; Vue `:deep()`, `:slotted()`, `:global()`, `::v-deep`; CSS Modules
 * `:global`, `:local`, `:export`, `:import`, `composes`; Tailwind v3/v4 at-rules, the `@apply`
 * prelude and `theme()`, `screen()`, `--alpha()`, `--spacing()`.
 */
const FRAMEWORK_AT_RULES = [
  'tailwind',
  'apply',
  'config',
  'theme',
  'utility',
  'variant',
  'custom-variant',
  'plugin',
  'source',
  'reference',
  'screen',
  'responsive',
  'variants',
];
const FRAMEWORK_SELECTOR_RULES = {
  'selector-pseudo-element-no-unknown': [
    true,
    { ignorePseudoElements: ['ng-deep', 'v-deep', 'v-global', 'v-slotted'] },
  ],
  'selector-pseudo-class-no-unknown': [
    true,
    { ignorePseudoClasses: ['deep', 'global', 'local', 'slotted', 'export', 'import'] },
  ],
  'property-no-unknown': [
    true,
    // `:import("./x.css")` carries its source, so a pattern rather than the plain selector.
    { ignoreProperties: ['composes'], ignoreSelectors: [':export', '/^:import/'] },
  ],
};

/**
 * A repository without a stylelint configuration, or `configFile: qualor-default` (decision D2):
 * stylelint-config-recommended without `no-descending-specificity` (a style preference that floods
 * any stylesheet grown by cascade order) and with the framework carve-outs above. The SCSS override
 * extends stylelint-config-recommended again through stylelint-config-recommended-scss, which would
 * reset the rule options, so it repeats the carve-outs that still apply to SCSS; the top-level rules
 * also win over that `extends`, so it turns off again what the SCSS config turns off.
 */
export const QUALOR_DEFAULT_STYLELINT: StylelintConfig = {
  extends: ['stylelint-config-recommended'],
  rules: {
    'no-descending-specificity': null,
    ...FRAMEWORK_SELECTOR_RULES,
    'at-rule-no-unknown': [true, { ignoreAtRules: FRAMEWORK_AT_RULES }],
    'at-rule-prelude-no-invalid': [true, { ignoreAtRules: ['apply'] }],
    'function-no-unknown': [true, { ignoreFunctions: ['theme', 'screen', '--alpha', '--spacing'] }],
  },
  overrides: [
    {
      files: ['**/*.scss'],
      extends: ['stylelint-config-recommended-scss'],
      // Rules the top level sets win over this override's `extends`, so the ones
      // stylelint-config-recommended-scss turns off for SCSS are turned off again here.
      rules: {
        'at-rule-no-unknown': null,
        'at-rule-prelude-no-invalid': null,
        'function-no-unknown': null,
        ...FRAMEWORK_SELECTOR_RULES,
        'scss/at-rule-no-unknown': [true, { ignoreAtRules: FRAMEWORK_AT_RULES }],
      },
    },
  ],
};

const MAX_CONFIG_BYTES = 1024 * 1024;
const MAX_PACKAGE_JSON_BYTES = 4 * 1024 * 1024;

/** cosmiconfig 9's search places for `stylelint`, in stylelint 17's order (verified facts F9). */
export const STYLELINT_CONFIG_FILES: readonly string[] = [
  'package.json',
  '.stylelintrc',
  '.stylelintrc.json',
  '.stylelintrc.yaml',
  '.stylelintrc.yml',
  '.stylelintrc.js',
  '.stylelintrc.ts',
  '.stylelintrc.cjs',
  '.stylelintrc.mjs',
  '.config/stylelintrc',
  '.config/stylelintrc.json',
  '.config/stylelintrc.yaml',
  '.config/stylelintrc.yml',
  '.config/stylelintrc.js',
  '.config/stylelintrc.ts',
  '.config/stylelintrc.cjs',
  '.config/stylelintrc.mjs',
  'stylelint.config.js',
  'stylelint.config.ts',
  'stylelint.config.cjs',
  'stylelint.config.mjs',
];

const EXECUTABLE = /\.(?:[cm]?js|[cm]?ts)$/i;
const ESCAPE =
  "set analyzers.stylelint.configFile: qualor-default to use Qualor's own configuration";
/** Keys a root config may set. */
const TOP_KEYS = new Set([
  'extends',
  'plugins',
  'customSyntax',
  'rules',
  'overrides',
  'ignoreFiles',
  'defaultSeverity',
  'reportNeedlessDisables',
  'reportInvalidScopeDisables',
  'reportDescriptionlessDisables',
  'reportUnscopedDisables',
  'ignoreDisables',
  'configurationComment',
  'languageOptions',
  'validate',
]);
/** Keys an `overrides` entry may set. */
const OVERRIDE_KEYS = new Set([
  'files',
  'extends',
  'plugins',
  'customSyntax',
  'rules',
  'languageOptions',
  'defaultSeverity',
]);
/** Dropped: Qualor passes its own `fix: false`, `cache: false` and `allowEmptyInput`. */
const IGNORED_KEYS = new Set(['$schema', 'fix', 'cache', 'allowEmptyInput']);

const isObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === 'object' && v !== null && !Array.isArray(v);
const isGlobs = (v: unknown): boolean =>
  typeof v === 'string' ||
  (Array.isArray(v) && v.length > 0 && v.every((g) => typeof g === 'string'));

/**
 * An `ignoreFiles` glob that names something outside the repository: absolute (POSIX, a drive or
 * UNC path) or with a `..` segment, negated or not. Such a glob could only narrow the CLI's list,
 * but it would make stylelint look outside the checkout, so it is refused.
 */
function leavesRoot(glob: string): boolean {
  const g = glob.replace(/^!+/, '');
  return (
    path.posix.isAbsolute(g) ||
    path.win32.isAbsolute(g) ||
    /^[a-z]:/i.test(g) ||
    // Brace and extglob alternatives (`{..,src}/**`, `{/etc,x}`, `+(..)/x`) expand to paths too.
    /(?:^|[{,(|])\s*(?:[\\/]|[a-z]:)/i.test(g) ||
    g.split(/[\\/{},()|]/).some((segment) => segment.trim() === '..')
  );
}

function names(value: unknown, what: string, allowed: readonly string[]): unknown {
  const list = typeof value === 'string' ? [value] : value;
  if (!Array.isArray(list) || !list.every((n): n is string => typeof n === 'string')) {
    throw new WeblintConfigError(`${what} must be a package name or a list of them`);
  }
  for (const n of list) {
    if (!allowed.includes(n)) {
      throw new WeblintConfigError(
        `${what} "${n}" is not one of the packages Qualor bundles (${allowed.join(', ')})`,
      );
    }
  }
  return value;
}

function block(raw: unknown, where: string, allowed: ReadonlySet<string>): StylelintConfig {
  if (!isObject(raw))
    throw new WeblintConfigError(`${where} is not a stylelint configuration object`);
  const out: StylelintConfig = {};
  for (const [key, value] of Object.entries(raw)) {
    if (IGNORED_KEYS.has(key)) continue;
    if (!allowed.has(key))
      throw new WeblintConfigError(`${where} sets "${key}", which Qualor does not support`);
    if (key === 'extends') out[key] = names(value, `${where} extends`, STYLELINT_BUNDLED.extends);
    else if (key === 'plugins')
      out[key] = names(value, `${where} plugins`, STYLELINT_BUNDLED.plugins);
    else if (key === 'customSyntax') {
      if (typeof value !== 'string')
        throw new WeblintConfigError(`${where} customSyntax must be a package name`);
      out[key] = names(value, `${where} customSyntax`, STYLELINT_BUNDLED.customSyntax);
    } else if (key === 'rules') {
      if (!isObject(value)) throw new WeblintConfigError(`${where} rules must be an object`);
      for (const id of Object.keys(value)) {
        // `constructor`, `toString`, `__proto__`…: stylelint looks rules up on a plain object.
        if (id in Object.prototype)
          throw new WeblintConfigError(
            `${where} rules sets "${id}", which is not a stylelint rule`,
          );
      }
      out[key] = value;
    } else if (key === 'overrides') {
      if (!Array.isArray(value)) throw new WeblintConfigError(`${where} overrides must be a list`);
      out[key] = value.map((entry, i) => {
        const b = block(entry, `${where} overrides[${i}]`, OVERRIDE_KEYS);
        if (!isGlobs(b['files']))
          throw new WeblintConfigError(`${where} overrides[${i}] has no "files" globs`);
        return b;
      });
    } else if (key === 'files' || key === 'ignoreFiles') {
      if (!isGlobs(value)) throw new WeblintConfigError(`${where} ${key} must be globs`);
      if (key === 'ignoreFiles') {
        for (const glob of [value].flat() as string[]) {
          if (leavesRoot(glob))
            throw new WeblintConfigError(
              `${where} ignoreFiles "${glob}" is outside the repository`,
            );
        }
      }
      out[key] = value;
    } else out[key] = value;
  }
  return out;
}

const scssExtends = (v: unknown): boolean =>
  [v].flat().some((n) => typeof n === 'string' && n.endsWith('-scss'));
function setsScssSyntax(c: StylelintConfig): boolean {
  const overrides = Array.isArray(c['overrides']) ? (c['overrides'] as StylelintConfig[]) : [];
  return (
    'customSyntax' in c ||
    scssExtends(c['extends']) ||
    overrides.some((o) => 'customSyntax' in o || scssExtends(o['extends']))
  );
}

/**
 * A project configuration as Qualor passes it on: only bundled package names, no key that loads
 * code, `fix`/`cache` dropped, and postcss-scss for `.scss` when the project set no SCSS syntax.
 */
export function sanitizeStylelintConfig(raw: unknown, source: string): StylelintConfig {
  const config = block(raw, source, TOP_KEYS);
  if (!setsScssSyntax(config)) {
    const overrides = Array.isArray(config['overrides']) ? config['overrides'] : [];
    config['overrides'] = [...overrides, { files: ['**/*.scss'], customSyntax: 'postcss-scss' }];
  }
  return config;
}

/**
 * One YAML document as plain data: the core schema, no duplicate keys, no tag the schema does not
 * know (an unresolved tag is only a warning in `yaml`, so any warning is refused), and at most 100
 * alias expansions (an alias bomb throws).
 */
function parseYamlData(text: string): unknown {
  const doc = parseDocument(text, { schema: 'core', uniqueKeys: true, merge: false });
  if (doc.errors.length > 0 || doc.warnings.length > 0) throw new SyntaxError('invalid YAML');
  return doc.toJS({ maxAliasCount: 100 });
}

function load(root: string, rel: string): StylelintConfig {
  if (EXECUTABLE.test(rel)) {
    throw new WeblintConfigError(
      `${rel} is executable configuration, which Qualor never runs (config.md §6); use a .stylelintrc.json, or`,
    );
  }
  const text = readRepoConfig(root, rel, MAX_CONFIG_BYTES);
  let raw: unknown;
  try {
    raw = rel.endsWith('.json') ? JSON.parse(text) : parseYamlData(text);
  } catch {
    throw new WeblintConfigError(
      `${rel} is not valid ${rel.endsWith('.json') ? 'JSON' : 'YAML or JSON'}`,
    );
  }
  return sanitizeStylelintConfig(raw, rel);
}

/**
 * package.json's `stylelint` key; undefined when there is no package.json or it has no such key.
 * A package.json that cannot be used (outside the repository, too large, not JSON) is a skip
 * reason, never silently passed over: stylelint would have read its key.
 */
function packageJsonConfig(root: string): unknown {
  if (!repoEntryExists(path.join(root, 'package.json'))) return undefined;
  const text = readRepoConfig(root, 'package.json', MAX_PACKAGE_JSON_BYTES);
  let pkg: unknown;
  try {
    pkg = JSON.parse(text);
  } catch {
    throw new WeblintConfigError('package.json is not valid JSON');
  }
  return isObject(pkg) ? pkg['stylelint'] : undefined;
}

/**
 * The root .stylelintignore's text, null without one, or a skip reason of its own. The CLI hands the
 * pass this text (written into its work directory), never the path: a link inside the repository is
 * allowed here (ruling D8) and the file is read once (no time-of-check/time-of-use gap).
 */
function stylelintIgnore(root: string): string | null | { skip: string } {
  if (!repoEntryExists(path.join(root, '.stylelintignore'))) return null;
  try {
    return readRepoConfig(root, '.stylelintignore', MAX_CONFIG_BYTES);
  } catch (err) {
    if (!(err instanceof WeblintConfigError)) throw err;
    // configFile does not help here: the ignore file applies whatever the configuration.
    return { skip: `${err.message}; fix or remove .stylelintignore` };
  }
}

/**
 * config.md §6: the stylelint configuration Qualor runs — `configFile`, else the first of
 * stylelint's own search places at the repository root, else Qualor's default — or the reason
 * stylelint is skipped. Never evaluates a configuration.
 */
export function resolveStylelintConfig(
  root: string,
  configFile: string | null,
): { config: StylelintConfig; source: string; ignore: string | null } | { skip: string } {
  const ignore = stylelintIgnore(root);
  if (ignore !== null && typeof ignore === 'object') return ignore;
  try {
    if (configFile === 'qualor-default') {
      return { config: QUALOR_DEFAULT_STYLELINT, source: 'qualor-default', ignore };
    }
    if (configFile !== null) return { config: load(root, configFile), source: configFile, ignore };
    for (const rel of STYLELINT_CONFIG_FILES) {
      if (rel === 'package.json') {
        const raw = packageJsonConfig(root);
        if (raw === undefined) continue;
        const source = 'package.json "stylelint"';
        return { config: sanitizeStylelintConfig(raw, source), source, ignore };
      }
      if (repoEntryExists(path.join(root, rel)))
        return { config: load(root, rel), source: rel, ignore };
    }
    return { config: QUALOR_DEFAULT_STYLELINT, source: 'qualor-default', ignore };
  } catch (err) {
    if (!(err instanceof WeblintConfigError)) throw err;
    const sep = err.message.endsWith(' or') ? ' ' : '; ';
    return { skip: `${err.message}${sep}${ESCAPE}` };
  }
}
