// Qualor's stylelint pass (config.md §6, plan 8D): stylelint 17 with the configuration the CLI
// resolved (the project's JSON/YAML config, or Qualor's default), using only the packages
// installed next to this file. Every bundled package name in the config becomes the absolute path
// of this directory's copy (ruling D9), so stylelint never resolves a name from the checkout's
// node_modules or a linted file's directory; anything else is refused (exit 2). stylelint gets the
// config inline (its own search for configuration files never runs), `configBasedir` the
// repository root (so the project's relative override and ignoreFiles globs mean what they say)
// and `cwd` this directory (so no fallback lookup, and no default .stylelintignore, is ever taken
// from the checkout). The project's .stylelintignore, whose text the CLI copies into its work
// directory, is applied here, relative to the root, with stylelint's own `ignore` package. PostCSS configs and browserslist are never read. It never
// writes to the checkout (`fix: false`, `cache: false`).
//   node stylelint.mjs --root <dir> --out <file.sarif> --files <list.json> --config <config.json>
//                      [--ignore-file <path>]
// Prints one JSON line
//   {"files":N,"listed":N,"parseErrors":N,"unknownRules":[...],"invalidOptions":N}:
// files counts the files linted (listed, and not ignored by .stylelintignore or ignoreFiles),
// listed the usable entries of the --files list; parseErrors counts the linted files that did not
// parse or that stylelint threw on (skipped, ruling D12).
// Exit 0 whenever the log is written, 2 on any error: a refused configuration, a stylelint
// ConfigurationError, or a throw on every file linted when there are two or more.
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import stylelint from 'stylelint';
import recommended from 'stylelint-config-recommended';
import recommendedScss from 'stylelint-config-recommended-scss';
import scssPlugins from 'stylelint-scss';
import { BUNDLED } from './bundled.mjs';
import {
  https,
  listedFiles,
  option,
  readJson,
  region,
  required,
  run,
  stderr,
  uriOf,
} from './files.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const SOURCE = /\.(?:css|scss)$/i;

/** The absolute path of this directory's copy of a bundled package. */
export const bundledPath = (name) => fileURLToPath(import.meta.resolve(name));

/**
 * A copy of `config` with every bundled package name replaced by the absolute path of its copy
 * here. Throws on any other module reference and on `processors` and `referenceFiles`, at the top
 * and in `overrides`. `config` itself is never changed.
 */
export function resolveBundled(config, resolve = bundledPath) {
  const names = (value, kind) => {
    const list = typeof value === 'string' ? [value] : value;
    if (
      !Array.isArray(list) ||
      !list.every((n) => typeof n === 'string' && BUNDLED[kind].includes(n))
    ) {
      throw new Error(
        `refusing ${kind} ${JSON.stringify(value)}: only ${BUNDLED[kind].join(', ')}`,
      );
    }
    const paths = list.map(resolve);
    return typeof value === 'string' ? paths[0] : paths;
  };
  const block = (c, nested = false) => {
    if (c === null || typeof c !== 'object' || Array.isArray(c)) {
      throw new Error('a stylelint config must be an object');
    }
    for (const key of ['processors', 'referenceFiles']) {
      if (key in c) throw new Error(`refusing ${key}`);
    }
    if (nested && 'overrides' in c) throw new Error('refusing overrides inside an override');
    const out = structuredClone(c);
    if ('extends' in c) out.extends = names(c.extends, 'extends');
    if ('plugins' in c) out.plugins = names(c.plugins, 'plugins');
    if ('customSyntax' in c) {
      if (typeof c.customSyntax !== 'string') {
        throw new Error('refusing a customSyntax that is not a package name');
      }
      out.customSyntax = names(c.customSyntax, 'customSyntax');
    }
    return out;
  };
  const top = block(config);
  if ('overrides' in config) {
    if (!Array.isArray(config.overrides)) throw new Error('overrides must be a list');
    top.overrides = config.overrides.map((o) => block(o, true));
  }
  return top;
}

/** Every rule this stylelint knows (core and stylelint-scss) with its help link, and the "avoid errors" ones. */
export async function ruleCatalogue() {
  const known = new Map();
  for (const [id, rule] of Object.entries(stylelint.rules)) {
    known.set(id, https((await rule)?.meta?.url));
  }
  for (const { ruleName, rule } of scssPlugins) known.set(ruleName, https(rule?.meta?.url));
  const possibleErrors = new Set(
    [recommended, recommendedScss]
      .flatMap((c) => Object.entries(c.rules ?? {}))
      .filter(([, setting]) => setting !== null)
      .map(([id]) => id),
  );
  return { known, possibleErrors };
}

/** stylelint's text without its trailing " (<rule>)". */
export function messageText(w) {
  const suffix = ` (${w.rule})`;
  return w.text.endsWith(suffix) ? w.text.slice(0, -suffix.length) : w.text;
}

/**
 * The project's .stylelintignore as a filter over root-relative paths, read with stylelint's own
 * `ignore` package (the copy stylelint resolves). `ignoreFile` is the copy of its text the CLI
 * wrote into its work directory, like the configuration, never the checkout's file.
 */
function ignoreFilter(root, ignoreFile) {
  if (ignoreFile === undefined) return () => false;
  const ignore = createRequire(fileURLToPath(import.meta.resolve('stylelint')))('ignore');
  const ignorer = ignore().add(readFileSync(path.resolve(ignoreFile), 'utf8'));
  return (full) => ignorer.ignores(uriOf(root, full));
}

/**
 * stylelint's result for one file as `{ res }` (undefined when it returned none), or
 * `{ threw: true }` when it threw on the file.
 */
async function lintFile(root, file, config) {
  try {
    const {
      results: [res],
    } = await stylelint.lint({
      code: readFileSync(file, 'utf8'),
      codeFilename: file,
      config: structuredClone(config),
      configBasedir: root,
      cwd: here,
      cache: false,
      fix: false,
      allowEmptyInput: true,
    });
    return { res };
  } catch (err) {
    // stylelint turns only a CssSyntaxError into a warning and rethrows the rest. A problem of
    // the configuration fails the pass; one file's own (a nesting depth that overflows the
    // stack, a source map PostCSS cannot decode) is counted and skipped (ruling D12).
    if (err?.name === 'ConfigurationError') throw err;
    stderr(`stylelint: ${uriOf(root, file)} not linted: ${err?.message ?? err}\n`);
    return { threw: true };
  }
}

/** One stylelint warning as a SARIF result. */
function sarifResult(root, file, w) {
  return {
    ruleId: w.rule,
    level: w.severity === 'warning' ? 'warning' : 'error',
    message: { text: messageText(w) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: uriOf(root, file) },
          region: region(w.line, w.column, w.endLine, w.endColumn),
        },
      },
    ],
  };
}

/**
 * Adds one linted file's warnings to `found` (its results, the rules they use, unknown rules and
 * invalid options); true when the file did not parse.
 */
function addWarnings(root, file, res, found) {
  for (const w of res.invalidOptionWarnings ?? []) found.invalidOptions.add(w.text);
  let broken = false;
  for (const w of res.warnings) {
    if (w.rule === 'CssSyntaxError') {
      broken = true;
      continue;
    }
    if (w.rule.startsWith('--')) continue; // --report-needless-disables and the like: not findings
    if (!found.known.has(w.rule)) {
      found.unknownRules.add(w.rule);
      continue;
    }
    found.used.add(w.rule);
    found.results.push(sarifResult(root, file, w));
  }
  return broken;
}

/** The rules the findings use as SARIF rule descriptors, by id. */
function sarifRules(used, known, possibleErrors) {
  return [...used].sort().map((id) => ({
    id,
    name: id,
    shortDescription: { text: id },
    ...(known.get(id) && { helpUri: known.get(id) }),
    properties: { category: possibleErrors.has(id) ? 'possible-error' : 'convention' },
  }));
}

async function main(args) {
  const root = path.resolve(required(args, '--root'));
  const out = path.resolve(required(args, '--out'));
  const config = resolveBundled(readJson(required(args, '--config')));
  const ignored = ignoreFilter(root, option(args, '--ignore-file'));
  const files = listedFiles(root, readJson(required(args, '--files')), SOURCE);
  const { known, possibleErrors } = await ruleCatalogue();
  const version = JSON.parse(
    readFileSync(path.join(here, 'node_modules/stylelint/package.json'), 'utf8'),
  ).version;

  const used = new Set();
  const results = [];
  const unknownRules = new Set();
  const invalidOptions = new Set();
  let parseErrors = 0;
  let linted = 0;
  let threw = 0;
  const found = { known, used, results, unknownRules, invalidOptions };
  for (const file of files) {
    if (ignored(file)) continue;
    const outcome = await lintFile(root, file, config);
    if (outcome.threw) {
      linted += 1;
      threw += 1;
      parseErrors += 1;
      continue;
    }
    if (outcome.res === undefined || outcome.res.ignored) continue;
    linted += 1;
    if (addWarnings(root, file, outcome.res, found)) parseErrors += 1;
  }

  // One file in scope that throws is a parse error like any other; only a throw on every one of
  // several files says the pass itself is broken (final review, minor 7).
  if (linted >= 2 && threw === linted) {
    throw new Error(`stylelint failed on every file it linted (${threw})`);
  }

  const rules = sarifRules(used, known, possibleErrors);
  writeFileSync(
    out,
    JSON.stringify({
      version: '2.1.0',
      $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
      runs: [
        {
          tool: {
            driver: { name: 'stylelint', version, informationUri: 'https://stylelint.io', rules },
          },
          results,
        },
      ],
    }),
  );
  process.stdout.write(
    `${JSON.stringify({ files: linted, listed: files.length, parseErrors, unknownRules: [...unknownRules].sort(), invalidOptions: invalidOptions.size })}\n`,
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await run('stylelint', main);
}
