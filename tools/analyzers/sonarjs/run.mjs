// Qualor's sonarjs pass (config.md §6): eslint-plugin-sonarjs 2.0.4 (LGPL-3.0, frozen: later
// versions are under the SONAR Source-Available License) with its own `recommended` config, run by
// Qualor's own ESLint 9. Never loads the project's config, plugins or node_modules: everything is
// imported from this directory, and ESLint gets the config inline (overrideConfigFile: true).
//   node run.mjs --root <dir> --out <file.sarif> [--files <list.json>] [--type-checking on|off]
//                [--exclude <glob>]...
// Writes a SARIF 2.1.0 log keyed by RSPEC ids (S1192) and prints one JSON line
// {"typeChecking":"on"|"off"|"fallback","files":N,"parseErrors":N,"disabledRules":["S…"]}.
// Exit 0 whenever the log is written, 2 on an internal error.
// With --files (a JSON array of paths, what the CLI passes: the scan's in-scope JS/TS files, so
// Qualor's excludes and .gitignore apply), it lints exactly those, after checking each again: a
// regular JS/TS file inside --root, reached without a symbolic link or junction, never under
// node_modules or .git. Without it, it lints the regular files it finds itself under --root, with
// the same rules. An --exclude can narrow either set but never widen it.
import {
  existsSync,
  lstatSync,
  readdirSync,
  readFileSync,
  realpathSync,
  writeFileSync,
} from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';
import sonarjs from 'eslint-plugin-sonarjs';
import tsParser from '@typescript-eslint/parser';

const here = path.dirname(fileURLToPath(import.meta.url));

// S7060 (no-self-import) decorates eslint-plugin-import's rule, whose resolver lookup
// (eslint-module-utils resolve.js `requireResolver`) require()s `eslint-import-resolver-<name>`
// resolved relative to the linted file first: a checkout committing
// node_modules/eslint-import-resolver-node would run its code inside the scan, and no
// `import/resolver` setting avoids that lookup. So the same rule is rebuilt here around the
// bundled resolver, called in-process: it only reads package.json files to resolve a path, and
// never loads a module from the checkout. The plugin's own S7060 decorator still wraps it.
const requireHere = createRequire(import.meta.url);
const requireSonarjs = createRequire(
  requireHere.resolve('eslint-plugin-sonarjs/cjs/S7060/index.js'),
);
const requireImport = createRequire(requireSonarjs.resolve('eslint-plugin-import'));

/** S7060 with the bundled eslint-import-resolver-node, never one found next to the linted file. */
export function safeNoSelfImport() {
  const original = requireImport('eslint-plugin-import').rules['no-self-import'];
  const moduleVisitor = requireImport('eslint-module-utils/moduleVisitor').default;
  const resolver = requireImport('eslint-import-resolver-node');
  const { decorate } = requireSonarjs('./decorator.js');
  return decorate({
    meta: original.meta,
    create(context) {
      const file = context.physicalFilename ?? context.filename;
      return moduleVisitor(
        (source, node) => {
          if (file === '<text>') return;
          const resolved = resolver.resolve(source.value, file, {});
          if (resolved.found && resolved.path === file)
            context.report({ node, message: 'Module imports itself.' });
        },
        { commonjs: true },
      );
    },
  });
}

/** The plugin, with S7060 replaced by `safeNoSelfImport()`: what the pass registers as `sonarjs`. */
export function safePlugin() {
  return { ...sonarjs, rules: { ...sonarjs.rules, 'no-self-import': safeNoSelfImport() } };
}

/** Paths never linted and directories never entered, whatever the excludes say. */
const NEVER = ['**/node_modules/**', '**/.git/**'];
const NEVER_DIRS = new Set(['node_modules', '.git']);
const SOURCE = /\.(?:[cm]?[jt]s|[jt]sx)$/;

// The rule named in the error ESLint throws when a rule crashes: "Error while loading rule
// 'sonarjs/<name>'" (in create) or "Rule: \"sonarjs/<name>\"" (while linting a file).
const CRASHED_RULE = /rule '(sonarjs\/[\w-]+)'|Rule: "(sonarjs\/[\w-]+)"/;
// Decorated ESLint core rules whose ESLint 9 implementation reads options that ESLint 8 (which
// SonarJS 2.0.4 was built against) defaulted itself; ESLint 9 fills them only from a core rule's
// own meta.defaultOptions, which the plugin's wrapper does not carry, so without these they crash
// on create. The values are ESLint 9's defaults, i.e. what the same rules did under ESLint 8.
const OPTIONS = {
  'sonarjs/no-empty-function': [{ allow: [] }],
  'sonarjs/no-unused-expressions': [
    {
      allowShortCircuit: false,
      allowTernary: false,
      allowTaggedTemplates: false,
      enforceForJSX: false,
      ignoreDirectives: false,
    },
  ],
};

const stderr = (line) => process.stderr.write(line);

/**
 * The excludes that only narrow the linted set. A negated (`!`) pattern would re-include what
 * another ignore leaves out (node_modules among them), so it is dropped, with a note on stderr.
 */
export function usableExcludes(excludes, warn = stderr) {
  return excludes.filter((glob) => {
    if (!glob.trimStart().startsWith('!')) return true;
    warn(
      `sonarjs: ignoring the negated --exclude ${JSON.stringify(glob)}: an exclude never re-includes files\n`,
    );
    return false;
  });
}

/**
 * Every regular JS/TS file under `root`, found without following links: a symbolic link or a
 * junction (to a file or a directory, inside the checkout or outside it) is neither linted nor
 * entered, and node_modules and .git are never entered.
 */
export function sourceFiles(root) {
  const out = [];
  const visit = (dir) => {
    for (const entry of readdirSync(dir, { withFileTypes: true })) {
      if (entry.isSymbolicLink()) continue;
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (!NEVER_DIRS.has(entry.name)) visit(full);
      } else if (entry.isFile() && SOURCE.test(entry.name)) out.push(full);
    }
  };
  visit(root);
  return out.sort();
}

/**
 * The entries of a --files list that may be linted: absolute paths (a relative entry is taken
 * relative to `root`) of regular JS/TS files inside `root`, reached without a symbolic link or
 * junction in any component, and never under node_modules or .git. The list comes from the CLI,
 * but each entry is checked against the disk again here, as `sourceFiles` would find it.
 */
export function listedFiles(root, entries, warn = stderr) {
  const realRoot = realpathSync(root);
  const out = new Set();
  let dropped = 0;
  for (const entry of entries) {
    const full = typeof entry === 'string' ? path.resolve(root, entry) : undefined;
    const rel = full === undefined ? '' : path.relative(root, full);
    const ok =
      rel !== '' &&
      rel !== '..' &&
      !rel.startsWith(`..${path.sep}`) &&
      !path.isAbsolute(rel) &&
      SOURCE.test(full) &&
      !rel.split(path.sep).some((part) => NEVER_DIRS.has(part)) &&
      (() => {
        try {
          // lstat: the file itself is no link; realpath: no directory on the way is one either.
          return lstatSync(full).isFile() && realpathSync(full) === path.join(realRoot, rel);
        } catch {
          return false;
        }
      })();
    if (ok) out.add(full);
    else dropped += 1;
  }
  if (dropped > 0)
    warn(`sonarjs: ${dropped} listed file(s) not linted (not a regular source file inside the root)
`);
  return [...out].sort();
}

/**
 * `lint()`, again with each rule that crashes turned off (`disabled` collects the rule ids, which
 * `lint` must honour), so one rule failing on one file never loses the whole pass.
 */
export async function lintGuarded(lint, disabled, warn = stderr) {
  for (;;) {
    try {
      return await lint();
    } catch (err) {
      const match = CRASHED_RULE.exec(String(err?.message));
      const id = match?.[1] ?? match?.[2];
      if (!id || disabled.has(id)) throw err;
      disabled.add(id);
      warn(
        `sonarjs: ${id} crashed and is off for this run: ${String(err.message).split('\n')[0]}\n`,
      );
    }
  }
}

/**
 * The stdout line: besides the mode and the number of linted files, what a caller can act on
 * without reading stderr: the files that did not parse (a fatal message, never a finding) and the
 * RSPEC keys of the rules the crash guard turned off.
 */
export function summary(mode, results, disabled, keyOf) {
  return {
    typeChecking: mode,
    files: results.length,
    parseErrors: results.filter((r) => r.messages.some((m) => m.fatal)).length,
    disabledRules: [...disabled].map((id) => keyOf.get(id.replace(/^sonarjs\//, '')) ?? id).sort(),
  };
}

/** Plugin rule name → RSPEC key, from each rule's docs URL (…/rspec/#/rspec/S1192/javascript). */
export function rspecKeys() {
  const keyOf = new Map();
  for (const [name, rule] of Object.entries(sonarjs.rules)) {
    const key = rule.meta?.docs?.url?.match(/rspec\/(S\d+)\//)?.[1];
    if (key) keyOf.set(name, key);
  }
  return keyOf;
}

async function main(args) {
  const opt = (name) => {
    const i = args.indexOf(name);
    return i < 0 ? undefined : args[i + 1];
  };
  const all = (name) =>
    args.flatMap((a, i) => (a === name && args[i + 1] !== undefined ? [args[i + 1]] : []));
  if (!opt('--root') || !opt('--out'))
    throw new Error(
      'usage: run.mjs --root <dir> --out <file> [--files <list.json>] [--type-checking on|off] [--exclude <glob>]...',
    );
  const root = path.resolve(opt('--root'));
  const out = path.resolve(opt('--out'));
  const tsconfig = path.join(root, 'tsconfig.json');
  const wantTypes = opt('--type-checking') !== 'off' && existsSync(tsconfig);

  const categories = JSON.parse(readFileSync(path.join(here, 'categories.json'), 'utf8')); // { S1192: "Critical Code Smell", ... }
  const keyOf = rspecKeys();
  const typeAware = new Set(
    Object.entries(sonarjs.rules)
      .filter(([, r]) => r.meta?.docs?.requiresTypeChecking)
      .map(([name]) => `sonarjs/${name}`),
  );
  // The plugin's flat `recommended` config: { name, plugins: { sonarjs }, rules: { 'sonarjs/<name>': 'error' | 'off' }, settings }.
  const recommended = sonarjs.configs.recommended;
  const plugin = safePlugin();
  const disabled = new Set(); // rules that crashed, turned off for the rest of the run
  const excludes = usableExcludes(all('--exclude'));

  function config(types) {
    const rules = Object.fromEntries(
      Object.entries(recommended.rules).map(([id, level]) => [
        id,
        disabled.has(id) || (!types && typeAware.has(id))
          ? 'off'
          : level !== 'off' && OPTIONS[id]
            ? [level, ...OPTIONS[id]]
            : level,
      ]),
    );
    return [
      ...(excludes.length > 0 ? [{ ignores: excludes }] : []),
      // The fixed ignores come last, so that nothing before them can re-include their paths.
      { ignores: NEVER },
      {
        files: ['**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts}'],
        plugins: { sonarjs: plugin },
        // The plugin's own settings, written out rather than inherited: an explicit React version,
        // so eslint-plugin-react never detects it by loading `react` from the checkout, and no
        // `import/*` settings (S7060 above never reads them). The regression test in run.test.ts
        // plants every package or config a parser or rule could load from the checkout and checks
        // that none runs.
        settings: { react: { version: '999.999.999' } },
        languageOptions: {
          parser: tsParser,
          parserOptions: {
            ecmaVersion: 'latest',
            sourceType: 'module',
            ecmaFeatures: { jsx: true },
            ...(types && { project: tsconfig, tsconfigRootDir: root }),
          },
        },
        linterOptions: { reportUnusedDisableDirectives: 'off' },
        rules,
      },
    ];
  }

  async function lint(types, files) {
    if (files.length === 0) return [];
    return lintGuarded(
      () =>
        new ESLint({
          cwd: root,
          overrideConfigFile: true,
          overrideConfig: config(types),
          errorOnUnmatchedPattern: false,
          warnIgnored: false,
        }).lintFiles(files),
      disabled,
    );
  }

  // Explicit paths, never a glob ESLint expands itself (that would follow symbolic links); ESLint
  // still applies the ignores above to each of them.
  const list = opt('--files');
  const listed = list ? JSON.parse(readFileSync(path.resolve(list), 'utf8')) : undefined;
  if (list && !Array.isArray(listed)) throw new Error('--files must name a JSON array of paths');
  const files = listed ? listedFiles(root, listed) : sourceFiles(root);
  let mode = wantTypes ? 'on' : 'off';
  let results;
  if (wantTypes) {
    try {
      results = await lint(true, files);
      // Every file with a fatal message in the type-aware parse is linted again without type
      // information: a tsconfig that does not parse, or a file outside the project it describes,
      // fails the type-aware parse with a message that differs by platform and TypeScript version
      // ("Expression expected." for a truncated tsconfig on Linux), so it is not matched by text.
      // A file that parses without types was a type-aware failure (mode `fallback`); one that
      // still does not parse keeps its parse error.
      const failed = results.filter((r) => r.messages.some((m) => m.fatal));
      if (failed.length > 0) {
        const again = new Map(
          (
            await lint(
              false,
              failed.map((r) => r.filePath),
            )
          ).map((r) => [r.filePath, r]),
        );
        if ([...again.values()].some((r) => !r.messages.some((m) => m.fatal))) mode = 'fallback';
        results = results.map((r) => again.get(r.filePath) ?? r);
      }
    } catch (err) {
      stderr(
        `sonarjs: the type-aware pass failed, linting without type information: ${String(err?.message).split('\n')[0]}\n`,
      );
      mode = 'fallback';
      results = undefined;
    }
  }
  results ??= await lint(false, files);

  const used = new Set();
  const sarifResults = [];
  for (const file of results) {
    const uri = path.relative(root, file.filePath).split(path.sep).join('/');
    for (const m of file.messages) {
      const name = m.ruleId?.replace(/^sonarjs\//, '');
      const key = name && keyOf.get(name);
      if (!key) continue;
      used.add(name);
      const region = {
        startLine: m.line ?? 1,
        ...(m.column && { startColumn: m.column }),
        ...(m.endLine && { endLine: m.endLine }),
        ...(m.endColumn && { endColumn: m.endColumn }),
      };
      sarifResults.push({
        ruleId: key,
        level: 'warning',
        message: { text: m.message },
        locations: [{ physicalLocation: { artifactLocation: { uri }, region } }],
      });
    }
  }
  const rules = [...used].sort().map((name) => {
    const key = keyOf.get(name);
    return {
      id: key,
      name,
      shortDescription: { text: sonarjs.rules[name].meta?.docs?.description ?? name },
      helpUri: `https://rules.sonarsource.com/javascript/RSPEC-${key.slice(1)}`,
      ...(categories[key] && { properties: { category: categories[key] } }),
    };
  });
  const log = {
    version: '2.1.0',
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json',
    runs: [
      {
        tool: {
          driver: {
            name: 'eslint-plugin-sonarjs',
            version: '2.0.4',
            informationUri: 'https://github.com/SonarSource/SonarJS',
            rules,
          },
        },
        results: sarifResults,
      },
    ],
  };
  writeFileSync(out, JSON.stringify(log));
  process.stdout.write(`${JSON.stringify(summary(mode, results, disabled, keyOf))}\n`);
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    await main(process.argv.slice(2));
  } catch (err) {
    stderr(`sonarjs: ${err?.stack ?? err}\n`);
    process.exit(2);
  }
}
