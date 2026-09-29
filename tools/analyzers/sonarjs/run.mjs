// Qualor's sonarjs pass (config.md §6): eslint-plugin-sonarjs 2.0.4 (LGPL-3.0, frozen: later
// versions are under the SONAR Source-Available License) with its own `recommended` config, run by
// Qualor's own ESLint 9. Never loads the project's config, plugins or node_modules: everything is
// imported from this directory, and ESLint gets the config inline (overrideConfigFile: true).
//   node run.mjs --root <dir> --out <file.sarif> [--type-checking on|off] [--exclude <glob>]...
// Writes a SARIF 2.1.0 log keyed by RSPEC ids (S1192) and prints one JSON line
// {"typeChecking":"on"|"off"|"fallback","files":N}. Exit 0 whenever the log is written, 2 on an
// internal error.
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';
import sonarjs from 'eslint-plugin-sonarjs';
import tsParser from '@typescript-eslint/parser';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = process.argv.slice(2);
const opt = (name) => {
  const i = args.indexOf(name);
  return i < 0 ? undefined : args[i + 1];
};
const all = (name) =>
  args.flatMap((a, i) => (a === name && args[i + 1] !== undefined ? [args[i + 1]] : []));

// A fatal parse message of the type-aware parse: the tsconfig does not parse, or a file is not
// in the project it describes. Such files are linted again without type information.
const TYPE_FAILURE = /tsconfig|parserOptions\.project|\bproject\b/i;
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

/** Plugin rule name → RSPEC key, from each rule's docs URL (…/rspec/#/rspec/S1192/javascript). */
function rspecKeys() {
  const keyOf = new Map();
  for (const [name, rule] of Object.entries(sonarjs.rules)) {
    const key = rule.meta?.docs?.url?.match(/rspec\/(S\d+)\//)?.[1];
    if (key) keyOf.set(name, key);
  }
  return keyOf;
}

async function main() {
  if (!opt('--root') || !opt('--out'))
    throw new Error(
      'usage: run.mjs --root <dir> --out <file> [--type-checking on|off] [--exclude <glob>]...',
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
  const disabled = new Set(); // rules that crashed, turned off for the rest of the run

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
      { ignores: ['**/node_modules/**', '**/.git/**', ...all('--exclude')] },
      {
        files: ['**/*.{js,jsx,mjs,cjs,ts,tsx,mts,cts}'],
        plugins: recommended.plugins,
        settings: recommended.settings,
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

  async function lint(types, patterns) {
    for (;;) {
      const eslint = new ESLint({
        cwd: root,
        overrideConfigFile: true,
        overrideConfig: config(types),
        errorOnUnmatchedPattern: false,
        warnIgnored: false,
      });
      try {
        return await eslint.lintFiles(patterns);
      } catch (err) {
        // One rule crashing on one file must not lose the whole pass: drop it and lint again.
        const match = CRASHED_RULE.exec(String(err?.message));
        const id = match?.[1] ?? match?.[2];
        if (!id || disabled.has(id)) throw err;
        disabled.add(id);
        process.stderr.write(
          `sonarjs: ${id} crashed and is off for this run: ${String(err.message).split('\n')[0]}\n`,
        );
      }
    }
  }

  let mode = wantTypes ? 'on' : 'off';
  let results;
  if (wantTypes) {
    try {
      results = await lint(true, ['.']);
      const failed = results.filter((r) =>
        r.messages.some((m) => m.fatal && TYPE_FAILURE.test(m.message)),
      );
      if (failed.length > 0) {
        mode = 'fallback';
        const again = new Map(
          (
            await lint(
              false,
              failed.map((r) => r.filePath),
            )
          ).map((r) => [r.filePath, r]),
        );
        results = results.map((r) => again.get(r.filePath) ?? r);
      }
    } catch (err) {
      process.stderr.write(
        `sonarjs: the type-aware pass failed, linting without type information: ${String(err?.message).split('\n')[0]}\n`,
      );
      mode = 'fallback';
      results = undefined;
    }
  }
  results ??= await lint(false, ['.']);

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
  process.stdout.write(`${JSON.stringify({ typeChecking: mode, files: results.length })}\n`);
}

try {
  await main();
} catch (err) {
  process.stderr.write(`sonarjs: ${err?.stack ?? err}\n`);
  process.exit(2);
}
