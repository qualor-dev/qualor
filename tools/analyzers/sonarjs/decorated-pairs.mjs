#!/usr/bin/env node
/**
 * Derives cross-engine rule-equivalence pairs (data-model.md §5.3) from the
 * installed eslint-plugin-sonarjs 2.0.4 package: for every sonarjs rule that
 * decorates (wraps) an ESLint core, typescript-eslint, eslint-plugin-react,
 * eslint-plugin-jsx-a11y, eslint-plugin-react-hooks or eslint-plugin-import
 * rule, print a `{ rules: [...], reason: ... }` pair suitable for
 * `packages/shared/rules/equivalences.json`'s `pairs` array. Phase 8A/8B
 * Task 8 (see task-8-brief.md and task-8-report.md).
 *
 * Run from the repo root (or anywhere):
 *   node tools/analyzers/sonarjs/decorated-pairs.mjs
 *
 * Requires `tools/analyzers/sonarjs/node_modules` to be installed
 * (`npm ci --omit=dev --ignore-scripts` in this directory if missing).
 *
 * Output is a JSON array on stdout, printed for a human to review and paste
 * into equivalences.json by hand (the file's own `$comment` asks for
 * reviewed, reasoned entries) -- this script does not write the JSON file
 * itself. Per-rule notes (which files were read, any rule the script could
 * not resolve) go to stderr so stdout stays clean JSON.
 *
 * --- Mechanism -------------------------------------------------------------
 *
 * 1. `cjs/decorated.js` lists every decorated rule as a line of the form
 *
 *        var index_js_N = require("./S####/index.js"); // <friendly-name>
 *
 *    The trailing comment is the base rule's own name (as eslint-plugin-sonarjs's
 *    authors wrote it), not something we rely on for correctness -- it is only
 *    used as a hint in stderr notes.
 *
 * 2. Each `S####/index.js` either *is* the rule's logic, or just re-exports it
 *    from `./rule.js` (either `var rule_js_1 = require("./rule.js"); ...` or
 *    `__exportStar(require("./rule.js"), exports);`). We read whichever file
 *    holds the actual logic.
 *
 * 3. In that logic file we look for lookups of a base rule out of one of the
 *    plugin's own re-export tables (`cjs/core/index.js`,
 *    `cjs/typescript-eslint/index.js`) or a peer ESLint plugin required
 *    directly:
 *
 *      require("../core/index.js")              -> eslintRules['<name>']        eslint:<name>
 *      require("../typescript-eslint/index.js")  -> tsEslintRules['<name>']      eslint:@typescript-eslint/<name>
 *      require("eslint-plugin-react")            -> rules['<name>']              eslint:react/<name>
 *      require("eslint-plugin-jsx-a11y")         -> rules['<name>']              eslint:jsx-a11y/<name>
 *      require("eslint-plugin-react-hooks")      -> rules['<name>']              eslint:react-hooks/<name>
 *      require("eslint-plugin-import")           -> rules['<name>']              eslint:import/<name>
 *
 *    A single decorated rule can reference more than one base rule (e.g. S1534
 *    merges a core rule, a typescript-eslint rule and a react rule into one
 *    "sonar-no-dupe-keys" check; S5254 merges two separate jsx-a11y rules;
 *    S6544 merges a typescript-eslint rule with a core rule; S6747 merges a
 *    react rule with a jsx-a11y rule; S6535 merges two core rules). Every
 *    distinct base rule found becomes its own candidate pair -- the ESLint
 *    engine could report any one of them at the same path/line as the sonarjs
 *    finding, so each is a legitimate, independently reviewable equivalence.
 *
 * 4. For a typescript-eslint base, we additionally ask the *installed*
 *    @typescript-eslint/eslint-plugin itself whether it extends an ESLint core
 *    rule of the same (or a different) name, via the rule's own
 *    `meta.docs.extendsBaseRule` (`true` = same name, a string = a different
 *    core rule name, `undefined` = no core equivalent -- this is
 *    typescript-eslint's own documented convention, not a guess). When it
 *    does extend a core rule, we also emit that core pair alongside the
 *    @typescript-eslint one -- this is the S1186 (no-empty-function) case the
 *    task brief calls out by name.
 */

import { existsSync, readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const require = createRequire(import.meta.url);

const pluginRoot = path.join(here, 'node_modules', 'eslint-plugin-sonarjs');
const cjsRoot = path.join(pluginRoot, 'cjs');

if (!existsSync(cjsRoot)) {
  console.error(
    `eslint-plugin-sonarjs is not installed at ${pluginRoot}. Run ` +
      `"npm ci --omit=dev --ignore-scripts" in tools/analyzers/sonarjs first.`,
  );
  process.exit(1);
}

/** Maps our internal "origin" tag to the ESLint rule-id prefix used in the project's own report. */
const ORIGIN_PREFIX = {
  core: '',
  ts: '@typescript-eslint/',
  react: 'react/',
  'jsx-a11y': 'jsx-a11y/',
  'react-hooks': 'react-hooks/',
  import: 'import/',
};

function escapeRe(literal) {
  return literal.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/** `require("<pathFragment>")` assigned to an ident, then `<ident>.<prop>['<name>']` reads. */
function extractNamespaceRefs(text, pathFragment, prop) {
  const names = new Set();
  const reqRe = new RegExp(`const (\\w+) = require\\("${escapeRe(pathFragment)}"\\);`, 'g');
  let rm;
  while ((rm = reqRe.exec(text))) {
    const ident = rm[1];
    const accessRe = new RegExp(`\\b${ident}\\.${prop}\\[(['"])([\\w-]+)\\1\\]`, 'g');
    let am;
    while ((am = accessRe.exec(text))) names.add(am[2]);
  }
  return names;
}

/** `const X = __importDefault(require("<pkg>")); const { rules[: alias] } = X.default;` then `<alias>['<name>']`. */
function extractDefaultPluginRefs(text, pkg) {
  const names = new Set();
  const reqRe = new RegExp(`const (\\w+) = __importDefault\\(require\\("${escapeRe(pkg)}"\\)\\);`, 'g');
  let rm;
  while ((rm = reqRe.exec(text))) {
    const ident = rm[1];
    const destructRe = new RegExp(`const \\{\\s*rules(?::\\s*(\\w+))?\\s*\\} = ${ident}\\.default;`);
    const dm = text.match(destructRe);
    if (!dm) continue;
    const localVar = dm[1] || 'rules';
    const accessRe = new RegExp(`\\b${localVar}\\[(['"])([\\w-]+)\\1\\]`, 'g');
    let am;
    while ((am = accessRe.exec(text))) names.add(am[2]);
  }
  return names;
}

/** `const X = require("<pkg>");` (no __importDefault) then `X.rules['<name>']`. */
function extractDirectPluginRefs(text, pkg) {
  const names = new Set();
  const reqRe = new RegExp(`const (\\w+) = require\\("${escapeRe(pkg)}"\\);`, 'g');
  let rm;
  while ((rm = reqRe.exec(text))) {
    const ident = rm[1];
    const accessRe = new RegExp(`\\b${ident}\\.rules\\[(['"])([\\w-]+)\\1\\]`, 'g');
    let am;
    while ((am = accessRe.exec(text))) names.add(am[2]);
  }
  return names;
}

let tsPlugin = null;
try {
  tsPlugin = require('@typescript-eslint/eslint-plugin');
} catch (err) {
  console.error(`Warning: could not load @typescript-eslint/eslint-plugin (${err.message}); ` +
    `typescript-eslint bases will not be checked for a core-rule extension.`);
}

/** typescript-eslint's own documented convention for "this rule extends an ESLint core rule". */
function coreNameExtendedBy(tsRuleName) {
  const ext = tsPlugin?.rules?.[tsRuleName]?.meta?.docs?.extendsBaseRule;
  if (ext === true) return tsRuleName;
  if (typeof ext === 'string') return ext;
  return null;
}

// Step 1: parse decorated.js for every `require("./S####/index.js"); // <name>` line.
const decoratedSrc = readFileSync(path.join(cjsRoot, 'decorated.js'), 'utf8');
const entryRe = /require\("\.\/(S\d+)\/index\.js"\);\s*\/\/\s*(.+)$/gm;
const entries = [];
let em;
while ((em = entryRe.exec(decoratedSrc))) {
  entries.push({ sonarKey: em[1], hint: em[2].trim() });
}
console.error(`decorated.js lists ${entries.length} decorated rules.`);

const pairs = [];
let unresolved = 0;

for (const { sonarKey, hint } of entries) {
  const dir = path.join(cjsRoot, sonarKey);
  const indexSrc = readFileSync(path.join(dir, 'index.js'), 'utf8');

  // Step 2: index.js is the logic, unless it just re-exports rule.js.
  let logicFile = 'index.js';
  let logicSrc = indexSrc;
  if (/require\("\.\/rule\.js"\)/.test(indexSrc)) {
    logicFile = 'rule.js';
    logicSrc = readFileSync(path.join(dir, 'rule.js'), 'utf8');
  }

  // Step 3: collect every distinct base-rule reference in the logic file.
  const candidates = []; // { origin, name }

  for (const name of extractNamespaceRefs(logicSrc, '../core/index.js', 'eslintRules')) {
    candidates.push({ origin: 'core', name });
  }
  for (const name of extractNamespaceRefs(logicSrc, '../typescript-eslint/index.js', 'tsEslintRules')) {
    candidates.push({ origin: 'ts', name });
    // Step 4: does typescript-eslint itself say this extends an ESLint core rule?
    const coreName = coreNameExtendedBy(name);
    if (coreName) candidates.push({ origin: 'core', name: coreName });
  }
  for (const name of extractDefaultPluginRefs(logicSrc, 'eslint-plugin-react')) {
    candidates.push({ origin: 'react', name });
  }
  for (const name of extractDefaultPluginRefs(logicSrc, 'eslint-plugin-jsx-a11y')) {
    candidates.push({ origin: 'jsx-a11y', name });
  }
  for (const name of extractDirectPluginRefs(logicSrc, 'eslint-plugin-react-hooks')) {
    candidates.push({ origin: 'react-hooks', name });
  }
  for (const name of extractDirectPluginRefs(logicSrc, 'eslint-plugin-import')) {
    candidates.push({ origin: 'import', name });
  }

  if (candidates.length === 0) {
    unresolved += 1;
    console.error(`WARNING: no base rule found for ${sonarKey} (hint: "${hint}", read ${logicFile}).`);
    continue;
  }

  const seen = new Set();
  for (const { origin, name } of candidates) {
    const eslintName = `${ORIGIN_PREFIX[origin]}${name}`;
    const ruleId = `eslint:${eslintName}`;
    if (seen.has(ruleId)) continue;
    seen.add(ruleId);
    pairs.push({
      rules: [ruleId, `sonarjs:${sonarKey}`],
      reason: `eslint-plugin-sonarjs decorates the ESLint rule ${eslintName} as ${sonarKey}`,
    });
  }
  console.error(`${sonarKey} (${hint}, ${logicFile}): ${[...seen].join(', ')}`);
}

console.error(`\n${pairs.length} pairs from ${entries.length} decorated rules (${unresolved} unresolved).`);
console.log(JSON.stringify(pairs, null, 2));
