#!/usr/bin/env node
// Derives the equivalence pairs (data-model.md §5.3) between a project's own eslint-plugin-sonarjs
// and Qualor's sonarjs pass: a project whose ESLint config already runs the plugin reports a
// problem as `eslint:sonarjs/<rule name>`, and the pass reports the same one as `sonarjs:<RSPEC
// key>`. One pair per rule of the installed eslint-plugin-sonarjs 2.0.4, from run.mjs's own
// rspecKeys() (rule name -> key, read from each rule's meta.docs.url); the ESLint rule comes first,
// as it stays primary (ENGINE_PRIORITY). Rule names and keys are facts; no SonarSource text.
//   node tools/analyzers/sonarjs/own-pairs.mjs            prints the pairs as JSON
//   node tools/analyzers/sonarjs/own-pairs.mjs --write    replaces every `eslint:sonarjs/` pair of
//                                                         packages/shared/rules/equivalences.json
//                                                         (then `prettier --write` that file)
// Needs tools/analyzers/sonarjs/node_modules (npm ci --omit=dev --ignore-scripts).
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const OWN = 'eslint:sonarjs/';

/**
 * `{ rules: ['eslint:sonarjs/<name>', 'sonarjs:<key>'], reason }` for every rule of `keyOf`
 * (run.mjs's rspecKeys(): rule name -> RSPEC key), by key number.
 */
export function ownPairs(keyOf) {
  return [...keyOf]
    .sort(([, a], [, b]) => Number(a.slice(1)) - Number(b.slice(1)))
    .map(([name, key]) => ({
      rules: [`${OWN}${name}`, `sonarjs:${key}`],
      reason: `The project's own eslint-plugin-sonarjs reports ${key} as sonarjs/${name}`,
    }));
}

/** `data` (equivalences.json) with its `eslint:sonarjs/` pairs replaced by `pairs`, appended last. */
export function withOwnPairs(data, pairs) {
  return {
    ...data,
    pairs: [...data.pairs.filter((p) => !p.rules.some((r) => r.startsWith(OWN))), ...pairs],
  };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  // Imported here, not at the top: ownPairs() itself needs no installed plugin (run.test.ts).
  const { rspecKeys } = await import('./run.mjs');
  const pairs = ownPairs(rspecKeys());
  if (pairs.length === 0) {
    process.stderr.write('own-pairs.mjs: no rule had an RSPEC key (is the plugin installed?)\n');
    process.exit(1);
  }
  if (process.argv.includes('--write')) {
    const here = path.dirname(fileURLToPath(import.meta.url));
    const file = path.join(here, '../../../packages/shared/rules/equivalences.json');
    const data = JSON.parse(readFileSync(file, 'utf8'));
    writeFileSync(file, `${JSON.stringify(withOwnPairs(data, pairs), null, 2)}\n`);
    process.stdout.write(`own-pairs.mjs: ${pairs.length} pairs written to ${file}\n`);
  } else {
    process.stdout.write(`${JSON.stringify(pairs, null, 2)}\n`);
  }
}
