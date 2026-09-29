// Writes packages/shared/rules/sonarjs-keys.json: the RSPEC rule ids (`S####`) of every rule the
// installed eslint-plugin-sonarjs 2.0.4 package has, derived the same way run.mjs's own
// rspecKeys() does (each rule's meta.docs.url, …/rspec/S####/…) — reused from run.mjs rather than
// duplicated. Also writes packages/shared/rules/sonarjs-default-keys.json: the subset the pass
// actually runs, the rules its bundled `recommended` configuration turns on (the import plan
// reports a profile rule mapped to any other key as "mapped, not run by the bundled
// configuration"). Never reads SonarSource's rule metadata or documentation; the files hold bare
// rule ids only (spec §6.4).
//   node tools/analyzers/sonarjs/keys.mjs [out file] [default-keys out file]
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const byNumber = (keys) =>
  [...new Set(keys)].sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));

/** The unique RSPEC keys (`S####`) of `keyOf` (run.mjs's rspecKeys()), sorted by number. */
export function sonarjsKeys(keyOf) {
  return byNumber(keyOf.values());
}

/** The RSPEC keys of the rules the plugin's `recommended` configuration turns on, sorted by number. */
export function sonarjsDefaultKeys(keyOf, rules) {
  return byNumber(
    Object.entries(rules)
      .filter(([, level]) => level !== 'off' && level !== 0)
      .map(([id]) => keyOf.get(id.replace(/^sonarjs\//, '')))
      .filter((key) => key !== undefined),
  );
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const out =
    process.argv[2] ?? path.join(here, '../../../packages/shared/rules/sonarjs-keys.json');
  const defaultOut =
    process.argv[3] ?? path.join(here, '../../../packages/shared/rules/sonarjs-default-keys.json');
  // Imported here, not at the top: the functions above need no installed plugin (run.test.ts).
  const { rspecKeys } = await import('./run.mjs');
  const { default: sonarjs } = await import('eslint-plugin-sonarjs');
  const keyOf = rspecKeys();
  const keys = sonarjsKeys(keyOf);
  if (keys.length === 0) {
    process.stderr.write(
      'keys.mjs: no rule had an RSPEC key (is eslint-plugin-sonarjs installed under node_modules?)\n',
    );
    process.exit(1);
  }
  const defaults = sonarjsDefaultKeys(keyOf, sonarjs.configs.recommended.rules);
  writeFileSync(out, `${JSON.stringify(keys, null, 2)}\n`);
  writeFileSync(defaultOut, `${JSON.stringify(defaults, null, 2)}\n`);
  process.stdout.write(
    `keys.mjs: ${keys.length} rule ids written to ${out}, ${defaults.length} run by default to ${defaultOut}\n`,
  );
}
