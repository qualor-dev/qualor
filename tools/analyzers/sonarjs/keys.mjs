// Writes packages/shared/rules/sonarjs-keys.json: the RSPEC rule ids (`S####`) of every rule the
// installed eslint-plugin-sonarjs 2.0.4 package has, derived the same way run.mjs's own
// rspecKeys() does (each rule's meta.docs.url, …/rspec/S####/…) — reused from run.mjs rather than
// duplicated. Never reads SonarSource's rule metadata or documentation; the file holds bare rule
// ids only (spec §6.4).
//   node tools/analyzers/sonarjs/keys.mjs [out file]
import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { rspecKeys } from './run.mjs';

/** The unique RSPEC keys (`S####`) of the installed eslint-plugin-sonarjs package, sorted by number. */
export function sonarjsKeys() {
  return [...new Set(rspecKeys().values())].sort((a, b) => Number(a.slice(1)) - Number(b.slice(1)));
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const out =
    process.argv[2] ?? path.join(here, '../../../packages/shared/rules/sonarjs-keys.json');
  const keys = sonarjsKeys();
  if (keys.length === 0) {
    process.stderr.write(
      'keys.mjs: no rule had an RSPEC key (is eslint-plugin-sonarjs installed under node_modules?)\n',
    );
    process.exit(1);
  }
  writeFileSync(out, `${JSON.stringify(keys, null, 2)}\n`);
  process.stdout.write(`keys.mjs: ${keys.length} rule ids written to ${out}\n`);
}
