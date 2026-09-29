// Writes categories.json next to run.mjs: each RSPEC key's SonarQube category, e.g.
// { "S1192": "Critical Code Smell" }, from the rule metadata (S<N>.json: `type`,
// `defaultSeverity`) of the SonarJS source at the commit eslint-plugin-sonarjs 2.0.4 was published
// from. Run at image build only, over the rules directory unpacked from the archive pinned in
// tools/analyzers/install.sh; the metadata itself is never copied, and categories.json is not
// committed (only keys and category words are kept).
//   node categories.mjs <rules dir> [out file]
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const TYPES = {
  CODE_SMELL: 'Code Smell',
  BUG: 'Bug',
  VULNERABILITY: 'Vulnerability',
  SECURITY_HOTSPOT: 'Security Hotspot',
};

/** "<defaultSeverity> <type in SonarQube words>", or null when either is missing or unknown. */
export function categoryOf(meta) {
  const type = TYPES[meta?.type];
  const severity = meta?.defaultSeverity;
  return type && typeof severity === 'string' && severity !== '' ? `${severity} ${type}` : null;
}

/** { S<N>: category } for every S<N>.json of `dir` that has one, sorted by key. */
export function categories(dir) {
  const out = {};
  const files = readdirSync(dir)
    .filter((f) => /^S\d+\.json$/.test(f))
    .sort((a, b) => Number(a.slice(1, -5)) - Number(b.slice(1, -5)));
  for (const file of files) {
    const category = categoryOf(JSON.parse(readFileSync(path.join(dir, file), 'utf8')));
    if (category) out[file.slice(0, -5)] = category;
  }
  return out;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [dir, outFile] = process.argv.slice(2);
  if (!dir) {
    process.stderr.write('usage: node categories.mjs <rules dir> [out file]\n');
    process.exit(2);
  }
  const result = categories(dir);
  const count = Object.keys(result).length;
  if (count === 0) {
    process.stderr.write(`categories.mjs: no rule metadata in ${dir}\n`);
    process.exit(1);
  }
  const target =
    outFile ?? path.join(path.dirname(fileURLToPath(import.meta.url)), 'categories.json');
  writeFileSync(target, `${JSON.stringify(result, null, 2)}\n`);
  process.stdout.write(`categories.mjs: ${count} rule categories written to ${target}\n`);
}
