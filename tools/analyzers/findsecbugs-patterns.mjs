// The bug pattern ids of a FindSecBugs plugin jar (its findbugs.xml), compared with
// packages/shared/rules/findsecbugs.json (plan 6A). On a FINDSECBUGS_VERSION bump, run
//   node tools/analyzers/findsecbugs-patterns.mjs <path of the new jar>
// and classify every id it prints as missing (report-format.md §7.1), and drop the stale ones.
import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** The `type` of every <BugPattern> of a findbugs.xml text, sorted, without duplicates. */
export function patternIds(xml) {
  const ids = [...xml.matchAll(/<BugPattern\b[^>]*?\btype="([A-Z][A-Z0-9_]*)"/g)].map((m) => m[1]);
  return [...new Set(ids)].sort();
}

/** findbugs.xml of a plugin jar, through `unzip -p` (install.sh needs unzip anyway). */
export function findbugsXml(jar) {
  const r = spawnSync('unzip', ['-p', jar, 'findbugs.xml'], {
    encoding: 'utf8',
    maxBuffer: 16 * 1024 * 1024,
  });
  if (r.status !== 0) throw new Error(`unzip -p ${jar} findbugs.xml failed: ${r.stderr}`);
  return r.stdout;
}

/** Ids in the jar but not in the table (missing), and in the table but not in the jar (stale). */
export function compareWithTable(ids, table) {
  const known = new Set(Object.keys(table.patterns));
  const inJar = new Set(ids);
  return {
    missing: ids.filter((id) => !known.has(id)),
    stale: [...known].filter((id) => !inJar.has(id)).sort(),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const jar = process.argv[2];
  if (!jar) {
    console.error('usage: node tools/analyzers/findsecbugs-patterns.mjs <findsecbugs-plugin jar>');
    process.exit(2);
  }
  const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
  const table = JSON.parse(
    readFileSync(path.join(root, 'packages/shared/rules/findsecbugs.json'), 'utf8'),
  );
  const { missing, stale } = compareWithTable(patternIds(findbugsXml(jar)), table);
  console.log(JSON.stringify({ missing, stale }, null, 2));
  process.exit(missing.length + stale.length === 0 ? 0 : 1);
}
