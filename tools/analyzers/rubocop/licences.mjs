// The gems of Qualor's RuboCop pass (plan 9B): RuboCop and what it runs on (gems/, installed from
// tools/analyzers/rubocop/gems.lock) and racc, the one of Ruby's bundled gems install-rubocop.sh
// keeps (ruby/lib/ruby/gems/<abi>/), each with the licence files it ships, and Ruby's default gems:
// those under Ruby's licence by name, the others (MIT) with the licence files install-rubocop.sh
// put in licenses/gems/<name>-<version>/ (rubocop/licence-gems.lock). Fails on a licence outside
// ALLOWED, and on a default gem outside Ruby's licence without its licence files. Writes
// deploy/scanner/licenses/RUBOCOP-DEPENDENCIES.txt. Run where the pass is installed (the analyzers
// toolbox):
//   node tools/analyzers/rubocop/licences.mjs [/opt/qualor/rubocop] [output file]
import { existsSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const ALLOWED = new Set(['MIT', 'Ruby', 'BSD-2-Clause']);
const LICENCE_FILE = /^(licen[cs]e|copying|bsdl|legal|mit-licen[cs]e)/i;

/** The licence ids of an installed gemspec (`s.licenses = ["Ruby".freeze, "BSD-2-Clause".freeze]`). */
export function gemspecLicences(text) {
  const list = /^\s*s\.licenses = \[(.*)\]\s*$/m.exec(text);
  if (list !== null) return [...list[1].matchAll(/"([^"]+)"/g)].map((m) => m[1]);
  const one = /^\s*s\.license = "([^"]+)"/m.exec(text);
  return one === null ? [] : [one[1]];
}

/** Installed gems of one gem directory: name, version, licences and directory. */
function gemsIn(gemDir, only, specs = path.join(gemDir, 'specifications')) {
  return readdirSync(specs)
    .filter((f) => f.endsWith('.gemspec'))
    .map((f) => {
      const full = f.slice(0, -'.gemspec'.length);
      const dash = full.lastIndexOf('-');
      return {
        name: full.slice(0, dash),
        version: full.slice(dash + 1),
        licences: gemspecLicences(readFileSync(path.join(specs, f), 'utf8')),
        dir: path.join(gemDir, 'gems', full),
      };
    })
    .filter((g) => only === undefined || only.includes(g.name));
}

/** Orders gems by name, by UTF-16 code units (not by locale). */
function byName(a, b) {
  if (a.name === b.name) return 0;
  return a.name < b.name ? -1 : 1;
}

/** The licence files in `dir` (none if it does not exist), sorted. */
export function licenceFiles(dir) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir)
    .filter((f) => LICENCE_FILE.test(f) && statSync(path.join(dir, f)).isFile())
    .sort();
}

/** One section: the gem's name, version and licences, then each licence file in `dir`. */
function section(g, dir) {
  const files = licenceFiles(dir);
  const lines = ['='.repeat(78), `${g.name} ${g.version} (${g.licences.join(' OR ')})`];
  if (files.length === 0)
    lines.push('', '(the gem ships no licence file; its licence is the one named above)');
  for (const f of files)
    lines.push('', `--- ${f}`, readFileSync(path.join(dir, f), 'utf8').trimEnd());
  return lines.join('\n');
}

/** `items` joined by ', ' in lines of at most 98 characters. */
function wrap(items) {
  const lines = [];
  let line = '';
  for (const [i, item] of items.entries()) {
    const word = i < items.length - 1 ? `${item},` : item;
    if (line === '') line = word;
    else if (line.length + 1 + word.length > 98) {
      lines.push(line);
      line = word;
    } else line = `${line} ${word}`;
  }
  if (line !== '') lines.push(line);
  return lines;
}

/**
 * Ruby's default gems in the pass at `rubocopDir`: `ruby`, under Ruby's licence (RUBY-COPYING.txt
 * and RUBY-BSDL.txt cover them), and `own`, under another, each with its licence directory
 * (licenses/gems/<name>-<version>, which install-rubocop.sh fills).
 */
export function defaultGems(rubocopDir) {
  const abi = readdirSync(path.join(rubocopDir, 'ruby/lib/ruby/gems'))[0];
  const gemDir = path.join(rubocopDir, 'ruby/lib/ruby/gems', abi);
  const all = gemsIn(gemDir, undefined, path.join(gemDir, 'specifications', 'default'))
    .map((g) => ({
      ...g,
      dir: path.join(rubocopDir, 'licenses', 'gems', `${g.name}-${g.version}`),
    }))
    .sort(byName);
  return {
    ruby: all.filter((g) => g.licences.includes('Ruby')),
    own: all.filter((g) => !g.licences.includes('Ruby')),
  };
}

/** The text of RUBOCOP-DEPENDENCIES.txt for the pass installed at `rubocopDir`. */
export function dependenciesText(rubocopDir) {
  const abi = readdirSync(path.join(rubocopDir, 'ruby/lib/ruby/gems'))[0];
  const gems = [
    ...gemsIn(path.join(rubocopDir, 'gems')),
    ...gemsIn(path.join(rubocopDir, 'ruby/lib/ruby/gems', abi), ['racc']),
  ].sort(byName);
  const defaults = defaultGems(rubocopDir);
  const problems = [...gems, ...defaults.ruby, ...defaults.own]
    .filter((g) => g.licences.length === 0 || !g.licences.some((l) => ALLOWED.has(l)))
    .map((g) => `${g.name} ${g.version}: ${g.licences.join(', ') || 'no licence declared'}`);
  if (problems.length > 0) throw new Error(`disallowed licences:\n${problems.join('\n')}`);
  const bare = defaults.own.filter((g) => licenceFiles(g.dir).length === 0);
  if (bare.length > 0) {
    const names = bare.map((g) => `${g.name} ${g.version}`).join(', ');
    throw new Error(
      `default gems without their licence files (rubocop/licence-gems.lock): ${names}`,
    );
  }
  const sections = [...gems, ...defaults.own].map((g) => section(g, g.dir));
  return [
    'The gems of Qualor’s RuboCop pass in /opt/qualor/rubocop (RuboCop and what it runs on, installed',
    'from tools/analyzers/rubocop/gems.lock, and racc, the one of Ruby’s bundled gems it keeps), each',
    'with the licence files it ships, then the default gems of its Ruby under a licence of their own,',
    'with theirs. Generated by tools/analyzers/rubocop/licences.mjs; do not edit.',
    '',
    ...sections,
    '='.repeat(78),
    'The other default gems of Ruby are under Ruby’s licence (RUBY-COPYING.txt, RUBY-BSDL.txt):',
    ...wrap(defaults.ruby.map((g) => `${g.name} ${g.version}`)),
    '',
  ].join('\n');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const dir = process.argv[2] ?? '/opt/qualor/rubocop';
  const out =
    process.argv[3] ?? path.join(here, '../../../deploy/scanner/licenses/RUBOCOP-DEPENDENCIES.txt');
  writeFileSync(out, dependenciesText(dir));
  console.log(`wrote ${out}`);
}
