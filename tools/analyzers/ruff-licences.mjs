// The licences of the Rust crates compiled into the Ruff binary the qualor/scanner image ships
// (plan 8C). The release binaries are built from the release's Cargo.lock (every crate@version
// the x86_64 binary names in its embedded source paths is in it, probe of 2026-09-30). Inputs:
// the `cargo metadata` of that source per Linux target, and its Cargo.lock. Every crate's
// .crate archive is downloaded from static.crates.io, checked against Cargo.lock's checksum,
// and its licence files are copied into deploy/scanner/licenses/RUFF-DEPENDENCIES.txt (for a
// crate that ships none: the standard SPDX texts of licence-texts/ and its Cargo.toml authors).
// It fails on any licence outside the allowlist below, and on a crate without a licence file
// whose licence has no standard text there.
//
//   curl -fsSL --proto '=https' --proto-redir '=https' -o src.tar.gz \
//     https://github.com/astral-sh/ruff/releases/download/$V/source.tar.gz
//   (check RUFF_SOURCE_SHA256 of tools/analyzers/install.sh) && tar -xzf src.tar.gz
//   MSYS_NO_PATHCONV=1 docker run --rm -e RUSTUP_TOOLCHAIN=stable -v "$PWD/ruff-$V:/src:ro" \
//     -v "$PWD/out:/out" rust:1-slim-bookworm@sha256:ff521445a372125ed4f76e1453a1f8098f2d05332d1601d30db1c1f62757e730 \
//     sh -c 'for t in x86_64 aarch64; do cargo metadata --locked --format-version 1 \
//       --filter-platform $t-unknown-linux-gnu --manifest-path /src/Cargo.toml > /out/meta-$t.json; done'
//   node tools/analyzers/ruff-licences.mjs ruff-$V out/meta-x86_64.json out/meta-aarch64.json
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

// Permissive licences (MIT, BSD, Apache-2.0, ISC and the like).
const ALLOWED = new Set([
  'MIT',
  'MIT-0',
  'Apache-2.0',
  'Apache-2.0 WITH LLVM-exception',
  'BSD-2-Clause',
  'BSD-3-Clause',
  'ISC',
  '0BSD',
  'Zlib',
  'Unlicense',
  'CC0-1.0',
  'BSL-1.0',
  'Unicode-3.0',
  'Unicode-DFS-2016',
]);
// Named exceptions: only these crates may carry these licences.
// - colored, option-ext, version-ranges: MPL-2.0, file-level copyleft. Unmodified; their source
//   is in qualor/scanner-sources (deploy/scanner/sources.json).
// - terminfo: WTFPL, a permissive public-licence text.
// - libcst: PSF-2.0 parts inside an AND with MIT, the permissive Python licence.
const EXCEPTIONS = new Map([
  ['colored', 'MPL-2.0'],
  ['option-ext', 'MPL-2.0'],
  ['version-ranges', 'MPL-2.0'],
  ['terminfo', 'WTFPL'],
  ['libcst', 'PSF-2.0'],
]);

/** Why crate `name`'s SPDX `expression` is not acceptable, or null when it is. */
export function licenceProblem(name, expression) {
  if (typeof expression !== 'string' || expression.trim() === '')
    return `${name}: no licence declared`;
  const ok = (id) => ALLOWED.has(id) || EXCEPTIONS.get(name) === id;
  const tokens = expression
    .replace(/\//g, ' OR ')
    .replace(/\(/g, ' ( ')
    .replace(/\)/g, ' ) ')
    .trim()
    .split(/\s+/);
  let i = 0;
  // or := and ('OR' and)*; and := atom ('AND' atom)*; atom := '(' or ')' | ID ['WITH' ID]
  const atom = () => {
    if (tokens[i] === '(') {
      i++;
      const inner = or();
      if (tokens[i++] !== ')') throw new Error('unbalanced');
      return inner;
    }
    const id = tokens[i++];
    if (id === undefined || id === ')' || id === 'AND' || id === 'OR')
      throw new Error('expected a licence');
    if (tokens[i] === 'WITH') {
      const exception = tokens[i + 1];
      i += 2;
      return ok(`${id} WITH ${exception}`);
    }
    return ok(id);
  };
  const and = () => {
    let all = atom();
    while (tokens[i] === 'AND') {
      i++;
      all = atom() && all;
    }
    return all;
  };
  const or = () => {
    let any = and();
    while (tokens[i] === 'OR') {
      i++;
      any = and() || any;
    }
    return any;
  };
  let good;
  try {
    good = or();
    if (i !== tokens.length) throw new Error('trailing tokens');
  } catch {
    return `${name}: cannot read the licence expression ${expression}`;
  }
  return good ? null : `${name}: ${expression} is not an allowed licence`;
}

/** The registry crates the `ruff` package links: its normal-dependency closure, workspace crates left out. */
export function shippedCrates(metadata) {
  const packages = new Map(metadata.packages.map((p) => [p.id, p]));
  const nodes = new Map(metadata.resolve.nodes.map((n) => [n.id, n]));
  const root = metadata.packages.find((p) => p.name === 'ruff' && p.source === null);
  if (!root) throw new Error('no workspace package ruff in the metadata');
  const seen = new Set();
  const queue = [root.id];
  while (queue.length > 0) {
    const id = queue.pop();
    if (seen.has(id)) continue;
    seen.add(id);
    for (const d of nodes.get(id)?.deps ?? []) {
      if (d.dep_kinds.some((k) => k.kind === null)) queue.push(d.pkg);
    }
  }
  return [...seen]
    .map((id) => packages.get(id))
    .filter((p) => p.source !== null)
    .map((p) => ({ name: p.name, version: p.version, license: p.license ?? '' }))
    .sort(byNameThenVersion);
}

/** By name, then by version (as strings); never 0, as the two are unique together. */
function byNameThenVersion(a, b) {
  if (a.name !== b.name) return a.name < b.name ? -1 : 1;
  return a.version < b.version ? -1 : 1;
}

/** By name alone, keeping the order of crates that share one. */
function byName(a, b) {
  if (a.name === b.name) return 0;
  return a.name < b.name ? -1 : 1;
}

/** `name@version` → the sha256 Cargo.lock records for its .crate archive. */
export function lockChecksums(lockText) {
  const out = new Map();
  for (const block of lockText.split('[[package]]')) {
    const name = /^name = "([^"]+)"$/m.exec(block)?.[1];
    const version = /^version = "([^"]+)"$/m.exec(block)?.[1];
    const checksum = /^checksum = "([0-9a-f]{64})"$/m.exec(block)?.[1];
    if (name && version && checksum) out.set(`${name}@${version}`, checksum);
  }
  return out;
}

const LICENCE_FILE = /^[^/]+\/(licen[cs]e|copying|notice|copyright)[^/]*$/i;

function licenceTexts(crateFile) {
  // tar runs next to the archive with its bare name: GNU tar reads a `C:` path as a remote host.
  const run = { cwd: path.dirname(crateFile), encoding: 'utf8' };
  const archive = path.basename(crateFile);
  const names = execFileSync('tar', ['-tzf', archive], run)
    .split('\n')
    .filter((n) => LICENCE_FILE.test(n))
    .sort();
  return names.map((n) => ({
    file: n.slice(n.indexOf('/') + 1),
    // LF only, as git stores the file (.gitattributes eol=lf); some crates ship CRLF texts.
    text: execFileSync('tar', ['-xzOf', archive, n], run).replace(/\r\n?/g, '\n'),
  }));
}

// Standard texts for crates that ship no licence file: SPDX license-list-data v3.29.0
// (commit 76c9a79bb7d2bf851143b76b3935a4d7cbaa644b), text/<id>.txt, verbatim.
const STANDARD_TEXTS = path.join(path.dirname(fileURLToPath(import.meta.url)), 'licence-texts');
const STANDARD_IDS = new Set(['MIT', 'Apache-2.0', 'MPL-2.0']);

/** The `authors` of a crate's Cargo.toml, or []. */
export function cargoAuthors(cargoToml) {
  const list = /^authors\s*=\s*\[([^\]]*)\]/m.exec(cargoToml)?.[1];
  return list === undefined ? [] : [...list.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1]);
}

/**
 * For a crate that ships no licence file: the standard text of every licence id its SPDX
 * `expression` names, and the line naming its copyright holders (its Cargo.toml authors). Fails
 * closed when an id has no standard text in tools/analyzers/licence-texts.
 */
export function standardTexts(name, expression, authors) {
  const ids = [
    ...new Set(
      expression
        .replace(/[()/]/g, ' ')
        .split(/\s+/)
        .filter((t) => t !== '' && t !== 'AND' && t !== 'OR'),
    ),
  ];
  const files = ids.map((id) => {
    if (!STANDARD_IDS.has(id)) {
      throw new Error(`${name}: ships no licence file, and there is no standard text for ${id}`);
    }
    return {
      file: `${id} (standard SPDX text)`,
      text: readFileSync(path.join(STANDARD_TEXTS, `${id}.txt`), 'utf8').replace(/\r\n?/g, '\n'),
    };
  });
  const holders =
    authors.length > 0
      ? `Copyright holders (Cargo.toml authors): ${authors.join(', ')}`
      : 'no copyright holder declared';
  return { holders, files };
}

/** Crate `c`'s .crate archive in `cache`, downloaded once and checked against Cargo.lock's `sum`. */
function fetchCrate(cache, c, sum) {
  if (!sum) throw new Error(`${c.name}@${c.version} is not in Cargo.lock`);
  const file = path.join(cache, `${c.name}-${c.version}.crate`);
  if (!existsSync(file)) {
    execFileSync('curl', [
      '-fsSL',
      '--proto',
      '=https',
      '--proto-redir',
      '=https',
      '--tlsv1.2',
      '--retry',
      '3',
      '-o',
      file,
      `https://static.crates.io/crates/${c.name}/${c.name}-${c.version}.crate`,
    ]);
  }
  const got = createHash('sha256').update(readFileSync(file)).digest('hex');
  if (got !== sum) throw new Error(`checksum mismatch: ${c.name}@${c.version}`);
  return file;
}

/**
 * The licence files of crate `c`'s archive `file`, or, when it ships none, the standard texts of
 * the licences it names, after adding the lines that say so and name its holders to `lines`.
 */
function crateLicenceFiles(file, c, lines) {
  const found = licenceTexts(file);
  if (found.length > 0) return found;
  const toml = execFileSync(
    'tar',
    ['-xzOf', path.basename(file), `${c.name}-${c.version}/Cargo.toml`],
    {
      cwd: path.dirname(file),
      encoding: 'utf8',
    },
  );
  const standard = standardTexts(c.name, c.license, cargoAuthors(toml));
  lines.push(
    '',
    '(the crate ships no licence file: the standard SPDX text of each licence it names)',
    standard.holders,
  );
  return standard.files;
}

function main([sourceDir, ...metadataFiles]) {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repo = path.resolve(here, '../..');
  const version = /^RUFF_VERSION=(.+)$/m.exec(
    readFileSync(path.join(repo, 'tools/analyzers/install.sh'), 'utf8'),
  )?.[1];
  const checksums = lockChecksums(readFileSync(path.join(sourceDir, 'Cargo.lock'), 'utf8'));
  const crates = new Map();
  for (const file of metadataFiles) {
    for (const c of shippedCrates(JSON.parse(readFileSync(file, 'utf8'))))
      crates.set(`${c.name}@${c.version}`, c);
  }
  const list = [...crates.values()].sort(byName);
  const problems = list.map((c) => licenceProblem(c.name, c.license)).filter((p) => p !== null);
  if (problems.length > 0) throw new Error(`disallowed licences:\n${problems.join('\n')}`);
  const cache = path.join(repo, '.tmp/crates');
  mkdirSync(cache, { recursive: true });
  const texts = new Map(); // text → its number, printed once
  const sections = [];
  for (const c of list) {
    const file = fetchCrate(cache, c, checksums.get(`${c.name}@${c.version}`));
    const lines = [
      `${c.name} ${c.version} (${c.license})`,
      `https://crates.io/crates/${c.name}/${c.version}`,
    ];
    for (const { file: name, text } of crateLicenceFiles(file, c, lines)) {
      if (!texts.has(text)) texts.set(text, texts.size + 1);
      lines.push('', `--- ${name}: text ${texts.get(text)}`);
    }
    sections.push(lines.join('\n'));
  }
  const bar = '='.repeat(78);
  const body = [...texts].map(([text, n]) => `${bar}\ntext ${n}\n\n${text.trimEnd()}`).join('\n\n');
  const out = [
    `The Rust crates compiled into Ruff ${version} (the ruff binary of /opt/qualor/bin), with the licence files`,
    'each crate ships (the standard SPDX text where it ships none). Each crate names its files by number;',
    'the texts follow the list, each printed once.',
    'Generated by tools/analyzers/ruff-licences.mjs; do not edit.',
    '',
    ...sections.map((s) => `${bar}\n${s}`),
    '',
    body,
    '',
  ].join('\n');
  writeFileSync(path.join(repo, 'deploy/scanner/licenses/RUFF-DEPENDENCIES.txt'), out);
  console.log(`${list.length} crates, ${texts.size} distinct licence texts`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
