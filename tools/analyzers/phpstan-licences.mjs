// The licence texts of the Composer packages inside the pinned PHPStan phar (plan 9A). Run where
// the phar and a php are (the analyzers toolbox):
//   node tools/analyzers/phpstan-licences.mjs /opt/qualor/lib/phpstan/phpstan.phar
// It reads the phar's vendor/composer/installed.php (name, version, commit) and the licence files
// each package keeps inside the phar. Each package's licence comes from phpstan-src's composer.lock
// at the phar's own commit (installed.php's root reference), whose version and source commit must be
// installed.php's. A package the phar ships without a licence file takes the licence its own source
// files carry in their header when they carry it whole (the hoa/* packages, whose repositories hold
// no licence file), and otherwise gets the file from GitHub at
// that commit. Every fetched file is pinned by sha256 in tools/analyzers/phpstan-licence-pins.json
// (ruling A9-10): nothing else is fetched. A package the phar build installs at another version
// than the lock's (PHAR_DOWNGRADES) takes its licence from its own composer.json at the phar's commit. Any licence outside ALLOWED fails the run.
// Writes deploy/scanner/licenses/PHPSTAN-DEPENDENCIES.txt.
//   node tools/analyzers/phpstan-licences.mjs --record /opt/qualor/lib/phpstan/phpstan.phar
// only prints the URLs and sha256s a new version needs, for the pins file (Step 4b).
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const ALLOWED = ['MIT', 'BSD-2-Clause', 'BSD-3-Clause', 'Apache-2.0', 'ISC'];
const LICENCE_NAMES = [
  'LICENSE',
  'LICENSE.md',
  'LICENSE.txt',
  'license.md',
  'license',
  'License.md',
  'COPYING',
  'LICENCE',
  'LICENCE.md',
];
const RAW = 'https://raw.githubusercontent.com';

/** A Composer `license` array is a choice (composer.json schema): the first allowed one, or null. */
export function chosenLicence(licences) {
  return licences.find((l) => ALLOWED.includes(l)) ?? null;
}

/** `owner/repo` of a GitHub source URL, or null. */
export function githubRepo(url) {
  return /^https:\/\/github\.com\/([\w.-]+\/[\w.-]+?)(?:\.git)?$/.exec(url)?.[1] ?? null;
}

/** composer.lock's entry for `name`, which must be the phar's version and commit. */
export function lockEntry(lock, name, pkg) {
  const entry = [...(lock.packages ?? []), ...(lock['packages-dev'] ?? [])].find(
    (p) => p.name === name,
  );
  if (entry === undefined) throw new Error(`${name} is not in phpstan-src's composer.lock`);
  if (entry.version !== pkg.version) {
    throw new Error(
      `${name}: the lock's version ${entry.version} is not the phar's ${pkg.version}`,
    );
  }
  if (pkg.reference !== null && entry.source?.reference !== pkg.reference) {
    throw new Error(
      `${name}: the lock's commit ${entry.source?.reference} is not the phar's ${pkg.reference}`,
    );
  }
  return entry;
}

/**
 * The packages the phar build installs at another version than phpstan-src's composer.lock: the
 * "Downgrade PHPUnit" step of phpstan-src's .github/workflows/phar.yml requires sebastian/diff ^4.0
 * (the only one for PHP 7.4) into the phar. Their licence comes from their own composer.json at the
 * commit installed.php records, pinned like every fetched file.
 */
export const PHAR_DOWNGRADES = ['sebastian/diff'];

/** The raw GitHub URL of a downgraded package's composer.json at the phar's commit. */
export function manifestUrl(lock, name, pkg) {
  if (!PHAR_DOWNGRADES.includes(name))
    throw new Error(`${name} is not a package the phar build downgrades`);
  const locked = [...(lock.packages ?? []), ...(lock['packages-dev'] ?? [])].find(
    (p) => p.name === name,
  );
  if (locked === undefined) throw new Error(`${name} is not in phpstan-src's composer.lock`);
  const gh = githubRepo(locked.source?.url ?? '');
  if (gh === null || pkg.reference === null)
    throw new Error(`${name}: no GitHub source at the phar's commit`);
  return `${RAW}/${gh}/${pkg.reference}/composer.json`;
}

/** A downgraded package's entry, from its composer.json at the phar's commit, in the shape of the lock's. */
export function manifestEntry(lock, name, pkg, manifest) {
  const url = manifestUrl(lock, name, pkg);
  if (manifest.name !== name) throw new Error(`${url} names ${manifest.name}, not ${name}`);
  const locked = [...(lock.packages ?? []), ...(lock['packages-dev'] ?? [])].find(
    (p) => p.name === name,
  );
  return {
    name,
    version: pkg.version,
    license: [manifest.license ?? []].flat(),
    source: { url: locked.source.url, reference: pkg.reference },
  };
}

/** The one pinned URL below `prefix` (a repository at a commit), or null. */
export function pinnedUrl(pins, prefix) {
  const urls = Object.keys(pins.files).filter((u) => u.startsWith(prefix));
  if (urls.length > 1) throw new Error(`more than one pinned file below ${prefix}`);
  return urls[0] ?? null;
}

/** The fetched bytes of `url` as text, after checking them against the pin. */
export function checkedText(bytes, url, pins) {
  const expected = pins.files[url];
  if (expected === undefined) throw new Error(`${url} is not pinned in phpstan-licence-pins.json`);
  const sum = createHash('sha256').update(bytes).digest('hex');
  if (sum !== expected) throw new Error(`checksum mismatch: ${url} is ${sum}, pinned ${expected}`);
  return bytes.toString('utf8');
}

const curl = (url) =>
  execFileSync(
    'curl',
    ['-fsSL', '--proto', '=https', '--proto-redir', '=https', '--tlsv1.2', '--retry', '3', url],
    {
      maxBuffer: 64 * 1024 * 1024,
    },
  );
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

const DUMP = `
$p = $argv[1];
$i = require "phar://$p/vendor/composer/installed.php";
$out = [];
foreach ($i['versions'] as $name => $v) {
    $dir = "phar://$p/vendor/$name";
    if ($name === $i['root']['name'] || !is_dir($dir)) continue;
    $files = [];
    foreach (scandir($dir) as $f) {
        if (preg_match('/^(licen[cs]e|copying|notice)/i', $f) === 1 && is_file("$dir/$f")) $files[$f] = file_get_contents("$dir/$f");
    }
    if ($files === []) {
        // No licence file (the hoa/* packages): the licence is the header of their source files, so the
        // first .php file whose leading docblock carries the whole licence gives the text, verbatim.
        $php = [];
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $f) {
            if (substr($f->getPathname(), -4) === ".php") $php[] = $f->getPathname();
        }
        sort($php);
        foreach ($php as $f) {
            $src = file_get_contents($f);
            $end = strpos($src, "*/");
            if (strncmp($src, "<?php\\n\\n/**", 10) !== 0 || $end === false) continue;
            $head = substr($src, 7, $end + 2 - 7);
            if (strpos($head, "@license") !== false && strpos($head, "Redistribution and use") !== false) {
                $files[substr($f, strlen($dir) + 1) . " (licence header)"] = $head;
                break;
            }
        }
    }
    $out[$name] = ['version' => $v['pretty_version'], 'reference' => $v['reference'] ?? null, 'files' => $files];
}
echo json_encode(['root' => $i['root'], 'packages' => $out]);
`;

/** The lock entry of a package: from the phar commit's lock, or its downgraded manifest. */
function packageEntry(lock, name, pkg, manifestOf) {
  if (!PHAR_DOWNGRADES.includes(name)) return { entry: lockEntry(lock, name, pkg), url: null };
  const url = manifestUrl(lock, name, pkg);
  return { entry: manifestEntry(lock, name, pkg, manifestOf(url)), url };
}

/** Trust on first use (Step 4b): the sha256 of every fetched input, for a person to check. */
function recordPins(version, lockUrl, packages) {
  // The lock, then each package without a licence file in the phar, at the commit the phar
  // records.
  const lockBytes = curl(lockUrl);
  const lock = JSON.parse(lockBytes.toString('utf8'));
  const out = { [lockUrl]: sha(lockBytes) };
  const manifestOf = (url) => {
    const bytes = curl(url);
    out[url] = sha(bytes);
    return JSON.parse(bytes.toString('utf8'));
  };
  for (const [name, pkg] of packages) {
    const { entry } = packageEntry(lock, name, pkg, manifestOf);
    if (Object.keys(pkg.files).length === 0) recordLicenceFile(name, pkg, entry, out);
  }
  console.log(JSON.stringify({ phpstan: version, files: out }, null, 2));
}

function recordLicenceFile(name, pkg, entry, out) {
  const gh = githubRepo(entry.source?.url ?? '');
  if (gh === null || pkg.reference === null)
    throw new Error(`${name}: no licence file and no GitHub source`);
  const found = LICENCE_NAMES.map((n) => `${RAW}/${gh}/${pkg.reference}/${n}`).find((u) => {
    try {
      out[u] = sha(curl(u));
      return true;
    } catch {
      return false;
    }
  });
  if (found === undefined) throw new Error(`${name}: no licence file at ${gh}@${pkg.reference}`);
}

/** A package's licence files: those inside the phar, or the pinned one from its source. */
function licenceFiles(name, pkg, entry, pins) {
  const files = Object.entries(pkg.files);
  if (files.length > 0) return { files, where: 'inside the phar' };
  const gh = githubRepo(entry.source?.url ?? '');
  if (gh === null || pkg.reference === null)
    throw new Error(`${name}: no licence file and no GitHub source`);
  const url = pinnedUrl(pins, `${RAW}/${gh}/${pkg.reference}/`);
  if (url === null) throw new Error(`${name}: no pinned licence file for ${gh}@${pkg.reference}`);
  return {
    files: [[url.slice(url.lastIndexOf('/') + 1), checkedText(curl(url), url, pins)]],
    where: `${url} (sha256 ${pins.files[url]})`,
  };
}

/** One package's section of PHPSTAN-DEPENDENCIES.txt; its texts are numbered in `texts`. */
function packageSection(lock, name, pkg, pins, texts, problems) {
  const manifestOf = (url) => JSON.parse(checkedText(curl(url), url, pins));
  const { entry, url: manifest } = packageEntry(lock, name, pkg, manifestOf);
  const licence = chosenLicence(entry.license ?? []);
  if (licence === null)
    problems.push(`${name}: ${(entry.license ?? []).join(' OR ') || 'no licence'} is not allowed`);
  const { files, where } = licenceFiles(name, pkg, entry, pins);
  const lines = [`${name} ${pkg.version} (${licence ?? (entry.license ?? []).join(' OR ')})`];
  if (manifest !== null) lines.push(`licences from: ${manifest} (sha256 ${pins.files[manifest]})`);
  lines.push(`licence files: ${where}`);
  for (const [file, text] of files) {
    if (!texts.has(text)) texts.set(text, texts.size + 1);
    lines.push(`--- ${file}: text ${texts.get(text)}`);
  }
  return lines.join('\n');
}

/** Writes deploy/scanner/licenses/PHPSTAN-DEPENDENCIES.txt from the pinned inputs only. */
function generate(repo, version, lockUrl, packages) {
  const pins = JSON.parse(
    readFileSync(path.join(repo, 'tools/analyzers/phpstan-licence-pins.json'), 'utf8'),
  );
  if (pins.phpstan !== version)
    throw new Error(`phpstan-licence-pins.json is for ${pins.phpstan}, install.sh pins ${version}`);
  const lock = JSON.parse(checkedText(curl(lockUrl), lockUrl, pins));
  const texts = new Map();
  const problems = [];
  const sections = packages.map(([name, pkg]) =>
    packageSection(lock, name, pkg, pins, texts, problems),
  );
  if (problems.length > 0) throw new Error(`disallowed licences:\n${problems.join('\n')}`);
  const bar = '='.repeat(78);
  const body = [...texts].map(([text, n]) => `${bar}\ntext ${n}\n\n${text.trimEnd()}`).join('\n\n');
  writeFileSync(
    path.join(repo, 'deploy/scanner/licenses/PHPSTAN-DEPENDENCIES.txt'),
    [
      `The Composer packages inside PHPStan ${version}'s phar (/opt/qualor/lib/phpstan/phpstan.phar), with`,
      'their licence files. Where a package offers a choice of licences, the one named is the one Qualor',
      'takes. Each package names its files by number; the texts follow the list, each printed once.',
      `licences from: ${lockUrl} (sha256 ${pins.files[lockUrl]})`,
      'Generated by tools/analyzers/phpstan-licences.mjs; do not edit.',
      '',
      ...sections.map((s) => `${bar}\n${s}`),
      '',
      body,
      '',
    ].join('\n'),
  );
  console.log(`${sections.length} packages, ${texts.size} distinct licence texts`);
}

function main(argv) {
  const record = argv[0] === '--record';
  const phar = record ? argv[1] : argv[0];
  const here = path.dirname(fileURLToPath(import.meta.url));
  const repo = path.resolve(here, '../..');
  const version = /^PHPSTAN_VERSION=(.+)$/m.exec(
    readFileSync(path.join(repo, 'tools/analyzers/install.sh'), 'utf8'),
  )?.[1];
  const dump = JSON.parse(
    execFileSync('php', ['-r', DUMP, phar], { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 }),
  );
  if (dump.root.pretty_version !== version)
    throw new Error(`the phar is ${dump.root.pretty_version}, install.sh pins ${version}`);
  const lockUrl = `${RAW}/phpstan/phpstan-src/${dump.root.reference}/composer.lock`;
  const packages = Object.entries(dump.packages).sort(([a], [b]) => (a < b ? -1 : 1));

  if (record) recordPins(version, lockUrl, packages);
  else generate(repo, version, lockUrl, packages);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main(process.argv.slice(2));
