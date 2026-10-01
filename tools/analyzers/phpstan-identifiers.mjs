// The error identifiers of the pinned PHPStan's own rules (plan 9A): keys only, PHPStan's facts
// (MIT), from the errorsIdentifiers.json of the phpstan/phpstan tag (website/src), checked by sha256.
//   node tools/analyzers/phpstan-identifiers.mjs
// writes packages/shared/rules/phpstan-identifiers.json ({ phpstan, identifiers }). The version and
// the file's sha256 are install.sh's PHPSTAN_VERSION and PHPSTAN_IDENTIFIERS_SHA256: a bump sets both.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const repo = path.resolve(here, '../..');
const install = readFileSync(path.join(repo, 'tools/analyzers/install.sh'), 'utf8');
const version = /^PHPSTAN_VERSION=(.+)$/m.exec(install)?.[1];

export const IDENTIFIERS_URL = `https://raw.githubusercontent.com/phpstan/phpstan/${version}/website/src/errorsIdentifiers.json`;
export const IDENTIFIERS_SHA256 = /^PHPSTAN_IDENTIFIERS_SHA256=([0-9a-f]{64})$/m.exec(install)?.[1];

/** The identifiers at least one rule of phpstan/phpstan-src raises, sorted. */
export function coreIdentifiers(json) {
  return Object.keys(json)
    .filter((id) =>
      Object.values(json[id]).some((byRepo) => Object.hasOwn(byRepo, 'phpstan/phpstan-src')),
    )
    .sort();
}

function main() {
  if (version === undefined || IDENTIFIERS_SHA256 === undefined) {
    throw new Error('install.sh must set PHPSTAN_VERSION and PHPSTAN_IDENTIFIERS_SHA256');
  }
  const bytes = execFileSync(
    'curl',
    [
      '-fsSL',
      '--proto',
      '=https',
      '--proto-redir',
      '=https',
      '--tlsv1.2',
      '--retry',
      '3',
      IDENTIFIERS_URL,
    ],
    { maxBuffer: 64 * 1024 * 1024 },
  );
  const sum = createHash('sha256').update(bytes).digest('hex');
  if (sum !== IDENTIFIERS_SHA256)
    throw new Error(`checksum mismatch: ${IDENTIFIERS_URL} is ${sum}`);
  const ids = coreIdentifiers(JSON.parse(bytes.toString('utf8')));
  writeFileSync(
    path.join(repo, 'packages/shared/rules/phpstan-identifiers.json'),
    `${JSON.stringify({ phpstan: version, identifiers: ids }, null, 2)}\n`,
  );
  console.log(`${ids.length} identifiers`);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) main();
