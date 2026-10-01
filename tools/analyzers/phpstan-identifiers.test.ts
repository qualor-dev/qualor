import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { PHPSTAN_UNKNOWN_SYMBOL_IDS } from '../../packages/shared/src/rules/phpstan';
// @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
import { IDENTIFIERS_SHA256, IDENTIFIERS_URL, coreIdentifiers } from './phpstan-identifiers.mjs';

const install = readFileSync('tools/analyzers/install.sh', 'utf8');
const pinned = /^PHPSTAN_VERSION=(.+)$/m.exec(install)?.[1];

describe('phpstan-identifiers.mjs', () => {
  it('keeps the identifiers phpstan-src raises, not those of extensions Qualor does not ship', () => {
    const json = {
      'variable.undefined': { R1: { 'phpstan/phpstan-src': ['u'] } },
      'method.unused': {
        R2: { 'phpstan/phpstan-src': ['u'] },
        R3: { 'phpstan/phpstan-strict-rules': ['u'] },
      },
      'doctrine.dql': { R4: { 'phpstan/phpstan-doctrine': ['u'] } },
    };
    expect(coreIdentifiers(json)).toEqual(['method.unused', 'variable.undefined']);
  });

  it('reads the table of the pinned PHPStan, checked by the sha256 install.sh pins with it', () => {
    expect(IDENTIFIERS_URL).toBe(
      `https://raw.githubusercontent.com/phpstan/phpstan/${pinned}/website/src/errorsIdentifiers.json`,
    );
    expect(IDENTIFIERS_SHA256).toMatch(/^[0-9a-f]{64}$/);
    expect(install).toContain(`\nPHPSTAN_IDENTIFIERS_SHA256=${IDENTIFIERS_SHA256}\n`);
  });

  it('commits a sorted, unique table of the pinned PHPStan that knows what Qualor relies on', () => {
    const table = JSON.parse(
      readFileSync('packages/shared/rules/phpstan-identifiers.json', 'utf8'),
    ) as {
      phpstan: string;
      identifiers: string[];
    };
    // A PHPStan bump without a regenerated table (and so without a new PHPSTAN_IDENTIFIERS_SHA256,
    // which the generator checks) fails here (ruling A9-10).
    expect(table.phpstan).toBe(pinned);
    const ids = table.identifiers;
    expect(ids.length).toBeGreaterThan(800);
    expect([...ids].sort()).toEqual(ids);
    expect(new Set(ids).size).toBe(ids.length);
    for (const id of [
      ...PHPSTAN_UNKNOWN_SYMBOL_IDS,
      'variable.undefined',
      'arguments.count',
      'method.void',
      'phpstan.parse',
    ]) {
      expect(ids, id).toContain(id);
    }
  });
});
