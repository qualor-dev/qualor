import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
// @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
import { licenceProblem, lockChecksums, shippedCrates } from './ruff-licences.mjs';

describe('ruff-licences.mjs', () => {
  it('accepts permissive SPDX expressions, choices and legacy slashes', () => {
    for (const expression of [
      'MIT',
      'MIT OR Apache-2.0',
      'MIT/Apache-2.0',
      'Apache-2.0 / MIT',
      'Unlicense OR MIT',
      '(MIT OR Apache-2.0) AND Unicode-3.0',
      'Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT',
      'CC0-1.0 OR MIT-0 OR Apache-2.0',
      'Zlib',
      'MIT AND BSD-3-Clause',
    ]) {
      expect(licenceProblem('any', expression), expression).toBeNull();
    }
  });

  it('allows MPL-2.0, WTFPL and PSF-2.0 only for the named crates', () => {
    expect(licenceProblem('colored', 'MPL-2.0')).toBeNull();
    expect(licenceProblem('terminfo', 'WTFPL')).toBeNull();
    expect(licenceProblem('libcst', 'MIT AND (MIT AND PSF-2.0)')).toBeNull();
    expect(licenceProblem('newcrate', 'MPL-2.0')).toMatch(/not an allowed licence/);
    expect(licenceProblem('newcrate', 'GPL-3.0-only')).toMatch(/not an allowed licence/);
    expect(licenceProblem('newcrate', 'MIT AND GPL-3.0-only')).toMatch(/not an allowed licence/);
    expect(licenceProblem('newcrate', '')).toMatch(/no licence/);
    expect(licenceProblem('newcrate', 'MIT OR (')).toMatch(/cannot read/);
  });

  it('follows normal dependencies of the ruff package only, and leaves out workspace crates', () => {
    const pkg = (name: string, source: string | null, license = 'MIT') => ({
      id: `${name}-id`,
      name,
      version: '1.0.0',
      source,
      license,
    });
    const reg = 'registry+https://github.com/rust-lang/crates.io-index';
    const dep = (pkgId: string, kind: string | null) => ({ pkg: pkgId, dep_kinds: [{ kind }] });
    const metadata = {
      packages: [
        pkg('ruff', null),
        pkg('ruff_linter', null),
        pkg('a', reg),
        pkg('b', reg),
        pkg('dev-only', reg),
        pkg('build-only', reg),
      ],
      resolve: {
        nodes: [
          { id: 'ruff-id', deps: [dep('ruff_linter-id', null), dep('dev-only-id', 'dev')] },
          { id: 'ruff_linter-id', deps: [dep('a-id', null), dep('build-only-id', 'build')] },
          { id: 'a-id', deps: [dep('b-id', null)] },
          { id: 'b-id', deps: [] },
          { id: 'dev-only-id', deps: [] },
          { id: 'build-only-id', deps: [] },
        ],
      },
    };
    expect(shippedCrates(metadata).map((c: { name: string }) => c.name)).toEqual(['a', 'b']);
  });

  it('reads the checksums of Cargo.lock', () => {
    const lock =
      '[[package]]\nname = "colored"\nversion = "3.1.1"\nsource = "registry+x"\nchecksum = "' +
      'f'.repeat(64) +
      '"\n\n[[package]]\nname = "ruff"\nversion = "0.16.9"\n';
    expect([...lockChecksums(lock)]).toEqual([['colored@3.1.1', 'f'.repeat(64)]]);
  });

  it('keeps the committed RUFF-DEPENDENCIES.txt in step with the pinned Ruff', () => {
    const text = readFileSync('deploy/scanner/licenses/RUFF-DEPENDENCIES.txt', 'utf8');
    const pinned = /^RUFF_VERSION=(.+)$/m.exec(
      readFileSync('tools/analyzers/install.sh', 'utf8'),
    )?.[1];
    expect(text).toContain(`compiled into Ruff ${pinned} `);
    // A crate's header line follows the ===== bar; a licence text's own lines never do.
    const headers = [...text.matchAll(/^={78}\n(\S+) (\S+) \((.+)\)$/gm)];
    expect(headers.length).toBeGreaterThan(200);
    for (const [, name, , licence] of headers)
      expect(licenceProblem(name, licence), name).toBeNull();
    for (const name of ['colored', 'option-ext', 'version-ranges', 'terminfo', 'libcst']) {
      expect(
        headers.some(([, n]) => n === name),
        name,
      ).toBe(true);
    }
  });
});
