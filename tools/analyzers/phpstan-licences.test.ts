import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import {
  checkedText,
  chosenLicence,
  githubRepo,
  lockEntry,
  manifestEntry,
  manifestUrl,
  pinnedUrl,
  // @ts-expect-error: a plain ES module of the repository's tooling, without type declarations
} from './phpstan-licences.mjs';

const pinned = /^PHPSTAN_VERSION=(.+)$/m.exec(
  readFileSync('tools/analyzers/install.sh', 'utf8'),
)?.[1];
const sha256 = (s: string) => createHash('sha256').update(s).digest('hex');

describe('phpstan-licences.mjs', () => {
  it('takes an allowed licence out of a Composer choice, and refuses anything else', () => {
    expect(chosenLicence(['MIT'])).toBe('MIT');
    expect(chosenLicence(['BSD-3-Clause', 'GPL-2.0-only', 'GPL-3.0-only'])).toBe('BSD-3-Clause');
    expect(chosenLicence(['MIT', 'PHP-3.01'])).toBe('MIT');
    expect(chosenLicence(['Apache-2.0'])).toBe('Apache-2.0');
    expect(chosenLicence(['GPL-3.0-only'])).toBeNull();
    expect(chosenLicence(['(MIT and GPL-2.0-only)'])).toBeNull();
    expect(chosenLicence([])).toBeNull();
  });

  it("takes a package's licence and commit from phpstan-src's composer.lock, and refuses a mismatch", () => {
    const lock = {
      packages: [
        {
          name: 'a/b',
          version: '1.0.0',
          license: ['MIT'],
          source: { url: 'https://github.com/a/b.git', reference: 'r1' },
        },
      ],
      'packages-dev': [
        { name: 'c/d', version: 'v2.0.0', license: ['BSD-3-Clause'], source: { reference: 'r2' } },
      ],
    };
    expect(lockEntry(lock, 'a/b', { version: '1.0.0', reference: 'r1' })).toMatchObject({
      license: ['MIT'],
    });
    expect(lockEntry(lock, 'c/d', { version: 'v2.0.0', reference: null })).toMatchObject({
      license: ['BSD-3-Clause'],
    });
    expect(() => lockEntry(lock, 'a/b', { version: '1.0.1', reference: 'r1' })).toThrow(/version/);
    expect(() => lockEntry(lock, 'a/b', { version: '1.0.0', reference: 'r9' })).toThrow(/commit/);
    expect(() => lockEntry(lock, 'e/f', { version: '1.0.0', reference: null })).toThrow(/not in/);
  });

  it("reads a package the phar build downgrades from its own composer.json at the phar's commit", () => {
    const lock = {
      packages: [
        {
          name: 'sebastian/diff',
          version: '6.0.2',
          license: ['BSD-3-Clause'],
          source: { url: 'https://github.com/sebastianbergmann/diff.git', reference: 'r6' },
        },
      ],
    };
    const pkg = { version: '4.0.6', reference: 'r4' };
    const url = 'https://raw.githubusercontent.com/sebastianbergmann/diff/r4/composer.json';
    expect(manifestUrl(lock, 'sebastian/diff', pkg)).toBe(url);
    expect(
      manifestEntry(lock, 'sebastian/diff', pkg, {
        name: 'sebastian/diff',
        license: 'BSD-3-Clause', // composer.json allows a string
      }),
    ).toMatchObject({
      version: '4.0.6',
      license: ['BSD-3-Clause'],
      source: { url: 'https://github.com/sebastianbergmann/diff.git', reference: 'r4' },
    });
    expect(() =>
      manifestEntry(lock, 'sebastian/diff', pkg, { name: 'other/pkg', license: ['MIT'] }),
    ).toThrow(/names/);
    expect(() => manifestUrl(lock, 'a/b', pkg)).toThrow(/downgrades/);
    expect(() => manifestUrl({ packages: [] }, 'sebastian/diff', pkg)).toThrow(/not in/);
  });

  it('fetches nothing it has no pin for, and checks every pinned file', () => {
    const url = 'https://raw.githubusercontent.com/nette/utils/abc/license.md';
    const pins = { phpstan: '9.9.9', files: { [url]: sha256('text') } };
    expect(pinnedUrl(pins, 'https://raw.githubusercontent.com/nette/utils/abc/')).toBe(url);
    expect(pinnedUrl(pins, 'https://raw.githubusercontent.com/nette/utils/def/')).toBeNull();
    expect(checkedText(Buffer.from('text'), url, pins)).toBe('text');
    expect(() => checkedText(Buffer.from('other'), url, pins)).toThrow(/checksum/);
    expect(() => checkedText(Buffer.from('text'), `${url}x`, pins)).toThrow(/not pinned/);
  });

  it('reads a GitHub repository out of a source URL', () => {
    expect(githubRepo('https://github.com/hoaproject/Compiler.git')).toBe('hoaproject/Compiler');
    expect(githubRepo('https://github.com/nette/utils')).toBe('nette/utils');
    expect(githubRepo('https://gitlab.com/x/y.git')).toBeNull();
  });

  it('keeps the pins in step with the pinned PHPStan: commit-addressed GitHub files only', () => {
    const pins = JSON.parse(readFileSync('tools/analyzers/phpstan-licence-pins.json', 'utf8')) as {
      phpstan: string;
      files: Record<string, string>;
    };
    expect(pins.phpstan).toBe(pinned);
    for (const [url, sum] of Object.entries(pins.files)) {
      expect(url).toMatch(
        /^https:\/\/raw\.githubusercontent\.com\/[\w.-]+\/[\w.-]+\/[0-9a-f]{40}\/[^/]+$/,
      );
      expect(sum, url).toMatch(/^[0-9a-f]{64}$/);
    }
    expect(
      Object.keys(pins.files).filter((u) =>
        /\/phpstan\/phpstan-src\/[0-9a-f]{40}\/composer\.lock$/.test(u),
      ),
    ).toHaveLength(1);
  });

  it('keeps the committed PHPSTAN-DEPENDENCIES.txt in step with the pinned PHPStan and its pins', () => {
    const text = readFileSync('deploy/scanner/licenses/PHPSTAN-DEPENDENCIES.txt', 'utf8');
    const pins = JSON.parse(readFileSync('tools/analyzers/phpstan-licence-pins.json', 'utf8')) as {
      files: Record<string, string>;
    };
    expect(text).toContain(`inside PHPStan ${pinned}'s phar`);
    // Every fetched file is named with the sha256 it was checked against (ruling A9-10).
    const fetched = [
      ...text.matchAll(
        /^(?:licence files|licences from): (https:\S+) \(sha256 ([0-9a-f]{64})\)$/gm,
      ),
    ];
    expect(fetched.length).toBeGreaterThan(0);
    for (const [, url, sum] of fetched) expect(pins.files[url!], url).toBe(sum);
    const headers = [...text.matchAll(/^={78}\n(\S+) (\S+) \((.+)\)$/gm)];
    expect(headers.length).toBeGreaterThanOrEqual(60);
    for (const [, name, , licence] of headers)
      expect(chosenLicence([licence]), name).not.toBeNull();
    for (const name of [
      'nikic/php-parser',
      'nette/neon',
      'hoa/compiler',
      'jetbrains/phpstorm-stubs',
    ]) {
      expect(
        headers.some(([, n]) => n === name),
        name,
      ).toBe(true);
    }
    expect(readFileSync('deploy/scanner/licenses/PHPSTAN-LICENSE.txt', 'utf8')).toMatch(
      /^MIT License/,
    );
  });
});
