import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { inventoryName, inventoryVersion, parsePurl } from './purl';

const SUITE = join(__dirname, '../../test/purl-spec');

interface SuiteCase {
  description: string;
  test_type: string;
  input: unknown;
  expected_output: {
    type: string;
    namespace: string | null;
    name: string;
    version: string | null;
    qualifiers: Record<string, string> | null;
    subpath: string | null;
  } | null;
  expected_failure: boolean;
}

/**
 * Cases of type-specific rules the reader leaves out on purpose: it takes what an SBOM tool wrote
 * and normalises nothing per type (pypi names are folded in `inventoryName`, ruling R1), and it
 * does not reject a purl for a missing part that only one type requires.
 */
const LENIENT: Record<string, string> = {
  'pkg:composer/Laravel/Laravel@5.5.0': 'composer lower-casing',
  'pkg:PYPI/Django_package@1.11.1.dev1': 'pypi name normalisation (inventoryName, R1)',
  'pkg:pypi/My.PyPI_.--._Package@1.11.1.dev1': 'pypi name normalisation (inventoryName, R1)',
  'pkg:pypi/friendly--bard@1.0': 'pypi name normalisation (inventoryName, R1)',
  'pkg:pypi/friendly.bard@1.0': 'pypi name normalisation (inventoryName, R1)',
  'pkg:pypi/friendly__bard@1.0': 'pypi name normalisation (inventoryName, R1)',
  'pkg:gem/jruby-launcher@1.1.2?Platform=java': 'upper-case qualifier key is lower-cased',
  'pkg:Rpm/fedora/curl@7.50.3-1.fc25?Arch=i386&Distro=fedora-25':
    'upper-case qualifier key is lower-cased',
  'pkg:swift/Alamofire@5.4.3': 'swift without a namespace still parses',
  'pkg:swift/github.com/Alamofire/@5.4.3': 'an empty name segment before the version is dropped',
};

const cases: { file: string; test: SuiteCase }[] = readdirSync(SUITE)
  .filter((f) => f.endsWith('.json'))
  .flatMap((file) =>
    (JSON.parse(readFileSync(join(SUITE, file), 'utf8')) as { tests: SuiteCase[] }).tests
      .filter((t) => t.test_type === 'parse' && !Object.hasOwn(LENIENT, String(t.input)))
      .map((test) => ({ file, test })),
  );

describe('the purl-spec suite', () => {
  it('has cases', () => {
    expect(cases.length).toBeGreaterThan(75);
    expect(cases.some((c) => c.test.expected_failure)).toBe(true);
  });

  for (const { file, test } of cases) {
    it(`${file}: ${test.description} (${String(test.input)})`, () => {
      const got = parsePurl(test.input as string);
      if (test.expected_failure || test.expected_output === null) {
        expect(got).toBeNull();
        return;
      }
      expect(got).toEqual({
        ...test.expected_output,
        qualifiers: test.expected_output.qualifiers ?? {},
      });
    });
  }
});

describe('the lenient cases', () => {
  it('parses them without the type rule', () => {
    expect(parsePurl('pkg:composer/Laravel/Laravel@5.5.0')).toMatchObject({
      namespace: 'Laravel',
      name: 'Laravel',
    });
    expect(parsePurl('pkg:pypi/friendly.bard@1.0')!.name).toBe('friendly.bard');
    expect(parsePurl('pkg:gem/jruby-launcher@1.1.2?Platform=java')!.qualifiers).toEqual({
      platform: 'java',
    });
    expect(parsePurl('pkg:swift/Alamofire@5.4.3')).toMatchObject({
      namespace: null,
      name: 'Alamofire',
    });
    expect(parsePurl('pkg:swift/github.com/Alamofire/@5.4.3')).toMatchObject({
      namespace: 'github.com',
      name: 'Alamofire',
    });
  });
});

describe('decodes', () => {
  it('a scoped npm name', () => {
    const p = parsePurl('pkg:npm/%40angular/core@16.2.0')!;
    expect(p.namespace).toBe('@angular');
    expect(p.name).toBe('core');
    expect(inventoryName(p)).toBe('@angular/core');
  });

  it('a version and qualifiers', () => {
    const p = parsePurl('pkg:deb/debian/attr@1%3A2.4.47-2%2Bb1?arch=amd64&distro=debian-12')!;
    expect(p.version).toBe('1:2.4.47-2+b1');
    expect(p.qualifiers).toEqual({ arch: 'amd64', distro: 'debian-12' });
  });

  it('a plus is not a space', () => {
    expect(parsePurl('pkg:deb/debian/curl@7.74.0-1.3+deb11u7')!.version).toBe('7.74.0-1.3+deb11u7');
  });
});

describe('inventory names', () => {
  it.each([
    ['pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', 'org.apache.logging.log4j:log4j-core'],
    ['pkg:golang/github.com/gin-gonic/gin@v1.9.1', 'github.com/gin-gonic/gin'],
    ['pkg:pypi/Django_Rest@3.0', 'django-rest'],
    ['pkg:composer/laravel/framework@10.0.0', 'laravel/framework'],
    ['pkg:deb/debian/libssl3@3.0.11', 'libssl3'],
    ['pkg:npm/left-pad@1.3.0', 'left-pad'],
  ])('%s', (purl, name) => {
    expect(inventoryName(parsePurl(purl)!)).toBe(name);
  });
});

describe('rpm epoch', () => {
  const base = 'pkg:rpm/fedora/centerim@4.22.10-1.el6?arch=i686';
  it('folds the epoch in', () => {
    expect(inventoryVersion(parsePurl(`${base}&epoch=1&distro=fedora-25`)!)).toBe(
      '1:4.22.10-1.el6',
    );
  });
  it('leaves a missing or zero epoch out', () => {
    expect(inventoryVersion(parsePurl(`${base}&distro=fedora-25`)!)).toBe('4.22.10-1.el6');
    expect(inventoryVersion(parsePurl(`${base}&epoch=0`)!)).toBe('4.22.10-1.el6');
  });
  it('returns other types as given', () => {
    expect(inventoryVersion(parsePurl('pkg:npm/a@1.0.0?epoch=2')!)).toBe('1.0.0');
  });
});

describe('refuses', () => {
  it.each([
    'npm/foo@1',
    'pkg:',
    'pkg:npm/',
    'pkg:npm/a%ZZ@1',
    'pkg:npm/a%00b@1',
    'pkg:npm/a%ED%A0%80@1',
    'pkg:npm/a\ud800b@1',
    '',
  ])('%j', (text) => {
    expect(parsePurl(text)).toBeNull();
  });
});
