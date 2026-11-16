import { parsePurl } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import { ecosystemsOfType, matchKeyOf, osMatchKey, purlOf, type MatchKeyInput } from './purl';

describe('purlOf', () => {
  it('replaces a lone surrogate with U+FFFD instead of throwing', () => {
    expect(purlOf('npm', 'a\uD800b', '1.0.0')).toContain('%EF%BF%BD');
    expect(purlOf('npm', 'lodash', '1\uDC00')).toBe('pkg:npm/lodash@1%EF%BF%BD');
  });

  it.each([
    ['npm', 'lodash', '4.17.20', 'pkg:npm/lodash@4.17.20'],
    ['yarn', 'lodash', '4.17.20', 'pkg:npm/lodash@4.17.20'],
    ['pnpm', 'lodash', '4.17.20', 'pkg:npm/lodash@4.17.20'],
    ['bun', 'lodash', '4.17.20', 'pkg:npm/lodash@4.17.20'],
    ['node-pkg', 'lodash', '4.17.20', 'pkg:npm/lodash@4.17.20'],
    ['npm', '@babel/traverse', '7.0.0', 'pkg:npm/%40babel/traverse@7.0.0'],
    ['pip', 'Django', '3.2.0', 'pkg:pypi/django@3.2.0'],
    ['pipenv', 'Django', '3.2.0', 'pkg:pypi/django@3.2.0'],
    ['poetry', 'Django', '3.2.0', 'pkg:pypi/django@3.2.0'],
    ['uv', 'Django', '3.2.0', 'pkg:pypi/django@3.2.0'],
    ['python-pkg', 'Django', '3.2.0', 'pkg:pypi/django@3.2.0'],
    ['poetry', 'typing_extensions', '4.0.0', 'pkg:pypi/typing-extensions@4.0.0'],
    [
      'pom',
      'org.apache.logging.log4j:log4j-core',
      '2.14.1',
      'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1',
    ],
    ['gradle', 'g:a', '1', 'pkg:maven/g/a@1'],
    ['sbt', 'g:a', '1', 'pkg:maven/g/a@1'],
    ['jar', 'g:a', '1', 'pkg:maven/g/a@1'],
    ['nuget', 'Newtonsoft.Json', '12.0.1', 'pkg:nuget/Newtonsoft.Json@12.0.1'],
    ['dotnet-core', 'Newtonsoft.Json', '12.0.1', 'pkg:nuget/Newtonsoft.Json@12.0.1'],
    ['packages-props', 'Newtonsoft.Json', '12.0.1', 'pkg:nuget/Newtonsoft.Json@12.0.1'],
    ['gomod', 'golang.org/x/text', 'v0.3.5', 'pkg:golang/golang.org/x/text@v0.3.5'],
    ['gobinary', 'golang.org/x/text', 'v0.3.5', 'pkg:golang/golang.org/x/text@v0.3.5'],
    ['cargo', 'serde', '1.0.0', 'pkg:cargo/serde@1.0.0'],
    ['rust-binary', 'serde', '1.0.0', 'pkg:cargo/serde@1.0.0'],
    ['composer', 'symfony/http-kernel', '5.0.0', 'pkg:composer/symfony/http-kernel@5.0.0'],
    ['composer-vendor', 'symfony/http-kernel', '5.0.0', 'pkg:composer/symfony/http-kernel@5.0.0'],
    ['bundler', 'rails', '6.0.0', 'pkg:gem/rails@6.0.0'],
    ['gemspec', 'rails', '6.0.0', 'pkg:gem/rails@6.0.0'],
    ['pub', 'http', '0.13.0', 'pkg:pub/http@0.13.0'],
    ['mix-lock', 'plug', '1.0.0', 'pkg:hex/plug@1.0.0'],
    ['swift', 'github.com/apple/swift-nio', '2.0.0', 'pkg:swift/github.com/apple/swift-nio@2.0.0'],
    ['cocoapods', 'AFNetworking', '3.0.0', 'pkg:cocoapods/AFNetworking@3.0.0'],
    ['conan', 'zlib', '1.2.11', 'pkg:conan/zlib@1.2.11'],
  ])('%s %s -> purl', (eco, name, version, expected) => {
    expect(purlOf(eco, name, version)).toBe(expected);
  });

  it('percent-encodes versions', () => {
    expect(purlOf('npm', 'a', '1.0.0+build 1')).toBe('pkg:npm/a@1.0.0%2Bbuild%201');
  });

  it('gives null for ecosystems without a purl, and for empty names', () => {
    expect(purlOf('dockerfile', 'x', '1')).toBeNull();
    expect(purlOf('', 'x', '1')).toBeNull();
    expect(purlOf('npm', '', '1')).toBeNull();
    expect(purlOf('npm', 'x', '')).toBeNull();
    expect(purlOf('pom', 'nocolon', '1')).toBe('pkg:maven/nocolon@1');
  });

  it.each(['constructor', '__proto__', 'toString', 'hasOwnProperty'])(
    'gives null for the inherited name %s, not a purl type',
    (eco) => {
      expect(purlOf(eco, 'x', '1')).toBeNull();
    },
  );

  it.each([
    ['pypi', 'Foo_Bar', '1.0', 'pkg:pypi/foo-bar@1.0'],
    ['maven', 'g:a', '1', 'pkg:maven/g/a@1'],
    ['golang', 'github.com/a/b', 'v1.0.0', 'pkg:golang/github.com/a/b@v1.0.0'],
    ['gem', 'rails', '7.0.0', 'pkg:gem/rails@7.0.0'],
    ['hex', 'phoenix', '1.7.0', 'pkg:hex/phoenix@1.7.0'],
    ['npm', '@scope/name', '1.0.0', 'pkg:npm/%40scope/name@1.0.0'],
  ])('gives the same purl back for the SBOM ecosystem %s %s', (eco, name, version, expected) => {
    expect(purlOf(eco, name, version)).toBe(expected);
  });

  it.each(['generic', 'oci', 'github', 'deb', 'rpm', 'apk'])(
    'gives null for %s, which Trivy cannot match without more',
    (eco) => {
      expect(purlOf(eco, 'x', '1')).toBeNull();
    },
  );
});

describe('osMatchKey (0.16 SBOM, Trivy’s own form)', () => {
  it.each([
    [
      ['deb', 'debian', '12.15', 'libssl3', '3.0.22-1~deb12u2'],
      'pkg:deb/debian/libssl3@3.0.22-1~deb12u2?distro=debian-12.15',
    ],
    [
      ['deb', 'debian', '12', 'login', '1:4.13+dfsg1-1'],
      'pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1?distro=debian-12',
    ],
    [
      ['rpm', 'redhat', '8.10', 'openssl-libs', '1:1.1.1k-12.el8_9'],
      'pkg:rpm/redhat/openssl-libs@1.1.1k-12.el8_9?epoch=1&distro=redhat-8.10',
    ],
    [
      ['rpm', 'redhat', '8.10', 'bash', '4.4.20-5.el8'],
      'pkg:rpm/redhat/bash@4.4.20-5.el8?distro=redhat-8.10',
    ],
    [
      ['apk', 'alpine', '3.20.3', 'libcrypto3', '3.3.2-r0'],
      'pkg:apk/alpine/libcrypto3@3.3.2-r0?distro=3.20.3',
    ],
    [
      ['rpm', 'redhat', '8.10', 'libstdc++', '8.5.0-31.el8_10'],
      'pkg:rpm/redhat/libstdc%2B%2B@8.5.0-31.el8_10?distro=redhat-8.10',
    ],
  ] as const)('%j -> %s', ([type, family, osVersion, name, version], expected) => {
    expect(osMatchKey(type, family, osVersion, name, version)).toBe(expected);
  });

  it('encodes what a stored row carries, and the shared parser reads it back (Review Focus 2)', () => {
    const key = osMatchKey('deb', 'debian', '12/x&y=z', 'a&b', '1:2+3?4#5 6');
    expect(key).toBe('pkg:deb/debian/a%26b@1%3A2%2B3%3F4%235%206?distro=debian-12%2Fx%26y%3Dz');
    expect(parsePurl(key)).toMatchObject({
      type: 'deb',
      namespace: 'debian',
      name: 'a&b',
      version: '1:2+3?4#5 6',
      qualifiers: { distro: 'debian-12/x&y=z' },
    });
    expect(
      parsePurl(osMatchKey('rpm', 'redhat', '8.10', 'openssl-libs', '1:1.1.1k-1')),
    ).toMatchObject({ version: '1.1.1k-1', qualifiers: { epoch: '1', distro: 'redhat-8.10' } });
    // A lone surrogate does not throw.
    expect(osMatchKey('apk', 'alpine', '3.20', 'x\uD800', '1')).toContain('%EF%BF%BD');
  });
});

describe('matchKeyOf', () => {
  const deb: MatchKeyInput = {
    ecosystem: 'deb',
    name: 'libssl3',
    version: '3.0.22-1~deb12u2',
    osFamily: 'debian',
    osVersion: '12.15',
  };

  it('gives an OS package of a known distribution its OS match key', () => {
    expect(matchKeyOf(deb)).toBe('pkg:deb/debian/libssl3@3.0.22-1~deb12u2?distro=debian-12.15');
  });

  it('gives null to an OS package without a distribution, or of an unknown family', () => {
    expect(matchKeyOf({ ...deb, osFamily: null, osVersion: null })).toBeNull();
    expect(matchKeyOf({ ...deb, osFamily: 'plan9' })).toBeNull();
    expect(matchKeyOf({ ...deb, osFamily: 'constructor' })).toBeNull();
    expect(matchKeyOf({ ...deb, osVersion: '' })).toBeNull();
    expect(matchKeyOf({ ...deb, name: '' })).toBeNull();
    expect(matchKeyOf({ ...deb, version: '' })).toBeNull();
  });

  it('gives a library its purl, with or without a distribution on the version', () => {
    const npm = { ecosystem: 'npm', name: 'lodash', version: '4.17.20' };
    expect(matchKeyOf({ ...npm, osFamily: 'debian', osVersion: '12.15' })).toBe(
      purlOf('npm', 'lodash', '4.17.20'),
    );
    expect(matchKeyOf({ ...npm, osFamily: null, osVersion: null })).toBe('pkg:npm/lodash@4.17.20');
    expect(
      matchKeyOf({
        ecosystem: 'generic',
        name: 'x',
        version: '1',
        osFamily: null,
        osVersion: null,
      }),
    ).toBeNull();
  });
});

describe('ecosystemsOfType', () => {
  it('is the type and every ecosystem that maps to it', () => {
    expect(ecosystemsOfType('pypi').sort()).toEqual(
      ['pip', 'pipenv', 'poetry', 'pypi', 'python-pkg', 'uv'].sort(),
    );
    expect(ecosystemsOfType('npm')).toEqual(
      expect.arrayContaining(['npm', 'yarn', 'pnpm', 'bun', 'node-pkg']),
    );
    expect(ecosystemsOfType('maven')).toEqual(
      expect.arrayContaining(['maven', 'pom', 'gradle', 'sbt', 'jar']),
    );
  });

  it('is the type alone when nothing maps to it', () => {
    expect(ecosystemsOfType('deb')).toEqual(['deb']);
    expect(ecosystemsOfType('generic')).toEqual(['generic']);
    expect(ecosystemsOfType('constructor')).toEqual(['constructor']);
  });
});
