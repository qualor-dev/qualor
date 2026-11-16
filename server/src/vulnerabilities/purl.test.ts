import { parsePurl } from '@qualor/shared';
import { describe, expect, it } from 'vitest';
import {
  ecosystemsOfType,
  matchKeyOf,
  osMatchKey,
  osSourceOf,
  purlOf,
  validStoredValues,
  type MatchKeyInput,
} from './purl';

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

describe('osMatchKey (0.16 SBOM, Trivy’s own form, R15: with the source package)', () => {
  it.each([
    [
      ['deb', 'debian', '12.15', 'libssl3', '3.0.22-1~deb12u2', 'openssl', '3.0.22-1~deb12u2'],
      'pkg:deb/debian/libssl3@3.0.22-1~deb12u2?distro=debian-12.15&upstream=openssl%403.0.22-1~deb12u2',
    ],
    [
      ['deb', 'debian', '12', 'login', '1:4.13+dfsg1-1', 'shadow', '1:4.13+dfsg1-1'],
      'pkg:deb/debian/login@1%3A4.13%2Bdfsg1-1?distro=debian-12&upstream=shadow%401%3A4.13%2Bdfsg1-1',
    ],
    [
      [
        'rpm',
        'redhat',
        '8.10',
        'openssl-libs',
        '1:1.1.1k-12.el8_9',
        'openssl',
        '1:1.1.1k-12.el8_9',
      ],
      'pkg:rpm/redhat/openssl-libs@1.1.1k-12.el8_9?epoch=1&distro=redhat-8.10&upstream=openssl%401%3A1.1.1k-12.el8_9',
    ],
    [
      ['rpm', 'redhat', '8.10', 'bash', '4.4.20-5.el8', 'bash', '4.4.20-5.el8'],
      'pkg:rpm/redhat/bash@4.4.20-5.el8?distro=redhat-8.10&upstream=bash%404.4.20-5.el8',
    ],
    [
      ['apk', 'alpine', '3.20.3', 'libcrypto3', '3.3.2-r0', 'openssl', '3.3.2-r0'],
      'pkg:apk/alpine/libcrypto3@3.3.2-r0?distro=3.20.3&upstream=openssl%403.3.2-r0',
    ],
    [
      ['rpm', 'redhat', '8.10', 'libstdc++', '8.5.0-31.el8_10', 'gcc', '8.5.0-31.el8_10'],
      'pkg:rpm/redhat/libstdc%2B%2B@8.5.0-31.el8_10?distro=redhat-8.10&upstream=gcc%408.5.0-31.el8_10',
    ],
  ] as const)(
    '%j -> %s',
    ([type, family, osVersion, name, version, sourceName, sourceVersion], expected) => {
      expect(
        osMatchKey(type, family, osVersion, name, version, {
          name: sourceName,
          version: sourceVersion,
        }),
      ).toBe(expected);
    },
  );

  it('encodes what a stored row carries, and the shared parser reads it back (Review Focus 2)', () => {
    const key = osMatchKey('deb', 'debian', '12/x&y=z', 'a&b', '1:2+3?4#5 6', {
      name: 's&t',
      version: '1:2+3',
    });
    expect(key).toBe(
      'pkg:deb/debian/a%26b@1%3A2%2B3%3F4%235%206?distro=debian-12%2Fx%26y%3Dz&upstream=s%26t%401%3A2%2B3',
    );
    expect(parsePurl(key)).toMatchObject({
      type: 'deb',
      namespace: 'debian',
      name: 'a&b',
      version: '1:2+3?4#5 6',
      qualifiers: { distro: 'debian-12/x&y=z', upstream: 's&t@1:2+3' },
    });
    expect(
      parsePurl(
        osMatchKey('rpm', 'redhat', '8.10', 'openssl-libs', '1:1.1.1k-1', {
          name: 'openssl',
          version: '1:1.1.1k-1',
        }),
      ),
    ).toMatchObject({
      version: '1.1.1k-1',
      qualifiers: { epoch: '1', distro: 'redhat-8.10', upstream: 'openssl@1:1.1.1k-1' },
    });
    // A lone surrogate does not throw.
    expect(
      osMatchKey('apk', 'alpine', '3.20', 'x\uD800', '1', { name: 'x', version: '1' }),
    ).toContain('%EF%BF%BD');
  });
});

describe('matchKeyOf', () => {
  const deb: MatchKeyInput = {
    ecosystem: 'deb',
    name: 'libssl3',
    version: '3.0.22-1~deb12u2',
    osFamily: 'debian',
    osVersion: '12.15',
    sourceName: 'openssl',
    sourceVersion: '3.0.22-1~deb12u2',
  };
  const LIBSSL3 =
    'pkg:deb/debian/libssl3@3.0.22-1~deb12u2?distro=debian-12.15&upstream=openssl%403.0.22-1~deb12u2';

  it('gives an OS package of a known distribution its OS match key, source included', () => {
    expect(matchKeyOf(deb)).toBe(LIBSSL3);
  });

  it('keys the binary itself as the source when the row names none (R15)', () => {
    const own =
      'pkg:deb/debian/libssl3@3.0.22-1~deb12u2?distro=debian-12.15&upstream=libssl3%403.0.22-1~deb12u2';
    expect(matchKeyOf({ ...deb, sourceName: null, sourceVersion: null })).toBe(own);
    expect(matchKeyOf({ ...deb, sourceName: '', sourceVersion: '' })).toBe(own);
    expect(osSourceOf({ ...deb, sourceName: null, sourceVersion: null })).toEqual({
      name: 'libssl3',
      version: '3.0.22-1~deb12u2',
    });
  });

  it('gives another source another key: one row’s claim never answers for another (R15)', () => {
    const other = matchKeyOf({ ...deb, sourceName: 'not-openssl' });
    const older = matchKeyOf({ ...deb, sourceVersion: '3.0.0-1' });
    expect(new Set([LIBSSL3, other, older]).size).toBe(3);
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
    const npm = { ecosystem: 'npm', name: 'lodash', version: '4.17.20', sourceName: null };
    expect(
      matchKeyOf({ ...npm, osFamily: 'debian', osVersion: '12.15', sourceVersion: null }),
    ).toBe(purlOf('npm', 'lodash', '4.17.20'));
    expect(matchKeyOf({ ...npm, osFamily: null, osVersion: null, sourceVersion: null })).toBe(
      'pkg:npm/lodash@4.17.20',
    );
    expect(
      matchKeyOf({
        ecosystem: 'generic',
        name: 'x',
        version: '1',
        osFamily: null,
        osVersion: null,
        sourceName: null,
        sourceVersion: null,
      }),
    ).toBeNull();
  });
});

describe('validStoredValues (R16: checked before anything goes to Trivy)', () => {
  const rpm: MatchKeyInput = {
    ecosystem: 'rpm',
    name: 'openssl-libs',
    version: '1:1.1.1k-18.el8_6',
    osFamily: 'redhat',
    osVersion: '8.10',
    sourceName: 'openssl',
    sourceVersion: '1:1.1.1k-18.el8_6',
  };

  it('takes well-formed rows, and leaves absent values to the key rules', () => {
    expect(validStoredValues(rpm)).toBe(true);
    expect(validStoredValues({ ...rpm, osFamily: null, osVersion: null })).toBe(true);
    expect(validStoredValues({ ...rpm, sourceName: null, sourceVersion: null })).toBe(true);
    expect(validStoredValues({ ...rpm, version: '' })).toBe(true);
    expect(validStoredValues({ ...rpm, version: '999999999:1-1' })).toBe(true);
  });

  it.each([
    ['a binary epoch that is not a number', { version: 'abc:1.0-1' }],
    ['a binary epoch Trivy cannot read as an int', { version: '9999999999:1.0-1' }],
    ['a source epoch that is not a number', { sourceVersion: 'x:1.0' }],
    ['a source epoch Trivy cannot read as an int', { sourceVersion: '99999999999:1.0-1' }],
    ['a control character in the name', { name: 'openssl\nlibs' }],
    ['a control character in the version', { version: '1.0\t-1' }],
    ['a C1 control character in the source name', { sourceName: 'open\u0085ssl' }],
    ['DEL in the source version', { sourceVersion: '1.0-1\u007f' }],
    ['a control character in the OS version', { osVersion: '8.10\r' }],
    ['an overlong name', { name: 'n'.repeat(513) }],
    ['an overlong version', { version: '1'.repeat(257) }],
    ['an overlong source name', { sourceName: 's'.repeat(513) }],
    ['an overlong source version', { sourceVersion: `1.0-${'1'.repeat(256)}` }],
    ['an overlong OS version', { osVersion: '8'.repeat(65) }],
  ] as const)('refuses %s, and the row gets no key', (_why, change) => {
    const row = { ...rpm, ...change };
    expect(validStoredValues(row)).toBe(false);
    expect(matchKeyOf(row)).toBeNull();
  });

  it('checks a library’s name and version too', () => {
    const npm: MatchKeyInput = {
      ecosystem: 'npm',
      name: 'left-pad',
      version: '1.3.0',
      osFamily: null,
      osVersion: null,
      sourceName: null,
      sourceVersion: null,
    };
    expect(validStoredValues(npm)).toBe(true);
    expect(validStoredValues({ ...npm, name: 'left\u0000pad' })).toBe(false);
    expect(matchKeyOf({ ...npm, version: '1.3.0\n' })).toBeNull();
    // An apk version has no epoch: a colon is only text.
    expect(
      validStoredValues({ ...rpm, ecosystem: 'apk', version: 'x:1-r0', sourceVersion: null }),
    ).toBe(true);
  });

  it('stays linear on a long hostile value', () => {
    const started = performance.now();
    expect(validStoredValues({ ...rpm, version: `${'1'.repeat(200_000)}:` })).toBe(false);
    expect(validStoredValues({ ...rpm, sourceName: '\u0001'.repeat(200_000) })).toBe(false);
    expect(performance.now() - started).toBeLessThan(500);
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
