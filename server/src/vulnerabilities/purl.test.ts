import { describe, expect, it } from 'vitest';
import { purlOf } from './purl';

describe('purlOf', () => {
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
});
