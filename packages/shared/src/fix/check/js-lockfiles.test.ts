import { describe, expect, it } from 'vitest';
import { checkJsLockfile, readNpmLock, readPnpmLock, readYarnLock } from './js-lockfiles';
import type { FixCheckContext, FixFileChange, LockEntry } from './types';

/** The `(name, version, kind)` and dependents of each entry, sorted. */
const shape = (entries: LockEntry[]) =>
  entries
    .map(({ name, version, kind, dependents }) => ({ name, version, kind, dependents }))
    .sort((a, b) => `${a.name}@${a.version}`.localeCompare(`${b.name}@${b.version}`));

const contextFor = (lockfile: string): FixCheckContext => ({
  family: 'js',
  packageName: 'qf-a',
  targets: [{ installed: '1.2.5', target: '1.2.6', lockfile }],
});

function check(path: string, base: string, next: string) {
  return checkJsLockfile({ path, base, next } satisfies FixFileChange, contextFor(path));
}

const NPM = 'https://registry.npmjs.org';

// ---------------------------------------------------------------------------------------------
// npm

function npmV3(qfA: Record<string, unknown>, extra: Record<string, unknown> = {}): string {
  const lock = {
    name: 'app',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': { name: 'app', version: '1.0.0', dependencies: { 'qf-b': '^2.0.0' } },
      'node_modules/qf-a': qfA,
      'node_modules/qf-b': {
        version: '2.0.0',
        resolved: `${NPM}/qf-b/-/qf-b-2.0.0.tgz`,
        integrity: 'sha512-bbb',
        dependencies: { 'qf-a': '^1.2.0' },
      },
      ...extra,
    },
  };
  return JSON.stringify(lock, null, 2) + '\n';
}

const npmQfA = (version: string, over: Record<string, unknown> = {}) => ({
  version,
  resolved: `${NPM}/qf-a/-/qf-a-${version}.tgz`,
  integrity: `sha512-a${version}`,
  ...over,
});

const NPM_V3_BASE = npmV3(npmQfA('1.2.5'));

function npmV1(qfA: Record<string, unknown>, extra: Record<string, unknown> = {}): string {
  const lock = {
    name: 'app',
    version: '1.0.0',
    lockfileVersion: 1,
    requires: true,
    dependencies: {
      'qf-a': qfA,
      'qf-b': {
        version: '2.0.0',
        resolved: `${NPM}/qf-b/-/qf-b-2.0.0.tgz`,
        integrity: 'sha512-bbb',
        requires: { 'qf-a': '^1.2.0', 'qf-c': '^3.0.0' },
        dependencies: {
          'qf-c': {
            version: '3.0.0',
            resolved: `${NPM}/qf-c/-/qf-c-3.0.0.tgz`,
            integrity: 'sha512-ccc',
          },
        },
      },
      ...extra,
    },
  };
  return JSON.stringify(lock, null, 2) + '\n';
}

const NPM_V1_BASE = npmV1(npmQfA('1.2.5'));

describe('readNpmLock', () => {
  it('reads lockfile v3 packages with dependents', () => {
    expect(shape(readNpmLock(NPM_V3_BASE))).toEqual([
      { name: 'qf-a', version: '1.2.5', kind: 'registry', dependents: ['qf-b'] },
      { name: 'qf-b', version: '2.0.0', kind: 'registry', dependents: [] },
    ]);
    const qfA = readNpmLock(NPM_V3_BASE).find((e) => e.name === 'qf-a');
    expect(qfA).toEqual({
      name: 'qf-a',
      version: '1.2.5',
      source: `${NPM}/qf-a/-/qf-a-1.2.5.tgz`,
      kind: 'registry',
      integrity: 'sha512-a1.2.5',
      dependents: ['qf-b'],
    });
  });

  it('reads the kind of each v3 entry: nested, alias, link, workspace, git, file and tarball', () => {
    const lock = npmV3(npmQfA('1.2.5'), {
      'node_modules/qf-b/node_modules/qf-a': npmQfA('2.0.1'),
      'node_modules/qf-alias': { ...npmQfA('1.2.5'), name: 'qf-a' },
      'node_modules/web': { resolved: 'packages/web', link: true },
      'packages/web': { name: 'web', version: '0.1.0', dependencies: { 'qf-a': '^1.0.0' } },
      'node_modules/qf-git': {
        version: '1.0.0',
        resolved: 'git+https://github.com/x/qf-git.git#abc',
      },
      'node_modules/qf-file': { version: '1.0.0', resolved: 'file:../qf-file-1.0.0.tgz' },
      'node_modules/qf-url': { version: '1.0.0', resolved: 'https://cdn.example/qf-url.tgz' },
    });
    expect(shape(readNpmLock(lock))).toEqual([
      { name: 'qf-a', version: '1.2.5', kind: 'registry', dependents: ['qf-b', 'web'] },
      { name: 'qf-a', version: '2.0.1', kind: 'registry', dependents: ['qf-b', 'web'] },
      { name: 'qf-b', version: '2.0.0', kind: 'registry', dependents: [] },
      { name: 'qf-file', version: '1.0.0', kind: 'file', dependents: [] },
      { name: 'qf-git', version: '1.0.0', kind: 'git', dependents: [] },
      { name: 'qf-url', version: '1.0.0', kind: 'tarball', dependents: [] },
      { name: 'web', version: '', kind: 'link', dependents: [] },
      { name: 'web', version: '0.1.0', kind: 'path', dependents: [] },
    ]);
  });

  it('reads lockfile v1 nested dependencies with dependents from requires', () => {
    const lock = npmV1(npmQfA('1.2.5'), {
      'qf-git': {
        version: 'git+https://github.com/x/qf-git.git#abc',
        from: 'git+https://github.com/x/qf-git.git',
      },
      'qf-file': { version: 'file:../qf-file' },
      'qf-url': { version: 'https://cdn.example/qf-url.tgz', integrity: 'sha512-u' },
    });
    expect(shape(readNpmLock(lock))).toEqual([
      { name: 'qf-a', version: '1.2.5', kind: 'registry', dependents: ['qf-b'] },
      { name: 'qf-b', version: '2.0.0', kind: 'registry', dependents: [] },
      { name: 'qf-c', version: '3.0.0', kind: 'registry', dependents: ['qf-b'] },
      { name: 'qf-file', version: 'file:../qf-file', kind: 'file', dependents: [] },
      {
        name: 'qf-git',
        version: 'git+https://github.com/x/qf-git.git#abc',
        kind: 'git',
        dependents: [],
      },
      {
        name: 'qf-url',
        version: 'https://cdn.example/qf-url.tgz',
        kind: 'tarball',
        dependents: [],
      },
    ]);
  });

  it('reads both sections of a v2 lockfile, once each', () => {
    const v3 = JSON.parse(NPM_V3_BASE) as Record<string, unknown>;
    const v1 = JSON.parse(NPM_V1_BASE) as Record<string, unknown>;
    const v2 = JSON.stringify({ ...v3, lockfileVersion: 2, dependencies: v1.dependencies });
    expect(shape(readNpmLock(v2)).map((e) => `${e.name}@${e.version}`)).toEqual([
      'qf-a@1.2.5',
      'qf-b@2.0.0',
      'qf-c@3.0.0',
    ]);
  });
});

describe('checkJsLockfile: npm', () => {
  it.each([
    ['package-lock.json v3', NPM_V3_BASE, npmV3(npmQfA('1.2.6'))],
    ['npm-shrinkwrap.json v1', NPM_V1_BASE, npmV1(npmQfA('1.2.6'))],
  ])('accepts the bump in %s', (_name, base, next) => {
    expect(check('package-lock.json', base, next)).toEqual({ ok: true });
    expect(check('apps/web/npm-shrinkwrap.json', base, next)).toEqual({ ok: true });
  });

  it.each([
    ['v3', NPM_V3_BASE, npmV3],
    ['v1', NPM_V1_BASE, npmV1],
  ] as const)('refuses a new host in %s (§11.8)', (_name, base, make) => {
    const evil = make(npmQfA('1.2.6', { resolved: 'https://evil.example/qf-a/-/qf-a-1.2.6.tgz' }));
    expect(check('package-lock.json', base, evil)).toEqual({
      ok: false,
      rule: 'new_source',
      path: 'package-lock.json',
    });
  });

  it('refuses a git+https entry', () => {
    const git = npmV3(npmQfA('1.2.6', { resolved: 'git+https://evil.example/qf-a.git#abc' }));
    expect(check('package-lock.json', NPM_V3_BASE, git)).toMatchObject({ rule: 'source_kind' });
    const v1 = npmV1({ version: 'git+https://evil.example/qf-a.git#abc' });
    expect(check('package-lock.json', NPM_V1_BASE, v1)).toMatchObject({ rule: 'source_kind' });
  });

  it('refuses a new entry without integrity in a v3 lockfile', () => {
    const bare = npmV3(npmQfA('1.2.6', { integrity: undefined }));
    expect(check('package-lock.json', NPM_V3_BASE, bare)).toMatchObject({
      rule: 'missing_integrity',
    });
  });

  it('refuses a lockfile that still holds the installed version', () => {
    const still = npmV3(npmQfA('1.2.6'), {
      'node_modules/qf-b/node_modules/qf-a': npmQfA('1.2.5'),
    });
    expect(check('package-lock.json', NPM_V3_BASE, still)).toEqual({
      ok: false,
      rule: 'below_target',
      path: 'package-lock.json',
    });
  });

  it('refuses a new version below the target of its own line (Ruling T3a)', () => {
    const ctx: FixCheckContext = {
      family: 'js',
      packageName: 'qf-a',
      targets: [
        { installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' },
        { installed: '2.0.1', target: '2.0.3', lockfile: 'package-lock.json' },
      ],
    };
    const base = npmV3(npmQfA('1.2.5'), {
      'node_modules/qf-b/node_modules/qf-a': npmQfA('2.0.1'),
    });
    const next = npmV3(npmQfA('1.2.6'), {
      'node_modules/qf-b/node_modules/qf-a': npmQfA('2.0.3'),
      'node_modules/qf-c/node_modules/qf-a': npmQfA('2.0.0'),
    });
    const change = { path: 'package-lock.json', base, next };
    expect(checkJsLockfile(change, ctx)).toEqual({
      ok: false,
      rule: 'below_target',
      path: 'package-lock.json',
    });
    const fixed = next.replaceAll('2.0.0', '2.0.4');
    expect(checkJsLockfile({ ...change, next: fixed }, ctx)).toEqual({ ok: true });
  });

  it('refuses a new tarball URL entry, even on a host the lockfile uses', () => {
    const tarball = npmV3(npmQfA('1.2.6', { resolved: `${NPM}/qf-a.tgz` }));
    expect(check('package-lock.json', NPM_V3_BASE, tarball)).toMatchObject({
      rule: 'source_kind',
    });
  });

  it('checks versions only against the targets of that lockfile (Ruling F14)', () => {
    const ctx = contextFor('other/package-lock.json');
    const change = { path: 'package-lock.json', base: NPM_V3_BASE, next: NPM_V3_BASE };
    expect(checkJsLockfile(change, ctx)).toEqual({ ok: true });
  });

  it('answers unparsable instead of throwing', () => {
    expect(check('package-lock.json', NPM_V3_BASE, '{"packages": ')).toMatchObject({
      rule: 'unparsable',
    });
    expect(
      check('package-lock.json', NPM_V3_BASE, '{"packages": {"node_modules/x": 1}}'),
    ).toMatchObject({
      rule: 'unparsable',
    });
    expect(check('package-lock.json', 'garbage', NPM_V3_BASE)).toMatchObject({
      rule: 'unparsable',
    });
  });

  it('refuses a file that is not a JS lockfile', () => {
    expect(check('package.json', NPM_V3_BASE, NPM_V3_BASE)).toMatchObject({ rule: 'other_change' });
  });
});

// ---------------------------------------------------------------------------------------------
// pnpm

const pnpmV6 = (qfA: string, extra = '') => `lockfileVersion: '6.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

dependencies:
  qf-b:
    specifier: ^2.0.0
    version: 2.0.0

packages:

  /qf-a@${qfA}:
    resolution: {integrity: sha512-a${qfA}}
    dev: false

  /qf-b@2.0.0(qf-peer@1.0.0):
    resolution: {integrity: sha512-bbb}
    peerDependencies:
      qf-peer: ^1.0.0
    dependencies:
      qf-a: ${qfA}
    dev: false
${extra}`;

const pnpmV9 = (qfA: string, packages = '', snapshots = '') => `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

importers:

  .:
    dependencies:
      qf-b:
        specifier: ^2.0.0
        version: 2.0.0

packages:

  qf-a@${qfA}:
    resolution: {integrity: sha512-a${qfA}}

  '@scope/qf-b@2.0.0':
    resolution: {integrity: sha512-bbb}
${packages}
snapshots:

  qf-a@${qfA}: {}

  '@scope/qf-b@2.0.0':
    dependencies:
      qf-a: ${qfA}
${snapshots}`;

describe('readPnpmLock', () => {
  it('reads v6 /name@version keys with peer suffixes, and dependents', () => {
    expect(shape(readPnpmLock(pnpmV6('1.2.5')))).toEqual([
      { name: 'qf-a', version: '1.2.5', kind: 'registry', dependents: ['qf-b'] },
      { name: 'qf-b', version: '2.0.0', kind: 'registry', dependents: [] },
    ]);
  });

  it('reads v5 /name/version keys', () => {
    const v5 = `lockfileVersion: 5.4

packages:

  /qf-a/1.2.5:
    resolution: {integrity: sha512-aaa}

  /@scope/qf-b/2.0.0_qf-peer@1.0.0:
    resolution: {integrity: sha512-bbb}
    dependencies:
      qf-a: 1.2.5
`;
    expect(shape(readPnpmLock(v5))).toEqual([
      { name: '@scope/qf-b', version: '2.0.0', kind: 'registry', dependents: [] },
      { name: 'qf-a', version: '1.2.5', kind: 'registry', dependents: ['@scope/qf-b'] },
    ]);
  });

  it('reads v9 name@version keys, dependents from snapshots, and the kind of each resolution', () => {
    const lock = pnpmV9(
      '1.2.5',
      `
  qf-git@https://codeload.github.com/x/qf-git/tar.gz/abc:
    resolution: {tarball: https://codeload.github.com/x/qf-git/tar.gz/abc}
    version: 1.0.0

  qf-repo@git+https://github.com/x/qf-repo.git#abc:
    resolution: {commit: abc, repo: https://github.com/x/qf-repo.git, type: git}
    version: 1.0.0

  qf-dir@file:../qf-dir:
    resolution: {directory: ../qf-dir, type: directory}
    version: 1.0.0

  qf-tgz@file:../qf-tgz.tgz:
    resolution: {integrity: sha512-t, tarball: file:../qf-tgz.tgz}
    version: 1.0.0
`,
    );
    const entries = readPnpmLock(lock);
    expect(shape(entries)).toEqual([
      { name: '@scope/qf-b', version: '2.0.0', kind: 'registry', dependents: [] },
      { name: 'qf-a', version: '1.2.5', kind: 'registry', dependents: ['@scope/qf-b'] },
      { name: 'qf-dir', version: '1.0.0', kind: 'path', dependents: [] },
      { name: 'qf-git', version: '1.0.0', kind: 'tarball', dependents: [] },
      { name: 'qf-repo', version: '1.0.0', kind: 'git', dependents: [] },
      { name: 'qf-tgz', version: '1.0.0', kind: 'file', dependents: [] },
    ]);
    expect(entries.find((e) => e.name === 'qf-a')).toMatchObject({
      source: null,
      integrity: 'sha512-a1.2.5',
    });
    expect(entries.find((e) => e.name === 'qf-repo')?.source).toBe(
      'https://github.com/x/qf-repo.git',
    );
  });

  it('reads the linked direct dependencies of importers and of a single-project lockfile', () => {
    const v9 = pnpmV9('1.2.5').replace(
      'importers:\n\n  .:\n',
      'importers:\n\n  apps/web:\n    dependencies:\n      lib:\n        specifier: workspace:*\n        version: link:../../packages/lib\n\n  .:\n',
    );
    const links = (lock: string) =>
      readPnpmLock(lock)
        .filter((e) => e.kind === 'link')
        .map((e) => [e.name, e.source]);
    expect(links(v9)).toEqual([['lib', 'link:../../packages/lib']]);
    const v6 = pnpmV6('1.2.5').replace(
      'dependencies:\n  qf-b:',
      'dependencies:\n  qf-local:\n    specifier: link:../qf-local\n    version: link:../qf-local\n  qf-b:',
    );
    expect(links(v6)).toEqual([['qf-local', 'link:../qf-local']]);
  });
});

describe('checkJsLockfile: pnpm', () => {
  it('refuses a direct dependency the lockfile alone turns into a link', () => {
    const linked = pnpmV9('1.2.6').replace(
      '        specifier: ^2.0.0\n        version: 2.0.0',
      '        specifier: ^2.0.0\n        version: link:../evil',
    );
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), linked)).toMatchObject({
      rule: 'source_kind',
    });
  });

  it.each([
    ['v6', pnpmV6('1.2.5'), pnpmV6('1.2.6')],
    ['v9', pnpmV9('1.2.5'), pnpmV9('1.2.6')],
  ])('accepts the bump in %s', (_name, base, next) => {
    expect(check('pnpm-lock.yaml', base, next)).toEqual({ ok: true });
  });

  it('refuses a tarball or git resolution of the package', () => {
    const tarball = pnpmV9('1.2.5').replace(
      'resolution: {integrity: sha512-a1.2.5}',
      'resolution: {integrity: sha512-x, tarball: https://evil.example/qf-a-1.2.5.tgz}',
    );
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), tarball)).toMatchObject({
      rule: 'source_kind',
    });
    const git = pnpmV6('1.2.6').replace(
      'resolution: {integrity: sha512-a1.2.6}',
      'resolution: {commit: abc, repo: git+https://evil.example/qf-a.git, type: git}',
    );
    expect(check('pnpm-lock.yaml', pnpmV6('1.2.5'), git)).toMatchObject({ rule: 'source_kind' });
  });

  it('applies merge keys as pnpm’s YAML reader does', () => {
    const merged = pnpmV9('1.2.6').replace(
      'resolution: {integrity: sha512-a1.2.6}',
      'resolution: {integrity: sha512-x, <<: {tarball: https://evil.example/qf-a.tgz}}',
    );
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), merged)).toMatchObject({
      rule: 'source_kind',
    });
  });

  it('refuses a lockfile that still holds the installed version', () => {
    const still = pnpmV9(
      '1.2.6',
      '\n  qf-a@1.2.5:\n    resolution: {integrity: sha512-a1.2.5}\n',
      '\n  qf-a@1.2.5: {}\n',
    );
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), still)).toMatchObject({
      rule: 'below_target',
    });
  });

  it('answers unparsable instead of throwing', () => {
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), 'packages: [')).toMatchObject({
      rule: 'unparsable',
    });
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), 'packages: {}\n')).toMatchObject({
      rule: 'unparsable',
    });
  });
});

// ---------------------------------------------------------------------------------------------
// Yarn

const yarnClassic = (
  qfA: string,
  resolved = `https://registry.yarnpkg.com/qf-a/-/qf-a-${qfA}.tgz#0a1b`,
) =>
  `# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.
# yarn lockfile v1


"@scope/qf-b@^2.0.0":
  version "2.0.0"
  resolved "https://registry.yarnpkg.com/@scope/qf-b/-/qf-b-2.0.0.tgz#2c3d"
  integrity sha512-bbb
  dependencies:
    qf-a "^1.2.0"
    "@scope/qf-c" "^3.0.0"

qf-a@^1.2.0, qf-a@^1.2.5:
  version "${qfA}"
  resolved "${resolved}"
  integrity sha512-a${qfA}
`;

describe('readYarnLock: classic', () => {
  it('reads blocks with their patterns, fields and dependents', () => {
    expect(shape(readYarnLock(yarnClassic('1.2.5')))).toEqual([
      { name: '@scope/qf-b', version: '2.0.0', kind: 'registry', dependents: [] },
      { name: 'qf-a', version: '1.2.5', kind: 'registry', dependents: ['@scope/qf-b'] },
    ]);
  });

  it('reads aliases by their package and the kind of each source', () => {
    const lock = `# yarn lockfile v1

"string-width-cjs@npm:string-width@^4.2.0", string-width@^4.1.0:
  version "4.2.3"
  resolved "https://registry.yarnpkg.com/string-width/-/string-width-4.2.3.tgz#2c3d"
  integrity sha512-s

"qf-dir@file:../qf-dir":
  version "1.0.0"

qf-git@x/qf-git:
  version "1.0.0"
  resolved "https://codeload.github.com/x/qf-git/tar.gz/abc"

"qf-repo@git+https://github.com/x/qf-repo.git":
  version "1.0.0"
  resolved "git+https://github.com/x/qf-repo.git#abc"

"qf-link@link:../qf-link":
  version "0.0.0"
  uid ""
`;
    expect(shape(readYarnLock(lock))).toEqual([
      { name: 'qf-dir', version: '1.0.0', kind: 'file', dependents: [] },
      { name: 'qf-git', version: '1.0.0', kind: 'git', dependents: [] },
      { name: 'qf-link', version: '0.0.0', kind: 'link', dependents: [] },
      { name: 'qf-repo', version: '1.0.0', kind: 'git', dependents: [] },
      { name: 'string-width', version: '4.2.3', kind: 'registry', dependents: [] },
    ]);
  });

  it('breaks lines at a lone carriage return, as Yarn does', () => {
    const cr = yarnClassic('1.2.5').replaceAll('\n', '\r');
    expect(shape(readYarnLock(cr))).toEqual(shape(readYarnLock(yarnClassic('1.2.5'))));
  });

  it.each([
    ['a duplicate field', yarnClassic('1.2.6') + '  resolved "https://evil.example/x.tgz"\n'],
    ['a field after a lone CR', yarnClassic('1.2.6').trimEnd() + '\r  resolved "https://evil"\n'],
    ['a tab indent', yarnClassic('1.2.6') + '\tresolved "https://evil.example/x.tgz"\n'],
    ['an odd indent', yarnClassic('1.2.6') + '   resolved "https://evil.example/x.tgz"\n'],
    ['a value with a comment', yarnClassic('1.2.6') + '  uid "x" # y\n'],
    ['a field outside a block', '# yarn lockfile v1\n\n  version "1.0.0"\n'],
    ['a header without colon', '# yarn lockfile v1\n\nqf-a@^1.0.0\n  version "1.0.0"\n'],
    ['a value after a colon', '# yarn lockfile v1\n\nqf-a@^1.0.0:\n  version: "1.0.0"\n'],
    [
      'a block without version',
      '# yarn lockfile v1\n\nqf-a@^1.0.0:\n  resolved "https://registry.yarnpkg.com/qf-a/-/qf-a-1.0.0.tgz"\n',
    ],
  ])('refuses %s', (_name, lock) => {
    expect(() => readYarnLock(lock)).toThrow();
  });
});

const BERRY_HEAD = `# This file is generated by running "yarn install" inside your project.
# Manual changes might be lost - proceed with caution!

__metadata:
  version: 8
  cacheKey: 10c0

"app@workspace:.":
  version: 0.0.0-use.local
  resolution: "app@workspace:."
  dependencies:
    qf-b: "npm:^2.0.0"
    typescript: "patch:typescript@npm%3A^5.6.3#optional!builtin<compat/typescript>"
  languageName: unknown
  linkType: soft

"qf-b@npm:^2.0.0":
  version: 2.0.0
  resolution: "qf-b@npm:2.0.0"
  dependencies:
    qf-a: "npm:^1.2.0"
  checksum: 10c0/bbb
  languageName: node
  linkType: hard
`;

const berry = (qfA: string, resolution = `qf-a@npm:${qfA}`, extra = '') => `${BERRY_HEAD}
"qf-a@npm:^1.2.0":
  version: ${qfA}
  resolution: "${resolution}"
  checksum: 10c0/a${qfA}
  languageName: node
  linkType: hard
${extra}`;

const TYPESCRIPT = `
"typescript@npm:^5.6.3":
  version: 5.6.3
  resolution: "typescript@npm:5.6.3"
  bin:
    tsc: bin/tsc
    tsserver: bin/tsserver
  checksum: 10c0/ts
  languageName: node
  linkType: hard
`;

const TYPESCRIPT_PATCH = `
"typescript@patch:typescript@npm%3A^5.6.3#optional!builtin<compat/typescript>":
  version: 5.6.3
  resolution: "typescript@patch:typescript@npm%3A5.6.3#optional!builtin<compat/typescript>::version=5.6.3&hash=8c6c40"
  bin:
    tsc: bin/tsc
    tsserver: bin/tsserver
  checksum: 10c0/ttt
  languageName: node
  linkType: hard
`;

describe('readYarnLock: Berry', () => {
  it('reads entries from their resolution, with dependents', () => {
    expect(shape(readYarnLock(berry('1.2.5')))).toEqual([
      { name: 'app', version: '0.0.0-use.local', kind: 'path', dependents: [] },
      { name: 'qf-a', version: '1.2.5', kind: 'registry', dependents: ['qf-b'] },
      { name: 'qf-b', version: '2.0.0', kind: 'registry', dependents: ['app'] },
    ]);
    expect(readYarnLock(berry('1.2.5')).find((e) => e.name === 'qf-a')).toMatchObject({
      source: 'npm:1.2.5',
      integrity: '10c0/a1.2.5',
    });
  });

  it.each([
    ['qf-a@https://evil.example/qf-a.tgz', 'tarball'],
    ['qf-a@https://github.com/x/qf-a.git#commit=abc', 'git'],
    ['qf-a@git+ssh://git@github.com/x/qf-a.git#commit=abc', 'git'],
    ['qf-a@file:../qf-a#../qf-a::hash=1&locator=app%40workspace%3A.', 'file'],
    ['qf-a@link:../qf-a::locator=app%40workspace%3A.', 'link'],
    ['qf-a@portal:../qf-a::locator=app%40workspace%3A.', 'link'],
    ['qf-a@exec:./gen.js::locator=app%40workspace%3A.', 'other'],
    ['qf-a@patch:qf-a@npm%3A1.2.5#~/.yarn/patches/qf-a.patch::version=1.2.5&hash=1', 'file'],
    ['qf-a@patch:qf-a@https%3A//evil.example/a.tgz#optional!builtin<compat/qf-a>', 'other'],
  ])('reads the kind of %s as %s', (resolution, kind) => {
    const entry = readYarnLock(berry('1.2.5', resolution)).find((e) => e.name === 'qf-a');
    expect(entry?.kind).toBe(kind);
  });

  it('takes the version of an npm resolution from the resolution', () => {
    const lying = berry('1.2.6', 'qf-a@npm:1.2.5');
    expect(readYarnLock(lying).find((e) => e.name === 'qf-a')?.version).toBe('1.2.5');
  });
});

describe('checkJsLockfile: Yarn', () => {
  it.each([
    ['classic', yarnClassic('1.2.5'), yarnClassic('1.2.6')],
    ['Berry', berry('1.2.5'), berry('1.2.6')],
  ])('accepts the bump in %s', (_name, base, next) => {
    expect(check('yarn.lock', base, next)).toEqual({ ok: true });
  });

  it('reads through CRLF line endings and a BOM', () => {
    const crlf = (text: string) => '﻿' + text.replaceAll('\n', '\r\n');
    expect(check('yarn.lock', crlf(yarnClassic('1.2.5')), crlf(yarnClassic('1.2.6')))).toEqual({
      ok: true,
    });
    expect(check('yarn.lock', crlf(berry('1.2.5')), crlf(berry('1.2.6')))).toEqual({ ok: true });
  });

  it('refuses a new host in classic (§11.8)', () => {
    const evil = yarnClassic('1.2.6', 'https://evil.example/qf-a/-/qf-a-1.2.6.tgz');
    expect(check('yarn.lock', yarnClassic('1.2.5'), evil)).toEqual({
      ok: false,
      rule: 'new_source',
      path: 'yarn.lock',
    });
  });

  it('refuses a new host in a Berry archive URL', () => {
    const archive = encodeURIComponent('https://evil.example/qf-a/-/qf-a-1.2.6.tgz');
    const evil = berry('1.2.6', `qf-a@npm:1.2.6::__archiveUrl=${archive}`);
    expect(check('yarn.lock', berry('1.2.5'), evil)).toMatchObject({ rule: 'new_source' });
    const twice = berry('1.2.6', `qf-a@npm:1.2.6::__archiveUrl=${archive}&__archiveUrl=${archive}`);
    expect(check('yarn.lock', berry('1.2.5'), twice)).toMatchObject({ rule: 'unparsable' });
  });

  it('refuses git+https and tarball sources', () => {
    const classic = yarnClassic('1.2.6', 'git+https://evil.example/qf-a.git#abc');
    expect(check('yarn.lock', yarnClassic('1.2.5'), classic)).toMatchObject({
      rule: 'source_kind',
    });
    const berryGit = berry('1.2.6', 'qf-a@git+https://evil.example/qf-a.git#commit=abc');
    expect(check('yarn.lock', berry('1.2.5'), berryGit)).toMatchObject({ rule: 'source_kind' });
    const berryTarball = berry('1.2.6', 'qf-a@https://evil.example/qf-a.tgz');
    expect(check('yarn.lock', berry('1.2.5'), berryTarball)).toMatchObject({
      rule: 'source_kind',
    });
  });

  it('accepts an added Berry builtin compat patch', () => {
    const base = berry('1.2.5', undefined, TYPESCRIPT);
    const next = berry('1.2.6', undefined, TYPESCRIPT + TYPESCRIPT_PATCH);
    expect(check('yarn.lock', base, next)).toEqual({ ok: true });
    const bare = next.replace('  checksum: 10c0/ttt\n', '');
    expect(check('yarn.lock', base, bare)).toMatchObject({ rule: 'missing_integrity' });
    const patch = readYarnLock(next).filter((e) => e.name === 'typescript');
    expect(patch.map((e) => [e.version, e.kind, e.integrity])).toEqual([
      ['5.6.3', 'registry', '10c0/ts'],
      ['5.6.3', 'registry', '10c0/ttt'],
    ]);
  });

  it('refuses a lockfile that still holds the installed version', () => {
    const still =
      yarnClassic('1.2.6') +
      `
qf-a@~1.2.0:
  version "1.2.5"
  resolved "https://registry.yarnpkg.com/qf-a/-/qf-a-1.2.5.tgz#0a1b"
  integrity sha512-a1.2.5
`;
    expect(check('yarn.lock', yarnClassic('1.2.5'), still)).toMatchObject({
      rule: 'below_target',
    });
    expect(check('yarn.lock', berry('1.2.5'), berry('1.2.5'))).toMatchObject({
      rule: 'below_target',
    });
  });

  it('answers unparsable instead of throwing', () => {
    expect(check('yarn.lock', berry('1.2.5'), 'a: [')).toMatchObject({ rule: 'unparsable' });
    expect(check('yarn.lock', berry('1.2.5'), 'a: 1\n')).toMatchObject({ rule: 'unparsable' });
    const dup = berry('1.2.6') + '\n"qf-a@npm:^1.2.0":\n  version: 1.2.6\n';
    expect(check('yarn.lock', berry('1.2.5'), dup)).toMatchObject({ rule: 'unparsable' });
  });
});
