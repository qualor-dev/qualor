import { describe, expect, it } from 'vitest';
import { FIX_LIMITS } from '../families';
import {
  checkJsLockfile,
  jsLockfileAdditions,
  readNpmLock,
  readPnpmLock,
  readYarnLock,
} from './js-lockfiles';
import { withDependents } from './lock-read';
import { parseYaml } from './values';
import type { FixCheckContext, FixFileChange, LockEntry } from './types';

/** The `(name, version, kind)`, alias slot and dependents of each entry, sorted. */
const shape = (entries: LockEntry[]) =>
  entries
    .map(({ name, version, kind, dependents, slot }) => ({
      name,
      version,
      kind,
      dependents,
      ...(slot === undefined ? {} : { slot }),
    }))
    .sort((a, b) =>
      `${a.name}@${a.version}@${a.slot ?? ''}`.localeCompare(
        `${b.name}@${b.version}@${b.slot ?? ''}`,
      ),
    );

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
      dependencies: [],
      dependents: ['qf-b'],
    });
    const qfB = readNpmLock(NPM_V3_BASE).find((e) => e.name === 'qf-b');
    expect(qfB?.dependencies).toEqual(['qf-a']);
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
      { name: 'qf-a', version: '1.2.5', kind: 'registry', dependents: [], slot: 'qf-alias' },
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
    const fixed = npmV3(npmQfA('1.2.6'), {
      'node_modules/qf-b/node_modules/qf-a': npmQfA('2.0.3'),
      'node_modules/qf-c/node_modules/qf-a': npmQfA('2.0.4'),
    });
    expect(checkJsLockfile({ ...change, next: fixed }, ctx)).toEqual({ ok: true });
  });

  it.each([
    ['another package', `${NPM}/evil/-/evil-6.6.6.tgz`],
    ['another version', `${NPM}/qf-a/-/qf-a-1.2.5.tgz`],
    ['the name only in a prefix', `${NPM}/qf-a/-/x/evil/-/evil-1.2.6.tgz`],
  ])('refuses a resolved URL that names %s (Ruling T3b)', (_name, resolved) => {
    const evil = npmV3(npmQfA('1.2.6', { resolved, integrity: 'sha512-evil' }));
    expect(check('package-lock.json', NPM_V3_BASE, evil)).toMatchObject({
      rule: 'source_kind',
    });
  });

  it.each([
    ['a scoped package', `${NPM}/@scope/qf-d/-/qf-d-1.0.0.tgz`],
    ['a scoped package with %2F', `${NPM}/@scope%2Fqf-d/-/qf-d-1.0.0.tgz`],
    ['a scoped package with %2f', `${NPM}/@scope%2fqf-d/-/qf-d-1.0.0.tgz`],
  ])('accepts %s on the registry (Ruling T3b)', (_name, resolved) => {
    const added = { version: '1.0.0', resolved, integrity: 'sha512-d' };
    const qfA = npmQfA('1.2.6', { dependencies: { '@scope/qf-d': '^1.0.0' } });
    const next = npmV3(qfA, { 'node_modules/@scope/qf-d': added });
    expect(check('package-lock.json', NPM_V3_BASE, next)).toEqual({ ok: true });
  });

  it('accepts an alias the base already has, by its real name (Ruling T3b, C1)', () => {
    const qfD = (v: string) => ({
      name: 'qf-d',
      version: v,
      resolved: `${NPM}/qf-d/-/qf-d-${v}.tgz`,
      integrity: `sha512-d${v}`,
    });
    const at = (a: string, d: string) =>
      npmV3(npmQfA(a, { dependencies: { 'qf-alias': 'npm:qf-d@^0.9.0' } }), {
        'node_modules/qf-alias': qfD(d),
      });
    expect(check('package-lock.json', at('1.2.5', '0.9.0'), at('1.2.6', '0.9.1'))).toEqual({
      ok: true,
    });
  });

  it.each([
    ['backslashes', 'https:\\\\evil.example/qf-a/-/qf-a-1.2.6.tgz'],
    ['one slash', 'https:/evil.example/qf-a/-/qf-a-1.2.6.tgz'],
    ['no slashes', 'https:evil.example/qf-a/-/qf-a-1.2.6.tgz'],
    ['a leading space', ' https://evil.example/qf-a/-/qf-a-1.2.6.tgz'],
    ['a tab in the host', 'https://registry.npm\tjs.org.evil.example/qf-a/-/qf-a-1.2.6.tgz'],
  ])('reads a resolved URL with %s as a URL does (Ruling T3c)', (_name, resolved) => {
    const evil = npmV3(npmQfA('1.2.6', { resolved }));
    expect(check('package-lock.json', NPM_V3_BASE, evil)).toMatchObject({ rule: 'new_source' });
  });

  it('accepts a registry path prefix, as Artifactory and Verdaccio write it (Ruling T3b)', () => {
    const prefix = 'https://artifactory.example/artifactory/api/npm/npm-remote';
    const at = (version: string) =>
      npmQfA(version, { resolved: `${prefix}/qf-a/-/qf-a-${version}.tgz` });
    expect(check('package-lock.json', npmV3(at('1.2.5')), npmV3(at('1.2.6')))).toEqual({
      ok: true,
    });
  });

  it('reads a v1 alias by its real name and version', () => {
    const alias = {
      version: 'npm:string-width@4.2.3',
      resolved: `${NPM}/string-width/-/string-width-4.2.3.tgz`,
      integrity: 'sha512-s',
    };
    const entries = readNpmLock(npmV1(npmQfA('1.2.5'), { 'string-width-cjs': alias }));
    expect(entries.find((e) => e.integrity === 'sha512-s')).toMatchObject({
      slot: 'string-width-cjs',
      name: 'string-width',
      version: '4.2.3',
      kind: 'registry',
    });
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
  it('reads a registry entry by its key, as pnpm installs it (Ruling T3b)', () => {
    const lying = pnpmV9('1.2.5').replace(
      'resolution: {integrity: sha512-a1.2.5}',
      'resolution: {integrity: sha512-a1.2.5}\n    version: 1.2.6',
    );
    expect(readPnpmLock(lying).find((e) => e.name === 'qf-a')).toMatchObject({
      version: '1.2.5',
      kind: 'other',
    });
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), lying)).toMatchObject({
      rule: 'source_kind',
    });
    const renamed = pnpmV9('1.2.6').replace(
      'resolution: {integrity: sha512-a1.2.6}',
      'resolution: {integrity: sha512-a1.2.6}\n    name: qf-other',
    );
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), renamed)).toMatchObject({
      rule: 'source_kind',
    });
  });

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

  it('refuses a merge key, which pnpm never writes (Ruling T3o)', () => {
    const merged = pnpmV9('1.2.6').replace(
      'resolution: {integrity: sha512-a1.2.6}',
      'resolution: {integrity: sha512-x, <<: {tarball: https://evil.example/qf-a.tgz}}',
    );
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), merged)).toMatchObject({
      rule: 'unparsable',
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
      {
        name: 'string-width',
        version: '4.2.3',
        kind: 'registry',
        dependents: [],
        slot: 'string-width-cjs',
      },
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

const typescript = (v: string) => `
"typescript@npm:^5.6.2":
  version: ${v}
  resolution: "typescript@npm:${v}"
  bin:
    tsc: bin/tsc
    tsserver: bin/tsserver
  checksum: 10c0/ts${v}
  languageName: node
  linkType: hard
`;

const typescriptPatch = (v: string, patched = `typescript@npm%3A${v}`) => `
"typescript@patch:typescript@npm%3A^5.6.2#optional!builtin<compat/typescript>":
  version: ${v}
  resolution: "typescript@patch:${patched}#optional!builtin<compat/typescript>::version=${v}&hash=8c6c40"
  bin:
    tsc: bin/tsc
    tsserver: bin/tsserver
  checksum: 10c0/patched${v}
  languageName: node
  linkType: hard
`;

const TS: FixCheckContext = {
  family: 'js',
  packageName: 'typescript',
  targets: [{ installed: '5.6.2', target: '5.6.3', lockfile: 'yarn.lock' }],
};

describe('readYarnLock: Berry', () => {
  it('reads entries from their resolution, with dependents', () => {
    expect(shape(readYarnLock(berry('1.2.5')))).toEqual([
      { name: 'app', version: '0.0.0-use.local', kind: 'path', dependents: [] },
      { name: 'qf-a', version: '1.2.5', kind: 'registry', dependents: ['qf-b'] },
      { name: 'qf-b', version: '2.0.0', kind: 'registry', dependents: ['app'] },
    ]);
    expect(readYarnLock(berry('1.2.5')).find((e) => e.name === 'qf-a')).toMatchObject({
      source: null,
      integrity: '10c0/a1.2.5',
    });
  });

  it('reads an archive URL as the source, and refuses one that does not parse', () => {
    const archive = encodeURIComponent('https://npm.example/qf-a/-/qf-a-1.2.5.tgz');
    const custom = berry('1.2.5', `qf-a@npm:1.2.5::__archiveUrl=${archive}`);
    expect(readYarnLock(custom).find((e) => e.name === 'qf-a')?.source).toBe(
      'https://npm.example/qf-a/-/qf-a-1.2.5.tgz',
    );
    expect(() => readYarnLock(berry('1.2.5', 'qf-a@npm:1.2.5::__archiveUrl=not-a-url'))).toThrow();
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
    const crlf = (text: string) => '\uFEFF' + text.replaceAll('\n', '\r\n');
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

  it('refuses a classic resolved URL that names another package (Ruling T3b)', () => {
    const evil = yarnClassic('1.2.6', 'https://registry.yarnpkg.com/evil/-/evil-6.6.6.tgz#0a1b');
    expect(check('yarn.lock', yarnClassic('1.2.5'), evil)).toMatchObject({
      rule: 'source_kind',
    });
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

  it('accepts a Berry builtin compat patch of the package, bumped with it', () => {
    const lock = (v: string) => berry('1.2.5', undefined, typescript(v) + typescriptPatch(v));
    const change = { path: 'yarn.lock', base: lock('5.6.2'), next: lock('5.6.3') };
    expect(checkJsLockfile(change, TS)).toEqual({ ok: true });
    const bare = { ...change, next: change.next.replace('  checksum: 10c0/patched5.6.3\n', '') };
    expect(checkJsLockfile(bare, TS)).toMatchObject({ rule: 'missing_integrity' });
    const patch = readYarnLock(change.next).filter((e) => e.name === 'typescript');
    expect(patch.map((e) => [e.version, e.kind, e.integrity])).toEqual([
      ['5.6.3', 'registry', '10c0/ts5.6.3'],
      ['5.6.3', 'registry', '10c0/patched5.6.3'],
    ]);
  });

  it.each([
    ['another package', 'evil@npm%3A5.6.3'],
    ['another version', 'typescript@npm%3A5.6.4'],
  ])('refuses a builtin patch of %s (C2)', (_name, patched) => {
    const base = berry('1.2.5', undefined, typescript('5.6.2') + typescriptPatch('5.6.2'));
    const next = berry('1.2.5', undefined, typescript('5.6.3') + typescriptPatch('5.6.3', patched));
    expect(checkJsLockfile({ path: 'yarn.lock', base, next }, TS)).toMatchObject({
      rule: 'source_kind',
    });
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

// ---------------------------------------------------------------------------------------------
// Fix round 1 (task-3-fix-1.md): the reviewer's probes, and Rulings T3e and T3f

const evilNpm = (version: string) => ({
  version,
  resolved: `${NPM}/evil/-/evil-${version}.tgz`,
  integrity: `sha512-evil${version}`,
});

describe('fix round 1: another package in the package’s slot (C1)', () => {
  it('refuses npm v3 and v1 entries that put another package in the slot', () => {
    const v3 = npmV3({ ...evilNpm('1.2.6'), name: 'evil' });
    expect(check('package-lock.json', NPM_V3_BASE, v3)).toMatchObject({ rule: 'source_kind' });
    const v1 = npmV1({ ...evilNpm('1.2.6'), version: 'npm:evil@1.2.6' });
    expect(check('package-lock.json', NPM_V1_BASE, v1)).toMatchObject({ rule: 'source_kind' });
  });

  it('refuses a Berry descriptor of the package resolved to another package', () => {
    const next = berry('1.2.6', 'evil@npm:1.2.6');
    expect(check('yarn.lock', berry('1.2.5'), next)).toMatchObject({ rule: 'source_kind' });
  });

  it('refuses a pnpm importer or snapshot reference to another package', () => {
    const lock = (ref: string, pkg: string) => `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      qf-a:
        specifier: ^1.2.5
        version: ${ref}

packages:

  ${pkg}:
    resolution: {integrity: sha512-${pkg}}

snapshots:

  ${pkg}: {}
`;
    const importer = lock('evil@1.2.6', 'evil@1.2.6');
    expect(check('pnpm-lock.yaml', lock('1.2.5', 'qf-a@1.2.5'), importer)).toMatchObject({
      rule: 'source_kind',
    });
    const evil = '\n  evil@1.2.6:\n    resolution: {integrity: sha512-e}\n';
    const snapshot = pnpmV9('1.2.6', evil, '\n  evil@1.2.6: {}\n').replace(
      '      qf-a: 1.2.6\n',
      '      qf-a: evil@1.2.6\n',
    );
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), snapshot)).toMatchObject({
      rule: 'source_kind',
    });
  });

  it('refuses a Yarn classic alias pattern the base does not have', () => {
    const alias = `${yarnClassic('1.2.6')}
"qf-a@npm:evil@^1.2.6":
  version "1.2.6"
  resolved "https://registry.yarnpkg.com/evil/-/evil-1.2.6.tgz#1"
  integrity sha512-e
`;
    expect(check('yarn.lock', yarnClassic('1.2.5'), alias)).toMatchObject({
      rule: 'source_kind',
    });
  });
});

describe('fix round 1: Berry archive URLs and patches name the entry (C2)', () => {
  it('refuses an archive URL that names another package', () => {
    const archive = encodeURIComponent('https://registry.yarnpkg.com/evil/-/evil-6.6.6.tgz');
    const next = berry('1.2.6', `qf-a@npm:1.2.6::__archiveUrl=${archive}`);
    expect(check('yarn.lock', berry('1.2.5'), next)).toMatchObject({ rule: 'source_kind' });
  });

  it('accepts an archive URL of the package itself on a public registry', () => {
    const archive = encodeURIComponent('https://registry.yarnpkg.com/qf-a/-/qf-a-1.2.6.tgz');
    const next = berry('1.2.6', `qf-a@npm:1.2.6::__archiveUrl=${archive}`);
    expect(check('yarn.lock', berry('1.2.5'), next)).toEqual({ ok: true });
  });

  it('refuses a builtin patch of another package in the package’s entry', () => {
    const next = berry('1.2.6', 'qf-a@patch:evil@npm%3A1.2.6#optional!builtin<compat/typescript>');
    expect(check('yarn.lock', berry('1.2.5'), next)).toMatchObject({ rule: 'source_kind' });
  });
});

describe('fix round 1: a raw host with %, user info or other characters (C3)', () => {
  const at = (host: string) => `https://${host}/qf-a/-/qf-a-1.2.6.tgz`;
  const char = (code: number) => String.fromCharCode(code);

  it.each([
    ['a percent-encoded host', at('registry.yarnpkg.co%6D')],
    ['user info', at('registry.npmjs.org@registry.yarnpkg.com')],
    ['an IDN host', at(`r${char(0x435)}gistry.yarnpkg.com`)],
  ])('refuses %s', (_name, resolved) => {
    expect(check('yarn.lock', yarnClassic('1.2.5'), yarnClassic('1.2.6', resolved))).toEqual({
      ok: false,
      rule: 'new_source',
      path: 'yarn.lock',
    });
  });

  it.each([
    at('registry.yarnpkg.co%6d'),
    at('registry%2Eyarnpkg%2Ecom'),
    at(`registry.yarnpkg.com${char(0xff0e)}`),
    at(`registry${char(0xff0e)}yarnpkg${char(0xff0e)}com`),
    at(`registry.yarnpkg.com${char(0xad)}`),
    at(`evil.example${char(9)}@registry.yarnpkg.com`),
    at('registry.yarnpkg.com;.evil.example'),
  ])('refuses the reviewer’s probe %j', (resolved) => {
    expect(check('yarn.lock', yarnClassic('1.2.5'), yarnClassic('1.2.6', resolved)).ok).toBe(false);
  });
});

describe('fix round 1: the lockfile keeps the base’s format (C4)', () => {
  it('refuses a classic base with a Berry-shaped next', () => {
    const next = `"__metadata":
  version: "8"

"qf-a@^1.2.5":
  version: "1.2.6"
  resolution: "qf-a@npm:1.2.6"
  checksum: "10c0/evil"
`;
    expect(check('yarn.lock', yarnClassic('1.2.5'), next)).toMatchObject({ rule: 'unparsable' });
  });

  it.each(['resolved: "https://evil.example/x.tgz"', 'integrity: sha512-evil'])(
    'refuses a Berry entry with %s',
    (field) => {
      const next = berry('1.2.6').replace(
        '  checksum: 10c0/a1.2.6\n',
        `  checksum: 10c0/a1.2.6\n  ${field}\n`,
      );
      expect(() => readYarnLock(next)).toThrow();
      expect(check('yarn.lock', berry('1.2.5'), next)).toMatchObject({ rule: 'unparsable' });
    },
  );

  it('refuses a changed lockfile version (npm, pnpm, Berry)', () => {
    const v2 = NPM_V3_BASE.replace('"lockfileVersion": 3', '"lockfileVersion": 2');
    expect(check('package-lock.json', NPM_V3_BASE, v2)).toMatchObject({ rule: 'unparsable' });
    expect(check('pnpm-lock.yaml', pnpmV6('1.2.5'), pnpmV9('1.2.6'))).toMatchObject({
      rule: 'unparsable',
    });
    const berry6 = berry('1.2.6').replace('  version: 8\n', '  version: 6\n');
    expect(check('yarn.lock', berry('1.2.5'), berry6)).toMatchObject({ rule: 'unparsable' });
  });
});

describe('fix round 1: YAML in linear time (I1)', () => {
  const big = (qfA: string) => {
    const packages: string[] = [];
    const snapshots: string[] = [];
    for (let i = 0; i < 20_000; i++) {
      packages.push(`\n  pkg-${i}@1.0.${i}:\n    resolution: {integrity: sha512-p${i}}\n`);
      snapshots.push(`\n  pkg-${i}@1.0.${i}:\n    dependencies:\n      qf-a: ${qfA}\n`);
    }
    return pnpmV9(qfA, packages.join(''), snapshots.join(''));
  };

  it('checks a pnpm-lock.yaml of 20 000 packages in well under 3 s', { timeout: 60_000 }, () => {
    const [base, next] = [big('1.2.5'), big('1.2.6')];
    const started = performance.now();
    expect(check('pnpm-lock.yaml', base, next)).toEqual({ ok: true });
    expect(performance.now() - started).toBeLessThan(3000);
  });

  it('still refuses a duplicate key, also one written once as a number', () => {
    const dup = pnpmV9('1.2.6') + '\n  qf-a@1.2.6: {}\n';
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), dup)).toMatchObject({ rule: 'unparsable' });
    const numbered = pnpmV9('1.2.6').replace('settings:\n', "settings:\n  1: a\n  '1': b\n");
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), numbered)).toMatchObject({
      rule: 'unparsable',
    });
  });
});

describe('fix round 1: new entries are reachable from the package (Ruling T3e)', () => {
  const refused = (path: string) => ({ ok: false, rule: 'new_dependency', path });
  // An existing package that gains a dependency is refused first, by Ruling T3j.
  const changedParent = (path: string) => ({ ok: false, rule: 'other_change', path });

  it('npm: refuses an unrelated new package, or one only an unrelated package depends on', () => {
    const evil = { 'node_modules/evil': evilNpm('1.0.0') };
    const alone = npmV3(npmQfA('1.2.6'), evil);
    expect(check('package-lock.json', NPM_V3_BASE, alone)).toEqual(refused('package-lock.json'));
    const qfB = {
      version: '2.0.0',
      resolved: `${NPM}/qf-b/-/qf-b-2.0.0.tgz`,
      integrity: 'sha512-bbb',
      dependencies: { 'qf-a': '^1.2.0', evil: '^1.0.0' },
    };
    const byQfB = npmV3(npmQfA('1.2.6'), { 'node_modules/qf-b': qfB, ...evil });
    expect(check('package-lock.json', NPM_V3_BASE, byQfB)).toEqual(
      changedParent('package-lock.json'),
    );
  });

  it('npm: accepts a new dependency of the package’s new version', () => {
    const qfX = {
      version: '1.0.0',
      resolved: `${NPM}/qf-x/-/qf-x-1.0.0.tgz`,
      integrity: 'sha512-x',
    };
    const qfA = npmQfA('1.2.6', { dependencies: { 'qf-x': '^1.0.0' } });
    const next = npmV3(qfA, { 'node_modules/qf-x': qfX });
    expect(check('package-lock.json', NPM_V3_BASE, next)).toEqual({ ok: true });
  });

  const evilPnpm = [
    '\n  evil@1.0.0:\n    resolution: {integrity: sha512-e}\n',
    '\n  evil@1.0.0: {}\n',
  ];

  it('pnpm: refuses an unrelated new package, or one only an unrelated package depends on', () => {
    const alone = pnpmV9('1.2.6', ...evilPnpm);
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), alone)).toEqual(refused('pnpm-lock.yaml'));
    const byQfB = alone.replace('      qf-a: 1.2.6\n', '      qf-a: 1.2.6\n      evil: 1.0.0\n');
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), byQfB)).toEqual(
      changedParent('pnpm-lock.yaml'),
    );
  });

  it('pnpm: accepts a new dependency of the package’s new version', () => {
    const next = pnpmV9(
      '1.2.6',
      '\n  qf-x@1.0.0:\n    resolution: {integrity: sha512-x}\n',
      '\n  qf-x@1.0.0: {}\n',
    ).replace('  qf-a@1.2.6: {}\n', '  qf-a@1.2.6:\n    dependencies:\n      qf-x: 1.0.0\n');
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), next)).toEqual({ ok: true });
  });

  const evilClassic = `
evil@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/evil/-/evil-1.0.0.tgz#1"
  integrity sha512-e
`;

  it('Yarn classic: refuses an unrelated new package, or one only an unrelated package depends on', () => {
    const alone = yarnClassic('1.2.6') + evilClassic;
    expect(check('yarn.lock', yarnClassic('1.2.5'), alone)).toEqual(refused('yarn.lock'));
    const byQfB = alone.replace(
      '    "@scope/qf-c" "^3.0.0"\n',
      '    "@scope/qf-c" "^3.0.0"\n    evil "^1.0.0"\n',
    );
    expect(check('yarn.lock', yarnClassic('1.2.5'), byQfB)).toEqual(changedParent('yarn.lock'));
  });

  it('Yarn classic: accepts a new dependency of the package’s new version', () => {
    const next = `${yarnClassic('1.2.6')}  dependencies:
    qf-x "^1.0.0"

qf-x@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/qf-x/-/qf-x-1.0.0.tgz#1"
  integrity sha512-x
`;
    expect(check('yarn.lock', yarnClassic('1.2.5'), next)).toEqual({ ok: true });
  });

  const berryEntry = (name: string) => `
"${name}@npm:^1.0.0":
  version: 1.0.0
  resolution: "${name}@npm:1.0.0"
  checksum: 10c0/${name}
  languageName: node
  linkType: hard
`;

  it('Berry: refuses an unrelated new package, or one only an unrelated package depends on', () => {
    const alone = berry('1.2.6', undefined, berryEntry('evil'));
    expect(check('yarn.lock', berry('1.2.5'), alone)).toEqual(refused('yarn.lock'));
    const byQfB = alone.replace(
      '    qf-a: "npm:^1.2.0"\n',
      '    qf-a: "npm:^1.2.0"\n    evil: "npm:^1.0.0"\n',
    );
    expect(check('yarn.lock', berry('1.2.5'), byQfB)).toEqual(changedParent('yarn.lock'));
  });

  it('Berry: accepts a new dependency of the package’s new version', () => {
    const next = berry('1.2.6', undefined, berryEntry('qf-x')).replace(
      '  checksum: 10c0/a1.2.6\n',
      '  dependencies:\n    qf-x: "npm:^1.0.0"\n  checksum: 10c0/a1.2.6\n',
    );
    expect(check('yarn.lock', berry('1.2.5'), next)).toEqual({ ok: true });
  });
});

describe('fix round 1: existing entries keep their dependency names (Ruling T3j)', () => {
  const otherChange = (path: string) => ({ ok: false, rule: 'other_change', path });

  it('npm: refuses an existing dependency of the package that gains a new dependency', () => {
    const qfX = (dependencies: Record<string, string>) => ({
      version: '1.0.0',
      resolved: `${NPM}/qf-x/-/qf-x-1.0.0.tgz`,
      integrity: 'sha512-x',
      dependencies,
    });
    const lock = (a: string, xDeps: Record<string, string> = {}, extra = {}) =>
      npmV3(npmQfA(a, { dependencies: { 'qf-x': '^1.0.0' } }), {
        'node_modules/qf-x': qfX(xDeps),
        ...extra,
      });
    const evil = lock('1.2.6', { evil: '^1.0.0' }, { 'node_modules/evil': evilNpm('1.0.0') });
    expect(check('package-lock.json', lock('1.2.5'), evil)).toEqual(
      otherChange('package-lock.json'),
    );
    expect(check('package-lock.json', lock('1.2.5'), lock('1.2.6'))).toEqual({ ok: true });
  });

  it('pnpm: refuses an existing dependency of the package that gains a new dependency', () => {
    const lock = (a: string, xSnapshot: string, extra = ['', '']) =>
      pnpmV9(
        a,
        `\n  qf-x@1.0.0:\n    resolution: {integrity: sha512-x}\n${extra[0]}`,
        `\n  qf-x@1.0.0:${xSnapshot}\n${extra[1]}`,
      ).replace(`  qf-a@${a}: {}\n`, `  qf-a@${a}:\n    dependencies:\n      qf-x: 1.0.0\n`);
    const evilPackage = '\n  evil@1.0.0:\n    resolution: {integrity: sha512-e}\n';
    const evil = lock('1.2.6', '\n    dependencies:\n      evil: 1.0.0', [
      evilPackage,
      '\n  evil@1.0.0: {}\n',
    ]);
    expect(check('pnpm-lock.yaml', lock('1.2.5', ' {}'), evil)).toEqual(
      otherChange('pnpm-lock.yaml'),
    );
    expect(check('pnpm-lock.yaml', lock('1.2.5', ' {}'), lock('1.2.6', ' {}'))).toEqual({
      ok: true,
    });
  });

  it('Yarn classic: refuses an existing dependency of the package that gains a new dependency', () => {
    const lock = (a: string, xDeps = '') => `${yarnClassic(a)}  dependencies:
    qf-x "^1.0.0"

qf-x@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/qf-x/-/qf-x-1.0.0.tgz#1"
  integrity sha512-x
${xDeps}`;
    const evil = `${lock('1.2.6', '  dependencies:\n    evil "^1.0.0"\n')}
evil@^1.0.0:
  version "1.0.0"
  resolved "https://registry.yarnpkg.com/evil/-/evil-1.0.0.tgz#1"
  integrity sha512-e
`;
    expect(check('yarn.lock', lock('1.2.5'), evil)).toEqual(otherChange('yarn.lock'));
    expect(check('yarn.lock', lock('1.2.5'), lock('1.2.6'))).toEqual({ ok: true });
  });

  it('Berry: refuses an existing dependency of the package that gains a new dependency', () => {
    const entry = (name: string, deps = '') => `
"${name}@npm:^1.0.0":
  version: 1.0.0
  resolution: "${name}@npm:1.0.0"
${deps}  checksum: 10c0/${name}
  languageName: node
  linkType: hard
`;
    const lock = (a: string, xDeps = '', extra = '') =>
      berry(a, undefined, entry('qf-x', xDeps) + extra).replace(
        `  checksum: 10c0/a${a}\n`,
        `  dependencies:\n    qf-x: "npm:^1.0.0"\n  checksum: 10c0/a${a}\n`,
      );
    const evil = lock('1.2.6', '  dependencies:\n    evil: "npm:^1.0.0"\n', entry('evil'));
    expect(check('yarn.lock', lock('1.2.5'), evil)).toEqual(otherChange('yarn.lock'));
    expect(check('yarn.lock', lock('1.2.5'), lock('1.2.6'))).toEqual({ ok: true });
  });
});

describe('fix round 1: unknown references fail closed', () => {
  it('pnpm: reads a reference with an @ that names no package as an alias', () => {
    const next = pnpmV9('1.2.6').replace(
      '        version: 2.0.0\n',
      '        version: git+ssh://git@evil.example/qf-b.git\n',
    );
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), next)).toMatchObject({ rule: 'source_kind' });
    const kept = (v: string) =>
      pnpmV9(v).replace(
        '        version: 2.0.0\n',
        '        version: git+ssh://git@x.example/qf-b.git\n',
      );
    expect(check('pnpm-lock.yaml', kept('1.2.5'), kept('1.2.6'))).toEqual({ ok: true });
  });

  it('Yarn classic: reads npm:<name> without a range as an alias of that name', () => {
    const alias = (slot: string, name: string, resolvedName: string, integrity: string) => `
"${slot}@npm:${name}":
  version "1.2.6"
  resolved "https://registry.yarnpkg.com/${resolvedName}/-/${resolvedName}-1.2.6.tgz#1"
  integrity ${integrity}
`;
    const evil = yarnClassic('1.2.6') + alias('qf-a', 'evil', 'qf-a', 'sha512-a1.2.6');
    expect(check('yarn.lock', yarnClassic('1.2.5'), evil)).toMatchObject({ rule: 'source_kind' });
    const kept = alias('qf-alias', 'qf-d', 'qf-d', 'sha512-d');
    expect(readYarnLock(yarnClassic('1.2.5') + kept).find((e) => e.name === 'qf-d')).toMatchObject({
      slot: 'qf-alias',
      kind: 'registry',
    });
    expect(check('yarn.lock', yarnClassic('1.2.5') + kept, yarnClassic('1.2.6') + kept)).toEqual({
      ok: true,
    });
  });
});

describe('jsLockfileAdditions (Ruling T3i)', () => {
  it('lists the entries a lockfile change adds, and null for an unreadable change', () => {
    const qfX = {
      version: '1.0.0',
      resolved: `${NPM}/qf-x/-/qf-x-1.0.0.tgz`,
      integrity: 'sha512-x',
    };
    const next = npmV3(npmQfA('1.2.6', { dependencies: { 'qf-x': '^1.0.0' } }), {
      'node_modules/qf-x': qfX,
    });
    const added = jsLockfileAdditions({ path: 'package-lock.json', base: NPM_V3_BASE, next });
    expect(added?.map((e) => [e.slot, e.name, e.version])).toEqual([
      [undefined, 'qf-a', '1.2.6'],
      [undefined, 'qf-x', '1.0.0'],
    ]);
    expect(
      jsLockfileAdditions({ path: 'package-lock.json', base: NPM_V3_BASE, next: '{' }),
    ).toBeNull();
    expect(jsLockfileAdditions({ path: 'go.sum', base: '', next: '' })).toBeNull();
  });
});

// ---------------------------------------------------------------------------------------------
// Fix round 2 (task-3-fix-2.md): the re-reviewer's probes (t3rr) and Ruling T3l

/** An npm v3 lockfile with only the given packages (the root depends on `qf-a`). */
const npmOnly = (packages: Record<string, unknown>) =>
  JSON.stringify(
    {
      name: 'app',
      version: '1.0.0',
      lockfileVersion: 3,
      requires: true,
      packages: {
        '': { name: 'app', version: '1.0.0', dependencies: { 'qf-a': '^1.2.5' } },
        ...packages,
      },
    },
    null,
    2,
  );

const reg = (name: string, version: string, over: Record<string, unknown> = {}) => ({
  version,
  resolved: `${NPM}/${name}/-/${name}-${version}.tgz`,
  integrity: `sha512-${name}${version}`,
  ...over,
});

describe('fix round 2: existing packages keep their dependency names (Ruling T3l)', () => {
  const base = npmOnly({
    'node_modules/qf-a': reg('qf-a', '1.2.5', { dependencies: { 'qf-x': '^1.0.0' } }),
    'node_modules/qf-x': reg('qf-x', '1.0.0', { dependencies: { 'qf-y': '^1.0.0' } }),
    'node_modules/qf-y': reg('qf-y', '1.0.0'),
  });
  const qfA = reg('qf-a', '1.2.6', { dependencies: { 'qf-x': '^1.0.0' } });
  const evil = reg('evil', '1.0.0');
  const otherChange = { ok: false, rule: 'other_change', path: 'package-lock.json' };

  it('refuses a dependency re-entered with another integrity string and an edge to evil', () => {
    const qfX = reg('qf-x', '1.0.0', {
      integrity: 'sha512-qf-x1.0.0 sha1-bogus',
      dependencies: { 'qf-y': '^1.0.0', evil: '^1.0.0' },
    });
    const next = npmOnly({
      'node_modules/qf-a': qfA,
      'node_modules/qf-x': qfX,
      'node_modules/qf-y': reg('qf-y', '1.0.0'),
      'node_modules/evil': evil,
    });
    expect(check('package-lock.json', base, next)).toEqual(otherChange);
  });

  it('refuses a new version of an existing dependency with an edge to evil', () => {
    const next = npmOnly({
      'node_modules/qf-a': qfA,
      'node_modules/qf-x': reg('qf-x', '1.0.1', { dependencies: { evil: '^1.0.0' } }),
      'node_modules/evil': evil,
    });
    expect(check('package-lock.json', base, next)).toEqual(otherChange);
  });

  it('refuses an existing version of the package on another line that gains an edge', () => {
    const lock = (a: string, deps: Record<string, string> = {}, extra = {}) =>
      npmOnly({
        'node_modules/qf-a': reg('qf-a', a),
        'node_modules/qf-b': reg('qf-b', '2.0.0', { dependencies: { 'qf-a': '^2.0.0' } }),
        'node_modules/qf-b/node_modules/qf-a': reg('qf-a', '2.0.3', { dependencies: deps }),
        ...extra,
      });
    const gained = lock('1.2.6', { evil: '^1.0.0' }, { 'node_modules/evil': evil });
    expect(check('package-lock.json', lock('1.2.5'), gained)).toEqual(otherChange);
    expect(check('package-lock.json', lock('1.2.5'), lock('1.2.6'))).toEqual({ ok: true });
  });

  it('accepts a parent of the package, a new name under the new version, and a dropped name', () => {
    const withParent = (a: Record<string, unknown>) =>
      npmOnly({
        'node_modules/qf-a': a,
        'node_modules/qf-b': reg('qf-b', '2.0.0', { dependencies: { 'qf-a': '^1.2.0' } }),
        'node_modules/qf-x': reg('qf-x', '1.0.0', { dependencies: { 'qf-y': '^1.0.0' } }),
        'node_modules/qf-y': reg('qf-y', '1.0.0'),
      });
    const before = withParent(reg('qf-a', '1.2.5', { dependencies: { 'qf-x': '^1.0.0' } }));
    expect(check('package-lock.json', before, withParent(qfA))).toEqual({ ok: true });
    const newName = npmOnly({
      'node_modules/qf-a': reg('qf-a', '1.2.6', {
        dependencies: { 'qf-x': '^1.0.0', 'qf-z': '^1.0.0' },
      }),
      'node_modules/qf-x': reg('qf-x', '1.0.0', { dependencies: { 'qf-y': '^1.0.0' } }),
      'node_modules/qf-y': reg('qf-y', '1.0.0'),
      'node_modules/qf-z': reg('qf-z', '1.0.0'),
    });
    expect(check('package-lock.json', base, newName)).toEqual({ ok: true });
    const dropped = npmOnly({
      'node_modules/qf-a': qfA,
      'node_modules/qf-x': reg('qf-x', '1.0.1'),
      'node_modules/qf-y': reg('qf-y', '1.0.0'),
    });
    expect(check('package-lock.json', base, dropped)).toEqual({ ok: true });
  });
});

describe('fix round 2: pnpm v5 peer suffixes in references (N2)', () => {
  const peerOfX = (a: string) => `lockfileVersion: 5.4

importers:

  .:
    specifiers:
      qf-a: ^1.2.5
      qf-x: ^1.0.0
    dependencies:
      qf-a: ${a}
      qf-x: 1.0.0_qf-a@${a}

packages:

  /qf-a/${a}:
    resolution: {integrity: sha512-a${a}}
    dev: false

  /qf-x/1.0.0_qf-a@${a}:
    resolution: {integrity: sha512-x}
    peerDependencies:
      qf-a: ^1.2.0
    dependencies:
      qf-a: ${a}
    dev: false
`;

  const withPeer = (a: string) => `lockfileVersion: 5.4

importers:

  .:
    specifiers:
      qf-a: ^1.2.5
      react: ^18.2.0
    dependencies:
      qf-a: ${a}_react@18.2.0
      react: 18.2.0

packages:

  /qf-a/${a}_react@18.2.0:
    resolution: {integrity: sha512-a${a}}
    peerDependencies:
      react: ^18
    dependencies:
      react: 18.2.0
    dev: false

  /react/18.2.0:
    resolution: {integrity: sha512-r}
    dev: false
`;

  it('reads a peer-suffixed reference as a version, not as an alias', () => {
    expect(readPnpmLock(peerOfX('1.2.5')).filter((e) => e.slot !== undefined)).toEqual([]);
    expect(readPnpmLock(withPeer('1.2.5')).filter((e) => e.slot !== undefined)).toEqual([]);
  });

  it('accepts a bump of a package that is a peer, or has one', () => {
    expect(check('pnpm-lock.yaml', peerOfX('1.2.5'), peerOfX('1.2.6'))).toEqual({ ok: true });
    expect(check('pnpm-lock.yaml', withPeer('1.2.5'), withPeer('1.2.6'))).toEqual({ ok: true });
  });

  it('still reads a v5 alias reference', () => {
    const alias = peerOfX('1.2.6').replace(
      '      qf-a: 1.2.6\n    dev',
      '      qf-a: /evil/1.2.6\n    dev',
    );
    expect(readPnpmLock(alias).find((e) => e.slot === 'qf-a')).toMatchObject({ name: 'evil' });
  });
});

describe('fix round 2: the dependents graph in linear time (N1)', () => {
  const qfA = { 'node_modules/qf-a': reg('qf-a', '1.2.5') };
  const timed = (next: string) => {
    const started = performance.now();
    const result = check('package-lock.json', npmOnly(qfA), next);
    return { result, ms: performance.now() - started };
  };

  it(
    'checks 20 000 distinct parents of 20 000 copies of x in under 3 s',
    { timeout: 60_000 },
    () => {
      const packages: Record<string, unknown> = { ...qfA };
      for (let i = 0; i < 20_000; i++) {
        packages[`node_modules/p${i}`] = reg(`p${i}`, '1.0.0', { dependencies: { x: '*' } });
        packages[`node_modules/p${i}/node_modules/x`] = reg('x', `1.0.${i}`);
      }
      const { result, ms } = timed(JSON.stringify({ lockfileVersion: 3, packages }));
      expect(result).toMatchObject({ rule: 'new_dependency' });
      expect(ms).toBeLessThan(3000);
    },
  );

  it(
    'checks 80 000 nested copies of x, each depending on x, in under 3 s',
    { timeout: 60_000 },
    () => {
      const packages: Record<string, unknown> = { ...qfA };
      for (let i = 0; i < 80_000; i++) {
        packages[`node_modules/p${i}/node_modules/x`] = reg('x', `1.0.${i}`, {
          dependencies: { x: '*' },
        });
      }
      const { result, ms } = timed(JSON.stringify({ lockfileVersion: 3, packages }));
      expect(result).toMatchObject({ rule: 'new_dependency' });
      expect(ms).toBeLessThan(3000);
    },
  );

  it('shares one dependents array between the entries of a slot', () => {
    const packages: Record<string, unknown> = { ...qfA };
    for (let i = 0; i < 3; i++) {
      packages[`node_modules/p${i}`] = reg(`p${i}`, '1.0.0', { dependencies: { x: '*' } });
      packages[`node_modules/p${i}/node_modules/x`] = reg('x', `1.0.${i}`);
    }
    const copies = readNpmLock(JSON.stringify({ lockfileVersion: 3, packages })).filter(
      (e) => e.name === 'x',
    );
    expect(copies[0]?.dependents).toEqual(['p0', 'p1', 'p2']);
    expect(copies[1]?.dependents).toBe(copies[0]?.dependents);
  });
});

// ---------------------------------------------------------------------------------------------
// Fix round 3 (task-3-fix-3.md): the re-reviewer's probes (t3rr2) and Ruling T3m

/** {@link check} and the time it took. */
function timedCheck(path: string, base: string, next: string) {
  const started = performance.now();
  const result = check(path, base, next);
  return { result, ms: performance.now() - started };
}

describe('fix round 3: alias fan-out in linear time (NB1)', () => {
  const R = 'https://registry.yarnpkg.com';
  // Fix round 4 (R4-1): n × m dependency references above FIX_LIMITS.lockDependencyRefs make the
  // file unparsable; below it the fan-out still runs in linear time.
  it.each([
    [2000, 'source_kind'],
    [15_000, 'unparsable'],
  ] as const)(
    'checks a Yarn classic block of %i aliases with as many dependencies in under 3 s: %s',
    { timeout: 120_000 },
    (size, rule) => {
      const lock = (n: number) => {
        const lines = ['# yarn lockfile v1', '', 'qf-a@^1.2.5:', '  version "1.2.6"'];
        lines.push(`  resolved "${R}/qf-a/-/qf-a-1.2.6.tgz#abc"`, '  integrity sha512-a', '');
        if (n > 0) {
          const patterns = Array.from({ length: n }, (_, i) => `"s${i}@npm:evil@^1.0.0"`);
          lines.push(`${patterns.join(', ')}:`, '  version "1.0.0"');
          lines.push(`  resolved "${R}/evil/-/evil-1.0.0.tgz#abc"`, '  integrity sha512-e');
          lines.push(
            '  dependencies:',
            ...Array.from({ length: n }, (_, j) => `    d${j} "^1.0.0"`),
          );
        }
        return lines.join('\n') + '\n';
      };
      const { result, ms } = timedCheck('yarn.lock', lock(0), lock(size));
      expect(result).toMatchObject({ rule });
      expect(ms).toBeLessThan(3000);
    },
  );

  it.each([
    [2000, 'source_kind'],
    [5000, 'unparsable'],
  ] as const)(
    'checks %i pnpm references to one package with as many dependencies in under 3 s: %s',
    { timeout: 120_000 },
    (size, rule) => {
      const lock = (n: number) => {
        const lines = ["lockfileVersion: '9.0'", '', 'importers:', '  .:', '    dependencies:'];
        lines.push('      qf-a:', '        specifier: ^1.2.5', '        version: 1.2.6', '');
        lines.push('packages:', '  qf-a@1.2.6:', '    resolution: {integrity: sha512-a}');
        if (n > 0) lines.push('  evil@1.0.0:', '    resolution: {integrity: sha512-e}');
        lines.push('', 'snapshots:', n > 0 ? '  qf-a@1.2.6:' : '  qf-a@1.2.6: {}');
        if (n > 0) {
          lines.push(
            '    dependencies:',
            ...Array.from({ length: n }, (_, i) => `      s${i}: evil@1.0.0`),
          );
          lines.push('  evil@1.0.0:', '    dependencies:');
          lines.push(...Array.from({ length: n }, (_, j) => `      d${j}: 1.0.0`));
        }
        return lines.join('\n') + '\n';
      };
      const { result, ms } = timedCheck('pnpm-lock.yaml', lock(0), lock(size));
      expect(result).toMatchObject({ rule });
      expect(ms).toBeLessThan(3000);
    },
  );

  it.each([
    [2000, 'source_kind'],
    [5000, 'unparsable'],
  ] as const)(
    'checks a Berry key of %i aliases with as many dependencies in under 3 s: %s',
    { timeout: 120_000 },
    (size, rule) => {
      const lock = (n: number) => {
        const lines = ['__metadata:', '  version: 8', '  cacheKey: 10', '', '"qf-a@npm:^1.2.5":'];
        lines.push('  version: 1.2.6', '  resolution: "qf-a@npm:1.2.6"', '  checksum: 10/abc', '');
        if (n > 0) {
          const descriptors = Array.from({ length: n }, (_, i) => `s${i}@npm:evil@^1.0.0`);
          // An explicit key: YAML limits implicit keys to 1 024 characters.
          lines.push(`? "${descriptors.join(', ')}"`, ':', '  version: 1.0.0');
          lines.push('  resolution: "evil@npm:1.0.0"', '  checksum: 10/e', '  dependencies:');
          lines.push(...Array.from({ length: n }, (_, j) => `    d${j}: "npm:^1.0.0"`));
        }
        return lines.join('\n') + '\n';
      };
      const { result, ms } = timedCheck('yarn.lock', lock(0), lock(size));
      expect(result).toMatchObject({ rule });
      expect(ms).toBeLessThan(3000);
    },
  );
});

describe('fix round 3: brand-new names only through the package or other new names (Ruling T3m)', () => {
  const qfX = reg('qf-x', '1.0.0', {
    peerDependencies: { 'opt-peer': '*' },
    peerDependenciesMeta: { 'opt-peer': { optional: true } },
  });
  const base = npmOnly({
    'node_modules/qf-a': reg('qf-a', '1.2.5', { dependencies: { 'qf-x': '^1.0.0' } }),
    'node_modules/qf-x': qfX,
  });
  const qfA = reg('qf-a', '1.2.6', { dependencies: { 'qf-x': '^1.0.0' } });
  const newDependency = { ok: false, rule: 'new_dependency', path: 'package-lock.json' };

  it('npm: refuses a new optional peer of an existing package, and what it brings', () => {
    const next = npmOnly({
      'node_modules/qf-a': qfA,
      'node_modules/qf-x': qfX,
      'node_modules/opt-peer': reg('opt-peer', '1.0.0', { dependencies: { evil: '^1.0.0' } }),
      'node_modules/evil': reg('evil', '1.0.0'),
    });
    expect(check('package-lock.json', base, next)).toEqual(newDependency);
  });

  it('Berry: refuses a new optional peer of an existing package, and what it brings', () => {
    const lock = (a: string, extra = '') => `__metadata:
  version: 8
  cacheKey: 10

"qf-a@npm:^1.2.5":
  version: ${a}
  resolution: "qf-a@npm:${a}"
  dependencies:
    qf-x: "npm:^1.0.0"
  checksum: 10/a${a}
  languageName: node
  linkType: hard

"qf-x@npm:^1.0.0":
  version: 1.0.0
  resolution: "qf-x@npm:1.0.0"
  peerDependencies:
    opt-peer: "*"
  peerDependenciesMeta:
    opt-peer:
      optional: true
  checksum: 10/x
  languageName: node
  linkType: hard
${extra}`;
    const extra = `
"opt-peer@npm:*":
  version: 1.0.0
  resolution: "opt-peer@npm:1.0.0"
  dependencies:
    evil: "npm:^1.0.0"
  checksum: 10/o
  languageName: node
  linkType: hard

"evil@npm:^1.0.0":
  version: 1.0.0
  resolution: "evil@npm:1.0.0"
  checksum: 10/e
  languageName: node
  linkType: hard
`;
    expect(check('yarn.lock', lock('1.2.5'), lock('1.2.6', extra))).toEqual({
      ok: false,
      rule: 'new_dependency',
      path: 'yarn.lock',
    });
  });

  it('accepts a new dependency of the new version, and a new dependency of that', () => {
    const next = npmOnly({
      'node_modules/qf-a': reg('qf-a', '1.2.6', {
        dependencies: { 'qf-x': '^1.0.0', 'qf-z': '^1.0.0' },
      }),
      'node_modules/qf-x': qfX,
      'node_modules/qf-z': reg('qf-z', '1.0.0', { dependencies: { 'qf-w': '^1.0.0' } }),
      'node_modules/qf-w': reg('qf-w', '1.0.0'),
    });
    expect(check('package-lock.json', base, next)).toEqual({ ok: true });
  });

  it('accepts an existing package hoisted to another folder at a new version, reached only through an existing package (Rulings T3m, T3n)', () => {
    // Fix round 4, R4-5: the hoisted qf-x@1.0.1 is a new entry with the base's (slot, name)
    // pair. The new qf-a no longer depends on it; only qf-b, an existing package qf-a depends
    // on, does: a closed edge reaches it.
    const qfB = reg('qf-b', '2.0.0', { dependencies: { 'qf-x': '^1.0.0' } });
    const before = npmOnly({
      'node_modules/qf-a': reg('qf-a', '1.2.5', {
        dependencies: { 'qf-b': '^2.0.0', 'qf-x': '^1.0.0' },
      }),
      'node_modules/qf-a/node_modules/qf-x': qfX,
      'node_modules/qf-b': qfB,
      'node_modules/qf-b/node_modules/qf-x': qfX,
    });
    const hoisted = npmOnly({
      'node_modules/qf-a': reg('qf-a', '1.2.6', { dependencies: { 'qf-b': '^2.0.0' } }),
      'node_modules/qf-b': qfB,
      'node_modules/qf-x': { ...qfX, ...reg('qf-x', '1.0.1') },
    });
    expect(
      jsLockfileAdditions({ path: 'package-lock.json', base: before, next: hoisted })?.map(
        (e) => `${e.name}@${e.version}`,
      ),
    ).toEqual(['qf-a@1.2.6', 'qf-x@1.0.1']);
    expect(check('package-lock.json', before, hoisted)).toEqual({ ok: true });
  });
});

describe('fix round 3: pnpm v5 references with a path (NB3)', () => {
  const absolute = (qfA: string, withQfA: boolean) => `lockfileVersion: 5.4

importers:

  .:
    specifiers:
      qf-a: ^1.2.5
      foo: ^1.0.0
    dependencies:
      qf-a: ${qfA}
      foo: registry.example.com/foo/1.0.0_react@18.2.0
      react: 18.2.0

packages:
${withQfA ? '\n  /qf-a/1.2.5:\n    resolution: {integrity: sha512-a}\n    dev: false\n' : ''}
  registry.example.com/foo/1.0.0_react@18.2.0:
    resolution: {integrity: sha512-f}
    name: foo
    version: 1.0.0
    dependencies:
      react: 18.2.0
    dev: false

  /react/18.2.0:
    resolution: {integrity: sha512-r}
    dev: false
`;

  it('reads an absolute depPath reference by its packages key', () => {
    expect(readPnpmLock(absolute('1.2.5', true)).filter((e) => e.slot !== undefined)).toEqual([]);
    const moved = readPnpmLock(absolute('registry.example.com/foo/1.0.0_react@18.2.0', false));
    expect(moved.find((e) => e.slot === 'qf-a')).toMatchObject({ name: 'foo', version: '1.0.0' });
  });

  it('refuses the package’s slot pointed at another package by its depPath', () => {
    const next = absolute('registry.example.com/foo/1.0.0_react@18.2.0', false);
    expect(check('pnpm-lock.yaml', absolute('1.2.5', true), next)).toMatchObject({
      rule: 'source_kind',
    });
  });

  it('reads a path reference without a packages entry as an unknown alias (fail closed)', () => {
    const missing = readPnpmLock(absolute('registry.example.com/evil/1.0.0', false));
    expect(missing.find((e) => e.slot === 'qf-a')).toMatchObject({ kind: 'other' });
  });

  it('accepts bumps with hashed and scoped peer suffixes', () => {
    const scoped = (a: string) => `lockfileVersion: 5.4

importers:

  .:
    specifiers:
      qf-a: ^1.2.5
    dependencies:
      qf-a: ${a}_@types+react@18.0.0+react@18.2.0
      '@types/react': 18.0.0
      react: 18.2.0
      qf-x: 1.0.0_7a5e4d3c2b1a

packages:

  /qf-a/${a}_@types+react@18.0.0+react@18.2.0:
    resolution: {integrity: sha512-a${a}}
    dependencies:
      react: 18.2.0
      '@types/react': 18.0.0
    dev: false

  /qf-x/1.0.0_7a5e4d3c2b1a:
    resolution: {integrity: sha512-x}
    dependencies:
      qf-a: ${a}_@types+react@18.0.0+react@18.2.0
    dev: false

  /react/18.2.0:
    resolution: {integrity: sha512-r}
    dev: false

  /@types/react/18.0.0:
    resolution: {integrity: sha512-t}
    dev: false
`;
    expect(check('pnpm-lock.yaml', scoped('1.2.5'), scoped('1.2.6'))).toEqual({ ok: true });
  });
});

// ---------------------------------------------------------------------------------------------
// Fix round 4 (task-3-fix-4.md): a bound on the work, whatever the shape (R4-1, R4-4), pnpm
// `file:` references (R4-2) and the base's (slot, name) pairs (Ruling T3n)

describe('fix round 4: a bound on the work of a read (R4-1, R4-4)', () => {
  const raw = (n: number, dependencies: string[], source: string | null = null) =>
    Array.from({ length: n }, (_, i) => ({
      slot: `s${i}`,
      name: 'p',
      version: '1.0.0',
      source,
      kind: 'registry' as const,
      integrity: 'sha512-p',
      dependencies,
    }));

  it('reads up to FIX_LIMITS.lockDependencyRefs dependency names, alias copies counted, not one more', () => {
    const names = Array.from({ length: 1000 }, (_, j) => `d${j}`);
    const full = raw(FIX_LIMITS.lockDependencyRefs / names.length, names);
    expect(withDependents(full)).toHaveLength(full.length);
    const extra = { ...full[0]!, slot: 'extra', dependencies: ['d0'] };
    expect(() => withDependents([...full, extra])).toThrow(/unreadable/);
  });

  it('shares one sorted dependencies array between entries of any name that hold one raw array', () => {
    const names = ['qf-y', 'qf-x'];
    const [one] = raw(1, names);
    const [first, second] = withDependents([
      { ...one!, slot: undefined, name: 'e1' },
      { ...one!, slot: undefined, name: 'e2' },
    ]);
    expect(first?.dependencies).toEqual(['qf-x', 'qf-y']);
    expect(second?.dependencies).toBe(first?.dependencies);
  });

  it('contributes each raw array once: the slots it lists share one dependents array', () => {
    const names = ['qf-x', 'qf-y'];
    const [one] = raw(1, names);
    const leaf = (name: string) => ({ ...one!, slot: undefined, name, dependencies: [] });
    const entries = withDependents([
      { ...one!, slot: undefined, name: 'e2' },
      { ...one!, slot: undefined, name: 'e1' },
      leaf('qf-x'),
      leaf('qf-y'),
    ]);
    const x = entries.find((e) => e.name === 'qf-x');
    expect(x?.dependents).toEqual(['e1', 'e2']);
    expect(entries.find((e) => e.name === 'qf-y')?.dependents).toBe(x?.dependents);
  });

  it('refuses a source longer than FIX_LIMITS.lockSourceChars at once, however many copies share it', () => {
    const source = `https://r.example/evil/-/evil-1.0.0.tgz#${'a'.repeat(100_000)}`;
    const started = performance.now();
    expect(() => withDependents(raw(3000, [], source))).toThrow(/unreadable/);
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it('builds no key per copy that holds the source (100 000 copies of a 4 096-character source)', () => {
    const head = 'https://r.example/evil/-/evil-1.0.0.tgz#';
    const source = head + 'a'.repeat(FIX_LIMITS.lockSourceChars - head.length);
    const started = performance.now();
    expect(withDependents(raw(100_000, [], source))).toHaveLength(100_000);
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it('accepts a resolved URL of FIX_LIMITS.lockSourceChars characters, and refuses one more', () => {
    const resolved = (length: number) => {
      const url = `${NPM}/qf-a/-/qf-a-1.2.6.tgz#`;
      return url + 'a'.repeat(length - url.length);
    };
    const next = (length: number) => npmV3(npmQfA('1.2.6', { resolved: resolved(length) }));
    expect(check('package-lock.json', NPM_V3_BASE, next(FIX_LIMITS.lockSourceChars))).toEqual({
      ok: true,
    });
    expect(check('package-lock.json', NPM_V3_BASE, next(FIX_LIMITS.lockSourceChars + 1))).toEqual({
      ok: false,
      rule: 'unparsable',
      path: 'package-lock.json',
    });
  });
});

describe('fix round 4: fan-out shapes are unparsable, real lockfiles are not (R4-1, R4-4)', () => {
  const R = 'https://registry.yarnpkg.com';
  const unparsable = { ok: false, rule: 'unparsable', path: 'yarn.lock' };
  /** A Yarn classic lockfile: the bumped qf-a, then a block with this header and m dependencies. */
  const classic = (header: string | null, m = 0, resolved = `${R}/evil/-/evil-1.0.0.tgz#abc`) => {
    const lines = ['# yarn lockfile v1', '', 'qf-a@^1.2.5:', '  version "1.2.6"'];
    lines.push(`  resolved "${R}/qf-a/-/qf-a-1.2.6.tgz#abc"`, '  integrity sha512-a', '');
    if (header !== null) {
      lines.push(`${header}:`, '  version "1.0.0"', `  resolved "${resolved}"`);
      lines.push('  integrity sha512-e');
      if (m > 0) {
        lines.push('  dependencies:', ...Array.from({ length: m }, (_, j) => `    d${j} "^1.0.0"`));
      }
    }
    return lines.join('\n') + '\n';
  };
  const header = (n: number, pattern: (i: number) => string) =>
    Array.from({ length: n }, (_, i) => JSON.stringify(pattern(i))).join(', ');

  it('refuses a Yarn classic block whose patterns name more than one package', () => {
    expect(() => readYarnLock(classic('"s1@npm:e1@^1.0.0", "s2@npm:e2@^1.0.0"'))).toThrow();
    expect(() => readYarnLock(classic('"e1@^1.0.0", "e2@^1.0.0"'))).toThrow();
    expect(() => readYarnLock(classic('"qf-x@^1.0.0", "qf-y@npm:qf-z@^1.0.0"'))).toThrow();
    const one = readYarnLock(classic('"evil@^1.0.0", "evil@^1.0"'));
    expect(one.filter((e) => e.name === 'evil')).toHaveLength(1);
    const alias = readYarnLock(classic('"evil-cjs@npm:evil@^1.0.0", "evil@^1.0.0"'));
    expect(alias.filter((e) => e.name === 'evil').map((e) => e.slot)).toEqual([
      'evil-cjs',
      undefined,
    ]);
  });

  it.each([
    ['10 000 aliases of different packages', 10_000, (i: number) => `s${i}@npm:e${i}@^1.0.0`],
    ['5 000 different packages', 5000, (i: number) => `e${i}@^1.0.0`],
  ])(
    'refuses a Yarn classic block of %s sharing as many dependencies, in under 3 s',
    { timeout: 120_000 },
    (_name, n, pattern) => {
      const { result, ms } = timedCheck('yarn.lock', classic(null), classic(header(n, pattern), n));
      expect(result).toEqual(unparsable);
      expect(ms).toBeLessThan(3000);
    },
  );

  it(
    'refuses a base whose alias copies share 6 000 × 6 000 dependency names, in under 3 s',
    { timeout: 120_000 },
    () => {
      const n = 6000;
      const p1 = header(n, (i) => 's' + i + '@npm:p@^1.0.0');
      const p2 = header(n, (i) => 's' + i + '@npm:p@^2.0.0');
      const lock = (a: string) => {
        const lines = ['# yarn lockfile v1', '', 'qf-a@^1.2.5:', `  version "${a}"`];
        lines.push(`  resolved "${R}/qf-a/-/qf-a-${a}.tgz#abc"`, '  integrity sha512-a', '');
        lines.push(`${p1}:`, '  version "1.0.0"');
        lines.push(`  resolved "${R}/p/-/p-1.0.0.tgz#abc"`, '  integrity sha512-p1');
        lines.push('  dependencies:', ...Array.from({ length: n }, (_, j) => `    d${j} "^1.0.0"`));
        lines.push('', `${p2}:`, '  version "2.0.0"');
        lines.push(`  resolved "${R}/p/-/p-2.0.0.tgz#abc"`, '  integrity sha512-p2', '');
        return lines.join('\n');
      };
      const { result, ms } = timedCheck('yarn.lock', lock('1.2.5'), lock('1.2.6'));
      expect(result).toEqual(unparsable);
      expect(ms).toBeLessThan(3000);
    },
  );

  it('refuses 5 000 alias copies of a package with a 200 000-character resolved URL, in under 1 s', () => {
    const long = `${R}/evil/-/evil-1.0.0.tgz#${'a'.repeat(200_000)}`;
    const aliases = header(5000, (i) => `s${i}@npm:evil@^1.0.0`);
    const { result, ms } = timedCheck('yarn.lock', classic(null), classic(aliases, 0, long));
    expect(result).toEqual(unparsable);
    expect(ms).toBeLessThan(1000);
  });

  it.each([
    [
      '20 000 parents of 20 000 copies of x',
      (packages: Record<string, unknown>) => {
        for (let i = 0; i < 20_000; i++) {
          packages[`node_modules/p${i}`] = reg(`p${i}`, '1.0.0', { dependencies: { x: '*' } });
          packages[`node_modules/p${i}/node_modules/x`] = reg('x', `1.0.${i}`);
        }
      },
    ],
    [
      '80 000 nested copies of x, each depending on x',
      (packages: Record<string, unknown>) => {
        for (let i = 0; i < 80_000; i++) {
          packages[`node_modules/p${i}/node_modules/x`] = reg('x', `1.0.${i}`, {
            dependencies: { x: '*' },
          });
        }
      },
    ],
  ])(
    'still accepts the bump in a lockfile of %s, in under 3 s',
    { timeout: 60_000 },
    (_n, fill) => {
      const lock = (a: string) => {
        const packages: Record<string, unknown> = { 'node_modules/qf-a': reg('qf-a', a) };
        fill(packages);
        return JSON.stringify({ lockfileVersion: 3, packages });
      };
      const { result, ms } = timedCheck('package-lock.json', lock('1.2.5'), lock('1.2.6'));
      expect(result).toEqual({ ok: true });
      expect(ms).toBeLessThan(3000);
    },
  );
});

describe('fix round 4: pnpm file: references (R4-2)', () => {
  /** v5.4 or v6.0: the root depends on qf-a (by `qfA`) and on `foo: file:foo-1.0.0.tgz`. */
  const fileLock = (major: string, qfA: string, packaged: string | null) => {
    const v5 = major === '5.4';
    const importer = v5
      ? `specifiers:\n  qf-a: ^1.2.5\n  foo: file:foo-1.0.0.tgz\n\ndependencies:\n  qf-a: ${qfA}\n  foo: file:foo-1.0.0.tgz`
      : `dependencies:\n  qf-a:\n    specifier: ^1.2.5\n    version: ${qfA}\n  foo:\n    specifier: file:foo-1.0.0.tgz\n    version: file:foo-1.0.0.tgz`;
    const qfAKey = v5 ? `/qf-a/${packaged}` : `/qf-a@${packaged}`;
    const qfAEntry =
      packaged === null
        ? ''
        : `\n  ${qfAKey}:\n    resolution: {integrity: sha512-a${packaged}}\n    dev: false\n`;
    return `lockfileVersion: ${v5 ? '5.4' : "'6.0'"}

${importer}

packages:
${qfAEntry}
  file:foo-1.0.0.tgz:
    resolution: {integrity: sha512-f, tarball: file:foo-1.0.0.tgz}
    name: foo
    version: 1.0.0
    dev: false
`;
  };

  it.each(['5.4', '6.0'])(
    'v%s: refuses the package’s slot pointed at an existing file: package, accepts the bump',
    (major) => {
      const base = fileLock(major, '1.2.5', '1.2.5');
      const moved = fileLock(major, 'file:foo-1.0.0.tgz', null);
      expect(readPnpmLock(moved).find((e) => e.slot === 'qf-a')).toMatchObject({
        name: 'foo',
        kind: 'file',
      });
      expect(check('pnpm-lock.yaml', base, moved)).toEqual({
        ok: false,
        rule: 'source_kind',
        path: 'pnpm-lock.yaml',
      });
      expect(check('pnpm-lock.yaml', base, fileLock(major, '1.2.6', '1.2.6'))).toEqual({
        ok: true,
      });
    },
  );

  it('reads a reference that names no package and is no plain version as an unknown alias (fail closed)', () => {
    const odd = (qfA: string) =>
      pnpmV9(qfA).replace('        version: 2.0.0\n', '        version: evil\n');
    expect(readPnpmLock(odd('1.2.6')).find((e) => e.slot === 'qf-b')).toMatchObject({
      name: 'evil',
      kind: 'other',
    });
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), odd('1.2.6'))).toMatchObject({
      rule: 'source_kind',
    });
    expect(readPnpmLock(pnpmV9('1.2.5')).filter((e) => e.slot !== undefined)).toEqual([]);
  });
});

describe('fix round 4: the base’s (slot, name) pairs are what is known (Ruling T3n)', () => {
  it('refuses a real package in a slot the base used only for an alias', () => {
    const cliui = reg('cliui', '8.0.0', {
      dependencies: { 'string-width-cjs': 'npm:string-width@^4.2.0' },
    });
    const base = npmOnly({
      'node_modules/qf-a': reg('qf-a', '1.2.5', { dependencies: { cliui: '^8' } }),
      'node_modules/cliui': cliui,
      'node_modules/string-width-cjs': { ...reg('string-width', '4.2.3'), name: 'string-width' },
    });
    const next = npmOnly({
      'node_modules/qf-a': reg('qf-a', '1.2.6', { dependencies: { cliui: '^8' } }),
      'node_modules/cliui': cliui,
      'node_modules/string-width-cjs': reg('string-width-cjs', '6.6.6'),
    });
    expect(check('package-lock.json', base, next)).toEqual({
      ok: false,
      rule: 'new_dependency',
      path: 'package-lock.json',
    });
  });
});

// ---------------------------------------------------------------------------------------------
// Fix round 5 (task-3-fix-5.md): the union fan-out after the merge (R5-1), and YAML anchors,
// aliases and merge keys in pnpm and Berry lockfiles (R5-2, Ruling T3o)

describe('fix round 5: the union fan-out after the merge (R5-1)', () => {
  const Y = 'https://registry.yarnpkg.com';
  const raw = (slot: string, version: string, dependencies: string[]) => ({
    slot,
    name: 'p',
    version,
    source: null,
    kind: 'registry' as const,
    integrity: 'sha512-p',
    dependencies,
  });

  it('counts the names each merged copy ends up with: up to FIX_LIMITS.lockDependencyRefs, not one more', () => {
    // 2 000 copies of one package, 2 names each: 4 000 raw names, but every copy gets the union
    // of 4 000 names, 8 000 000 in all.
    const copies = Array.from({ length: 2000 }, (_, i) =>
      raw(`s${i}`, '1.0.0', [`d${2 * i}`, `d${2 * i + 1}`]),
    );
    expect(withDependents(copies)).toHaveLength(2000);
    expect(() => withDependents([...copies, raw('extra', '1.0.0', ['d-extra'])])).toThrow(
      /unreadable/,
    );
  });

  /** k alias copies of p@1.0.0 with one name each, and in each slot a p@2.0.i of its own. */
  const npmUnion = (k: number, a: string) => {
    const packages: Record<string, unknown> = {
      '': { name: 'root', version: '0.0.0', dependencies: { 'qf-a': '^1.2.5' } },
      'node_modules/qf-a': reg('qf-a', a),
    };
    for (let i = 0; i < k; i++) {
      packages[`node_modules/s${i}`] = {
        ...reg('p', '1.0.0'),
        name: 'p',
        dependencies: { [`d${i}`]: '*' },
      };
      packages[`node_modules/q/node_modules/s${i}`] = { ...reg('p', `2.0.${i}`), name: 'p' };
    }
    return JSON.stringify({ name: 'root', lockfileVersion: 3, packages });
  };
  const classicUnion = (k: number, a: string) => {
    const lines = ['# yarn lockfile v1', '', 'qf-a@^1.2.5:', `  version "${a}"`];
    lines.push(`  resolved "${Y}/qf-a/-/qf-a-${a}.tgz#abc"`, '  integrity sha512-a', '');
    for (let i = 0; i < k; i++) {
      lines.push(
        `"s${i}@npm:p@^1.0.0":`,
        '  version "1.0.0"',
        `  resolved "${Y}/p/-/p-1.0.0.tgz#a"`,
      );
      lines.push('  integrity sha512-p', '  dependencies:', `    d${i} "^1.0.0"`, '');
      lines.push(`"s${i}@npm:p@~2.0.${i}":`, `  version "2.0.${i}"`);
      lines.push(`  resolved "${Y}/p/-/p-2.0.${i}.tgz#b"`, '  integrity sha512-q', '');
    }
    return lines.join('\n');
  };

  it.each([
    ['package-lock.json', npmUnion],
    ['yarn.lock', classicUnion],
  ])(
    '%s: refuses 16 000 alias copies whose union fans out, in under 3 s',
    { timeout: 120_000 },
    (path, lock) => {
      const { result, ms } = timedCheck(path, lock(16_000, '1.2.5'), lock(16_000, '1.2.6'));
      expect(result).toEqual({ ok: false, rule: 'unparsable', path });
      expect(ms).toBeLessThan(3000);
    },
  );

  it('still accepts the same shape at 1 000 copies', { timeout: 60_000 }, () => {
    const { result, ms } = timedCheck(
      'package-lock.json',
      npmUnion(1000, '1.2.5'),
      npmUnion(1000, '1.2.6'),
    );
    expect(result).toEqual({ ok: true });
    expect(ms).toBeLessThan(3000);
  });
});

describe('fix round 5: no YAML anchors, aliases or merge keys in a lockfile (R5-2, Ruling T3o)', () => {
  /** pnpm v6: one anchored dependencies map of m names, used by u more packages as `*a`. */
  const pnpmAliases = (m: number, u: number, a: string) => {
    const lines = [
      "lockfileVersion: '6.0'",
      '',
      'dependencies:',
      '  qf-a:',
      '    specifier: ^1.2.5',
    ];
    lines.push(`    version: ${a}`, '', 'packages:', '', `  /qf-a@${a}:`);
    lines.push('    resolution: {integrity: sha512-a}', '    dev: false', '');
    lines.push('  /p0@1.0.0:', '    resolution: {integrity: sha512-p}', '    dependencies: &a');
    for (let j = 0; j < m; j++) lines.push(`      d${j}: 1.0.0`);
    for (let i = 1; i <= u; i++) {
      lines.push(
        `  /p${i}@1.0.0:`,
        '    resolution: {integrity: sha512-p}',
        '    dependencies: *a',
      );
    }
    return lines.join('\n') + '\n';
  };
  /** Berry: the same through `dependencies: &a` and `*a`. */
  const berryAliases = (m: number, u: number, a: string) => {
    const lines = ['__metadata:', '  version: 8', '  cacheKey: 10', '', '"qf-a@npm:^1.2.5":'];
    lines.push(`  version: ${a}`, `  resolution: "qf-a@npm:${a}"`, '  checksum: 10/abc', '');
    lines.push('"p0@npm:1.0.0":', '  version: 1.0.0', '  resolution: "p0@npm:1.0.0"');
    lines.push('  checksum: 10/p', '  dependencies: &a');
    for (let j = 0; j < m; j++) lines.push(`    d${j}: "npm:1.0.0"`);
    lines.push('');
    for (let i = 1; i <= u; i++) {
      lines.push(`"p${i}@npm:1.0.0":`, '  version: 1.0.0', `  resolution: "p${i}@npm:1.0.0"`);
      lines.push('  checksum: 10/p', '  dependencies: *a', '');
    }
    return lines.join('\n') + '\n';
  };

  it.each([
    ['pnpm-lock.yaml', 70_000, pnpmAliases],
    ['yarn.lock', 70_000, berryAliases],
    ['pnpm-lock.yaml', 300_000, pnpmAliases],
  ])(
    '%s: refuses one map of %i names used 99 more times through aliases, in under 3 s',
    { timeout: 120_000 },
    (path, m, lock) => {
      const { result, ms } = timedCheck(path, lock(m, 99, '1.2.5'), lock(m, 99, '1.2.6'));
      expect(result).toEqual({ ok: false, rule: 'unparsable', path });
      expect(ms).toBeLessThan(3000);
    },
  );

  it('refuses a pnpm-lock.yaml with a single anchor, with or without an alias', () => {
    const anchored = pnpmV9('1.2.6').replace(
      'resolution: {integrity: sha512-a1.2.6}',
      'resolution: &r {integrity: sha512-a1.2.6}',
    );
    const unparsable = { ok: false, rule: 'unparsable', path: 'pnpm-lock.yaml' };
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), anchored)).toEqual(unparsable);
    const aliased = anchored.replace('resolution: {integrity: sha512-bbb}', 'resolution: *r');
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), aliased)).toEqual(unparsable);
    expect(() => readPnpmLock(aliased)).toThrow();
  });

  it('refuses a Berry yarn.lock with a merge key', () => {
    const merged = berry('1.2.6').replace(
      '  checksum: 10c0/a1.2.6\n',
      '  checksum: 10c0/a1.2.6\n  <<:\n    checksum: 10c0/evil\n',
    );
    expect(check('yarn.lock', berry('1.2.5'), merged)).toEqual({
      ok: false,
      rule: 'unparsable',
      path: 'yarn.lock',
    });
  });

  it('still accepts ordinary pnpm v6, v9 and Berry lockfiles', () => {
    expect(check('pnpm-lock.yaml', pnpmV6('1.2.5'), pnpmV6('1.2.6'))).toEqual({ ok: true });
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), pnpmV9('1.2.6'))).toEqual({ ok: true });
    expect(check('yarn.lock', berry('1.2.5'), berry('1.2.6'))).toEqual({ ok: true });
  });

  it('pnpm: stops counting references while walking them, not after', () => {
    // 3 000 references to a package of 3 000 dependencies: 9 000 000 names.
    const lines = ["lockfileVersion: '9.0'", '', 'importers:', '  .:', '    dependencies:'];
    lines.push('      qf-a:', '        specifier: ^1.2.5', '        version: 1.2.6', '');
    lines.push('packages:', '  qf-a@1.2.6:', '    resolution: {integrity: sha512-a}');
    lines.push('  evil@1.0.0:', '    resolution: {integrity: sha512-e}', '', 'snapshots:');
    lines.push('  qf-a@1.2.6:', '    dependencies:');
    lines.push(...Array.from({ length: 3000 }, (_, i) => `      s${i}: evil@1.0.0`));
    lines.push('  evil@1.0.0:', '    dependencies:');
    lines.push(...Array.from({ length: 3000 }, (_, j) => `      d${j}: 1.0.0`));
    expect(() => readPnpmLock(lines.join('\n') + '\n')).toThrow(/pnpm packages and references/);
  });
});

// ---------------------------------------------------------------------------------------------
// Ruling T3p (carried into Task 4): every spelling of a YAML merge, through tags and directives

describe('Ruling T3p: no YAML tags, directives or non-string keys in pnpm and Berry lockfiles', () => {
  const unparsable = (path: string) => ({ ok: false, rule: 'unparsable', path });
  const EVIL = 'https://evil.example/qf-a.tgz';
  /** pnpm v9 at 1.2.6 whose qf-a resolution holds one more `<key>: <value>` pair. */
  const pnpmWith = (key: string, value: string) =>
    pnpmV9('1.2.6').replace(
      'resolution: {integrity: sha512-a1.2.6}',
      `resolution: {integrity: sha512-a1.2.6, ${key}: ${value}}`,
    );
  /** Berry at 1.2.6 whose qf-a entry holds one more `<key>: <value>` line. */
  const berryWith = (key: string, value: string) =>
    berry('1.2.6').replace(
      '  checksum: 10c0/a1.2.6\n',
      `  checksum: 10c0/a1.2.6\n  ${key}: ${value}\n`,
    );

  it.each(['!!merge <<', '!!merge foo', '!<tag:yaml.org,2002:merge> "<<"'])(
    'pnpm-lock.yaml: refuses the merge key %s',
    (key) => {
      const next = pnpmWith(key, `{tarball: ${EVIL}}`);
      expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), next)).toEqual(unparsable('pnpm-lock.yaml'));
      expect(() => readPnpmLock(next)).toThrow();
    },
  );

  it.each(['!!merge <<', '!!merge foo', '!<tag:yaml.org,2002:merge> "<<"'])(
    'Berry yarn.lock: refuses the merge key %s',
    (key) => {
      const next = berryWith(key, '{checksum: 10c0/evil}');
      expect(check('yarn.lock', berry('1.2.5'), next)).toEqual(unparsable('yarn.lock'));
      expect(() => readYarnLock(next)).toThrow();
    },
  );

  it('refuses a plain << after a %YAML 1.1 directive in pnpm-lock.yaml', () => {
    const evil = `{tarball: ${EVIL}}`;
    const next = `%YAML 1.1\n---\n${pnpmWith('<<', evil)}`;
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), next)).toEqual(unparsable('pnpm-lock.yaml'));
    // The same directive on both sides, and with a harmless merge, is still refused.
    const harmless = `%YAML 1.1\n---\n${pnpmWith('<<', '{name: qf-a}')}`;
    expect(check('pnpm-lock.yaml', `%YAML 1.1\n---\n${pnpmV9('1.2.5')}`, harmless)).toEqual(
      unparsable('pnpm-lock.yaml'),
    );
    expect(() => readPnpmLock(next)).toThrow();
  });

  it('refuses any directive, also without a merge', () => {
    const directive = `%YAML 1.2\n---\n${pnpmV9('1.2.6')}`;
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), directive)).toEqual(
      unparsable('pnpm-lock.yaml'),
    );
    const tagDirective = `%TAG !e! tag:example.com,2000:\n---\n${berry('1.2.6')}`;
    expect(check('yarn.lock', berry('1.2.5'), tagDirective)).toEqual(unparsable('yarn.lock'));
  });

  it('refuses a !!str tag in pnpm-lock.yaml and in Berry yarn.lock', () => {
    const pnpm = pnpmV9('1.2.6').replace('version: 2.0.0', 'version: !!str 2.0.0');
    expect(pnpm).not.toBe(pnpmV9('1.2.6'));
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), pnpm)).toEqual(unparsable('pnpm-lock.yaml'));
    const yarn = berry('1.2.6').replace('  version: 1.2.6\n', '  version: !!str 1.2.6\n');
    expect(yarn).not.toBe(berry('1.2.6'));
    expect(check('yarn.lock', berry('1.2.5'), yarn)).toEqual(unparsable('yarn.lock'));
  });

  it.each([
    ['null', 'null'],
    ['~', 'null'],
    ['123', 'a number'],
    ['true', 'a boolean'],
  ])('pnpm-lock.yaml: refuses the key %s, which pnpm reads as %s', (key) => {
    const next = pnpmV9('1.2.6').replace(
      '  autoInstallPeers: true\n',
      `  autoInstallPeers: true\n  ${key}: x\n`,
    );
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), next)).toEqual(unparsable('pnpm-lock.yaml'));
  });

  it('still reads quoted keys, and values that hold ! or %', () => {
    const quoted = pnpmV9('1.2.6').replace(
      '  autoInstallPeers: true\n',
      "  autoInstallPeers: true\n  '123': '!x'\n  'null': '%y'\n",
    );
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), quoted)).toEqual({ ok: true });
    const yarn = berry('1.2.6').replace(
      '  linkType: hard\n',
      '  linkType: hard\n  bin:\n    "123": "!x"\n    "null": "%y"\n',
    );
    expect(check('yarn.lock', berry('1.2.5'), yarn)).toEqual({ ok: true });
  });

  /**
   * The re-reviewer's merge-nest probe: d nested merges of a flow map of n keys, through the
   * !!merge tag or a %YAML 1.1 directive, each level copying the n keys inside it.
   */
  const mergeNest = (format: 'pnpm-tag' | 'pnpm-11' | 'berry-tag', a: string, big: boolean) => {
    const n = 103_000;
    const d = 100;
    const key = format === 'pnpm-11' ? '<<' : '!!merge <<';
    const keys = Array.from({ length: n }, (_, j) => `k${j}: v`);
    const inner = `{${keys.join(', ')}}`;
    const nest = `{${key}: `.repeat(d) + inner + '}'.repeat(d);
    if (format === 'berry-tag') {
      const lines = ['__metadata:', '  version: 8', '  cacheKey: 10', '', '"qf-a@npm:^1.2.5":'];
      lines.push(`  version: ${a}`, `  resolution: "qf-a@npm:${a}"`, '  checksum: 10/abc');
      if (big) lines.push(`  bin: ${nest}`);
      return lines.join('\n') + '\n';
    }
    const head = format === 'pnpm-11' ? '%YAML 1.1\n---\n' : '';
    const lines = [`${head}lockfileVersion: '9.0'`, '', 'importers:', '  .:', '    dependencies:'];
    lines.push('      qf-a:', '        specifier: ^1.2.5', `        version: ${a}`, '');
    lines.push('packages:', `  qf-a@${a}:`, '    resolution: {integrity: sha512-a}', '');
    lines.push('snapshots:', `  qf-a@${a}: {}`, '');
    if (big) lines.push(`settings: ${nest}`);
    return lines.join('\n') + '\n';
  };

  it.each(['pnpm-tag', 'pnpm-11', 'berry-tag'] as const)(
    'refuses the %s merge nest of 1.07 MiB in under 1 s',
    { timeout: 120_000 },
    (format) => {
      const path = format === 'berry-tag' ? 'yarn.lock' : 'pnpm-lock.yaml';
      const next = mergeNest(format, '1.2.6', true);
      expect(next.length).toBeGreaterThan(1.07 * 1024 * 1024);
      const { result, ms } = timedCheck(path, mergeNest(format, '1.2.5', false), next);
      expect(result).toEqual(unparsable(path));
      expect(ms).toBeLessThan(1000);
    },
  );

  it('still accepts ordinary pnpm v6, v9 and Berry lockfiles', () => {
    expect(check('pnpm-lock.yaml', pnpmV6('1.2.5'), pnpmV6('1.2.6'))).toEqual({ ok: true });
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), pnpmV9('1.2.6'))).toEqual({ ok: true });
    expect(check('yarn.lock', berry('1.2.5'), berry('1.2.6'))).toEqual({ ok: true });
  });
});

// ---------------------------------------------------------------------------------------------
// Ruling T3q (with T3p): plain scalars that js-yaml (pnpm) and `yaml` (YAML 1.2 core) may read
// differently

describe('Ruling T3q: no plain scalars the YAML readers may resolve differently in a lockfile', () => {
  const AMBIGUOUS = ['1_000', '0b101', '0o17', '0x1F', '0755', '.inf', '-.Inf', '.NaN'];
  const MORE = ['2001-12-14', '2001-12-14T21:59:43Z', '1:20', '190:20:30.15'];
  const unparsable = (path: string) => ({ ok: false, rule: 'unparsable', path });
  const pnpmSetting = (line: string) =>
    pnpmV9('1.2.6').replace('  autoInstallPeers: true\n', `  autoInstallPeers: true\n  ${line}\n`);
  const berryBin = (line: string) =>
    berry('1.2.6').replace('  linkType: hard\n', `  linkType: hard\n  bin:\n    ${line}\n`);

  it.each([...AMBIGUOUS, ...MORE])('refuses %s as a plain key or value', (plain) => {
    for (const line of [`${plain}: x`, `x: ${plain}`]) {
      expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), pnpmSetting(line))).toEqual(
        unparsable('pnpm-lock.yaml'),
      );
      expect(check('yarn.lock', berry('1.2.5'), berryBin(line))).toEqual(unparsable('yarn.lock'));
    }
  });

  it.each(['1_000', '0b101', '.inf', '2001-12-14', '1:20'])(
    'refuses %s as a plain version',
    (plain) => {
      const pnpm = pnpmV9('1.2.6').replace('version: 2.0.0', `version: ${plain}`);
      expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), pnpm)).toEqual(unparsable('pnpm-lock.yaml'));
      const yarn = berry('1.2.6').replace('  version: 1.2.6\n', `  version: ${plain}\n`);
      expect(check('yarn.lock', berry('1.2.5'), yarn)).toEqual(unparsable('yarn.lock'));
    },
  );

  it.each([...AMBIGUOUS, ...MORE])('reads %s quoted, as a key or a value', (plain) => {
    expect(parseYaml(`'${plain}': '${plain}'\nx: "${plain}"\n`, { lockfile: true })).toEqual({
      [plain]: plain,
      x: plain,
    });
    const quoted = `'${plain}': '${plain}'`;
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), pnpmSetting(quoted))).toEqual({ ok: true });
    expect(check('yarn.lock', berry('1.2.5'), berryBin(`"${plain}": "${plain}"`))).toEqual({
      ok: true,
    });
  });

  // Ruling T3r: an allowlist for plain scalars the core schema reads as no string.
  it.each(['+.5', '-.5', '.5', '1e3', '~', '+1', 'True', 'NULL', '0x1F', '0o17'])(
    'refuses %s, which is no plain -?digits(.digits), true, false or null (Ruling T3r)',
    (plain) => {
      for (const line of [`${plain}: x`, `x: ${plain}`]) {
        expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), pnpmSetting(line))).toEqual(
          unparsable('pnpm-lock.yaml'),
        );
        expect(check('yarn.lock', berry('1.2.5'), berryBin(line))).toEqual(unparsable('yarn.lock'));
      }
    },
  );

  it('reads 5.4, 8, -1, true, false, null and an empty value (Ruling T3r)', () => {
    const text = 'a: 5.4\nb: 8\nc: -1\nd: true\ne: false\nf: null\ng:\n';
    expect(parseYaml(text, { lockfile: true })).toEqual({
      a: 5.4,
      b: 8,
      c: -1,
      d: true,
      e: false,
      f: null,
      g: null,
    });
    expect(parseYaml(text, { lockfile: true, schema: 'failsafe' })).toEqual({
      a: '5.4',
      b: '8',
      c: '-1',
      d: 'true',
      e: 'false',
      f: 'null',
      g: '',
    });
    const lines = 'x5: 5.4\n  x8: 8\n  xt: true\n  xn: null';
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), pnpmSetting(lines))).toEqual({ ok: true });
    expect(
      check('yarn.lock', berry('1.2.5'), berryBin(lines.replaceAll('\n  ', '\n    '))),
    ).toEqual({ ok: true });
  });

  it('reads packages plainly named yes and n, and y, no, on, off (Ruling T4c)', () => {
    const packages = [
      '',
      '  n@9.0.0:',
      '    resolution: {integrity: sha512-n}',
      '',
      '  yes@1.0.0:',
      '    resolution: {integrity: sha512-yes}',
      '',
    ].join('\n');
    const snapshots = [
      '',
      '  n@9.0.0:',
      '    dependencies:',
      '      yes: 1.0.0',
      '',
      '  yes@1.0.0: {}',
      '',
    ].join('\n');
    const at = (v: string) => pnpmV9(v, packages, snapshots);
    expect(at('1.2.6')).toContain('      yes: 1.0.0\n');
    expect(check('pnpm-lock.yaml', at('1.2.5'), at('1.2.6'))).toEqual({ ok: true });
    const words = 'n: yes\n  y: No\n  on: OFF';
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), pnpmSetting(words))).toEqual({ ok: true });
    const bins = berryBin('n: n\n    yes: yes\n    on: off');
    expect(check('yarn.lock', berry('1.2.5'), bins)).toEqual({ ok: true });
    expect(parseYaml('n: yes\ny: No\n', { lockfile: true })).toEqual({ n: 'yes', y: 'No' });
  });

  it('reads a Berry checksum of plain hex that starts with 0b, 0e or digits', () => {
    const hex = (head: string) => head + 'a1'.repeat(64 - head.length / 2);
    for (const head of ['0b08b5', '0e12', '1e34', '0755', '2001']) {
      const lock = berry('1.2.6').replace('checksum: 10c0/a1.2.6', `checksum: ${hex(head)}`);
      expect(lock).not.toBe(berry('1.2.6'));
      expect(check('yarn.lock', berry('1.2.5'), lock)).toEqual({ ok: true });
    }
  });

  it('still reads the plain values real lockfiles hold', () => {
    const text = [
      'lockfileVersion: 5.4',
      'a: true',
      'b: false',
      'c: 1.2.6',
      'd: sha512-abc==',
      'e: 10c0/abc',
      'f: node',
      'g: 0.0.0-use.local',
      'h: 0',
      'i: 10',
      'j: 2.0.0(react@18.0.0)',
      'k: link:../x',
      'l: ^1.2.5',
      '',
    ].join('\n');
    expect(parseYaml(text, { lockfile: true })).toMatchObject({
      lockfileVersion: 5.4,
      a: true,
      c: '1.2.6',
      e: '10c0/abc',
      h: 0,
      j: '2.0.0(react@18.0.0)',
    });
  });
});

// ---------------------------------------------------------------------------------------------
// Ruling T4b: pnpm 11's boot document before the lockfile

describe('Ruling T4b: a pnpm lockfile with a boot document', () => {
  const unparsable = { ok: false, rule: 'unparsable', path: 'pnpm-lock.yaml' };
  const otherChange = { ok: false, rule: 'other_change', path: 'pnpm-lock.yaml' };
  /**
   * The boot document of gitea's pnpm-lock.yaml (pnpm 12.6.0, `"packageManager": "pnpm@12.6.0"`),
   * two of its fourteen platform packages kept.
   */
  const BOOT = [
    '---',
    "lockfileVersion: '9.0'",
    '',
    'importers:',
    '',
    '  .:',
    '    configDependencies: {}',
    '    packageManagerDependencies:',
    '      pnpm:',
    '        specifier: 12.6.0',
    '        version: 12.6.0',
    '',
    'packages:',
    '',
    "  '@pnpm/exe.linux-x64@12.6.0':",
    '    resolution: {integrity: sha512-qFWBneHJAJ73W4whtbaFOL1M/7DBC6ILHXuxc7ZPtEhfPuT1zeZiGrmKHoMAfJA+mcm6xhOFljqVTUS+00Jabw==}',
    '    cpu: [x64]',
    '    os: [linux]',
    '    libc: [glibc]',
    '',
    "  '@pnpm/exe.win32-x64@12.6.0':",
    '    resolution: {integrity: sha512-L2tuyrD2+Imgxs3VK/ST/2L3xD6vDP0ktJQxM0TaGw7TbAQEMq+RMc8iK6Ew7Id579uzjJe8jSfJID2ZGsOHCA==}',
    '    cpu: [x64]',
    '    os: [win32]',
    '',
    '  pnpm@12.6.0:',
    '    resolution: {integrity: sha512-PvaPlRyxEawgS0paFvCy3fDaVqluBBPoHYVdnwtV75JnFHCQKOHNAMQFwsX7e56OxNxGd3yAXQNzwvL/AP0g7A==}',
    "    engines: {node: '>=18.*'}",
    '    hasBin: true',
    '',
    'snapshots:',
    '',
    "  '@pnpm/exe.linux-x64@12.6.0':",
    '    optional: true',
    '',
    "  '@pnpm/exe.win32-x64@12.6.0':",
    '    optional: true',
    '',
    '  pnpm@12.6.0:',
    '    optionalDependencies:',
    "      '@pnpm/exe.linux-x64': 12.6.0",
    "      '@pnpm/exe.win32-x64': 12.6.0",
    '',
    '',
  ].join('\n');
  const twoDocuments = (qfA: string, boot = BOOT) => `${boot}---\n${pnpmV9(qfA)}`;

  it('accepts the package bumped in the lockfile document, the boot document unchanged', () => {
    expect(check('pnpm-lock.yaml', twoDocuments('1.2.5'), twoDocuments('1.2.6'))).toEqual({
      ok: true,
    });
    // Only the lockfile document is read for entries.
    expect(shape(readPnpmLock(twoDocuments('1.2.6'))).map((e) => e.name)).toEqual([
      '@scope/qf-b',
      'qf-a',
    ]);
    expect(check('pnpm-lock.yaml', twoDocuments('1.2.5'), twoDocuments('1.2.5'))).toMatchObject({
      rule: 'below_target',
    });
  });

  it.each([
    ['the pnpm pin', BOOT.replaceAll('12.6.0', '12.7.0')],
    [
      'an added config dependency',
      BOOT.replace(
        '    configDependencies: {}',
        '    configDependencies:\n      evil:\n        specifier: 1.0.0\n        version: 1.0.0+sha512-e',
      ),
    ],
    ['a changed integrity', BOOT.replace('sha512-PvaP', 'sha512-EvaP')],
    ['a dropped platform package', BOOT.replace("      '@pnpm/exe.win32-x64': 12.6.0\n", '')],
  ])('refuses a changed boot document (%s) as other_change', (_name, boot) => {
    expect(boot).not.toBe(BOOT);
    expect(check('pnpm-lock.yaml', twoDocuments('1.2.5'), twoDocuments('1.2.6', boot))).toEqual(
      otherChange,
    );
  });

  it('refuses a boot document the base has and the upload drops as other_change', () => {
    expect(check('pnpm-lock.yaml', twoDocuments('1.2.5'), pnpmV9('1.2.6'))).toEqual(otherChange);
  });

  it('refuses a boot document a one-document base does not have as unparsable', () => {
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), twoDocuments('1.2.6'))).toEqual(unparsable);
  });

  it('refuses three documents as unparsable', () => {
    const three = `${BOOT}---\n${BOOT.slice('---\n'.length)}---\n${pnpmV9('1.2.6')}`;
    expect(check('pnpm-lock.yaml', twoDocuments('1.2.5'), three)).toEqual(unparsable);
    expect(check('pnpm-lock.yaml', three, three)).toEqual(unparsable);
    expect(() => readPnpmLock(three)).toThrow(/more than 2 YAML documents/);
  });

  it('refuses a first document that is no boot document, and boot dependencies in the lockfile', () => {
    const twoLockfiles = `---\n${pnpmV9('1.2.5')}---\n${pnpmV9('1.2.6')}`;
    expect(check('pnpm-lock.yaml', twoLockfiles, twoLockfiles)).toEqual(unparsable);
    const settingsOnly = BOOT.replace(
      /importers:[\s\S]*?\n\npackages:/,
      'importers:\n\n  .: {}\n\npackages:',
    );
    expect(settingsOnly).not.toBe(BOOT);
    expect(
      check(
        'pnpm-lock.yaml',
        twoDocuments('1.2.5', settingsOnly),
        twoDocuments('1.2.6', settingsOnly),
      ),
    ).toEqual(unparsable);
    const smuggled = pnpmV9('1.2.6').replace(
      '    dependencies:\n      qf-b:',
      '    configDependencies:\n      evil:\n        specifier: 1.0.0\n        version: 1.0.0+sha512-e\n    dependencies:\n      qf-b:',
    );
    expect(smuggled).not.toBe(pnpmV9('1.2.6'));
    expect(check('pnpm-lock.yaml', pnpmV9('1.2.5'), smuggled)).toEqual(unparsable);
    expect(check('pnpm-lock.yaml', twoDocuments('1.2.5'), `${BOOT}---\n${smuggled}`)).toEqual(
      unparsable,
    );
  });

  it.each([
    ['an anchor', ['configDependencies: {}', 'configDependencies: &c {}']],
    ['a tag', ['configDependencies: {}', 'configDependencies: !!map {}']],
    ['a non-string plain scalar', ['specifier: 12.6.0', 'specifier: 0x1F']],
    ['a timestamp-like plain scalar', ['specifier: 12.6.0', 'specifier: 2026-11-18']],
  ])('applies the token rules to the boot document: %s → unparsable', (_name, [from, to]) => {
    const boot = BOOT.replace(from ?? '', to ?? '');
    expect(boot).not.toBe(BOOT);
    expect(check('pnpm-lock.yaml', twoDocuments('1.2.5'), twoDocuments('1.2.6', boot))).toEqual(
      unparsable,
    );
  });

  it('reads the jsLockfileAdditions of a two-document lockfile', () => {
    const change = {
      path: 'pnpm-lock.yaml',
      base: twoDocuments('1.2.5'),
      next: twoDocuments('1.2.6'),
    };
    expect(jsLockfileAdditions(change)?.map((e) => `${e.name}@${e.version}`)).toEqual([
      'qf-a@1.2.6',
    ]);
  });
});
