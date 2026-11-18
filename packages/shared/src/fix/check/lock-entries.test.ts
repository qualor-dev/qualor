import { describe, expect, it } from 'vitest';
import {
  belowTarget,
  checkLockEntries,
  lockfileBelowTarget,
  newLockEntries,
  sourceOrigin,
} from './lock-entries';
import type { FixTarget, LockEntry } from './types';

const LOCK = 'package-lock.json';
const targets: FixTarget[] = [
  { installed: '1.2.5', target: '1.2.6', lockfile: LOCK },
  { installed: '2.0.1', target: '2.0.3', lockfile: LOCK },
];

describe('belowTarget', () => {
  it('is false when every resolved version is at least the target of its line', () => {
    expect(belowTarget(['1.2.6', '2.0.3'], targets, 'semver')).toBe(false);
  });

  it('is true when a version still lies between an installed version and its target', () => {
    expect(belowTarget(['1.2.6', '2.0.2'], targets, 'semver')).toBe(true);
  });

  it('is true for a new version below the smallest target, false when the base had it', () => {
    expect(belowTarget(['1.0.0', '1.2.6', '2.0.3'], targets, 'semver')).toBe(true);
    expect(
      belowTarget(['1.0.0', '1.2.6', '2.0.3'], targets, 'semver', ['1.0.0', '1.2.5', '2.0.1']),
    ).toBe(false);
  });

  it('counts a new version that does not parse as below (fail closed), an old one not', () => {
    expect(belowTarget(['1.2.6', 'not-a-version'], targets, 'semver')).toBe(true);
    expect(belowTarget(['1.2.6', 'not-a-version'], targets, 'semver', ['not-a-version'])).toBe(
      false,
    );
  });

  it('is false without targets', () => {
    expect(belowTarget(['1.0.0'], [], 'semver')).toBe(false);
  });

  it('is true for a new version below the target of its own line (Ruling T3a)', () => {
    expect(belowTarget(['1.2.6', '2.0.0', '2.0.3'], targets, 'semver')).toBe(true);
    expect(belowTarget(['1.2.6', '2.0.0', '2.0.3'], targets, 'semver', ['2.0.0'])).toBe(false);
    expect(belowTarget(['1.2.6', '2.0.5'], targets, 'semver')).toBe(false);
    expect(belowTarget(['1.2.6', '2.0.3', '3.0.0'], targets, 'semver')).toBe(false);
  });

  it('reads line 0 by its minor (Ruling T3a)', () => {
    const zero: FixTarget[] = [{ installed: '0.4.1', target: '0.4.3', lockfile: LOCK }];
    expect(belowTarget(['0.4.2'], zero, 'semver', ['0.4.1'])).toBe(true);
    expect(belowTarget(['0.5.0'], zero, 'semver', ['0.4.1'])).toBe(false);
    const twoLines: FixTarget[] = [
      { installed: '0.3.1', target: '0.3.4', lockfile: LOCK },
      { installed: '0.4.5', target: '0.4.7', lockfile: LOCK },
    ];
    expect(belowTarget(['0.3.4', '0.4.2', '0.4.7'], twoLines, 'semver')).toBe(true);
    expect(belowTarget(['0.3.4', '0.4.7', '0.5.0'], twoLines, 'semver')).toBe(false);
  });
});

const entry = (over: Partial<LockEntry> = {}): LockEntry => ({
  name: 'qf-a',
  version: '1.2.6',
  source: 'https://registry.npmjs.org/qf-a/-/qf-a-1.2.6.tgz',
  kind: 'registry',
  integrity: 'sha512-new',
  dependencies: [],
  dependents: [],
  ...over,
});

const baseEntries: LockEntry[] = [
  entry({ version: '1.2.5', source: 'https://npm.example.com/qf-a/-/qf-a-1.2.5.tgz' }),
  entry({
    name: 'qf-git',
    version: '1.0.0',
    source: 'git+https://github.com/x/y.git#1',
    kind: 'git',
  }),
];

const ctx = {
  family: 'js',
  packageName: 'qf-a',
  targets,
  lockfile: 'apps/web/package-lock.json',
  publicHosts: ['https://registry.npmjs.org'],
  integrityRequired: true,
  reachableOnly: false,
} as const;

describe('checkLockEntries', () => {
  it('accepts unchanged entries, whatever their kind', () => {
    expect(checkLockEntries(baseEntries, baseEntries, ctx)).toEqual({ ok: true });
  });

  it('accepts a new registry entry on a host of the base or a public registry', () => {
    const onBaseHost = entry({ source: 'https://npm.example.com/qf-a/-/qf-a-1.2.6.tgz' });
    expect(checkLockEntries(baseEntries, [...baseEntries, onBaseHost], ctx)).toEqual({ ok: true });
    expect(checkLockEntries(baseEntries, [...baseEntries, entry()], ctx)).toEqual({ ok: true });
  });

  it('compares scheme and host only, case-insensitively', () => {
    const next = entry({ source: 'HTTPS://NPM.example.com/other/path.tgz' });
    expect(checkLockEntries(baseEntries, [next], ctx)).toEqual({ ok: true });
  });

  it.each([
    'https://registry.npmjs.org@registry.npmjs.org/qf-a/-/qf-a-1.2.6.tgz',
    'https://user:pw@npm.example.com/qf-a/-/qf-a-1.2.6.tgz',
    'https://registry.npmjs.or%67/qf-a/-/qf-a-1.2.6.tgz',
    'https://npm.example.co%6D/qf-a/-/qf-a-1.2.6.tgz',
    'https://registry.npmjs.org\uFF0E/qf-a/-/qf-a-1.2.6.tgz',
    'https://r\u0435gistry.npmjs.org/qf-a/-/qf-a-1.2.6.tgz',
    'https://registry.npmjs.org;.evil.example/qf-a/-/qf-a-1.2.6.tgz',
  ])('refuses a source whose raw host has user info, %, or other characters: %j (C3)', (source) => {
    expect(checkLockEntries(baseEntries, [entry({ source })], ctx)).toMatchObject({
      rule: 'new_source',
    });
  });

  it('takes the allowed origins from the base’s registry entries only (Ruling T3f)', () => {
    const base = [
      ...baseEntries,
      entry({ name: 'qf-y', source: 'https://github.com/x/y.git', kind: 'git' }),
    ];
    const raw = entry({ source: 'https://github.com/x/raw/main/qf-a/-/qf-a-1.2.6.tgz' });
    expect(checkLockEntries(base, [raw], ctx)).toMatchObject({ rule: 'new_source' });
  });

  it('refuses a new alias (slot and name differ) unless the base has the same pair (C1)', () => {
    const alias = entry({
      slot: 'qf-a',
      name: 'evil',
      source: 'https://registry.npmjs.org/evil/-/evil-1.2.6.tgz',
    });
    expect(checkLockEntries(baseEntries, [alias], ctx)).toMatchObject({ rule: 'source_kind' });
    const base = [
      ...baseEntries,
      entry({ slot: 'qf-c', name: 'qf-d', version: '0.9.0', source: null }),
    ];
    const bumped = entry({ slot: 'qf-c', name: 'qf-d', version: '1.0.0', source: null });
    expect(checkLockEntries(base, [bumped], ctx)).toEqual({ ok: true });
    expect(checkLockEntries(base, [{ ...bumped, slot: 'qf-e' }], ctx)).toMatchObject({
      rule: 'source_kind',
    });
  });

  it.each([
    'https://evil.example/qf-a/-/qf-a-1.2.6.tgz',
    'git+https://registry.npmjs.org/qf-a/-/qf-a-1.2.6.tgz',
    'https://registry.npmjs.org@evil.example/qf-a/-/qf-a-1.2.6.tgz',
    'https://evil.example\\@registry.npmjs.org/qf-a/-/qf-a-1.2.6.tgz',
    'https://registry.npmjs.org:8443/qf-a/-/qf-a-1.2.6.tgz',
    'https://registry.npmjs.org.evil.example/qf-a/-/qf-a-1.2.6.tgz',
  ])('refuses a new entry from a host the lockfile did not use: %s', (source) => {
    expect(checkLockEntries(baseEntries, [entry({ source })], ctx)).toEqual({
      ok: false,
      rule: 'new_source',
      path: 'apps/web/package-lock.json',
    });
  });

  it('refuses an existing package and version moved to a new host', () => {
    const moved = entry({ version: '1.2.5', source: 'https://evil.example/qf-a-1.2.5.tgz' });
    expect(checkLockEntries(baseEntries, [moved], ctx)).toMatchObject({ rule: 'new_source' });
  });

  it.each(['git', 'file', 'link', 'tarball', 'path', 'other'] as const)(
    'refuses a new %s entry before looking at its host',
    (kind) => {
      const next = entry({ kind, source: 'https://registry.npmjs.org/x.tgz' });
      expect(checkLockEntries(baseEntries, [next], ctx)).toMatchObject({ rule: 'source_kind' });
    },
  );

  it('refuses a new entry without integrity only where the lockfile has integrity', () => {
    const bare = entry({ integrity: null });
    expect(checkLockEntries(baseEntries, [bare], ctx)).toMatchObject({
      rule: 'missing_integrity',
    });
    expect(checkLockEntries(baseEntries, [bare], { ...ctx, integrityRequired: false })).toEqual({
      ok: true,
    });
  });

  it('checks no host for an entry without a source', () => {
    expect(checkLockEntries(baseEntries, [entry({ source: null })], ctx)).toEqual({ ok: true });
  });

  it.each([
    'https:\\\\evil.example/qf-a/-/qf-a-1.2.6.tgz',
    'https:/evil.example/qf-a/-/qf-a-1.2.6.tgz',
    ' https://evil.example/qf-a/-/qf-a-1.2.6.tgz',
  ])('reads %j as a URL does (Ruling T3c)', (source) => {
    expect(checkLockEntries(baseEntries, [entry({ source })], ctx)).toMatchObject({
      rule: 'new_source',
    });
  });

  it.each(['garbage', '../qf-a-1.2.6.tgz', 'npm:1.2.6', 'https://', ''])(
    'refuses a new registry entry whose source %j gives no origin (Ruling T3c)',
    (source) => {
      expect(checkLockEntries(baseEntries, [entry({ source })], ctx)).toMatchObject({
        rule: 'new_source',
      });
    },
  );

  it('checks an entry whose integrity or kind changed as new (Ruling T3b)', () => {
    const base = [entry({ integrity: 'sha512-old' })];
    expect(checkLockEntries(base, [entry({ integrity: 'sha512-other' })], ctx)).toEqual({
      ok: true,
    });
    expect(checkLockEntries(base, [entry({ integrity: null })], ctx)).toMatchObject({
      rule: 'missing_integrity',
    });
    expect(
      checkLockEntries(base, [entry({ integrity: 'sha512-old', kind: 'other' })], ctx),
    ).toMatchObject({
      rule: 'source_kind',
    });
  });
});

describe('checkLockEntries: reachability (Ruling T3e)', () => {
  const on = { ...ctx, reachableOnly: true };
  const evil = entry({
    name: 'evil',
    version: '1.0.0',
    source: 'https://registry.npmjs.org/evil/-/evil-1.0.0.tgz',
  });
  const named = (name: string, dependencies: string[] = [], over: Partial<LockEntry> = {}) =>
    entry({ name, version: '1.0.0', source: null, dependencies, ...over });

  it('refuses a new entry that nothing reachable from the package depends on', () => {
    expect(checkLockEntries(baseEntries, [entry(), evil], on)).toEqual({
      ok: false,
      rule: 'new_dependency',
      path: 'apps/web/package-lock.json',
    });
    const other = named('qf-b', ['evil']);
    expect(checkLockEntries([...baseEntries, other], [entry(), other, evil], on)).toMatchObject({
      rule: 'new_dependency',
    });
    expect(checkLockEntries(baseEntries, [entry(), evil], ctx)).toEqual({ ok: true });
  });

  it('accepts a new dependency of the package, and of that dependency, also through slots', () => {
    const chain = [named('qf-y'), named('qf-x', ['qf-y']), entry({ dependencies: ['qf-x'] })];
    expect(checkLockEntries(baseEntries, chain, on)).toEqual({ ok: true });
    const slotted = entry({ slot: 'qf-a', name: 'qf-a', version: '1.2.6', dependencies: ['qf-x'] });
    expect(checkLockEntries(baseEntries, [slotted, named('qf-x')], on)).toEqual({ ok: true });
    const base = [...baseEntries, named('qf-d', [], { slot: 'qf-alias', version: '0.9.0' })];
    const alias = named('qf-d', [], { slot: 'qf-alias' });
    const viaAlias = [entry({ dependencies: ['qf-alias'] }), alias];
    expect(checkLockEntries(base, viaAlias, on)).toEqual({ ok: true });
    expect(checkLockEntries(base, [entry(), alias], on)).toMatchObject({
      rule: 'new_dependency',
    });
  });
});

describe('checkLockEntries: dependencies of existing packages (Rulings T3j, T3l)', () => {
  const x = (dependencies: string[], over: Partial<LockEntry> = {}) =>
    entry({ name: 'qf-x', version: '1.0.0', source: null, dependencies, ...over });

  it('refuses an existing package that gains a dependency, whatever its version or integrity', () => {
    expect(checkLockEntries([...baseEntries, x([])], [entry(), x(['evil'])], ctx)).toEqual({
      ok: false,
      rule: 'other_change',
      path: 'apps/web/package-lock.json',
    });
    const bumped = x(['qf-y', 'evil'], { version: '1.0.1' });
    expect(checkLockEntries([x(['qf-y'])], [entry(), bumped], ctx)).toMatchObject({
      rule: 'other_change',
    });
    const retagged = x(['evil'], { integrity: 'sha512-new sha1-bogus' });
    expect(checkLockEntries([x([])], [entry(), retagged], ctx)).toMatchObject({
      rule: 'other_change',
    });
  });

  it('accepts the same names in any order, fewer names, and a new version that drops one', () => {
    expect(checkLockEntries([x(['qf-a', 'qf-y'])], [entry(), x(['qf-y', 'qf-a'])], ctx)).toEqual({
      ok: true,
    });
    expect(checkLockEntries([x(['qf-y'])], [entry(), x([])], ctx)).toEqual({ ok: true });
    const dropped = x([], { version: '1.0.1' });
    expect(checkLockEntries([x(['qf-y'])], [entry(), dropped], ctx)).toEqual({ ok: true });
  });

  it('refuses an existing version of the package that gains a dependency, not a new one', () => {
    const own = (version: string, dependencies: string[]) => entry({ version, dependencies });
    expect(checkLockEntries([own('2.0.3', [])], [own('2.0.3', ['evil'])], ctx)).toMatchObject({
      rule: 'other_change',
    });
    expect(checkLockEntries([own('1.2.5', [])], [own('1.2.6', ['qf-x'])], ctx)).toEqual({
      ok: true,
    });
  });
});
describe('checkLockEntries: brand-new names (Ruling T3m)', () => {
  const on = { ...ctx, reachableOnly: true };
  const named = (name: string, dependencies: string[] = [], over: Partial<LockEntry> = {}) =>
    entry({ name, version: '1.0.0', source: null, dependencies, ...over });
  const existing = named('qf-x', ['opt-peer']);
  const base = [...baseEntries, existing];

  it('refuses a brand-new name reached only through an existing package', () => {
    const next = [entry({ dependencies: ['qf-x'] }), existing, named('opt-peer')];
    expect(checkLockEntries(base, next, on)).toEqual({
      ok: false,
      rule: 'new_dependency',
      path: 'apps/web/package-lock.json',
    });
  });

  it('reaches brand-new names from the package and from other brand-new names', () => {
    const next = [
      entry({ dependencies: ['qf-x', 'qf-z'] }),
      existing,
      named('qf-z', ['qf-w']),
      named('qf-w'),
    ];
    expect(checkLockEntries(base, next, on)).toEqual({ ok: true });
  });

  it('still reaches a name the base has through an existing package', () => {
    const before = [
      ...baseEntries,
      named('qf-x', ['qf-y']),
      named('qf-y', [], { version: '0.9.0' }),
    ];
    const next = [entry({ dependencies: ['qf-x'] }), named('qf-x', ['qf-y']), named('qf-y')];
    expect(checkLockEntries(before, next, on)).toEqual({ ok: true });
  });
});

describe('newLockEntries (Ruling T3i)', () => {
  it('lists the entries of next that the base does not have, with slot, name and version', () => {
    const alias = entry({ slot: 'qf-c', name: 'qf-d', version: '1.0.0', source: null });
    const added = newLockEntries(baseEntries, [...baseEntries, entry(), alias]);
    expect(added.map((e) => [e.slot, e.name, e.version])).toEqual([
      [undefined, 'qf-a', '1.2.6'],
      ['qf-c', 'qf-d', '1.0.0'],
    ]);
  });
});

describe('sourceOrigin', () => {
  it.each([
    ['https://registry.npmjs.org/a/-/a-1.0.0.tgz', 'https://registry.npmjs.org'],
    ['git+SSH://GitHub.com/x/y.git', 'git+ssh://github.com'],
    ['git+ssh://git@github.com/x/y.git', null],
    ['https://a:b@host:8080?x', null],
    ['https://[::1]:8080/a', 'https://[::1]:8080'],
    ['https://registry.yarnpkg.co%6D/a', null],
    ['https://registry.npmjs.org:443/a', 'https://registry.npmjs.org'],
    ['https://evil\\@registry.npmjs.org/', 'https://evil'],
    ['https:\\\\evil.example/x', 'https://evil.example'],
    ['https:/evil.example/x', 'https://evil.example'],
    ['https:evil.example/x', 'https://evil.example'],
    ['  https://evil.example/x  ', 'https://evil.example'],
    ['file:../x', null],
    ['github:x/y', null],
    ['npm:1.2.6', null],
    ['garbage', null],
  ])('%j → %s', (source, origin) => {
    expect(sourceOrigin(source)).toBe(origin);
  });
});

describe('lockfileBelowTarget (Ruling F14)', () => {
  const lockEntries = (...versions: string[]): LockEntry[] =>
    versions.map((version) => entry({ version }));

  it('uses only the targets of that lockfile and skips a lockfile without any', () => {
    const other = { family: 'js', packageName: 'qf-a', targets } as const;
    expect(lockfileBelowTarget(lockEntries('1.2.5'), lockEntries('1.2.5'), other, LOCK)).toBe(true);
    expect(
      lockfileBelowTarget(lockEntries('1.2.5'), lockEntries('1.2.5'), other, 'web/' + LOCK),
    ).toBe(false);
  });

  it('counts an entry in the package’s slot as the package (C1)', () => {
    const fixCtx = { family: 'js', packageName: 'qf-a', targets } as const;
    const slotted = [entry({ slot: 'qf-a', name: 'evil', version: '1.2.5' })];
    expect(
      lockfileBelowTarget(
        lockEntries('1.2.5'),
        [...lockEntries('1.2.6'), ...slotted],
        fixCtx,
        LOCK,
      ),
    ).toBe(true);
  });

  it('reads only the package’s versions, and the base’s as old', () => {
    const fixCtx = { family: 'js', packageName: 'qf-a', targets } as const;
    const base = [...lockEntries('1.2.5'), entry({ name: 'qf-b', version: '0.1.0' })];
    const next = [...lockEntries('1.2.6'), entry({ name: 'qf-b', version: '0.1.0' })];
    expect(lockfileBelowTarget(base, next, fixCtx, LOCK)).toBe(false);
    expect(
      lockfileBelowTarget(lockEntries('1.0.0'), lockEntries('1.0.0', '1.2.6'), fixCtx, LOCK),
    ).toBe(false);
    expect(
      lockfileBelowTarget(lockEntries('1.2.5'), lockEntries('1.0.0', '1.2.6'), fixCtx, LOCK),
    ).toBe(true);
  });
});
