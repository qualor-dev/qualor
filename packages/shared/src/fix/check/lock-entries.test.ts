import { describe, expect, it } from 'vitest';
import { belowTarget, checkLockEntries, lockfileBelowTarget, sourceOrigin } from './lock-entries';
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

  it('compares scheme and host only, case-insensitively and without user info', () => {
    const next = entry({ source: 'HTTPS://user:pw@NPM.example.com/other/path.tgz' });
    expect(checkLockEntries(baseEntries, [next], ctx)).toEqual({ ok: true });
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

  it('checks no host for an entry without a URL source', () => {
    expect(checkLockEntries(baseEntries, [entry({ source: null })], ctx)).toEqual({ ok: true });
    expect(checkLockEntries(baseEntries, [entry({ source: 'npm:1.2.6' })], ctx)).toEqual({
      ok: true,
    });
  });
});

describe('sourceOrigin', () => {
  it.each([
    ['https://registry.npmjs.org/a/-/a-1.0.0.tgz', 'https://registry.npmjs.org'],
    ['git+SSH://git@GitHub.com/x/y.git', 'git+ssh://github.com'],
    ['https://a:b@host:8080?x', 'https://host:8080'],
    ['https://evil\\@registry.npmjs.org/', 'https://evil'],
    ['file:../x', null],
    ['github:x/y', null],
    ['https:evil.example/x', null],
  ])('%s → %s', (source, origin) => {
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
