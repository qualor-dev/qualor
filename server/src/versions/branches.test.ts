import { describe, expect, it } from 'vitest';
import { branchMatcher, branchMatches, normalizePatterns, validGlob } from './branches';
import { isTrackedBranch, type VulnerabilitySettings } from './settings';

describe('branchMatches', () => {
  it.each([
    ['release/2.3', true],
    ['release/2.3/hotfix', false],
    ['feature/x', false],
  ])('release/* vs %s', (name, expected) => {
    expect(branchMatches(name, ['release/*'])).toBe(expected);
  });

  it('matches dot branches and returns false for no patterns', () => {
    expect(branchMatches('.hidden', ['*'])).toBe(true);
    expect(branchMatches('main', [])).toBe(false);
  });

  it('still matches after more pattern lists than the cache holds', () => {
    for (let i = 0; i <= 1_000; i++) expect(branchMatches(`b${i}`, [`b${i}`])).toBe(true);
    expect(branchMatches('b0', ['b0'])).toBe(true);
    expect(branchMatches('b1', ['b0'])).toBe(false);
    expect(branchMatches('b1000', ['b1000'])).toBe(true);
  });
});

describe('branchMatcher', () => {
  it.each([[['release/*']], [['**']]])('answers as branchMatches for %j', (patterns) => {
    const match = branchMatcher(patterns);
    for (const name of ['release/1.x', 'main', '.hidden/x']) {
      expect(match(name), name).toBe(branchMatches(name, patterns));
    }
  });

  it('matches nothing without patterns', () => {
    const match = branchMatcher([]);
    for (const name of ['main', 'release/1.x', '']) expect(match(name), name).toBe(false);
  });
});

describe('normalizePatterns', () => {
  it('trims, drops empties and dedupes', () => {
    expect(normalizePatterns([' release/* ', '', 'release/*', '  '])).toEqual(['release/*']);
  });
});

describe('validGlob', () => {
  it.each(['release/*', 'hotfix/**', 'v1.[0-9]*', 'f/{a,b}', '.hidden', 'main'])(
    'takes %s',
    (pattern) => {
      expect(validGlob(pattern)).toBe(true);
    },
  );

  it.each(['release/[z-a]*', 'a{', '[z-a]', 'a\u0001b', 'a\u007fb', 'tab\there'])(
    'refuses %j',
    (pattern) => {
      expect(validGlob(pattern)).toBe(false);
    },
  );
});

describe('isTrackedBranch', () => {
  const settings: VulnerabilitySettings = {
    enabled: true,
    branchPatterns: ['release/*'],
    versionRule: { kind: 'lines', lines: 5 },
    labelVersions: false,
  };
  it.each([
    [{ name: 'main', isMain: true, kind: 'branch' }, true],
    [{ name: 'release/1.0', isMain: false, kind: 'branch' }, true],
    [{ name: 'feature/x', isMain: false, kind: 'branch' }, false],
    [{ name: 'release/1.0', isMain: false, kind: 'merge_request' }, false],
    [{ name: 'main', isMain: true, kind: 'merge_request' }, true],
  ])('%j', (branch, expected) => {
    expect(isTrackedBranch(settings, branch)).toBe(expected);
  });
});
