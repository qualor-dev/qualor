import { describe, expect, it } from 'vitest';
import { branchMatches, normalizePatterns } from './branches';
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
});

describe('normalizePatterns', () => {
  it('trims, drops empties and dedupes', () => {
    expect(normalizePatterns([' release/* ', '', 'release/*', '  '])).toEqual(['release/*']);
  });
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
