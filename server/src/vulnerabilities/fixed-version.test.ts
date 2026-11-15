import { describe, expect, it } from 'vitest';

import { compareFixedVersions, highestFixedVersion } from './fixed-version';

describe('compareFixedVersions', () => {
  it.each([
    // B2-k and B2-q
    ['2', '4.9'],
    ['4.9', '4.17'],
    ['1.0rc1', '1.0'],
    ['1.0', '1.0.1'],
    ['9.9', '1:0.1'],
    ['4.17.0-rc.1', '4.17.0'],
    ['1.0beta2', '1.0RC1'],
    ['2.16.0', '2.17.1, 2.12.4'],
    // real strings
    ['4.17.5', '4.17.21'],
    ['2.13.4', '2.13.4.2'],
    ['4.1.68.Final', '4.1.94.Final'],
    ['31.1-jre', '32.0.0-jre'],
    ['v0.0.0-20211202192323-5770296d904e', 'v0.0.0-20220314234659-1baeb1ce4c0b'],
    ['1.123456789012345678900', '1.123456789012345678901'],
    ['1.2', '1.02.1'],
    // Accepted limits (B2-k): a letter run sorts before the end, so a post-release or a
    // `.RELEASE` suffix sorts below the bare version.
    ['2.0.post1', '2.0'],
    ['5.2.20.RELEASE', '5.2.20'],
  ])('puts %s below %s', (lower, higher) => {
    expect(compareFixedVersions(lower, higher)).toBeLessThan(0);
    expect(compareFixedVersions(higher, lower)).toBeGreaterThan(0);
  });

  it('answers 0 only for equal strings', () => {
    expect(compareFixedVersions('1.0', '1.0')).toBe(0);
    expect(compareFixedVersions('1.0', '1.00')).not.toBe(0);
  });
});

describe('highestFixedVersion', () => {
  it('takes the greatest version, whatever the order', () => {
    expect(highestFixedVersion(['4.9.5', null, '4.17.2'])).toBe('4.17.2');
    expect(highestFixedVersion(['4.17.2', null, '4.9.5'])).toBe('4.17.2');
  });

  it('is null without a version', () => {
    expect(highestFixedVersion([])).toBeNull();
    expect(highestFixedVersion([null])).toBeNull();
  });
});
