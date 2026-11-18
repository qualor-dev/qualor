import { describe, expect, it } from 'vitest';
import { chooseTarget } from './target';
import {
  compareVersions,
  isGreater,
  isPrerelease,
  parseFixedVersions,
  releaseLine,
  sameVersion,
  schemeOf,
} from './versions';
import { compareGo, goSameModuleMajor } from './versions/go';
import { comparePep440 } from './versions/pep440';
import { compareSemver } from './versions/semver';

const sign = (n: number | null): number | null => (n === null ? null : Math.sign(n));

describe('schemeOf', () => {
  it('orders js by SemVer, go by Go SemVer, python by PEP 440, maven by ComparableVersion', () => {
    expect(schemeOf('js')).toBe('semver');
    expect(schemeOf('go')).toBe('go');
    expect(schemeOf('python')).toBe('pep440');
    expect(schemeOf('maven')).toBe('maven');
  });
});

describe('parseFixedVersions', () => {
  it('splits Trivy’s comma list, trims, drops empties and duplicates, keeps the order', () => {
    expect(parseFixedVersions(null)).toEqual([]);
    expect(parseFixedVersions('')).toEqual([]);
    expect(parseFixedVersions(' , ')).toEqual([]);
    expect(parseFixedVersions(' 1.2.3 ,1.2.3, 2.0.1')).toEqual(['1.2.3', '2.0.1']);
    expect(parseFixedVersions('1.22.12, 1.23.6, 1.24.0-rc.3')).toEqual([
      '1.22.12',
      '1.23.6',
      '1.24.0-rc.3',
    ]);
  });
});

describe('chooseTarget, SemVer (§11.4)', () => {
  it('prefers the smallest fixed version on the installed release line', () => {
    expect(chooseTarget('semver', '1.2.5', parseFixedVersions('1.2.6, 0.2.4'))).toEqual({
      version: '1.2.6',
      majorJump: false,
    });
    expect(chooseTarget('semver', '1.2.5', parseFixedVersions('2.0.1, 1.4.0, 1.3.0'))).toEqual({
      version: '1.3.0',
      majorJump: false,
    });
  });

  it('jumps a major when no fixed version is on the line', () => {
    expect(chooseTarget('semver', '2.0.0', parseFixedVersions('1.9.9, 3.1.0'))).toEqual({
      version: '3.1.0',
      majorJump: true,
    });
  });

  it('treats each 0.x minor as its own line', () => {
    expect(chooseTarget('semver', '0.2.1', parseFixedVersions('0.2.4, 0.3.1'))).toEqual({
      version: '0.2.4',
      majorJump: false,
    });
    expect(chooseTarget('semver', '0.2.5', parseFixedVersions('0.3.1'))).toEqual({
      version: '0.3.1',
      majorJump: true,
    });
  });

  it('has no target when nothing parses or nothing is greater', () => {
    expect(chooseTarget('semver', '1.2.5', parseFixedVersions('abc, '))).toBeNull();
    expect(chooseTarget('semver', '1.2.5', parseFixedVersions('1.2.5, 1.0.0'))).toBeNull();
    expect(chooseTarget('semver', '1.2.5', [])).toBeNull();
    expect(chooseTarget('semver', 'not-a-version', ['1.2.6'])).toBeNull();
  });
});

describe('chooseTarget, pre-releases (R2)', () => {
  it('skips a pre-release fix for a released install', () => {
    expect(chooseTarget('semver', '1.2.5', parseFixedVersions('1.3.0-rc.1, 1.2.7'))).toEqual({
      version: '1.2.7',
      majorJump: false,
    });
    expect(chooseTarget('semver', '1.2.5', ['1.3.0-rc.1'])).toBeNull();
  });

  it('takes a pre-release fix for a pre-release install on the same line', () => {
    expect(chooseTarget('semver', '1.3.0-beta.1', parseFixedVersions('1.3.0-rc.1'))).toEqual({
      version: '1.3.0-rc.1',
      majorJump: false,
    });
    expect(chooseTarget('semver', '1.3.0-beta.1', ['2.0.0-rc.1'])).toBeNull();
  });
});

describe('SemVer order', () => {
  it('compares strictly and ignores build metadata', () => {
    expect(sign(compareSemver('1.2.3', '1.2.4'))).toBe(-1);
    expect(sign(compareSemver('1.2.3+build.1', '1.2.3+build.2'))).toBe(0);
    expect(sign(compareSemver('1.0.0-rc.1', '1.0.0'))).toBe(-1);
    expect(compareSemver('1.2', '1.2.0')).toBeNull();
    expect(compareSemver('1.2.3', '~1.2.3')).toBeNull();
    expect(sign(compareVersions('semver', '10.0.0', '9.9.9'))).toBe(1);
  });

  it('knows pre-releases and release lines', () => {
    expect(isPrerelease('semver', '1.0.0-rc.1')).toBe(true);
    expect(isPrerelease('semver', '1.0.0')).toBe(false);
    expect(isPrerelease('semver', 'junk')).toBe(false);
    expect(releaseLine('semver', '1.2.3')).toBe('1');
    expect(releaseLine('semver', '0.4.3')).toBe('0.4');
    expect(releaseLine('semver', 'junk')).toBeNull();
  });
});

describe('Go order', () => {
  it('drops the v prefix and +incompatible', () => {
    expect(sign(compareGo('v1.2.3', '1.2.4'))).toBe(-1);
    expect(sign(compareGo('v2.0.0+incompatible', '2.0.0'))).toBe(0);
    expect(sign(compareVersions('go', 'v1.10.0', 'v1.9.0'))).toBe(1);
    expect(compareGo('v1.2', 'v1.2.0')).toBeNull();
  });

  it('orders pseudo-versions as SemVer pre-releases', () => {
    expect(sign(compareGo('v0.0.0-20191109021931-daa7c04131f5', 'v0.0.1'))).toBe(-1);
    expect(sign(compareGo('v1.2.4-0.20200101000000-abcdefabcdef', 'v1.2.3'))).toBe(1);
    expect(sign(compareGo('v1.2.4-0.20200101000000-abcdefabcdef', 'v1.2.4'))).toBe(-1);
    expect(isPrerelease('go', 'v0.0.0-20191109021931-daa7c04131f5')).toBe(true);
    expect(releaseLine('go', 'v0.0.0-20191109021931-daa7c04131f5')).toBe('0.0');
    expect(releaseLine('go', 'v3.1.0+incompatible')).toBe('3');
  });

  it('keeps the module path major (R3)', () => {
    expect(goSameModuleMajor('v1.4.0', 'v0.9.0')).toBe(true);
    expect(goSameModuleMajor('v2.1.0', 'v2.0.0')).toBe(true);
    expect(goSameModuleMajor('v1.4.0', '2.1.0')).toBe(false);
    expect(goSameModuleMajor('v1.4.0', 'junk')).toBe(false);
    expect(chooseTarget('go', 'v1.4.0', ['2.1.0'])).toBeNull();
    expect(chooseTarget('go', 'v1.4.0', ['2.1.0', '1.5.2'])).toEqual({
      version: '1.5.2',
      majorJump: false,
    });
    expect(chooseTarget('go', 'v0.3.0', ['1.0.1'])).toEqual({ version: '1.0.1', majorJump: true });
  });

  it('puts +incompatible versions on the path without /vN (Ruling T1b)', () => {
    expect(
      chooseTarget('go', 'v20.10.27+incompatible', ['25.0.6+incompatible', '26.1.5+incompatible']),
    ).toEqual({ version: '25.0.6+incompatible', majorJump: true });
    // Trivy's fixed versions for github.com/docker/docker drop the suffix (CVE-2024-41110).
    expect(
      chooseTarget('go', 'v24.0.7+incompatible', ['23.0.15', '26.1.5', '27.1.1', '25.0.6']),
    ).toEqual({ version: '25.0.6', majorJump: true });
    expect(chooseTarget('go', 'v20.10.7+incompatible', ['20.10.11'])).toEqual({
      version: '20.10.11',
      majorJump: false,
    });
    expect(chooseTarget('go', 'v1.4.0', ['2.1.0+incompatible'])).toEqual({
      version: '2.1.0+incompatible',
      majorJump: true,
    });
    // A version from v2 on without the suffix lives on its own /vN path.
    expect(chooseTarget('go', 'v2.3.0', ['3.0.0+incompatible', '3.1.0'])).toBeNull();
    expect(goSameModuleMajor('25.0.6+incompatible', 'v20.10.27+incompatible')).toBe(true);
    expect(goSameModuleMajor('3.0.0+incompatible', 'v2.3.0')).toBe(false);
  });
});

describe('PEP 440 order', () => {
  it('orders pre-, post- and dev releases', () => {
    expect(sign(comparePep440('1.0rc1', '1.0'))).toBe(-1);
    expect(sign(comparePep440('1.0', '1.0.post1'))).toBe(-1);
    expect(sign(comparePep440('1.0.dev1', '1.0a1'))).toBe(-1);
    expect(sign(comparePep440('1!0.1', '2.0'))).toBe(1);
    expect(sign(comparePep440('1.0', '1.0.0'))).toBe(0);
    expect(comparePep440('1.0', 'not a version')).toBeNull();
  });

  it('knows pre-releases and release lines, with the epoch', () => {
    expect(isPrerelease('pep440', '1.0rc1')).toBe(true);
    expect(isPrerelease('pep440', '1.0.dev1')).toBe(true);
    expect(isPrerelease('pep440', '1.0.post1')).toBe(false);
    expect(releaseLine('pep440', '2.31.0')).toBe('2');
    expect(releaseLine('pep440', '0.9.1')).toBe('0.9');
    expect(releaseLine('pep440', '1!2.0')).toBe('1!2');
    expect(releaseLine('pep440', '3')).toBe('3');
    expect(releaseLine('pep440', '0')).toBe('0.0');
  });

  it('chooses a post-release and skips a release candidate', () => {
    expect(chooseTarget('pep440', '1.0', ['1.0rc1', '1.0.post1'])).toEqual({
      version: '1.0.post1',
      majorJump: false,
    });
    expect(chooseTarget('pep440', '1.0rc1', ['1.0rc2', '1.0'])).toEqual({
      version: '1.0rc2',
      majorJump: false,
    });
  });
});

describe('sameVersion and isGreater (ruling T11c: the one copy, for the CLI and the server)', () => {
  it("sameVersion compares by the scheme's order, and by text when either does not parse (T1c)", () => {
    expect(sameVersion('go', 'v1.2.3', '1.2.3')).toBe(true);
    expect(sameVersion('pep440', '1.0', '1.0.0')).toBe(true);
    expect(sameVersion('semver', '1.2.3', '1.2.4')).toBe(false);
    expect(sameVersion('semver', 'not a version', 'not a version')).toBe(true);
    expect(sameVersion('semver', 'not a version', '1.2.3')).toBe(false);
  });

  it('isGreater is true only for a greater version by the order; never when either does not parse', () => {
    expect(isGreater('semver', '1.2.8', '1.2.6')).toBe(true);
    expect(isGreater('semver', '1.2.6', '1.2.6')).toBe(false);
    expect(isGreater('semver', '1.2.6', '1.2.8')).toBe(false);
    expect(isGreater('maven', '5.2.21', '5.2.20.RELEASE')).toBe(true);
    expect(isGreater('semver', 'not a version', '1.0.0')).toBe(false);
  });
});
