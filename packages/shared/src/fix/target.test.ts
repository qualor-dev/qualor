import { describe, expect, it } from 'vitest';
import { chooseTargets, greatestVersion, type VulnerabilityFixFacts } from './target';

describe('chooseTargets (B3)', () => {
  it('gives each installed version its own target on its own line', () => {
    const vulnerabilities: VulnerabilityFixFacts[] = [
      { id: 'A', installedVersions: ['1.2.5', '2.0.1'], fixedVersions: ['1.2.6', '2.0.3'] },
      { id: 'B', installedVersions: ['2.0.1'], fixedVersions: [] },
    ];
    expect(chooseTargets('semver', ['1.2.5', '2.0.1'], vulnerabilities)).toEqual([
      { installed: '1.2.5', target: '1.2.6', majorJump: false, unfixable: [] },
      { installed: '2.0.1', target: '2.0.3', majorJump: false, unfixable: ['B'] },
    ]);
  });

  it('takes the greatest of the vulnerabilities’ choices, with its major jump', () => {
    const vulnerabilities: VulnerabilityFixFacts[] = [
      { id: 'A', installedVersions: ['1.2.5'], fixedVersions: ['1.2.6'] },
      { id: 'B', installedVersions: ['1.2.5'], fixedVersions: ['1.4.0', '0.9.9'] },
      { id: 'C', installedVersions: ['1.2.5'], fixedVersions: ['2.0.0'] },
    ];
    expect(chooseTargets('semver', ['1.2.5'], vulnerabilities)).toEqual([
      { installed: '1.2.5', target: '2.0.0', majorJump: true, unfixable: [] },
    ]);
  });

  it('has no target when every vulnerability of a version is unfixable, or none affects it', () => {
    const vulnerabilities: VulnerabilityFixFacts[] = [
      { id: 'A', installedVersions: ['1.0.0'], fixedVersions: ['0.9.0'] },
      { id: 'B', installedVersions: ['1.0.0'], fixedVersions: ['1.1.0-rc.1'] },
    ];
    expect(chooseTargets('semver', ['1.0.0', '3.0.0'], vulnerabilities)).toEqual([
      { installed: '1.0.0', target: null, majorJump: false, unfixable: ['A', 'B'] },
      { installed: '3.0.0', target: null, majorJump: false, unfixable: [] },
    ]);
  });

  it('matches installed versions by version order, not spelling (Ruling T1c)', () => {
    const go: VulnerabilityFixFacts[] = [
      { id: 'A', installedVersions: ['1.2.3'], fixedVersions: ['1.2.4'] },
    ];
    expect(chooseTargets('go', ['v1.2.3'], go)).toEqual([
      { installed: 'v1.2.3', target: '1.2.4', majorJump: false, unfixable: [] },
    ]);
    const maven: VulnerabilityFixFacts[] = [
      { id: 'A', installedVersions: ['5.2.20.RELEASE'], fixedVersions: ['5.2.21'] },
      { id: 'B', installedVersions: ['junk version'], fixedVersions: ['1.0'] },
    ];
    expect(chooseTargets('maven', ['5.2.20', 'junk version'], maven)).toEqual([
      { installed: '5.2.20', target: '5.2.21', majorJump: false, unfixable: [] },
      { installed: 'junk version', target: null, majorJump: false, unfixable: ['B'] },
    ]);
  });
});

describe('greatestVersion', () => {
  it('returns the greatest version that parses', () => {
    expect(greatestVersion('semver', ['1.2.6', '2.0.3'])).toBe('2.0.3');
    expect(greatestVersion('semver', ['2.0.3', 'junk', '10.0.0', '9.1.0'])).toBe('10.0.0');
    expect(greatestVersion('maven', ['5.2.20.RELEASE', '5.2.3'])).toBe('5.2.20.RELEASE');
    expect(greatestVersion('pep440', ['1.0', '1.0.post1', '1.0rc1'])).toBe('1.0.post1');
    expect(greatestVersion('semver', ['junk'])).toBeNull();
    expect(greatestVersion('semver', [])).toBeNull();
  });
});
