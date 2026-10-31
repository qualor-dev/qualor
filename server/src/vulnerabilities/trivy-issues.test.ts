import { describe, expect, it } from 'vitest';
import { DEFAULT_VULNERABILITY_SETTINGS, type VulnerabilitySettings } from '../versions/settings';
import { packageNameOf, writesDecision } from './trivy-issues';

const MESSAGE = 'lodash 4.17.20: CVE-2026-0001 Title (fixed in 4.17.21)';

describe('packageNameOf', () => {
  const trivy = (over: { ruleId?: string; message?: string; properties?: unknown } = {}) => ({
    engineId: 'trivy',
    ruleId: 'CVE-2026-0001',
    message: MESSAGE,
    ...over,
  });

  it('takes the name from the properties over the message', () => {
    expect(packageNameOf(trivy({ properties: { dependency: { name: '@types/lodash' } } }))).toBe(
      '@types/lodash',
    );
  });

  it('reads the first word of the message without properties', () => {
    expect(packageNameOf(trivy())).toBe('lodash');
  });

  it('answers null for a message without ": <id>"', () => {
    expect(packageNameOf(trivy({ message: 'lodash@4.17.20 CVE-2026-0001 Title' }))).toBeNull();
    expect(packageNameOf(trivy({ message: 'lodash 4.17.20: CVE-2026-00012 Title' }))).toBeNull();
  });

  it('answers null for another engine, whatever it says', () => {
    expect(
      packageNameOf({
        engineId: 'osv',
        ruleId: 'CVE-2026-0001',
        message: MESSAGE,
        properties: { dependency: { name: 'lodash' } },
      }),
    ).toBeNull();
  });

  it('falls back to the message when the property is not a name of 1–512 characters', () => {
    for (const name of ['', 'x'.repeat(513), 42]) {
      expect(packageNameOf(trivy({ properties: { dependency: { name } } }))).toBe('lodash');
    }
    expect(packageNameOf(trivy({ properties: { dependency: 'lodash-es' } }))).toBe('lodash');
  });

  it('takes the id literally, not as a pattern', () => {
    expect(packageNameOf(trivy({ ruleId: 'GHSA-a.b+', message: 'pkg 1.0: GHSA-a.b+ Title' }))).toBe(
      'pkg',
    );
    expect(
      packageNameOf(trivy({ ruleId: 'GHSA-a.b+', message: 'pkg 1.0: GHSA-aXbbb Title' })),
    ).toBeNull();
  });
});

describe('writesDecision', () => {
  const settings: VulnerabilitySettings = {
    ...DEFAULT_VULNERABILITY_SETTINGS,
    branchPatterns: ['release/*'],
  };
  const issue = (over: Partial<Parameters<typeof writesDecision>[1]> = {}) => ({
    engineId: 'trivy',
    packageName: 'lodash' as string | null,
    branch: { name: 'main', isMain: true, kind: 'branch' },
    ...over,
  });

  it('is true for a Trivy issue with a package name on main or a tracked branch', () => {
    expect(writesDecision(settings, issue())).toBe(true);
    expect(
      writesDecision(
        settings,
        issue({ branch: { name: 'release/1.x', isMain: false, kind: 'branch' } }),
      ),
    ).toBe(true);
  });

  it('is false on other branches and merge requests', () => {
    expect(
      writesDecision(
        settings,
        issue({ branch: { name: 'feature/x', isMain: false, kind: 'branch' } }),
      ),
    ).toBe(false);
    expect(
      writesDecision(
        settings,
        issue({ branch: { name: 'release/1.x', isMain: false, kind: 'merge_request' } }),
      ),
    ).toBe(false);
  });

  it('is false without a package name or for another engine', () => {
    expect(writesDecision(settings, issue({ packageName: null }))).toBe(false);
    expect(writesDecision(settings, issue({ engineId: 'qualor' }))).toBe(false);
  });
});
