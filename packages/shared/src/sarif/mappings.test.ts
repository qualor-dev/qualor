import { describe, expect, it } from 'vitest';
import { engineMapping, ENGINE_MAPPINGS, sonarCategory } from './mappings';
import type { SarifResult, SarifRule } from './types';

const rule = (id: string, properties: Record<string, unknown> = {}): SarifRule => ({
  id,
  properties,
});
const result = (properties: Record<string, unknown> = {}): SarifResult => ({ properties });

describe('engineMapping', () => {
  it('returns mappings for built-in engines only', () => {
    expect(engineMapping('eslint')).toBe(ENGINE_MAPPINGS.eslint);
    expect(engineMapping('mytool')).toBeUndefined();
  });
});

describe('eslint', () => {
  const m = ENGINE_MAPPINGS.eslint;
  it.each([
    ['no-eval', 'security'],
    ['security/detect-object-injection', 'security'],
    ['no-undef', 'reliability'],
    ['@typescript-eslint/no-floating-promises', 'reliability'],
    ['no-console', 'maintainability'],
  ])('%s → %s', (id, quality) => {
    expect(m.rule!(rule(id)).quality).toBe(quality);
  });
});

describe('pmd', () => {
  const m = ENGINE_MAPPINGS.pmd;
  it.each([
    ['Security', 'security'],
    ['Error Prone', 'reliability'],
    ['Multithreading', 'reliability'],
    ['Best Practices', 'maintainability'],
    ['Code Style', 'maintainability'],
  ])('ruleset %s → %s', (ruleset, quality) => {
    expect(m.rule!(rule('X', { ruleset, priority: 3 })).quality).toBe(quality);
  });
  it.each([
    [1, 'high'],
    [2, 'medium'],
    [3, 'medium'],
    [4, 'low'],
    [5, 'info'],
  ])('priority %i → %s', (priority, severity) => {
    const r = rule('X', { ruleset: 'Design', priority });
    expect(m.rule!(r).defaultSeverity).toBe(severity);
    expect(m.severity!(result(), r)).toBe(severity);
  });
});

describe('spotbugs', () => {
  const m = ENGINE_MAPPINGS.spotbugs;
  it.each([
    ['SECURITY', 'security'],
    ['CORRECTNESS', 'reliability'],
    ['MT_CORRECTNESS', 'reliability'],
    ['BAD_PRACTICE', 'maintainability'],
    ['STYLE', 'maintainability'],
  ])('category %s → %s', (category, quality) => {
    expect(m.rule!(rule('X', { tags: [category] })).quality).toBe(quality);
  });
  it.each([
    [1, 'high'],
    [4, 'high'],
    [5, 'medium'],
    [9, 'medium'],
    [10, 'low'],
    [14, 'low'],
    [15, 'info'],
    [20, 'info'],
  ])('rank %i → %s', (rank, severity) => {
    expect(m.severity!(result({ rank }), undefined)).toBe(severity);
  });
  it('falls back to the SARIF level when no rank is present', () => {
    expect(m.severity!(result(), undefined)).toBeUndefined();
  });
});

describe('semgrep', () => {
  const m = ENGINE_MAPPINGS.semgrep;
  it('maps security, correctness and other tags', () => {
    expect(m.rule!(rule('a', { tags: ['security', 'CWE-95: x'] })).quality).toBe('security');
    expect(m.rule!(rule('b', { tags: ['CWE-78: x'] })).quality).toBe('security');
    expect(m.rule!(rule('c', { tags: ['correctness'] })).quality).toBe('reliability');
    expect(m.rule!(rule('d', { tags: ['maintainability'] })).quality).toBe('maintainability');
  });
  it('redacts secret rules only', () => {
    const redact = m.redactRegion as (r: SarifRule | undefined) => boolean;
    expect(redact(rule('k', { tags: ['CWE-798: Use of Hard-coded Credentials'] }))).toBe(true);
    expect(redact(rule('k', { tags: ['secrets'] }))).toBe(true);
    expect(redact(rule('e', { tags: ['CWE-95: x'] }))).toBe(false);
    expect(redact(undefined)).toBe(false);
  });
});

describe('gitleaks', () => {
  const m = ENGINE_MAPPINGS.gitleaks;
  it('is always security/blocker and redacted', () => {
    expect(m.rule!(rule('generic-api-key'))).toEqual({
      quality: 'security',
      defaultSeverity: 'blocker',
      kind: 'issue',
    });
    expect(m.severity!(result(), undefined)).toBe('blocker');
    expect(m.redactRegion).toBe(true);
  });
  it('drops partial fingerprints (author, email, commit message are personal data)', () => {
    expect(m.dropPartialFingerprints).toBe(true);
    for (const other of ['eslint', 'pmd', 'spotbugs', 'semgrep'] as const) {
      expect(ENGINE_MAPPINGS[other]).not.toHaveProperty('dropPartialFingerprints');
    }
  });
});

describe('trivy (plan 2B)', () => {
  const m = ENGINE_MAPPINGS.trivy;
  it('is security, an issue, with the severity Trivy selected', () => {
    expect(m.rule!(rule('CVE-2021-44906', { trivySeverity: 'CRITICAL' }))).toEqual({
      quality: 'security',
      kind: 'issue',
      defaultSeverity: 'blocker',
    });
    expect(m.rule!(rule('CVE-1'))).toEqual({ quality: 'security', kind: 'issue' });
    const levels = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN', 'critical', 'toString', 7];
    expect(levels.map((v) => m.severity!(result({ trivySeverity: v }), undefined))).toEqual([
      'blocker',
      'high',
      'medium',
      'low',
      'medium',
      undefined,
      undefined,
      undefined,
    ]);
    // A result without its own severity takes its rule's.
    expect(m.severity!(result(), rule('CVE-1', { trivySeverity: 'LOW' }))).toBe('low');
  });
  it('identifies a finding by the package name and version, not by its lines', () => {
    const dependency = (d: unknown) => m.identity!(result({ dependency: d }));
    expect(dependency({ name: 'minimist', version: '1.2.5', fixedVersion: '1.2.6' })).toBe(
      'minimist@1.2.5',
    );
    expect(dependency({ name: 'org.a:b', version: '2.14.1' })).toBe('org.a:b@2.14.1');
    for (const bad of [undefined, null, 'minimist', { name: 'x' }, { name: '', version: '1' }]) {
      expect(dependency(bad), JSON.stringify(bad)).toBeUndefined();
    }
    for (const other of ['eslint', 'pmd', 'spotbugs', 'semgrep', 'gitleaks'] as const) {
      expect(ENGINE_MAPPINGS[other]).not.toHaveProperty('identity');
    }
  });
});

describe('roslyn (plan 2D)', () => {
  const rule = (category: string | undefined) => ({
    id: 'CA0000',
    ...(category !== undefined && { properties: { category } }),
  });
  const quality = (category: string | undefined) =>
    engineMapping('roslyn')!.rule!(rule(category)).quality;

  it('maps the rule category to a quality, whatever its case', () => {
    expect(quality('Security')).toBe('security');
    expect(quality('security')).toBe('security');
    expect(quality('Reliability')).toBe('reliability');
    expect(quality('Usage')).toBe('reliability');
    for (const c of [
      'Design',
      'Performance',
      'Naming',
      'Style',
      'Maintainability',
      'Compiler',
      'Roslynator',
      'StyleCop.CSharp.DocumentationRules',
      undefined,
    ]) {
      expect(quality(c)).toBe('maintainability');
    }
  });

  it('reports issues; a non-SonarAnalyzer rule leaves severity to the result level', () => {
    const m = engineMapping('roslyn')!;
    expect(m.rule!(rule('Security')).kind).toBe('issue');
    expect(m.severity!(result(), rule('Security'))).toBeUndefined();
    expect(m.redactRegion).toBeUndefined();
  });
});

describe('sonarCategory (report-format.md §7.1)', () => {
  it.each([
    ['Blocker Bug', 'reliability', 'issue', 'blocker'],
    ['Critical Bug', 'reliability', 'issue', 'high'],
    ['Major Code Smell', 'maintainability', 'issue', 'medium'],
    ['Minor Code Smell', 'maintainability', 'issue', 'low'],
    ['Info Code Smell', 'maintainability', 'issue', 'info'],
    ['Critical Vulnerability', 'security', 'issue', 'high'],
    ['Major Security Hotspot', 'security', 'hotspot', 'medium'],
  ])('%s → %s %s %s', (category, quality, kind, defaultSeverity) => {
    expect(sonarCategory(category)).toEqual({ quality, kind, defaultSeverity });
  });

  it('is null for anything else (a Microsoft or Roslynator category)', () => {
    for (const c of ['Security', 'Reliability', 'Roslynator', '', 'Major', 'Bug', 'Major  Bug'])
      expect(sonarCategory(c)).toBeNull();
  });

  it('roslyn uses it for SonarAnalyzer rules and keeps the Microsoft mapping otherwise', () => {
    const roslyn = engineMapping('roslyn')!;
    expect(roslyn.rule!({ id: 'S2930', properties: { category: 'Major Bug' } })).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    expect(roslyn.rule!({ id: 'CA5351', properties: { category: 'Security' } })).toEqual({
      quality: 'security',
      kind: 'issue',
    });
  });

  it('sonarjs uses it, and defaults to maintainability without a category', () => {
    const sonarjs = engineMapping('sonarjs')!;
    expect(
      sonarjs.rule!({ id: 'S5332', properties: { category: 'Critical Security Hotspot' } }),
    ).toEqual({ quality: 'security', kind: 'hotspot', defaultSeverity: 'high' });
    expect(sonarjs.rule!({ id: 'S9999' })).toEqual({ quality: 'maintainability', kind: 'issue' });
  });

  it('a SonarAnalyzer result takes its severity from the category, not the SARIF level', () => {
    const roslyn = engineMapping('roslyn')!;
    expect(
      roslyn.severity!({ ruleId: 'S2930', level: 'warning' } as never, {
        id: 'S2930',
        properties: { category: 'Blocker Bug' },
      }),
    ).toBe('blocker');
    expect(
      roslyn.severity!({ ruleId: 'CA5351', level: 'warning' } as never, {
        id: 'CA5351',
        properties: { category: 'Security' },
      }),
    ).toBeUndefined();
  });
});
