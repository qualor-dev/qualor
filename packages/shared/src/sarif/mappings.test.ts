import { describe, expect, it } from 'vitest';
import { BUILTIN_ENGINES, LANGUAGES } from '../report/taxonomy';
import { engineMapping, ENGINE_MAPPINGS, ruffRule, sonarCategory } from './mappings';
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

describe('spotbugs: FindSecBugs patterns (report-format.md §7.1, plan 6A)', () => {
  const m = ENGINE_MAPPINGS.spotbugs;

  it.each([
    ['SQL_INJECTION_JDBC', 'issue', 'high'],
    ['ECB_MODE', 'issue', 'medium'],
    ['PREDICTABLE_RANDOM', 'hotspot', 'medium'],
    ['SERVLET_PARAMETER', 'hotspot', 'low'],
    ['SPRING_ENDPOINT', 'hotspot', 'info'],
  ])('%s → %s, default %s', (id, kind, defaultSeverity) => {
    expect(m.rule!(rule(id, { tags: ['SECURITY'] }))).toEqual({
      quality: 'security',
      kind,
      defaultSeverity,
    });
  });

  it('takes the severity from the table, one step lower at note, whatever SpotBugs ranked', () => {
    const sev = (id: string, level?: 'error' | 'warning' | 'note') =>
      m.severity!(
        { ruleId: id, ...(level && { level }), properties: { rank: 1 } } as never,
        rule(id),
      );
    expect(sev('SQL_INJECTION_JDBC', 'warning')).toBe('high');
    expect(sev('CRLF_INJECTION_LOGS', 'warning')).toBe('medium');
    expect(sev('CRLF_INJECTION_LOGS', 'note')).toBe('low');
    expect(sev('SERVLET_PARAMETER', 'note')).toBe('info');
  });

  it('leaves core SpotBugs patterns and unknown ids as they were', () => {
    expect(
      m.rule!(rule('SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE', { tags: ['SECURITY'] })),
    ).toEqual({ quality: 'security' });
    expect(m.rule!(rule('A_PATTERN_OF_ANOTHER_VERSION', { tags: ['SECURITY'] }))).toEqual({
      quality: 'security',
    });
    expect(m.severity!(result({ rank: 3 }), rule('SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE'))).toBe(
      'high',
    );
    expect(m.severity!(result(), rule('A_PATTERN_OF_ANOTHER_VERSION'))).toBeUndefined();
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

describe('ruff (report-format.md §7.1, plan 8C)', () => {
  it.each([
    ['S608', 'security', 'high'],
    ['S602', 'security', 'high'],
    ['S324', 'security', 'medium'],
    ['F841', 'reliability', 'medium'],
    ['F401', 'reliability', 'medium'],
    ['B006', 'reliability', 'medium'],
    ['C901', 'maintainability', 'low'],
    ['SIM102', 'maintainability', 'medium'],
    ['E711', 'maintainability', 'low'],
    ['E501', 'maintainability', 'low'],
    ['ZZZ999', 'maintainability', 'medium'],
  ])('%s → %s %s', (code, quality, defaultSeverity) => {
    expect(ruffRule(code)).toEqual({ quality, kind: 'issue', defaultSeverity });
  });

  it("takes the severity from the rule, not from Ruff's SARIF level (always error)", () => {
    const ruff = engineMapping('ruff')!;
    expect(ruff.rule!({ id: 'E711' })).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'low',
    });
    expect(ruff.severity!({ ruleId: 'E711', level: 'error' } as never, { id: 'E711' })).toBe('low');
    expect(ruff.severity!({ ruleId: 'S608', level: 'error' } as never, undefined)).toBe('high');
  });
});

describe('stylelint and htmlhint (report-format.md §7.1, plan 8D)', () => {
  it('are built-in engines and html/css are languages before other', () => {
    expect(BUILTIN_ENGINES).toEqual(expect.arrayContaining(['stylelint', 'htmlhint']));
    expect(LANGUAGES).toEqual(expect.arrayContaining(['html', 'css']));
    expect(LANGUAGES.at(-1)).toBe('other');
  });

  it('stylelint: a possible-error rule is reliability/medium, anything else maintainability/low', () => {
    const m = engineMapping('stylelint')!;
    const possible = { id: 'block-no-empty', properties: { category: 'possible-error' } };
    const convention = { id: 'length-zero-no-unit', properties: { category: 'convention' } };
    expect(m.rule!(possible)).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    expect(m.rule!(convention)).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'low',
    });
    expect(m.rule!({ id: 'x' })).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'low',
    });
    expect(m.rule!({ id: 'x', properties: { category: '__proto__' } }).quality).toBe(
      'maintainability',
    );
    // The configured level (stylelint configs set everything to error) does not decide severity.
    expect(
      m.severity!({ ruleId: 'length-zero-no-unit', level: 'error' } as never, convention),
    ).toBe('low');
    expect(m.severity!({ ruleId: 'block-no-empty', level: 'warning' } as never, possible)).toBe(
      'medium',
    );
  });

  it('htmlhint: correctness rules are reliability, accessibility rules medium, the rest low', () => {
    const m = engineMapping('htmlhint')!;
    expect(m.rule!({ id: 'tag-pair' })).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    expect(m.rule!({ id: 'alt-require' })).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    expect(m.rule!({ id: 'title-require' })).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'low',
    });
    expect(
      m.severity!({ ruleId: 'tag-no-obsolete', level: 'error' } as never, {
        id: 'tag-no-obsolete',
      }),
    ).toBe('low');
    expect(m.severity!({ ruleId: 'attr-no-duplication', level: 'error' } as never, undefined)).toBe(
      'medium',
    );
  });
});

describe('detekt (report-format.md 7.1, phase 8E)', () => {
  const detekt = () => engineMapping('detekt')!;

  it.each([
    ['potential-bugs', 'reliability', 'medium'],
    ['coroutines', 'reliability', 'medium'],
    ['exceptions', 'reliability', 'medium'],
    ['complexity', 'maintainability', 'medium'],
    ['empty-blocks', 'maintainability', 'medium'],
    ['performance', 'maintainability', 'medium'],
    ['style', 'maintainability', 'low'],
    ['naming', 'maintainability', 'low'],
    ['comments', 'maintainability', 'low'],
  ])('rule set %s -> %s, default %s', (ruleset, quality, defaultSeverity) => {
    expect(detekt().rule!(rule('X', { ruleset }))).toEqual({ quality, defaultSeverity });
  });

  it('treats a rule without a rule set as maintainability/medium', () => {
    expect(detekt().rule!(rule('X'))).toEqual({
      quality: 'maintainability',
      defaultSeverity: 'medium',
    });
  });

  it('takes a project severity from the SARIF level and the rule set default otherwise', () => {
    const style = rule('MagicNumber', { ruleset: 'style' });
    const sev = (level: 'error' | 'warning' | 'note' | 'none' | undefined) =>
      detekt().severity!({ ruleId: 'MagicNumber', ...(level && { level }) } as never, style);
    expect(sev('error')).toBe('high');
    expect(sev('note')).toBe('low');
    expect(sev('none')).toBe('info');
    expect(sev('warning')).toBe('low');
    expect(sev(undefined)).toBe('low');
    expect(
      detekt().severity!(
        { ruleId: 'UnsafeCast', level: 'warning' } as never,
        rule('UnsafeCast', { ruleset: 'potential-bugs' }),
      ),
    ).toBe('medium');
  });

  it('gives the external ext-detekt engine no mapping, so no rule set is required', () => {
    expect(engineMapping('ext-detekt')).toBeUndefined();
  });
});

describe('swiftlint (report-format.md 7.1, phase 8F)', () => {
  it('takes quality and severity from the rule kind', () => {
    const m = engineMapping('swiftlint')!;
    expect(m.rule!({ id: 'duplicate_conditions' })).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    expect(m.rule!({ id: 'line_length' })).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'low',
    });
    expect(
      m.severity!({ ruleId: 'force_cast', level: 'error' } as never, { id: 'force_cast' }),
    ).toBe('high');
    expect(
      m.severity!({ ruleId: 'force_unwrapping', level: 'warning' } as never, {
        id: 'force_unwrapping',
      }),
    ).toBe('low');
    expect(
      m.severity!({ ruleId: 'duplicate_conditions', level: 'warning' } as never, undefined),
    ).toBe('medium');
  });

  it('maps level none to info and a missing level to a warning', () => {
    const m = engineMapping('swiftlint')!;
    expect(m.severity!({ ruleId: 'line_length', level: 'none' } as never, undefined)).toBe('info');
    expect(m.severity!({ ruleId: 'duplicate_conditions' } as never, undefined)).toBe('medium');
  });

  it('gives the external ext-swiftlint engine no mapping', () => {
    expect(engineMapping('ext-swiftlint')).toBeUndefined();
  });

  it('maps the Go engines by check id, analyzer and gosec severity tag (report-format.md §7.1, plan 9C)', () => {
    const sc = engineMapping('staticcheck')!;
    expect(sc.rule!({ id: 'SA5009' })).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'high',
    });
    expect(sc.severity!({ ruleId: 'S1002', level: 'warning' } as never, undefined)).toBe('low');
    const vet = engineMapping('govet')!;
    expect(vet.rule!({ id: 'copylocks' })).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    const gs = engineMapping('gosec')!;
    const g401 = { id: 'G401', properties: { tags: ['security', 'MEDIUM'] } };
    expect(gs.rule!(g401)).toEqual({
      quality: 'security',
      kind: 'issue',
      defaultSeverity: 'medium',
    });
    expect(
      gs.severity!({ ruleId: 'G402', level: 'error' } as never, {
        id: 'G402',
        properties: { tags: ['security', 'HIGH'] },
      }),
    ).toBe('high');
    expect(gs.severity!({ ruleId: 'G999' } as never, undefined)).toBe('medium');
  });
});

describe('phpstan (report-format.md §7.1, plan 9A)', () => {
  it('takes quality and severity from the identifier, never from the level', () => {
    const phpstan = engineMapping('phpstan')!;
    expect(phpstan.rule!({ id: 'parameter.phpDocType' })).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'low',
    });
    expect(
      phpstan.severity!({ ruleId: 'variable.undefined', level: 'warning' } as never, {
        id: 'variable.undefined',
      }),
    ).toBe('medium');
    expect(phpstan.severity!({ ruleId: 'method.unused', level: 'error' } as never, undefined)).toBe(
      'low',
    );
  });
});

describe('rubocop (report-format.md §7.1, plan 9B)', () => {
  it('maps quality and severity from the department, never from the SARIF level', () => {
    const rubocop = engineMapping('rubocop')!;
    expect(rubocop.rule!({ id: 'Security/Eval' })).toEqual({
      quality: 'security',
      kind: 'issue',
      defaultSeverity: 'high',
    });
    expect(rubocop.rule!({ id: 'Style/StringLiterals' })).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'low',
    });
    expect(
      rubocop.severity!({ ruleId: 'Lint/UselessAssignment', level: 'note' } as never, undefined),
    ).toBe('medium');
    expect(
      rubocop.severity!({ ruleId: 'Security/YAMLLoad', level: 'warning' } as never, undefined),
    ).toBe('high');
  });

  it('gives the external ext-rubocop engine no mapping', () => {
    expect(engineMapping('ext-rubocop')).toBeUndefined();
  });
});

describe('cppcheck and clang-tidy (plan 9D)', () => {
  it('cppcheck takes quality and severity from cppcheck severity, carried in properties', () => {
    const m = engineMapping('cppcheck')!;
    expect(m.rule!({ id: 'nullPointer', properties: { cppcheckSeverity: 'error' } })).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'high',
    });
    expect(
      m.rule!({ id: 'passedByValue', properties: { cppcheckSeverity: 'performance' } }),
    ).toEqual({ quality: 'maintainability', kind: 'issue', defaultSeverity: 'low' });
    const r = (cppcheckSeverity: string, level = 'warning') =>
      ({ ruleId: 'x', level, properties: { cppcheckSeverity } }) as never;
    expect(m.severity!(r('warning', 'error'), undefined)).toBe('medium');
    expect(m.severity!(r('style'), undefined)).toBe('low');
    // An external cppcheck SARIF (ext-cppcheck) has only levels.
    expect(m.severity!({ ruleId: 'x', level: 'error' } as never, { id: 'x' })).toBe('high');
    expect(m.severity!({ ruleId: 'x', level: 'note' } as never, { id: 'x' })).toBe('low');
  });

  it('clang-tidy takes quality and severity from the check group', () => {
    const m = engineMapping('clang-tidy')!;
    expect(m.rule!({ id: 'clang-analyzer-core.DivideZero' })).toEqual({
      quality: 'reliability',
      kind: 'issue',
      defaultSeverity: 'high',
    });
    expect(m.rule!({ id: 'readability-identifier-length' })).toEqual({
      quality: 'maintainability',
      kind: 'issue',
      defaultSeverity: 'low',
    });
    expect(
      m.severity!({ ruleId: 'bugprone-use-after-move', level: 'warning' } as never, undefined),
    ).toBe('medium');
  });
});
