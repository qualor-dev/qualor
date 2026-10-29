import { describe, expect, it } from 'vitest';
import { PROFILE_LANGUAGES } from '../orgs/builtins';
import { governingLanguage, ruleSetting, type ProfileSet, type RuleSetting } from './profiles';

describe('ruleSetting (data-model.md §4.4)', () => {
  const row = (setting: Partial<RuleSetting>): RuleSetting => ({
    active: true,
    severityOverride: null,
    scopeOverride: null,
    ...setting,
  });
  const set = (
    rows: Record<string, RuleSetting>,
    unknownRules: 'activate' | 'ignore' = 'activate',
  ): ProfileSet => ({
    chains: new Map([['typescript', { profileIds: ['child', 'parent'], unknownRules }]]),
    settings: new Map(Object.entries(rows).map(([profile, r]) => [profile, new Map([['r', r]])])),
  });

  it('takes activation and severity from the nearest row, the scope from the nearest override (0.13)', () => {
    expect(
      ruleSetting(
        set({
          child: row({ active: false }),
          parent: row({ severityOverride: 'high', scopeOverride: 'all' }),
        }),
        'typescript',
        'r',
      ),
    ).toEqual({ active: false, severityOverride: null, scopeOverride: 'all' });
    expect(
      ruleSetting(
        set({ child: row({ scopeOverride: 'test' }), parent: row({ scopeOverride: 'all' }) }),
        'typescript',
        'r',
      ).scopeOverride,
    ).toBe('test');
  });

  it('has no scope override for a rule no profile of the chain sets, nor without a profile', () => {
    expect(ruleSetting(set({}, 'ignore'), 'typescript', 'r')).toEqual({
      active: false,
      severityOverride: null,
      scopeOverride: null,
    });
    expect(ruleSetting(set({}), 'java', 'r')).toEqual({
      active: true,
      severityOverride: null,
      scopeOverride: null,
    });
  });
});

describe('governingLanguage (ruling P2, data-model.md §4.4)', () => {
  it('lets the csharp profile govern roslyn findings on C# files', () => {
    expect(governingLanguage('roslyn', 'csharp')).toBe('csharp');
  });

  it('lets the swift profile govern swiftlint findings on Swift files (plan 8F)', () => {
    expect(governingLanguage('swiftlint', 'swift')).toBe('swift');
    expect(governingLanguage('swiftlint', null)).toBe('*');
    for (const engine of ['semgrep', 'gitleaks', 'trivy', 'osv-scanner']) {
      expect(governingLanguage(engine, 'swift')).toBe('*');
    }
  });

  it('lets the php profile govern phpstan findings on PHP files (plan 9A)', () => {
    expect(governingLanguage('phpstan', 'php')).toBe('php');
    expect(governingLanguage('phpstan', null)).toBe('*');
    for (const engine of ['semgrep', 'gitleaks', 'trivy', 'osv-scanner']) {
      expect(governingLanguage(engine, 'php')).toBe('*');
    }
  });

  it('lets the ruby profile govern rubocop findings on Ruby files (plan 9B)', () => {
    expect(governingLanguage('rubocop', 'ruby')).toBe('ruby');
    expect(governingLanguage('rubocop', null)).toBe('*');
    for (const engine of ['semgrep', 'gitleaks', 'trivy'])
      expect(governingLanguage(engine, 'ruby')).toBe('*');
  });

  it('lets the go profile govern the Go engines on Go files (plan 9C)', () => {
    for (const engine of ['staticcheck', 'govet', 'gosec']) {
      expect(governingLanguage(engine, 'go'), engine).toBe('go');
      expect(governingLanguage(engine, null), engine).toBe('*');
    }
    for (const engine of ['semgrep', 'gitleaks', 'trivy']) {
      expect(governingLanguage(engine, 'go'), engine).toBe('*');
    }
  });

  it("lets the language's profile govern Qualor's security rules (plan 6B-1)", () => {
    expect(governingLanguage('qualor', 'java')).toBe('java');
    expect(governingLanguage('qualor', 'typescript')).toBe('typescript');
    expect(governingLanguage('qualor', 'javascript')).toBe('javascript');
    expect(governingLanguage('qualor', null)).toBe('*');
    expect(governingLanguage('qualor', 'other')).toBe('*');
  });

  it('lets the kotlin profile govern detekt findings on Kotlin files (phase 8E)', () => {
    expect(governingLanguage('detekt', 'kotlin')).toBe('kotlin');
    expect(governingLanguage('detekt', null)).toBe('*');
    for (const engine of ['semgrep', 'gitleaks', 'trivy']) {
      expect(governingLanguage(engine, 'kotlin')).toBe('*');
    }
  });

  it('lets the typescript/javascript profiles govern sonarjs findings (phase 8A)', () => {
    expect(governingLanguage('sonarjs', 'typescript')).toBe('typescript');
    expect(governingLanguage('sonarjs', 'javascript')).toBe('javascript');
  });

  it('leaves Semgrep, Gitleaks and Trivy on C# files to the * profile', () => {
    for (const engine of ['semgrep', 'gitleaks', 'trivy', 'osv-scanner']) {
      expect(governingLanguage(engine, 'csharp')).toBe('*');
    }
  });

  it('sends a file-less or other-language roslyn finding to *', () => {
    expect(governingLanguage('roslyn', null)).toBe('*');
    expect(governingLanguage('roslyn', 'other')).toBe('*');
  });

  it('lets the python profile govern ruff findings on Python files (plan 8C)', () => {
    expect(governingLanguage('ruff', 'python')).toBe('python');
    expect(governingLanguage('ruff', null)).toBe('*');
    for (const engine of ['semgrep', 'gitleaks', 'trivy', 'osv-scanner']) {
      expect(governingLanguage(engine, 'python')).toBe('*');
    }
  });

  it('binds stylelint to the css profile and htmlhint to the html profile (plan 8D)', () => {
    expect(governingLanguage('stylelint', 'css')).toBe('css');
    expect(governingLanguage('htmlhint', 'html')).toBe('html');
    expect(governingLanguage('stylelint', 'other')).toBe('*');
    expect(governingLanguage('htmlhint', null)).toBe('*');
    expect(PROFILE_LANGUAGES).toEqual(expect.arrayContaining(['html', 'css']));
    expect(PROFILE_LANGUAGES.at(-1)).toBe('*');
  });

  it('lets the c and cpp profiles govern cppcheck and clang-tidy findings (plan 9D)', () => {
    for (const engine of ['cppcheck', 'clang-tidy']) {
      expect(governingLanguage(engine, 'c'), engine).toBe('c');
      expect(governingLanguage(engine, 'cpp'), engine).toBe('cpp');
      expect(governingLanguage(engine, null), engine).toBe('*');
    }
    for (const engine of ['semgrep', 'gitleaks', 'trivy'])
      expect(governingLanguage(engine, 'cpp')).toBe('*');
  });
});
