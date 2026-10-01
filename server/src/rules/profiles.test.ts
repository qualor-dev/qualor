import { describe, expect, it } from 'vitest';
import { PROFILE_LANGUAGES } from '../orgs/builtins';
import { governingLanguage } from './profiles';

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
