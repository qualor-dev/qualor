import { describe, expect, it } from 'vitest';
import { DEPENDENCY_ENGINES, engineRuleDefaults } from './defaults';

describe('engineRuleDefaults (report-format.md §7.1)', () => {
  it('grades Gitleaks and Trivy rules without metadata as security, the rest as maintainability', () => {
    expect(engineRuleDefaults('gitleaks')).toEqual({
      quality: 'security',
      defaultSeverity: 'blocker',
    });
    expect(engineRuleDefaults('trivy')).toEqual({ quality: 'security', defaultSeverity: 'medium' });
    for (const id of ['eslint', 'sonarjs', 'pmd', 'spotbugs', 'semgrep', 'detekt', 'osv-scanner']) {
      expect(engineRuleDefaults(id), id).toEqual({
        quality: 'maintainability',
        defaultSeverity: 'medium',
      });
    }
  });
});

describe('engineRuleDefaults for qualor (plan 6B-1)', () => {
  it('gives a qualor rule without metadata security/medium', () => {
    expect(engineRuleDefaults('qualor')).toEqual({
      quality: 'security',
      defaultSeverity: 'medium',
    });
  });
});

describe('DEPENDENCY_ENGINES (scm.md §9)', () => {
  it('names Trivy only', () => {
    expect([...DEPENDENCY_ENGINES]).toEqual(['trivy']);
  });
});
