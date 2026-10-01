import { describe, expect, it } from 'vitest';
import defaultKeys from '../../rules/rubocop-default-keys.json' with { type: 'json' };
import {
  normalizeTargetRuby,
  RUBOCOP_COPS,
  RUBOCOP_DEFAULT_TARGET_RUBY,
  RUBOCOP_DEPARTMENTS,
  RUBOCOP_SELECTOR,
  RUBOCOP_TARGET_RUBIES,
  RUBOCOP_VERSION,
  rubocopHelpUri,
  rubocopQuality,
  rubocopSelection,
  rubocopSelectorKnown,
  rubocopSeverity,
  rubocopVersionSupported,
} from './rubocop';
import { RUBOCOP_DEFAULT_EXCLUDE, RUBOCOP_SYNTAX_COP } from './rubocop-default';

describe('rubocopSelection (config.md §6, plan 9B)', () => {
  it('expands qualor-default into the committed default keys', () => {
    expect(rubocopSelection(['qualor-default'], [])).toEqual(defaultKeys);
    for (const cop of RUBOCOP_DEFAULT_EXCLUDE) expect(defaultKeys).not.toContain(cop);
    expect(defaultKeys).not.toContain(RUBOCOP_SYNTAX_COP);
  });

  it('leaves Lint/ScriptPermission out of qualor-default (the checked copy has no exec bit), but a user can select it', () => {
    expect(RUBOCOP_DEFAULT_EXCLUDE).toContain('Lint/ScriptPermission');
    expect(defaultKeys).not.toContain('Lint/ScriptPermission');
    expect(rubocopSelection(['qualor-default'], [])).not.toContain('Lint/ScriptPermission');
    expect(rubocopSelection(['qualor-default', 'Lint/ScriptPermission'], [])).toContain(
      'Lint/ScriptPermission',
    );
    expect(rubocopSelection(['Lint'], [])).toContain('Lint/ScriptPermission');
  });

  it('expands a department into its cops RuboCop enables by default, and takes a cop by name whatever its state', () => {
    const style = rubocopSelection(['Style'], []);
    expect(style.length).toBeGreaterThan(100);
    expect(style.every((c) => c.startsWith('Style/') && RUBOCOP_COPS.get(c) === 'enabled')).toBe(
      true,
    );
    const pending = [...RUBOCOP_COPS].find(([, s]) => s === 'pending')![0];
    expect(rubocopSelection([pending], [])).toEqual([pending]);
    expect(rubocopSelection(['qualor-default', 'Lint/UnusedMethodArgument'], [])).toContain(
      'Lint/UnusedMethodArgument',
    );
  });

  it('removes ignored departments and cops, and never selects Lint/Syntax', () => {
    const s = rubocopSelection(
      ['qualor-default', 'Style/StringLiterals'],
      ['Security', 'Lint/Loop'],
    );
    expect(s).toContain('Style/StringLiterals');
    expect(s.some((c) => c.startsWith('Security/'))).toBe(false);
    expect(s).not.toContain('Lint/Loop');
    expect(rubocopSelection(['Lint', RUBOCOP_SYNTAX_COP], [])).not.toContain(RUBOCOP_SYNTAX_COP);
    expect(rubocopSelection(['Security'], ['Security'])).toEqual([]);
  });

  it('knows departments and cops, and nothing else', () => {
    for (const s of [
      'Lint',
      'Security',
      'Style',
      'Layout',
      'Naming',
      'Metrics',
      'Lint/UselessAssignment',
    ]) {
      expect(RUBOCOP_SELECTOR.test(s), s).toBe(true);
      expect(rubocopSelectorKnown(s), s).toBe(true);
    }
    expect(rubocopSelectorKnown('Rails')).toBe(false);
    expect(rubocopSelectorKnown('Lint/NotACop')).toBe(false);
    for (const s of ['lint', 'Lint/', 'Lint/useless', 'qualor-default', 'Lint//X', '']) {
      expect(RUBOCOP_SELECTOR.test(s), s).toBe(false);
    }
    expect(RUBOCOP_DEPARTMENTS.has('Lint')).toBe(true);
  });
});

describe('versions', () => {
  const [major, minor] = RUBOCOP_VERSION.split('.').map(Number) as [number, number];
  it('accepts every patch of the pinned minor only', () => {
    expect(rubocopVersionSupported(RUBOCOP_VERSION)).toBe(true);
    expect(rubocopVersionSupported(`${major}.${minor}.99`)).toBe(true);
    expect(rubocopVersionSupported(`${major}.${minor + 1}.0`)).toBe(false);
    expect(rubocopVersionSupported(`${major}.${minor - 1}.0`)).toBe(false);
    expect(rubocopVersionSupported('x')).toBe(false);
  });

  it('normalises target Rubies written as YAML numbers', () => {
    expect(normalizeTargetRuby(3.3)).toBe('3.3');
    expect(normalizeTargetRuby(4)).toBe('4.0');
    expect(normalizeTargetRuby('3.4')).toBe('3.4');
    expect(RUBOCOP_TARGET_RUBIES).toContain(RUBOCOP_DEFAULT_TARGET_RUBY);
  });
});

describe('rubocop quality and severity (report-format.md §7.1)', () => {
  it.each([
    ['Security/Eval', 'security', 'high'],
    ['Security/MarshalLoad', 'security', 'high'],
    ['Security/CompoundHash', 'security', 'medium'],
    ['Lint/UselessAssignment', 'reliability', 'medium'],
    ['Metrics/MethodLength', 'maintainability', 'medium'],
    ['Style/StringLiterals', 'maintainability', 'low'],
    ['Layout/LineLength', 'maintainability', 'low'],
    ['Naming/MethodName', 'maintainability', 'low'],
    ['Gemspec/RequireMFA', 'maintainability', 'low'],
    ['Bundler/OrderedGems', 'maintainability', 'low'],
    ['Migration/DepartmentName', 'maintainability', 'low'],
    ['Rails/Output', 'maintainability', 'medium'],
  ])('%s → %s %s', (cop, quality, severity) => {
    expect(rubocopQuality(cop)).toBe(quality);
    expect(rubocopSeverity(cop)).toBe(severity);
  });

  it('links each cop to its documentation', () => {
    expect(rubocopHelpUri('Lint/UselessAssignment')).toBe(
      'https://docs.rubocop.org/rubocop/latest/cops_lint.html#lintuselessassignment',
    );
    expect(rubocopHelpUri('Style/RedundantRegexpArgument')).toBe(
      'https://docs.rubocop.org/rubocop/latest/cops_style.html#styleredundantregexpargument',
    );
    expect(rubocopHelpUri('not a cop')).toBeNull();
  });
});
