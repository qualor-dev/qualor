import { describe, expect, it } from 'vitest';
import table from '../../rules/swiftlint-rules.json' with { type: 'json' };
import {
  SWIFTLINT_RULES,
  SWIFTLINT_VERSION,
  swiftlintQuality,
  swiftlintSeverity,
  swiftlintVersionSupported,
} from './swiftlint';

describe('the SwiftLint rule table (plan 8F)', () => {
  it('describes the pinned SwiftLint', () => {
    expect(table.version).toBe(SWIFTLINT_VERSION);
    expect(SWIFTLINT_RULES.size).toBe(Object.keys(table.rules).length);
    expect(SWIFTLINT_RULES.get('force_cast')?.kind).toBe('idiomatic');
    expect(SWIFTLINT_RULES.get('statement_position')?.sourceKit).toBe(true);
  });

  it('maps lint rules to reliability and every other kind to maintainability', () => {
    const lint = [...SWIFTLINT_RULES].find(([, r]) => r.kind === 'lint')?.[0] ?? '';
    const style = [...SWIFTLINT_RULES].find(([, r]) => r.kind === 'style')?.[0] ?? '';
    expect(swiftlintQuality(lint)).toBe('reliability');
    expect(swiftlintQuality(style)).toBe('maintainability');
    expect(swiftlintQuality('my_custom_rule')).toBe('maintainability');
  });

  it('grades an error high, and a warning medium for lint rules and low otherwise', () => {
    const lint = [...SWIFTLINT_RULES].find(([, r]) => r.kind === 'lint')?.[0] ?? '';
    expect(swiftlintSeverity('force_cast', 'error')).toBe('high');
    expect(swiftlintSeverity(lint, 'warning')).toBe('medium');
    expect(swiftlintSeverity('line_length', 'warning')).toBe('low');
    expect(swiftlintSeverity('my_custom_rule', 'warning')).toBe('low');
  });

  it('grades a note low and level none info (preflight 2/4)', () => {
    const lint = [...SWIFTLINT_RULES].find(([, r]) => r.kind === 'lint')?.[0] ?? '';
    expect(swiftlintSeverity(lint, 'note')).toBe('low');
    expect(swiftlintSeverity('line_length', 'note')).toBe('low');
    expect(swiftlintSeverity(lint, 'none')).toBe('info');
  });

  it('runs every patch of the pinned minor and nothing else', () => {
    const [major, minor] = SWIFTLINT_VERSION.split('.').map(Number) as [number, number];
    expect(swiftlintVersionSupported(SWIFTLINT_VERSION)).toBe(true);
    expect(swiftlintVersionSupported(`${major}.${minor}.0`)).toBe(true);
    expect(swiftlintVersionSupported(`${major}.${minor}.99`)).toBe(true);
    expect(swiftlintVersionSupported(`${major}.${minor + 1}.0`)).toBe(false);
    expect(swiftlintVersionSupported(`${major}.${minor - 1}.3`)).toBe(false);
    expect(swiftlintVersionSupported('')).toBe(false);
  });
});
