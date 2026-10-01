import { describe, expect, it } from 'vitest';
import {
  PHPSTAN_NO_DEPENDENCY_IDS,
  PHPSTAN_UNKNOWN_SYMBOL_IDS,
  PHPSTAN_VERSION,
  phpstanNotFinding,
  phpstanRule,
  phpstanVersionSupported,
} from './phpstan';

describe('phpstanRule (report-format.md §7.1, plan 9A)', () => {
  it.each([
    ['variable.undefined', 'reliability', 'medium'],
    ['arguments.count', 'reliability', 'medium'],
    ['method.void', 'reliability', 'medium'],
    ['deadCode.unreachable', 'reliability', 'medium'],
    ['argument.type', 'reliability', 'medium'],
    ['parameter.phpDocType', 'maintainability', 'low'],
    ['varTag.nativeType', 'maintainability', 'low'],
    ['missingType.return', 'maintainability', 'low'],
    ['method.unused', 'maintainability', 'low'],
    ['property.onlyWritten', 'maintainability', 'low'],
    ['constructor.unusedParameter', 'maintainability', 'low'],
    ['function.alreadyNarrowedType', 'maintainability', 'low'],
    ['parameter.unresolvableType', 'maintainability', 'low'],
    ['new.static', 'maintainability', 'low'],
    ['some.futureIdentifier', 'reliability', 'medium'],
  ])('%s → %s %s', (id, quality, defaultSeverity) => {
    expect(phpstanRule(id)).toEqual({ quality, kind: 'issue', defaultSeverity });
  });
});

describe('what Qualor drops (config.md §6)', () => {
  it('drops the twelve unknown-symbol identifiers, not the other notFound ones', () => {
    expect([...PHPSTAN_UNKNOWN_SYMBOL_IDS].sort()).toEqual([
      'argument.unknown',
      'attribute.notFound',
      'class.notFound',
      'classConstant.notFound',
      'constant.notFound',
      'function.notFound',
      'interface.notFound',
      'method.notFound',
      'property.notFound',
      'staticMethod.notFound',
      'staticProperty.notFound',
      'trait.notFound',
    ]);
    // An array key that does not exist is a finding, whatever is installed.
    expect(PHPSTAN_UNKNOWN_SYMBOL_IDS.has('offsetAccess.notFound')).toBe(false);
    expect([...PHPSTAN_NO_DEPENDENCY_IDS].sort()).toEqual(['class.noParent', 'new.noConstructor']);
  });

  it('knows the messages that are not findings', () => {
    expect(phpstanNotFinding('phpstan.parse')).toBe(true);
    expect(phpstanNotFinding('ignore.unmatchedLine')).toBe(true);
    expect(phpstanNotFinding('ignore.unmatchedIdentifier')).toBe(true);
    expect(phpstanNotFinding('variable.undefined')).toBe(false);
    expect(phpstanNotFinding('phpstan.other')).toBe(false);
  });
});

describe('phpstanVersionSupported', () => {
  const [major, minor] = PHPSTAN_VERSION.split('.').map(Number) as [number, number];
  it('accepts every patch of the pinned minor and nothing else', () => {
    expect(phpstanVersionSupported(PHPSTAN_VERSION)).toBe(true);
    expect(phpstanVersionSupported(`${major}.${minor}.0`)).toBe(true);
    expect(phpstanVersionSupported(`${major}.${minor}.99`)).toBe(true);
    expect(phpstanVersionSupported(`${major}.${minor + 1}.0`)).toBe(false);
    expect(phpstanVersionSupported(`${major}.${minor - 1}.9`)).toBe(false);
    expect(phpstanVersionSupported(`${major + 1}.${minor}.0`)).toBe(false);
    expect(phpstanVersionSupported('2.2.x-dev')).toBe(false);
  });
});
