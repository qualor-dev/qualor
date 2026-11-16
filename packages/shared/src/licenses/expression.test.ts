import { describe, expect, it } from 'vitest';
import { formatLicenseExpression, parseLicenseExpression } from './expression';

const id = (v: string) => ({ kind: 'id', id: v });

describe('parseLicenseExpression', () => {
  it('parses a single id', () => {
    expect(parseLicenseExpression('MIT')).toEqual(id('MIT'));
  });

  it('refuses a text over 1 024 characters instead of recursing through it', () => {
    expect(parseLicenseExpression(`${'MIT AND '.repeat(5_000)}MIT`)).toBeNull();
    expect(parseLicenseExpression(`${'('.repeat(10_000)}MIT${')'.repeat(10_000)}`)).toBeNull();
    const longest = `${'MIT AND '.repeat(127)}ISC-1234`;
    expect(longest).toHaveLength(1_024);
    expect(parseLicenseExpression(longest)).not.toBeNull();
    expect(parseLicenseExpression(`${longest}5`)).toBeNull();
  });

  it('parses OR', () => {
    expect(parseLicenseExpression('MIT OR Apache-2.0')).toEqual({
      kind: 'or',
      left: id('MIT'),
      right: id('Apache-2.0'),
    });
  });

  it('parses parentheses', () => {
    expect(parseLicenseExpression('(MIT OR GPL-3.0-only) AND BSD-3-Clause')).toEqual({
      kind: 'and',
      left: { kind: 'or', left: id('MIT'), right: id('GPL-3.0-only') },
      right: id('BSD-3-Clause'),
    });
  });

  it('parses WITH', () => {
    expect(parseLicenseExpression('GPL-2.0-only WITH Classpath-exception-2.0')).toEqual({
      kind: 'with',
      id: 'GPL-2.0-only',
      exception: 'Classpath-exception-2.0',
    });
  });

  it('gives WITH > AND > OR precedence', () => {
    expect(parseLicenseExpression('A OR B AND C WITH Classpath-exception-2.0')).toEqual({
      kind: 'or',
      left: id('A'),
      right: {
        kind: 'and',
        left: id('B'),
        right: { kind: 'with', id: 'C', exception: 'Classpath-exception-2.0' },
      },
    });
  });

  it('reads a + suffix as -or-later', () => {
    expect(parseLicenseExpression('GPL-2.0+')).toEqual(id('GPL-2.0-or-later'));
    expect(parseLicenseExpression('LGPL-2.1-only+')).toEqual(id('LGPL-2.1-only'));
    expect(parseLicenseExpression('EUPL-1.2+')).toEqual(id('EUPL-1.2'));
  });

  it('is case-insensitive in keywords and ids', () => {
    expect(parseLicenseExpression('mit or apache-2.0')).toEqual({
      kind: 'or',
      left: id('MIT'),
      right: id('Apache-2.0'),
    });
    expect(parseLicenseExpression('gpl-2.0-only with classpath-exception-2.0')).toEqual({
      kind: 'with',
      id: 'GPL-2.0-only',
      exception: 'Classpath-exception-2.0',
    });
  });

  it('reads a deprecated -with- id as its id WITH exception', () => {
    expect(parseLicenseExpression('GPL-2.0-with-classpath-exception')).toEqual({
      kind: 'with',
      id: 'GPL-2.0-only',
      exception: 'Classpath-exception-2.0',
    });
    expect(parseLicenseExpression('GPL-2.0-with-classpath-exception WITH Foo')).toBeNull();
  });

  it('keeps an id that is not on the SPDX list as written', () => {
    expect(parseLicenseExpression('Weird-Licence OR MIT')).toEqual({
      kind: 'or',
      left: id('Weird-Licence'),
      right: id('MIT'),
    });
  });

  it('splits on parentheses without spaces', () => {
    expect(parseLicenseExpression('(MIT)OR(ISC)')).toEqual({
      kind: 'or',
      left: id('MIT'),
      right: id('ISC'),
    });
  });

  it.each([
    'MIT OR',
    '(MIT',
    'AND',
    '',
    '   ',
    'MIT)',
    'MIT AND OR ISC',
    'MIT WITH',
    'Public Domain',
    '()',
  ])('returns null for %j', (text) => {
    expect(parseLicenseExpression(text)).toBeNull();
  });
});

describe('formatLicenseExpression', () => {
  it('round-trips and parenthesises an OR inside an AND', () => {
    for (const text of [
      'MIT',
      'MIT OR Apache-2.0',
      '(MIT OR GPL-3.0-only) AND BSD-3-Clause',
      'GPL-2.0-only WITH Classpath-exception-2.0',
    ]) {
      expect(formatLicenseExpression(parseLicenseExpression(text)!)).toBe(text);
    }
  });
});
