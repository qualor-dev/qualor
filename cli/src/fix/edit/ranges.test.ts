import { describe, expect, it } from 'vitest';
import { rangeAllows, rangeWithTarget } from './ranges';

describe('rangeWithTarget (R22)', () => {
  it.each([
    ['^1.2.3', '^1.2.6'],
    ['~1.2.3', '~1.2.6'],
    ['1.2.3', '1.2.6'],
    ['>=1.2.3', '>=1.2.6'],
    ['=1.2.3', '=1.2.6'],
    ['^1.2.3-beta.1', '^1.2.6'],
  ])('keeps the operator of %s', (spec, expected) => {
    expect(rangeWithTarget(spec, '1.2.6')).toBe(expected);
  });

  it.each([
    '1.x',
    '>=1 <2',
    '^1 || ^2',
    'latest',
    'workspace:*',
    'catalog:',
    'npm:x@1',
    'https://x/a.tgz',
    '1.2.3 - 1.2.9',
    '^1.2',
    '>= 1.2.3',
    ' ^1.2.3',
    'v1.2.3',
    '',
  ])('refuses %j', (spec) => {
    expect(rangeWithTarget(spec, '1.2.6')).toBeNull();
  });

  it('refuses a target that is not a plain version', () => {
    expect(rangeWithTarget('^1.2.3', '1.2')).toBeNull();
    expect(rangeWithTarget('^1.2.3', 'v1.2.6')).toBeNull();
  });
});

describe('rangeAllows', () => {
  it('reads the five shapes as npm does for plain versions', () => {
    expect(rangeAllows('^1.2.3', '1.9.0')).toBe(true);
    expect(rangeAllows('^1.2.3', '2.0.0')).toBe(false);
    expect(rangeAllows('^1.2.3', '1.2.2')).toBe(false);
    expect(rangeAllows('^0.2.3', '0.2.9')).toBe(true);
    expect(rangeAllows('^0.2.3', '0.3.0')).toBe(false);
    expect(rangeAllows('^0.0.3', '0.0.4')).toBe(false);
    expect(rangeAllows('~1.2.3', '1.2.9')).toBe(true);
    expect(rangeAllows('~1.2.3', '1.3.0')).toBe(false);
    expect(rangeAllows('>=1.2.3', '7.0.0')).toBe(true);
    expect(rangeAllows('>=1.2.3', '1.2.2')).toBe(false);
    expect(rangeAllows('1.2.3', '1.2.3')).toBe(true);
    expect(rangeAllows('=1.2.3', '1.2.4')).toBe(false);
  });

  it('allows nothing for another shape', () => {
    expect(rangeAllows('1.x', '1.2.3')).toBe(false);
    expect(rangeAllows('latest', '1.2.3')).toBe(false);
  });
});
