import { describe, expect, it } from 'vitest';
import { chooseTarget } from './target';
import { compareVersions, isPrerelease, releaseLine } from './versions';
import { compareMaven, mavenItems } from './versions/maven';

/**
 * The versions with the order of each neighbour pair between them, as the POM reference writes it
 * (`1-snapshot < 1 < 1-sp`); `?` when the pair compares the same way both ways round.
 */
function order(...versions: string[]): string {
  return versions.reduce((out, b, i) => {
    const a = versions[i - 1];
    if (a === undefined) return b;
    const ab = Math.sign(compareMaven(a, b));
    const symbol = ab === 0 - Math.sign(compareMaven(b, a)) ? ['<', '=', '>'][ab + 1] : '?';
    return `${out} ${symbol} ${b}`;
  }, '');
}

describe('Maven version order (POM reference, Version Order Specification)', () => {
  it('pads with null values', () => {
    expect(order('1', '1.1')).toBe('1 < 1.1');
    expect(order('1-snapshot', '1', '1-sp')).toBe('1-snapshot < 1 < 1-sp');
  });

  it('switches to numeric order inside a qualifier', () => {
    expect(order('1-foo2', '1-foo10')).toBe('1-foo2 < 1-foo10');
  });

  it('orders qualifiers before numbers, and "-" numbers before "." numbers', () => {
    expect(order('1.foo', '1-foo', '1-1', '1.1')).toBe('1.foo = 1-foo < 1-1 < 1.1');
  });

  it('removes trailing null values', () => {
    expect(
      order('1.ga', '1-ga', '1-0', '1.0', '1', '1.0.0', '1.final', '1.', '1-', '1.release'),
    ).toBe('1.ga = 1-ga = 1-0 = 1.0 = 1 = 1.0.0 = 1.final = 1. = 1- = 1.release');
    expect(order('1.0.0-foo.0.0', '1-foo')).toBe('1.0.0-foo.0.0 = 1-foo');
    expect(order('1.0.0-0.0.0', '1')).toBe('1.0.0-0.0.0 = 1');
    expect(order('1_0', '1_', '1')).toBe('1_0 = 1_ = 1');
  });

  it('places sp after a release', () => {
    expect(order('1-ga', '1-sp')).toBe('1-ga < 1-sp');
    expect(order('1-ga.1', '1-sp.1')).toBe('1-ga.1 < 1-sp.1');
  });

  it('removes null values at each hyphen', () => {
    expect(order('1-sp-1', '1-ga-1', '1-1')).toBe('1-sp-1 < 1-ga-1 = 1-1');
  });

  it('reads a, b and m followed by a number as alpha, beta and milestone', () => {
    expect(order('1-a1', '1-alpha-1')).toBe('1-a1 = 1-alpha-1');
    expect(order('1-b2', '1-beta-2')).toBe('1-b2 = 1-beta-2');
    expect(order('1-m3', '1-milestone-3')).toBe('1-m3 = 1-milestone-3');
    // Not directly followed by a number: `a` is an unknown qualifier, after `sp`.
    expect(order('1-alpha-1', '1-sp-1', '1-a-1')).toBe('1-alpha-1 < 1-sp-1 < 1-a-1');
  });

  it('ignores case', () => {
    expect(order('1-RC1', '1-rc1')).toBe('1-RC1 = 1-rc1');
    expect(order('1.0-SNAPSHOT', '1-snapshot')).toBe('1.0-SNAPSHOT = 1-snapshot');
    expect(order('1.0-alpha1', '1.0-ALPHA1')).toBe('1.0-alpha1 = 1.0-ALPHA1');
  });

  it('orders the known qualifiers, unknown ones after sp and lexically', () => {
    expect(order('1-alpha', '1-beta', '1-milestone', '1-rc', '1-snapshot', '1', '1-sp')).toBe(
      '1-alpha < 1-beta < 1-milestone < 1-rc < 1-snapshot < 1 < 1-sp',
    );
    expect(order('1-rc', '1-cr')).toBe('1-rc = 1-cr');
    expect(order('1', '1-final', '1-ga', '1-release')).toBe('1 = 1-final = 1-ga = 1-release');
    expect(order('1-sp', '1-abc', '1-jre', '1-xyz')).toBe('1-sp < 1-abc < 1-jre < 1-xyz');
    expect(order('1.K', '1.7')).toBe('1.K < 1.7');
    expect(order('5.aardvark', '5.zebra')).toBe('5.aardvark < 5.zebra');
    expect(order('1.b', '1.α')).toBe('1.b < 1.α');
    expect(order('1-alpha', '1-a1', '1-beta', '1-b1', '1-milestone', '1-m1', '1-rc')).toBe(
      '1-alpha < 1-a1 < 1-beta < 1-b1 < 1-milestone < 1-m1 < 1-rc',
    );
  });

  it('splits on dots, hyphens and digit/letter transitions; empty tokens are 0', () => {
    expect(mavenItems('1-1.foo-bar1baz-.1')).toEqual(mavenItems('1-1.foo-bar-1-baz-0.1'));
    expect(mavenItems('1.0.0')).toEqual(mavenItems('1'));
    expect(mavenItems('1.2-RC1')).toEqual([
      { prefix: '.', kind: 'number', value: '1' },
      { prefix: '.', kind: 'number', value: '2' },
      { prefix: '-', kind: 'qualifier', value: 'rc' },
      { prefix: '-', kind: 'number', value: '1' },
    ]);
    expect(mavenItems('0')).toEqual([]);
  });

  it('compares long numbers exactly', () => {
    expect(order('1.20191109021931', '1.20191109021932', '1.100000000000000000000')).toBe(
      '1.20191109021931 < 1.20191109021932 < 1.100000000000000000000',
    );
    expect(order('1.007', '1.7')).toBe('1.007 = 1.7');
  });

  it('orders Spring and Guava style versions (§11.4)', () => {
    expect(order('5.2.20.RELEASE', '5.2.20', '5.2.21')).toBe('5.2.20.RELEASE = 5.2.20 < 5.2.21');
    expect(order('5.3.0.M1', '5.3.0.RC1', '5.3.0')).toBe('5.3.0.M1 < 5.3.0.RC1 < 5.3.0');
    expect(order('31.1-jre', '32.0.0-android', '32.0.0-jre')).toBe(
      '31.1-jre < 32.0.0-android < 32.0.0-jre',
    );
    expect(order('1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-beta', '1.0.0-beta.2')).toBe(
      '1.0.0-alpha < 1.0.0-alpha.1 < 1.0.0-beta < 1.0.0-beta.2',
    );
    expect(order('1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1', '1.0.0')).toBe(
      '1.0.0-beta.2 < 1.0.0-beta.11 < 1.0.0-rc.1 < 1.0.0',
    );
    expect(chooseTarget('maven', '5.2.20.RELEASE', ['5.2.21'])).toEqual({
      version: '5.2.21',
      majorJump: false,
    });
  });

  it('knows pre-releases and release lines', () => {
    expect(isPrerelease('maven', '1.0-SNAPSHOT')).toBe(true);
    expect(isPrerelease('maven', '5.3.0.M1')).toBe(true);
    expect(isPrerelease('maven', '2.0.0-rc1')).toBe(true);
    expect(isPrerelease('maven', '5.2.20.RELEASE')).toBe(false);
    expect(isPrerelease('maven', '32.0.0-jre')).toBe(false);
    expect(isPrerelease('maven', '1.0-sp1')).toBe(false);
    expect(releaseLine('maven', '5.2.20.RELEASE')).toBe('5');
    expect(releaseLine('maven', '0.9.1')).toBe('0.9');
    expect(releaseLine('maven', '0-rc1')).toBe('0.0');
    expect(releaseLine('maven', 'abc')).toBeNull();
    expect(compareVersions('maven', '', '1')).toBeNull();
    expect(compareVersions('maven', '1.0', '1.1')).toBe(-1);
  });
});
