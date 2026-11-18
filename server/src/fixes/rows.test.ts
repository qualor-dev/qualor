import { describe, expect, it } from 'vitest';
import { EMPTY_PACKAGE_SLUG, fixBranchName, packageSlug } from './rows';

/**
 * git's own ref rules (`git check-ref-format`, ruling T5a), as the test reads them: the reasons a
 * name breaks them, empty when it is a valid ref.
 */
function refProblems(name: string): string[] {
  const problems: string[] = [];
  const segments = name.split('/');
  if (name.includes('..')) problems.push('".." anywhere');
  if (name.includes('@{')) problems.push('"@{"');
  if (name.endsWith('/') || name.endsWith('.')) problems.push('trailing "/" or "."');
  if (name.includes('//')) problems.push('"//"');
  // Control characters, space, DEL and ~ ^ : ? * [ \.
  const forbidden = [...name].some((c) => c.charCodeAt(0) <= 0x20 || c.charCodeAt(0) === 0x7f);
  if (forbidden || /[~^:?*[\\]/.test(name)) problems.push('a forbidden character');
  for (const segment of segments) {
    if (segment === '.' || segment === '..') problems.push(`segment "${segment}"`);
    if (segment.startsWith('.')) problems.push(`segment "${segment}" starts with "."`);
    if (segment.endsWith('.lock')) problems.push(`segment "${segment}" ends with ".lock"`);
  }
  if (name.length > 100) problems.push(`${name.length} characters`);
  return problems;
}

describe('fix branch names (spec §6.7, R32, Review Focus 3)', () => {
  it('slugs scoped, mixed-case, dotted and colon names', () => {
    expect(fixBranchName('js', '@Types/Node', 1)).toBe('qualor/fix/js/types-node');
    expect(fixBranchName('maven', 'org.springframework:spring-core', 1)).toBe(
      'qualor/fix/maven/org.springframework-spring-core',
    );
    expect(fixBranchName('python', 'Django_Rest', 3)).toBe('qualor/fix/python/django_rest-3');
    expect(fixBranchName('js', '@a/b', 1)).toBe('qualor/fix/js/a-b');
    expect(fixBranchName('js', 'a-b', 2)).toBe('qualor/fix/js/a-b-2');
  });

  it('cuts a long slug to 100 characters and keeps the -n suffix', () => {
    const name = fixBranchName('js', 'x'.repeat(300), 2);
    expect(name.length).toBeLessThanOrEqual(100);
    expect(name).toMatch(/^qualor\/fix\/js\/x+-2$/);
    const python = fixBranchName('python', 'y'.repeat(300), 12345);
    expect(python).toHaveLength(100);
    expect(python.endsWith('-12345')).toBe(true);
    expect(fixBranchName('js', 'z'.repeat(300), 1)).toHaveLength(100);
  });

  it('never leaves ".." or a ".lock" ending', () => {
    const name = fixBranchName('js', 'a..b.lock', 1);
    expect(name).not.toContain('..');
    expect(name.endsWith('.lock')).toBe(false);
    expect(name).toBe('qualor/fix/js/a.b-lock');
  });

  it.each([
    ['@scope/.hidden', 'scope-.hidden'],
    ['.hidden', 'hidden'],
    ['foo.lock', 'foo-lock'],
    ['.lock', 'lock'],
    ['a.lock.lock', 'a.lock-lock'],
    ['a~b^c:d', 'a-b-c-d'],
    ['x@{y}', 'x-y'],
    ['q?w*e[r\\t', 'q-w-e-r-t'],
    ['trailing.', 'trailing'],
    ['trailing/', 'trailing'],
    ['a//b', 'a-b'],
    ['a b\tc\u0001d\u007f', 'a-b-c-d'],
    ['Ünïcode', 'n-code'],
    ['..', EMPTY_PACKAGE_SLUG],
    ['@#$%', EMPTY_PACKAGE_SLUG],
    ['', EMPTY_PACKAGE_SLUG],
  ])('slugs %j to %j, a valid ref', (raw, slug) => {
    expect(packageSlug(raw)).toBe(slug);
    for (const n of [1, 2]) {
      const name = fixBranchName('js', raw, n);
      expect(refProblems(name), name).toEqual([]);
    }
  });

  it('keeps every name a valid ref when the cut lands on a dot, a dash or ".lock"', () => {
    // The 86-character room of `qualor/fix/js/` is cut so the slug would end on `.`, `-` or `.lock`.
    for (const tail of ['.', '-', '.lock', '..', '.-.', '-.lock']) {
      for (let pad = 70; pad <= 90; pad += 1) {
        for (const n of [1, 2, 99]) {
          const name = fixBranchName('js', `${'p'.repeat(pad)}${tail}${'q'.repeat(20)}`, n);
          expect(refProblems(name), name).toEqual([]);
        }
      }
    }
    // A name of only symbols past the cut still has a slug.
    expect(fixBranchName('js', `${'.'.repeat(200)}`, 3)).toBe(
      `qualor/fix/js/${EMPTY_PACKAGE_SLUG}-3`,
    );
  });

  it('refuses a number below 1', () => {
    expect(() => fixBranchName('go', 'x', 0)).toThrow(RangeError);
    expect(() => fixBranchName('go', 'x', 1.5)).toThrow(RangeError);
  });
});
