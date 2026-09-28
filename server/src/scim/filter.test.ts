import { describe, expect, it } from 'vitest';
import { parseScimFilter } from './filter';

/** A backslash, built at run time so no escape sequence sits in this file. */
const BS = String.fromCharCode(92);

describe('SCIM filters (sso-scim.md §12.5)', () => {
  it.each([
    [
      'userName eq "alice@acme.example"',
      'User',
      { attribute: 'userName', value: 'alice@acme.example' },
    ],
    ['USERNAME EQ "a"', 'User', { attribute: 'userName', value: 'a' }],
    ['externalId eq "9f1c"', 'User', { attribute: 'externalId', value: '9f1c' }],
    ['emails.value eq "a@b.c"', 'User', { attribute: 'emails.value', value: 'a@b.c' }],
    [
      'emails[type eq "work"].value eq "a@b.c"',
      'User',
      { attribute: 'emails.value', value: 'a@b.c' },
    ],
    [
      'id eq "0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f"',
      'User',
      { attribute: 'id', value: '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f' },
    ],
    [
      'displayName eq "Qualor Admins"',
      'Group',
      { attribute: 'displayName', value: 'Qualor Admins' },
    ],
    ['userName eq "quote \\" inside"', 'User', { attribute: 'userName', value: 'quote " inside' }],
  ])('%s', (raw, resource, expected) => {
    expect(parseScimFilter(raw, resource as 'User' | 'Group')).toEqual(expected);
  });

  it('is null without a filter', () => {
    expect(parseScimFilter(undefined, 'User')).toBeNull();
    expect(parseScimFilter('', 'User')).toBeNull();
    expect(parseScimFilter('   ', 'User')).toBeNull();
  });

  it.each(['eq', 'EQ', 'Eq', 'eQ'])('accepts the operator %s in any case', (op) => {
    expect(parseScimFilter(`userName ${op} "a"`, 'User')).toEqual({
      attribute: 'userName',
      value: 'a',
    });
  });

  it.each([
    ['USERNAME', 'userName'],
    ['ExternalId', 'externalId'],
    ['EMAILS.VALUE', 'emails.value'],
    ['Emails[Type EQ "Work"].Value', 'emails.value'],
    ['ID', 'id'],
  ])('accepts the attribute %s in any case', (attr, attribute) => {
    expect(parseScimFilter(`${attr} eq "v"`, 'User')).toEqual({ attribute, value: 'v' });
  });

  it('decodes JSON escapes in the value', () => {
    expect(parseScimFilter(`userName eq "a${BS}${BS}b${BS}u0041${BS}n"`, 'User')).toEqual({
      attribute: 'userName',
      value: 'a' + BS + 'bA\n',
    });
  });

  it('keeps the value as sent, without trimming', () => {
    expect(parseScimFilter('  userName eq " a "  ', 'User')).toEqual({
      attribute: 'userName',
      value: ' a ',
    });
  });

  it('allows a value of exactly 512 characters', () => {
    const value = 'a'.repeat(512);
    expect(parseScimFilter(`userName eq "${value}"`, 'User')).toEqual({
      attribute: 'userName',
      value,
    });
  });

  it.each([
    'userName co "a"',
    'userName sw "a"',
    'userName eq "a" and externalId eq "b"',
    'userName eq "a" or userName eq "b"',
    'not (userName eq "a")',
    'userName pr',
    'userName eq a',
    'userName eq "unterminated',
    'password eq "x"',
    'displayName eq "x"',
    'meta.created gt "2020"',
    `userName eq "${'a'.repeat(513)}"`,
  ])('refuses %s as invalidFilter', (raw) => {
    expect(() => parseScimFilter(raw, 'User')).toThrow(
      expect.objectContaining({ status: 400, scimType: 'invalidFilter' }),
    );
  });

  it('refuses userName on Groups', () => {
    expect(() => parseScimFilter('userName eq "a"', 'Group')).toThrow(
      expect.objectContaining({ scimType: 'invalidFilter' }),
    );
  });

  describe('hostile input', () => {
    const refuses = (raw: unknown, resource: 'User' | 'Group' = 'User') =>
      expect(() => parseScimFilter(raw, resource)).toThrow(
        expect.objectContaining({ status: 400, scimType: 'invalidFilter' }),
      );

    it('refuses deep parentheses quickly', () => {
      const started = performance.now();
      refuses(`${'('.repeat(10_000)}userName eq "a"${')'.repeat(10_000)}`);
      refuses('(userName eq "a")');
      refuses('((((((((((');
      expect(performance.now() - started).toBeLessThan(1_000);
    });

    it.each([
      'userName eq "',
      'userName eq "a',
      `userName eq "a${BS}"`,
      `userName eq "a" "`,
      'userName eq "a"b"',
      "userName eq 'a'",
    ])('refuses the broken quoting %s', (raw) => refuses(raw));

    it.each([
      [`userName eq "${BS}x"`, 'an unknown escape'],
      [`userName eq "${BS}u12"`, 'a short unicode escape'],
      [`userName eq "${BS}u0000"`, 'an escaped U+0000'],
      [`userName eq "${BS}ud800"`, 'an escaped lone surrogate'],
      [`userName eq "a${String.fromCharCode(0)}b"`, 'a raw U+0000'],
      [`userName eq "a${String.fromCharCode(0xdc00)}b"`, 'a raw lone surrogate'],
      ['userName eq "a\nb"', 'a raw newline'],
    ])('refuses %s (%s)', (raw) => refuses(raw));

    it('refuses a huge filter quickly, whatever its shape', () => {
      const started = performance.now();
      refuses(`userName eq "${'a'.repeat(1_000_000)}"`);
      refuses(`userName eq "${'a'.repeat(1_000_000)}`);
      refuses(`userName eq "${`${BS}"`.repeat(500_000)}`);
      refuses(`${'a'.repeat(1_000_000)} eq "x"`);
      refuses(`userName${' '.repeat(1_000_000)}eq "x"`);
      refuses(`userName eq "${`${BS}u0041`.repeat(513)}"`);
      expect(performance.now() - started).toBeLessThan(1_000);
    });

    it('refuses long and / or chains quickly', () => {
      const started = performance.now();
      refuses(Array.from({ length: 10_000 }, () => 'userName eq "a"').join(' or '));
      refuses(Array.from({ length: 10_000 }, () => 'userName eq "a"').join(' and '));
      refuses('userName eq "a" OR userName eq "b"');
      refuses('userName eq "a"and userName eq "b"');
      expect(performance.now() - started).toBeLessThan(1_000);
    });

    it.each([
      'name.givenName eq "a"',
      'emails eq "a@b.c"',
      'emails[type eq "home"].value eq "a@b.c"',
      'emails[type eq "work"] eq "a@b.c"',
      'active eq "true"',
      'members eq "x"',
      'urn:ietf:params:scim:schemas:core:2.0:User:userName eq "a"',
      '__proto__ eq "a"',
      'constructor eq "a"',
      'toString eq "a"',
    ])('refuses the unknown attribute in %s', (raw) => refuses(raw));

    it.each(['members eq "x"', 'emails.value eq "a@b.c"', 'userName eq "a"', 'active eq "true"'])(
      'refuses the attribute a Group does not filter on: %s',
      (raw) => refuses(raw, 'Group'),
    );

    it.each([
      'userName ne "a"',
      'userName ew "a"',
      'userName gt "a"',
      'userName eq true',
      'userName eq null',
      'userName eq 1',
      'userName  "a"',
      'userName eq"a"',
      'userNameeq "a"',
    ])('allows only `eq` and a string: %s', (raw) => refuses(raw));

    it.each([
      ['a list (a repeated query parameter)', ['userName eq "a"', 'userName eq "b"']],
      ['a number', 1],
      ['null', null],
      ['an object', { userName: 'a' }],
    ])('refuses %s as the filter', (_n, raw) => refuses(raw));

    it('separates only by spaces and tabs', () => {
      expect(parseScimFilter('userName\teq\t"a"', 'User')).toEqual({
        attribute: 'userName',
        value: 'a',
      });
      expect(parseScimFilter('\t', 'User')).toBeNull();
      refuses('userName\neq "a"');
      refuses('userName eq\r"a"');
      refuses(`userName${String.fromCharCode(0xa0)}eq "a"`);
      refuses(`userName eq "a"${String.fromCharCode(0x2028)}`);
      refuses('\n');
    });

    it('answers a detail that does not echo the filter', () => {
      try {
        parseScimFilter('password eq "hunter2-secret"', 'User');
        expect.unreachable();
      } catch (e) {
        expect((e as Error).message).not.toContain('hunter2');
      }
    });
  });
});
