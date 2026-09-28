import { describe, expect, it } from 'vitest';
import { safeReturnTo } from './return-to';

const ch = (code: number) => String.fromCharCode(code);
const BACKSLASH = ch(92);

describe('safeReturnTo (sso-scim.md §7.3)', () => {
  it.each([
    ['/projects/abc?tab=issues', '/projects/abc?tab=issues'],
    ['/', '/'],
    ['/projects/a%2Fb#frag', '/projects/a%2Fb#frag'],
    ['/projects/caf%C3%A9', '/projects/caf%C3%A9'],
    ['/search?q=100%25', '/search?q=100%25'],
    ['/search?q=50%', '/search?q=50%'],
    [undefined, '/'],
    [null, '/'],
    [42, '/'],
    ['', '/'],
    ['//evil.example', '/'],
    ['/' + BACKSLASH + 'evil.example', '/'],
    ['/a' + BACKSLASH + 'b', '/'],
    ['https://evil.example/x', '/'],
    ['javascript:alert(1)', '/'],
    ['projects', '/'],
    [' /projects', '/'],
    ['/a' + ch(10) + 'b', '/'],
    ['/' + ch(9) + '/evil.example', '/'],
    ['/a' + ch(0) + 'b', '/'],
    ['/a' + ch(0x7f) + 'b', '/'],
    ['/a' + ch(0x85) + 'b', '/'],
    ['/a' + ch(0x2028) + 'b', '/'],
    ['/caf' + ch(0xe9), '/'],
    ['/' + 'a'.repeat(2048), '/'],
    [['/a'], '/'],
    // Encoded tricks: whatever a later decoder makes of it must still be a same-origin path.
    ['/%2F%2Fevil.example', '/'],
    ['/%2f/evil.example', '/'],
    ['/%5Cevil.example', '/'],
    ['/%5cevil.example', '/'],
    ['/%252F%252Fevil.example', '/'],
    ['/%25252F%25252Fevil.example', '/'],
    ['/%09/evil.example', '/'],
    ['/a%0Ab', '/'],
    ['/a%00b', '/'],
    ['/a%7Fb', '/'],
    ['/%E0%A4%A', '/'],
    // Dot segments that normalise into `//host`, plain and encoded.
    ['/.//evil', '/'],
    ['/..//evil', '/'],
    ['/a/..//evil', '/'],
    ['/%2e//evil', '/'],
    ['/%2E%2E//evil', '/'],
    ['/a/%2e%2e//evil', '/'],
    ['/.%2F%2Fevil', '/'],
    ['/%252e//evil', '/'],
    ['/%252E%252E//evil', '/'],
    ['/a/%252e%252e//evil', '/'],
    ['/.%252F%252Fevil', '/'],
    ['/..%252F%252Fevil', '/'],
  ])('%j → %s', (raw, expected) => {
    expect(safeReturnTo(raw)).toBe(expected);
  });

  it('keeps a path of exactly 2 048 characters', () => {
    const path = '/' + 'a'.repeat(2047);
    expect(safeReturnTo(path)).toBe(path);
  });
});
