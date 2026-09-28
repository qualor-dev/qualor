import { describe, expect, it } from 'vitest';
import { deriveUsername, withSuffix } from './username';

describe('deriveUsername (sso-scim.md §8.4)', () => {
  it.each([
    [{ username: 'alice', email: null }, 'alice'],
    [{ username: 'Alice Smith', email: null }, 'Alice-Smith'],
    [{ username: null, email: 'bob.jones@acme.example' }, 'bob.jones'],
    [{ username: 'ünïcødé', email: null }, 'n-c-d'],
    [{ username: '---', email: null }, 'user'],
    [{ username: null, email: null }, 'user'],
    [{ username: 'a'.repeat(80), email: null }, 'a'.repeat(64)],
    [{ username: 'x@y', email: 'z@q' }, 'x-y'],
    [{ username: '.hidden.', email: null }, 'hidden'],
    [{ username: '', email: 'bob.jones@acme.example' }, 'bob.jones'],
    [{ username: '   ', email: 'bob.jones@acme.example' }, 'bob.jones'],
    [{ username: '', email: '' }, 'user'],
  ])('%j → %s', (claims, expected) => {
    expect(deriveUsername(claims)).toBe(expected);
    expect(expected).toMatch(/^[A-Za-z0-9._-]{1,64}$/);
  });

  it('appends a suffix within 64 characters', () => {
    expect(withSuffix('alice', 2)).toBe('alice-2');
    expect(withSuffix('a'.repeat(64), 20)).toBe('a'.repeat(61) + '-20');
  });

  it('trims a . or - left at the cut before the suffix', () => {
    const base = 'a'.repeat(60) + '.bcd';
    expect(base).toHaveLength(64);
    expect(withSuffix(base, 20)).toBe('a'.repeat(60) + '-20');
    expect(withSuffix('a'.repeat(59) + '-.bcd', 20)).toBe('a'.repeat(59) + '-20');
    expect(withSuffix(base, 20)).toMatch(/^[A-Za-z0-9._-]{1,64}$/);
  });
});
