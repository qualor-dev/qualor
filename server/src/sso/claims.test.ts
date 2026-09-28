import { describe, expect, it } from 'vitest';
import { requiredClaimsMet } from './claims';

describe('requiredClaimsMet (sso-scim.md §4.1)', () => {
  it('holds for a string claim equal to the value', () => {
    expect(requiredClaimsMet([{ claim: 'hd', value: 'example.com' }], { hd: 'example.com' })).toBe(
      true,
    );
    expect(requiredClaimsMet([{ claim: 'hd', value: 'example.com' }], { hd: 'Example.com' })).toBe(
      false,
    );
  });

  it('holds for an array claim containing the value', () => {
    expect(requiredClaimsMet([{ claim: 'roles', value: 'dev' }], { roles: ['ops', 'dev'] })).toBe(
      true,
    );
    expect(requiredClaimsMet([{ claim: 'roles', value: 'dev' }], { roles: ['ops'] })).toBe(false);
  });

  it('refuses a missing claim', () => {
    expect(requiredClaimsMet([{ claim: 'hd', value: 'example.com' }], {})).toBe(false);
  });

  it('refuses a number 1 against "1", in an array too', () => {
    expect(requiredClaimsMet([{ claim: 'level', value: '1' }], { level: 1 })).toBe(false);
    expect(requiredClaimsMet([{ claim: 'level', value: '1' }], { level: [1] })).toBe(false);
  });

  it('holds for an empty requirement list', () => {
    expect(requiredClaimsMet([], {})).toBe(true);
  });

  it('needs every pair', () => {
    const required = [
      { claim: 'hd', value: 'example.com' },
      { claim: 'roles', value: 'dev' },
    ];
    expect(requiredClaimsMet(required, { hd: 'example.com', roles: ['dev'] })).toBe(true);
    expect(requiredClaimsMet(required, { hd: 'example.com', roles: [] })).toBe(false);
  });

  it('never reads an inherited property', () => {
    expect(requiredClaimsMet([{ claim: 'constructor', value: 'x' }], {})).toBe(false);
  });
});
