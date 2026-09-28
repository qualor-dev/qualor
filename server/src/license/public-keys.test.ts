import { describe, expect, it } from 'vitest';
import {
  LICENSE_PUBLIC_KEYS,
  PRODUCTION_KEYS,
  REVOKED_LICENSE_IDS,
  testKeysFrom,
} from './public-keys';

describe('accepted public keys (enterprise.md §4.1)', () => {
  it('ships no test key and no production key before the maintainer adds one', () => {
    expect(Object.keys(PRODUCTION_KEYS).filter((kid) => kid.startsWith('test-'))).toEqual([]);
    // Without the esbuild define (vitest, the release build) only the production keys count.
    expect(LICENSE_PUBLIC_KEYS).toEqual(PRODUCTION_KEYS);
    expect(REVOKED_LICENSE_IDS).toEqual([]);
  });

  it('every production key is a 32-byte Ed25519 key in base64url', () => {
    for (const [kid, x] of Object.entries(PRODUCTION_KEYS)) {
      expect(kid).toMatch(/^[a-z0-9][a-z0-9-]{0,31}$/);
      expect(Buffer.from(x, 'base64url')).toHaveLength(32);
    }
  });

  it('accepts test keys only under a test- kid', () => {
    expect(testKeysFrom(undefined)).toEqual({});
    expect(testKeysFrom(JSON.stringify({ 'test-e2e': 'AAAA' }))).toEqual({ 'test-e2e': 'AAAA' });
    expect(() => testKeysFrom(JSON.stringify({ k2026: 'AAAA' }))).toThrow(/test-/);
  });
});
