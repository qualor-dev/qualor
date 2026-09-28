import { hkdfSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { decryptSecret, encryptionKey, encryptSecret } from './secrets';

describe('column encryption (data-model.md §2 `_enc`)', () => {
  const key = encryptionKey('a-server-secret-key-of-at-least-32-chars');

  it('round-trips, with a fresh IV each time', () => {
    const a = encryptSecret(key, 'whsec_example', 'webhooks');
    const b = encryptSecret(key, 'whsec_example', 'webhooks');
    expect(a.v).toBe(1);
    expect(a.iv).not.toBe(b.iv);
    expect(Buffer.from(a.iv, 'base64')).toHaveLength(12);
    expect(Buffer.from(a.tag, 'base64')).toHaveLength(16);
    expect(a.ct).not.toContain('whsec');
    expect(decryptSecret(key, a, 'webhooks')).toBe('whsec_example');
  });

  it('refuses another key, another column, a tampered envelope or a short tag (null)', () => {
    const value = encryptSecret(key, 'whsec_example', 'webhooks');
    const otherKey = encryptionKey('another-server-secret-key-of-32-chars!!');
    expect(decryptSecret(otherKey, value, 'webhooks')).toBeNull();
    expect(decryptSecret(key, value, 'scm_connections.token_enc')).toBeNull();
    const ct = Buffer.from(value.ct, 'base64');
    ct[0] = (ct[0] ?? 0) ^ 1;
    expect(decryptSecret(key, { ...value, ct: ct.toString('base64') }, 'webhooks')).toBeNull();
    const shortTag = Buffer.from(value.tag, 'base64').subarray(0, 4).toString('base64');
    expect(decryptSecret(key, { ...value, tag: shortTag }, 'webhooks')).toBeNull();
    expect(decryptSecret(key, { ...value, v: 2 as 1 }, 'webhooks')).toBeNull();
  });

  it('refuses a malformed envelope (null, never a throw)', () => {
    const value = encryptSecret(key, 'whsec_example', 'webhooks');
    const shortIv = Buffer.from(value.iv, 'base64').subarray(0, 8).toString('base64');
    expect(decryptSecret(key, { ...value, iv: shortIv }, 'webhooks')).toBeNull();
    for (const broken of [null, 'x', {}, { v: 1 }, { ...value, ct: 42 }]) {
      expect(decryptSecret(key, broken as never, 'webhooks')).toBeNull();
    }
  });

  it('derives a key that differs from the CSRF key of the same secret', () => {
    expect(encryptionKey('x'.repeat(32))).toHaveLength(32);
    expect(encryptionKey('x'.repeat(32)).equals(encryptionKey('y'.repeat(32)))).toBe(false);
    // auth/sessions.ts derives the CSRF key from the same secret with the label `csrf v1`.
    const csrfKey = Buffer.from(hkdfSync('sha256', 'x'.repeat(32), 'qualor', 'csrf v1', 32));
    expect(encryptionKey('x'.repeat(32)).equals(csrfKey)).toBe(false);
  });
});
