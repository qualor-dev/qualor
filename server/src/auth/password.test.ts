import { describe, expect, it } from 'vitest';
import { hashPassword, verifyPassword } from './password';

describe('password hashing', () => {
  it('uses argon2id with the OWASP baseline cost and a fresh salt', async () => {
    const a = await hashPassword('correct horse battery');
    const b = await hashPassword('correct horse battery');
    expect(a).toMatch(/^\$argon2id\$v=19\$m=19456,t=2,p=1\$/);
    expect(a).not.toBe(b);
  });

  it('verifies only the right password', async () => {
    const stored = await hashPassword('correct horse battery');
    expect(await verifyPassword(stored, 'correct horse battery')).toBe(true);
    expect(await verifyPassword(stored, 'Correct horse battery')).toBe(false);
  });

  it('returns false without a stored hash or with a malformed one', async () => {
    expect(await verifyPassword(null, 'anything at all')).toBe(false);
    expect(await verifyPassword('not-a-phc-string', 'anything at all')).toBe(false);
  });
});
