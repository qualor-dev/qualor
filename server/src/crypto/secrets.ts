import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import type { EncryptedValue } from '../db/schema';

const IV_BYTES = 12;
const TAG_BYTES = 16;

/**
 * data-model.md §2: retrievable secrets (webhook secrets, later SCM tokens) are stored as an
 * AES-256-GCM envelope `{ v, iv, ct, tag }` in `*_enc` columns, under a key derived from
 * `QUALOR_SECRET_KEY` with HKDF. The `info` label keeps it independent of the CSRF key (ruling
 * R13, auth/sessions.ts uses `csrf v1`), and `aad` binds each ciphertext to its column, so a value
 * copied into another `_enc` column does not decrypt there. Rotating `QUALOR_SECRET_KEY` makes
 * existing values unreadable (ruling W1: the webhook must then be given a new secret).
 */
export function encryptionKey(secretKey: string): Buffer {
  return Buffer.from(hkdfSync('sha256', secretKey, 'qualor', 'column encryption v1', 32));
}

/** A fresh random 96-bit IV per value; the 128-bit tag is kept whole. */
export function encryptSecret(key: Buffer, plaintext: string, aad: string): EncryptedValue {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
  cipher.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  return {
    v: 1,
    iv: iv.toString('base64'),
    ct: ct.toString('base64'),
    tag: cipher.getAuthTag().toString('base64'),
  };
}

/**
 * The plaintext, or null when the envelope is malformed, was encrypted under another key or for
 * another column, or was tampered with. Never throws, and never says which of these it was.
 */
export function decryptSecret(key: Buffer, value: EncryptedValue, aad: string): string | null {
  try {
    if (typeof value !== 'object' || value === null || value.v !== 1) return null;
    if (typeof value.iv !== 'string' || typeof value.ct !== 'string') return null;
    if (typeof value.tag !== 'string') return null;
    const iv = Buffer.from(value.iv, 'base64');
    const tag = Buffer.from(value.tag, 'base64');
    // Only full-length IVs and tags: a truncated tag would make forgeries cheaper.
    if (iv.length !== IV_BYTES || tag.length !== TAG_BYTES) return null;
    const decipher = createDecipheriv('aes-256-gcm', key, iv, { authTagLength: TAG_BYTES });
    decipher.setAAD(Buffer.from(aad, 'utf8'));
    decipher.setAuthTag(tag);
    return Buffer.concat([
      decipher.update(Buffer.from(value.ct, 'base64')),
      decipher.final(),
    ]).toString('utf8');
  } catch {
    return null;
  }
}
