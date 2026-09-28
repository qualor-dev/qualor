import type { KeyObject } from 'node:crypto';
import { decryptSecret, encryptSecret } from '../../crypto/secrets';
import type { EncryptedValue } from '../../db/schema';
import { SCM_TOKEN_AAD } from '../connections';
import { parseAppPrivateKey, WEBHOOK_SECRET_PATTERN } from './app-auth';

/**
 * github.md §2.5 (D1): the webhook secret's AAD, its own, so its envelope never decrypts in
 * `token_enc` and the key's never decrypts in `webhook_secret_enc`.
 */
export const WEBHOOK_SECRET_AAD = 'scm_connections.webhook_secret_enc';

/** github.md §5.4. */
export const UNDECRYPTABLE_KEY =
  'The stored GitHub App private key cannot be decrypted (QUALOR_SECRET_KEY changed?); set it again';

/** The canonical PKCS#8 PEM (`parseAppPrivateKey(...).pkcs8`) into `token_enc`. */
export function encryptPrivateKey(key: Buffer, pkcs8: string): EncryptedValue {
  return encryptSecret(key, pkcs8, SCM_TOKEN_AAD);
}

/** The key, or null when `token_enc` does not decrypt or does not hold an RSA key Qualor accepts. */
export function decryptPrivateKey(
  key: Buffer,
  value: EncryptedValue,
): { key: KeyObject; pkcs8: string } | null {
  const pem = decryptSecret(key, value, SCM_TOKEN_AAD);
  if (pem === null) return null;
  const parsed = parseAppPrivateKey(pem);
  return 'key' in parsed ? parsed : null;
}

export function encryptWebhookSecret(key: Buffer, secret: string): EncryptedValue {
  return encryptSecret(key, secret, WEBHOOK_SECRET_AAD);
}

/** The secret, or null when unset, undecryptable, or not a secret Qualor would have stored. */
export function decryptWebhookSecret(key: Buffer, value: EncryptedValue | null): string | null {
  if (value === null) return null;
  const secret = decryptSecret(key, value, WEBHOOK_SECRET_AAD);
  return secret !== null && WEBHOOK_SECRET_PATTERN.test(secret) ? secret : null;
}
