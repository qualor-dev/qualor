import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { encryptionKey, encryptSecret } from '../../crypto/secrets';
import { SCM_TOKEN_AAD } from '../connections';
import {
  decryptPrivateKey,
  decryptWebhookSecret,
  encryptPrivateKey,
  encryptWebhookSecret,
  WEBHOOK_SECRET_AAD,
} from './credentials';

const KEY = encryptionKey('k'.repeat(32));
const PKCS8 = generateKeyPairSync('rsa', { modulusLength: 2048 })
  .privateKey.export({ type: 'pkcs8', format: 'pem' })
  .toString();
// Assembled at run time, so the repository's own Gitleaks check finds no fake secret here (.gitleaks.toml).
const SECRET = ['whsec-', '0123456789abcdef'].join('');

describe('GitHub App secrets in their own columns (github.md §2.5, D1)', () => {
  it('round-trips the key (token_enc) and the webhook secret (webhook_secret_enc)', () => {
    expect(decryptPrivateKey(KEY, encryptPrivateKey(KEY, PKCS8))?.pkcs8).toBe(PKCS8);
    expect(decryptWebhookSecret(KEY, encryptWebhookSecret(KEY, SECRET))).toBe(SECRET);
    expect(decryptWebhookSecret(KEY, null)).toBeNull();
    expect(JSON.stringify(encryptPrivateKey(KEY, PKCS8))).not.toContain('PRIVATE KEY');
  });

  it('never decrypts an envelope moved to the other column', () => {
    // A webhook secret copied into token_enc, and the key copied into webhook_secret_enc.
    expect(decryptPrivateKey(KEY, encryptSecret(KEY, PKCS8, WEBHOOK_SECRET_AAD))).toBeNull();
    expect(decryptWebhookSecret(KEY, encryptSecret(KEY, SECRET, SCM_TOKEN_AAD))).toBeNull();
    expect(WEBHOOK_SECRET_AAD).not.toBe(SCM_TOKEN_AAD);
  });

  it('reads a GitLab token, another server key, or a secret out of bounds as undecryptable', () => {
    expect(decryptPrivateKey(KEY, encryptSecret(KEY, 'glpat-xyz', SCM_TOKEN_AAD))).toBeNull();
    expect(
      decryptPrivateKey(encryptionKey('o'.repeat(32)), encryptPrivateKey(KEY, PKCS8)),
    ).toBeNull();
    expect(decryptWebhookSecret(KEY, encryptSecret(KEY, 'short', WEBHOOK_SECRET_AAD))).toBeNull();
  });
});
