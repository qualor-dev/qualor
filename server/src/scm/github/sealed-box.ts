import { blake2b } from 'blakejs';
import nacl from 'tweetnacl';

/**
 * Encrypts `value` for a GitHub Actions secret: libsodium's `crypto_box_seal` against the
 * repository's public key (X25519, XSalsa20-Poly1305). The result is base64 of the ephemeral public
 * key followed by the box, whose nonce is the 24-byte blake2b digest of
 * `ephemeralPublicKey || recipientPublicKey`. The ephemeral secret key is dropped at once.
 */
export function sealSecret(publicKeyBase64: string, value: string): string {
  const recipient = Buffer.from(publicKeyBase64, 'base64');
  if (recipient.length !== nacl.box.publicKeyLength) {
    throw new Error('not a repository public key');
  }
  const ephemeral = nacl.box.keyPair();
  const nonceInput = new Uint8Array(2 * nacl.box.publicKeyLength);
  nonceInput.set(ephemeral.publicKey);
  nonceInput.set(recipient, nacl.box.publicKeyLength);
  const nonce = blake2b(nonceInput, undefined, nacl.box.nonceLength);
  const box = nacl.box(Buffer.from(value, 'utf8'), nonce, recipient, ephemeral.secretKey);
  ephemeral.secretKey.fill(0);
  return Buffer.concat([ephemeral.publicKey, box]).toString('base64');
}
