import { blake2b } from 'blakejs';
import nacl from 'tweetnacl';
import { describe, expect, it } from 'vitest';
import { sealSecret } from './sealed-box';

/** libsodium's sealed-box nonce: blake2b with a 24-byte digest of `ephemeral || recipient`. */
function nonceOf(ephemeral: Uint8Array, recipient: Uint8Array): Uint8Array {
  const input = new Uint8Array(ephemeral.length + recipient.length);
  input.set(ephemeral);
  input.set(recipient, ephemeral.length);
  return blake2b(input, undefined, 24);
}

describe('sealSecret (libsodium crypto_box_seal for GitHub Actions secrets)', () => {
  const recipient = nacl.box.keyPair();
  const publicKey = Buffer.from(recipient.publicKey).toString('base64');

  it('seals so that the recipient opens it with the blake2b nonce', () => {
    const sealed = Buffer.from(sealSecret(publicKey, 'qlr_secret value ü'), 'base64');
    const ephemeral = sealed.subarray(0, nacl.box.publicKeyLength);
    const box = sealed.subarray(nacl.box.publicKeyLength);
    expect(sealed.length).toBe(32 + 16 + Buffer.byteLength('qlr_secret value ü'));
    const opened = nacl.box.open(
      box,
      nonceOf(ephemeral, recipient.publicKey),
      ephemeral,
      recipient.secretKey,
    );
    expect(opened).not.toBeNull();
    expect(Buffer.from(opened!).toString('utf8')).toBe('qlr_secret value ü');
  });

  it('uses a fresh ephemeral key every time', () => {
    expect(sealSecret(publicKey, 'x')).not.toBe(sealSecret(publicKey, 'x'));
  });

  it('refuses a key that is not 32 bytes of base64', () => {
    expect(() => sealSecret('AAAA', 'x')).toThrow('not a repository public key');
  });
});
