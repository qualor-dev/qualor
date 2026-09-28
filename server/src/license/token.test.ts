import { generateKeyPairSync } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { signTest, testPayload, testSigner } from '../../test/license';
import {
  keyHash,
  MAX_KEY_LENGTH,
  normaliseKey,
  parseLicenseKey,
  signLicenseKey,
  type LicensePayload,
} from './token';

describe('licence key text (enterprise.md §3)', () => {
  const signer = testSigner();

  it('has four dot-separated segments starting QLK1 and the kid', () => {
    const key = signTest(signer);
    const [prefix, kid, payload, signature] = key.split('.');
    expect(prefix).toBe('QLK1');
    expect(kid).toBe('test-a');
    expect(JSON.parse(Buffer.from(payload!, 'base64url').toString('utf8'))).toMatchObject({ v: 1 });
    expect(Buffer.from(signature!, 'base64url')).toHaveLength(64);
  });

  it('accepts a key with whitespace anywhere in it', () => {
    const key = signTest(signer);
    const wrapped = `  ${key.slice(0, 40)}\r\n${key.slice(40, 90)}\n\t${key.slice(90)}\n`;
    expect(normaliseKey(wrapped)).toBe(key);
    expect(parseLicenseKey(wrapped)?.kid).toBe('test-a');
    expect(keyHash(wrapped)).toBe(keyHash(key));
  });

  it.each([
    ['empty', ''],
    ['three segments', 'QLK1.test-a.abc'],
    ['five segments', 'QLK1.test-a.abc.def.ghi'],
    ['another prefix', 'QLK2.test-a.YQ.' + 'A'.repeat(86)],
    ['an upper-case kid', 'QLK1.Test.YQ.' + 'A'.repeat(86)],
    ['a kid of 33 characters', `QLK1.${'a'.repeat(33)}.YQ.` + 'A'.repeat(86)],
    ['padding', 'QLK1.test-a.YQ==.' + 'A'.repeat(86)],
    ['standard base64 characters', 'QLK1.test-a.a+b/.' + 'A'.repeat(86)],
    ['a short signature', 'QLK1.test-a.YQ.' + 'A'.repeat(85)],
  ])('rejects %s as malformed', (_name, text) => {
    expect(parseLicenseKey(text)).toBeNull();
  });

  it('rejects a non-canonical base64url segment (a second spelling of the same bytes)', () => {
    const key = signTest(signer);
    const parts = key.split('.');
    // The last character of an 86-character signature carries 2 unused bits; flipping one of
    // them decodes to the same 64 bytes but is not the canonical spelling.
    const last = parts[3]!.at(-1)!;
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const twin = alphabet[alphabet.indexOf(last) ^ 1]!;
    parts[3] = parts[3]!.slice(0, -1) + twin;
    expect(parseLicenseKey(parts.join('.'))).toBeNull();
  });

  it('rejects a key longer than 8 192 characters before decoding it', () => {
    expect(parseLicenseKey('QLK1.test-a.' + 'A'.repeat(MAX_KEY_LENGTH) + '.x')).toBeNull();
  });

  /** A well-formed key of exactly `length` characters (the payload bytes are zeros). */
  function keyOfLength(kid: string, length: number): string {
    const signature = Buffer.alloc(64).toString('base64url');
    const room = length - `QLK1.${kid}..`.length - signature.length;
    const payload = Buffer.alloc((room / 4) * 3).toString('base64url');
    const key = `QLK1.${kid}.${payload}.${signature}`;
    expect(key).toHaveLength(length);
    return key;
  }

  it('accepts exactly 8 192 characters, refuses 8 193, and does not count whitespace', () => {
    expect(MAX_KEY_LENGTH).toBe(8192);
    const max = keyOfLength('test-ab', 8192);
    expect(parseLicenseKey(max)).not.toBeNull();
    expect(parseLicenseKey(keyOfLength('test-abc', 8193))).toBeNull();
    // 8 196 characters as pasted, 8 192 once the line breaks are gone.
    const wrapped = `${max.slice(0, 4000)}\r\n${max.slice(4000)}\r\n`;
    expect(wrapped).toHaveLength(8196);
    expect(parseLicenseKey(wrapped)).not.toBeNull();
  });

  it('drops a byte-order mark (U+FEFF) wherever it is, as it does whitespace', () => {
    const key = signTest(signer);
    expect(normaliseKey(`\uFEFF${key}\n`)).toBe(key);
    expect(normaliseKey(`${key.slice(0, 10)}\uFEFF${key.slice(10)}`)).toBe(key);
    expect(keyHash(`\uFEFF${key}`)).toBe(keyHash(key));
    expect(parseLicenseKey(`\uFEFF${key}`)).not.toBeNull();
  });

  it('refuses to sign a payload the server would reject', () => {
    expect(() => signTest(signer, testPayload({ features: ['Bad Feature'] }))).toThrow();
  });

  it('never writes organizations, even when given one (enterprise.md §3.1)', () => {
    const withOld = { ...testPayload(), organizations: 5 } as unknown as LicensePayload;
    const key = signLicenseKey(withOld, signer.kid, signer.privateKey);
    const json = JSON.parse(
      Buffer.from(key.split('.')[2]!, 'base64url').toString('utf8'),
    ) as object;
    expect(Object.keys(json)).toEqual(['v', 'id', 'customer', 'issued', 'expires', 'features']);
  });

  it('refuses an impossible date and a signer that is not Ed25519', () => {
    expect(() => signTest(signer, testPayload({ expires: '2027-02-30T00:00:00Z' }))).toThrow();
    expect(() => signTest(signer, testPayload({ issued: '2026-10-01T24:00:00Z' }))).toThrow();
    const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    expect(() => signLicenseKey(testPayload(), 'test-a', privateKey)).toThrow(/Ed25519/);
  });
});
