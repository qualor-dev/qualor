import { generateKeyPairSync, randomUUID, type KeyObject } from 'node:crypto';
import { signLicenseKey, type LicensePayload } from '../src/license/token';
import type { VerifyOptions } from '../src/license/verify';

/** A throwaway Ed25519 signer; nothing is written to disk. */
export interface TestSigner {
  kid: string;
  /** The public key as the JWK `x` member (base64url of the raw 32 bytes). */
  x: string;
  privateKey: KeyObject;
}

export function testSigner(kid = 'test-a'): TestSigner {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const { x } = publicKey.export({ format: 'jwk' }) as { x: string };
  return { kid, x, privateKey };
}

export const T0 = new Date('2026-10-01T00:00:00.000Z');

/** enterprise.md §1.7 (5D): the features a Business key lists. */
export const BUSINESS_FEATURES: readonly string[] = Object.freeze([
  'sso',
  'audit-log',
  'llm.fix-quota',
]);

/** enterprise.md §1.7 (5D): the features an Enterprise key lists. */
export const ENTERPRISE_FEATURES: readonly string[] = Object.freeze([
  'sso',
  'sso.multi',
  'audit-log',
  'audit-log.stream',
  'llm.fix-quota',
  'scim',
]);

export function testPayload(overrides: Partial<LicensePayload> = {}): LicensePayload {
  return {
    v: 1,
    id: randomUUID(),
    customer: 'Acme Corporation',
    issued: '2026-10-01T00:00:00Z',
    expires: '2027-10-01T00:00:00Z',
    features: ['llm.fix-quota'],
    ...overrides,
  };
}

export function signTest(signer: TestSigner, payload: LicensePayload = testPayload()): string {
  return signLicenseKey(payload, signer.kid, signer.privateKey);
}

export function verifyWith(signer: TestSigner, now: Date = T0): VerifyOptions {
  return { publicKeys: { [signer.kid]: signer.x }, revoked: [], now };
}
