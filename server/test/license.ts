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

/**
 * enterprise.md §1.7 (5D): the features a Business key lists. 6I (D10): `llm.fix-quota` left the
 * plans, since the community edition has no fix ceiling; a key issued earlier may still list it.
 */
export const BUSINESS_FEATURES: readonly string[] = Object.freeze([
  'sso',
  'audit-log',
  'support-bundle',
  'license-policy',
  'vuln.priority',
  'vuln.alerts',
  'sbom',
]);

/**
 * enterprise.md §1.7 (5D, 4E-1, 4E-2): the features an Enterprise key lists (6I D10: without
 * `llm.fix-quota`, as in the Business list).
 */
export const ENTERPRISE_FEATURES: readonly string[] = Object.freeze([
  'sso',
  'sso.multi',
  'audit-log',
  'audit-log.stream',
  'scim',
  'compliance-export',
  'portfolio',
  'llm.auto-fix',
  'support-bundle',
  'license-policy',
  'vuln.priority',
  'vuln.alerts',
  'sbom',
]);

export function testPayload(overrides: Partial<LicensePayload> = {}): LicensePayload {
  return {
    v: 1,
    id: randomUUID(),
    customer: 'Acme Corporation',
    issued: '2026-10-01T00:00:00Z',
    expires: '2027-10-01T00:00:00Z',
    // A key issued before 6I D10 lists llm.fix-quota: still accepted, and it changes nothing.
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
