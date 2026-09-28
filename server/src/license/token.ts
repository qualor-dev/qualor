import { createHash, createPublicKey, sign, type KeyObject } from 'node:crypto';
import { z } from 'zod';

/** enterprise.md §3: `QLK1.<kid>.<payload>.<signature>`. */
export const KEY_PREFIX = 'QLK1';
export const MAX_KEY_LENGTH = 8192;
export const KID_PATTERN = /^[a-z0-9][a-z0-9-]{0,31}$/;
export const FEATURE_PATTERN = /^[a-z][a-z0-9-]*(\.[a-z][a-z0-9-]*)*$/;
/**
 * enterprise.md §1.4, §3.1: feature names no plugin implements any more. A key that lists one
 * still verifies (unknown and retired names are kept and ignored, §3.1); only `pnpm license:sign`
 * refuses one in `--features` (§15).
 */
export const RETIRED_FEATURES: readonly string[] = Object.freeze(['rbac']);
const BASE64URL = /^[A-Za-z0-9_-]+$/;
const ISO_UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,3})?Z$/;
const ED25519_SIGNATURE_BYTES = 64;

/**
 * A real instant: V8's `Date.parse` rolls `2027-02-30` over to March and `24:00:00` over to the
 * next day, so the parsed value must print back as the same date and time.
 */
function isRealTimestamp(text: string): boolean {
  const ms = Date.parse(text);
  return !Number.isNaN(ms) && new Date(ms).toISOString().slice(0, 19) === text.slice(0, 19);
}

const timestamp = z
  .string()
  .regex(ISO_UTC, 'an ISO-8601 UTC timestamp')
  .refine(isRealTimestamp, 'a real date');

export const licensePayloadSchema = z
  .strictObject({
    v: z.literal(1),
    id: z.uuid(),
    customer: z
      .string()
      .min(1)
      .max(200)
      .regex(/^[^\p{Cc}]+$/u, 'no control characters'),
    issued: timestamp,
    expires: timestamp,
    /** enterprise.md §3.1: retired on 2026-09-28. Accepted with any value from older keys, then dropped. */
    organizations: z.unknown().optional(),
    features: z
      .array(z.string().max(64).regex(FEATURE_PATTERN))
      .max(64)
      .refine((list) => new Set(list).size === list.length, 'features must be distinct'),
  })
  .refine((p) => Date.parse(p.issued) < Date.parse(p.expires), {
    message: 'issued must be before expires',
    path: ['expires'],
  })
  .transform((p) => {
    const { organizations, ...licence } = p;
    void organizations;
    return licence;
  });

export type LicensePayload = z.output<typeof licensePayloadSchema>;

export interface ParsedKey {
  kid: string;
  payload: Buffer;
  signature: Buffer;
  /** The ASCII bytes the signature covers: `QLK1.<kid>.<payload>`. */
  signingInput: Buffer;
}

/**
 * A pasted key may be wrapped, and a Windows editor may put a byte-order mark in front of it:
 * every ASCII whitespace character and every U+FEFF is dropped (§3). The upload, the boot and
 * `license:inspect` all go through this one function.
 */
export function normaliseKey(text: string): string {
  return text.replace(/[\t\n\v\f\r \uFEFF]+/g, '');
}

/** SHA-256 of the whitespace-free key, to tell whether a stored key is the boot key. */
export function keyHash(text: string): string {
  return createHash('sha256').update(normaliseKey(text), 'utf8').digest('hex');
}

/** Only the canonical spelling decodes: no padding, and it must re-encode to itself. */
function decodeCanonical(segment: string): Buffer | null {
  if (!BASE64URL.test(segment)) return null;
  const bytes = Buffer.from(segment, 'base64url');
  return bytes.toString('base64url') === segment ? bytes : null;
}

/** The shape of §3 only; nothing here is trusted until `verifyLicenseKey` checked the signature. */
export function parseLicenseKey(text: string): ParsedKey | null {
  const key = normaliseKey(text);
  if (key.length === 0 || key.length > MAX_KEY_LENGTH) return null;
  const parts = key.split('.');
  if (parts.length !== 4) return null;
  const [prefix, kid, payloadText, signatureText] = parts as [string, string, string, string];
  if (prefix !== KEY_PREFIX || !KID_PATTERN.test(kid)) return null;
  const payload = decodeCanonical(payloadText);
  const signature = decodeCanonical(signatureText);
  if (!payload || !signature || signature.length !== ED25519_SIGNATURE_BYTES) return null;
  return {
    kid,
    payload,
    signature,
    signingInput: Buffer.from(`${prefix}.${kid}.${payloadText}`, 'ascii'),
  };
}

/** Used by tests and `pnpm license:sign`; the server itself never signs. */
export function signLicenseKey(
  payload: LicensePayload,
  kid: string,
  privateKey: KeyObject,
): string {
  const valid = licensePayloadSchema.parse(payload);
  if (!KID_PATTERN.test(kid)) throw new Error(`invalid key id "${kid}"`);
  if (privateKey.type !== 'private' || privateKey.asymmetricKeyType !== 'ed25519') {
    throw new Error('a licence key is signed with an Ed25519 private key');
  }
  const body = Buffer.from(JSON.stringify(valid), 'utf8').toString('base64url');
  const input = `${KEY_PREFIX}.${kid}.${body}`;
  const key = `${input}.${sign(null, Buffer.from(input, 'ascii'), privateKey).toString('base64url')}`;
  if (key.length > MAX_KEY_LENGTH)
    throw new Error(`a licence key is at most ${MAX_KEY_LENGTH} characters`);
  return key;
}

/** An Ed25519 public key from its JWK `x` member (base64url of the raw 32 bytes). */
export function publicKeyFromX(x: string): KeyObject {
  const key = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x }, format: 'jwk' });
  // No algorithm confusion: whatever the map holds, only an Ed25519 public key verifies.
  if (key.asymmetricKeyType !== 'ed25519') throw new Error('not an Ed25519 public key');
  return key;
}
