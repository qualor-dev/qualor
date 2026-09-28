import { verify } from 'node:crypto';
import { LICENSE_PUBLIC_KEYS, REVOKED_LICENSE_IDS } from './public-keys';
import {
  licensePayloadSchema,
  parseLicenseKey,
  publicKeyFromX,
  type LicensePayload,
} from './token';

export type InvalidReason =
  'malformed' | 'unknown-key' | 'bad-signature' | 'bad-payload' | 'revoked' | 'not-yet-valid';

export type Verification =
  | { ok: true; kid: string; license: LicensePayload }
  | { ok: false; reason: InvalidReason; kid?: string; license?: LicensePayload };

export interface VerifyOptions {
  publicKeys: Readonly<Record<string, string>>;
  revoked: readonly string[];
  now: Date;
}

/** `issued` may be this far ahead of the server's clock (enterprise.md §4). */
export const CLOCK_SKEW_MS = 24 * 60 * 60 * 1000;

/** Strict UTF-8: a byte sequence that is not UTF-8, or a byte-order mark, is not a payload. */
const UTF8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });

export function productionVerifyOptions(now: Date): VerifyOptions {
  return { publicKeys: LICENSE_PUBLIC_KEYS, revoked: REVOKED_LICENSE_IDS, now };
}

function signatureMatches(input: Buffer, x: string, signature: Buffer): boolean {
  try {
    // `null` digest: with an Ed25519 key this is pure Ed25519 (RFC 8032), nothing else.
    return verify(null, input, publicKeyFromX(x), signature);
  } catch {
    return false;
  }
}

/** enterprise.md §4: the checks in order; the first failure wins. Expiry is a state, not a failure. */
export function verifyLicenseKey(text: string, options: VerifyOptions): Verification {
  const parsed = parseLicenseKey(text);
  if (!parsed) return { ok: false, reason: 'malformed' };
  // Own properties only: a kid such as "constructor" must never reach Object.prototype.
  const x = Object.hasOwn(options.publicKeys, parsed.kid)
    ? options.publicKeys[parsed.kid]
    : undefined;
  if (typeof x !== 'string') return { ok: false, reason: 'unknown-key' };
  // The payload is not read before its signature is checked.
  if (!signatureMatches(parsed.signingInput, x, parsed.signature)) {
    return { ok: false, reason: 'bad-signature' };
  }
  let json: unknown;
  try {
    json = JSON.parse(UTF8.decode(parsed.payload));
  } catch {
    return { ok: false, reason: 'bad-payload' };
  }
  const payload = licensePayloadSchema.safeParse(json);
  if (!payload.success) return { ok: false, reason: 'bad-payload' };
  const license = payload.data;
  // A UUID has two spellings; a revocation catches both.
  const id = license.id.toLowerCase();
  if (options.revoked.some((revoked) => revoked.toLowerCase() === id)) {
    return { ok: false, reason: 'revoked', kid: parsed.kid, license };
  }
  // Fails closed: a clock that is not a valid date never lets a key through.
  const now = options.now.getTime();
  if (!Number.isFinite(now) || Date.parse(license.issued) > now + CLOCK_SKEW_MS) {
    return { ok: false, reason: 'not-yet-valid', kid: parsed.kid, license };
  }
  return { ok: true, kid: parsed.kid, license };
}
