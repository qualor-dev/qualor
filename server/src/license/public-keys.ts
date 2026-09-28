/**
 * enterprise.md §4.1: the Ed25519 public keys a licence may be signed with, by key id (the JWK
 * `x`, base64url of the raw 32 bytes). Several at once, for rotation. Empty until the maintainer
 * creates the production key pair with `pnpm license:keygen`: until then no key
 * validates in a release build. Removing a kid invalidates every licence it signed.
 */
export const PRODUCTION_KEYS: Readonly<Record<string, string>> = Object.freeze({});

/** Licence ids revoked in this release (enterprise.md §4.1). */
export const REVOKED_LICENSE_IDS: readonly string[] = Object.freeze([]);

/** Set only by `buildServer({ testLicenseKeys })` in test bundles (enterprise.md §14.2). */
declare const __QUALOR_TEST_LICENSE_KEYS__: string | undefined;

const TEST_KID = /^test-[a-z0-9-]{1,27}$/;

/** The test keys of a test bundle's define; every kid must start with `test-` (ruling EE6). */
export function testKeysFrom(json: string | undefined): Record<string, string> {
  if (json === undefined) return {};
  const parsed = JSON.parse(json) as unknown;
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error('test licence keys must be a JSON object of test- key ids');
  }
  const keys: Record<string, string> = {};
  for (const [kid, x] of Object.entries(parsed)) {
    if (!TEST_KID.test(kid)) {
      throw new Error(`test licence key ids must start with "test-" (got "${kid}")`);
    }
    if (typeof x !== 'string') throw new Error(`test licence key "${kid}" must be a string`);
    keys[kid] = x;
  }
  return keys;
}

export const LICENSE_PUBLIC_KEYS: Readonly<Record<string, string>> = Object.freeze({
  ...PRODUCTION_KEYS,
  ...testKeysFrom(
    typeof __QUALOR_TEST_LICENSE_KEYS__ === 'string' ? __QUALOR_TEST_LICENSE_KEYS__ : undefined,
  ),
});
