import { signTest, testPayload, testSigner } from './license';

/** One throwaway signer per test process for the test bundles (enterprise.md §14.2). */
export const E2E_SIGNER = testSigner('test-e2e');

/** The whole-second UTC form the licence payload takes (enterprise.md §3.1). */
const utc = (ms: number): string => new Date(ms).toISOString().replace(/\.\d{3}Z$/, 'Z');

/**
 * A key signed by `signer` that is active on the real clock: issued a day ago, a year to run;
 * `features` replaces the default list when given.
 */
export function signCurrent(signer = E2E_SIGNER, features?: string[]): string {
  const now = Date.now();
  const day = 24 * 60 * 60 * 1000;
  return signTest(
    signer,
    testPayload({
      issued: utc(now - day),
      expires: utc(now + 365 * day),
      ...(features ? { features } : {}),
    }),
  );
}
