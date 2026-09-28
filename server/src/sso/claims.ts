/**
 * sso-scim.md §4.1: every required pair must hold, exactly: the claim is a string equal to
 * `value`, or an array containing that string. A number `1` never equals `"1"`. Only the claims'
 * own properties count (a claim named `constructor` is not the object's constructor). Shared by the
 * OIDC flow (the ID token and userinfo claims) and the SAML flow (the assertion's attributes).
 */
export function requiredClaimsMet(
  required: readonly { claim: string; value: string }[],
  claims: Record<string, unknown>,
): boolean {
  return required.every(({ claim, value }) => {
    if (!Object.hasOwn(claims, claim)) return false;
    const actual = claims[claim];
    return actual === value || (Array.isArray(actual) && actual.some((v) => v === value));
  });
}
