/**
 * sso-scim.md §7.7: the codes a failed single sign-on flow sends the browser back with
 * (`/login?sso_error=<code>`), the same list as `SSO_ERROR_REASONS` in
 * server/src/audit/catalogue.ts (the UI never imports the server, rule 5). Each has a fixed
 * message; the query value itself is never shown, and an unknown one gets the generic message.
 */
export const SSO_ERROR_CODES = [
  'unavailable',
  'flow_expired',
  'flow_mismatch',
  'idp_error',
  'invalid_response',
  'replayed',
  'required_claim',
  'no_account',
  'inactive_user',
  'email_in_use',
  'username_unavailable',
  'identity_in_use',
  'already_linked',
  'rate_limited',
] as const;

export type SsoErrorCode = (typeof SSO_ERROR_CODES)[number];

export const SSO_ERROR_TEXT: Readonly<Record<SsoErrorCode, string>> = {
  unavailable: $localize`:@@sso.error.unavailable:This sign-in method is not available.`,
  flow_expired: $localize`:@@sso.error.flowExpired:The sign-in took too long or was already used. Try again.`,
  flow_mismatch: $localize`:@@sso.error.flowMismatch:The sign-in was started in another tab or browser. Start again here.`,
  idp_error: $localize`:@@sso.error.idpError:Your identity provider did not complete the sign-in. Try again, or ask an administrator.`,
  invalid_response: $localize`:@@sso.error.invalidResponse:Qualor could not accept the answer of your identity provider. Ask an administrator to check the connection.`,
  replayed: $localize`:@@sso.error.replayed:This sign-in was already used. Start again.`,
  required_claim: $localize`:@@sso.error.requiredClaim:Your identity provider account is not allowed to sign in to Qualor. Ask an administrator.`,
  no_account: $localize`:@@sso.error.noAccount:There is no Qualor account for you yet. Ask an administrator.`,
  inactive_user: $localize`:@@sso.error.inactiveUser:Your Qualor account is deactivated.`,
  email_in_use: $localize`:@@sso.error.emailInUse:Your identity provider's email already has a Qualor account. Sign in to that account and link it under Settings → Linked accounts, or ask an administrator.`,
  username_unavailable: $localize`:@@sso.error.usernameUnavailable:A Qualor account could not be created for you because your user name is already taken. Ask an administrator.`,
  identity_in_use: $localize`:@@sso.error.identityInUse:This identity provider account is already linked to another Qualor account.`,
  already_linked: $localize`:@@sso.error.alreadyLinked:Your Qualor account is already linked to an account of this identity provider.`,
  rate_limited: $localize`:@@sso.error.rateLimited:Too many sign-in attempts. Wait a minute and try again.`,
};

export const SSO_ERROR_GENERIC = $localize`:@@sso.error.generic:Single sign-on failed. Try again, or ask an administrator.`;

const KNOWN: ReadonlySet<string> = new Set(SSO_ERROR_CODES);

/** The fixed message for a `?sso_error=` value; anything else gets the generic message. */
export function ssoErrorText(code: string): string {
  return KNOWN.has(code) ? SSO_ERROR_TEXT[code as SsoErrorCode] : SSO_ERROR_GENERIC;
}
