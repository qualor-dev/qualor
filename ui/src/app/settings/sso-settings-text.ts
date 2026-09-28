import { ApiError, problemMessage } from '../api/errors';

/**
 * The fixed texts of the single sign-on settings (sso-scim.md §4, §17.2): the problem codes of the
 * connection routes and the **Test** answer, in this app's words. The server's own `message` is
 * never shown: it may name a host or echo an identity provider, and every word on screen is ours.
 */

/** §4.2, §4.3: what a failed **Test** found, by `problem.code`. */
export function testProblemText(code: string): string {
  switch (code) {
    case 'issuer_mismatch':
      return $localize`:@@sso.test.issuerMismatch:The discovery document names another issuer. Copy the issuer exactly as the identity provider publishes it.`;
    case 'client_secret':
      return $localize`:@@sso.test.clientSecret:The stored client secret cannot be read with this server's key. Give the client secret again.`;
    case 'issuer_url':
      return $localize`:@@sso.test.issuerUrl:The issuer URL is not allowed. Use https, or list the host in QUALOR_SSO_INTERNAL_HOSTS.`;
    case 'discovery':
      return $localize`:@@sso.test.discovery:The issuer's discovery document could not be read.`;
    case 'jwks':
      return $localize`:@@sso.test.jwks:The identity provider's signing keys (JWKS) could not be read.`;
    case 'sso_url':
      return $localize`:@@sso.test.ssoUrl:The SSO URL is not allowed. Use https, or list the host in QUALOR_SSO_INTERNAL_HOSTS.`;
    case 'certificates_expired':
      return $localize`:@@sso.test.certificatesExpired:No identity provider certificate is valid now.`;
    case 'sp_key':
      return $localize`:@@sso.test.spKey:The stored service provider key cannot be read with this server's key. Give the key again.`;
    case 'config_invalid':
      return $localize`:@@sso.test.configInvalid:The stored configuration is not valid. Check the fields and save the connection again.`;
    case 'fetch.not_public':
      return $localize`:@@sso.test.notPublic:The host is not public. List it in QUALOR_SSO_INTERNAL_HOSTS if Qualor may call it.`;
    case 'fetch.refused_address':
      return $localize`:@@sso.test.refusedAddress:The host resolves to an address Qualor never calls.`;
    case 'fetch.unresolved':
      return $localize`:@@sso.test.unresolved:The host name could not be resolved.`;
    case 'fetch.timeout':
    case 'fetch.connect_timeout':
      return $localize`:@@sso.test.timeout:The identity provider did not answer in time.`;
    case 'fetch.status':
      return $localize`:@@sso.test.status:The identity provider answered with an error status.`;
    case 'fetch.too_large':
      return $localize`:@@sso.test.tooLarge:The identity provider's answer is too large.`;
    case 'fetch.not_allowed':
      return $localize`:@@sso.test.notAllowed:The discovery document names an address Qualor does not call.`;
    // The request itself failed: the general text says so.
    case 'fetch.request':
    case 'fetch.connection':
    case 'fetch.invalid_url':
    case 'fetch.method':
    default:
      return $localize`:@@sso.test.failed:The test failed: the identity provider could not be reached or its answer was refused.`;
  }
}

/**
 * A refused request of the single sign-on and SCIM screens, in this app's words. `multi` says
 * whether `sso.multi` is active: without it (§4.4) enabling another connection is refused, so the
 * advice for `LAST_SSO_CONNECTION` names only the sign-in policy.
 */
export function ssoProblem(err: unknown, multi = true): string {
  if (err instanceof ApiError) {
    switch (err.code) {
      case 'SSO_CONNECTION_LIMIT_REACHED':
        return $localize`:@@sso.error.limit:Qualor has as many single sign-on connections as it can have (10). Delete one first.`;
      case 'SSO_MULTI_NOT_LICENSED':
        // §4.4: the server's own sentence, in this app's words.
        return $localize`:@@sso.error.multiNotLicensed:Your plan allows one enabled single sign-on connection. Disable the enabled one first, or keep this one disabled; several enabled connections need the Enterprise plan.`;
      case 'SSO_CONNECTION_NAME_TAKEN':
        return nameTakenText();
      case 'PUBLIC_URL_REQUIRED':
        return $localize`:@@sso.error.publicUrl:Enabling a connection needs QUALOR_PUBLIC_URL, the address people use to reach Qualor. Set it and restart the server.`;
      case 'SSO_UNAVAILABLE':
        return $localize`:@@sso.settings.unavailable:The identity provider cannot be used right now. Try again later.`;
      case 'SCIM_TOKEN_LIMIT_REACHED':
        return $localize`:@@scim.error.limit:This connection has as many active SCIM tokens as it can have (5). Revoke one first.`;
      case 'LAST_BREAK_GLASS_ADMIN':
        return $localize`:@@signIn.error.lastBreakGlass:At least one break-glass administrator must stay usable while password sign-in is limited. Set password sign-in back to everyone first.`;
      case 'LAST_SSO_CONNECTION':
        return multi
          ? $localize`:@@sso.error.lastConnection:This is the last enabled connection, and password sign-in is limited to break-glass administrators. Enable another connection, or set password sign-in back to everyone first.`
          : $localize`:@@sso.error.lastConnectionOne:This is the last enabled connection, and password sign-in is limited to break-glass administrators. Set password sign-in back to everyone first (Settings → Sign-in).`;
    }
  }
  return problemMessage(err);
}

export function nameTakenText(): string {
  return $localize`:@@sso.error.nameTaken:Another connection has this name. Names are compared ignoring case.`;
}
