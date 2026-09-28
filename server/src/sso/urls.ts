import { baseUrlProblem } from '../scm/url';

export interface SsoUrls {
  /** OIDC: the redirect URI registered at the IdP. */
  redirectUri: string;
  /** SAML: the Assertion Consumer Service URL. */
  acsUrl: string;
  /** SAML: the SP entity id, which is also where the SP metadata is served. */
  entityId: string;
  metadataUrl: string;
  /** Relative: the sign-in page's button starts the flow here. */
  startUrl: string;
}

/** spec §4.1: every URL an IdP needs, from QUALOR_PUBLIC_URL (never from a Host header). */
export function ssoUrls(publicUrl: string, connectionId: string): SsoUrls {
  const base = publicUrl.replace(/\/+$/, '');
  const metadata = `${base}/api/v0/ee/sso/saml/${connectionId}/metadata`;
  return {
    redirectUri: `${base}/api/v0/ee/sso/oidc/${connectionId}/callback`,
    acsUrl: `${base}/api/v0/ee/sso/saml/${connectionId}/acs`,
    entityId: metadata,
    metadataUrl: metadata,
    startUrl: `/api/v0/ee/sso/${connectionId}/start`,
  };
}

const MAX_URL_LENGTH = 2_048;
const INTERNAL_HOSTS = 'QUALOR_SSO_INTERNAL_HOSTS';

/**
 * WHATWG parsing silently drops tabs and line breaks anywhere and spaces at either end; a URL
 * holding them is refused instead, so what is stored is what the admin typed.
 */
function whitespaceProblem(raw: string): string | null {
  if (/[\t\n\r]/.test(raw) || raw !== raw.trim()) {
    return 'The URL must not contain tabs, line breaks, or spaces at either end';
  }
  return null;
}

/**
 * spec §4.2: an OIDC issuer is `https` (or `http` for a host in QUALOR_SSO_INTERNAL_HOSTS), at
 * most 2 048 characters, without credentials, query or fragment (an issuer has none). A trailing
 * slash is allowed: it is part of the issuer (Auth0's end in `/`).
 */
export function issuerProblem(raw: string, internalHosts: ReadonlySet<string>): string | null {
  const blank = whitespaceProblem(raw);
  if (blank) return blank;
  return baseUrlProblem(raw, internalHosts, {
    variable: INTERNAL_HOSTS,
    credential: 'the client secret',
  });
}

/**
 * spec §4.2: the issuer as stored, which discovery must match exactly: the WHATWG form, except
 * that the `/` WHATWG adds to a bare origin is not added (`https://accounts.google.com` stays as
 * given); a trailing slash the admin typed is kept.
 */
export function normalIssuer(raw: string): string {
  const url = new URL(raw);
  if (url.pathname === '/' && !raw.endsWith('/')) return url.href.slice(0, -1);
  return url.href;
}

/** OIDC Discovery §4: one trailing `/` of the issuer is removed before the well-known path. */
export function oidcDiscoveryUrl(issuer: string): string {
  const base = issuer.endsWith('/') ? issuer.slice(0, -1) : issuer;
  return `${base}/.well-known/openid-configuration`;
}

/**
 * spec §4.3: a SAML IdP URL (`idpSsoUrl`, `metadataUrl`): the issuer's rules, except that a
 * query is allowed (Google's `?idpid=`, Entra ID's `?appid=`). No fragment, no credentials.
 */
export function idpUrlProblem(raw: string, internalHosts: ReadonlySet<string>): string | null {
  if (raw.length > MAX_URL_LENGTH) return 'The URL is too long';
  const blank = whitespaceProblem(raw);
  if (blank) return blank;
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return 'Not a valid URL';
  }
  if (url.href.length > MAX_URL_LENGTH) return 'The URL is too long';
  if (url.hash !== '' || raw.includes('#')) return 'The URL must not contain a fragment';
  const query = raw.indexOf('?');
  return baseUrlProblem(query === -1 ? raw : raw.slice(0, query), internalHosts, {
    variable: INTERNAL_HOSTS,
    credential: 'the certificates, not a password in the URL',
  });
}

/** The stored form of a SAML IdP URL: WHATWG, query kept. */
export function normalIdpUrl(raw: string): string {
  return new URL(raw).href;
}
