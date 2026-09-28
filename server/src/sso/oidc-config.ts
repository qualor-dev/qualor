import * as client from 'openid-client';
import type { Resolver } from '../http/outbound';
import { isInternalHostAllowed } from '../scm/url';
import type { LoadedConnection } from './connections';
import { createSsoFetch, type SsoFetch } from './fetch';
import { oidcDiscoveryUrl } from './urls';

/**
 * spec §4.2: the discovery document is cached per connection for 1 hour; the JWKS is openid-client's
 * (refetched after 5 minutes, or once for an unknown kid, §3.2).
 */
const TTL_MS = 60 * 60_000;
/** spec §5: 60 s of clock tolerance on the ID token's times. */
const CLOCK_TOLERANCE_S = 60;
/** spec §14: 10 s for each request (ssoFetch holds its own deadline too). */
const TIMEOUT_S = 10;

export interface OidcConfiguration {
  config: client.Configuration;
  fetch: SsoFetch;
}

interface Entry {
  key: string;
  at: number;
  value: OidcConfiguration;
}
const cache = new Map<string, Entry>();

/** The message of the error thrown when discovery names another issuer (the connection test). */
export const ISSUER_MISMATCH = 'the discovery document names another issuer';

export function forgetOidcConfiguration(connectionId: string): void {
  cache.delete(connectionId);
}

/**
 * spec §4.2, §14: discovery of the configured issuer, through ssoFetch, cached for an hour per
 * row version (`updated_at`). The discovery document's `issuer` must equal the configured one
 * exactly: openid-client compares normalised forms only, and skips the comparison for Entra ID
 * (`login.microsoftonline.com`), Azure AD B2C (`*.b2clogin.com`) and a URL already holding
 * `/.well-known/`, so the pin is checked here, before any endpoint is allowed. Only the token,
 * JWKS and userinfo endpoints discovery named are added to the fetch's allow-list.
 */
export async function oidcConfiguration(
  connection: LoadedConnection,
  deps: { internalHosts: ReadonlySet<string>; resolve?: Resolver; now?: () => number },
): Promise<OidcConfiguration> {
  if (connection.parsed.protocol !== 'oidc') throw new Error('not an OIDC connection');
  const now = deps.now ?? Date.now;
  const key = `${connection.row.id}:${String(connection.row.updatedAt.getTime())}`;
  const hit = cache.get(connection.row.id);
  if (hit && hit.key === key && now() - hit.at < TTL_MS) return hit.value;

  const cfg = connection.parsed.config;
  const issuer = new URL(cfg.issuer);
  if (issuer.href.includes('/.well-known/')) throw new Error('the issuer is not an issuer URL');
  if (issuer.protocol === 'http:' && !isInternalHostAllowed(issuer, deps.internalHosts)) {
    throw new Error('an http issuer must be listed in QUALOR_SSO_INTERNAL_HOSTS');
  }
  if (connection.clientSecret === null) throw new Error('the connection has no client secret');
  const fetch = createSsoFetch({
    internalHosts: deps.internalHosts,
    allowed: new Set([new URL(oidcDiscoveryUrl(cfg.issuer)).href]),
    ...(deps.resolve ? { resolve: deps.resolve } : {}),
  });
  const auth =
    cfg.clientAuth === 'client_secret_post'
      ? client.ClientSecretPost(connection.clientSecret)
      : client.ClientSecretBasic(connection.clientSecret);
  const config = await client.discovery(
    issuer,
    cfg.clientId,
    { [client.clockTolerance]: CLOCK_TOLERANCE_S },
    auth,
    {
      [client.customFetch]: fetch,
      timeout: TIMEOUT_S,
      // Only reached for a listed internal host (checked above; ssoFetch checks every request).
      ...(issuer.protocol === 'http:' ? { execute: [client.allowInsecureRequests] } : {}),
    },
  );
  const meta = config.serverMetadata();
  if (meta.issuer !== cfg.issuer) {
    throw new Error(ISSUER_MISMATCH);
  }
  for (const endpoint of [meta.token_endpoint, meta.jwks_uri, meta.userinfo_endpoint]) {
    if (typeof endpoint === 'string') fetch.allow(endpoint);
  }
  // spec §3.2: openid-client 6 verifies the ID token's JWS signature only with non-repudiation
  // checks on. With them, the key comes from `jwks_uri` (through ssoFetch, allowed just above):
  // a kid the JWKS lacks is refused (after one refetch once the cached JWKS is 60 s old), an RSA
  // key under 2048 bits is refused, and a signature by any other key is refused. The JWKS is
  // cached with this configuration and refetched after 5 minutes.
  if (typeof meta.jwks_uri !== 'string')
    throw new Error('the discovery document names no jwks_uri');
  client.enableNonRepudiationChecks(config);
  const value = { config, fetch };
  cache.set(connection.row.id, { key, at: now(), value });
  return value;
}
