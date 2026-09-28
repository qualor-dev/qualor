import { z } from 'zod';
import type { SsoProtocol } from '../db/schema';
import { noNul } from '../http/schemas';

/** sso-scim.md §4.1: a resource bound. */
export const MAX_SSO_CONNECTIONS = 10;
/** data-model.md §2: the AADs binding each encrypted value to its column. */
export const SECRET_AAD = 'sso_connections.secret_enc';
export const SP_KEY_AAD = 'sso_connections.sp_key_enc';

const claimName = z.string().regex(/^[A-Za-z0-9_.:/-]{1,128}$/);
const scope = z.string().regex(/^[\x21\x23-\x5B\x5D-\x7E]{1,128}$/);
/** Free text is storable: no NUL, no lone surrogate (http/schemas.ts), each a 422 on its field. */
const url = noNul(z.string().min(1).max(2_048));

/** spec §4.1: the fields every connection has. */
const common = {
  jit: z.boolean().default(true),
  linkByEmail: z.boolean().default(false),
  groupSource: z.enum(['none', 'claims', 'scim']).default('none'),
  requiredClaims: z
    .array(z.strictObject({ claim: claimName, value: noNul(z.string().min(1).max(255)) }))
    .max(5)
    .default([]),
};

/** spec §4.2: the non-secret OIDC fields (the client secret is `secret_enc`). */
export const OIDC_CONFIG = z.strictObject({
  ...common,
  issuer: url,
  clientId: noNul(z.string().min(1).max(255)),
  clientAuth: z.enum(['client_secret_basic', 'client_secret_post']).default('client_secret_basic'),
  scopes: z
    .array(scope)
    .min(1)
    .max(20)
    .default(['openid', 'email', 'profile'])
    .refine((s) => s.includes('openid'), { message: 'The scopes must include openid' }),
  claims: z
    .strictObject({
      username: claimName.nullable().default('preferred_username'),
      email: claimName.nullable().default('email'),
      displayName: claimName.nullable().default('name'),
      groups: claimName.nullable().default(null),
    })
    .default({ username: 'preferred_username', email: 'email', displayName: 'name', groups: null }),
  userinfo: z.boolean().default(false),
});
export type OidcConfig = z.infer<typeof OIDC_CONFIG>;

export const NAME_ID_FORMATS = [
  'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress',
  'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified',
] as const;

const pem = noNul(z.string().min(1).max(16_384));

/** spec §4.3: the non-secret SAML fields (the SP key is `sp_key_enc`). Qualor's, not node-saml's. */
export const SAML_CONFIG = z.strictObject({
  ...common,
  idpEntityId: noNul(z.string().min(1).max(1_024)),
  idpSsoUrl: url,
  idpCertificates: z.array(pem).min(1).max(3),
  metadataUrl: url.nullable().default(null),
  nameIdFormat: z.enum(NAME_ID_FORMATS).default(NAME_ID_FORMATS[0]),
  claims: z
    .strictObject({
      username: claimName.nullable().default(null),
      email: claimName.nullable().default('email'),
      displayName: claimName.nullable().default('displayName'),
      groups: claimName.nullable().default(null),
    })
    .default({ username: null, email: 'email', displayName: 'displayName', groups: null }),
  emailVerified: z.boolean().default(false),
  wantResponseSigned: z.boolean().default(false),
  spCertificate: pem.nullable().default(null),
});
export type SamlConfig = z.infer<typeof SAML_CONFIG>;

export type ConnectionConfig =
  { protocol: 'oidc'; config: OidcConfig } | { protocol: 'saml'; config: SamlConfig };

/** A stored `config` read back; a row that does not parse makes the connection unusable (spec §13). */
export function parseStoredConfig(protocol: SsoProtocol, raw: unknown): ConnectionConfig | null {
  if (protocol === 'oidc') {
    const r = OIDC_CONFIG.safeParse(raw);
    return r.success ? { protocol, config: r.data } : null;
  }
  const r = SAML_CONFIG.safeParse(raw);
  return r.success ? { protocol, config: r.data } : null;
}
