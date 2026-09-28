import { describe, expect, it } from 'vitest';
import { decryptSecret, encryptionKey, encryptSecret } from '../crypto/secrets';
import {
  OIDC_CONFIG,
  parseStoredConfig,
  SAML_CONFIG,
  SECRET_AAD,
  SP_KEY_AAD,
} from './connection-config';
import {
  idpUrlProblem,
  issuerProblem,
  normalIdpUrl,
  normalIssuer,
  oidcDiscoveryUrl,
  ssoUrls,
} from './urls';

const oidc = {
  issuer: 'https://idp.example/realms/acme',
  clientId: 'qualor',
};

describe('SSO connection config (sso-scim.md §4)', () => {
  it('fills the OIDC defaults', () => {
    expect(OIDC_CONFIG.parse(oidc)).toMatchObject({
      clientAuth: 'client_secret_basic',
      scopes: ['openid', 'email', 'profile'],
      claims: { username: 'preferred_username', email: 'email', displayName: 'name', groups: null },
      userinfo: false,
      jit: true,
      linkByEmail: false,
      groupSource: 'none',
      requiredClaims: [],
    });
  });

  it.each([
    [{ ...oidc, scopes: ['email'] }, 'scopes'],
    [{ ...oidc, scopes: ['openid', 'a b'] }, 'scopes'],
    [
      {
        ...oidc,
        requiredClaims: Array.from({ length: 6 }, () => ({ claim: 'hd', value: 'x' })),
      },
      'requiredClaims',
    ],
    [{ ...oidc, claims: { username: 'bad claim!' } }, 'claims'],
    [{ ...oidc, extra: 1 }, ''],
  ])('refuses %j', (input, path) => {
    const r = OIDC_CONFIG.safeParse(input);
    expect(r.success).toBe(false);
    expect(r.error!.issues[0]!.path.join('.')).toContain(path);
  });

  it('fills the SAML defaults and keeps up to three certificates', () => {
    const parsed = SAML_CONFIG.parse({
      idpEntityId: 'https://idp.example/saml',
      idpSsoUrl: 'https://idp.example/saml/sso',
      idpCertificates: ['A', 'B', 'C'],
    });
    expect(parsed).toMatchObject({
      nameIdFormat: 'urn:oasis:names:tc:SAML:2.0:nameid-format:persistent',
      claims: { username: null, email: 'email', displayName: 'displayName', groups: null },
      emailVerified: false,
      wantResponseSigned: false,
    });
    expect(
      SAML_CONFIG.safeParse({ ...parsed, idpCertificates: ['A', 'B', 'C', 'D'] }).success,
    ).toBe(false);
  });

  it('never throws on a stored row that does not parse', () => {
    expect(parseStoredConfig('oidc', { issuer: 42 })).toBeNull();
    expect(parseStoredConfig('saml', null)).toBeNull();
    expect(parseStoredConfig('oidc', oidc)).toMatchObject({ protocol: 'oidc' });
  });

  it('derives the URLs from QUALOR_PUBLIC_URL', () => {
    expect(ssoUrls('https://q.example', 'c1')).toEqual({
      redirectUri: 'https://q.example/api/v0/ee/sso/oidc/c1/callback',
      acsUrl: 'https://q.example/api/v0/ee/sso/saml/c1/acs',
      entityId: 'https://q.example/api/v0/ee/sso/saml/c1/metadata',
      metadataUrl: 'https://q.example/api/v0/ee/sso/saml/c1/metadata',
      startUrl: '/api/v0/ee/sso/c1/start',
    });
  });

  it('keeps an OIDC issuer exactly, with or without its trailing slash (OIDC Discovery §4)', () => {
    const none = new Set<string>();
    expect(issuerProblem('https://x.auth0.com/', none)).toBeNull();
    expect(normalIssuer('https://x.auth0.com/')).toBe('https://x.auth0.com/');
    expect(oidcDiscoveryUrl('https://x.auth0.com/')).toBe(
      'https://x.auth0.com/.well-known/openid-configuration',
    );
    expect(normalIssuer('https://x/realms/r')).toBe('https://x/realms/r');
    expect(oidcDiscoveryUrl('https://x/realms/r')).toBe(
      'https://x/realms/r/.well-known/openid-configuration',
    );
    // WHATWG adds a / to a bare origin; Google's issuer has none, so none is added.
    expect(normalIssuer('https://accounts.google.com')).toBe('https://accounts.google.com');
    expect(oidcDiscoveryUrl('https://accounts.google.com')).toBe(
      'https://accounts.google.com/.well-known/openid-configuration',
    );
    for (const bad of [
      'https://x.example/?a=1',
      'https://x.example/#f',
      'https://u:p@x.example/',
      'http://x.example/',
    ]) {
      expect(issuerProblem(bad, none), bad).not.toBeNull();
    }
  });

  it('allows a query in a SAML IdP URL, never a fragment, credentials or plain http', () => {
    const none = new Set<string>();
    const google = 'https://accounts.google.com/o/saml2/idp?idpid=C0abc123';
    const entra =
      'https://login.microsoftonline.com/t/federationmetadata/2007-06/federationmetadata.xml?appid=a1';
    expect(idpUrlProblem(google, none)).toBeNull();
    expect(idpUrlProblem(entra, none)).toBeNull();
    expect(normalIdpUrl(google)).toBe(google);
    for (const bad of [
      'https://idp.example/sso#frag',
      'https://idp.example/sso?a=1#frag',
      'https://user:pass@idp.example/sso',
      'http://idp.example/sso?a=1',
      'https://10.0.0.5/sso?a=1',
      `https://idp.example/sso?q=${'a'.repeat(2_048)}`,
    ]) {
      expect(idpUrlProblem(bad, none), bad).not.toBeNull();
    }
    expect(
      idpUrlProblem('http://127.0.0.1:18080/sso?a=1', new Set(['127.0.0.1:18080'])),
    ).toBeNull();
  });

  it('binds each secret to its column: secret_enc never decrypts as sp_key_enc', () => {
    const key = encryptionKey('a-secret-key-of-at-least-32-characters');
    const enc = encryptSecret(key, 'client-secret', SECRET_AAD);
    expect(decryptSecret(key, enc, SECRET_AAD)).toBe('client-secret');
    expect(decryptSecret(key, enc, SP_KEY_AAD)).toBeNull();
  });

  it('refuses tabs, line breaks and spaces at either end of a URL instead of dropping them', () => {
    const none = new Set<string>();
    const tab = String.fromCharCode(9);
    for (const raw of [
      ' https://x.example',
      'https://x.example ',
      `https://x.exa${tab}mple/`,
      'https://x.example/a\nb',
      'https://x.example/a\rb',
    ]) {
      expect(issuerProblem(raw, none), raw).not.toBeNull();
      expect(idpUrlProblem(`${raw}?q=1`, none), raw).not.toBeNull();
      expect(idpUrlProblem(raw, none), raw).not.toBeNull();
    }
  });
});
