import { describe, expect, it } from 'vitest';
import { SSO_ERROR_REASONS } from '../audit/catalogue';
import { SSO_DETAIL_CODES, ssoDetail, SsoFailure } from './errors';

describe('SSO failure details (sso-scim.md §7.7)', () => {
  it.each([
    ['oidc.id_token.aud', 'oidc.id_token.aud'],
    ['saml.recipient', 'saml.recipient'],
    ['account.no_account', 'account.no_account'],
    ['oidc.idp.access_denied', 'oidc.idp.access_denied'],
    ['saml.precheck.comment', 'saml.precheck.comment'],
    ['oidc.fetch.redirect', 'oidc.fetch.redirect'],
    ['oidc.idp.Access Denied', 'other'],
    ['oidc.idp.', 'other'],
    ['something the IdP said', 'other'],
    ['saml.precheck.' + 'a'.repeat(41), 'other'],
  ])('%j is logged as %j', (detail, logged) => {
    expect(ssoDetail(detail)).toBe(logged);
  });

  it('has an account detail for every code, and only lower-case dotted names', () => {
    for (const code of SSO_ERROR_REASONS) expect(SSO_DETAIL_CODES).toContain(`account.${code}`);
    for (const detail of SSO_DETAIL_CODES) expect(detail).toMatch(/^[a-z_]+(\.[a-z_]+)+$/);
  });

  it('carries the code, the detail and the user, with a message that holds neither detail nor user', () => {
    const failure = new SsoFailure('no_account', 'account.no_account', 'u1');
    expect([failure.code, failure.detail, failure.userId]).toEqual([
      'no_account',
      'account.no_account',
      'u1',
    ]);
    expect(failure.message).toBe('sso flow failed: no_account');
    expect(new SsoFailure('replayed', 'saml.validate').userId).toBeNull();
  });
});
