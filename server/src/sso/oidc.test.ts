import { describe, expect, it } from 'vitest';
import { OIDC_CONFIG, type OidcConfig } from './connection-config';
import { SsoFetchRefused } from './fetch';
import { SsoFailure, ssoDetail } from './errors';
import { MAX_GROUP_VALUES } from './groups';
import { claimsFrom, oidcDetail } from './oidc';

const cfg = (over: Partial<OidcConfig> = {}): OidcConfig =>
  OIDC_CONFIG.parse({
    issuer: 'https://idp.example',
    clientId: 'qualor',
    groupSource: 'claims',
    claims: { groups: 'groups' },
    ...over,
  });

const alice = {
  sub: 'alice-sub',
  preferred_username: 'alice',
  email: 'alice@acme.example',
  email_verified: true,
  name: 'Alice A',
  groups: ['qualor-admins'],
};

describe('claimsFrom (sso-scim.md §5 step 4, §8.3)', () => {
  it('reads the configured claims of the ID token', () => {
    expect(claimsFrom(alice, null, cfg())).toEqual({
      subject: 'alice-sub',
      username: 'alice',
      email: 'alice@acme.example',
      emailVerified: true,
      displayName: 'Alice A',
      groups: ['qualor-admins'],
    });
  });

  it('merges userinfo under the ID token: the ID token wins', () => {
    const c = claimsFrom(
      { sub: 's', name: 'From token' },
      { sub: 's', name: 'From userinfo', email: 'u@acme.example', groups: 'one' },
      cfg(),
    );
    expect(c).toMatchObject({
      displayName: 'From token',
      email: 'u@acme.example',
      groups: ['one'],
    });
  });

  it('is null without a sub of 1-255 characters', () => {
    expect(claimsFrom({ ...alice, sub: '' }, null, cfg())).toBeNull();
    expect(claimsFrom({ ...alice, sub: 'x'.repeat(256) }, null, cfg())).toBeNull();
    expect(claimsFrom({ ...alice, sub: 42 }, null, cfg())).toBeNull();
    expect(claimsFrom({ ...alice, sub: 'x'.repeat(255) }, null, cfg())?.subject).toHaveLength(255);
  });

  it('email_verified is the boolean true only: the string "true" is not verified', () => {
    expect(claimsFrom({ ...alice, email_verified: 'true' }, null, cfg())?.emailVerified).toBe(
      false,
    );
    expect(claimsFrom({ ...alice, email_verified: 1 }, null, cfg())?.emailVerified).toBe(false);
    // The ID token's own false is not overridden by userinfo.
    expect(
      claimsFrom({ ...alice, email_verified: false }, { email_verified: true }, cfg())
        ?.emailVerified,
    ).toBe(false);
  });

  it('reads email_verified from the claims the email came from', () => {
    const bare = { sub: 'alice-sub' };
    // The email and its flag from userinfo: verified.
    expect(
      claimsFrom(bare, { sub: 'alice-sub', email: 'a@acme.example', email_verified: true }, cfg()),
    ).toMatchObject({ email: 'a@acme.example', emailVerified: true });
    expect(
      claimsFrom(bare, { email: 'a@acme.example', email_verified: 'true' }, cfg())?.emailVerified,
    ).toBe(false);
    // The email from the ID token, the flag only in userinfo: not verified.
    expect(
      claimsFrom({ ...bare, email: 'a@acme.example' }, { email_verified: true }, cfg()),
    ).toMatchObject({ email: 'a@acme.example', emailVerified: false });
    // The flag in the ID token, the email only in userinfo: not verified.
    expect(
      claimsFrom({ ...bare, email_verified: true }, { email: 'u@acme.example' }, cfg()),
    ).toMatchObject({ email: 'u@acme.example', emailVerified: false });
    // No email at all: never verified.
    expect(claimsFrom({ ...bare, email_verified: true }, null, cfg())?.emailVerified).toBe(false);
  });

  it('refuses U+0000 and lone surrogates: a sub is null, a claim is absent', () => {
    const nul = String.fromCharCode(0);
    const lone = String.fromCharCode(0xd800);
    expect(claimsFrom({ ...alice, sub: `alice${nul}` }, null, cfg())).toBeNull();
    expect(claimsFrom({ ...alice, sub: `alice${lone}` }, null, cfg())).toBeNull();
    const c = claimsFrom(
      {
        ...alice,
        preferred_username: `al${nul}ice`,
        email: `alice${lone}@acme.example`,
        name: `A${String.fromCharCode(0xdc00)}`,
      },
      null,
      cfg(),
    );
    expect(c).toMatchObject({
      username: null,
      email: null,
      emailVerified: false,
      displayName: null,
    });
    // A well-formed surrogate pair is kept.
    const smile = `A ${String.fromCodePoint(0x1f600)}`;
    expect(claimsFrom({ ...alice, name: smile }, null, cfg())?.displayName).toBe(smile);
  });

  it('counts an empty, blank, over-long or non-string claim as absent', () => {
    const c = claimsFrom(
      { ...alice, preferred_username: '', name: '   ', email: 'x'.repeat(1_025) },
      null,
      cfg(),
    );
    expect(c).toMatchObject({ username: null, displayName: null, email: null });
    expect(
      claimsFrom({ ...alice, preferred_username: ['alice'] }, null, cfg())?.username,
    ).toBeNull();
  });

  it('reads groups only when named: an array of strings or one string, else none', () => {
    expect(claimsFrom(alice, null, cfg({ claims: { groups: null } } as never))?.groups).toEqual([]);
    expect(claimsFrom({ ...alice, groups: 'solo' }, null, cfg())?.groups).toEqual(['solo']);
    expect(claimsFrom({ ...alice, groups: ['a', 1] }, null, cfg())?.groups).toEqual([]);
    expect(claimsFrom({ ...alice, groups: { a: 1 } }, null, cfg())?.groups).toEqual([]);
  });

  it(`refuses more than ${MAX_GROUP_VALUES} groups as groups.too_many, never cuts`, () => {
    const many = Array.from({ length: MAX_GROUP_VALUES + 1 }, (_, i) => `g${i}`);
    let thrown: unknown;
    try {
      claimsFrom({ ...alice, groups: many }, null, cfg());
    } catch (err) {
      thrown = err;
    }
    expect(thrown).toBeInstanceOf(SsoFailure);
    expect(thrown).toMatchObject({ code: 'invalid_response', detail: 'groups.too_many' });
    expect(
      claimsFrom({ ...alice, groups: many.slice(0, MAX_GROUP_VALUES) }, null, cfg())?.groups,
    ).toHaveLength(MAX_GROUP_VALUES);
  });
});

/** An oauth4webapi OperationProcessingError as openid-client wraps it (ClientError, same code). */
function wrapped(code: string, cause: unknown): Error {
  const inner = Object.assign(new Error('attacker <b>text</b>', { cause }), { code });
  return Object.assign(new Error('attacker <b>text</b>', { cause: inner }), { code });
}

describe('oidcDetail (sso-scim.md §7.7)', () => {
  it('names the ID token claim that failed', () => {
    for (const claim of ['iss', 'aud', 'azp', 'nonce']) {
      expect(oidcDetail(wrapped('OAUTH_JWT_CLAIM_COMPARISON_FAILED', { claim }))).toBe(
        `oidc.id_token.${claim}`,
      );
    }
    for (const claim of ['exp', 'iat']) {
      expect(oidcDetail(wrapped('OAUTH_JWT_TIMESTAMP_CHECK_FAILED', { claim }))).toBe(
        `oidc.id_token.${claim}`,
      );
    }
    expect(oidcDetail(wrapped('OAUTH_JWT_CLAIM_COMPARISON_FAILED', { claim: 'c_hash' }))).toBe(
      'oidc.id_token.other',
    );
  });

  it('maps the other codes to fixed details, and never the message', () => {
    expect(oidcDetail(wrapped('OAUTH_RESPONSE_BODY_ERROR', {}))).toBe('oidc.token_endpoint');
    expect(oidcDetail(wrapped('OAUTH_RESPONSE_IS_NOT_CONFORM', {}))).toBe('oidc.token_endpoint');
    expect(oidcDetail(wrapped('OAUTH_INVALID_RESPONSE', {}))).toBe('oidc.invalid_response');
    // oauth4webapi's failed JWS check: OAUTH_INVALID_RESPONSE with the signature in its cause.
    expect(
      oidcDetail(
        wrapped('OAUTH_INVALID_RESPONSE', { key: {}, data: {}, signature: {}, algorithm: 'RS' }),
      ),
    ).toBe('oidc.id_token.signature');
    expect(oidcDetail(wrapped('OAUTH_UNSUPPORTED_OPERATION', {}))).toBe('oidc.unsupported_alg');
    expect(oidcDetail(wrapped('OAUTH_KEY_SELECTION_FAILED', {}))).toBe('oidc.key_selection');
    expect(oidcDetail(new Error('<b>evil</b>'))).toBe('oidc.other');
    expect(oidcDetail('a string')).toBe('oidc.other');
  });

  it('names a refusal of ssoFetch however deep openid-client wrapped it', () => {
    const refused = new SsoFetchRefused('not_allowed');
    expect(oidcDetail(refused)).toBe('oidc.fetch.not_allowed');
    expect(oidcDetail(new Error('something went wrong', { cause: refused }))).toBe(
      'oidc.fetch.not_allowed',
    );
  });

  it('produces only details the log keeps (SSO_DETAIL_CODES or a family)', () => {
    const produced = [
      'oidc.id_token.iss',
      'oidc.id_token.aud',
      'oidc.id_token.azp',
      'oidc.id_token.nonce',
      'oidc.id_token.exp',
      'oidc.id_token.iat',
      'oidc.id_token.other',
      'oidc.id_token.signature',
      'oidc.token_endpoint',
      'oidc.invalid_response',
      'oidc.unsupported_alg',
      'oidc.key_selection',
      'oidc.iss_param',
      'oidc.discovery',
      'oidc.secret',
      'oidc.inactive',
      'oidc.fetch.timeout',
      'oidc.other',
    ];
    for (const detail of produced) expect(ssoDetail(detail)).toBe(detail);
  });
});
