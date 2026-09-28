import { DrizzleQueryError } from 'drizzle-orm/errors';
import { describe, expect, it } from 'vitest';
import { createLogger, SSO_PATH_PREFIX } from './logger';

function capture(level: 'info' | 'warn' = 'info') {
  const lines: string[] = [];
  const logger = createLogger(level, {
    write: (line: string) => {
      lines.push(line);
    },
  });
  return { lines, logger };
}

describe('createLogger (api.md §4 redaction)', () => {
  it('redacts a licence key logged under license (enterprise.md §6)', () => {
    const { lines, logger } = capture();
    logger.info({ license: { key: 'QLK1.test-a.top' } }, 'a');
    logger.info({ setting: { license: { key: 'QLK1.test-a.nested' } } }, 'b');
    const out = lines.join('');
    expect(out).not.toContain('QLK1.test-a');
    expect(out).toContain('[redacted]');
  });

  it('redacts credentials at the top level, one level down and in request headers', () => {
    const { lines, logger } = capture();
    logger.info(
      {
        password: 'pw-top',
        token: 'qlr_pat_top',
        secret: 's-top',
        apiKey: 'llm-key-top',
        body: {
          password: 'pw-nested',
          newPassword: 'pw-new',
          currentPassword: 'pw-cur',
          token: 'qlr_pat_nested',
          secret: 's-nested',
          apiKey: 'llm-key-nested',
        },
        req: {
          headers: {
            authorization: 'Bearer qlr_pat_header',
            cookie: 'qualor_session=abc',
            'x-qualor-csrf': 'csrf-value',
          },
        },
        res: { headers: { 'set-cookie': 'qualor_session=def' } },
      },
      'hello',
    );
    const out = lines.join('');
    for (const secret of [
      'pw-top',
      'qlr_pat_top',
      's-top',
      'pw-nested',
      'pw-new',
      'pw-cur',
      'qlr_pat_nested',
      's-nested',
      'llm-key-top',
      'llm-key-nested',
      'qlr_pat_header',
      'qualor_session=abc',
      'csrf-value',
      'qualor_session=def',
    ]) {
      expect(out).not.toContain(secret);
    }
    expect(out).toContain('[redacted]');
    expect(JSON.parse(lines[0]!).msg).toBe('hello');
  });

  it('honours the level', () => {
    const { lines, logger } = capture('warn');
    logger.info('dropped');
    logger.warn('kept');
    expect(lines).toHaveLength(1);
  });

  it('never logs a DrizzleQueryError message/stack/params, even with a sentinel bind param (S7)', () => {
    const { lines, logger } = capture();
    const sentinel = 'argon2id$v=19$m=19456,t=2,p=1$sentinel-password-hash-must-not-leak';
    const cause = Object.assign(new Error('duplicate key value violates unique constraint'), {
      code: '23505',
    });
    const err = new DrizzleQueryError(
      'update "users" set "password_hash" = $1 where "id" = $2',
      [sentinel, 'user-id'],
      cause,
    );
    logger.error({ err }, 'unhandled error');
    const out = lines.join('');
    expect(out).not.toContain(sentinel);
    expect(out).not.toContain('password_hash');
    expect(out).not.toContain('update "users"');
    const parsed = JSON.parse(lines[0]!) as {
      err: { type: string; message: string; code: string };
    };
    expect(parsed.err).toEqual({
      type: 'DrizzleQueryError',
      message: 'database query failed',
      code: '23505',
    });
  });

  it('still fully serializes ordinary errors (type, message and stack)', () => {
    const { lines, logger } = capture();
    logger.error({ err: new Error('plain failure') }, 'unhandled error');
    const parsed = JSON.parse(lines[0]!) as {
      err: { type: string; message: string; stack: string };
    };
    expect(parsed.err).toMatchObject({ type: 'Error', message: 'plain failure' });
    expect(parsed.err.stack).toContain('plain failure');
  });

  it('drops the query string of SSO callback URLs, and keeps other URLs whole (sso-scim.md §7.8)', () => {
    const lines: string[] = [];
    const logger = createLogger('info', { write: (l: string) => lines.push(l) });
    logger.info(
      { req: { method: 'GET', url: '/api/v0/ee/sso/oidc/abc/callback?code=SECRETCODE&state=S' } },
      'r',
    );
    logger.info({ req: { method: 'GET', url: '/api/v0/issues?branchId=b' } }, 'r');
    expect(lines.join('\n')).not.toContain('SECRETCODE');
    expect(lines[0]).toContain('/api/v0/ee/sso/oidc/abc/callback');
    expect(lines[1]).toContain('branchId=b');
  });

  it.each([
    'clientSecret',
    'spKey',
    'SAMLResponse',
    'code_verifier',
    'id_token',
    'access_token',
    'refresh_token',
  ])('redacts %s, bare and nested', (name) => {
    const lines: string[] = [];
    const logger = createLogger('info', { write: (l: string) => lines.push(l) });
    logger.info({ [name]: 'S3CRET', body: { [name]: 'S3CRET' } }, 'x');
    expect(lines.join('')).not.toContain('S3CRET');
  });

  it('logs every new SSO/SCIM secret shape at once and finds none of them in the output (sso-scim.md §7.8)', () => {
    const lines: string[] = [];
    const logger = createLogger('info', { write: (l: string) => lines.push(l) });
    const scimToken = `qlr_scim_${'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6'}`;
    logger.info(
      {
        // OIDC client secret
        clientSecret: 'oidc-CLIENT-SECRET-value',
        // SAML SP private key and a signed assertion body
        spKey: '-----BEGIN PRIVATE KEY-----\nSAML-SP-PRIVATE-KEY-BYTES\n-----END PRIVATE KEY-----',
        body: {
          SAMLResponse:
            '<samlp:Response><Assertion>ASSERTION-BODY-TEXT</Assertion></samlp:Response>',
          // id_token, access_token, refresh_token from an OIDC token response
          id_token: 'OIDC-ID-TOKEN-VALUE',
          access_token: 'OIDC-ACCESS-TOKEN-VALUE',
          refresh_token: 'OIDC-REFRESH-TOKEN-VALUE',
          code_verifier: 'OIDC-PKCE-VERIFIER-VALUE',
        },
        // a SCIM bearer token, qlr_scim_ prefixed: under the generic redacted key, and presented
        // the way personal tokens are, in the Authorization header (dropped entirely by the
        // request serializer, sso-scim.md §7.8)
        token: scimToken,
        req: {
          method: 'POST',
          url: '/scim/v2/Users',
          headers: { authorization: `Bearer ${scimToken}` },
        },
      },
      'combined secret shapes',
    );
    // the `code` and `state` query values on an SSO callback URL
    logger.info(
      {
        req: {
          method: 'GET',
          url: `${SSO_PATH_PREFIX}oidc/conn-1/callback?code=CB-CODE-VALUE&state=CB-STATE-VALUE`,
        },
      },
      'callback',
    );
    const out = lines.join('\n');
    for (const secret of [
      'oidc-CLIENT-SECRET-value',
      'SAML-SP-PRIVATE-KEY-BYTES',
      'ASSERTION-BODY-TEXT',
      'OIDC-ID-TOKEN-VALUE',
      'OIDC-ACCESS-TOKEN-VALUE',
      'OIDC-REFRESH-TOKEN-VALUE',
      'OIDC-PKCE-VERIFIER-VALUE',
      scimToken,
      'CB-CODE-VALUE',
      'CB-STATE-VALUE',
    ]) {
      expect(out).not.toContain(secret);
    }
  });
});
