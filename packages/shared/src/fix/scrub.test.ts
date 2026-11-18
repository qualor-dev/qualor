import { describe, expect, it } from 'vitest';
import { FIX_LIMITS } from './families';
import { FIX_SECRET_NAME, scrubToolOutput, secretEnvValues } from './scrub';

/** Test secrets are assembled at run time, so no secret scanner finds one in this file. */
const j = (...parts: string[]): string => parts.join('');
const SECRET = j('s3', 'cr3t', '-Va', 'lue-42xy');
const NPM_TOKEN = j('np', 'mtok', '-9f8e', '7d6c');
const bytes = (s: string): number => Buffer.byteLength(s, 'utf8');

describe('secretEnvValues (B9, R21)', () => {
  it('takes the values of secret-named variables of at least 4 characters, not PWD/OLDPWD', () => {
    expect(
      secretEnvValues({ PWD: '/builds/x', DB_PWD: 'pw-1234', K: 'abc', API_KEY: 'xyz' }),
    ).toEqual(['pw-1234']);
    expect(
      secretEnvValues({
        OLDPWD: '/builds/old',
        A_TOKEN: 'abcd',
        b_secret: 'abcdefgh',
        C_PASS: undefined,
        DEPLOY_CREDENTIALS: 'abcdef',
        GH_AUTH: 'abcdefgh',
        HOME: '/home/user',
      }),
    ).toEqual(['abcdefgh', 'abcdef', 'abcd']);
  });

  it('matches the names the spec lists, in any case', () => {
    for (const name of ['NPM_TOKEN', 'db_password', 'PASS', 'MY_PWD', 'SECRET_X', 'AUTH', 'KEY']) {
      expect(FIX_SECRET_NAME.test(name), name).toBe(true);
    }
    expect(FIX_SECRET_NAME.test('CREDENTIAL_FILE')).toBe(true);
    expect(FIX_SECRET_NAME.test('HOME')).toBe(false);
  });
});

describe('scrubToolOutput (§6.9, B9)', () => {
  it('redacts every secret shape in place', () => {
    const text = [
      `//r.example/:_authToken=${SECRET}`,
      `_auth=${SECRET}`,
      `_password = ${SECRET}`,
      `Authorization: Bearer ${SECRET}`,
      `<password>${SECRET}</password>`,
      `https://u:${SECRET}@r.example/x`,
      `npm ERR! token ${NPM_TOKEN} was refused`,
    ].join('\n');
    const out = scrubToolOutput(text, secretEnvValues({ NPM_TOKEN }));
    expect(out).not.toContain(SECRET.slice(2, 10));
    expect(out).not.toContain(NPM_TOKEN.slice(2, 10));
    expect(out.split('\n')).toEqual([
      '//r.example/:_authToken=[redacted]',
      '_auth=[redacted]',
      '_password = [redacted]',
      'Authorization: [redacted]',
      '<password>[redacted]</password>',
      'https://[redacted]@r.example/x',
      'npm ERR! token [redacted] was refused',
    ]);
  });

  it('redacts URL credentials up to the last @, and a token as the user', () => {
    const out = scrubToolOutput(
      [
        `fetch https://user:${SECRET}@x/y@host/x failed`,
        `git+https://${NPM_TOKEN}@github.com/o/r.git`,
        'GET http://registry.local:4873/@scope%2fpkg 404',
      ].join('\n'),
      [],
    );
    expect(out.split('\n')).toEqual([
      'fetch https://[redacted]@host/x failed',
      'git+https://[redacted]@github.com/o/r.git',
      'GET http://registry.local:4873/@scope%2fpkg 404',
    ]);
  });

  it('replaces the longest secret first and skips values under 4 characters', () => {
    expect(scrubToolOutput('x abcdefgh y abc', ['abcd', 'abcdefgh', 'abc', ''])).toBe(
      'x [redacted] y abc',
    );
  });

  it('runs the general secret redaction too', () => {
    const github = j('gh', 'p_', 'A1b2C3d4'.repeat(4), 'E5f6');
    const out = scrubToolOutput(`remote: using ${github} for the fetch`, []);
    expect(out).not.toContain(github);
  });

  it('keeps the last 2 KiB, never splitting a UTF-8 character', () => {
    const head = Array.from({ length: 300 }, (_, i) => `npm warn deprecated line ${i}: use other`);
    const tail = '€€€ '.repeat(300);
    const text = [...head, tail].join('\n');
    expect(bytes(text)).toBeGreaterThan(10_000);
    const out = scrubToolOutput(text, []);
    // 2 048 bytes are 204 units of 10 bytes and 8 bytes of the unit before: its space, two euros
    // and the last byte of its first euro, which is dropped.
    expect(bytes(out)).toBe(2047);
    expect(bytes(out)).toBeLessThanOrEqual(FIX_LIMITS.messageBytes);
    expect(text.endsWith(out)).toBe(true);
    expect(out).not.toContain('�');
  });

  it('scrubs before cutting, so no part of a secret at the cut survives', () => {
    const secret = j('Zq9', 'Lm2', 'Xv8', 'Pw4', 'Ks7', 'Rt1', 'Nb6', 'Hy3', 'Gf5', 'Dc0');
    const after = ` done${'.'.repeat(2030)}`;
    const text = `ok\nAuthorization: Basic ${secret}\n${after}`;
    const naive = Buffer.from(text, 'utf8').subarray(-FIX_LIMITS.messageBytes).toString('utf8');
    expect(naive).toContain(secret.slice(-12));
    const out = scrubToolOutput(text, [secret]);
    for (let i = 0; i + 4 <= secret.length; i++) expect(out).not.toContain(secret.slice(i, i + 4));
    expect(text.endsWith(out.slice(-100))).toBe(true);
  });

  it('keeps a useful tail of a very long output and still redacts it', () => {
    const lines = Array.from({ length: 12_000 }, (_, i) => `[INFO] Downloading artifact ${i}`);
    const github = j('gh', 'p_', 'Q7w8E9r0'.repeat(4), 'T1y2');
    const text = [
      ...lines,
      `//r.example/:_authToken=${SECRET}`,
      `[ERROR] token ${github} rejected`,
      '[ERROR] BUILD FAILURE',
    ].join('\n');
    expect(text.length).toBeGreaterThan(300_000);
    const out = scrubToolOutput(text, []);
    expect(out).not.toContain(SECRET);
    expect(out).not.toContain(github);
    expect(out).toContain('_authToken=[redacted]');
    expect(out.endsWith('[ERROR] BUILD FAILURE')).toBe(true);
    expect(bytes(out)).toBeLessThanOrEqual(FIX_LIMITS.messageBytes);
  });
});
