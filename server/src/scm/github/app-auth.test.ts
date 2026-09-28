import { createPublicKey, generateKeyPairSync, verify } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  appJwt,
  credentialsId,
  InstallationTokenCache,
  isGitHubAppId,
  MAX_PRIVATE_KEY_BYTES,
  MutationPacer,
  parseAppPrivateKey,
  tokenCacheKey,
  verifyWebhookSignature,
} from './app-auth';

const rsa = (bits: number) => generateKeyPairSync('rsa', { modulusLength: bits }).privateKey;
const KEY = rsa(2048);
const PKCS1 = KEY.export({ type: 'pkcs1', format: 'pem' }).toString();
const PKCS8 = KEY.export({ type: 'pkcs8', format: 'pem' }).toString();
const canonical = (pem: string) => {
  const parsed = parseAppPrivateKey(pem);
  return 'pkcs8' in parsed ? parsed.pkcs8 : parsed.problem;
};

describe('parseAppPrivateKey (github.md §2.2, ruling GH4)', () => {
  it('accepts the PKCS#1 key GitHub generates and the same key as PKCS#8, as one canonical form', () => {
    expect(canonical(PKCS1)).toBe(canonical(PKCS8));
    expect(canonical(PKCS1).startsWith(['-----BEGIN', 'PRIVATE KEY-----'].join(' '))).toBe(true);
  });

  it('accepts the key with CRLF line ends and surrounding white space', () => {
    const windows = `\r\n  ${PKCS1.replace(/\n/g, '\r\n')}\r\n\r\n`;
    expect(canonical(windows)).toBe(canonical(PKCS8));
  });

  it('refuses an encrypted, an EC and a 1024-bit key', () => {
    const encrypted = KEY.export({
      type: 'pkcs8',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: 'p',
    }).toString();
    const ec = generateKeyPairSync('ec', { namedCurve: 'P-256' })
      .privateKey.export({ type: 'pkcs8', format: 'pem' })
      .toString();
    const short = rsa(1024).export({ type: 'pkcs1', format: 'pem' }).toString();
    const legacy = KEY.export({
      type: 'pkcs1',
      format: 'pem',
      cipher: 'aes-256-cbc',
      passphrase: 'p',
    }).toString();
    expect(legacy).toContain('Proc-Type: 4,ENCRYPTED');
    expect(parseAppPrivateKey(encrypted)).toEqual({ problem: 'encrypted' });
    expect(parseAppPrivateKey(legacy)).toEqual({ problem: 'encrypted' });
    expect(parseAppPrivateKey(ec)).toEqual({ problem: 'not_rsa' });
    expect(parseAppPrivateKey(short)).toEqual({ problem: 'too_short' });
  });

  it('reads ENCRYPTED only on the header lines, not in the key material', () => {
    const body = '-----BEGIN RSA PRIVATE KEY-----\nMIIENCRYPTEDAAAA\n-----END RSA PRIVATE KEY-----';
    expect(parseAppPrivateKey(body)).toEqual({ problem: 'not_pem' });
  });

  it('refuses a token, a damaged key, a public key and anything over 16 KiB', () => {
    expect(parseAppPrivateKey('ghp_notakey')).toEqual({ problem: 'not_pem' });
    expect(parseAppPrivateKey(PKCS1.replace('MII', 'XII'))).toEqual({ problem: 'not_pem' });
    const publicPem = createPublicKey(KEY).export({ type: 'spki', format: 'pem' }).toString();
    expect(parseAppPrivateKey(publicPem)).toEqual({ problem: 'not_pem' });
    expect(parseAppPrivateKey('x'.repeat(MAX_PRIVATE_KEY_BYTES + 1))).toEqual({
      problem: 'too_large',
    });
  });
});

describe('appJwt (github.md §4)', () => {
  it('is an RS256 JWT for the App, back-dated 60 s, valid 9 minutes, verifiable with the public key', () => {
    const jwt = appJwt('123456', KEY, 1_800_000_000);
    const [header, payload, signature] = jwt.split('.');
    expect(JSON.parse(Buffer.from(header!, 'base64url').toString())).toEqual({
      alg: 'RS256',
      typ: 'JWT',
    });
    expect(JSON.parse(Buffer.from(payload!, 'base64url').toString())).toEqual({
      iat: 1_800_000_000 - 60,
      exp: 1_800_000_000 + 540,
      iss: '123456',
    });
    expect(jwt).not.toMatch(/[=+/]/);
    const ok = verify(
      'sha256',
      Buffer.from(`${header}.${payload}`),
      createPublicKey(KEY),
      Buffer.from(signature!, 'base64url'),
    );
    expect(ok).toBe(true);
  });

  it('refuses an App id that is not digits', () => {
    expect(() => appJwt('12a', KEY, 0)).toThrow();
  });

  it('refuses a time that is not a safe integer of seconds', () => {
    for (const t of [Number.NaN, Infinity, 1.5, 2 ** 53]) {
      expect(() => appJwt('1', KEY, t)).toThrow();
    }
  });
});

describe('isGitHubAppId (github.md §2.2)', () => {
  it.each(['1', '123456', '1234567890123456', String(Number.MAX_SAFE_INTEGER)])(
    'accepts %s',
    (id) => {
      expect(isGitHubAppId(id)).toBe(true);
    },
  );
  it.each([
    '',
    '0',
    '007',
    '12a',
    '-1',
    '1e3',
    ' 1',
    '1\n',
    String(Number.MAX_SAFE_INTEGER + 1), // 16 digits, past the safe range
    '9'.repeat(16),
    '1'.repeat(17),
    '1'.repeat(20),
  ])('refuses %j', (id) => {
    expect(isGitHubAppId(id)).toBe(false);
    expect(() => appJwt(id, KEY, 0)).toThrow();
  });
});

describe('verifyWebhookSignature (github.md §9)', () => {
  // The example of GitHub's documentation, "Validating webhook deliveries".
  const secret = "It's a Secret to Everybody";
  const body = Buffer.from('Hello, World!');
  const good = 'sha256=757107ea0eb2509fc211221cce984b8a37570b6d7586c22c46f4379c8b043e17';

  it('accepts the documented example', () => {
    expect(verifyWebhookSignature(secret, body, good)).toBe(true);
  });

  it('refuses another body, another secret, and a missing, SHA-1, upper-case or short signature', () => {
    expect(verifyWebhookSignature(secret, Buffer.from('Hello, World?'), good)).toBe(false);
    expect(verifyWebhookSignature('another secret!!', body, good)).toBe(false);
    expect(verifyWebhookSignature(secret, body, undefined)).toBe(false);
    expect(
      verifyWebhookSignature(secret, body, 'sha1=01dc10d0c83e72ed246219cdd91669667fe2ca59'),
    ).toBe(false);
    expect(verifyWebhookSignature(secret, body, good.toUpperCase())).toBe(false);
    expect(verifyWebhookSignature(secret, body, good.slice(0, -2))).toBe(false);
  });
});

describe('InstallationTokenCache (github.md §4)', () => {
  it('reuses a token while more than 5 minutes remain, and forgets it after', () => {
    let now = 0;
    const cache = new InstallationTokenCache(() => now);
    cache.set('k', 'ghs_a', 60 * 60_000);
    now = 54 * 60_000;
    expect(cache.get('k')).toBe('ghs_a');
    now = 55 * 60_000 + 1;
    expect(cache.get('k')).toBeNull();
    expect(cache.size).toBe(0);
  });

  it('reuses a token with 5 minutes and 1 ms left, not with exactly 5 minutes', () => {
    let now = 0;
    const cache = new InstallationTokenCache(() => now);
    cache.set('k', 'ghs_a', 60 * 60_000);
    now = 55 * 60_000 - 1;
    expect(cache.get('k')).toBe('ghs_a');
    now = 55 * 60_000;
    expect(cache.get('k')).toBeNull();
  });

  it('refuses an expiry that is not a finite time', () => {
    const cache = new InstallationTokenCache(() => 0);
    for (const at of [Number.NaN, Infinity, -Infinity]) {
      expect(() => cache.set('k', 'ghs_a', at)).toThrow();
    }
    expect(cache.size).toBe(0);
  });

  it('keys by the credentials, so a replaced key never reuses a token', () => {
    const parts = { connectionId: 'c', installationId: 9, repo: 'Acme/API' };
    const a = tokenCacheKey({ ...parts, credentials: credentialsId('1', 'key-a') });
    const b = tokenCacheKey({ ...parts, credentials: credentialsId('1', 'key-b') });
    expect(a).not.toBe(b);
    expect(
      tokenCacheKey({ ...parts, repo: 'acme/api', credentials: credentialsId('1', 'key-a') }),
    ).toBe(a);
    expect(a).not.toContain('key-a');
  });

  it('holds at most 1 000 entries, dropping the oldest', () => {
    const cache = new InstallationTokenCache(() => 0);
    for (let i = 0; i < 1_001; i++) cache.set(`k${i}`, `t${i}`, 60 * 60_000);
    expect(cache.size).toBe(1_000);
    expect(cache.get('k0')).toBeNull();
    expect(cache.get('k1000')).toBe('t1000');
  });

  it('keeps no token where a logger could print it', () => {
    const cache = new InstallationTokenCache(() => 0);
    cache.set('k', 'ghs_secret', 60 * 60_000);
    expect(JSON.stringify(cache)).not.toContain('ghs_secret');
  });
});

describe('MutationPacer (github.md §5.3)', () => {
  it('spaces mutations of one installation at least 1 s apart, and not those of another', async () => {
    let now = 0;
    const slept: number[] = [];
    const pacer = new MutationPacer(
      () => now,
      async (ms) => {
        slept.push(ms);
        now += ms;
      },
    );
    await pacer.wait('i1');
    await pacer.wait('i2');
    now += 300;
    await pacer.wait('i1');
    expect(slept).toEqual([700]);
  });

  it('lets two waiters of one installation through one second apart', async () => {
    let now = 0;
    const pacer = new MutationPacer(
      () => now,
      async (ms) => {
        now += ms;
        await Promise.resolve();
      },
    );
    const times: number[] = [];
    await pacer.wait('i');
    times.push(now);
    await Promise.all([
      pacer.wait('i').then(() => times.push(now)),
      pacer.wait('i').then(() => times.push(now)),
    ]);
    expect(times[0]).toBe(0);
    expect(times[2]! - times[1]!).toBeGreaterThanOrEqual(1_000);
  });
});
