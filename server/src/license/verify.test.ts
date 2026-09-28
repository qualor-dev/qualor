import { sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  signTest,
  T0,
  testPayload,
  testSigner,
  verifyWith,
  type TestSigner,
} from '../../test/license';
import { verifyLicenseKey } from './verify';

/** Signs arbitrary payload bytes by hand: signLicenseKey itself refuses an invalid payload. */
function signBytes(signer: TestSigner, body: Buffer): string {
  const input = `QLK1.${signer.kid}.${body.toString('base64url')}`;
  return `${input}.${sign(null, Buffer.from(input), signer.privateKey).toString('base64url')}`;
}

function tamperPayload(key: string, change: (p: Record<string, unknown>) => void): string {
  const [prefix, kid, payload, signature] = key.split('.') as [string, string, string, string];
  const json = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')) as Record<
    string,
    unknown
  >;
  change(json);
  const next = Buffer.from(JSON.stringify(json), 'utf8').toString('base64url');
  return [prefix, kid, next, signature].join('.');
}

describe('verifyLicenseKey (enterprise.md §4)', () => {
  const signer = testSigner();

  it('verifies a key signed by an accepted key', () => {
    const payload = testPayload();
    const result = verifyLicenseKey(signTest(signer, payload), verifyWith(signer));
    expect(result).toEqual({ ok: true, kid: 'test-a', license: payload });
  });

  it.each([
    ['the customer', (p: Record<string, unknown>) => (p['customer'] = 'Someone Else')],
    ['an added organisation limit', (p: Record<string, unknown>) => (p['organizations'] = 10_000)],
    ['the expiry', (p: Record<string, unknown>) => (p['expires'] = '2099-01-01T00:00:00Z')],
    ['the features', (p: Record<string, unknown>) => (p['features'] = ['sso', 'scim'])],
  ])('rejects a key whose payload changed (%s) as bad-signature', (_what, change) => {
    const key = tamperPayload(signTest(signer), change);
    expect(verifyLicenseKey(key, verifyWith(signer))).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('rejects a changed signature byte as bad-signature', () => {
    const key = signTest(signer);
    const parts = key.split('.');
    const sig = Buffer.from(parts[3]!, 'base64url');
    sig[10] = sig[10]! ^ 0xff;
    parts[3] = sig.toString('base64url');
    expect(verifyLicenseKey(parts.join('.'), verifyWith(signer))).toMatchObject({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('rejects a key moved to another kid, even one that is accepted', () => {
    const other = testSigner('test-b');
    const parts = signTest(signer).split('.');
    parts[1] = 'test-b';
    const options = {
      ...verifyWith(signer),
      publicKeys: { 'test-a': signer.x, 'test-b': other.x },
    };
    expect(verifyLicenseKey(parts.join('.'), options)).toMatchObject({ reason: 'bad-signature' });
  });

  it('rejects a key signed by an unknown key as unknown-key', () => {
    const stranger = testSigner('test-z');
    expect(verifyLicenseKey(signTest(stranger), verifyWith(signer))).toEqual({
      ok: false,
      reason: 'unknown-key',
    });
  });

  it('rejects a key signed by a different private key under the accepted kid', () => {
    const impostor = testSigner('test-a');
    expect(verifyLicenseKey(signTest(impostor), verifyWith(signer))).toMatchObject({
      reason: 'bad-signature',
    });
  });

  it('treats a kid that names an Object.prototype member as unknown', () => {
    // `constructor` passes the kid pattern; `publicKeys.constructor` is Object's function.
    const s = testSigner('constructor');
    expect(verifyLicenseKey(signTest(s), verifyWith(signer))).toEqual({
      ok: false,
      reason: 'unknown-key',
    });
    // `__proto__` never passes the kid pattern.
    expect(verifyLicenseKey(`QLK1.__proto__.YQ.${'A'.repeat(86)}`, verifyWith(signer))).toEqual({
      ok: false,
      reason: 'malformed',
    });
  });

  it('rejects a correctly signed payload with an unknown field as bad-payload', () => {
    const payload = { ...testPayload(), seats: 5 };
    // Sign by hand: signLicenseKey itself refuses an invalid payload.
    const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const input = `QLK1.test-a.${body}`;
    const key = `${input}.${sign(null, Buffer.from(input), signer.privateKey).toString('base64url')}`;
    expect(verifyLicenseKey(key, verifyWith(signer))).toEqual({ ok: false, reason: 'bad-payload' });
  });

  it('rejects a revoked licence id and still reports the licence', () => {
    const payload = testPayload();
    const result = verifyLicenseKey(signTest(signer, payload), {
      ...verifyWith(signer),
      revoked: [payload.id],
    });
    expect(result).toEqual({ ok: false, reason: 'revoked', kid: 'test-a', license: payload });
  });

  it('compares revoked ids in lower case, whichever spelling the list or the key uses', () => {
    const payload = testPayload();
    const upperInList = verifyLicenseKey(signTest(signer, payload), {
      ...verifyWith(signer),
      revoked: [payload.id.toUpperCase()],
    });
    expect(upperInList).toMatchObject({ ok: false, reason: 'revoked' });
    const upperKey = testPayload({ id: payload.id.toUpperCase() });
    const upperInKey = verifyLicenseKey(signTest(signer, upperKey), {
      ...verifyWith(signer),
      revoked: [payload.id],
    });
    expect(upperInKey).toMatchObject({ ok: false, reason: 'revoked' });
  });

  it('fails closed as not-yet-valid when the clock is not a valid date', () => {
    const result = verifyLicenseKey(signTest(signer), verifyWith(signer, new Date(Number.NaN)));
    expect(result).toMatchObject({ ok: false, reason: 'not-yet-valid' });
  });

  it('accepts issued up to 24 h ahead of the clock, rejects it beyond as not-yet-valid', () => {
    const payload = testPayload({ issued: '2026-10-02T00:00:00Z' });
    const key = signTest(signer, payload);
    expect(verifyLicenseKey(key, verifyWith(signer, T0)).ok).toBe(true);
    const early = new Date(T0.getTime() - 1);
    expect(verifyLicenseKey(key, verifyWith(signer, early))).toMatchObject({
      reason: 'not-yet-valid',
    });
  });

  it('reports malformed for text that is not a key', () => {
    expect(verifyLicenseKey('hello', verifyWith(signer))).toEqual({
      ok: false,
      reason: 'malformed',
    });
  });

  it('rejects a malleated signature (S + L, the same point) as bad-signature', () => {
    const parts = signTest(signer).split('.');
    const sig = Buffer.from(parts[3]!, 'base64url');
    // RFC 8032 §5.1.7: S must be below the group order L; S + L verifies in a lax implementation.
    const L = 2n ** 252n + 27742317777372353535851937790883648493n;
    const s = BigInt('0x' + Buffer.from(sig.subarray(32)).reverse().toString('hex'));
    const high = Buffer.from((s + L).toString(16).padStart(64, '0'), 'hex').reverse();
    parts[3] = Buffer.concat([sig.subarray(0, 32), high]).toString('base64url');
    expect(verifyLicenseKey(parts.join('.'), verifyWith(signer))).toEqual({
      ok: false,
      reason: 'bad-signature',
    });
  });

  it('treats an accepted public key that is not a 32-byte Ed25519 key as bad-signature, not a crash', () => {
    const key = signTest(signer);
    for (const x of ['', 'AAAA', 'A'.repeat(44), signer.x + 'AA']) {
      expect(verifyLicenseKey(key, { ...verifyWith(signer), publicKeys: { 'test-a': x } })).toEqual(
        {
          ok: false,
          reason: 'bad-signature',
        },
      );
    }
  });

  it('does not accept a kid inherited through the prototype of the key map', () => {
    const publicKeys = Object.create({ 'test-a': signer.x }) as Record<string, string>;
    expect(verifyLicenseKey(signTest(signer), { ...verifyWith(signer), publicKeys })).toEqual({
      ok: false,
      reason: 'unknown-key',
    });
  });

  it.each([
    [
      'a __proto__ member',
      Buffer.from(`{"__proto__":{"x":1},${JSON.stringify(testPayload()).slice(1)}`),
    ],
    [
      // A lax decoder would turn the byte 0xff into U+FFFD and accept the customer name.
      'bytes that are not UTF-8',
      Buffer.from(
        JSON.stringify(testPayload({ customer: 'Acme @' })).replace('@', '\xff'),
        'latin1',
      ),
    ],
    [
      'a byte-order mark',
      Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(testPayload()))]),
    ],
    ['JSON that is not an object', Buffer.from('[1]')],
    [
      'an impossible date',
      Buffer.from(JSON.stringify({ ...testPayload(), expires: '2027-02-30T00:00:00Z' })),
    ],
    [
      'a date without Z',
      Buffer.from(JSON.stringify({ ...testPayload(), expires: '2027-10-01T00:00:00+00:00' })),
    ],
    [
      'expires before issued',
      Buffer.from(JSON.stringify({ ...testPayload(), expires: '2026-09-30T00:00:00Z' })),
    ],
    [
      'duplicate features',
      Buffer.from(JSON.stringify({ ...testPayload(), features: ['sso', 'sso'] })),
    ],
    [
      'a control character in the customer',
      Buffer.from(JSON.stringify({ ...testPayload(), customer: 'A\u0007B' })),
    ],
    ['another format version', Buffer.from(JSON.stringify({ ...testPayload(), v: 2 }))],
  ])('rejects a correctly signed payload with %s as bad-payload', (_what, body) => {
    expect(verifyLicenseKey(signBytes(signer, body), verifyWith(signer))).toEqual({
      ok: false,
      reason: 'bad-payload',
    });
  });

  it('reports malformed for whitespace only', () => {
    expect(verifyLicenseKey(' \r\n\t ', verifyWith(signer))).toEqual({
      ok: false,
      reason: 'malformed',
    });
  });
});

describe('the retired organizations member (enterprise.md §3.1)', () => {
  const signer = testSigner();
  const preFiveA = (organizations: unknown) =>
    signBytes(signer, Buffer.from(JSON.stringify({ ...testPayload(), organizations })));

  it('a pre-5A key verifies and its licence has no organizations', () => {
    const payload = testPayload();
    const key = signBytes(signer, Buffer.from(JSON.stringify({ ...payload, organizations: 10 })));
    const result = verifyLicenseKey(key, verifyWith(signer));
    expect(result).toEqual({ ok: true, kid: 'test-a', license: payload });
    expect(result.ok && 'organizations' in result.license).toBe(false);
  });

  it.each([0, 'ten', 10_001, 1.5, null, { n: 3 }])(
    'accepts any value of the retired organizations member (%j)',
    (value) => {
      expect(verifyLicenseKey(preFiveA(value), verifyWith(signer)).ok).toBe(true);
    },
  );

  it('still rejects any other unknown member as bad-payload', () => {
    const key = signBytes(signer, Buffer.from(JSON.stringify({ ...testPayload(), seats: 5 })));
    expect(verifyLicenseKey(key, verifyWith(signer))).toEqual({
      ok: false,
      reason: 'bad-payload',
    });
  });
});
