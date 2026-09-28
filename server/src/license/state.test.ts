import { describe, expect, it } from 'vitest';
import { testPayload } from '../../test/license';
import { DAY_MS, licenseState } from './state';
import type { Verification } from './verify';

const license = testPayload({ expires: '2027-10-01T00:00:00Z' });
const ok: Verification = { ok: true, kid: 'test-a', license };
const expires = Date.parse(license.expires);
const at = (ms: number) => new Date(ms);

describe('licenseState (enterprise.md §5)', () => {
  it('is none without a key and invalid with a reason', () => {
    expect(licenseState(null, at(expires))).toMatchObject({ state: 'none', licensed: false });
    expect(licenseState({ ok: false, reason: 'bad-signature' }, at(expires))).toMatchObject({
      state: 'invalid',
      reason: 'bad-signature',
      license: null,
      licensed: false,
    });
  });

  it.each([
    ['1 ms before expires', expires - 1, 'active', true],
    ['at expires', expires, 'grace', true],
    ['1 ms before the grace ends', expires + 14 * DAY_MS - 1, 'grace', true],
    ['when the grace ends', expires + 14 * DAY_MS, 'expired', false],
    ['a year later', expires + 365 * DAY_MS, 'expired', false],
  ])('%s: %s', (_when, ms, state, licensed) => {
    expect(licenseState(ok, at(ms))).toMatchObject({ state, licensed });
  });

  it('reports the grace end to the millisecond', () => {
    expect(licenseState(ok, at(expires)).graceEndsAt?.toISOString()).toBe(
      '2027-10-15T00:00:00.000Z',
    );
  });

  it('warns 29 days before expiry, not 30', () => {
    expect(licenseState(ok, at(expires - 30 * DAY_MS)).expiresSoon).toBe(false);
    expect(licenseState(ok, at(expires - 29 * DAY_MS)).expiresSoon).toBe(true);
    expect(licenseState(ok, at(expires)).expiresSoon).toBe(false);
  });

  it('keeps the licence of a revoked key for the admin screen', () => {
    expect(
      licenseState({ ok: false, reason: 'revoked', kid: 'test-a', license }, at(0)),
    ).toMatchObject({
      state: 'invalid',
      reason: 'revoked',
      license,
    });
  });

  it('is never licensed while invalid, even inside the dates of the licence', () => {
    const revoked: Verification = { ok: false, reason: 'revoked', kid: 'test-a', license };
    expect(licenseState(revoked, at(expires - 1))).toMatchObject({
      state: 'invalid',
      licensed: false,
      expiresSoon: false,
    });
  });
});
