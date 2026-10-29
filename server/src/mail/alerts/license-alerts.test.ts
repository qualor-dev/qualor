import { describe, expect, it } from 'vitest';
import { testPayload } from '../../../test/license';
import { DAY_MS, licenseState } from '../../license/state';
import { licenseAlertBucket } from './license-alerts';

const NOW = new Date('2026-10-13T12:00:00.000Z');
/** A valid licence that expires `ms` after NOW. */
const expiringIn = (ms: number) =>
  licenseState(
    {
      ok: true,
      kid: 'test-a',
      license: testPayload({ expires: new Date(NOW.getTime() + ms).toISOString() }),
    },
    NOW,
  );

describe('licence alert buckets (E1 spec, Alerts)', () => {
  it.each([
    ['31 days', 31 * DAY_MS, null],
    ['30 days and 1 ms', 30 * DAY_MS + 1, null],
    ['exactly 30 days', 30 * DAY_MS, '30d'],
    ['7 days and 1 ms', 7 * DAY_MS + 1, '30d'],
    ['exactly 7 days', 7 * DAY_MS, '7d'],
    ['1 day and 1 ms', DAY_MS + 1, '7d'],
    ['exactly 1 day', DAY_MS, '1d'],
    ['1 ms', 1, '1d'],
    ['0 ms (expired now: grace)', 0, 'grace'],
    ['13 days ago (grace)', -13 * DAY_MS, 'grace'],
    ['14 days ago (grace over)', -14 * DAY_MS, 'expired'],
  ] as const)('%s left is %s', (_what, ms, bucket) => {
    expect(licenseAlertBucket(expiringIn(ms), NOW)).toBe(bucket);
  });

  it('has no bucket without a licence or for an invalid one', () => {
    expect(licenseAlertBucket(licenseState(null, NOW), NOW)).toBeNull();
    expect(
      licenseAlertBucket(licenseState({ ok: false, reason: 'bad-signature' }, NOW), NOW),
    ).toBeNull();
  });
});
