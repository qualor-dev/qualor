import { describe, expect, it } from 'vitest';
import { testPayload } from '../../../test/license';
import { DAY_MS, licenseState } from '../../license/state';
import { renderLicenseExpiry } from '../templates/license-expiry';
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

describe('trial licence alerts', () => {
  const trialIn = (ms: number) =>
    licenseState(
      {
        ok: true,
        kid: 'test-a',
        license: testPayload({
          expires: new Date(NOW.getTime() + ms).toISOString(),
          trial: true,
        }),
      },
      NOW,
    );

  it.each([
    ['20 days (no 30-day mail)', 20 * DAY_MS, null],
    ['5 days', 5 * DAY_MS, '7d'],
    ['12 hours', DAY_MS / 2, '1d'],
    ['0 ms (ended)', 0, 'expired'],
    ['3 days ago', -3 * DAY_MS, 'expired'],
  ] as const)('a trial with %s left is %s, never grace', (_what, ms, bucket) => {
    expect(licenseAlertBucket(trialIn(ms), NOW)).toBe(bucket);
  });
});

describe('trial licence e-mail wording', () => {
  const base = {
    licensee: 'Acme Corporation',
    plan: 'Enterprise',
    expires: new Date('2026-10-18T12:00:00Z'),
    graceEndsAt: new Date('2026-10-18T12:00:00Z'),
    now: NOW,
    publicUrl: null,
    trial: true,
  };

  it.each([
    ['7d', 'Your Qualor Enterprise trial ends in 5 days', new Date('2026-10-18T12:00:00Z')],
    ['1d', 'Your Qualor Enterprise trial ends in 1 day', new Date('2026-10-14T00:00:00Z')],
    ['expired', 'Your Qualor Enterprise trial has ended', new Date('2026-10-12T12:00:00Z')],
  ] as const)('%s', (variant, subject, expires) => {
    const mail = renderLicenseExpiry({ ...base, variant, expires, graceEndsAt: expires });
    expect(mail.subject).toBe(subject);
    expect(mail.html).toContain('<a href="mailto:license@qualor.dev"');
    expect(mail.text).toContain('license@qualor.dev');
    expect(mail.html).toContain('buy a licence or extend the trial');
    expect(mail.text).toContain('buy a licence or extend the trial');
    expect(`${mail.html}${mail.text}`.toLowerCase()).not.toContain('grace');
  });

  it('keeps the paid wording when trial is false', () => {
    const mail = renderLicenseExpiry({
      ...base,
      trial: false,
      variant: '7d',
      plan: 'Business',
      graceEndsAt: new Date('2026-11-01T12:00:00Z'),
    });
    expect(mail.subject).toBe('Your Qualor licence expires in 5 days');
    expect(mail.html).not.toContain('license@qualor.dev');
  });
});
