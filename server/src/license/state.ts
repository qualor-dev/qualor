import { LICENSE_GRACE_DAYS } from '../limits';
import type { LicensePayload } from './token';
import type { InvalidReason, Verification } from './verify';

export const DAY_MS = 24 * 60 * 60 * 1000;
/** Instance admins are warned this many days before `expires` (enterprise.md §5). */
export const EXPIRES_SOON_DAYS = 30;

export type LicenseStateName = 'none' | 'invalid' | 'active' | 'grace' | 'expired';

export interface LicenseState {
  state: LicenseStateName;
  reason: InvalidReason | null;
  kid: string | null;
  license: LicensePayload | null;
  graceEndsAt: Date | null;
  expiresSoon: boolean;
  /** `active` or `grace`: the edition is enterprise. */
  licensed: boolean;
}

export function graceEndsAt(license: LicensePayload): Date {
  return new Date(Date.parse(license.expires) + LICENSE_GRACE_DAYS * DAY_MS);
}

/**
 * enterprise.md §5: computed on every read, so a key lapses on a running server. Both
 * boundaries are half-open: at exactly `expires` the state is `grace`, at exactly the grace end
 * it is `expired`.
 */
export function licenseState(verification: Verification | null, now: Date): LicenseState {
  if (!verification) {
    return {
      state: 'none',
      reason: null,
      kid: null,
      license: null,
      graceEndsAt: null,
      expiresSoon: false,
      licensed: false,
    };
  }
  if (!verification.ok) {
    const license = verification.license ?? null;
    return {
      state: 'invalid',
      reason: verification.reason,
      kid: verification.kid ?? null,
      license,
      graceEndsAt: license ? graceEndsAt(license) : null,
      expiresSoon: false,
      licensed: false,
    };
  }
  const { license, kid } = verification;
  const t = now.getTime();
  const expires = Date.parse(license.expires);
  const graceEnd = graceEndsAt(license);
  const state: LicenseStateName =
    t < expires ? 'active' : t < graceEnd.getTime() ? 'grace' : 'expired';
  return {
    state,
    reason: null,
    kid,
    license,
    graceEndsAt: graceEnd,
    expiresSoon: state === 'active' && expires - t < EXPIRES_SOON_DAYS * DAY_MS,
    licensed: state === 'active' || state === 'grace',
  };
}
