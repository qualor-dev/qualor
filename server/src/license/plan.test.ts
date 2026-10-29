import { describe, expect, it } from 'vitest';
import { BUSINESS_FEATURES, ENTERPRISE_FEATURES } from '../../test/license';
import { licensePlan } from './plan';

describe('licensePlan', () => {
  it('names the plan from the features: Enterprise when it lists sso.multi, audit-log.stream or scim', () => {
    expect(licensePlan(BUSINESS_FEATURES)).toBe('Business');
    expect(licensePlan(ENTERPRISE_FEATURES)).toBe('Enterprise');
    expect(licensePlan(['scim'])).toBe('Enterprise');
  });
});
