import { describe, expect, it } from 'vitest';
import {
  COMMUNITY_LLM_LIMITS,
  communityLimits,
  LICENSE_GRACE_DAYS,
  licensedLimits,
} from './limits';

describe('licensed limits (enterprise.md §7.2)', () => {
  it('keeps the constants in one place', () => {
    expect(LICENSE_GRACE_DAYS).toBe(14);
  });

  it('has no organisation limit and no fix ceiling: only the seams (enterprise.md §1.3, D10)', () => {
    expect(communityLimits()).toEqual({
      llm: { automaticFixSuggestions: false },
      licenses: { policy: false },
      vulnerabilities: { priority: false, alerts: false, sbom: false },
    });
    expect(licensedLimits([])).toEqual({
      llm: COMMUNITY_LLM_LIMITS,
      licenses: { policy: false },
      vulnerabilities: { priority: false, alerts: false, sbom: false },
    });
    expect(licensedLimits([{ llm: { automaticFixSuggestions: true } }])).toEqual({
      llm: { automaticFixSuggestions: true },
      licenses: { policy: false },
      vulnerabilities: { priority: false, alerts: false, sbom: false },
    });
  });

  it('reads each override value once (a getter cannot pass one value and use another)', () => {
    let reads = 0;
    const llm = {
      get automaticFixSuggestions(): boolean {
        reads += 1;
        return reads === 1;
      },
    };
    expect(licensedLimits([{ llm }]).llm.automaticFixSuggestions).toBe(true);
    expect(reads).toBe(1);
  });

  it('applies LLM overrides in order and ignores anything else', () => {
    expect(
      licensedLimits([
        { llm: { automaticFixSuggestions: true } },
        { organizations: 9999 } as never,
      ]),
    ).toEqual({
      llm: { automaticFixSuggestions: true },
      licenses: { policy: false },
      vulnerabilities: { priority: false, alerts: false, sbom: false },
    });
    expect(
      licensedLimits([
        { llm: { automaticFixSuggestions: true } },
        { llm: { automaticFixSuggestions: false } },
      ]).llm,
    ).toEqual({ automaticFixSuggestions: false });
  });

  it('ignores an override of the wrong type, and the retired fix ceiling (D10)', () => {
    const limits = licensedLimits([
      { llm: { maxFixPerOrganizationPerDay: 100_000 } as never },
      { llm: { automaticFixSuggestions: 'yes' as never } },
      { llm: { automaticFixSuggestions: 1 as never } },
    ]);
    expect(limits.llm).toEqual(COMMUNITY_LLM_LIMITS);
    expect(limits.llm).not.toHaveProperty('maxFixPerOrganizationPerDay');
  });

  it('turns the licence policy on only with a boolean override (6M)', () => {
    expect(licensedLimits([{ licenses: { policy: true } }]).licenses).toEqual({ policy: true });
    // In order: a later boolean wins, anything else is ignored.
    expect(
      licensedLimits([
        { licenses: { policy: true } },
        { licenses: { policy: 'no' as never } },
        { licenses: {} },
      ]).licenses,
    ).toEqual({ policy: true });
    expect(
      licensedLimits([{ licenses: { policy: true } }, { licenses: { policy: false } }]).licenses,
    ).toEqual({ policy: false });
    expect(licensedLimits([{ licenses: { policy: 1 as never } }]).licenses).toEqual({
      policy: false,
    });
    // An unknown key is ignored, and the policy limit leaves the LLM limits alone.
    const limits = licensedLimits([
      { licenses: { policy: true, inventory: true } as never },
      { licences: { policy: true } } as never,
    ]);
    expect(limits).toEqual({
      llm: COMMUNITY_LLM_LIMITS,
      licenses: { policy: true },
      vulnerabilities: { priority: false, alerts: false, sbom: false },
    });
  });

  it('reads the policy override once', () => {
    let reads = 0;
    const licenses = {
      get policy(): boolean {
        reads += 1;
        return reads === 1;
      },
    };
    expect(licensedLimits([{ licenses }]).licenses.policy).toBe(true);
    expect(reads).toBe(1);
  });

  it('turns each vulnerability switch on only with a boolean override', () => {
    expect(communityLimits().vulnerabilities).toEqual({
      priority: false,
      alerts: false,
      sbom: false,
    });
    expect(
      licensedLimits([
        { vulnerabilities: { priority: true } },
        { vulnerabilities: { sbom: true } },
        { vulnerabilities: { alerts: 'true' as never } },
      ]).vulnerabilities,
    ).toEqual({ priority: true, alerts: false, sbom: true });
  });
});
