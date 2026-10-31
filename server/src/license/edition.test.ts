import { describe, expect, it } from 'vitest';
import {
  BUSINESS_FEATURES,
  signTest,
  testPayload,
  testSigner,
  verifyWith,
  T0,
} from '../../test/license';
import { communityLimits } from '../limits';
import { licensePlan } from './plan';
import type { EditionPlugins } from './edition';
import {
  createEdition,
  FEATURE_PREREQUISITES,
  fixedEdition,
  NO_PLUGINS,
  prerequisiteOf,
} from './edition';
import type { BootLicense } from './source';
import { DAY_MS } from './state';
import { verifyLicenseKey } from './verify';

const license = testPayload({
  expires: '2027-10-01T00:00:00Z',
  features: ['llm.fix-quota', 'sso'],
});
const boot: BootLicense = {
  source: 'environment',
  keyHash: 'h',
  verification: { ok: true, kid: 'test-a', license },
};
const plugins: EditionPlugins = {
  reports: [{ name: 'p', state: 'loaded', features: ['llm.fix-quota', 'audit-log'], error: null }],
  features: new Set(['llm.fix-quota', 'audit-log']),
  // D10: llm.fix-quota is implemented, so a licence listing it is active, but it sets no limit.
  limitOverrides: [],
  extensions: [
    {
      feature: 'llm.fix-quota',
      extension: { point: 'settings.nav', id: 'quota', label: 'Quota', path: '/settings/ee/quota' },
    },
    {
      feature: 'audit-log',
      extension: { point: 'settings.nav', id: 'audit', label: 'Audit', path: '/settings/ee/audit' },
    },
  ],
};

describe('createEdition (enterprise.md §7)', () => {
  it('moves from active to grace to expired as the clock advances, without a restart', () => {
    let now = new Date('2027-09-30T00:00:00Z');
    const edition = createEdition({ boot, plugins, now: () => now });
    expect(edition.state().state).toBe('active');
    expect(edition.edition()).toBe('enterprise');
    now = new Date(Date.parse(license.expires) + DAY_MS);
    expect(edition.state().state).toBe('grace');
    expect(edition.edition()).toBe('enterprise');
    now = new Date(Date.parse(license.expires) + 14 * DAY_MS);
    expect(edition.state().state).toBe('expired');
    expect(edition.edition()).toBe('community');
    expect(edition.limits()).toEqual(communityLimits());
    expect(edition.activeFeatures()).toEqual([]);
    expect(edition.uiExtensions()).toEqual([]);
  });

  it('activates only features both licensed and implemented', () => {
    const edition = createEdition({ boot, plugins, now: () => T0 });
    expect(edition.activeFeatures()).toEqual(['llm.fix-quota']);
    expect(edition.isFeatureActive('sso')).toBe(false); // licensed, no plugin
    expect(edition.isFeatureActive('audit-log')).toBe(false); // plugin, not licensed
    expect(edition.uiExtensions().map((e) => e.id)).toEqual(['quota']);
  });

  it('takes the LLM limits from active overrides; there is no organisation limit', () => {
    const autoFixLicense = testPayload({
      expires: '2027-10-01T00:00:00Z',
      features: ['llm.auto-fix'],
    });
    const autoFixBoot: BootLicense = {
      source: 'environment',
      keyHash: 'h',
      verification: { ok: true, kid: 'test-a', license: autoFixLicense },
    };
    const autoFixPlugins: EditionPlugins = {
      ...plugins,
      features: new Set(['llm.fix-quota', 'llm.auto-fix']),
      limitOverrides: [
        { feature: 'llm.auto-fix', override: { llm: { automaticFixSuggestions: true } } },
      ],
    };
    expect(
      createEdition({ boot: autoFixBoot, plugins: autoFixPlugins, now: () => T0 }).limits(),
    ).toEqual({
      llm: { automaticFixSuggestions: true },
      licenses: { policy: false },
      vulnerabilities: { priority: false, alerts: false, sbom: false },
    });
    // A licence that does not list the feature leaves its override unused.
    expect(createEdition({ boot, plugins: autoFixPlugins, now: () => T0 }).limits()).toEqual(
      communityLimits(),
    );
  });

  it('a licence listing llm.fix-quota is active and changes no limit (D10)', () => {
    const edition = createEdition({ boot, plugins, now: () => T0 });
    expect(edition.isFeatureActive('llm.fix-quota')).toBe(true);
    expect(edition.limits()).toEqual(communityLimits());
  });

  it('is licensed without plugins: the community LLM limits, no features', () => {
    const edition = createEdition({ boot, now: () => T0 });
    expect(edition.edition()).toBe('enterprise');
    expect(edition.limits()).toEqual(communityLimits());
    expect(edition.activeFeatures()).toEqual([]);
  });

  it('is community for no key and for an invalid key', () => {
    for (const verification of [null, { ok: false as const, reason: 'bad-signature' as const }]) {
      const edition = createEdition({
        boot: { source: null, keyHash: null, verification },
        plugins,
        now: () => T0,
      });
      expect(edition.edition()).toBe('community');
      expect(edition.limits()).toEqual(communityLimits());
    }
  });

  it('exposes the clock its state is computed with', () => {
    let t = new Date('2026-10-01T00:00:00.000Z');
    const edition = createEdition({
      boot: { source: null, keyHash: null, verification: null },
      now: () => t,
    });
    expect(edition.now()).toEqual(new Date('2026-10-01T00:00:00.000Z'));
    t = new Date('2027-01-01T00:00:00.000Z');
    expect(edition.now()).toEqual(t);
  });

  it('a pre-5B key listing rbac verifies and rbac is never active (enterprise.md §1.4)', () => {
    // Review Focus 3: a customer's pre-5B key that lists rbac, every other feature on, and rbac
    // never active. A real signed key, checked through the server's own verifier.
    const signer = testSigner();
    const retiredLicense = testPayload({
      expires: '2027-10-01T00:00:00Z',
      features: ['rbac', 'audit-log'],
    });
    const verification = verifyLicenseKey(signTest(signer, retiredLicense), verifyWith(signer, T0));
    expect(verification).toEqual({ ok: true, kid: signer.kid, license: retiredLicense });
    const editionWithoutRbac = createEdition({
      boot: { source: 'environment', keyHash: 'h', verification },
      // The real plugin's feature list since 5B (enterprise.md §7.1, §13): rbac is gone.
      plugins: {
        reports: [],
        features: new Set(['llm.fix-quota', 'audit-log', 'sso', 'scim']),
        limitOverrides: [],
        extensions: [],
      },
      now: () => T0,
    });
    expect(editionWithoutRbac.state().state).toBe('active');
    expect(editionWithoutRbac.state().license?.features).toContain('rbac');
    expect(editionWithoutRbac.activeFeatures()).toEqual(['audit-log']);
    expect(editionWithoutRbac.isFeatureActive('rbac')).toBe(false);
  });

  it('a feature without its prerequisite is never active (enterprise.md §7.1)', () => {
    // Review Focus 3: a key made by hand that lists audit-log.stream without audit-log. Real
    // signed keys, checked through the server's own verifier, against a plugin implementing all six.
    const six = ['llm.fix-quota', 'audit-log', 'audit-log.stream', 'sso', 'sso.multi', 'scim'];
    const allSix: EditionPlugins = {
      reports: [],
      features: new Set(six),
      limitOverrides: six.map((feature) => ({
        feature,
        override: { llm: { automaticFixSuggestions: true } },
      })),
      extensions: six.map((feature) => ({
        feature,
        extension: { point: 'settings.nav', id: feature, label: feature, path: `/x/${feature}` },
      })),
    };
    const signer = testSigner();
    const editionFor = (features: string[]) => {
      const payload = testPayload({ expires: '2027-10-01T00:00:00Z', features });
      const verification = verifyLicenseKey(signTest(signer, payload), verifyWith(signer, T0));
      expect(verification.ok).toBe(true);
      return createEdition({
        boot: { source: 'environment', keyHash: 'h', verification },
        plugins: allSix,
        now: () => T0,
      });
    };

    const orphans = editionFor(['audit-log.stream', 'sso.multi']);
    expect(orphans.state().state).toBe('active');
    // The key verifies and the status shows what it lists; neither feature is active.
    expect(orphans.state().license?.features).toEqual(['audit-log.stream', 'sso.multi']);
    expect(orphans.activeFeatures()).toEqual([]);
    expect(orphans.isFeatureActive('audit-log.stream')).toBe(false);
    expect(orphans.isFeatureActive('sso.multi')).toBe(false);
    expect(orphans.limits()).toEqual(communityLimits());
    expect(orphans.uiExtensions()).toEqual([]);

    const four = ['audit-log', 'audit-log.stream', 'sso', 'sso.multi'];
    const whole = editionFor(four);
    expect(whole.activeFeatures()).toEqual(four);
    for (const f of four) expect(whole.isFeatureActive(f)).toBe(true);
    expect(whole.uiExtensions().map((e) => e.id)).toEqual(four);
    expect(whole.limits().llm.automaticFixSuggestions).toBe(true);

    // One pass suffices: no prerequisite has a prerequisite of its own.
    expect(FEATURE_PREREQUISITES).toEqual({ 'audit-log.stream': 'audit-log', 'sso.multi': 'sso' });
    expect(Object.isFrozen(FEATURE_PREREQUISITES)).toBe(true);
    for (const needs of Object.values(FEATURE_PREREQUISITES)) {
      expect(FEATURE_PREREQUISITES[needs]).toBeUndefined();
    }
  });

  it('reads only its own prerequisites, never an inherited object key', () => {
    // `constructor` matches the feature pattern; Object.prototype must not give it a prerequisite.
    expect(prerequisiteOf('constructor')).toBeUndefined();
    expect(prerequisiteOf('toString')).toBeUndefined();
    expect(prerequisiteOf('sso.multi')).toBe('sso');
    const signer = testSigner();
    const payload = testPayload({ expires: '2027-10-01T00:00:00Z', features: ['constructor'] });
    const verification = verifyLicenseKey(signTest(signer, payload), verifyWith(signer, T0));
    expect(verification.ok).toBe(true);
    const edition = createEdition({
      boot: { source: 'environment', keyHash: 'h', verification },
      plugins: { ...NO_PLUGINS, features: new Set(['constructor']) },
      now: () => T0,
    });
    expect(edition.activeFeatures()).toEqual(['constructor']);
  });

  it('fixedEdition keeps the limits a test passes', () => {
    const limits = {
      llm: { automaticFixSuggestions: true },
      licenses: { policy: true },
      vulnerabilities: { priority: true, alerts: false, sbom: false },
    };
    const edition = fixedEdition(limits);
    expect(edition.limits()).toEqual(limits);
    // A copy: a caller cannot change the edition's limits through the answer.
    edition.limits().licenses.policy = false;
    expect(edition.limits().licenses.policy).toBe(true);
    edition.limits().vulnerabilities.priority = false;
    expect(edition.limits().vulnerabilities.priority).toBe(true);
    expect(edition.edition()).toBe('community');
    expect(edition.state().state).toBe('none');
  });

  it('activates the vulnerability features of a Business key and still says Business', () => {
    const vulnFeatures = ['vuln.priority', 'vuln.alerts', 'sbom'];
    const businessBoot: BootLicense = {
      source: 'environment',
      keyHash: 'h',
      verification: {
        ok: true,
        kid: 'test-a',
        license: testPayload({ expires: '2027-10-01T00:00:00Z', features: [...BUSINESS_FEATURES] }),
      },
    };
    const edition = createEdition({
      boot: businessBoot,
      plugins: {
        reports: [],
        features: new Set(vulnFeatures),
        limitOverrides: [
          { feature: 'vuln.priority', override: { vulnerabilities: { priority: true } } },
          { feature: 'vuln.alerts', override: { vulnerabilities: { alerts: true } } },
          { feature: 'sbom', override: { vulnerabilities: { sbom: true } } },
        ],
        extensions: [],
      },
      now: () => T0,
    });
    for (const f of vulnFeatures) expect(edition.isFeatureActive(f)).toBe(true);
    expect(edition.limits().vulnerabilities).toEqual({ priority: true, alerts: true, sbom: true });
    expect(licensePlan(BUSINESS_FEATURES)).toBe('Business');
  });
});
