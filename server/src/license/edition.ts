import { communityLimits, licensedLimits, type Limits, type PluginLimitOverride } from '../limits';
import type { PluginReport, UiExtension } from '../plugins/contract';
import type { BootLicense, LicenseSource } from './source';
import { licenseState, type LicenseState } from './state';
import { productionVerifyOptions, type VerifyOptions } from './verify';

/** What loaded plugins contribute to the edition (the registry of Task 6 extends it). */
export interface EditionPlugins {
  reports: readonly PluginReport[];
  /** Features implemented by loaded plugins. */
  features: ReadonlySet<string>;
  limitOverrides: readonly { feature: string; override: PluginLimitOverride }[];
  extensions: readonly { feature: string; extension: UiExtension }[];
}

/**
 * enterprise.md §7.1 (5D): a feature that extends another is active only with it. The
 * edition's active set applies this, so every guard, skip, extension, limit override and
 * `/system/info.features` agrees without a check of its own. A key that breaks it still verifies.
 */
export const FEATURE_PREREQUISITES: Readonly<Record<string, string>> = Object.freeze({
  'audit-log.stream': 'audit-log',
  'sso.multi': 'sso',
});

/**
 * The prerequisite of `feature`, if it has one. Reads only the table's own keys: a feature name
 * such as `constructor` (which the feature pattern allows) never finds `Object.prototype`.
 */
export function prerequisiteOf(feature: string): string | undefined {
  return Object.hasOwn(FEATURE_PREREQUISITES, feature) ? FEATURE_PREREQUISITES[feature] : undefined;
}

export const NO_PLUGINS: EditionPlugins = {
  reports: [],
  features: new Set(),
  limitOverrides: [],
  extensions: [],
};

/**
 * enterprise.md §7: the one object that answers "which edition, which limits, which features".
 * Everything is computed from the boot key and the clock on every call, so a key lapses on a
 * running server without a restart. It never holds the key text, only its hash.
 */
export interface Edition {
  state(): LicenseState;
  edition(): 'community' | 'enterprise';
  limits(): Limits;
  /**
   * Licensed by the key and implemented by a loaded plugin, with its prerequisite
   * ({@link FEATURE_PREREQUISITES}) active too, sorted.
   */
  activeFeatures(): string[];
  isFeatureActive(feature: string): boolean;
  /** The extensions of active features only (enterprise.md §10.4). */
  uiExtensions(): UiExtension[];
  plugins(): readonly PluginReport[];
  /** The clock the state is computed with; the licence API checks an uploaded key against it. */
  now(): Date;
  /**
   * The public keys and revocations the boot key was verified with, at `now`. The licence API
   * verifies an upload with the same ones (one seam: a test key accepted at boot is accepted by
   * PUT /license, and a release build accepts neither).
   */
  verifyOptions(now: Date): VerifyOptions;
  readonly bootSource: LicenseSource | null;
  /** SHA-256 of the whitespace-free boot key, for `restartRequired`. */
  readonly bootKeyHash: string | null;
}

export function createEdition(options: {
  boot: BootLicense;
  plugins?: EditionPlugins;
  now?: () => Date;
  /** Defaults to the compiled public keys (`productionVerifyOptions`). */
  verifyOptions?: (now: Date) => VerifyOptions;
}): Edition {
  const plugins = options.plugins ?? NO_PLUGINS;
  // A copy: nothing done to the caller's set later changes which features are implemented.
  const implemented: ReadonlySet<string> = new Set(plugins.features);
  const now = options.now ?? (() => new Date());
  const state = (): LicenseState => licenseState(options.boot.verification, now());
  // Licensed, implemented, and with its prerequisite (if any) licensed and implemented too. One
  // pass is enough: no prerequisite has a prerequisite of its own (edition.test.ts pins it).
  const active = (s: LicenseState): string[] => {
    if (!s.licensed || !s.license) return [];
    const on = new Set(s.license.features.filter((f) => implemented.has(f)));
    return [...on]
      .filter((f) => {
        const needs = prerequisiteOf(f);
        return needs === undefined || on.has(needs);
      })
      .sort();
  };
  return {
    state,
    edition: () => (state().licensed ? 'enterprise' : 'community'),
    limits: () => {
      const s = state();
      if (!s.licensed || !s.license) return communityLimits();
      const on = new Set(active(s));
      return licensedLimits(
        plugins.limitOverrides.filter((o) => on.has(o.feature)).map((o) => o.override),
      );
    },
    activeFeatures: () => active(state()),
    isFeatureActive: (feature) => active(state()).includes(feature),
    uiExtensions: () => {
      const on = new Set(active(state()));
      return plugins.extensions.filter((e) => on.has(e.feature)).map((e) => ({ ...e.extension }));
    },
    plugins: () => plugins.reports,
    now,
    verifyOptions: options.verifyOptions ?? productionVerifyOptions,
    bootSource: options.boot.source,
    bootKeyHash: options.boot.keyHash,
  };
}

/** For tests and `buildApp` without an edition: no licence, the given limits. */
export function fixedEdition(limits: Limits = communityLimits()): Edition {
  const edition = createEdition({ boot: { source: null, keyHash: null, verification: null } });
  return { ...edition, limits: () => ({ ...limits, llm: { ...limits.llm } }) };
}
