import type { FastifyBaseLogger } from 'fastify';
import { createAuditRecorder, type AuditRecorder } from '../audit/recorder';
import type { Config } from '../config';
import type { Db } from '../db/client';
import { bootLicenseLog } from '../license/boot-log';
import { createEdition, type Edition } from '../license/edition';
import { readBootLicense, type BootLicense } from '../license/source';
import { licenseState } from '../license/state';
import { productionVerifyOptions, type VerifyOptions } from '../license/verify';
import { loadPlugins, type LoadPluginsOptions } from './loader';
import { dropPluginsThatFailToMount, freezePlugins, type LoadedPlugins } from './mount';
import { PluginError } from './registry';
import { createPluginServices } from './services';

export interface EnterpriseBoot {
  boot: BootLicense;
  plugins: LoadedPlugins;
  edition: Edition;
  /**
   * The one audit recorder: the plugin services record through it, and main.ts gives it to the
   * app (`AppDeps.audit`), so core and plugin changes land in one chain under one rule.
   */
  audit: AuditRecorder;
}

/**
 * enterprise.md §6, §10, §12: the licence is read once, then the loader runs, which touches no
 * plugin path unless the boot state is active or in grace. The committed registry is frozen, and
 * the API, the workers and the edition all use that one copy. One line states the edition and
 * the loaded plugins. A QUALOR_LICENSE_FILE that cannot be read throws LicenseFileError, which
 * main.ts turns into a failed boot. The plugins get the access, audit, sso and scim services
 * (rbac-audit.md §15), bound to the edition created after they load: until it exists, no feature
 * is active, so nothing a plugin does while it registers is recorded or allowed as licensed.
 */
export async function bootEnterprise(options: {
  config: Config;
  db: Db;
  logger: FastifyBaseLogger;
  serverVersion: string;
  /** Tests pass throwaway keys; production uses the compiled public keys. */
  verifyOptions?: (now: Date) => VerifyOptions;
  now?: () => Date;
  importModule?: LoadPluginsOptions['importModule'];
  checkFile?: LoadPluginsOptions['checkFile'];
}): Promise<EnterpriseBoot> {
  const now = options.now ?? (() => new Date());
  const verifyOptions = options.verifyOptions ?? productionVerifyOptions;
  const boot = await readBootLicense(options.config, options.db, verifyOptions(now()));
  const state = licenseState(boot.verification, now());
  // Filled in below, once the plugins are loaded; until then no feature is active.
  const bound: { edition?: Edition } = {};
  const isFeatureActive = (feature: string): boolean =>
    bound.edition?.isFeatureActive(feature) ?? false;
  const audit = createAuditRecorder({
    isActive: () => isFeatureActive('audit-log'),
    now,
    log: options.logger,
  });
  const services = createPluginServices({
    db: options.db,
    isFeatureActive,
    secretKey: options.config.secretKey,
    version: options.serverVersion,
    recorder: audit,
    now,
    log: { warn: (message) => options.logger.warn({ component: 'audit-stream' }, message) },
    // sso-scim.md §17.1: bound to the edition once it exists; until then a call fails the plugin
    // (nothing of SSO or SCIM runs while plugins register).
    config: options.config,
    edition: () => {
      if (!bound.edition) throw new PluginError('the edition does not exist yet');
      return bound.edition;
    },
    logger: options.logger,
  });
  const registry = await loadPlugins({
    paths: options.config.pluginPaths,
    state,
    base: {
      serverVersion: options.serverVersion,
      db: options.db,
      logger: options.logger,
      services,
    },
    importModule: options.importModule,
    checkFile: options.checkFile,
  });
  // Ruling R-MOUNT: a plugin whose routes throw at mount is dropped as a whole, before the app
  // exists, so the edition, the workers and the boot line all see it as failed.
  await dropPluginsThatFailToMount(registry, options.logger);
  const plugins = freezePlugins(registry);
  const edition = createEdition({ boot, plugins, now, verifyOptions });
  bound.edition = edition;
  const line = bootLicenseLog(boot, state, plugins.reports);
  options.logger[line.level]({ component: 'licence', ...line.fields }, line.message);
  return { boot, plugins, edition, audit };
}
