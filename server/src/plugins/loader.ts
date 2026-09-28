import { basename, extname, isAbsolute } from 'node:path';
import { pathToFileURL } from 'node:url';
import type { FastifyBaseLogger } from 'fastify';
import type { Db } from '../db/client';
import { pgErrorCode } from '../db/errors';
import type { LicenseState } from '../license/state';
import { checkPluginFile, type PluginFileCheck } from './plugin-file';
import {
  emptyRegistry,
  PluginError,
  StagedPlugin,
  validatePlugin,
  type PluginRegistry,
} from './registry';
import type { PluginServices } from './services';

export { checkPluginFile, type PluginFileCheck, type PluginFileSystem } from './plugin-file';

/** enterprise.md §10.1: a plugin's `register` must resolve within 10 s. */
export const REGISTER_TIMEOUT_MS = 10_000;
/** api.md §4.1: QUALOR_PLUGIN_PATHS holds at most 8 paths (config.ts refuses more at boot). */
const MAX_PLUGIN_PATHS = 8;
const MAX_ERROR_LENGTH = 500;

export interface LoadPluginsOptions {
  /** config.pluginPaths, from QUALOR_PLUGIN_PATHS only. */
  paths: readonly string[];
  /** The boot licence state; nothing is touched unless it is `active` or `grace`. */
  state: LicenseState;
  base: {
    serverVersion: string;
    db: Db;
    logger: FastifyBaseLogger;
    /** rbac-audit.md §15: the plugin's access, audit, sso and scim services (bootEnterprise). */
    services?: PluginServices;
  };
  importModule?: (url: string) => Promise<unknown>;
  /** Defaults to `checkPluginFile` (enterprise.md §10.1.1). */
  checkFile?: (path: string) => Promise<PluginFileCheck>;
  timeoutMs?: number;
}

/**
 * enterprise.md §12: the only import() expression in server/src. Its specifier is the file URL
 * of a path from QUALOR_PLUGIN_PATHS; core never names enterprise/.
 */
const importByUrl = (url: string): Promise<unknown> => import(url);

function withTimeout<T>(work: Promise<T>, ms: number): Promise<T> {
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new PluginError(`did not register within ${ms / 1000} s`)), ms);
  });
  return Promise.race([work, timeout]).finally(() => clearTimeout(timer));
}

/**
 * A plugin's error, as text that cannot throw and is bounded in length. Sanitised like the
 * logger's `err` serializer (http/logger.ts): an error carrying a database `query` or `params`
 * (drizzle's DrizzleQueryError puts the SQL and its bind parameters in its message) is reported
 * as "database query failed" with its SQLSTATE, never its message (enterprise.md §10.1).
 */
export function describePluginError(err: unknown): string {
  let text: string;
  try {
    if (err instanceof Error && ('query' in err || 'params' in err)) {
      const code = pgErrorCode(err);
      text = code ? `database query failed (SQLSTATE ${code})` : 'database query failed';
    } else {
      text = err instanceof Error ? String(err.message) : String(err);
    }
  } catch {
    text = 'the plugin threw a value that cannot be described';
  }
  return text.length > MAX_ERROR_LENGTH ? `${text.slice(0, MAX_ERROR_LENGTH)}…` : text;
}

/**
 * The same shape config.ts accepts (api.md §4.1), checked again here because this is where a path
 * becomes an import: an absolute .js or .mjs path, nothing else.
 */
function checkPath(path: string): void {
  if (
    typeof path !== 'string' ||
    path.includes('\0') ||
    !isAbsolute(path) ||
    !['.js', '.mjs'].includes(extname(path))
  ) {
    throw new PluginError('a plugin path must be an absolute path to a .js or .mjs file');
  }
}

/** enterprise.md §5, §12: enterprise code runs only while the boot licence is active or in grace. */
function isLicensed(state: LicenseState): boolean {
  return (
    (state.state === 'active' || state.state === 'grace') &&
    state.licensed &&
    state.license !== null
  );
}

export async function loadPlugins(options: LoadPluginsOptions): Promise<PluginRegistry> {
  const registry = emptyRegistry();
  const { state, base } = options;
  // No licence, an invalid one or an expired one: return before any file system access.
  if (!isLicensed(state) || !state.license) return registry;
  const license = state.license;
  if (options.paths.length > MAX_PLUGIN_PATHS) {
    throw new PluginError(`at most ${MAX_PLUGIN_PATHS} plugin paths`);
  }
  const importModule = options.importModule ?? importByUrl;
  const checkFile = options.checkFile ?? ((path: string) => checkPluginFile(path));
  const timeoutMs = options.timeoutMs ?? REGISTER_TIMEOUT_MS;
  for (const path of options.paths) {
    let name = basename(path);
    let staged: StagedPlugin | undefined;
    try {
      checkPath(path);
      // Ruling R-PLUGINPATH: resolved, a regular file, and (on POSIX) owned and not writable by
      // others; the resolved path is what is imported.
      const file = await checkFile(path);
      if (!file.ok) throw new PluginError(file.reason);
      const mod = (await importModule(pathToFileURL(file.realPath).href)) as
        { default?: unknown } | undefined;
      const plugin = validatePlugin(mod?.default);
      name = plugin.name;
      staged = new StagedPlugin(plugin, registry);
      const logger = base.logger.child({ plugin: plugin.name });
      const ctx = staged.context(
        {
          serverVersion: base.serverVersion,
          db: base.db,
          logger,
          license,
          ...(base.services ? { services: base.services } : {}),
        },
        registry,
      );
      await withTimeout(
        new Promise<void>((resolve, reject) => {
          Promise.resolve(plugin.register(ctx)).then(() => resolve(), reject);
        }),
        timeoutMs,
      );
      staged.commit(registry);
      base.logger.info({ plugin: plugin.name, features: plugin.features }, 'plugin loaded');
    } catch (err) {
      staged?.discard();
      const message = describePluginError(err);
      registry.reports.push({ name, state: 'failed', features: [], error: message });
      base.logger.error({ plugin: name, path, err: message }, 'plugin failed to load');
    }
  }
  return registry;
}
