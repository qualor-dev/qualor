import { fileURLToPath } from 'node:url';
import { buildApp, type AppDeps } from '../app';
import { DEFAULT_TELEMETRY_URL, type Config } from '../config';
import { createDatabase, type Db } from '../db/client';
import { createLogger } from './logger';

export const OPENAPI_PATH = fileURLToPath(new URL('../../openapi.json', import.meta.url));

const MiB = 1024 * 1024;
const UNUSED_DATABASE = 'postgres://openapi@127.0.0.1:1/openapi';

/** Loads plugins into the app the document is taken from (a plugin package's own document). */
export type OpenApiPlugins = (
  db: Db,
  config: Config,
) => Promise<Pick<AppDeps, 'plugins' | 'edition' | 'audit'>>;

/**
 * Builds the app against a pool that never connects and returns its OpenAPI document. The
 * committed server/openapi.json is generated without plugins; `plugins` adds their routes.
 */
export async function openApiDocument(plugins?: OpenApiPlugins): Promise<unknown> {
  const database = createDatabase(UNUSED_DATABASE, { max: 1 });
  const config: Config = {
    databaseUrl: UNUSED_DATABASE,
    embedded: { dataDir: '/var/lib/qualor', postgresDir: '/opt/postgresql' },
    secretKey: 'openapi-document-generation-only-secret',
    host: '127.0.0.1',
    port: 0,
    logLevel: 'silent',
    trustProxy: false,
    bootstrapAdmin: { username: 'admin', password: undefined },
    sessionTtlHours: 1,
    upload: { maxCompressedBytes: 50 * MiB, maxDecompressedBytes: 500 * MiB },
    workerConcurrency: 1,
    requestTimeoutMs: 300_000,
    maxConcurrentUploads: 4,
    uiDir: null,
    publicUrl: null,
    scmInternalHosts: new Set(),
    llmInternalHosts: new Set(),
    ssoInternalHosts: new Set(),
    forcePasswordSignIn: false,
    // The committed document is generated without a licence or plugins (enterprise.md §10.2).
    license: { text: null, file: null },
    pluginPaths: [],
    demoUser: null,
    telemetry: { enabled: false, url: DEFAULT_TELEMETRY_URL },
  };
  const loaded = plugins ? await plugins(database.db, config) : {};
  const app = await buildApp({
    config,
    ...loaded,
    db: database.db,
    logger: createLogger('silent'),
    checkReady: async () => false,
  });
  try {
    await app.ready();
    return app.swagger();
  } finally {
    await app.close();
    await database.close();
  }
}

export function serializeOpenApi(doc: unknown): string {
  return `${JSON.stringify(doc, null, 2)}\n`;
}
