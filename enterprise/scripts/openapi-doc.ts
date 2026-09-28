// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { fileURLToPath } from 'node:url';
import { createAuditRecorder } from '../../server/src/audit/recorder';
import { openApiDocument } from '../../server/src/http/openapi-doc';
import { createEdition } from '../../server/src/license/edition';
import { licenseState } from '../../server/src/license/state';
import { verifyLicenseKey } from '../../server/src/license/verify';
import { loadPlugins } from '../../server/src/plugins/loader';
import { dropPluginsThatFailToMount, freezePlugins } from '../../server/src/plugins/mount';
import { createPluginServices } from '../../server/src/plugins/services';
import { signTest, testPayload, testSigner, verifyWith } from '../../server/test/license';
import plugin from '../src/plugin';

export const ENTERPRISE_OPENAPI_PATH = fileURLToPath(new URL('../openapi.json', import.meta.url));

/** Inside the throwaway test licence (issued 2026-10-01, expires 2027-10-01). */
const LICENSED = new Date('2027-01-01T00:00:00Z');
const EE_PREFIX = '/api/v0/ee/';

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

/**
 * rbac-audit.md §17: the OpenAPI document of the enterprise routes. Built as the
 * server's is (server/src/http/openapi-doc.ts), with the plugin's source module loaded through the
 * real loader under a throwaway key listing every feature it declares; only the paths under
 * /api/v0/ee are kept. Nothing connects to a database.
 */
export async function enterpriseOpenApiDocument(): Promise<unknown> {
  const doc = (await openApiDocument(async (db, config) => {
    const signer = testSigner();
    const verification = verifyLicenseKey(
      signTest(signer, testPayload({ features: [...plugin.features] })),
      verifyWith(signer, LICENSED),
    );
    const boot = { source: 'environment' as const, keyHash: 'openapi', verification };
    const audit = createAuditRecorder({ isActive: () => false, log: { error: () => undefined } });
    const services = createPluginServices({
      db,
      isFeatureActive: () => false,
      secretKey: config.secretKey,
      version: '0.0.0',
      recorder: audit,
    });
    const registry = await loadPlugins({
      paths: ['/virtual/qualor-enterprise.js'],
      state: licenseState(verification, LICENSED),
      base: { serverVersion: '0.0.0', db, logger: quietLogger(), services },
      checkFile: async (path) => ({ ok: true, realPath: path }),
      importModule: async () => ({ default: plugin }),
    });
    await dropPluginsThatFailToMount(registry, quietLogger());
    const failed = registry.reports.filter((r) => r.state !== 'loaded');
    if (failed.length > 0) throw new Error(`the plugin did not load: ${failed[0]?.error ?? ''}`);
    const plugins = freezePlugins(registry);
    return { plugins, edition: createEdition({ boot, plugins, now: () => LICENSED }), audit };
  })) as { info: Record<string, unknown>; paths: Record<string, unknown> };
  return {
    ...doc,
    info: {
      ...doc.info,
      title: 'Qualor Enterprise API',
      description:
        'The routes of the Qualor Enterprise plugin (/api/v0/ee), mounted while a licence lists their feature; 403 FEATURE_NOT_LICENSED otherwise. Unstable, as the core API.',
    },
    paths: Object.fromEntries(Object.entries(doc.paths).filter(([p]) => p.startsWith(EE_PREFIX))),
  };
}
