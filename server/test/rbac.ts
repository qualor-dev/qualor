import { sql } from 'drizzle-orm';
import { createAuditRecorder } from '../src/audit/recorder';
import { projectMemberships, type ProjectRole } from '../src/db/schema';
import { createEdition, type Edition } from '../src/license/edition';
import { DAY_MS, licenseState } from '../src/license/state';
import { verifyLicenseKey } from '../src/license/verify';
import type { QualorPlugin } from '../src/plugins/contract';
import { loadPlugins } from '../src/plugins/loader';
import { createPluginServices } from '../src/plugins/services';
import { createTestContext, type TestContext } from './app';
import { signTest, testPayload, testSigner, verifyWith } from './license';

/**
 * Implements the 4C features and registers nothing: core does the work (rbac-audit.md §15).
 * `rbac` is retired since 5B (enterprise.md §1.4): the real plugin no longer declares it.
 */
export const RBAC_FIXTURE: QualorPlugin = {
  name: 'rbac-fixture',
  apiVersion: 1,
  features: ['audit-log'],
  register() {},
};

export const LICENSE_EXPIRES = '2027-10-01T00:00:00Z';
/** One day after the grace period of a licence that expires at LICENSE_EXPIRES. */
export const AFTER_GRACE = new Date(Date.parse(LICENSE_EXPIRES) + 15 * DAY_MS);

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

type PluginsFor = NonNullable<NonNullable<Parameters<typeof createTestContext>[0]>['pluginsFor']>;

/**
 * The fixture plugin (or `plugin`) loaded under a licence listing `features`, with the services
 * and the one recorder bound to the edition as bootEnterprise binds them: createTestContext's
 * `pluginsFor`. `edition` may wrap the edition (a test that changes its limits).
 */
export function rbacPlugins(options: {
  features?: string[];
  now: () => Date;
  expires?: string;
  plugin?: QualorPlugin;
  edition?: (edition: Edition) => Edition;
}): PluginsFor {
  const signer = testSigner();
  const license = testPayload({
    features: options.features ?? ['audit-log'],
    expires: options.expires ?? LICENSE_EXPIRES,
  });
  const verification = verifyLicenseKey(
    signTest(signer, license),
    verifyWith(signer, options.now()),
  );
  const boot = { source: 'environment' as const, keyHash: 'h', verification };
  return async (db, config, logger) => {
    let edition: Edition | undefined;
    const isFeatureActive = (f: string): boolean => edition?.isFeatureActive(f) ?? false;
    // Records on the real clock, as the app's own recorder did before (only the licence moves).
    const audit = createAuditRecorder({
      isActive: () => isFeatureActive('audit-log'),
      log: logger,
    });
    const services = createPluginServices({
      db,
      isFeatureActive,
      secretKey: config.secretKey,
      version: '0.0.0',
      recorder: audit,
      // sso-scim.md §17.1: as bootEnterprise binds them.
      config,
      edition: () => {
        if (!edition) throw new Error('the edition does not exist yet');
        return edition;
      },
      logger,
    });
    const plugins = await loadPlugins({
      paths: ['/virtual/rbac-fixture.js'],
      state: licenseState(verification, options.now()),
      base: { serverVersion: '0.0.0', db, logger: quietLogger(), services },
      checkFile: async (path) => ({ ok: true, realPath: path }),
      importModule: async () => ({ default: options.plugin ?? RBAC_FIXTURE }),
    });
    return {
      plugins,
      edition: (frozen) => {
        const created = createEdition({ boot, plugins: frozen, now: options.now });
        edition = options.edition ? options.edition(created) : created;
        return edition;
      },
      audit,
    };
  };
}

/** A licensed test server listing `features`, the fixture plugin loaded; `now` moves the clock. */
export async function rbacContext(options: {
  features?: string[];
  now: () => Date;
  expires?: string;
  plugin?: QualorPlugin;
  edition?: (edition: Edition) => Edition;
}): Promise<TestContext> {
  return createTestContext({ pluginsFor: rbacPlugins(options) });
}

export async function grantProject(
  ctx: TestContext,
  projectId: string,
  userId: string,
  role: ProjectRole,
): Promise<void> {
  await ctx.db.insert(projectMemberships).values({ projectId, userId, role });
}

/**
 * Gives `n` users named `bulk-1` … `bulk-n` (made when missing) a `viewer` grant on the project:
 * the fill for the bound of 1 000 grants a project (rbac-audit.md §7.2).
 */
export async function fillProjectGrants(
  ctx: TestContext,
  projectId: string,
  n: number,
): Promise<void> {
  await ctx.db.execute(sql`
    INSERT INTO users (id, username)
    SELECT gen_random_uuid(), 'bulk-' || i FROM generate_series(1, ${n}) AS i
    ON CONFLICT (username) DO NOTHING`);
  await ctx.db.execute(sql`
    INSERT INTO project_memberships (project_id, user_id, role)
    SELECT ${projectId}, u.id, 'viewer' FROM users u
     WHERE u.username IN (SELECT 'bulk-' || i FROM generate_series(1, ${n}) AS i)`);
}
