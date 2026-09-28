// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { readFileSync } from 'node:fs';
import { count } from 'drizzle-orm';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createTestContext,
  createUser,
  login,
  type Session,
  type TestContext,
} from '../../server/test/app';
import { signTest, testPayload, testSigner, verifyWith } from '../../server/test/license';
import type { LicensePayload } from '../../server/src/license/token';
import { organizations, projects } from '../../server/src/db/schema';
import { createEdition } from '../../server/src/license/edition';
import { DAY_MS, licenseState } from '../../server/src/license/state';
import { verifyLicenseKey } from '../../server/src/license/verify';
import { loadPlugins } from '../../server/src/plugins/loader';
import { assertEnterpriseInputs, buildEnterprise } from '../scripts/bundle';

// Under enterprise/, so the bundle resolves its external zod from enterprise/node_modules, as the
// image's /app/enterprise/plugin.js resolves it from /app/node_modules.
const OUT = fileURLToPath(new URL('../.tmp/enterprise-test/plugin.js', import.meta.url));

/** A test server that booted with `license` and loaded the built plugin through the real loader. */
async function bootWith(license: LicensePayload, clock: () => Date): Promise<TestContext> {
  const signer = testSigner();
  const verification = verifyLicenseKey(signTest(signer, license), verifyWith(signer, clock()));
  const boot = { source: 'environment' as const, keyHash: 'h', verification };
  return createTestContext({
    pluginsFor: async (db) => {
      const quiet = { debug() {}, info() {}, warn() {}, error() {}, child: () => quiet };
      const plugins = await loadPlugins({
        paths: [OUT],
        state: licenseState(verification, clock()),
        base: { serverVersion: '0.0.0', db, logger: quiet as never },
      });
      return { plugins, edition: createEdition({ boot, plugins, now: clock }) };
    },
  });
}

let inputs: string[];
beforeAll(async () => {
  ({ inputs } = await buildEnterprise({ outfile: OUT }));
}, 60_000);

describe('Qualor Enterprise end to end (enterprise.md §17)', () => {
  const license = testPayload({
    features: ['llm.fix-quota'],
    expires: '2027-10-01T00:00:00Z',
  });
  let now = new Date('2027-01-01T00:00:00Z');
  let ctx: TestContext;
  let admin: Session;

  beforeAll(async () => {
    ctx = await bootWith(license, () => now);
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
  }, 60_000);
  afterAll(async () => ctx.close());

  const get = (url: string) => ctx.app.inject({ method: 'GET', url, headers: admin.headers });

  it('bundles only enterprise/src: no core code (types only), no package copy', () => {
    // The same allowlist the build enforces (enterprise.md §12), on the bundle this test loads.
    expect(inputs).toContain('src/plugin.ts');
    expect(() => assertEnterpriseInputs(inputs)).not.toThrow();
    expect(inputs.filter((i) => !i.startsWith('src/'))).toEqual([]);
    const bundle = readFileSync(OUT, 'utf8');
    expect(bundle).not.toMatch(/verifyLicenseKey|licensePayloadSchema/);
    // zod, the one runtime dependency, stays external: imported from node_modules, not copied.
    expect(bundle).toMatch(/from "zod"/);
    expect(bundle).not.toMatch(/class ZodError|\$ZodType/);
  });

  it('loads through the real loader and runs as the enterprise edition', async () => {
    expect(ctx.edition!.plugins()).toEqual([
      {
        name: 'qualor-enterprise',
        state: 'loaded',
        features: ['llm.fix-quota', 'audit-log', 'audit-log.stream', 'sso', 'sso.multi', 'scim'],
        error: null,
      },
    ]);
    expect((await get('/api/v0/system/info')).json()).toMatchObject({
      edition: 'enterprise',
      features: ['llm.fix-quota'],
    });
    expect((await get('/api/v0/system/llm')).json()).toMatchObject({ maxFixPerDay: 100_000 });
  });

  it('allows more than three organisations while licensed', async () => {
    for (const key of ['second', 'third', 'fourth']) {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/organizations',
        headers: admin.headers,
        payload: { key, name: key },
      });
      expect(res.statusCode).toBe(201);
    }
  });

  it('after grace, every organisation stays writable and nothing is deleted (enterprise.md §8, §17 item 4)', async () => {
    // Four organisations under the licence, then the clock past graceEndsAt.
    const member = await createUser(ctx, { username: 'lapse-member' });
    const before = {
      orgs: (await ctx.db.select({ n: count() }).from(organizations))[0]!.n,
      projects: (await ctx.db.select({ n: count() }).from(projects))[0]!.n,
    };
    now = new Date(Date.parse(license.expires) + 15 * DAY_MS);
    expect((await get('/api/v0/system/info')).json()).toMatchObject({
      edition: 'community',
      features: [],
    });
    expect((await get('/api/v0/system/llm')).json()).toMatchObject({ maxFixPerDay: 25 });
    const orgs = (await get('/api/v0/organizations')).json() as {
      items: Record<string, unknown>[];
    };
    expect(orgs.items).toHaveLength(4);
    for (const item of orgs.items) expect(item).not.toHaveProperty('readOnly');
    const fourth = orgs.items.find((o) => o['key'] === 'fourth')!;
    // An organisation-scoped mutation, refused with 409 as read-only before 5A.
    const changed = await ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/organizations/${fourth['id'] as string}/members/${member.id}`,
      headers: admin.headers,
      payload: { role: 'member' },
    });
    expect(changed.statusCode).toBe(200);
    expect({
      orgs: (await ctx.db.select({ n: count() }).from(organizations))[0]!.n,
      projects: (await ctx.db.select({ n: count() }).from(projects))[0]!.n,
    }).toEqual(before);
  });
});

describe('Qualor Enterprise with a key that does not list llm.fix-quota (enterprise.md §7.2)', () => {
  const now = new Date('2027-01-01T00:00:00Z');
  let ctx: TestContext;
  let admin: Session;

  beforeAll(async () => {
    ctx = await bootWith(testPayload({ features: [] }), () => now);
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
  }, 60_000);
  afterAll(async () => ctx.close());

  it('keeps the community fix ceiling: the plugin may not lift a limit the key does not license', async () => {
    const get = (url: string) => ctx.app.inject({ method: 'GET', url, headers: admin.headers });
    expect((await get('/api/v0/system/info')).json()).toMatchObject({
      features: [],
    });
    expect((await get('/api/v0/system/llm')).json()).toMatchObject({ maxFixPerDay: 25 });
  });

  it('answers 403 FEATURE_NOT_LICENSED on the audit-log, sso and scim routes the key does not list', async () => {
    const get = (url: string) => ctx.app.inject({ method: 'GET', url, headers: admin.headers });
    const info = (await get('/api/v0/system/info')).json() as { extensions: unknown[] };
    expect(info.extensions).toEqual([]);
    for (const url of [
      '/api/v0/ee/audit/events',
      '/api/v0/ee/audit/head',
      '/api/v0/ee/audit/settings',
      '/api/v0/ee/sso/connections',
      '/api/v0/ee/sso/00000000-0000-4000-8000-000000000000/start',
      '/api/v0/ee/scim/tokens',
      '/api/v0/ee/scim/v2/Users',
    ]) {
      const res = await get(url);
      expect(res.statusCode, url).toBe(403);
      expect(res.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED' });
    }
  });
});
