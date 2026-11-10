// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  createProject,
  createTestContext,
  createUser,
  login,
  organizationId as organizationIdOf,
  type Session,
  type TestContext,
} from '../../server/test/app';
import { mainBranchId, seedIssue, seedRule } from '../../server/test/issues';
import {
  BUSINESS_FEATURES,
  ENTERPRISE_FEATURES,
  signTest,
  testPayload,
  testSigner,
  verifyWith,
  type TestSigner,
} from '../../server/test/license';
import { grantProject, LICENSE_EXPIRES } from '../../server/test/rbac';
import { createAuditRecorder } from '../../server/src/audit/recorder';
import { uuidv7 } from '../../server/src/db/ids';
import { analyses, measures } from '../../server/src/db/schema';
import { createEdition, type Edition } from '../../server/src/license/edition';
import { licenseState } from '../../server/src/license/state';
import { verifyLicenseKey } from '../../server/src/license/verify';
import { loadPlugins } from '../../server/src/plugins/loader';
import { dropPluginsThatFailToMount } from '../../server/src/plugins/mount';
import { createPluginServices } from '../../server/src/plugins/services';
import { buildEnterprise } from '../scripts/bundle';

// Under enterprise/, so the bundle resolves its external zod and pdfkit from enterprise/node_modules,
// and finds the fonts in enterprise/fonts, as the image's /app/enterprise/plugin.js does.
const OUT = fileURLToPath(new URL('../.tmp/portfolio-test/plugin.js', import.meta.url));
const LICENSED = new Date('2027-01-01T00:00:00Z');
const PORTFOLIO = '/api/v0/ee/portfolio';
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);
const MAIN_NAV = {
  point: 'main.nav',
  id: 'portfolio',
  label: 'Portfolio',
  path: '/portfolio',
};

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

/**
 * The built plugin through the real loader (as compliance.db.test.ts boots it), under a key the
 * edition trusts, with the services and the one recorder bound to the edition as bootEnterprise
 * binds them. The licence runs on `clock`; the portfolio's `generatedAt` is the database's now().
 */
async function bootEnterpriseTest(
  signer: TestSigner,
  clock: () => Date,
  features: readonly string[] = ENTERPRISE_FEATURES,
): Promise<TestContext> {
  const verifyOptions = (at: Date) => verifyWith(signer, at);
  const verification = verifyLicenseKey(
    signTest(signer, testPayload({ features: [...features], expires: LICENSE_EXPIRES })),
    verifyOptions(clock()),
  );
  const boot = { source: 'uploaded' as const, keyHash: 'h', verification };
  return createTestContext({
    pluginsFor: async (db, config, logger) => {
      let edition: Edition | undefined;
      const isFeatureActive = (f: string): boolean => edition?.isFeatureActive(f) ?? false;
      const audit = createAuditRecorder({
        isActive: () => isFeatureActive('audit-log'),
        now: clock,
        log: logger,
      });
      const services = createPluginServices({
        db,
        isFeatureActive,
        secretKey: config.secretKey,
        version: '0.0.0',
        recorder: audit,
        now: clock,
      });
      const plugins = await loadPlugins({
        paths: [OUT],
        state: licenseState(verification, clock()),
        base: { serverVersion: '0.0.0', db, logger: quietLogger(), services },
      });
      await dropPluginsThatFailToMount(plugins, quietLogger());
      return {
        plugins,
        edition: (frozen) => {
          edition = createEdition({ boot, plugins: frozen, now: clock, verifyOptions });
          return edition;
        },
        audit,
      };
    },
  });
}

type Row = { organization: { key: string }; project: { key: string } };
type Overview = {
  scope: { kind: string; organization: { key: string } | null };
  granularity: string;
  totals: { projects: number; analysed: number; ncloc: number; issues: number };
  organizations: { key: string; projects: number }[] | null;
  trend: unknown[];
  attention: Record<string, Row[]>;
};

beforeAll(async () => {
  await buildEnterprise({ outfile: OUT });
}, 60_000);

describe('Qualor Enterprise: portfolio reports through the built plugin (4E-2 §3)', () => {
  const signer = testSigner();
  let ctx: TestContext;
  const sessions: Record<string, Session> = {};
  let orgA: string;
  let orgB: string;

  const get = (session: Session, url: string) =>
    ctx.app.inject({ method: 'GET', url, headers: session.headers });
  const keysOf = (rows: Row[]) => rows.map((r) => `${r.organization.key}/${r.project.key}`);
  const csvLines = (body: string) => {
    const lines = body.replace(/^\uFEFF/, '').split('\r\n');
    expect(lines.pop()).toBe('');
    return lines;
  };

  beforeAll(async () => {
    ctx = await bootEnterpriseTest(signer, () => LICENSED);
    const root = await login(ctx, 'admin', ADMIN_PASSWORD);
    sessions['root'] = root;
    const newOrg = async (key: string): Promise<string> => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/organizations',
        headers: root.headers,
        payload: { key, name: `${key} team` },
      });
      expect(res.statusCode, res.body).toBe(201);
      return (res.json() as { id: string }).id;
    };
    orgA = await newOrg('org-a');
    orgB = await newOrg('org-b');
    const alpha = await createProject(ctx, root, { organizationId: orgA, key: 'alpha' });
    await createProject(ctx, root, { organizationId: orgA, key: 'beta' });
    const gamma = await createProject(ctx, root, { organizationId: orgB, key: 'gamma' });

    const member = await createUser(ctx, { username: 'member' });
    await addMember(ctx, orgA, member.id, 'member');
    sessions['member'] = await login(ctx, member.username, member.password);
    const grantOnly = await createUser(ctx, { username: 'grant-only' });
    await grantProject(ctx, alpha.id, grantOnly.id, 'viewer');
    sessions['grant-only'] = await login(ctx, grantOnly.username, grantOnly.password);

    // alpha and gamma: one succeeded analysis each on main, with measures; beta never analysed.
    // Seeded a minute ago: the server reads its own clock, and a database clock ahead of it (a
    // Docker VM drifts by hundreds of milliseconds) would put the analyses in the future. uuidv7
    // never goes back in a process, so the id takes a new timestamp over a fresh one.
    const aMinuteAgo = (): string => {
      const hex = (Date.now() - 60_000).toString(16).padStart(12, '0');
      const id = uuidv7().replaceAll('-', '');
      const back = hex + id.slice(12);
      return [0, 8, 12, 16, 20].map((p, i, a) => back.slice(p, a[i + 1] ?? 32)).join('-');
    };
    for (const [project, ncloc, gateStatus] of [
      [alpha.id, 1_200, 'passed'],
      [gamma.id, 3_000, 'failed'],
    ] as const) {
      const branchId = await mainBranchId(ctx.db, project);
      const [analysis] = await ctx.db
        .insert(analyses)
        .values({
          id: aMinuteAgo(),
          projectId: project,
          branchId,
          status: 'succeeded',
          revision: 'a'.repeat(40),
          baselineStatus: 'ok',
          scannerVersion: '1.0.0',
          analysisDate: new Date(Date.now() - 60_000),
          gateStatus,
        })
        .returning({ id: analyses.id });
      await ctx.db.insert(measures).values(
        Object.entries({
          ncloc,
          coverage: 80,
          duplicated_lines_density: 5,
          security_rating: 2,
          reliability_rating: 1,
          issues: 2,
          high_issues: 1,
          medium_issues: 1,
        }).map(([metricKey, value]) => ({
          analysisId: analysis!.id,
          metricKey,
          scope: 'overall' as const,
          value,
        })),
      );
      const ruleId = await seedRule(ctx.db, {
        key: `semgrep:rule-${ncloc}`,
        name: 'A rule',
        quality: 'security',
        defaultSeverity: 'high',
      });
      await seedIssue(ctx.db, { projectId: project, branchId, ruleId, quality: 'security' });
    }
  }, 120_000);
  afterAll(async () => ctx?.close());

  it('loads portfolio and shows the Portfolio entry in the main menu', async () => {
    expect(ctx.edition!.activeFeatures()).toContain('portfolio');
    const info = (await get(sessions['member']!, '/api/v0/system/info')).json() as {
      features: string[];
      extensions: unknown[];
    };
    expect(info.features).toContain('portfolio');
    expect(info.extensions).toContainEqual(MAIN_NAV);
  });

  it('answers the overview and the project pages of both scopes', async () => {
    const root = sessions['root']!;
    const org = await get(root, `${PORTFOLIO}?scope=organization&organizationId=${orgA}`);
    expect(org.statusCode, org.body).toBe(200);
    const overview = org.json() as Overview;
    expect(overview).toMatchObject({
      scope: { kind: 'organization', organization: { key: 'org-a' } },
      granularity: 'week',
      totals: { projects: 2, analysed: 1, ncloc: 1_200 },
      organizations: null,
    });
    expect(overview.trend).toHaveLength(12);

    const all = (await get(root, `${PORTFOLIO}?scope=all&granularity=month`)).json() as Overview;
    expect(all).toMatchObject({
      scope: { kind: 'all', organization: null },
      granularity: 'month',
      totals: { projects: 3, analysed: 2, ncloc: 4_200 },
    });
    expect(all.organizations?.map((o) => [o.key, o.projects])).toEqual(
      expect.arrayContaining([
        ['org-a', 2],
        ['org-b', 1],
      ]),
    );

    const first = await get(root, `${PORTFOLIO}/projects?scope=all&sort=key&limit=2`);
    expect(first.statusCode, first.body).toBe(200);
    const page = first.json() as { items: Row[]; nextCursor: string | null };
    expect(keysOf(page.items)).toEqual(['org-a/alpha', 'org-a/beta']);
    expect(page.nextCursor).not.toBeNull();
    const rest = (
      await get(root, `${PORTFOLIO}/projects?scope=all&sort=key&limit=2&cursor=${page.nextCursor!}`)
    ).json() as { items: Row[]; nextCursor: string | null };
    expect(keysOf(rest.items)).toEqual(['org-b/gamma']);
    expect(rest.nextCursor).toBeNull();
  });

  it('exports the CSV and the PDF, not cached and named by the scope', async () => {
    const root = sessions['root']!;
    const day = /\d{8}/.source;
    const csv = await get(
      root,
      `${PORTFOLIO}/export?scope=organization&organizationId=${orgA}&format=csv`,
    );
    expect(csv.statusCode, csv.body).toBe(200);
    expect(csv.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(csv.headers['cache-control']).toBe('no-store');
    expect(csv.headers['content-disposition']).toMatch(
      new RegExp(`^attachment; filename="qualor-portfolio-org-a-${day}\\.csv"$`),
    );
    expect(csv.rawPayload.subarray(0, 3).equals(BOM)).toBe(true);
    const lines = csvLines(csv.body);
    expect(lines[0]).toMatch(/^organization_key,organization,project_key,project,/);
    expect(lines.slice(1).map((l) => l.split(',').slice(0, 3).join(','))).toEqual([
      'org-a,org-a team,alpha',
      'org-a,org-a team,beta',
    ]);

    const pdf = await get(root, `${PORTFOLIO}/export?scope=all&format=pdf&granularity=month`);
    expect(pdf.statusCode, pdf.body.slice(0, 200)).toBe(200);
    expect(pdf.headers['content-type']).toBe('application/pdf');
    expect(pdf.headers['cache-control']).toBe('no-store');
    expect(pdf.headers['content-disposition']).toMatch(
      new RegExp(`^attachment; filename="qualor-portfolio-all-${day}\\.pdf"$`),
    );
    // The fonts resolved from the bundle's own location.
    expect(pdf.rawPayload.subarray(0, 5).toString()).toBe('%PDF-');
  });

  it('shows a grant-only user only its granted project', async () => {
    const session = sessions['grant-only']!;
    const all = (await get(session, `${PORTFOLIO}?scope=all`)).json() as Overview;
    expect(all.totals).toMatchObject({ projects: 1, ncloc: 1_200 });
    expect(all.organizations?.map((o) => o.key)).toEqual(['org-a']);
    const org = (
      await get(session, `${PORTFOLIO}?scope=organization&organizationId=${orgA}`)
    ).json() as Overview;
    expect(org.totals.projects).toBe(1);
    // Review Focus 2: the attention lists hold no hidden project. gamma (org-b, failed gate) is
    // in root's failing gates, never in the grant-only user's.
    const rootAll = (await get(sessions['root']!, `${PORTFOLIO}?scope=all`)).json() as Overview;
    expect(keysOf(rootAll.attention['failingGates']!)).toContain('org-b/gamma');
    for (const overview of [all, org]) {
      expect(Object.keys(overview.attention).sort()).toEqual(
        ['abandoned', 'exploited', 'failingGates', 'mostSevere', 'worstSecurity'].sort(),
      );
      for (const [list, rows] of Object.entries(overview.attention)) {
        for (const key of keysOf(rows)) expect(key, list).toBe('org-a/alpha');
      }
      expect(overview.attention['failingGates']).toEqual([]);
    }
    const page = (await get(session, `${PORTFOLIO}/projects?scope=all`)).json() as {
      items: Row[];
    };
    expect(keysOf(page.items)).toEqual(['org-a/alpha']);
    const csv = await get(session, `${PORTFOLIO}/export?scope=all&format=csv`);
    expect(csv.statusCode).toBe(200);
    expect(csvLines(csv.body)).toHaveLength(2);
    // The organisation scope of org A: beta is hidden, alpha alone.
    const orgCsv = await get(
      session,
      `${PORTFOLIO}/export?scope=organization&organizationId=${orgA}&format=csv`,
    );
    expect(orgCsv.statusCode).toBe(200);
    expect(orgCsv.headers['content-disposition']).toMatch(/filename="qualor-portfolio-org-a-/);
    const orgLines = csvLines(orgCsv.body);
    expect(orgLines).toHaveLength(2);
    expect(orgLines[1]).toMatch(/^org-a,org-a team,alpha,/);
    // Another organisation is not visible: a problem, never a header and a broken stream.
    for (const format of ['csv', 'pdf']) {
      const hidden = await get(
        session,
        `${PORTFOLIO}/export?scope=organization&organizationId=${orgB}&format=${format}`,
      );
      expect(hidden.statusCode, format).toBe(404);
      expect(hidden.headers['content-disposition']).toBeUndefined();
    }
    expect(
      (await get(session, `${PORTFOLIO}?scope=organization&organizationId=${orgB}`)).statusCode,
    ).toBe(404);
  });

  it('answers 422 for malformed input, never a database error', async () => {
    const root = sessions['root']!;
    for (const url of [
      `${PORTFOLIO}?scope=organization`,
      `${PORTFOLIO}?scope=all&organizationId=${orgA}`,
      `${PORTFOLIO}?scope=organization&organizationId=not-a-uuid`,
      `${PORTFOLIO}?scope=all&granularity=day`,
      `${PORTFOLIO}/projects?scope=all&limit=101`,
      `${PORTFOLIO}/projects?scope=all&sort=name`,
      `${PORTFOLIO}/projects?scope=all&cursor=nope`,
      `${PORTFOLIO}/export?scope=all&format=xlsx`,
    ]) {
      const res = await get(root, url);
      expect(res.statusCode, url).toBe(422);
      expect(res.json()).toMatchObject({ code: 'VALIDATION_FAILED' });
    }
  });
});

describe('Qualor Enterprise under a Business key: no portfolio (4E-2 §3)', () => {
  let ctx: TestContext;
  let admin: Session;

  beforeAll(async () => {
    ctx = await bootEnterpriseTest(testSigner(), () => LICENSED, BUSINESS_FEATURES);
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
  }, 60_000);
  afterAll(async () => ctx?.close());

  it('answers 403 FEATURE_NOT_LICENSED on every route and shows no main-menu entry', async () => {
    const organizationId = await organizationIdOf(ctx, 'default');
    for (const url of [
      `${PORTFOLIO}?scope=all`,
      `${PORTFOLIO}?scope=organization&organizationId=${organizationId}`,
      `${PORTFOLIO}/projects?scope=all`,
      `${PORTFOLIO}/export?scope=all&format=csv`,
      `${PORTFOLIO}/export?scope=all&format=pdf`,
    ]) {
      const res = await ctx.app.inject({ method: 'GET', url, headers: admin.headers });
      expect(res.statusCode, url).toBe(403);
      expect(res.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED' });
    }
    const info = (
      await ctx.app.inject({ method: 'GET', url: '/api/v0/system/info', headers: admin.headers })
    ).json() as { features: string[]; extensions: { point: string }[] };
    expect(info.features).not.toContain('portfolio');
    expect(info.extensions.filter((e) => e.point === 'main.nav')).toEqual([]);
  });
});
