// SPDX-License-Identifier: LicenseRef-Qualor-Enterprise
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  addMember,
  bearer,
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
import { AFTER_GRACE, grantProject, LICENSE_EXPIRES } from '../../server/test/rbac';
import { createAuditRecorder } from '../../server/src/audit/recorder';
import {
  analyses,
  auditEvents,
  complianceReports,
  projectVersions,
} from '../../server/src/db/schema';
import { seedCheck, seedTargetRow } from '../../server/test/vulnerabilities';
import { createEdition, type Edition } from '../../server/src/license/edition';
import { licenseState } from '../../server/src/license/state';
import { verifyLicenseKey } from '../../server/src/license/verify';
import { loadPlugins } from '../../server/src/plugins/loader';
import { dropPluginsThatFailToMount, pluginJobHandlers } from '../../server/src/plugins/mount';
import { ensurePluginScheduled } from '../../server/src/plugins/schedule';
import { createPluginServices } from '../../server/src/plugins/services';
import { runUntilIdle } from '../../server/src/queue/worker';
import { buildEnterprise } from '../scripts/bundle';

// Under enterprise/, so the bundle resolves its external zod and pdfkit from enterprise/node_modules,
// and finds the fonts in enterprise/fonts, as the image's /app/enterprise/plugin.js does.
const OUT = fileURLToPath(new URL('../.tmp/compliance-test/plugin.js', import.meta.url));
const LICENSED = new Date('2027-01-01T00:00:00Z');
const REPORTS = '/api/v0/ee/compliance/reports';
const HOUSEKEEPING = 'ee.compliance.housekeeping';
const BOM = Buffer.from([0xef, 0xbb, 0xbf]);

function quietLogger(): never {
  const l = { debug() {}, info() {}, warn() {}, error() {}, child: () => l };
  return l as never;
}

/**
 * The built plugin through the real loader (as rbac-audit.db.test.ts boots it), under a key the
 * edition trusts, with the services and the one recorder bound to the edition as bootEnterprise
 * binds them. Everything runs on `clock`.
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

type View = {
  id: string;
  status: 'pending' | 'ready' | 'failed';
  sha256: string | null;
  error: string | null;
  canDelete: boolean;
  summary: { findings: { total: number }; dependencies: { open: number } } | null;
  branch: unknown;
  version: unknown;
};
type Report = {
  id: string;
  scope: { branch: unknown; version: unknown };
  projects: { key: string; analysis: unknown }[];
  findings: unknown[];
  triage: unknown[];
};

beforeAll(async () => {
  await buildEnterprise({ outfile: OUT });
}, 60_000);

describe('Qualor Enterprise: compliance exports through the built plugin (4E-1 §2.4, §2.5, §3)', () => {
  let now = LICENSED;
  const signer = testSigner();
  let ctx: TestContext;
  const sessions: Record<string, Session> = {};
  let orgA: string;
  let orgB: string;
  let alpha: { id: string; key: string };
  /** Ready reports that stay: what the read columns of the role matrix read. */
  let orgReport: string;
  let projectReport: string;

  const call = (
    session: Session | Record<string, string>,
    method: 'GET' | 'POST' | 'DELETE',
    url: string,
    payload?: object,
  ) =>
    ctx.app.inject({
      method,
      url,
      headers: 'headers' in session ? (session as Session).headers : session,
      ...(payload === undefined ? {} : { payload }),
    });
  const handlers = () =>
    pluginJobHandlers(ctx.plugins!, ctx.edition!, quietLogger(), { db: ctx.db });
  const runJobs = () => runUntilIdle(ctx.db, handlers(), quietLogger());
  const create = (session: Session, body: object) => call(session, 'POST', REPORTS, body);
  const read = async (session: Session, id: string) =>
    (await call(session, 'GET', `${REPORTS}/${id}`)).json() as View;
  /** Creates a report as `session` and builds it: the ready view. */
  const ready = async (session: Session, body: object): Promise<View> => {
    const res = await create(session, body);
    expect(res.statusCode, res.body).toBe(202);
    await runJobs();
    const view = await read(session, (res.json() as View).id);
    expect(view.status, view.error ?? '').toBe('ready');
    return view;
  };
  const download = (session: Session, id: string, format: string) =>
    call(session, 'GET', `${REPORTS}/${id}/download?format=${format}`);
  const auditOf = (action: string, targetId: string) =>
    ctx.db
      .select({ details: auditEvents.details })
      .from(auditEvents)
      .where(and(eq(auditEvents.action, action), eq(auditEvents.targetId, targetId)))
      .orderBy(auditEvents.seq);
  const newOrg = async (key: string): Promise<string> => {
    const res = await call(sessions['root']!, 'POST', '/api/v0/organizations', { key, name: key });
    expect(res.statusCode, res.body).toBe(201);
    return (res.json() as { id: string }).id;
  };

  beforeAll(async () => {
    ctx = await bootEnterpriseTest(signer, () => now);
    sessions['root'] = await login(ctx, 'admin', ADMIN_PASSWORD);
    orgA = await newOrg('org-a');
    orgB = await newOrg('org-b');
    alpha = await createProject(ctx, sessions['root']!, { organizationId: orgA, key: 'alpha' });
    await createProject(ctx, sessions['root']!, { organizationId: orgB, key: 'beta' });
    const user = async (
      name: string,
      org: string | null,
      role?: 'admin' | 'project_admin' | 'member' | 'viewer',
    ) => {
      const u = await createUser(ctx, { username: name });
      if (org && role) await addMember(ctx, org, u.id, role);
      sessions[name] = await login(ctx, u.username, u.password);
      return u.id;
    };
    await user('org-admin', orgA, 'admin');
    await user('project-admin', orgA, 'project_admin');
    await user('member', orgA, 'member');
    await user('viewer', orgA, 'viewer');
    await grantProject(ctx, alpha.id, await user('grant-only', null), 'viewer');
    await user('other-admin', orgB, 'admin');

    // alpha's main branch: one succeeded analysis, two open security findings and a triaged one.
    const branchId = await mainBranchId(ctx.db, alpha.id);
    await ctx.db.insert(analyses).values({
      projectId: alpha.id,
      branchId,
      status: 'succeeded',
      revision: 'a'.repeat(40),
      baselineStatus: 'ok',
      scannerVersion: '1.0.0',
      analysisDate: new Date('2026-10-01T00:00:00Z'),
    });
    const ruleId = await seedRule(ctx.db, {
      key: 'semgrep:sqli',
      name: 'SQL injection',
      quality: 'security',
      defaultSeverity: 'high',
      cwe: [89],
    });
    const issue = { projectId: alpha.id, branchId, ruleId, quality: 'security' } as const;
    await seedIssue(ctx.db, { ...issue, severity: 'high', path: 'src/a.ts', startLine: 3 });
    await seedIssue(ctx.db, { ...issue, severity: 'medium', path: 'src/b.ts', startLine: 9 });
    await seedIssue(ctx.db, { ...issue, severity: 'high', status: 'false_positive' });
    await seedIssue(ctx.db, { ...issue, severity: 'high', status: 'resolved' });

    orgReport = (await ready(sessions['root']!, { organizationId: orgA })).id;
    projectReport = (await ready(sessions['root']!, { projectId: alpha.id })).id;
  }, 120_000);
  afterAll(async () => ctx?.close());

  it('loads compliance-export with its two jobs, the hourly housekeeping and both UI entries', async () => {
    expect(ctx.edition!.activeFeatures()).toContain('compliance-export');
    expect(ctx.plugins!.jobs.map((j) => j.queue)).toEqual(
      expect.arrayContaining(['ee.compliance.build', HOUSEKEEPING]),
    );
    expect(ctx.plugins!.schedules).toContainEqual({
      plugin: 'qualor-enterprise',
      feature: 'compliance-export',
      queue: HOUSEKEEPING,
      everySeconds: 3_600,
    });
    const info = (await call(sessions['member']!, 'GET', '/api/v0/system/info')).json() as {
      extensions: unknown[];
    };
    expect(info.extensions).toEqual(
      expect.arrayContaining([
        { point: 'project.tab', id: 'compliance', label: 'Compliance', path: 'compliance' },
        {
          point: 'settings.nav',
          id: 'compliance',
          label: 'Compliance reports',
          path: '/settings/ee/compliance',
        },
      ]),
    );
  });

  it('builds a project report end to end, and downloads it as JSON, CSV and PDF, each recorded', async () => {
    const admin = sessions['org-admin']!;
    const res = await create(admin, { projectId: alpha.id });
    expect(res.statusCode, res.body).toBe(202);
    const pending = res.json() as View;
    expect(pending).toMatchObject({ status: 'pending', canDelete: true });
    // §2.4: one build at a time across workers, one attempt.
    const [job] = (
      await ctx.db.execute<{ concurrency_key: string; max_attempts: number }>(
        sql`SELECT concurrency_key, max_attempts FROM jobs
             WHERE queue = 'ee.compliance.build' AND payload->>'reportId' = ${pending.id}`,
      )
    ).rows;
    expect(job).toEqual({ concurrency_key: 'ee.compliance.build', max_attempts: 1 });
    // Pending: a second one for the scope, a download and a deletion are refused.
    expect((await create(admin, { projectId: alpha.id })).json()).toMatchObject({
      code: 'REPORT_PENDING',
    });
    expect((await download(admin, pending.id, 'json')).json()).toMatchObject({
      code: 'REPORT_NOT_READY',
    });
    expect((await call(admin, 'DELETE', `${REPORTS}/${pending.id}`)).statusCode).toBe(409);

    await runJobs();
    const view = await read(admin, pending.id);
    expect(view).toMatchObject({ status: 'ready', error: null });
    expect(view.summary?.findings.total).toBe(2);
    const listed = (
      await call(admin, 'GET', `${REPORTS}?projectId=${alpha.id}&limit=1`)
    ).json() as {
      items: View[];
      nextCursor: string | null;
    };
    expect(listed.items.map((v) => v.id)).toEqual([view.id]);
    expect(listed.nextCursor).toBe(view.id);

    const name = (ext: string) =>
      new RegExp(
        `^attachment; filename="qualor-compliance-alpha-\\d{8}-${view.id.slice(0, 8)}\\.${ext}"$`,
      );
    const json = await download(admin, view.id, 'json');
    expect(json.statusCode).toBe(200);
    expect(json.headers['content-type']).toBe('application/json; charset=utf-8');
    expect(json.headers['cache-control']).toBe('no-store');
    expect(json.headers['content-disposition']).toMatch(name('json'));
    expect(createHash('sha256').update(json.rawPayload).digest('hex')).toBe(view.sha256);
    expect((await download(admin, view.id, 'json')).rawPayload.equals(json.rawPayload)).toBe(true);
    const report = JSON.parse(json.body) as Report;
    expect(report.findings).toHaveLength(2);
    expect(report.triage).toHaveLength(1);

    const csv = await download(admin, view.id, 'csv');
    expect(csv.statusCode).toBe(200);
    expect(csv.headers['content-type']).toBe('text/csv; charset=utf-8');
    expect(csv.headers['content-disposition']).toMatch(name('csv'));
    expect(csv.rawPayload.subarray(0, 3).equals(BOM)).toBe(true);
    const lines = csv.body.replace(/^\uFEFF/, '').split('\r\n');
    expect(lines.pop()).toBe('');
    expect(lines[0]).toMatch(/^section,project,path,line,rule,rule_name,engine,severity,/);
    expect(lines).toHaveLength(report.findings.length + report.triage.length + 1);

    const pdf = await download(admin, view.id, 'pdf');
    expect(pdf.statusCode, pdf.body.slice(0, 200)).toBe(200);
    expect(pdf.headers['content-type']).toBe('application/pdf');
    expect(pdf.headers['content-disposition']).toMatch(name('pdf'));
    // The fonts resolved from the bundle's own location, and the bytes are stable.
    expect(pdf.rawPayload.subarray(0, 5).toString()).toBe('%PDF-');
    expect((await download(admin, view.id, 'pdf')).rawPayload.equals(pdf.rawPayload)).toBe(true);

    // §2.4 step 6, recorded through core's service (the coverage test exempts these actions).
    expect(await auditOf('compliance.report.created', view.id)).toEqual([
      { details: { scope: 'project', branch: 'main' } },
    ]);
    expect((await auditOf('compliance.report.downloaded', view.id)).map((e) => e.details)).toEqual(
      ['json', 'json', 'csv', 'pdf', 'pdf'].map((format) => ({ format, sha256: view.sha256 })),
    );
    expect((await call(admin, 'DELETE', `${REPORTS}/${view.id}`)).statusCode).toBe(204);
    expect(await auditOf('compliance.report.deleted', view.id)).toEqual([
      { details: { scope: 'project' } },
    ]);
    expect((await call(admin, 'GET', `${REPORTS}/${view.id}`)).statusCode).toBe(404);
  });

  it('answers 422 for malformed input, never a database error', async () => {
    const admin = sessions['org-admin']!;
    for (const body of [
      { organizationId: orgA, projectId: alpha.id },
      { organizationId: 'not-a-uuid' },
      { projectId: alpha.id, branchId: 'main' },
      { projectId: alpha.id, versionId: 'v1' },
      {
        projectId: alpha.id,
        branchId: '2c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f',
        versionId: '3c3d4e5f-6a7b-4c8d-9e0f-1a2b3c4d5e6f',
      },
    ]) {
      const res = await create(admin, body);
      expect(res.statusCode, JSON.stringify(body)).toBe(422);
      expect(res.json()).toMatchObject({ code: 'VALIDATION_FAILED' });
    }
    for (const url of [
      `${REPORTS}/not-a-uuid`,
      `${REPORTS}/not-a-uuid/download?format=json`,
      `${REPORTS}?organizationId=not-a-uuid`,
      `${REPORTS}?organizationId=${orgA}&cursor=nope`,
      `${REPORTS}?organizationId=${orgA}&projectId=${alpha.id}`,
      `${REPORTS}?organizationId=${orgA}&limit=101`,
      `${REPORTS}/${orgReport}/download?format=xlsx`,
    ]) {
      expect((await call(admin, 'GET', url)).statusCode, url).toBe(422);
    }
  });

  // 4E-1 §3: org create / read / delete, then project create / read. A report the caller cannot
  // read is a 404, never a 403.
  it.each([
    ['root', [202, 200, 204], [202, 200]],
    ['org-admin', [202, 200, 204], [202, 200]],
    ['project-admin', [403, 200, 403], [202, 200]],
    ['member', [403, 200, 403], [403, 200]],
    ['viewer', [403, 200, 403], [403, 200]],
    ['grant-only', [403, 404, 404], [403, 200]],
    ['other-admin', [404, 404, 404], [404, 404]],
  ] as const)('the role matrix: %s', async (caller, orgCodes, projectCodes) => {
    const session = sessions[caller]!;
    const orgCreate = await create(session, { organizationId: orgA });
    expect(orgCreate.statusCode, orgCreate.body).toBe(orgCodes[0]);
    if (orgCreate.statusCode === 202) await runJobs();
    expect((await call(session, 'GET', `${REPORTS}/${orgReport}`)).statusCode).toBe(orgCodes[1]);
    // The caller's own new report when it could create one, the kept one otherwise.
    const target = orgCreate.statusCode === 202 ? (orgCreate.json() as View).id : orgReport;
    expect((await call(session, 'DELETE', `${REPORTS}/${target}`)).statusCode).toBe(orgCodes[2]);

    const projectCreate = await create(session, { projectId: alpha.id });
    expect(projectCreate.statusCode, projectCreate.body).toBe(projectCodes[0]);
    if (projectCreate.statusCode === 202) await runJobs();
    expect((await call(session, 'GET', `${REPORTS}/${projectReport}`)).statusCode).toBe(
      projectCodes[1],
    );
    expect((await read(sessions['root']!, orgReport)).status).toBe('ready');
  });

  it('refuses a personal token with only the read scope (403 INSUFFICIENT_SCOPE)', async () => {
    const res = await call(sessions['org-admin']!, 'POST', '/api/v0/tokens', {
      name: 'read only',
      scopes: ['read'],
      expiresInDays: 30,
    });
    expect(res.statusCode, res.body).toBe(201);
    const token = bearer((res.json() as { token: string }).token);
    const refused = await call(token, 'POST', REPORTS, { organizationId: orgA });
    expect(refused.statusCode).toBe(403);
    expect(refused.json()).toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
    expect((await call(token, 'GET', `${REPORTS}/${orgReport}`)).statusCode).toBe(200);
  });

  it('builds the report of a version end to end, with its dependencies only', async () => {
    const root = sessions['root']!;
    const [version] = await ctx.db
      .insert(projectVersions)
      .values({ projectId: alpha.id, label: '3.1.0', source: 'label', analyzedAt: new Date() })
      .returning({ id: projectVersions.id });
    const versionId = version!.id;
    const unchecked = await create(root, { projectId: alpha.id, versionId });
    expect(unchecked.statusCode).toBe(409);
    expect(unchecked.json()).toMatchObject({ code: 'NOT_CHECKED' });
    await seedCheck(ctx.db, { projectId: alpha.id, versionId, baselineAt: new Date() });
    await seedTargetRow(ctx.db, {
      projectId: alpha.id,
      versionId,
      packageName: 'lodash',
      packageVersion: '4.17.20',
      vulnerabilityId: 'CVE-2026-0101',
      severity: 'critical',
      title: 'Prototype pollution',
      fixedVersion: '4.17.21',
    });
    const view = await ready(root, { projectId: alpha.id, versionId });
    expect(view).toMatchObject({ branch: null, version: { id: versionId, label: '3.1.0' } });
    expect(view.summary?.findings.total).toBe(1);
    expect(view.summary?.dependencies.open).toBe(1);
    const report = JSON.parse((await download(root, view.id, 'json')).body) as Report;
    expect(report.scope).toMatchObject({
      branch: null,
      version: { id: versionId, label: '3.1.0' },
    });
    expect(report.findings).toEqual([
      expect.objectContaining({
        section: 'dependency',
        path: null,
        severity: 'blocker',
        message: 'lodash 4.17.20: Prototype pollution',
        vulnerability: expect.objectContaining({ fixedVersions: ['4.17.21'] }),
      }),
    ]);
    expect((await download(root, view.id, 'csv')).statusCode).toBe(200);
    expect((await download(root, view.id, 'pdf')).statusCode).toBe(200);
    expect(await auditOf('compliance.report.created', view.id)).toEqual([
      { details: { scope: 'project', branch: null, version: { id: versionId, label: '3.1.0' } } },
    ]);
  });

  it('builds an organisation without projects, and lists a never-analysed project (Review Focus 1)', async () => {
    const root = sessions['root']!;
    const empty = await ready(root, { organizationId: await newOrg('org-empty') });
    expect(empty.summary?.findings.total).toBe(0);
    for (const format of ['json', 'csv', 'pdf']) {
      expect((await download(root, empty.id, format)).statusCode, format).toBe(200);
    }
    const fresh = await newOrg('org-fresh');
    await createProject(ctx, root, { organizationId: fresh, key: 'fresh' });
    const view = await ready(root, { organizationId: fresh });
    const report = JSON.parse((await download(root, view.id, 'json')).body) as Report;
    expect(report.projects).toEqual([expect.objectContaining({ key: 'fresh', analysis: null })]);
    expect(view.summary?.findings.total).toBe(0);
  });

  it('skips the build while the licence has lapsed; the housekeeping fails the stale row later (Review Focus 5)', async () => {
    const root = sessions['root']!;
    const org = await newOrg('org-lapse');
    const res = await create(root, { organizationId: org });
    expect(res.statusCode).toBe(202);
    const id = (res.json() as View).id;
    const statusOf = async () =>
      (
        await ctx.db
          .select({ status: complianceReports.status, error: complianceReports.error })
          .from(complianceReports)
          .where(eq(complianceReports.id, id))
      )[0];
    try {
      now = AFTER_GRACE;
      expect(await runJobs()).toBeGreaterThan(0); // claimed, skipped, completed
      expect(await statusOf()).toEqual({ status: 'pending', error: null });
      expect((await create(root, { organizationId: org })).json()).toMatchObject({
        code: 'FEATURE_NOT_LICENSED',
      });
    } finally {
      now = LICENSED;
    }
    await ctx.db
      .update(complianceReports)
      .set({ createdAt: sql`now() - interval '2 hours'` })
      .where(eq(complianceReports.id, id));
    await ensurePluginScheduled(ctx.db, HOUSEKEEPING, 0);
    await runJobs();
    expect(await statusOf()).toEqual({ status: 'failed', error: 'the build did not finish' });
    expect((await create(root, { organizationId: org })).statusCode).toBe(202);
    await runJobs();
  });
});

describe('Qualor Enterprise under a Business key: no compliance exports (4E-1 §3)', () => {
  let ctx: TestContext;
  let admin: Session;

  beforeAll(async () => {
    ctx = await bootEnterpriseTest(testSigner(), () => LICENSED, BUSINESS_FEATURES);
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
  }, 60_000);
  afterAll(async () => ctx?.close());

  it('answers 403 FEATURE_NOT_LICENSED on every route and shows no compliance entry', async () => {
    const id = '0b6f1c1e-5d3a-4a8e-9f2b-7c1d2e3f4a5b';
    const organizationId = await organizationIdOf(ctx, 'default');
    for (const [method, url, payload] of [
      ['POST', REPORTS, { organizationId }],
      ['GET', `${REPORTS}?organizationId=${organizationId}`],
      ['GET', `${REPORTS}/${id}`],
      ['GET', `${REPORTS}/${id}/download?format=json`],
      ['DELETE', `${REPORTS}/${id}`],
    ] as const) {
      const res = await ctx.app.inject({
        method,
        url,
        headers: admin.headers,
        ...(payload === undefined ? {} : { payload }),
      });
      expect(res.statusCode, `${method} ${url}`).toBe(403);
      expect(res.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED' });
    }
    const info = (
      await ctx.app.inject({ method: 'GET', url: '/api/v0/system/info', headers: admin.headers })
    ).json() as { features: string[]; extensions: { id: string }[] };
    expect(info.features).not.toContain('compliance-export');
    expect(info.extensions.map((e) => e.id)).not.toContain('compliance');
  });
});
