import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createProject,
  login,
  type Session,
  type TestContext,
} from '../../test/app';
import { rbacContext } from '../../test/rbac';
import { seedCheck } from '../../test/vulnerabilities';
import { auditEvents, projectVersions, projectVulnerabilitySettings } from '../db/schema';
import type { ComplianceReportView, QualorPlugin } from '../plugins/contract';

const STANDARDS = [{ id: 'cwe-top25-2025', version: '2025', sourceSha256: 'a'.repeat(64) }];

const FIXTURE: QualorPlugin = {
  name: 'compliance-fixture',
  apiVersion: 1,
  features: ['compliance-export', 'audit-log'],
  register(ctx) {
    ctx.routes('compliance-export', async (app) => {
      app.post('/t/reports', async (req, reply) =>
        reply.code(202).send(await ctx.compliance.create(req, req.body as never, STANDARDS)),
      );
    });
  },
};

describe('ctx.compliance.create for a version (0.15 plan 5, V12)', () => {
  let ctx: TestContext;
  let root: Session;
  let org: string;
  let app: { id: string; key: string };
  let versionId: string;
  let foreignVersion: string;

  const post = (payload: object) =>
    ctx.app.inject({
      method: 'POST',
      url: '/api/v0/ee/t/reports',
      headers: root.headers,
      payload,
    });
  const addVersion = async (projectId: string, label: string) => {
    const [v] = await ctx.db
      .insert(projectVersions)
      .values({ projectId, label, source: 'label', analyzedAt: new Date() })
      .returning({ id: projectVersions.id });
    return v!.id;
  };

  beforeAll(async () => {
    ctx = await rbacContext({
      now: () => new Date('2027-01-01T00:00:00Z'),
      features: ['compliance-export', 'audit-log'],
      plugin: FIXTURE,
    });
    root = await login(ctx, 'admin', ADMIN_PASSWORD);
    const newOrg = async (key: string) => {
      const res = await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/organizations',
        headers: root.headers,
        payload: { key, name: key },
      });
      return (res.json() as { id: string }).id;
    };
    org = await newOrg('org-a');
    app = await createProject(ctx, root, { organizationId: org, key: 'app' });
    const other = await createProject(ctx, root, { organizationId: org, key: 'other' });
    versionId = await addVersion(app.id, '1.0.0');
    foreignVersion = await addVersion(other.id, '9.9.9');
  });
  afterAll(() => ctx.close());

  it('refuses a version of another project with 404', async () => {
    const res = await post({ projectId: app.id, versionId: foreignVersion });
    expect(res.statusCode).toBe(404);
    expect(res.json()).toMatchObject({ code: 'NOT_FOUND', title: 'Version not found' });
  });

  it('refuses a project whose monitoring is off with 409 MONITORING_OFF', async () => {
    await ctx.db.insert(projectVulnerabilitySettings).values({ projectId: app.id, enabled: false });
    const res = await post({ projectId: app.id, versionId });
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({ code: 'MONITORING_OFF' });
    await ctx.db
      .delete(projectVulnerabilitySettings)
      .where(eq(projectVulnerabilitySettings.projectId, app.id));
  });

  it('refuses a version that was never checked with 409 NOT_CHECKED', async () => {
    const res = await post({ projectId: app.id, versionId });
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({ code: 'NOT_CHECKED' });
  });

  it('creates the report of a checked version, once while it is pending', async () => {
    await seedCheck(ctx.db, { projectId: app.id, versionId, baselineAt: new Date() });
    const res = await post({ projectId: app.id, versionId });
    expect(res.statusCode, res.body).toBe(202);
    const view = res.json() as ComplianceReportView;
    expect(view).toMatchObject({
      scope: 'project',
      status: 'pending',
      project: { id: app.id, key: 'app' },
      branch: null,
      version: { id: versionId, label: '1.0.0' },
    });
    const [event] = await ctx.db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.targetId, view.id));
    expect(event?.details).toEqual({
      scope: 'project',
      branch: null,
      version: { id: versionId, label: '1.0.0' },
    });
    const again = await post({ projectId: app.id, versionId });
    expect(again.statusCode).toBe(409);
    expect(again.json()).toMatchObject({ code: 'REPORT_PENDING' });
  });
});
