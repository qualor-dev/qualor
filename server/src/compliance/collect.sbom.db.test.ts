import { createHash } from 'node:crypto';
import { sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { validateAgainst } from '../../test/export-schemas';
import {
  ADMIN_PASSWORD,
  createProject,
  createTestContext,
  login,
  type TestContext,
} from '../../test/app';
import { mainBranchId } from '../../test/issues';
import {
  analyses,
  branchDependencies,
  branches,
  complianceReports,
  projectVersions,
  versionDependencies,
} from '../db/schema';
import { collectCompliance } from './collect';

describe('collectCompliance: the attached SBOM (0.15 plan 5, V13)', () => {
  let ctx: TestContext;
  let org: string;
  let project: { id: string; key: string };
  let main: string;
  let bare: string;
  let version: string;

  const newReport = async (values: Partial<typeof complianceReports.$inferInsert>) => {
    await ctx.db.execute(
      sql`UPDATE compliance_reports SET status = 'failed', error = 'x' WHERE status = 'pending'`,
    );
    const [r] = await ctx.db
      .insert(complianceReports)
      .values({
        organizationId: org,
        scope: 'project',
        projectId: project.id,
        branchId: main,
        createdByName: 'A',
        standards: [],
        ...values,
      })
      .returning({ id: complianceReports.id });
    return r!.id;
  };

  beforeAll(async () => {
    ctx = await createTestContext();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/organizations',
      headers: admin.headers,
      payload: { key: 'acme', name: 'Acme' },
    });
    org = (res.json() as { id: string }).id;
    project = await createProject(ctx, admin, { organizationId: org, key: 'alpha' });
    main = await mainBranchId(ctx.db, project.id);
    const [b] = await ctx.db
      .insert(branches)
      .values({ projectId: project.id, kind: 'branch', name: 'bare' })
      .returning({ id: branches.id });
    bare = b!.id;
    const [a] = await ctx.db
      .insert(analyses)
      .values({
        projectId: project.id,
        branchId: main,
        status: 'succeeded',
        revision: 'b'.repeat(40),
        baselineStatus: 'ok',
        scannerVersion: '1.0.0',
        analysisDate: new Date('2026-10-01T00:00:00Z'),
      })
      .returning({ id: analyses.id });
    const [v] = await ctx.db
      .insert(projectVersions)
      .values({
        projectId: project.id,
        label: '2.0.0',
        source: 'tag',
        tag: 'v2.0.0',
        analysisId: a!.id,
        analyzedAt: new Date(),
        hasInventory: true,
      })
      .returning({ id: projectVersions.id });
    version = v!.id;
    const row = (name: string, v: string) => ({
      path: 'package.json',
      ecosystem: 'npm',
      name,
      version: v,
      licenses: ['MIT'],
    });
    await ctx.db.insert(branchDependencies).values(
      [row('lodash', '4.17.21'), row('left-pad', '1.3.0')].map((r) => ({
        ...r,
        branchId: main,
        analysisId: a!.id,
      })),
    );
    await ctx.db
      .insert(versionDependencies)
      .values([{ ...row('lodash', '4.17.20'), versionId: version, analysisId: a!.id }]);
  });
  afterAll(() => ctx.close());

  it('builds a valid CycloneDX SBOM of the branch, with the report id as serial', async () => {
    const id = await newReport({});
    const s = await collectCompliance(ctx.db, id, { limit: 100, sbom: true });
    expect(s.sbom).not.toBeNull();
    const doc = JSON.parse(s.sbom!.json) as {
      bomFormat: string;
      specVersion: string;
      serialNumber: string;
      metadata: { timestamp: string };
      components: unknown[];
    };
    expect(doc.bomFormat).toBe('CycloneDX');
    expect(doc.specVersion).toBe('1.6');
    expect(doc.serialNumber).toBe(`urn:uuid:${id}`);
    expect(doc.metadata.timestamp).toBe(s.generatedAt);
    expect(s.sbom!.components).toBe(2);
    expect(doc.components).toHaveLength(2);
    expect(validateAgainst('cyclonedx', doc)).toEqual([]);
    expect(s.sbom!.sha256).toBe(createHash('sha256').update(s.sbom!.json, 'utf8').digest('hex'));
  });

  it('builds one for a version too', async () => {
    const s = await collectCompliance(
      ctx.db,
      await newReport({ branchId: null, versionId: version }),
      {
        limit: 100,
        sbom: true,
      },
    );
    expect(s.sbom?.components).toBe(1);
    expect(JSON.parse(s.sbom!.json).components[0].version).toBe('4.17.20');
  });

  it('has none without the sbom feature, for an organisation report, or without an inventory', async () => {
    expect((await collectCompliance(ctx.db, await newReport({}), { limit: 100 })).sbom).toBeNull();
    expect(
      (await collectCompliance(ctx.db, await newReport({}), { limit: 100, sbom: false })).sbom,
    ).toBeNull();
    const orgReport = await newReport({ scope: 'organization', projectId: null, branchId: null });
    expect(
      (await collectCompliance(ctx.db, orgReport, { limit: 100, sbom: true })).sbom,
    ).toBeNull();
    const none = await newReport({ branchId: bare });
    expect((await collectCompliance(ctx.db, none, { limit: 100, sbom: true })).sbom).toBeNull();
  });
});
