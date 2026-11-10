import { createHash } from 'node:crypto';
import { gunzipSync } from 'node:zlib';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createProject,
  login,
  type Session,
  type TestContext,
} from '../../test/app';
import { mainBranchId } from '../../test/issues';
import { rbacContext } from '../../test/rbac';
import { analyses, auditEvents, branchDependencies, complianceReports } from '../db/schema';
import type { PluginCompliance, QualorPlugin } from '../plugins/contract';

const STANDARDS = [{ id: 'cwe-top25-2025', version: '2025', sourceSha256: 'a'.repeat(64) }];
const CANONICAL = '{"a":1}';
const SHA = createHash('sha256').update(CANONICAL).digest('hex');
const SBOM = '{"bomFormat":"CycloneDX"}';
const SBOM_SHA = createHash('sha256').update(SBOM).digest('hex');

let compliance: PluginCompliance;

const FIXTURE: QualorPlugin = {
  name: 'compliance-fixture',
  apiVersion: 1,
  features: ['compliance-export', 'audit-log', 'sbom'],
  register(ctx) {
    compliance = ctx.compliance;
    ctx.routes('compliance-export', async (app) => {
      app.post('/t/reports', async (req, reply) =>
        reply.code(202).send(await ctx.compliance.create(req, req.body as never, STANDARDS)),
      );
      app.get('/t/reports/:id', async (req) =>
        ctx.compliance.get(req, (req.params as { id: string }).id),
      );
      app.get('/t/reports/:id/sbom', async (req) => {
        const r = await ctx.compliance.downloadSbom(req, (req.params as { id: string }).id);
        return { sha256: r.sha256, text: r.sbom.toString('utf8') };
      });
    });
  },
};

describe('ctx.compliance and the attached SBOM (0.15 plan 5, V13)', () => {
  let ctx: TestContext;
  let root: Session;
  let app: { id: string; key: string };

  const newReport = async () => {
    await ctx.db
      .update(complianceReports)
      .set({ status: 'failed', error: 'x' })
      .where(eq(complianceReports.status, 'pending'));
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/ee/t/reports',
      headers: root.headers,
      payload: { projectId: app.id },
    });
    return (res.json() as { id: string }).id;
  };
  const get = (url: string) =>
    ctx.app.inject({ method: 'GET', url: `/api/v0/ee/t/reports/${url}`, headers: root.headers });

  beforeAll(async () => {
    ctx = await rbacContext({
      now: () => new Date('2027-01-01T00:00:00Z'),
      features: ['compliance-export', 'audit-log', 'sbom'],
      plugin: FIXTURE,
    });
    root = await login(ctx, 'admin', ADMIN_PASSWORD);
    const res = await ctx.app.inject({
      method: 'POST',
      url: '/api/v0/organizations',
      headers: root.headers,
      payload: { key: 'org-a', name: 'org-a' },
    });
    app = await createProject(ctx, root, {
      organizationId: (res.json() as { id: string }).id,
      key: 'app',
    });
    const main = await mainBranchId(ctx.db, app.id);
    const [a] = await ctx.db
      .insert(analyses)
      .values({
        projectId: app.id,
        branchId: main,
        status: 'succeeded',
        revision: 'a'.repeat(40),
        baselineStatus: 'ok',
        scannerVersion: '1.0.0',
        analysisDate: new Date('2026-10-01T00:00:00Z'),
      })
      .returning({ id: analyses.id });
    await ctx.db.insert(branchDependencies).values({
      branchId: main,
      path: 'package.json',
      ecosystem: 'npm',
      name: 'lodash',
      version: '4.17.21',
      licenses: ['MIT'],
      analysisId: a!.id,
    });
  });
  afterAll(() => ctx.close());

  it('collects an SBOM while sbom is licensed', async () => {
    const id = await newReport();
    const source = await compliance.collect(id, { limit: 100 });
    expect(source.sbom?.components).toBe(1);
    expect(JSON.parse(source.sbom!.json).serialNumber).toBe(`urn:uuid:${id}`);
  });

  it('stores the SBOM gzipped with its hash, and serves it', async () => {
    const id = await newReport();
    await expect(
      compliance.complete(id, {
        canonical: Buffer.from(CANONICAL),
        sha256: SHA,
        summary: { s: 1 },
        sbom: { json: SBOM, sha256: SBOM_SHA },
      }),
    ).resolves.toBe(true);
    const [row] = await ctx.db
      .select({ sbom: complianceReports.sbom, sbomSha256: complianceReports.sbomSha256 })
      .from(complianceReports)
      .where(eq(complianceReports.id, id));
    expect(row!.sbomSha256).toBe(SBOM_SHA);
    expect(gunzipSync(row!.sbom!).toString('utf8')).toBe(SBOM);
    expect((await get(id)).json()).toMatchObject({ sbom: { sha256: SBOM_SHA } });
    const res = await get(`${id}/sbom`);
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toEqual({ sha256: SBOM_SHA, text: SBOM });
    const events = await ctx.db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.action, 'compliance.report.downloaded'));
    expect(events.at(-1)).toMatchObject({
      targetId: id,
      details: { format: 'sbom', sha256: SBOM_SHA },
    });
  });

  it('refuses an SBOM whose hash does not match, and fails the row', async () => {
    const id = await newReport();
    await expect(
      compliance.complete(id, {
        canonical: Buffer.from(CANONICAL),
        sha256: SHA,
        summary: { s: 1 },
        sbom: { json: SBOM, sha256: 'b'.repeat(64) },
      }),
    ).resolves.toBe(false);
    const [row] = await ctx.db
      .select({ status: complianceReports.status, error: complianceReports.error })
      .from(complianceReports)
      .where(eq(complianceReports.id, id));
    expect(row).toEqual({ status: 'failed', error: 'the SBOM hash does not match' });
  });

  it('answers 404 NOT_FOUND to the SBOM of a report that has none', async () => {
    const id = await newReport();
    await compliance.complete(id, { canonical: Buffer.from(CANONICAL), sha256: SHA, summary: {} });
    expect((await get(id)).json()).toMatchObject({ sbom: null });
    const res = await get(`${id}/sbom`);
    expect(res.statusCode).toBe(404);
    expect(res.json()).toMatchObject({ code: 'NOT_FOUND' });
  });
});
