import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createProject,
  createTestContext,
  login,
  type TestContext,
} from '../../test/app';
import { mainBranchId, seedRule } from '../../test/issues';
import { seedTargetRow } from '../../test/vulnerabilities';
import {
  analyses,
  complianceReports,
  projectVersions,
  users,
  vulnerabilityDecisions,
  vulnerabilityEpss,
  vulnerabilityKev,
} from '../db/schema';
import { writeVulndbSettings } from '../vulndb/settings';
import { collectCompliance } from './collect';

describe('collectCompliance: the report of a version (0.15 plan 5, V12)', () => {
  let ctx: TestContext;
  let org: string;
  let project: { id: string; key: string };
  let version: string;
  let analysis: string;

  const newReport = async (
    target: { versionId: string } | { branchId: string } = { versionId: version },
  ) => {
    await ctx.db.execute(
      sql`UPDATE compliance_reports SET status = 'failed', error = 'x' WHERE status = 'pending'`,
    );
    const [r] = await ctx.db
      .insert(complianceReports)
      .values({
        organizationId: org,
        scope: 'project',
        projectId: project.id,
        createdByName: 'A',
        standards: [],
        ...target,
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
    const main = await mainBranchId(ctx.db, project.id);
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
    analysis = a!.id;
    const [v] = await ctx.db
      .insert(projectVersions)
      .values({
        projectId: project.id,
        label: '2.0.0',
        source: 'tag',
        tag: 'v2.0.0',
        analysisId: analysis,
        analyzedAt: new Date(),
      })
      .returning({ id: projectVersions.id });
    version = v!.id;
    await seedRule(ctx.db, {
      key: 'trivy:CVE-2026-0001',
      name: 'Prototype pollution',
      quality: 'security',
      cwe: [1321],
    });
    const row = (extra: Parameters<typeof seedTargetRow>[1]) => seedTargetRow(ctx.db, extra);
    const base = { projectId: project.id, versionId: version };
    await row({
      ...base,
      packageName: 'lodash',
      packageVersion: '4.17.20',
      vulnerabilityId: 'CVE-2026-0001',
      severity: 'critical',
      title: 'Prototype pollution in lodash',
      fixedVersion: '4.17.21',
      firstSeenAt: new Date('2026-10-05T00:00:00Z'),
    });
    await row({
      ...base,
      packageName: 'left',
      vulnerabilityId: 'CVE-2026-0002',
      severity: 'unknown',
      title: null,
    });
    await row({
      ...base,
      packageName: 'minimist',
      vulnerabilityId: 'CVE-2026-0004',
      severity: 'medium',
    });
    await row({
      ...base,
      packageName: 'tar',
      vulnerabilityId: 'CVE-2026-0005',
      severity: 'low',
    });
    await row({
      ...base,
      packageName: 'ghost',
      vulnerabilityId: 'CVE-2026-0006',
      severity: 'high',
      ignored: true,
    });
    // A row of the project's main branch belongs to the branch report, not to this one.
    await row({
      projectId: project.id,
      branchId: main,
      packageName: 'branch-only',
      vulnerabilityId: 'CVE-2026-0007',
    });
    await ctx.db.insert(vulnerabilityKev).values({
      vulnerabilityId: 'CVE-2026-0001',
      dateAdded: '2026-03-05',
    });
    await ctx.db
      .insert(vulnerabilityEpss)
      .values({ vulnerabilityId: 'CVE-2026-0001', score: 0.42, percentile: 0.97 });
    const [adminUser] = await ctx.db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.username, 'admin'));
    await ctx.db.insert(vulnerabilityDecisions).values([
      {
        projectId: project.id,
        versionId: version,
        packageName: 'minimist',
        vulnerabilityId: 'CVE-2026-0004',
        status: 'false_positive',
        reason: 'component_not_present',
        comment: 'x'.repeat(1_200),
        decidedBy: adminUser!.id,
        decidedAt: new Date('2026-11-01T10:00:00Z'),
      },
      {
        projectId: project.id,
        versionId: version,
        packageName: 'tar',
        vulnerabilityId: 'CVE-2026-0005',
        status: 'wont_fix',
        reason: null,
        comment: null,
        decidedAt: new Date('2026-11-02T10:00:00Z'),
      },
    ]);
  });
  afterAll(() => ctx.close());

  it('has one project entry with the version analysis and no branch, gate or trend', async () => {
    const s = await collectCompliance(ctx.db, await newReport(), { limit: 100 });
    expect(s.scope.branch).toBeNull();
    expect(s.scope.version).toEqual({ id: version, label: '2.0.0' });
    expect(s.projects).toHaveLength(1);
    expect(s.projects[0]).toMatchObject({
      key: 'alpha',
      branch: null,
      gate: null,
      trend: [],
      analysis: { id: analysis, revision: 'b'.repeat(40) },
    });
  });

  it('lists the effective-open dependency rows as findings, in severity order', async () => {
    const s = await collectCompliance(ctx.db, await newReport(), { limit: 100, priority: true });
    expect(s.findings.map((f) => f.vulnerability?.id)).toEqual(['CVE-2026-0001', 'CVE-2026-0002']);
    const [critical, unknown] = s.findings;
    expect(critical).toMatchObject({
      project: 'alpha',
      path: null,
      line: null,
      rule: 'trivy:CVE-2026-0001',
      ruleName: 'Prototype pollution in lodash',
      engine: 'trivy',
      severity: 'blocker',
      kind: 'issue',
      cwe: [1321],
      message: 'lodash 4.17.20: Prototype pollution in lodash',
      inNewCode: false,
      firstSeenAt: '2026-10-05T00:00:00.000Z',
      section: 'dependency',
      vulnerability: {
        id: 'CVE-2026-0001',
        packageName: 'lodash',
        fixedVersions: ['4.17.21'],
        kev: { dateAdded: '2026-03-05' },
        epss: { score: 0.42, percentile: 0.97 },
      },
    });
    // No Trivy rule: the vulnerability id is the key and the name, with no CWE; unknown is medium.
    expect(unknown).toMatchObject({
      rule: 'CVE-2026-0002',
      ruleName: 'CVE-2026-0002',
      severity: 'medium',
      cwe: [],
      message: 'left 1.0.0: CVE-2026-0002',
      vulnerability: { fixedVersions: [], kev: null, epss: null },
    });
  });

  it('leaves KEV and EPSS out without priority', async () => {
    const s = await collectCompliance(ctx.db, await newReport(), { limit: 100 });
    expect(s.findings[0]!.vulnerability).toMatchObject({ kev: null, epss: null });
  });

  it('takes triage rows from the decisions, with reason, author, date and a cut comment', async () => {
    const s = await collectCompliance(ctx.db, await newReport(), { limit: 100 });
    expect(s.triage.map((t) => [t.status, t.reason, t.vulnerability?.id])).toEqual([
      ['wont_fix', null, 'CVE-2026-0005'],
      ['false_positive', 'component_not_present', 'CVE-2026-0004'],
    ]);
    const fp = s.triage[1]!;
    expect(fp).toMatchObject({
      project: 'alpha',
      path: null,
      line: null,
      section: 'dependency',
      severity: 'medium',
      by: 'Administrator',
      at: '2026-11-01T10:00:00.000Z',
    });
    expect(fp.comment).toHaveLength(1_000);
    expect(s.triage[0]).toMatchObject({ by: null, comment: null, severity: 'low' });
  });

  it('counts the rows by effective status and leaves the ignored one out', async () => {
    const s = await collectCompliance(ctx.db, await newReport(), { limit: 100 });
    const counts = s.groups.map((g) => `${g.status}:${g.rule}:${g.severity}:${g.count}`).sort();
    expect(counts).toEqual([
      'false_positive:CVE-2026-0004:medium:1',
      'open:CVE-2026-0002:medium:1',
      'open:trivy:CVE-2026-0001:blocker:1',
      'wont_fix:CVE-2026-0005:low:1',
    ]);
    expect(s.groups.every((g) => g.section === 'dependency' && g.kind === 'issue')).toBe(true);
    expect(s.groups.find((g) => g.rule === 'trivy:CVE-2026-0001')).toMatchObject({
      cwe: [1321],
      inNewCode: false,
      oldestFirstSeenAt: '2026-10-05T00:00:00.000Z',
    });
  });

  it('caps the lists at limit + 1', async () => {
    const s = await collectCompliance(ctx.db, await newReport(), { limit: 1 });
    expect(s.findings).toHaveLength(2);
    expect(s.triage).toHaveLength(2);
    const none = await collectCompliance(ctx.db, await newReport(), { limit: 0 });
    expect(none.findings).toHaveLength(1);
  });

  it('names the datasets as a branch report does', async () => {
    const s = await collectCompliance(ctx.db, await newReport(), { limit: 1 });
    expect(s.datasets).toEqual({ vulnerabilityDatabase: null, kev: null, epss: null });
  });

  it('refuses to build a version report while monitoring is off for the instance', async () => {
    await writeVulndbSettings(ctx.db, { enabled: false }, 'k');
    try {
      await expect(collectCompliance(ctx.db, await newReport(), { limit: 10 })).rejects.toThrow(
        /monitoring is off/,
      );
    } finally {
      await writeVulndbSettings(ctx.db, { enabled: true }, 'k');
    }
  });

  it('gives a branch report no version', async () => {
    const branchId = await mainBranchId(ctx.db, project.id);
    const s = await collectCompliance(ctx.db, await newReport({ branchId }), { limit: 10 });
    expect(s.scope.version).toBeNull();
  });
});
