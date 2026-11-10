import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  ADMIN_PASSWORD,
  createProject,
  createTestContext,
  login,
  type TestContext,
} from '../../test/app';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { seedTargetRow } from '../../test/vulnerabilities';
import {
  branches,
  complianceReports,
  projectVulnerabilitySettings,
  targetVulnerabilities,
  vulnerabilityDecisions,
  vulnerabilityEpss,
  vulnerabilityKev,
  vulndbDatasets,
} from '../db/schema';
import { writeVulndbSettings } from '../vulndb/settings';
import { updatePriorityState } from '../vulndb/priority/state';
import { updateVulndbState } from '../vulndb/state';
import { collectCompliance } from './collect';

describe('collectCompliance: dependency facts, triage reasons, dataset dates (0.15 plan 5)', () => {
  let ctx: TestContext;
  let org: string;
  let project: { id: string; key: string };
  let main: string;
  let feature: string;
  let lodash: string, other: string, untracked: string, fpMain: string, fpBranch: string;
  let split: string, decided: string, localWontFix: string;

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
    const [f] = await ctx.db
      .insert(branches)
      .values({ projectId: project.id, kind: 'branch', name: 'feature' })
      .returning({ id: branches.id });
    feature = f!.id;

    const dep = (id: string) =>
      seedRule(ctx.db, { key: `trivy:${id}`, quality: 'security', cwe: [1395] });
    const r1 = await dep('CVE-2026-0001');
    const r2 = await dep('CVE-2026-0002');
    const r3 = await dep('CVE-2026-0003');
    const r4 = await dep('CVE-2026-0004');
    const base = { projectId: project.id, quality: 'security' as const, severity: 'high' as const };
    lodash = await seedIssue(ctx.db, {
      ...base,
      branchId: main,
      ruleId: r1,
      packageName: 'lodash',
    });
    other = await seedIssue(ctx.db, { ...base, branchId: main, ruleId: r2, packageName: 'left' });
    // The branch "feature" is not monitored: it has no server rows.
    untracked = await seedIssue(ctx.db, {
      ...base,
      branchId: feature,
      ruleId: r3,
      packageName: 'lodash',
    });
    fpMain = await seedIssue(ctx.db, {
      ...base,
      branchId: main,
      ruleId: r4,
      packageName: 'minimist',
      status: 'false_positive',
    });
    fpBranch = await seedIssue(ctx.db, {
      ...base,
      branchId: feature,
      ruleId: r4,
      packageName: 'minimist',
      status: 'false_positive',
    });
    const r5 = await dep('CVE-2026-0005');
    const r6 = await dep('CVE-2026-0006');
    const r7 = await dep('CVE-2026-0007');
    split = await seedIssue(ctx.db, { ...base, branchId: main, ruleId: r5, packageName: 'split' });
    decided = await seedIssue(ctx.db, { ...base, branchId: main, ruleId: r6, packageName: 'dec' });
    // A local "won't fix" on the untracked branch, with a project-wide false positive.
    localWontFix = await seedIssue(ctx.db, {
      ...base,
      branchId: feature,
      ruleId: r7,
      packageName: 'wf',
      status: 'wont_fix',
    });
    const sqli = await seedRule(ctx.db, { key: 'semgrep:sqli', cwe: [89], quality: 'security' });
    await seedIssue(ctx.db, { ...base, branchId: main, ruleId: sqli });

    // Two installed versions of lodash with two fixed versions; one vulnerability without a fix.
    const row = (extra: Parameters<typeof seedTargetRow>[1]) => seedTargetRow(ctx.db, extra);
    await row({
      projectId: project.id,
      branchId: main,
      packageName: 'lodash',
      packageVersion: '4.17.20',
      vulnerabilityId: 'CVE-2026-0001',
      fixedVersion: '4.17.21',
    });
    await row({
      projectId: project.id,
      branchId: main,
      packageName: 'lodash',
      packageVersion: '3.10.0',
      vulnerabilityId: 'CVE-2026-0001',
      fixedVersion: '3.10.2',
    });
    // Rows the branch kept from before it stopped matching the tracking rule (recheck R17).
    await row({
      projectId: project.id,
      branchId: feature,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-2026-0003',
      fixedVersion: '9.9.9',
    });
    await row({
      projectId: project.id,
      branchId: main,
      packageName: 'left',
      vulnerabilityId: 'CVE-2026-0002',
    });
    await row({
      projectId: project.id,
      branchId: main,
      packageName: 'minimist',
      vulnerabilityId: 'CVE-2026-0004',
      fixedVersion: '1.2.6',
    });
    await row({
      projectId: project.id,
      branchId: main,
      packageName: 'split',
      vulnerabilityId: 'CVE-2026-0005',
      fixedVersion: '1.2.3, 2.0.1',
    });
    await row({
      projectId: project.id,
      branchId: main,
      packageName: 'dec',
      vulnerabilityId: 'CVE-2026-0006',
      fixedVersion: '5.0.0',
    });
    await ctx.db.insert(vulnerabilityKev).values({
      vulnerabilityId: 'CVE-2026-0001',
      dateAdded: '2026-03-05',
    });
    await ctx.db
      .insert(vulnerabilityEpss)
      .values({ vulnerabilityId: 'CVE-2026-0001', score: 0.42, percentile: 0.97 });
    // Project-wide reason, and the feature branch's own, different one.
    await ctx.db.insert(vulnerabilityDecisions).values([
      {
        projectId: project.id,
        packageName: 'dec',
        vulnerabilityId: 'CVE-2026-0006',
        status: 'wont_fix',
        reason: null,
      },
      {
        projectId: project.id,
        packageName: 'wf',
        vulnerabilityId: 'CVE-2026-0007',
        status: 'false_positive',
        reason: 'component_not_present',
      },
      {
        projectId: project.id,
        packageName: 'minimist',
        vulnerabilityId: 'CVE-2026-0004',
        status: 'false_positive',
        reason: 'component_not_present',
      },
      {
        projectId: project.id,
        branchId: feature,
        packageName: 'minimist',
        vulnerabilityId: 'CVE-2026-0004',
        status: 'false_positive',
        reason: 'vulnerable_code_not_in_execute_path',
      },
    ]);
    const [ds] = await ctx.db
      .insert(vulndbDatasets)
      .values({
        kind: 'trivy',
        digest: `sha256:${'a'.repeat(64)}`,
        sizeBytes: 1,
        builtAt: new Date('2026-11-08T06:00:00Z'),
        source: 'official',
        status: 'ready',
      })
      .returning({ id: vulndbDatasets.id });
    await updateVulndbState(ctx.db, (s) => ({ ...s, currentDatasetId: ds!.id }));
    await updatePriorityState(ctx.db, 'kev', (s) => ({
      ...s,
      refreshedAt: '2026-11-09T10:00:00.000Z',
      digest: 'sha256:kev1',
    }));
    await updatePriorityState(ctx.db, 'epss', (s) => ({
      ...s,
      dataDate: '2026-11-09',
      refreshedAt: '2026-11-09T11:00:00.000Z',
      digest: 'sha256:epss1',
    }));
  });
  afterAll(() => ctx.close());

  it('adds sorted fixed versions, KEV and EPSS to a dependency finding with priority', async () => {
    const s = await collectCompliance(ctx.db, await newReport({}), {
      limit: 100,
      priority: true,
    });
    expect(s.findings.find((f) => f.id === lodash)!.vulnerability).toEqual({
      id: 'CVE-2026-0001',
      packageName: 'lodash',
      fixedVersions: ['3.10.2', '4.17.21'],
      kev: { dateAdded: '2026-03-05' },
      epss: { score: 0.42, percentile: 0.97 },
    });
    expect(s.findings.find((f) => f.id === other)!.vulnerability).toEqual({
      id: 'CVE-2026-0002',
      packageName: 'left',
      fixedVersions: [],
      kev: null,
      epss: null,
    });
    // A code finding has none.
    expect(s.findings.find((f) => f.rule === 'semgrep:sqli')!.vulnerability).toBeNull();
  });

  it('leaves KEV and EPSS null without priority, and the fixed versions stay', async () => {
    const s = await collectCompliance(ctx.db, await newReport({}), { limit: 100 });
    expect(s.findings.find((f) => f.id === lodash)!.vulnerability).toEqual({
      id: 'CVE-2026-0001',
      packageName: 'lodash',
      fixedVersions: ['3.10.2', '4.17.21'],
      kev: null,
      epss: null,
    });
  });

  it('has no vulnerability for a branch the server does not track', async () => {
    const s = await collectCompliance(ctx.db, await newReport({ branchId: feature }), {
      limit: 100,
      priority: true,
    });
    expect(s.findings.find((f) => f.id === untracked)!.vulnerability).toBeNull();
  });

  it('gives a triage row the reason of its effective decision', async () => {
    const onMain = await collectCompliance(ctx.db, await newReport({}), { limit: 100 });
    const m = onMain.triage.find((t) => t.id === fpMain)!;
    expect(m.reason).toBe('component_not_present');
    expect(m.vulnerability).toMatchObject({ id: 'CVE-2026-0004', fixedVersions: ['1.2.6'] });
    const onBranch = await collectCompliance(ctx.db, await newReport({ branchId: feature }), {
      limit: 100,
    });
    const b = onBranch.triage.find((t) => t.id === fpBranch)!;
    expect(b.reason).toBe('vulnerable_code_not_in_execute_path');
    expect(b.vulnerability).toBeNull();
  });

  it('splits a comma-separated fixed version into single, sorted versions', async () => {
    const s = await collectCompliance(ctx.db, await newReport({}), { limit: 100 });
    expect(s.findings.find((f) => f.id === split)!.vulnerability!.fixedVersions).toEqual([
      '1.2.3',
      '2.0.1',
    ]);
  });

  it('has no vulnerability for an open finding whose every row is decided', async () => {
    const s = await collectCompliance(ctx.db, await newReport({}), { limit: 100 });
    expect(s.findings.find((f) => f.id === decided)!.vulnerability).toBeNull();
  });

  it("gives no reason to a local won't fix that a project-wide false positive does not decide", async () => {
    const s = await collectCompliance(ctx.db, await newReport({ branchId: feature }), {
      limit: 100,
    });
    expect(s.triage.find((t) => t.id === localWontFix)).toMatchObject({
      status: 'wont_fix',
      reason: null,
    });
  });

  it('gives a code triage row no reason and no vulnerability', async () => {
    const code = await seedRule(ctx.db, { key: 'semgrep:xss', cwe: [79], quality: 'security' });
    const id = await seedIssue(ctx.db, {
      projectId: project.id,
      branchId: main,
      ruleId: code,
      status: 'false_positive',
      quality: 'security',
    });
    const s = await collectCompliance(ctx.db, await newReport({}), { limit: 100 });
    expect(s.triage.find((t) => t.id === id)).toMatchObject({ reason: null, vulnerability: null });
  });

  it('reports the dataset dates, and leaves KEV and EPSS out without priority', async () => {
    const database = {
      builtAt: '2026-11-08T06:00:00.000Z',
      digest: `sha256:${'a'.repeat(64)}`,
    };
    const withPriority = await collectCompliance(ctx.db, await newReport({}), {
      limit: 1,
      priority: true,
    });
    expect(withPriority.datasets).toEqual({
      vulnerabilityDatabase: database,
      kev: { refreshedAt: '2026-11-09T10:00:00.000Z', digest: 'sha256:kev1' },
      epss: {
        dataDate: '2026-11-09',
        refreshedAt: '2026-11-09T11:00:00.000Z',
        digest: 'sha256:epss1',
      },
    });
    const without = await collectCompliance(ctx.db, await newReport({}), { limit: 1 });
    expect(without.datasets).toEqual({ vulnerabilityDatabase: database, kev: null, epss: null });
  });

  it('ignores the rows of a project whose monitoring is switched off', async () => {
    await ctx.db
      .insert(projectVulnerabilitySettings)
      .values({ projectId: project.id, enabled: false });
    try {
      const s = await collectCompliance(ctx.db, await newReport({}), {
        limit: 100,
        priority: true,
      });
      expect(s.findings.find((f) => f.id === lodash)!.vulnerability).toBeNull();
      expect(s.triage.find((x) => x.id === fpMain)!.vulnerability).toBeNull();
      expect(s.datasets).toEqual({ vulnerabilityDatabase: null, kev: null, epss: null });
    } finally {
      await ctx.db
        .delete(projectVulnerabilitySettings)
        .where(eq(projectVulnerabilitySettings.projectId, project.id));
    }
  });

  it('ignores every row and names no database while the instance switch is off', async () => {
    await writeVulndbSettings(ctx.db, { enabled: false }, 'k');
    try {
      const s = await collectCompliance(ctx.db, await newReport({}), {
        limit: 100,
        priority: true,
      });
      expect(s.findings.find((f) => f.id === lodash)!.vulnerability).toBeNull();
      expect(s.triage.find((x) => x.id === fpMain)!.vulnerability).toBeNull();
      expect(s.datasets).toEqual({ vulnerabilityDatabase: null, kev: null, epss: null });
    } finally {
      await writeVulndbSettings(ctx.db, { enabled: true }, 'k');
    }
  });

  it('counts only effective-open, not ignored rows for an open finding', async () => {
    const lodashRows = (version: string | null) =>
      ctx.db
        .update(targetVulnerabilities)
        .set({ ignored: true })
        .where(
          sql`branch_id = ${main} AND package_name = 'lodash'
            AND vulnerability_id = 'CVE-2026-0001'
            AND (${version}::text IS NULL OR package_version = ${version})`,
        );
    try {
      await lodashRows('3.10.0');
      const one = await collectCompliance(ctx.db, await newReport({}), { limit: 100 });
      expect(one.findings.find((f) => f.id === lodash)!.vulnerability!.fixedVersions).toEqual([
        '4.17.21',
      ]);
      await lodashRows(null);
      const none = await collectCompliance(ctx.db, await newReport({}), { limit: 100 });
      expect(none.findings.find((f) => f.id === lodash)!.vulnerability).toBeNull();
    } finally {
      await ctx.db
        .update(targetVulnerabilities)
        .set({ ignored: false })
        .where(sql`branch_id = ${main} AND package_name = 'lodash'`);
    }
  });

  it('gives a dataset without a build time a null builtAt', async () => {
    await ctx.db.execute(sql`UPDATE vulndb_datasets SET built_at = NULL`);
    try {
      const s = await collectCompliance(ctx.db, await newReport({}), { limit: 1 });
      expect(s.datasets.vulnerabilityDatabase).toEqual({
        builtAt: null,
        digest: `sha256:${'a'.repeat(64)}`,
      });
    } finally {
      await ctx.db.execute(sql`UPDATE vulndb_datasets SET built_at = '2026-11-08T06:00:00Z'`);
    }
  });
});
