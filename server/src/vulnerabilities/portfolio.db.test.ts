import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { seedTargetRow } from '../../test/vulnerabilities';
import { first } from '../db/rows';
import {
  branches,
  organizations,
  projects,
  projectVersions,
  projectVulnerabilitySettings,
  vulnerabilityDecisions,
  vulnerabilityKev,
} from '../db/schema';
import { writeVulndbSettings } from '../vulndb/settings';
import { portfolioVulnerabilityFacts } from './portfolio';

describe('portfolioVulnerabilityFacts (plan 5, V1)', () => {
  let t: TestDatabase;
  let n = 0;

  beforeAll(async () => {
    t = await createTestDatabase();
  });
  afterAll(async () => {
    await t.close();
  });

  const setup = async (
    settings: Partial<typeof projectVulnerabilitySettings.$inferInsert> = {},
  ) => {
    n += 1;
    const organizationId = first(
      await t.db
        .insert(organizations)
        .values({ key: `pf${n}`, name: `Pf ${n}` })
        .returning(),
    ).id;
    const projectId = first(
      await t.db
        .insert(projects)
        .values({ organizationId, key: `pf${n}/api`, name: 'Api' })
        .returning(),
    ).id;
    await t.db
      .insert(projectVulnerabilitySettings)
      .values({ projectId, versionRule: 'all', ...settings });
    const branch = async (name: string, isMain = false) =>
      first(
        await t.db.insert(branches).values({ projectId, kind: 'branch', name, isMain }).returning(),
      ).id;
    const version = async (label: string, minute: number) =>
      first(
        await t.db
          .insert(projectVersions)
          .values({
            projectId,
            label,
            source: 'tag',
            tag: label,
            analyzedAt: new Date(Date.UTC(2026, 9, 1, 0, minute)),
            tracking: 'auto',
          })
          .returning(),
      ).id;
    return { projectId, branch, version };
  };
  const row = (
    projectId: string,
    target: { branchId: string } | { versionId: string },
    id: string,
    extra: { ignored?: boolean; packageName?: string } = {},
  ) =>
    seedTargetRow(t.db, {
      projectId,
      ...target,
      packageName: extra.packageName ?? 'lodash',
      vulnerabilityId: id,
      ...(extra.ignored && { ignored: true }),
    });
  const kev = (...ids: string[]) =>
    t.db
      .insert(vulnerabilityKev)
      .values(ids.map((vulnerabilityId) => ({ vulnerabilityId, dateAdded: '2024-03-05' })))
      .onConflictDoUpdate({ target: vulnerabilityKev.vulnerabilityId, set: { delistedAt: null } });
  const facts = async (projectId: string, priority = true) =>
    (await portfolioVulnerabilityFacts(t.db, [projectId], { priority })).get(projectId);

  it('counts the tracked versions with an open row', async () => {
    const { projectId, branch, version } = await setup();
    await branch('main', true);
    const v1 = await version('v1', 1);
    const v2 = await version('v2', 2);
    await version('v3', 3);
    await row(projectId, { versionId: v1 }, 'CVE-2024-1001');
    await row(projectId, { versionId: v2 }, 'CVE-2024-1001');
    expect(await facts(projectId)).toEqual({ vulnerableReleases: 2, exploited: 0 });
  });

  it('leaves out ignored rows and false-positive decisions', async () => {
    const { projectId, branch, version } = await setup();
    await branch('main', true);
    const v1 = await version('v1', 1);
    const v2 = await version('v2', 2);
    const v3 = await version('v3', 3);
    await row(projectId, { versionId: v1 }, 'CVE-2024-1002', { ignored: true });
    await row(projectId, { versionId: v2 }, 'CVE-2024-1003');
    await t.db.insert(vulnerabilityDecisions).values({
      projectId,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-2024-1003',
      status: 'false_positive',
      reason: 'component_not_present',
      versionId: v2,
    });
    await row(projectId, { versionId: v3 }, 'CVE-2024-1004');
    expect(await facts(projectId)).toEqual({ vulnerableReleases: 1, exploited: 0 });
  });

  it('does not count a version that is not tracked', async () => {
    const { projectId, branch, version } = await setup({ versionRule: 'lines', versionLines: 1 });
    await branch('main', true);
    const old = await version('v1.0.0', 1);
    await version('v2.0.0', 2);
    await row(projectId, { versionId: old }, 'CVE-2024-1005');
    expect(await facts(projectId)).toEqual({ vulnerableReleases: 0, exploited: 0 });
  });

  it('counts a KEV id once, on main and on a version, and counts it only when open', async () => {
    const { projectId, branch, version } = await setup();
    const main = await branch('main', true);
    const other = await branch('feature/x');
    const v1 = await version('v1', 1);
    await kev('CVE-2024-2001', 'CVE-2024-2002');
    await row(projectId, { branchId: main }, 'CVE-2024-2001');
    await row(projectId, { versionId: v1 }, 'CVE-2024-2001');
    await row(projectId, { branchId: main }, 'CVE-2024-2002', {
      packageName: 'ignored-pkg',
      ignored: true,
    });
    // Another branch is tracked by neither number.
    await row(projectId, { branchId: other }, 'CVE-2024-2003');
    await kev('CVE-2024-2003');
    expect(await facts(projectId)).toEqual({ vulnerableReleases: 1, exploited: 1 });
  });

  it('does not count a KEV id of a tracked branch that is not the main one', async () => {
    const { projectId, branch } = await setup({ branchPatterns: ['feature/*'] });
    await branch('main', true);
    const feature = await branch('feature/x');
    await kev('CVE-2024-2101');
    await row(projectId, { branchId: feature }, 'CVE-2024-2101');
    // The branch is tracked (it has rows to show), yet neither number counts it.
    expect(await facts(projectId)).toEqual({ vulnerableReleases: 0, exploited: 0 });
  });

  it('counts the versions of a project whose switch is on but that has no main branch', async () => {
    const { projectId, version } = await setup();
    const v1 = await version('v1', 1);
    await row(projectId, { versionId: v1 }, 'CVE-2024-2102');
    expect(await facts(projectId)).toEqual({ vulnerableReleases: 1, exploited: 0 });
  });

  it('gives null and null to a project with its switch on that has no target at all', async () => {
    const { projectId } = await setup();
    expect(await facts(projectId)).toEqual({ vulnerableReleases: null, exploited: null });
  });

  it('does not count a delisted KEV id', async () => {
    const { projectId, branch } = await setup();
    const main = await branch('main', true);
    await row(projectId, { branchId: main }, 'CVE-2024-3001');
    await kev('CVE-2024-3001');
    await t.db.update(vulnerabilityKev).set({ delistedAt: new Date('2026-10-01T00:00:00Z') });
    expect(await facts(projectId)).toEqual({ vulnerableReleases: 0, exploited: 0 });
    await t.db.update(vulnerabilityKev).set({ delistedAt: null });
  });

  it('gives exploited null without priority', async () => {
    const { projectId, branch, version } = await setup();
    const main = await branch('main', true);
    const v1 = await version('v1', 1);
    await kev('CVE-2024-4001');
    await row(projectId, { branchId: main }, 'CVE-2024-4001');
    await row(projectId, { versionId: v1 }, 'CVE-2024-4001');
    expect(await facts(projectId, false)).toEqual({ vulnerableReleases: 1, exploited: null });
  });

  it('gives null and null while the project switch or the instance switch is off', async () => {
    const off = await setup({ enabled: false });
    const offMain = await off.branch('main', true);
    await row(off.projectId, { branchId: offMain }, 'CVE-2024-5001');
    const on = await setup();
    const onVersion = await on.version('v1', 1);
    await on.branch('main', true);
    await row(on.projectId, { versionId: onVersion }, 'CVE-2024-5002');
    const both = await portfolioVulnerabilityFacts(t.db, [off.projectId, on.projectId], {
      priority: true,
    });
    expect(both.get(off.projectId)).toEqual({ vulnerableReleases: null, exploited: null });
    expect(both.get(on.projectId)).toEqual({ vulnerableReleases: 1, exploited: 0 });

    await writeVulndbSettings(t.db, { enabled: false }, 'test-secret-key');
    try {
      const none = await portfolioVulnerabilityFacts(t.db, [on.projectId], { priority: true });
      expect(none.get(on.projectId)).toEqual({ vulnerableReleases: null, exploited: null });
    } finally {
      await writeVulndbSettings(t.db, { enabled: true }, 'test-secret-key');
    }
  });

  it('takes the instance switch from the caller when it has read it already', async () => {
    const { projectId, version } = await setup();
    const v1 = await version('v1', 1);
    await row(projectId, { versionId: v1 }, 'CVE-2024-5101');
    const read = (instanceEnabled: boolean) =>
      portfolioVulnerabilityFacts(t.db, [projectId], { priority: true, instanceEnabled });
    expect((await read(false)).get(projectId)).toEqual({
      vulnerableReleases: null,
      exploited: null,
    });
    expect((await read(true)).get(projectId)).toEqual({ vulnerableReleases: 1, exploited: 0 });
  });

  it('answers an empty list with an empty map', async () => {
    expect((await portfolioVulnerabilityFacts(t.db, [], { priority: true })).size).toBe(0);
  });
});
