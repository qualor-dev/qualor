import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { seedCheck, seedTargetRow } from '../../test/vulnerabilities';
import { first } from '../db/rows';
import { uuidv7 } from '../db/ids';
import {
  branches,
  instanceSettings,
  organizations,
  projects,
  projectVersions,
  projectVulnerabilitySettings,
  vulndbDatasets,
  vulnerabilityDecisions,
  vulnerabilityEpss,
  vulnerabilityKev,
} from '../db/schema';
import { listVulnerabilities } from './list';
import { newVulnerabilityMarkers, readTargetSummary } from './summary';

const T0 = new Date('2026-10-20T10:00:00Z');
const BEFORE = new Date('2026-10-19T10:00:00Z');
const AFTER = new Date('2026-10-21T10:00:00Z');

describe('the Vulnerabilities tab: target summary', () => {
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
        .values({ key: `sum${n}`, name: `Sum ${n}` })
        .returning(),
    ).id;
    const projectId = first(
      await t.db
        .insert(projects)
        .values({ organizationId, key: `sum${n}/api`, name: 'Api' })
        .returning(),
    ).id;
    await t.db
      .insert(projectVulnerabilitySettings)
      .values({ projectId, branchPatterns: ['release/*'], ...settings });
    const branch = async (name: string, isMain = false) =>
      first(
        await t.db.insert(branches).values({ projectId, kind: 'branch', name, isMain }).returning(),
      ).id;
    const version = async (label: string, minute: number, tracking: 'auto' | 'pinned' = 'auto') =>
      first(
        await t.db
          .insert(projectVersions)
          .values({
            projectId,
            label,
            source: 'tag',
            tag: label,
            analyzedAt: new Date(Date.UTC(2026, 9, 1, 0, minute)),
            tracking,
          })
          .returning(),
      ).id;
    return { projectId, branch, version };
  };
  const decide = (
    projectId: string,
    packageName: string,
    vulnerabilityId: string,
    status: 'open' | 'false_positive' | 'wont_fix',
    scope: { branchId?: string; versionId?: string } = {},
  ) =>
    t.db.insert(vulnerabilityDecisions).values({
      projectId,
      packageName,
      vulnerabilityId,
      status,
      reason: status === 'false_positive' ? 'component_not_present' : null,
      branchId: scope.branchId ?? null,
      versionId: scope.versionId ?? null,
    });

  it('counts effective-open rows by severity and leaves ignored and triaged rows out', async () => {
    const { projectId, branch } = await setup();
    const main = await branch('main', true);
    const rows: [string, 'critical' | 'high' | 'medium' | 'low' | 'unknown', boolean?][] = [
      ['a', 'critical'],
      ['b', 'high'],
      ['c', 'medium'],
      ['d', 'low'],
      ['e', 'unknown'],
      ['f', 'high', true],
      ['g', 'critical'],
    ];
    for (const [name, severity, ignored] of rows) {
      await seedTargetRow(t.db, {
        projectId,
        branchId: main,
        packageName: name,
        vulnerabilityId: `CVE-${name}`,
        severity,
        ...(ignored && { ignored }),
      });
    }
    await decide(projectId, 'g', 'CVE-g', 'false_positive');
    const summary = await readTargetSummary(t.db, projectId, { priority: false });
    expect(summary.targets).toEqual([
      expect.objectContaining({
        kind: 'branch',
        id: main,
        name: 'main',
        isMain: true,
        tracking: null,
        counts: { critical: 1, high: 1, medium: 1, low: 1, unknown: 1 },
        new: 0,
      }),
    ]);
  });

  it('lets a branch override change only that branch', async () => {
    const { projectId, branch } = await setup();
    const main = await branch('main', true);
    const release = await branch('release/1.x');
    for (const branchId of [main, release]) {
      await seedTargetRow(t.db, {
        projectId,
        branchId,
        packageName: 'lodash',
        vulnerabilityId: 'CVE-1',
        severity: 'high',
      });
    }
    await decide(projectId, 'lodash', 'CVE-1', 'wont_fix');
    await decide(projectId, 'lodash', 'CVE-1', 'open', { branchId: release });
    const byName = new Map(
      (await readTargetSummary(t.db, projectId, { priority: false })).targets.map((x) => [
        x.name,
        x.counts.high,
      ]),
    );
    expect(byName.get('main')).toBe(0);
    expect(byName.get('release/1.x')).toBe(1);
  });

  it('counts a new row on the branch with an Open override only (Review Focus 1)', async () => {
    const { projectId, branch } = await setup();
    const main = await branch('main', true);
    const release = await branch('release/2.x');
    for (const branchId of [main, release]) {
      await seedCheck(t.db, { projectId, branchId, baselineAt: T0 });
      await seedTargetRow(t.db, {
        projectId,
        branchId,
        packageName: 'lodash',
        vulnerabilityId: 'CVE-1',
        severity: 'high',
        firstSeenAt: AFTER,
      });
    }
    await decide(projectId, 'lodash', 'CVE-1', 'false_positive');
    await decide(projectId, 'lodash', 'CVE-1', 'open', { branchId: release });
    const byName = new Map(
      (await readTargetSummary(t.db, projectId, { priority: false })).targets.map((x) => [
        x.name,
        x,
      ]),
    );
    expect(byName.get('main')).toMatchObject({ new: 0, counts: { high: 0 } });
    expect(byName.get('release/2.x')).toMatchObject({ new: 1, counts: { high: 1 } });
    expect((await newVulnerabilityMarkers(t.db, [projectId])).get(projectId)).toEqual({
      main: false,
      versions: 0,
      branches: 1,
    });
  });

  it('counts a row as new only when it was first seen after the baseline', async () => {
    const { projectId, branch } = await setup();
    const main = await branch('main', true);
    await seedCheck(t.db, { projectId, branchId: main, baselineAt: T0 });
    const seed = (name: string, firstSeenAt: Date, extra: { ignored?: boolean } = {}) =>
      seedTargetRow(t.db, {
        projectId,
        branchId: main,
        packageName: name,
        vulnerabilityId: `CVE-${name}`,
        firstSeenAt,
        ...extra,
      });
    await seed('day-one', T0);
    await seed('older', BEFORE);
    await seed('fresh', AFTER);
    await seed('fresh-too', AFTER);
    await seed('triaged', AFTER);
    await seed('ignored', AFTER, { ignored: true });
    await decide(projectId, 'triaged', 'CVE-triaged', 'wont_fix');
    const [target] = (await readTargetSummary(t.db, projectId, { priority: false })).targets;
    expect(target?.new).toBe(2);
    expect(target?.counts.high).toBe(4);
  });

  it('shows no new rows for a target without a check row', async () => {
    const { projectId, branch } = await setup();
    const main = await branch('main', true);
    await seedTargetRow(t.db, {
      projectId,
      branchId: main,
      packageName: 'x',
      vulnerabilityId: 'CVE-x',
      firstSeenAt: AFTER,
    });
    const summary = await readTargetSummary(t.db, projectId, { priority: false });
    expect(summary.targets[0]).toMatchObject({ new: 0, checkedAt: null });
    expect(summary.checkedAt).toBeNull();
  });

  it('gives the newest check as the header time', async () => {
    const { projectId, branch } = await setup();
    const main = await branch('main', true);
    const release = await branch('release/1.x');
    await seedCheck(t.db, { projectId, branchId: main, baselineAt: T0, checkedAt: BEFORE });
    await seedCheck(t.db, { projectId, branchId: release, baselineAt: T0, checkedAt: AFTER });
    const summary = await readTargetSummary(t.db, projectId, { priority: false });
    expect(summary.checkedAt).toBe(AFTER.toISOString());
    expect(summary.targets.map((x) => x.checkedAt)).toEqual([
      BEFORE.toISOString(),
      AFTER.toISOString(),
    ]);
  });

  it('lists an untracked version with its frozen counts, not among the targets', async () => {
    const { projectId, branch, version } = await setup({ versionRule: 'lines', versionLines: 1 });
    const main = await branch('main', true);
    const newest = await version('2.0.0', 2);
    const old = await version('1.0.0', 1);
    const older = await version('0.9.0', 0);
    await seedTargetRow(t.db, {
      projectId,
      versionId: old,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-1',
      severity: 'critical',
    });
    await seedCheck(t.db, { projectId, versionId: old, baselineAt: T0, checkedAt: BEFORE });
    const summary = await readTargetSummary(t.db, projectId, { priority: false });
    expect(summary.versionCount).toBe(3);
    expect(summary.targets.map((x) => x.id)).toEqual([main, newest]);
    expect(summary.untracked.map((x) => x.id)).toEqual([old, older]);
    expect(summary.untracked[0]).toMatchObject({
      name: '1.0.0',
      tracking: 'auto',
      trackingReason: 'older_line',
      counts: { critical: 1, high: 0, medium: 0, low: 0, unknown: 0 },
      checkedAt: BEFORE.toISOString(),
    });
    expect(summary.untracked[1]?.counts.critical).toBe(0);
  });

  it('puts main first, then branches by name, then versions newest first', async () => {
    const { projectId, branch, version } = await setup({ versionRule: 'all' });
    await branch('release/2.x');
    await branch('release/1.x');
    const main = await branch('main', true);
    const v1 = await version('1.0.0', 1, 'pinned');
    const v2 = await version('2.0.0', 2);
    const summary = await readTargetSummary(t.db, projectId, { priority: false });
    expect(summary.monitoring).toBe('on');
    expect(summary.targets.map((x) => x.name)).toEqual([
      'main',
      'release/1.x',
      'release/2.x',
      '2.0.0',
      '1.0.0',
    ]);
    expect(summary.targets[0]?.id).toBe(main);
    expect(summary.targets.slice(3).map((x) => x.id)).toEqual([v2, v1]);
    expect(summary.targets[4]).toMatchObject({
      kind: 'version',
      tracking: 'pinned',
      isMain: false,
    });
  });

  it('reports hasInventory for a version', async () => {
    const { projectId, branch, version } = await setup({ versionRule: 'all' });
    await branch('main', true);
    const v = await version('1.0.0', 1);
    await t.db.update(projectVersions).set({ hasInventory: true }).where(eq(projectVersions.id, v));
    const summary = await readTargetSummary(t.db, projectId, { priority: false });
    expect(summary.targets.map((x) => [x.name, x.hasInventory])).toEqual([
      ['main', false],
      ['1.0.0', true],
    ]);
  });

  it('answers off when the project switch is off, and still counts the versions', async () => {
    const { projectId, branch, version } = await setup({ enabled: false });
    await branch('main', true);
    await version('1.0.0', 1);
    const summary = await readTargetSummary(t.db, projectId, { priority: false });
    expect(summary).toMatchObject({
      monitoring: 'off',
      checkedAt: null,
      versionCount: 1,
      targets: [],
      untracked: [],
    });
  });

  it('answers the dataset build time, or null without a dataset', async () => {
    const { projectId } = await setup();
    await t.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb_state'));
    expect((await readTargetSummary(t.db, projectId, { priority: false })).data).toBeNull();
    const id = uuidv7();
    await t.db.insert(vulndbDatasets).values({
      id,
      kind: 'trivy',
      digest: `sha256:${'a'.repeat(64)}`,
      sizeBytes: 1,
      builtAt: BEFORE,
      source: 'official',
      status: 'ready',
      chunkCount: 1,
    });
    await t.db
      .insert(instanceSettings)
      .values({ key: 'vulndb_state', value: { currentDatasetId: id } });
    expect((await readTargetSummary(t.db, projectId, { priority: false })).data).toEqual({
      builtAt: BEFORE.toISOString(),
    });
    await t.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb_state'));
  });

  it('counts the tracked targets with new rows, per project, in a few queries', async () => {
    const a = await setup({ versionRule: 'lines', versionLines: 1 });
    const aMain = await a.branch('main', true);
    const aRelease = await a.branch('release/1.x');
    const aFeature = await a.branch('feature/x');
    const aNew = await a.version('2.0.0', 2);
    const aOld = await a.version('1.0.0', 1);
    const b = await setup();
    const bMain = await b.branch('main', true);
    const c = await setup({ enabled: false });
    const cMain = await c.branch('main', true);
    const fresh = (projectId: string, target: { branchId: string } | { versionId: string }) =>
      seedTargetRow(t.db, {
        projectId,
        ...target,
        packageName: 'p',
        vulnerabilityId: 'CVE-p',
        firstSeenAt: AFTER,
      });
    for (const target of [
      { branchId: aMain },
      { branchId: aRelease },
      { branchId: aFeature },
      { versionId: aNew },
      { versionId: aOld },
    ]) {
      await seedCheck(t.db, { projectId: a.projectId, ...target, baselineAt: T0 });
      await fresh(a.projectId, target);
    }
    await seedCheck(t.db, { projectId: b.projectId, branchId: bMain, baselineAt: T0 });
    await seedCheck(t.db, { projectId: c.projectId, branchId: cMain, baselineAt: T0 });
    await fresh(c.projectId, { branchId: cMain });
    const quiet = await setup();
    await quiet.branch('main', true);

    const markers = await newVulnerabilityMarkers(t.db, [
      a.projectId,
      b.projectId,
      c.projectId,
      quiet.projectId,
    ]);
    expect(markers.get(a.projectId)).toEqual({ main: true, branches: 1, versions: 1 });
    expect(markers.get(b.projectId)).toEqual({ main: false, branches: 0, versions: 0 });
    expect(markers.get(c.projectId)).toEqual({ main: false, branches: 0, versions: 0 });
    expect(markers.get(quiet.projectId)).toEqual({ main: false, branches: 0, versions: 0 });
    expect((await newVulnerabilityMarkers(t.db, [])).size).toBe(0);
  });

  it('marks only branch-kind targets, and leaves ignored and triaged rows out', async () => {
    const p = await setup();
    const main = await p.branch('main', true);
    const mergeRequest = first(
      await t.db
        .insert(branches)
        .values({ projectId: p.projectId, kind: 'merge_request', name: 'release/7' })
        .returning(),
    ).id;
    await seedCheck(t.db, { projectId: p.projectId, branchId: main, baselineAt: T0 });
    await seedCheck(t.db, { projectId: p.projectId, branchId: mergeRequest, baselineAt: T0 });
    const row = (branchId: string, name: string, extra: { ignored?: boolean } = {}) =>
      seedTargetRow(t.db, {
        projectId: p.projectId,
        branchId,
        packageName: name,
        vulnerabilityId: `CVE-${name}`,
        firstSeenAt: AFTER,
        ...extra,
      });
    await row(mergeRequest, 'mr');
    await row(main, 'ignored', { ignored: true });
    await row(main, 'triaged');
    await decide(p.projectId, 'triaged', 'CVE-triaged', 'wont_fix');
    expect((await newVulnerabilityMarkers(t.db, [p.projectId])).get(p.projectId)).toEqual({
      main: false,
      branches: 0,
      versions: 0,
    });
    await row(main, 'open');
    expect((await newVulnerabilityMarkers(t.db, [p.projectId])).get(p.projectId)).toEqual({
      main: true,
      branches: 0,
      versions: 0,
    });
  });

  describe('KEV and EPSS (vuln.priority)', () => {
    const seed = async () => {
      const { projectId, branch } = await setup();
      const main = await branch('main', true);
      const row = (
        packageName: string,
        vulnerabilityId: string,
        severity: 'critical' | 'high' | 'medium' | 'low',
        ignored = false,
      ) =>
        seedTargetRow(t.db, {
          projectId,
          branchId: main,
          packageName,
          vulnerabilityId,
          severity,
          ignored,
        });
      await row('p1', 'CVE-2024-0001', 'medium');
      await row('p2', 'CVE-2024-0002', 'critical');
      await row('p3', 'GHSA-aaaa-bbbb-cccc', 'high');
      await row('p4', 'CVE-2024-0003', 'low', true);
      await row('p5', 'CVE-2024-0004', 'low');
      await decide(projectId, 'p5', 'CVE-2024-0004', 'wont_fix');
      await t.db
        .insert(vulnerabilityKev)
        .values(
          ['CVE-2024-0001', 'CVE-2024-0003', 'CVE-2024-0004'].map((vulnerabilityId) => ({
            vulnerabilityId,
            dateAdded: '2024-03-05',
            ransomware: vulnerabilityId === 'CVE-2024-0001',
          })),
        )
        .onConflictDoNothing();
      await t.db
        .insert(vulnerabilityEpss)
        .values({ vulnerabilityId: 'CVE-2024-0002', score: 0.42, percentile: 0.9 })
        .onConflictDoNothing();
      return { projectId, main };
    };
    const query = { status: 'all', page: 1, pageSize: 50 } as const;

    it('counts open, not ignored exploited rows and orders and fills the list', async () => {
      const { projectId } = await seed();
      const summary = await readTargetSummary(t.db, projectId, { priority: true });
      expect(summary.priority).toBe(true);
      expect(summary.targets[0]?.exploited).toBe(1);

      const list = await listVulnerabilities(t.db, projectId, query, { priority: true });
      const byId = new Map(list.items.map((i) => [i.vulnerabilityId, i]));
      expect(list.items[0]?.vulnerabilityId).toBe('CVE-2024-0001');
      expect(byId.get('CVE-2024-0001')?.exploited).toEqual({
        dateAdded: '2024-03-05',
        ransomware: true,
      });
      expect(byId.get('CVE-2024-0003')?.exploited?.ransomware).toBe(false);
      const epss = byId.get('CVE-2024-0002')?.epss;
      expect(epss?.score).toBeCloseTo(0.42, 2);
      expect(epss?.percentile).toBeCloseTo(0.9, 2);
      expect(byId.get('GHSA-aaaa-bbbb-cccc')).toMatchObject({ exploited: null, epss: null });
    });

    it('filters by exploited before paging and counting', async () => {
      const { projectId } = await seed();
      const ids = async (q: Parameters<typeof listVulnerabilities>[2]) => {
        const r = await listVulnerabilities(t.db, projectId, q, { priority: true });
        return { ids: r.items.map((i) => i.vulnerabilityId).sort(), total: r.total };
      };
      expect(await ids({ ...query, exploited: true })).toEqual({
        ids: ['CVE-2024-0001', 'CVE-2024-0003', 'CVE-2024-0004'],
        total: 3,
      });
      expect(await ids({ ...query, status: 'open', exploited: true })).toEqual({
        ids: ['CVE-2024-0001', 'CVE-2024-0003'],
        total: 2,
      });
      expect((await ids({ ...query, exploited: true, pageSize: 1 })).total).toBe(3);
    });

    it('hides every KEV and EPSS fact and the KEV order without the feature', async () => {
      const { projectId } = await seed();
      const summary = await readTargetSummary(t.db, projectId, { priority: false });
      expect(summary.priority).toBe(false);
      expect(summary.targets[0]?.exploited).toBeNull();
      const list = await listVulnerabilities(t.db, projectId, query, { priority: false });
      expect(list.items[0]?.vulnerabilityId).toBe('CVE-2024-0002');
      for (const item of list.items) expect(item).toMatchObject({ exploited: null, epss: null });
      const noop = await listVulnerabilities(
        t.db,
        projectId,
        { ...query, exploited: false },
        { priority: false },
      );
      expect(noop.total).toBe(list.total);
    });
  });
});
