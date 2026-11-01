import { and, asc, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../../test/db';
import { seedCheck, seedTargetRow } from '../../../test/vulnerabilities';
import { uuidv7 } from '../../db/ids';
import { LOCKS } from '../../db/locks';
import { first } from '../../db/rows';
import {
  branches,
  instanceSettings,
  organizations,
  projects,
  projectVersions,
  projectVulnerabilitySettings,
  targetVulnerabilities,
  vulnerabilityAlertItems,
  vulnerabilityAlertTargets,
  vulnerabilityTargetChecks,
} from '../../db/schema';
import { COMMUNITY_VULNERABILITY_LIMITS, type Limits } from '../../limits';
import { observeAlerts } from './observe';
import { alertScope } from './scope';

const ALERTS: Pick<Limits, 'vulnerabilities'> = {
  vulnerabilities: { ...COMMUNITY_VULNERABILITY_LIMITS, alerts: true },
};
const NO_ALERTS: Pick<Limits, 'vulnerabilities'> = {
  vulnerabilities: { ...COMMUNITY_VULNERABILITY_LIMITS },
};
const T0 = new Date('2026-11-01T05:00:00Z');
const T1 = new Date('2026-11-01T06:00:00Z');
const T2 = new Date('2026-11-01T07:00:00Z');
const T3 = new Date('2026-11-01T08:00:00Z');

type TargetKey = { branchId: string } | { versionId: string };

describe('vulnerability alerts: the scope and the observe step', () => {
  let t: TestDatabase;
  let n = 0;

  beforeAll(async () => {
    t = await createTestDatabase();
  });
  beforeEach(async () => {
    // alertScope reads every project: each test starts from an empty instance.
    await t.db.delete(projects);
    await t.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb'));
  });
  afterAll(async () => {
    await t.close();
  });

  /** One alert pass as the job runs it: the lock, the scope, then the observe step. */
  const pass = (now: Date, limits = ALERTS, targetSlice?: number) =>
    t.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityAlerts})`);
      return observeAlerts(tx, await alertScope(tx, limits), now, targetSlice);
    });

  /** The check row a re-check writes with the target's rows; `basis` is '' for a branch never analysed. */
  const checked = (projectId: string, key: TargetKey, basis = 'analysis-1') =>
    seedCheck(t.db, { projectId, ...key, baselineAt: T0, basis });

  const newProject = async () => {
    n += 1;
    const organizationId = first(
      await t.db
        .insert(organizations)
        .values({ key: `alr${n}`, name: `Alr ${n}` })
        .returning(),
    ).id;
    const projectId = first(
      await t.db
        .insert(projects)
        .values({ organizationId, key: `alr${n}/api`, name: 'Api' })
        .returning(),
    ).id;
    await t.db.insert(projectVulnerabilitySettings).values({ projectId });
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
          })
          .returning(),
      ).id;
    return { projectId, branch, version };
  };

  /** Project P, re-checked: main with CVE-1 and version 2.3.4 with CVE-2, before any alert pass. */
  const projectP = async () => {
    const p = await newProject();
    const main = await p.branch('main', true);
    const v234 = await p.version('2.3.4', 0);
    await seedTargetRow(t.db, {
      projectId: p.projectId,
      branchId: main,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-1',
    });
    await seedTargetRow(t.db, {
      projectId: p.projectId,
      versionId: v234,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-2',
    });
    await checked(p.projectId, { branchId: main });
    await checked(p.projectId, { versionId: v234 });
    return { ...p, main, v234 };
  };

  /** Project P after its first alert pass, at T1. */
  const observedP = async () => {
    const p = await projectP();
    await pass(T1);
    return p;
  };

  const targetRow = async (key: TargetKey) =>
    (
      await t.db
        .select({
          id: vulnerabilityAlertTargets.id,
          dayOne: vulnerabilityAlertTargets.dayOne,
          observedAt: vulnerabilityAlertTargets.observedAt,
        })
        .from(vulnerabilityAlertTargets)
        .where(
          'branchId' in key
            ? eq(vulnerabilityAlertTargets.branchId, key.branchId)
            : eq(vulnerabilityAlertTargets.versionId, key.versionId),
        )
    )[0];

  const itemsOf = async (key: TargetKey) =>
    t.db
      .select({
        vulnerabilityId: vulnerabilityAlertItems.vulnerabilityId,
        baseline: vulnerabilityAlertItems.baseline,
        foundAt: vulnerabilityAlertItems.foundAt,
        digestedAt: vulnerabilityAlertItems.digestedAt,
        kevNotifiedAt: vulnerabilityAlertItems.kevNotifiedAt,
      })
      .from(vulnerabilityAlertItems)
      .innerJoin(
        vulnerabilityAlertTargets,
        eq(vulnerabilityAlertTargets.id, vulnerabilityAlertItems.targetId),
      )
      .where(
        'branchId' in key
          ? eq(vulnerabilityAlertTargets.branchId, key.branchId)
          : eq(vulnerabilityAlertTargets.versionId, key.versionId),
      )
      .orderBy(asc(vulnerabilityAlertItems.vulnerabilityId));

  const item = (vulnerabilityId: string, baseline: boolean, foundAt: Date) => ({
    vulnerabilityId,
    baseline,
    foundAt,
    digestedAt: null,
    kevNotifiedAt: null,
  });

  const countOf = async (
    table: typeof vulnerabilityAlertTargets | typeof vulnerabilityAlertItems,
  ) => (await t.db.select({ id: table.id }).from(table)).length;

  it('records the first observation as day one, every pair a baseline', async () => {
    const p = await projectP();
    expect(await pass(T1)).toEqual({ targetsAdded: 2, itemsAdded: 2, targetsRemoved: 0 });
    expect(await targetRow({ branchId: p.main })).toMatchObject({ dayOne: true, observedAt: T1 });
    expect(await targetRow({ versionId: p.v234 })).toMatchObject({ dayOne: true, observedAt: T1 });
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T1)]);
    expect(await itemsOf({ versionId: p.v234 })).toEqual([item('CVE-2', true, T1)]);
  });

  it('records a new match as a new item, not a baseline', async () => {
    const p = await observedP();
    expect(await pass(T2)).toEqual({ targetsAdded: 0, itemsAdded: 0, targetsRemoved: 0 });
    await seedTargetRow(t.db, {
      projectId: p.projectId,
      branchId: p.main,
      packageName: 'axios',
      vulnerabilityId: 'CVE-3',
    });
    expect(await pass(T3)).toEqual({ targetsAdded: 0, itemsAdded: 1, targetsRemoved: 0 });
    expect(await itemsOf({ branchId: p.main })).toEqual([
      item('CVE-1', true, T1),
      item('CVE-3', false, T3),
    ]);
  });

  it('adds no item for a package bump that keeps the vulnerability, nor drops one for a gone match', async () => {
    const p = await observedP();
    // A bump, as the re-check writes it: the old purl's row goes, the new purl's row comes.
    await t.db
      .delete(targetVulnerabilities)
      .where(
        and(
          eq(targetVulnerabilities.branchId, p.main),
          eq(targetVulnerabilities.vulnerabilityId, 'CVE-1'),
        ),
      );
    await seedTargetRow(t.db, {
      projectId: p.projectId,
      branchId: p.main,
      packageName: 'lodash',
      packageVersion: '1.0.1',
      vulnerabilityId: 'CVE-1',
    });
    expect(await pass(T2)).toEqual({ targetsAdded: 0, itemsAdded: 0, targetsRemoved: 0 });
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T1)]);
    // The match goes away: the item stays while its target is in scope (A2).
    await t.db.delete(targetVulnerabilities).where(eq(targetVulnerabilities.branchId, p.main));
    expect(await pass(T3)).toEqual({ targetsAdded: 0, itemsAdded: 0, targetsRemoved: 0 });
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T1)]);
  });

  it('records a target added later without day one, after its re-check, its pairs as baselines', async () => {
    const p = await observedP();
    const v240 = await p.version('2.4.0', 1);
    for (const vulnerabilityId of ['CVE-1', 'CVE-4']) {
      await seedTargetRow(t.db, {
        projectId: p.projectId,
        versionId: v240,
        packageName: 'lodash',
        vulnerabilityId,
      });
    }
    // Tracked, but its re-check is still queued: no check row, so not recorded yet (R3).
    expect(await pass(T2)).toEqual({ targetsAdded: 0, itemsAdded: 0, targetsRemoved: 0 });
    expect(await targetRow({ versionId: v240 })).toBeUndefined();
    await checked(p.projectId, { versionId: v240 });
    expect(await pass(T3)).toEqual({ targetsAdded: 1, itemsAdded: 2, targetsRemoved: 0 });
    expect(await targetRow({ versionId: v240 })).toMatchObject({ dayOne: false, observedAt: T3 });
    expect(await itemsOf({ versionId: v240 })).toEqual([
      item('CVE-1', true, T3),
      item('CVE-4', true, T3),
    ]);
    expect(await targetRow({ branchId: p.main })).toMatchObject({ dayOne: true, observedAt: T1 });
  });

  it('forgets a version that is no longer tracked, and keeps its vulnerability rows', async () => {
    const p = await observedP();
    await t.db
      .update(projectVersions)
      .set({ tracking: 'unsupported' })
      .where(eq(projectVersions.id, p.v234));
    expect(await pass(T2)).toEqual({ targetsAdded: 0, itemsAdded: 0, targetsRemoved: 1 });
    expect(await targetRow({ versionId: p.v234 })).toBeUndefined();
    expect(await itemsOf({ versionId: p.v234 })).toEqual([]);
    expect(await countOf(vulnerabilityAlertItems)).toBe(1);
    expect(
      await t.db
        .select({ id: targetVulnerabilities.id })
        .from(targetVulnerabilities)
        .where(eq(targetVulnerabilities.versionId, p.v234)),
    ).toHaveLength(1);
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T1)]);
  });

  it('forgets a project switched off, and starts a new day one when it is switched on', async () => {
    const p = await observedP();
    const setEnabled = (enabled: boolean) =>
      t.db
        .update(projectVulnerabilitySettings)
        .set({ enabled })
        .where(eq(projectVulnerabilitySettings.projectId, p.projectId));
    await setEnabled(false);
    expect((await alertScope(t.db, ALERTS)).has(p.projectId)).toBe(false);
    expect(await pass(T2)).toEqual({ targetsAdded: 0, itemsAdded: 0, targetsRemoved: 2 });
    expect(await countOf(vulnerabilityAlertTargets)).toBe(0);
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    await setEnabled(true);
    expect(await pass(T3)).toEqual({ targetsAdded: 2, itemsAdded: 2, targetsRemoved: 0 });
    expect(await targetRow({ branchId: p.main })).toMatchObject({ dayOne: true, observedAt: T3 });
    expect(await targetRow({ versionId: p.v234 })).toMatchObject({ dayOne: true, observedAt: T3 });
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T3)]);
    expect(await itemsOf({ versionId: p.v234 })).toEqual([item('CVE-2', true, T3)]);
  });

  it('has no scope without vuln.alerts, and the pass deletes every row', async () => {
    const p = await observedP();
    expect(await alertScope(t.db, NO_ALERTS)).toEqual(new Map());
    expect(await pass(T2, NO_ALERTS)).toEqual({
      targetsAdded: 0,
      itemsAdded: 0,
      targetsRemoved: 2,
    });
    expect(await countOf(vulnerabilityAlertTargets)).toBe(0);
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    expect(await targetRow({ branchId: p.main })).toBeUndefined();
  });

  it('has no scope while the instance switch is off', async () => {
    await observedP();
    await t.db.insert(instanceSettings).values({ key: 'vulndb', value: { enabled: false } });
    expect(await alertScope(t.db, ALERTS)).toEqual(new Map());
    expect(await pass(T2)).toEqual({ targetsAdded: 0, itemsAdded: 0, targetsRemoved: 2 });
    expect(await countOf(vulnerabilityAlertTargets)).toBe(0);
  });

  it('maps each project with a tracked target to its targets, and leaves out the others', async () => {
    const p = await projectP();
    await newProject(); // switched on, but no branch or version yet
    const off = await newProject();
    await off.branch('main', true);
    await t.db
      .update(projectVulnerabilitySettings)
      .set({ enabled: false })
      .where(eq(projectVulnerabilitySettings.projectId, off.projectId));
    expect(await alertScope(t.db, ALERTS)).toEqual(
      new Map([
        [
          p.projectId,
          [
            { kind: 'branch', branchId: p.main },
            { kind: 'version', versionId: p.v234 },
          ],
        ],
      ]),
    );
  });

  it('gives a project its own day one while another is already observed', async () => {
    const p = await observedP();
    const q = await newProject();
    const qMain = await q.branch('main', true);
    await seedTargetRow(t.db, {
      projectId: q.projectId,
      branchId: qMain,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-1',
    });
    await checked(q.projectId, { branchId: qMain });
    expect(await pass(T2)).toEqual({ targetsAdded: 1, itemsAdded: 1, targetsRemoved: 0 });
    expect(await targetRow({ branchId: qMain })).toMatchObject({ dayOne: true, observedAt: T2 });
    expect(await itemsOf({ branchId: qMain })).toEqual([item('CVE-1', true, T2)]);
    expect(await targetRow({ branchId: p.main })).toMatchObject({ dayOne: true, observedAt: T1 });
  });

  it('keeps one item per vulnerability of a target, however many packages carry it', async () => {
    const p = await projectP();
    await seedTargetRow(t.db, {
      projectId: p.projectId,
      branchId: p.main,
      packageName: 'lodash-es',
      vulnerabilityId: 'CVE-1',
    });
    expect(await pass(T1)).toEqual({ targetsAdded: 2, itemsAdded: 2, targetsRemoved: 0 });
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T1)]);
  });

  it('records a new project only once its first re-check is in, then as day one', async () => {
    const r = await newProject();
    const main = await r.branch('main', true);
    await seedTargetRow(t.db, {
      projectId: r.projectId,
      branchId: main,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-1',
    });
    expect((await alertScope(t.db, ALERTS)).has(r.projectId)).toBe(true);
    expect(await pass(T1)).toEqual({ targetsAdded: 0, itemsAdded: 0, targetsRemoved: 0 });
    expect(await countOf(vulnerabilityAlertTargets)).toBe(0);
    await checked(r.projectId, { branchId: main });
    expect(await pass(T2)).toEqual({ targetsAdded: 1, itemsAdded: 1, targetsRemoved: 0 });
    expect(await targetRow({ branchId: main })).toMatchObject({ dayOne: true, observedAt: T2 });
    expect(await itemsOf({ branchId: main })).toEqual([item('CVE-1', true, T2)]);
  });

  it('does not record a branch whose check row has no basis (never analysed)', async () => {
    const r = await newProject();
    const main = await r.branch('main', true);
    await checked(r.projectId, { branchId: main }, '');
    expect(await pass(T1)).toEqual({ targetsAdded: 0, itemsAdded: 0, targetsRemoved: 0 });
    expect(await targetRow({ branchId: main })).toBeUndefined();
    // Its first analysis, re-checked: the basis is set and the branch is recorded.
    await t.db
      .update(vulnerabilityTargetChecks)
      .set({ basis: 'analysis-1' })
      .where(eq(vulnerabilityTargetChecks.branchId, main));
    expect(await pass(T2)).toEqual({ targetsAdded: 1, itemsAdded: 0, targetsRemoved: 0 });
    expect(await targetRow({ branchId: main })).toMatchObject({ dayOne: true, observedAt: T2 });
  });

  it('skips a target deleted since the scope was read, without failing the pass', async () => {
    const p = await projectP();
    const counts = await t.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityAlerts})`);
      const scope = await alertScope(tx, ALERTS);
      await tx.delete(projectVersions).where(eq(projectVersions.id, p.v234));
      scope.get(p.projectId)?.push({ kind: 'branch', branchId: uuidv7() });
      return observeAlerts(tx, scope, T1);
    });
    expect(counts).toEqual({ targetsAdded: 1, itemsAdded: 1, targetsRemoved: 0 });
    expect(await countOf(vulnerabilityAlertTargets)).toBe(1);
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T1)]);
  });

  it('adds every missing pair across slices of the scope', async () => {
    const p = await projectP();
    await seedTargetRow(t.db, {
      projectId: p.projectId,
      branchId: p.main,
      packageName: 'axios',
      vulnerabilityId: 'CVE-3',
    });
    const v240 = await p.version('2.4.0', 1);
    for (const vulnerabilityId of ['CVE-1', 'CVE-4']) {
      await seedTargetRow(t.db, {
        projectId: p.projectId,
        versionId: v240,
        packageName: 'lodash',
        vulnerabilityId,
      });
    }
    await checked(p.projectId, { versionId: v240 });
    const q = await newProject();
    const qMain = await q.branch('main', true);
    await seedTargetRow(t.db, {
      projectId: q.projectId,
      branchId: qMain,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-5',
    });
    await checked(q.projectId, { branchId: qMain });
    // Four targets, two at a time.
    expect(await pass(T1, ALERTS, 2)).toEqual({
      targetsAdded: 4,
      itemsAdded: 6,
      targetsRemoved: 0,
    });
    expect(await itemsOf({ branchId: p.main })).toEqual([
      item('CVE-1', true, T1),
      item('CVE-3', true, T1),
    ]);
    expect(await itemsOf({ versionId: v240 })).toEqual([
      item('CVE-1', true, T1),
      item('CVE-4', true, T1),
    ]);
    expect(await itemsOf({ versionId: p.v234 })).toEqual([item('CVE-2', true, T1)]);
    expect(await itemsOf({ branchId: qMain })).toEqual([item('CVE-5', true, T1)]);
    // One target at a time: a new target's pairs stay baselines, a new pair elsewhere is news.
    const v250 = await p.version('2.5.0', 2);
    await seedTargetRow(t.db, {
      projectId: p.projectId,
      versionId: v250,
      packageName: 'lodash',
      vulnerabilityId: 'CVE-7',
    });
    await checked(p.projectId, { versionId: v250 });
    await seedTargetRow(t.db, {
      projectId: p.projectId,
      versionId: p.v234,
      packageName: 'axios',
      vulnerabilityId: 'CVE-6',
    });
    expect(await pass(T2, ALERTS, 1)).toEqual({
      targetsAdded: 1,
      itemsAdded: 2,
      targetsRemoved: 0,
    });
    expect(await itemsOf({ versionId: v250 })).toEqual([item('CVE-7', true, T2)]);
    expect(await itemsOf({ versionId: p.v234 })).toEqual([
      item('CVE-2', true, T1),
      item('CVE-6', false, T2),
    ]);
  });
});
