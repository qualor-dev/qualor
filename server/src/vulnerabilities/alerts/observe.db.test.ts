import { and, asc, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../../test/db';
import { seedCheck, seedInventory, seedTargetRow } from '../../../test/vulnerabilities';
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
import { observeAlerts, type ObservedAlerts } from './observe';
import { alertScope } from './scope';

const ALERTS: Pick<Limits, 'vulnerabilities'> = {
  vulnerabilities: { ...COMMUNITY_VULNERABILITY_LIMITS, alerts: true },
};
const NO_ALERTS: Pick<Limits, 'vulnerabilities'> = {
  vulnerabilities: { ...COMMUNITY_VULNERABILITY_LIMITS },
};
const at = (hhmm: string) => new Date(`2026-11-01T${hhmm}:00Z`);
// Passes on the hour (T), re-checks on the half hour (R).
const T0 = at('05:00');
const T1 = at('06:00');
const R1 = at('06:30');
const T2 = at('07:00');
const T3 = at('08:00');
const R3 = at('08:30');
const T4 = at('09:00');
const R4 = at('09:30');
const T5 = at('10:00');
const R5 = at('10:30');
const T6 = at('11:00');

type TargetKey = { branchId: string } | { versionId: string };

const counts = (c: Partial<ObservedAlerts> = {}): ObservedAlerts => ({
  targetsAdded: 0,
  targetsSeeded: 0,
  itemsAdded: 0,
  targetsRemoved: 0,
  recheckProjectIds: [],
  ...c,
});

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

  /**
   * The check row a re-check writes with the target's rows, checked at T0 unless given. `basis` is
   * '' for a branch never analysed. The target has its dependency inventory unless the inventory flag is
   * false.
   */
  const checked = async (
    projectId: string,
    key: TargetKey,
    basis = 'analysis-1',
    checkedAt = T0,
    inventory = true,
  ) => {
    await seedCheck(t.db, { projectId, ...key, baselineAt: T0, checkedAt, basis });
    if (inventory) await seedInventory(t.db, { projectId, ...key });
  };

  const whereTarget = (key: TargetKey) =>
    'branchId' in key
      ? eq(vulnerabilityTargetChecks.branchId, key.branchId)
      : eq(vulnerabilityTargetChecks.versionId, key.versionId);

  /** A later re-check of the targets: their check rows move to `checkedAt`. */
  const rechecked = async (checkedAt: Date, ...keys: TargetKey[]) => {
    for (const key of keys) {
      await t.db.update(vulnerabilityTargetChecks).set({ checkedAt }).where(whereTarget(key));
    }
  };

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
    const vulnerable = (key: TargetKey, vulnerabilityId: string, packageName = 'lodash') =>
      seedTargetRow(t.db, { projectId, ...key, packageName, vulnerabilityId });
    return { projectId, branch, version, vulnerable };
  };

  /** Project P, re-checked at T0: main with CVE-1 and version 2.3.4 with CVE-2. */
  const projectP = async () => {
    const p = await newProject();
    const main = await p.branch('main', true);
    const v234 = await p.version('2.3.4', 0);
    await p.vulnerable({ branchId: main }, 'CVE-1');
    await p.vulnerable({ versionId: v234 }, 'CVE-2');
    await checked(p.projectId, { branchId: main });
    await checked(p.projectId, { versionId: v234 });
    return { ...p, main, v234 };
  };

  /** Project P recorded at T1, re-checked at R1 and seeded at T2. */
  const seededP = async () => {
    const p = await projectP();
    await pass(T1);
    await rechecked(R1, { branchId: p.main }, { versionId: p.v234 });
    await pass(T2);
    return p;
  };

  const targetRow = async (key: TargetKey) =>
    (
      await t.db
        .select({
          dayOne: vulnerabilityAlertTargets.dayOne,
          observedAt: vulnerabilityAlertTargets.observedAt,
          seededAt: vulnerabilityAlertTargets.seededAt,
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

  it('records the first observation as day one, unseeded, and seeds it after a re-check', async () => {
    const p = await projectP();
    expect(await pass(T1)).toEqual(counts({ targetsAdded: 2, recheckProjectIds: [p.projectId] }));
    const unseeded = { dayOne: true, observedAt: T1, seededAt: null };
    expect(await targetRow({ branchId: p.main })).toEqual(unseeded);
    expect(await targetRow({ versionId: p.v234 })).toEqual(unseeded);
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    // No re-check since T1: the T0 rows are not taken for the baseline.
    expect(await pass(T2)).toEqual(counts());
    await rechecked(R1, { branchId: p.main }, { versionId: p.v234 });
    expect(await pass(T3)).toEqual(counts({ targetsSeeded: 2, itemsAdded: 2 }));
    const seeded = { dayOne: true, observedAt: T1, seededAt: T3 };
    expect(await targetRow({ branchId: p.main })).toEqual(seeded);
    expect(await targetRow({ versionId: p.v234 })).toEqual(seeded);
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T3)]);
    expect(await itemsOf({ versionId: p.v234 })).toEqual([item('CVE-2', true, T3)]);
    expect(await pass(T4)).toEqual(counts());
  });

  it('records a new match on a seeded target as a new item, not a baseline', async () => {
    const p = await seededP();
    await p.vulnerable({ branchId: p.main }, 'CVE-3', 'axios');
    expect(await pass(T3)).toEqual(counts({ itemsAdded: 1 }));
    expect(await itemsOf({ branchId: p.main })).toEqual([
      item('CVE-1', true, T2),
      item('CVE-3', false, T3),
    ]);
  });

  it('adds no item for a package bump that keeps the vulnerability, nor drops one for a gone match', async () => {
    const p = await seededP();
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
    expect(await pass(T3)).toEqual(counts());
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T2)]);
    // The match goes away: the item stays while its target is in scope (A2).
    await t.db.delete(targetVulnerabilities).where(eq(targetVulnerabilities.branchId, p.main));
    expect(await pass(T4)).toEqual(counts());
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T2)]);
  });

  it('records a target added later without day one, after its re-check, and seeds it after the next', async () => {
    const p = await seededP();
    const v240 = await p.version('2.4.0', 1);
    await p.vulnerable({ versionId: v240 }, 'CVE-1');
    await p.vulnerable({ versionId: v240 }, 'CVE-4');
    // Tracked, but its re-check is still queued: no check row, so not recorded yet (R3).
    expect(await pass(T3)).toEqual(counts());
    expect(await targetRow({ versionId: v240 })).toBeUndefined();
    await checked(p.projectId, { versionId: v240 });
    expect(await pass(T4)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [p.projectId] }));
    expect(await targetRow({ versionId: v240 })).toEqual({
      dayOne: false,
      observedAt: T4,
      seededAt: null,
    });
    expect(await itemsOf({ versionId: v240 })).toEqual([]);
    await rechecked(R4, { versionId: v240 });
    expect(await pass(T5)).toEqual(counts({ targetsSeeded: 1, itemsAdded: 2 }));
    expect(await itemsOf({ versionId: v240 })).toEqual([
      item('CVE-1', true, T5),
      item('CVE-4', true, T5),
    ]);
    expect(await targetRow({ branchId: p.main })).toEqual({
      dayOne: true,
      observedAt: T1,
      seededAt: T2,
    });
  });

  it('forgets a version that is no longer tracked, and keeps its vulnerability rows', async () => {
    const p = await seededP();
    await t.db
      .update(projectVersions)
      .set({ tracking: 'unsupported' })
      .where(eq(projectVersions.id, p.v234));
    expect(await pass(T3)).toEqual(counts({ targetsRemoved: 1 }));
    expect(await targetRow({ versionId: p.v234 })).toBeUndefined();
    expect(await itemsOf({ versionId: p.v234 })).toEqual([]);
    expect(await countOf(vulnerabilityAlertItems)).toBe(1);
    expect(
      await t.db
        .select({ id: targetVulnerabilities.id })
        .from(targetVulnerabilities)
        .where(eq(targetVulnerabilities.versionId, p.v234)),
    ).toHaveLength(1);
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T2)]);
  });

  it('starts a new day one for a project switched off and on, taking no baseline from stale rows', async () => {
    const p = await seededP();
    const setEnabled = (enabled: boolean) =>
      t.db
        .update(projectVulnerabilitySettings)
        .set({ enabled })
        .where(eq(projectVulnerabilitySettings.projectId, p.projectId));
    await setEnabled(false);
    expect((await alertScope(t.db, ALERTS)).has(p.projectId)).toBe(false);
    expect(await pass(T3)).toEqual(counts({ targetsRemoved: 2 }));
    expect(await countOf(vulnerabilityAlertTargets)).toBe(0);
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    // Back on: the rows and check rows from R1 are stale.
    await setEnabled(true);
    expect(await pass(T4)).toEqual(counts({ targetsAdded: 2, recheckProjectIds: [p.projectId] }));
    const unseeded = { dayOne: true, observedAt: T4, seededAt: null };
    expect(await targetRow({ branchId: p.main })).toEqual(unseeded);
    expect(await targetRow({ versionId: p.v234 })).toEqual(unseeded);
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    // A pair that appears before the next re-check is not an item yet.
    await p.vulnerable({ branchId: p.main }, 'CVE-8', 'axios');
    expect(await pass(T5)).toEqual(counts());
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    // The re-check after re-entry: whatever is matched then is the baseline, nothing is news.
    await p.vulnerable({ versionId: p.v234 }, 'CVE-9', 'axios');
    await rechecked(R5, { branchId: p.main }, { versionId: p.v234 });
    expect(await pass(T6)).toEqual(counts({ targetsSeeded: 2, itemsAdded: 4 }));
    expect(await itemsOf({ branchId: p.main })).toEqual([
      item('CVE-1', true, T6),
      item('CVE-8', true, T6),
    ]);
    expect(await itemsOf({ versionId: p.v234 })).toEqual([
      item('CVE-2', true, T6),
      item('CVE-9', true, T6),
    ]);
  });

  it('takes no baseline from stale rows for a version tracked again', async () => {
    const p = await seededP();
    const setTracking = (tracking: 'auto' | 'unsupported') =>
      t.db.update(projectVersions).set({ tracking }).where(eq(projectVersions.id, p.v234));
    await setTracking('unsupported');
    expect(await pass(T3)).toEqual(counts({ targetsRemoved: 1 }));
    await setTracking('auto');
    expect(await pass(T4)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [p.projectId] }));
    expect(await targetRow({ versionId: p.v234 })).toEqual({
      dayOne: false,
      observedAt: T4,
      seededAt: null,
    });
    await p.vulnerable({ versionId: p.v234 }, 'CVE-10', 'axios');
    expect(await pass(T5)).toEqual(counts());
    expect(await itemsOf({ versionId: p.v234 })).toEqual([]);
    await rechecked(R5, { versionId: p.v234 });
    expect(await pass(T6)).toEqual(counts({ targetsSeeded: 1, itemsAdded: 2 }));
    expect(await itemsOf({ versionId: p.v234 })).toEqual([
      item('CVE-10', true, T6),
      item('CVE-2', true, T6),
    ]);
  });

  it('has no scope without vuln.alerts, and the pass deletes every row', async () => {
    const p = await seededP();
    expect(await alertScope(t.db, NO_ALERTS)).toEqual(new Map());
    expect(await pass(T3, NO_ALERTS)).toEqual(counts({ targetsRemoved: 2 }));
    expect(await countOf(vulnerabilityAlertTargets)).toBe(0);
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    expect(await targetRow({ branchId: p.main })).toBeUndefined();
  });

  it('has no scope while the instance switch is off', async () => {
    await seededP();
    await t.db.insert(instanceSettings).values({ key: 'vulndb', value: { enabled: false } });
    expect(await alertScope(t.db, ALERTS)).toEqual(new Map());
    expect(await pass(T3)).toEqual(counts({ targetsRemoved: 2 }));
    expect(await countOf(vulnerabilityAlertTargets)).toBe(0);
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
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
    const p = await seededP();
    const q = await newProject();
    const qMain = await q.branch('main', true);
    await q.vulnerable({ branchId: qMain }, 'CVE-1');
    await checked(q.projectId, { branchId: qMain });
    expect(await pass(T3)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [q.projectId] }));
    await rechecked(R3, { branchId: qMain });
    expect(await pass(T4)).toEqual(counts({ targetsSeeded: 1, itemsAdded: 1 }));
    expect(await targetRow({ branchId: qMain })).toEqual({
      dayOne: true,
      observedAt: T3,
      seededAt: T4,
    });
    expect(await itemsOf({ branchId: qMain })).toEqual([item('CVE-1', true, T4)]);
    expect(await targetRow({ branchId: p.main })).toMatchObject({ dayOne: true, observedAt: T1 });
  });

  it('keeps one item per vulnerability of a target, however many packages carry it', async () => {
    const p = await projectP();
    await p.vulnerable({ branchId: p.main }, 'CVE-1', 'lodash-es');
    await pass(T1);
    await rechecked(R1, { branchId: p.main }, { versionId: p.v234 });
    expect(await pass(T2)).toEqual(counts({ targetsSeeded: 2, itemsAdded: 2 }));
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T2)]);
  });

  it('records a new project only once its first re-check is in, then as day one', async () => {
    const r = await newProject();
    const main = await r.branch('main', true);
    await r.vulnerable({ branchId: main }, 'CVE-1');
    expect((await alertScope(t.db, ALERTS)).has(r.projectId)).toBe(true);
    expect(await pass(T1)).toEqual(counts());
    expect(await countOf(vulnerabilityAlertTargets)).toBe(0);
    await checked(r.projectId, { branchId: main }, 'analysis-1', R1);
    expect(await pass(T2)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [r.projectId] }));
    await rechecked(R3, { branchId: main });
    expect(await pass(T4)).toEqual(counts({ targetsSeeded: 1, itemsAdded: 1 }));
    expect(await targetRow({ branchId: main })).toEqual({
      dayOne: true,
      observedAt: T2,
      seededAt: T4,
    });
    expect(await itemsOf({ branchId: main })).toEqual([item('CVE-1', true, T4)]);
  });

  it('does not record a branch whose check row has no basis (never analysed)', async () => {
    const r = await newProject();
    const main = await r.branch('main', true);
    await checked(r.projectId, { branchId: main }, '');
    expect(await pass(T1)).toEqual(counts());
    expect(await targetRow({ branchId: main })).toBeUndefined();
    // Its first analysis, re-checked: the basis is set and the branch is recorded.
    await t.db
      .update(vulnerabilityTargetChecks)
      .set({ basis: 'analysis-1' })
      .where(eq(vulnerabilityTargetChecks.branchId, main));
    expect(await pass(T2)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [r.projectId] }));
    expect(await targetRow({ branchId: main })).toEqual({
      dayOne: true,
      observedAt: T2,
      seededAt: null,
    });
  });

  it('records a branch only once it has an inventory, and then seeds all its pairs as baseline', async () => {
    const r = await newProject();
    const main = await r.branch('main', true);
    await r.vulnerable({ branchId: main }, 'CVE-1');
    await checked(r.projectId, { branchId: main }, 'analysis-1', T0, false);
    expect(await pass(T1)).toEqual(counts());
    expect(await targetRow({ branchId: main })).toBeUndefined();
    // The first inventory arrives with its matches; a re-check moves the check row.
    await seedInventory(t.db, { projectId: r.projectId, branchId: main });
    await r.vulnerable({ branchId: main }, 'CVE-2', 'express');
    await rechecked(R3, { branchId: main });
    expect(await pass(T4)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [r.projectId] }));
    await rechecked(at('09:30'), { branchId: main });
    expect(await pass(T5)).toEqual(counts({ targetsSeeded: 1, itemsAdded: 2 }));
    expect(await itemsOf({ branchId: main })).toEqual([
      item('CVE-1', true, T5),
      item('CVE-2', true, T5),
    ]);
  });

  it('does not record a version without an inventory', async () => {
    const r = await newProject();
    const v = await r.version('1.0.0', 0);
    await r.vulnerable({ versionId: v }, 'CVE-1');
    await checked(r.projectId, { versionId: v }, 'analysis-1', T0, false);
    expect(await pass(T1)).toEqual(counts());
    expect(await targetRow({ versionId: v })).toBeUndefined();
    await seedInventory(t.db, { projectId: r.projectId, versionId: v });
    expect(await pass(T2)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [r.projectId] }));
  });

  it('does not seed a recorded target whose check row lost its basis, however fresh', async () => {
    const p = await projectP();
    await pass(T1);
    await t.db
      .update(vulnerabilityTargetChecks)
      .set({ basis: '', checkedAt: R1 })
      .where(eq(vulnerabilityTargetChecks.branchId, p.main));
    expect(await pass(T2)).toEqual(counts());
    expect(await targetRow({ branchId: p.main })).toMatchObject({ seededAt: null });
    expect(await itemsOf({ branchId: p.main })).toEqual([]);
  });

  it('skips a target deleted since the scope was read, without failing the pass', async () => {
    const p = await projectP();
    const result = await t.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityAlerts})`);
      const scope = await alertScope(tx, ALERTS);
      await tx.delete(projectVersions).where(eq(projectVersions.id, p.v234));
      scope.get(p.projectId)?.push({ kind: 'branch', branchId: uuidv7() });
      return observeAlerts(tx, scope, T1);
    });
    expect(result).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [p.projectId] }));
    expect(await countOf(vulnerabilityAlertTargets)).toBe(1);
    expect(await targetRow({ branchId: p.main })).toMatchObject({ observedAt: T1 });
  });

  it('seeds and adds every pair across slices of the scope', async () => {
    const p = await projectP();
    await p.vulnerable({ branchId: p.main }, 'CVE-3', 'axios');
    const v240 = await p.version('2.4.0', 1);
    await p.vulnerable({ versionId: v240 }, 'CVE-1');
    await p.vulnerable({ versionId: v240 }, 'CVE-4');
    await checked(p.projectId, { versionId: v240 });
    const q = await newProject();
    const qMain = await q.branch('main', true);
    await q.vulnerable({ branchId: qMain }, 'CVE-5');
    await checked(q.projectId, { branchId: qMain });
    // Four targets, two at a time.
    expect(await pass(T1, ALERTS, 2)).toEqual(
      counts({ targetsAdded: 4, recheckProjectIds: [p.projectId, q.projectId].sort() }),
    );
    await rechecked(R1, { branchId: p.main }, { versionId: p.v234 }, { versionId: v240 });
    await rechecked(R1, { branchId: qMain });
    expect(await pass(T2, ALERTS, 2)).toEqual(counts({ targetsSeeded: 4, itemsAdded: 6 }));
    expect(await itemsOf({ branchId: p.main })).toEqual([
      item('CVE-1', true, T2),
      item('CVE-3', true, T2),
    ]);
    expect(await itemsOf({ versionId: v240 })).toEqual([
      item('CVE-1', true, T2),
      item('CVE-4', true, T2),
    ]);
    expect(await itemsOf({ versionId: p.v234 })).toEqual([item('CVE-2', true, T2)]);
    expect(await itemsOf({ branchId: qMain })).toEqual([item('CVE-5', true, T2)]);
    // One target at a time: a target seeded in this pass gets baselines, a seeded one gets news.
    const v250 = await p.version('2.5.0', 2);
    await p.vulnerable({ versionId: v250 }, 'CVE-7');
    await checked(p.projectId, { versionId: v250 });
    expect(await pass(T3, ALERTS, 1)).toEqual(
      counts({ targetsAdded: 1, recheckProjectIds: [p.projectId] }),
    );
    await rechecked(R3, { versionId: v250 });
    await p.vulnerable({ versionId: p.v234 }, 'CVE-6', 'axios');
    expect(await pass(T4, ALERTS, 1)).toEqual(counts({ targetsSeeded: 1, itemsAdded: 2 }));
    expect(await itemsOf({ versionId: v250 })).toEqual([item('CVE-7', true, T4)]);
    expect(await itemsOf({ versionId: p.v234 })).toEqual([
      item('CVE-2', true, T2),
      item('CVE-6', false, T4),
    ]);
  });
});
