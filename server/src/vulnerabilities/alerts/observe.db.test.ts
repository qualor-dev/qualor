import { and, asc, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../../test/db';
import { afterEachStatement } from '../../../test/vulnerability-alerts';
import {
  seedCheck,
  seedEmptyInventory,
  seedInventory,
  seedTargetRow,
} from '../../../test/vulnerabilities';
import type { Executor } from '../../db/client';
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
  vulnerabilityAlertProjects,
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
// The job's clock: passes on the hour. It stamps `seeded_at` and `found_at`; the database's clock
// stamps `observed_at` and the re-checks' `checked_at` (A12).
const T0 = at('05:00');
const T1 = at('06:00');
const T2 = at('07:00');
const T3 = at('08:00');
const T4 = at('09:00');
const T5 = at('10:00');
const T6 = at('11:00');

type TargetKey = { branchId: string } | { versionId: string };

/** A piece of the statement that reads a slice's missing pairs (`addItems`). */
const MISSING_READ = 'JOIN target_vulnerabilities v ON v.branch_id = s.id';
/** A piece of the statement that reads which targets of a slice to scan (`addItems`, D18). */
const SCAN_READ = 'IS DISTINCT FROM a.items_checked_at';

/** The database clock of `db`'s transaction: `now()`, which stamps `observed_at` (A12). */
const clockOf = async (db: Executor): Promise<Date> =>
  new Date((await db.execute<{ at: string }>(sql`SELECT now() AS at`)).rows[0]!.at);

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

  /** The database clock of each pass, by the pass's job clock (see `recordedAt`). */
  const clocks = new Map<number, Date>();

  beforeAll(async () => {
    t = await createTestDatabase();
  });
  beforeEach(async () => {
    // alertScope reads every project: each test starts from an empty instance.
    await t.db.delete(projects);
    await t.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb'));
    clocks.clear();
  });
  afterAll(async () => {
    await t.close();
  });

  /**
   * One alert pass as the job runs it: the lock, the scope, then the observe step. `after` sees the
   * SQL text of each statement once it has run ({@link afterEachStatement}).
   */
  const pass = (
    now: Date,
    limits = ALERTS,
    targetSlice?: number,
    after?: (text: string) => Promise<void> | void,
  ) =>
    t.db.transaction(async (tx) => {
      if (after) afterEachStatement(tx, after);
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityAlerts})`);
      const observed = await observeAlerts(tx, await alertScope(tx, limits), now, targetSlice);
      clocks.set(now.getTime(), await clockOf(tx));
      return observed;
    });

  /** A pass, and how many times it read missing pairs (`MISSING_READ`): once per slice it scans. */
  const countedPass = async (now: Date, targetSlice?: number) => {
    let reads = 0;
    const observed = await pass(now, ALERTS, targetSlice, (text) => {
      if (text.includes(MISSING_READ)) reads += 1;
    });
    return { observed, reads };
  };

  /** The `observed_at` of a target the pass at job clock `now` recorded: its database clock. */
  const recordedAt = (now: Date): Date => {
    const clock = clocks.get(now.getTime());
    if (clock === undefined) throw new Error(`no pass ran at ${now.toISOString()}`);
    return clock;
  };

  /**
   * The check row a re-check writes with the target's rows, before the target is recorded: on the
   * database clock, as recheck.ts writes it. `basis` is '' for a branch never analysed. The target
   * has its dependency inventory unless the inventory flag is false.
   */
  const checked = async (
    projectId: string,
    key: TargetKey,
    basis = 'analysis-1',
    inventory = true,
  ) => {
    const checkedAt = await clockOf(t.db);
    await seedCheck(t.db, { projectId, ...key, baselineAt: T0, checkedAt, basis });
    if (inventory) await seedInventory(t.db, { projectId, ...key });
  };

  /**
   * A later re-check of the targets: their check rows move to the database's `now()`, as
   * recheck.ts stamps them, so past every record so far and before the next one.
   */
  const rechecked = async (...keys: TargetKey[]) => {
    for (const key of keys) {
      await t.db
        .update(vulnerabilityTargetChecks)
        .set({ checkedAt: sql`now()` })
        .where(
          'branchId' in key
            ? eq(vulnerabilityTargetChecks.branchId, key.branchId)
            : eq(vulnerabilityTargetChecks.versionId, key.versionId),
        );
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
    /** A re-check's new row, and its check row moved (`{ recheck: false }` leaves it). */
    const vulnerable = (
      key: TargetKey,
      vulnerabilityId: string,
      packageName = 'lodash',
      options?: { recheck?: boolean },
    ) => seedTargetRow(t.db, { projectId, ...key, packageName, vulnerabilityId }, options);
    return { projectId, branch, version, vulnerable };
  };

  /** Project P, re-checked before any pass: main with CVE-1 and version 2.3.4 with CVE-2. */
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

  /** Project P recorded at T1, re-checked, and seeded at T2. */
  const seededP = async () => {
    const p = await projectP();
    await pass(T1);
    await rechecked({ branchId: p.main }, { versionId: p.v234 });
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

  const countOf = (
    table:
      | typeof vulnerabilityAlertTargets
      | typeof vulnerabilityAlertItems
      | typeof vulnerabilityAlertProjects,
  ) => t.db.$count(table);

  /** The day-one rows of the projects, as the pass writes them with a project's first target. */
  const projectRows = () =>
    t.db
      .select({
        projectId: vulnerabilityAlertProjects.projectId,
        dayOneAt: vulnerabilityAlertProjects.dayOneAt,
      })
      .from(vulnerabilityAlertProjects)
      .orderBy(asc(vulnerabilityAlertProjects.projectId));

  it('records the first observation as day one, unseeded, and seeds it after a re-check', async () => {
    const p = await projectP();
    expect(await pass(T1)).toEqual(counts({ targetsAdded: 2, recheckProjectIds: [p.projectId] }));
    const unseeded = { dayOne: true, observedAt: recordedAt(T1), seededAt: null };
    expect(await targetRow({ branchId: p.main })).toEqual(unseeded);
    expect(await targetRow({ versionId: p.v234 })).toEqual(unseeded);
    expect(await projectRows()).toEqual([{ projectId: p.projectId, dayOneAt: recordedAt(T1) }]);
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    // No re-check since T1: the rows checked before it are not taken for the baseline.
    expect(await pass(T2)).toEqual(counts());
    await rechecked({ branchId: p.main }, { versionId: p.v234 });
    expect(await pass(T3)).toEqual(counts({ targetsSeeded: 2, itemsAdded: 2 }));
    const seeded = { dayOne: true, observedAt: recordedAt(T1), seededAt: T3 };
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
      observedAt: recordedAt(T4),
      seededAt: null,
    });
    expect(await itemsOf({ versionId: v240 })).toEqual([]);
    await rechecked({ versionId: v240 });
    expect(await pass(T5)).toEqual(counts({ targetsSeeded: 1, itemsAdded: 2 }));
    expect(await itemsOf({ versionId: v240 })).toEqual([
      item('CVE-1', true, T5),
      item('CVE-4', true, T5),
    ]);
    expect(await targetRow({ branchId: p.main })).toEqual({
      dayOne: true,
      observedAt: recordedAt(T1),
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

  it('keeps a project switched off and on past day one, taking no baseline from stale rows', async () => {
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
    expect(await countOf(vulnerabilityAlertProjects)).toBe(1);
    // Back on: the rows and check rows of the first re-check are stale.
    await setEnabled(true);
    expect(await pass(T4)).toEqual(counts({ targetsAdded: 2, recheckProjectIds: [p.projectId] }));
    const unseeded = { dayOne: false, observedAt: recordedAt(T4), seededAt: null };
    expect(await targetRow({ branchId: p.main })).toEqual(unseeded);
    expect(await targetRow({ versionId: p.v234 })).toEqual(unseeded);
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    // A pair that appears before the next re-check is not an item yet.
    await p.vulnerable({ branchId: p.main }, 'CVE-8', 'axios', { recheck: false });
    expect(await pass(T5)).toEqual(counts());
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    // The re-check after re-entry: whatever is matched then is the baseline, nothing is news.
    await p.vulnerable({ versionId: p.v234 }, 'CVE-9', 'axios');
    await rechecked({ branchId: p.main }, { versionId: p.v234 });
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
      observedAt: recordedAt(T4),
      seededAt: null,
    });
    await p.vulnerable({ versionId: p.v234 }, 'CVE-10', 'axios', { recheck: false });
    expect(await pass(T5)).toEqual(counts());
    expect(await itemsOf({ versionId: p.v234 })).toEqual([]);
    await rechecked({ versionId: p.v234 });
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
    // The project's day one stays: it does not come again with the feature.
    expect(await projectRows()).toEqual([{ projectId: p.projectId, dayOneAt: recordedAt(T1) }]);
  });

  it('has no scope while the instance switch is off', async () => {
    const p = await seededP();
    await t.db.insert(instanceSettings).values({ key: 'vulndb', value: { enabled: false } });
    expect(await alertScope(t.db, ALERTS)).toEqual(new Map());
    expect(await pass(T3)).toEqual(counts({ targetsRemoved: 2 }));
    expect(await countOf(vulnerabilityAlertTargets)).toBe(0);
    expect(await countOf(vulnerabilityAlertItems)).toBe(0);
    expect(await projectRows()).toEqual([{ projectId: p.projectId, dayOneAt: recordedAt(T1) }]);
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
    await rechecked({ branchId: qMain });
    expect(await pass(T4)).toEqual(counts({ targetsSeeded: 1, itemsAdded: 1 }));
    expect(await targetRow({ branchId: qMain })).toEqual({
      dayOne: true,
      observedAt: recordedAt(T3),
      seededAt: T4,
    });
    expect(await itemsOf({ branchId: qMain })).toEqual([item('CVE-1', true, T4)]);
    expect(await targetRow({ branchId: p.main })).toMatchObject({
      dayOne: true,
      observedAt: recordedAt(T1),
    });
  });

  it('keeps the project past day one when its main branch is replaced', async () => {
    const r = await newProject();
    const main = await r.branch('main', true);
    await r.vulnerable({ branchId: main }, 'CVE-1');
    await checked(r.projectId, { branchId: main });
    await pass(T1);
    await rechecked({ branchId: main });
    await pass(T2);
    // The old main leaves the scope with the project's only target; the new main comes after.
    await t.db.update(branches).set({ isMain: false }).where(eq(branches.id, main));
    const trunk = await r.branch('trunk', true);
    await r.vulnerable({ branchId: trunk }, 'CVE-1');
    await checked(r.projectId, { branchId: trunk });
    expect(await pass(T3)).toEqual(
      counts({ targetsAdded: 1, targetsRemoved: 1, recheckProjectIds: [r.projectId] }),
    );
    expect(await targetRow({ branchId: main })).toBeUndefined();
    expect(await targetRow({ branchId: trunk })).toEqual({
      dayOne: false,
      observedAt: recordedAt(T3),
      seededAt: null,
    });
    expect(await projectRows()).toEqual([{ projectId: r.projectId, dayOneAt: recordedAt(T1) }]);
  });

  it('treats a project with a backfilled row as past day one', async () => {
    const p = await projectP();
    // The row 0029 writes for a project observed before the upgrade, whose targets went since.
    await t.db.insert(vulnerabilityAlertProjects).values({ projectId: p.projectId, dayOneAt: T0 });
    expect(await pass(T1)).toEqual(counts({ targetsAdded: 2, recheckProjectIds: [p.projectId] }));
    const recorded = { dayOne: false, observedAt: recordedAt(T1), seededAt: null };
    expect(await targetRow({ branchId: p.main })).toEqual(recorded);
    expect(await targetRow({ versionId: p.v234 })).toEqual(recorded);
    expect(await projectRows()).toEqual([{ projectId: p.projectId, dayOneAt: T0 }]);
  });

  /** The target rows a 0.15 replica records during a rolling upgrade: no project row (D17). */
  const recordedBy015 = async (projectId: string, ...keys: TargetKey[]): Promise<Date> => {
    const observedAt = await clockOf(t.db);
    for (const key of keys) {
      await t.db
        .insert(vulnerabilityAlertTargets)
        .values({ projectId, ...key, dayOne: true, observedAt });
    }
    return observedAt;
  };

  it('writes the project row of targets a 0.15 replica recorded, at the next pass', async () => {
    const p = await projectP();
    const observedAt = await recordedBy015(
      p.projectId,
      { branchId: p.main },
      { versionId: p.v234 },
    );
    expect(await projectRows()).toEqual([]);
    expect(await pass(T1)).toEqual(counts());
    expect(await projectRows()).toEqual([{ projectId: p.projectId, dayOneAt: observedAt }]);
    // A target added later is no day one.
    const v240 = await p.version('2.4.0', 1);
    await checked(p.projectId, { versionId: v240 });
    expect(await pass(T2)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [p.projectId] }));
    expect(await targetRow({ versionId: v240 })).toMatchObject({ dayOne: false });
  });

  it('keeps the day one of a 0.15 target that leaves the scope in the same pass', async () => {
    const r = await newProject();
    const main = await r.branch('main', true);
    await checked(r.projectId, { branchId: main });
    const observedAt = await recordedBy015(r.projectId, { branchId: main });
    // The main branch is replaced before any 0.16 pass: step 1 deletes the 0.15 target.
    await t.db.update(branches).set({ isMain: false }).where(eq(branches.id, main));
    const trunk = await r.branch('trunk', true);
    await checked(r.projectId, { branchId: trunk });
    expect(await pass(T1)).toEqual(
      counts({ targetsAdded: 1, targetsRemoved: 1, recheckProjectIds: [r.projectId] }),
    );
    expect(await targetRow({ branchId: trunk })).toEqual({
      dayOne: false,
      observedAt: recordedAt(T1),
      seededAt: null,
    });
    expect(await projectRows()).toEqual([{ projectId: r.projectId, dayOneAt: observedAt }]);
  });

  it('keeps one item per vulnerability of a target, however many packages carry it', async () => {
    const p = await projectP();
    await p.vulnerable({ branchId: p.main }, 'CVE-1', 'lodash-es');
    await pass(T1);
    await rechecked({ branchId: p.main }, { versionId: p.v234 });
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
    await checked(r.projectId, { branchId: main });
    expect(await pass(T2)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [r.projectId] }));
    await rechecked({ branchId: main });
    expect(await pass(T4)).toEqual(counts({ targetsSeeded: 1, itemsAdded: 1 }));
    expect(await targetRow({ branchId: main })).toEqual({
      dayOne: true,
      observedAt: recordedAt(T2),
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
      observedAt: recordedAt(T2),
      seededAt: null,
    });
  });

  it('records a branch only once it has an inventory, and then seeds all its pairs as baseline', async () => {
    const r = await newProject();
    const main = await r.branch('main', true);
    await r.vulnerable({ branchId: main }, 'CVE-1');
    await checked(r.projectId, { branchId: main }, 'analysis-1', false);
    expect(await pass(T1)).toEqual(counts());
    expect(await targetRow({ branchId: main })).toBeUndefined();
    // The first inventory arrives with its matches; a re-check moves the check row.
    await seedInventory(t.db, { projectId: r.projectId, branchId: main });
    await r.vulnerable({ branchId: main }, 'CVE-2', 'express');
    await rechecked({ branchId: main });
    expect(await pass(T4)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [r.projectId] }));
    await rechecked({ branchId: main });
    expect(await pass(T5)).toEqual(counts({ targetsSeeded: 1, itemsAdded: 2 }));
    expect(await itemsOf({ branchId: main })).toEqual([
      item('CVE-1', true, T5),
      item('CVE-2', true, T5),
    ]);
  });

  it('records a branch with an empty inventory, so its later pairs are new', async () => {
    const r = await newProject();
    const main = await r.branch('main', true);
    await checked(r.projectId, { branchId: main }, 'analysis-1', false);
    // The licence pass ran and found no dependencies: an inventory, with no rows.
    await seedEmptyInventory(t.db, { projectId: r.projectId, branchId: main });
    expect(await pass(T1)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [r.projectId] }));
    expect(await targetRow({ branchId: main })).toEqual({
      dayOne: true,
      observedAt: recordedAt(T1),
      seededAt: null,
    });
    await rechecked({ branchId: main });
    expect(await pass(T2)).toEqual(counts({ targetsSeeded: 1 }));
    // A package added later, with its match: new, not a baseline.
    await r.vulnerable({ branchId: main }, 'CVE-1');
    expect(await pass(T3)).toEqual(counts({ itemsAdded: 1 }));
    expect(await itemsOf({ branchId: main })).toEqual([item('CVE-1', false, T3)]);
  });

  it('does not record a version without an inventory', async () => {
    const r = await newProject();
    const v = await r.version('1.0.0', 0);
    await r.vulnerable({ versionId: v }, 'CVE-1');
    await checked(r.projectId, { versionId: v }, 'analysis-1', false);
    expect(await pass(T1)).toEqual(counts());
    expect(await targetRow({ versionId: v })).toBeUndefined();
    await seedInventory(t.db, { projectId: r.projectId, versionId: v });
    expect(await pass(T2)).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [r.projectId] }));
  });

  it('does not seed a recorded target whose check row lost its basis, however fresh', async () => {
    const p = await projectP();
    await pass(T1);
    await rechecked({ branchId: p.main });
    await t.db
      .update(vulnerabilityTargetChecks)
      .set({ basis: '' })
      .where(eq(vulnerabilityTargetChecks.branchId, p.main));
    expect(await pass(T2)).toEqual(counts());
    expect(await targetRow({ branchId: p.main })).toMatchObject({ seededAt: null });
    expect(await itemsOf({ branchId: p.main })).toEqual([]);
  });

  it('skips a target deleted since the scope was read, without failing the pass', async () => {
    const p = await projectP();
    const { result, clock } = await t.db.transaction(async (tx) => {
      await tx.execute(sql`SELECT pg_advisory_xact_lock(${LOCKS.vulnerabilityAlerts})`);
      const scope = await alertScope(tx, ALERTS);
      await tx.delete(projectVersions).where(eq(projectVersions.id, p.v234));
      scope.get(p.projectId)?.push({ kind: 'branch', branchId: uuidv7() });
      return { result: await observeAlerts(tx, scope, T1), clock: await clockOf(tx) };
    });
    expect(result).toEqual(counts({ targetsAdded: 1, recheckProjectIds: [p.projectId] }));
    expect(await countOf(vulnerabilityAlertTargets)).toBe(1);
    expect(await targetRow({ branchId: p.main })).toMatchObject({ observedAt: clock });
  });

  it('seeds by the database clock when the job clock runs ahead', async () => {
    const p = await projectP();
    const ahead = new Date((await clockOf(t.db)).getTime() + 3_600_000);
    expect(await pass(ahead)).toEqual(
      counts({ targetsAdded: 2, recheckProjectIds: [p.projectId] }),
    );
    expect(await targetRow({ branchId: p.main })).toMatchObject({ observedAt: recordedAt(ahead) });
    // The re-check after the record stamps its check rows with the database's now().
    await rechecked({ branchId: p.main }, { versionId: p.v234 });
    expect(await pass(new Date(ahead.getTime() + 60_000))).toEqual(
      counts({ targetsSeeded: 2, itemsAdded: 2 }),
    );
  });

  it('does not fail when a target is deleted between the read and the insert', async () => {
    const p = await seededP();
    // Each row comes with its re-check, which moves the check row: the pass reads both targets.
    await p.vulnerable({ branchId: p.main }, 'CVE-3', 'axios');
    await p.vulnerable({ versionId: p.v234 }, 'CVE-6', 'axios');
    let deleted = false;
    const result = await pass(T3, ALERTS, undefined, async (text) => {
      if (deleted || !text.includes(MISSING_READ)) return;
      deleted = true;
      // A second connection: the branch goes, and its alert target with it (cascade).
      await t.db.delete(branches).where(eq(branches.id, p.main));
    });
    expect(deleted).toBe(true);
    expect(result).toEqual(counts({ itemsAdded: 1 }));
    expect(await targetRow({ branchId: p.main })).toBeUndefined();
    expect(await itemsOf({ versionId: p.v234 })).toEqual([
      item('CVE-2', true, T2),
      item('CVE-6', false, T3),
    ]);
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
    let reads = 0;
    const countReads = (text: string) => {
      if (text.includes(MISSING_READ)) reads += 1;
    };
    // Four targets, two at a time.
    expect(await pass(T1, ALERTS, 2)).toEqual(
      counts({ targetsAdded: 4, recheckProjectIds: [p.projectId, q.projectId].sort() }),
    );
    await rechecked({ branchId: p.main }, { versionId: p.v234 }, { versionId: v240 });
    await rechecked({ branchId: qMain });
    expect(await pass(T2, ALERTS, 2, countReads)).toEqual(
      counts({ targetsSeeded: 4, itemsAdded: 6 }),
    );
    expect(reads).toBe(2);
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
    await rechecked({ versionId: v250 });
    await p.vulnerable({ versionId: p.v234 }, 'CVE-6', 'axios');
    reads = 0;
    expect(await pass(T4, ALERTS, 1, countReads)).toEqual(
      counts({ targetsSeeded: 1, itemsAdded: 2 }),
    );
    // One read per slice that holds a target re-checked since its last read: 2.5.0, seeded now,
    // and 2.3.4, whose new row came with its re-check. The other three are not read.
    expect(reads).toBe(2);
    expect(await itemsOf({ versionId: v250 })).toEqual([item('CVE-7', true, T4)]);
    expect(await itemsOf({ versionId: p.v234 })).toEqual([
      item('CVE-2', true, T2),
      item('CVE-6', false, T4),
    ]);
  });

  it('reads nothing on a pass with nothing new', async () => {
    await seededP();
    expect(await countedPass(T3)).toEqual({ observed: counts(), reads: 0 });
  });

  it('reads only the targets re-checked since the last pass', async () => {
    const p = await seededP();
    await p.vulnerable({ branchId: p.main }, 'CVE-8', 'axios');
    // A row written without its re-check: the version is not read for it yet.
    await p.vulnerable({ versionId: p.v234 }, 'CVE-9', 'axios', { recheck: false });
    expect(await pass(T3)).toEqual(counts({ itemsAdded: 1 }));
    expect(await itemsOf({ branchId: p.main })).toEqual([
      item('CVE-1', true, T2),
      item('CVE-8', false, T3),
    ]);
    expect(await itemsOf({ versionId: p.v234 })).toEqual([item('CVE-2', true, T2)]);
    await rechecked({ versionId: p.v234 });
    expect(await pass(T4)).toEqual(counts({ itemsAdded: 1 }));
    expect(await itemsOf({ versionId: p.v234 })).toEqual([
      item('CVE-2', true, T2),
      item('CVE-9', false, T4),
    ]);
  });

  it('stores the checked_at it read', async () => {
    await seededP();
    // As text: to the microsecond, as the pass compares them.
    const stamps = await t.db.execute<{ read: string | null; checked: string }>(sql`
      SELECT a.items_checked_at::text AS read, c.checked_at::text AS checked
        FROM vulnerability_alert_targets a
        JOIN vulnerability_target_checks c
          ON c.branch_id = a.branch_id OR c.version_id = a.version_id`);
    expect(stamps.rows).toHaveLength(2);
    expect(stamps.rows.map((row) => row.read)).toEqual(stamps.rows.map((row) => row.checked));
  });

  it('reads a target again when its check moves during the pass', async () => {
    const p = await seededP();
    await rechecked({ branchId: p.main });
    let moved = false;
    const observed = await pass(T3, ALERTS, undefined, async (text) => {
      if (moved || !text.includes(SCAN_READ)) return;
      moved = true;
      // A re-check in a second connection, committed after the pass read the check row: a new
      // pair, and the check row moved past what the pass read.
      await t.db.transaction((tx) =>
        seedTargetRow(tx, {
          projectId: p.projectId,
          branchId: p.main,
          packageName: 'axios',
          vulnerabilityId: 'CVE-3',
        }),
      );
    });
    expect(moved).toBe(true);
    // The read of the pairs comes after the commit: the pair is an item already.
    expect(observed).toEqual(counts({ itemsAdded: 1 }));
    // The pass stored the check it read, not the one after: the next pass reads main again.
    expect(await countedPass(T4)).toEqual({ observed: counts(), reads: 1 });
    expect(await itemsOf({ branchId: p.main })).toEqual([
      item('CVE-1', true, T2),
      item('CVE-3', false, T3),
    ]);
    expect(await countedPass(T5)).toEqual({ observed: counts(), reads: 0 });
  });

  it('scans a target from before 0030 once, and adds nothing it already holds', async () => {
    const p = await seededP();
    // A target seeded before 0030: its pairs were never read against a check.
    await t.db
      .update(vulnerabilityAlertTargets)
      .set({ itemsCheckedAt: null })
      .where(eq(vulnerabilityAlertTargets.branchId, p.main));
    expect(await countedPass(T3)).toEqual({ observed: counts(), reads: 1 });
    expect(await countedPass(T4)).toEqual({ observed: counts(), reads: 0 });
    expect(await itemsOf({ branchId: p.main })).toEqual([item('CVE-1', true, T2)]);
  });
});
