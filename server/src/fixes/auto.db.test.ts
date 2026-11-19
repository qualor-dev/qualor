import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { enableFixes, seedFix } from '../../test/fixes';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { mappedProject, PUBLIC_URL, scmTestConfig, silentLogger } from '../../test/scm';
import { seedCheck, seedTargetRow } from '../../test/vulnerabilities';
import {
  auditEvents,
  dependencyFixes,
  jobs,
  projectFixSettings,
  projects,
  projectVulnerabilitySettings,
  targetVulnerabilities,
  users,
  vulnerabilityKev,
  vulnerabilityTargetChecks,
  type FixState,
  type JiraAutoSeverity,
} from '../db/schema';
import { communityLimits } from '../limits';
import { createScmRuntime } from '../scm/runtime';
import { autoCandidates, runFixAuto } from './auto';
import { FIX_QUEUE } from './jobs';
import type { FixJobDeps } from './run';
import { fixSettingsOf } from './settings';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
/** The rule's `since`: a week ago, at a time of day not midnight. */
const SINCE = new Date(Math.floor((Date.now() - 7 * DAY) / DAY) * DAY + 10 * HOUR);
/** The main branch's baseline: a row first seen after it is new (D3). */
const BASELINE = new Date(SINCE.getTime() - 7 * DAY);
/** `ms` after the rule's `since`. */
const after = (ms: number) => new Date(SINCE.getTime() + ms);
/** Before main's baseline: never new. */
const OLD = new Date(BASELINE.getTime() - DAY);
/** The UTC day of `d`, as CISA writes `date_added`. */
const dayOf = (d: Date) => d.toISOString().slice(0, 10);

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

interface Pkg {
  packageName: string;
  vulnerabilityId: string;
}

describe('the automatic fix mode (0.16 fix MRs §6.3, §11.5, B4, R9)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;
  let projectId: string;
  let main: string;
  let adminId: string;
  let pkgs = 0;

  const db = () => h.ctx.db;
  const deps = (over: Partial<FixJobDeps> = {}): FixJobDeps => ({
    db: db(),
    scm: {
      secretKey: h.ctx.config.secretKey,
      internalHosts: h.ctx.config.scmInternalHosts,
      clientOptions: { timeoutMs: 2_000 },
    },
    runtime: createScmRuntime(),
    publicUrl: PUBLIC_URL,
    limits: () => communityLimits(),
    logger: silentLogger,
    ...over,
  });
  const priority = (): Partial<FixJobDeps> => {
    const limits = communityLimits();
    return { limits: () => ({ vulnerabilities: { ...limits.vulnerabilities, priority: true } }) };
  };
  /** The automatic mode of the organisation, as step 4 of a pass runs it. */
  const auto = (over: Partial<FixJobDeps> = {}) => runFixAuto(deps(over), h.organizationId);

  /** A package name that sorts in the order it was made (`qa-00001`, …). */
  const freshPkg = (): Pkg => {
    pkgs += 1;
    return {
      packageName: `qa-${String(pkgs).padStart(5, '0')}`,
      vulnerabilityId: `CVE-2026-${20_000 + pkgs}`,
    };
  };
  /** A row of the package on main (npm 1.0.0, high, fixed in 1.0.1 unless given). */
  const seedRow = (
    pkg: Pkg,
    row: {
      firstSeenAt: Date;
      severity?: Severity;
      ecosystem?: string;
      fixedVersion?: string | null;
    },
  ) =>
    seedTargetRow(
      db(),
      {
        projectId,
        branchId: main,
        ...pkg,
        packageVersion: '1.0.0',
        ecosystem: row.ecosystem ?? 'npm',
        severity: row.severity ?? 'high',
        fixedVersion: row.fixedVersion === undefined ? '1.0.1' : row.fixedVersion,
        firstSeenAt: row.firstSeenAt,
      },
      { recheck: false },
    );
  /** `n` packages, each with one row on main, the i-th first seen at `firstSeenAt(i)`. */
  const seedPackages = async (
    n: number,
    row: { firstSeenAt: (i: number) => Date; severity?: Severity },
  ): Promise<Pkg[]> => {
    const made: Pkg[] = [];
    for (let i = 0; i < n; i++) {
      const pkg = freshPkg();
      await seedRow(pkg, { firstSeenAt: row.firstSeenAt(i), severity: row.severity });
      made.push(pkg);
    }
    return made;
  };
  const seedPackage = async (row: { firstSeenAt: Date; severity?: Severity }) =>
    (await seedPackages(1, { firstSeenAt: () => row.firstSeenAt, severity: row.severity }))[0]!;
  /** The rule as stored, written directly with a `since` in the past. */
  const rule = (set: {
    minSeverity?: JiraAutoSeverity | null;
    exploited?: boolean;
    maxOpen?: number;
    enabled?: boolean;
  }) =>
    db()
      .update(projectFixSettings)
      .set({
        autoMinSeverity: set.minSeverity ?? null,
        autoExploited: set.exploited ?? false,
        autoSince: SINCE,
        maxOpen: set.maxOpen ?? 5,
        enabled: set.enabled ?? true,
      })
      .where(eq(projectFixSettings.projectId, projectId));
  const kev = (vulnerabilityId: string, dateAdded: string) =>
    db().insert(vulnerabilityKev).values({ vulnerabilityId, dateAdded });
  const fixes = () =>
    db().select().from(dependencyFixes).where(eq(dependencyFixes.projectId, projectId));
  const autoNames = async () =>
    (await fixes())
      .filter((f) => f.origin === 'auto' && f.state === 'requested')
      .map((f) => f.packageName)
      .sort();
  const names = (list: Pkg[]) => list.map((p) => p.packageName).sort();

  beforeAll(async () => {
    fake = await createFakeGitLab();
    h = await createIngestHarness({ config: scmTestConfig(fake) });
    fake.addProject({ id: 900, path: 'acme/fix-auto' });
    const project = await mappedProject(h, fake, 'FAUTO', 900);
    projectId = project.id;
    await enableFixes(h, projectId);
    main = await mainBranchId(db(), projectId);
    adminId = (await db().select().from(users).where(eq(users.username, 'ingest-admin')))[0]!.id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(async () => {
    await seedCheck(db(), { projectId, branchId: main, baselineAt: BASELINE });
  });
  afterEach(async () => {
    await db().delete(jobs).where(eq(jobs.queue, FIX_QUEUE));
    await db().delete(dependencyFixes);
    await db().delete(targetVulnerabilities);
    await db().delete(vulnerabilityTargetChecks);
    await db().delete(vulnerabilityKev);
    await rule({ minSeverity: null });
    await db()
      .update(projectFixSettings)
      .set({ autoSince: null })
      .where(eq(projectFixSettings.projectId, projectId));
  });

  it('no backlog (§11.5): 300 new high rows first seen before since request nothing', async () => {
    await rule({ minSeverity: 'high' });
    // New on the tab (after main's baseline), but first seen an hour before the rule's since.
    await seedPackages(300, { firstSeenAt: () => after(-HOUR) });
    expect(await auto()).toBe(0);
    expect(await fixes()).toEqual([]);

    const fresh = await seedPackage({ firstSeenAt: after(MINUTE) });
    expect(await auto()).toBe(1);
    expect(await autoNames()).toEqual(names([fresh]));
  });

  it('a new batch (§11.5, R9): 8 new packages, cap 5, one manual open: 4 requested, oldest first; then none', async () => {
    await rule({ minSeverity: 'high', maxOpen: 5 });
    const manual = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: 'qa-manual',
      state: 'open',
      requestedBy: adminId,
    });
    const batch = await seedPackages(8, { firstSeenAt: (i) => after((8 - i) * MINUTE) });
    // Seeded newest first: the oldest are the last four.
    const oldest = batch.slice(4);

    expect(await auto()).toBe(4);
    expect(await autoNames()).toEqual(names(oldest));
    expect(await auto()).toBe(0);

    // Manual and automatic share the cap: one MR merged makes room for exactly one more.
    await db()
      .update(dependencyFixes)
      .set({ state: 'merged' })
      .where(eq(dependencyFixes.id, manual));
    expect(await auto()).toBe(1);
    expect(await autoNames()).toEqual(names(batch.slice(3)));
    expect(await auto()).toBe(0);
  });

  it('severity: high skips a new medium row; low skips a new unknown row', async () => {
    await rule({ minSeverity: 'high' });
    await seedPackage({ severity: 'medium', firstSeenAt: after(MINUTE) });
    expect(await auto()).toBe(0);
    await db().delete(targetVulnerabilities);

    await rule({ minSeverity: 'low' });
    await seedPackage({ severity: 'unknown', firstSeenAt: after(MINUTE) });
    expect(await auto()).toBe(0);
    const low = await seedPackage({ severity: 'low', firstSeenAt: after(MINUTE) });
    expect(await auto()).toBe(1);
    expect(await autoNames()).toEqual(names([low]));
  });

  it("exploited: CISA's date_added on the day of since requests an old row; the day before does not; never without vuln.priority", async () => {
    await rule({ exploited: true });
    const sameDay = await seedPackage({ severity: 'low', firstSeenAt: OLD });
    await kev(sameDay.vulnerabilityId, dayOf(SINCE));
    const dayBefore = await seedPackage({ firstSeenAt: OLD });
    await kev(dayBefore.vulnerabilityId, dayOf(new Date(SINCE.getTime() - DAY)));

    expect(await auto()).toBe(0);
    expect(await fixes()).toEqual([]);
    expect(await auto(priority())).toBe(1);
    expect(await autoNames()).toEqual(names([sameDay]));
    expect(await auto(priority())).toBe(0);
  });

  it('never re-requests (B4): failed, no_fix, cancelled, declined and taken_over rows with new qualifying rows', async () => {
    await rule({ minSeverity: 'high', maxOpen: 20 });
    const states: FixState[] = ['failed', 'no_fix', 'cancelled', 'declined', 'taken_over'];
    const seeded = new Map<string, FixState>();
    for (const state of states) {
      const pkg = await seedPackage({ firstSeenAt: after(MINUTE) });
      const id = await seedFix(db(), {
        projectId,
        family: 'js',
        packageName: pkg.packageName,
        state,
        vulnerabilityIds: ['CVE-2026-00001'],
      });
      seeded.set(id, state);
    }
    expect(await auto()).toBe(0);
    const kept = await fixes();
    expect(kept).toHaveLength(states.length);
    for (const f of kept) {
      expect(f).toMatchObject({ state: seeded.get(f.id), origin: 'manual', generation: 1 });
    }
  });

  it('merged or fixed and a new id (B4): re-armed as auto; with the id already handled, nothing', async () => {
    await rule({ minSeverity: 'high' });
    const merged = await seedPackage({ firstSeenAt: after(MINUTE) });
    const mergedId = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: merged.packageName,
      state: 'merged',
      requestedBy: adminId,
      vulnerabilityIds: ['CVE-2026-00002'],
    });
    const fixed = await seedPackage({ firstSeenAt: after(2 * MINUTE) });
    const fixedId = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: fixed.packageName,
      state: 'fixed',
      vulnerabilityIds: [],
    });
    const handled = await seedPackage({ firstSeenAt: after(3 * MINUTE) });
    const handledId = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: handled.packageName,
      state: 'merged',
      vulnerabilityIds: ['CVE-2026-00003', handled.vulnerabilityId],
    });

    expect(await auto()).toBe(2);
    const byId = new Map((await fixes()).map((f) => [f.id, f]));
    for (const id of [mergedId, fixedId]) {
      expect(byId.get(id)).toMatchObject({
        state: 'requested',
        origin: 'auto',
        requestedBy: null,
        generation: 2,
      });
    }
    expect(byId.get(handledId)).toMatchObject({ state: 'merged', generation: 1 });
    expect(byId.size).toBe(3);
  });

  it('T8b, R3: a Python fix is found by its PEP 503 name; Go stdlib is never requested', async () => {
    await rule({ minSeverity: 'high' });
    const id = await seedFix(db(), {
      projectId,
      family: 'python',
      packageName: 'django-rest',
      state: 'merged',
      vulnerabilityIds: ['CVE-2026-00004'],
    });
    await seedRow(
      { packageName: 'Django_Rest', vulnerabilityId: 'CVE-2026-30001' },
      { ecosystem: 'uv', firstSeenAt: after(MINUTE) },
    );
    await seedRow(
      { packageName: 'stdlib', vulnerabilityId: 'CVE-2026-30002' },
      { ecosystem: 'gomod', firstSeenAt: after(MINUTE) },
    );
    // A new row with no fixed version is nothing to fix.
    await seedRow(freshPkg(), { fixedVersion: null, firstSeenAt: after(MINUTE) });

    expect(await auto()).toBe(1);
    const all = await fixes();
    expect(all).toHaveLength(1);
    expect(all[0]).toMatchObject({ id, packageName: 'django-rest', state: 'requested' });
  });

  it('only while fixes are usable: switched off, or monitoring off, requests nothing', async () => {
    await rule({ minSeverity: 'high', enabled: false });
    const pkg = await seedPackage({ firstSeenAt: after(MINUTE) });
    expect(await auto()).toBe(0);

    await rule({ minSeverity: 'high' });
    await db()
      .insert(projectVulnerabilitySettings)
      .values({ projectId, enabled: false })
      .onConflictDoUpdate({
        target: projectVulnerabilitySettings.projectId,
        set: { enabled: false },
      });
    try {
      expect(await auto()).toBe(0);
    } finally {
      await db()
        .update(projectVulnerabilitySettings)
        .set({ enabled: true })
        .where(eq(projectVulnerabilitySettings.projectId, projectId));
    }
    expect(await auto()).toBe(1);
    expect(await autoNames()).toEqual(names([pkg]));
  });

  it('autoCandidates: the qualifying ids of each package, oldest first, at most the limit', async () => {
    await rule({ minSeverity: 'high' });
    const [first, second] = await seedPackages(2, { firstSeenAt: (i) => after((i + 1) * MINUTE) });
    // A second vulnerability of the first package.
    await seedRow(
      { packageName: first!.packageName, vulnerabilityId: 'CVE-2026-30003' },
      { severity: 'critical', firstSeenAt: after(5 * MINUTE) },
    );
    const settings = (await fixSettingsOf(db(), projectId))!;
    const [project] = await db().select().from(projects).where(eq(projects.id, projectId));
    expect(await autoCandidates(db(), project!, settings, { exploited: false, limit: 5 })).toEqual([
      {
        family: 'js',
        packageName: first!.packageName,
        vulnerabilityIds: ['CVE-2026-30003', first!.vulnerabilityId].sort(),
      },
      {
        family: 'js',
        packageName: second!.packageName,
        vulnerabilityIds: [second!.vulnerabilityId],
      },
    ]);
    expect(
      await autoCandidates(db(), project!, settings, { exploited: false, limit: 1 }),
    ).toHaveLength(1);
    expect(await autoCandidates(db(), project!, settings, { exploited: false, limit: 0 })).toEqual(
      [],
    );
  });

  it('rows: requested by nobody, origin auto, no audit event', async () => {
    await rule({ minSeverity: 'high' });
    const made = await seedPackages(3, { firstSeenAt: (i) => after((i + 1) * MINUTE) });
    const audited = (await db().select().from(auditEvents)).length;

    expect(await auto()).toBe(3);
    const rows = await fixes();
    expect(rows.map((r) => r.packageName).sort()).toEqual(names(made));
    for (const r of rows) {
      expect(r).toMatchObject({
        state: 'requested',
        origin: 'auto',
        requestedBy: null,
        generation: 1,
        branch: `qualor/fix/js/${r.packageName}`,
      });
    }
    expect((await db().select().from(auditEvents)).length).toBe(audited);
  });
});
