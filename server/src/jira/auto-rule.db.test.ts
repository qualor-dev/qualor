import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { azureConnection } from '../../test/azure-pending';
import { createFakeJira, type FakeJira } from '../../test/fake-jira';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { connectJira, jiraJobDeps, jiraTestConfig, mapJira, seedJiraLink } from '../../test/jira';
import { seedCheck, seedTargetRow } from '../../test/vulnerabilities';
import type { Db } from '../db/client';
import {
  auditEvents,
  boardsLinks,
  branches,
  jiraConnections,
  jiraLinks,
  jobs,
  projectJiraSettings,
  projectVersions,
  projectVulnerabilitySettings,
  scmConnections,
  targetVulnerabilities,
  users,
  vulnerabilityDecisions,
  vulnerabilityKev,
  vulnerabilityTargetChecks,
  type JiraAutoSeverity,
  type JiraLinkState,
} from '../db/schema';
import { communityLimits } from '../limits';
import { writeVulndbSettings } from '../vulndb/settings';
import { AUTO_PER_PASS, qualifyingPairs, runAutoRule } from './auto-rule';
import { JIRA_QUEUE } from './jobs';
import { mappingOf } from './mapping';
import { openRun, type JiraJobDeps } from './run';
import { runSyncPass } from './sync';

const QUAL = { id: '10000', key: 'QUAL', name: 'Qualor findings' };
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
/** The rule's `since` where a test sets it directly: a week ago, at a time of day not midnight. */
const SINCE = new Date(Math.floor((Date.now() - 7 * DAY) / DAY) * DAY + 10 * HOUR);
/** The main branch's baseline: a row first seen after it is new (D3). */
const BASELINE = new Date(SINCE.getTime() - 7 * DAY);
/** `ms` after the rule's `since`. */
const after = (ms: number) => new Date(SINCE.getTime() + ms);
/** The UTC day of `d`, as CISA writes `date_added`. */
const dayOf = (d: Date) => d.toISOString().slice(0, 10);

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

interface Pair {
  packageName: string;
  vulnerabilityId: string;
}

describe('the automatic Jira rule (spec §6.6, §11.10, §11.11)', () => {
  let h: IngestHarness;
  let fake: FakeJira;
  let projectId: string;
  let main: string;
  let adminId: string;
  let connectionId: string;
  let deps: JiraJobDeps;
  let pkgs = 0;

  const db = (): Db => h.ctx.db;
  const freshPair = (): Pair => ({
    packageName: `pkg-auto-${++pkgs}`,
    vulnerabilityId: `CVE-2026-${10_000 + pkgs}`,
  });
  const keyOf = (p: Pair) => `${p.packageName} ${p.vulnerabilityId}`;
  /** `n` pairs, each with one row on main (high unless given), the i-th first seen at `firstSeenAt(i)`. */
  const seedPairs = async (
    n: number,
    row: {
      firstSeenAt: (i: number) => Date;
      severity?: Severity;
      ignored?: boolean;
      projectId?: string;
      branchId?: string;
    },
  ): Promise<Pair[]> => {
    const pairs: Pair[] = [];
    for (let i = 0; i < n; i++) {
      const pair = freshPair();
      await seedTargetRow(
        db(),
        {
          projectId: row.projectId ?? projectId,
          branchId: row.branchId ?? main,
          ...pair,
          severity: row.severity ?? 'high',
          ignored: row.ignored ?? false,
          firstSeenAt: row.firstSeenAt(i),
        },
        { recheck: false },
      );
      pairs.push(pair);
    }
    return pairs;
  };
  const seedPair = async (row: Parameters<typeof seedPairs>[1]) => (await seedPairs(1, row))[0]!;
  /**
   * The rule as stored, written directly with a `since` in the past; the switch-on and threshold
   * tests go through the mapping route, whose `since` is the database's now ({@link storedSince}).
   */
  const rule = (
    set: { minSeverity?: JiraAutoSeverity | null; exploited?: boolean; since?: Date },
    project = projectId,
  ) =>
    db()
      .update(projectJiraSettings)
      .set({
        autoMinSeverity: set.minSeverity ?? null,
        autoExploited: set.exploited ?? false,
        autoSince: set.since ?? SINCE,
      })
      .where(eq(projectJiraSettings.projectId, project));
  /**
   * The `since` the mapping route stored (the database's clock, which may be a second or more off
   * the host's): a test that switches the rule on through the route derives every time from it.
   */
  const storedSince = async (): Promise<Date> => {
    const [row] = await db()
      .select({ since: projectJiraSettings.autoSince })
      .from(projectJiraSettings)
      .where(eq(projectJiraSettings.projectId, projectId));
    expect(row?.since, 'the rule is on').toBeInstanceOf(Date);
    return row!.since!;
  };
  /** `ms` after (or before) `d`. */
  const shifted = (d: Date, ms: number) => new Date(d.getTime() + ms);
  /** Moves main's baseline (its first check) to `at`. */
  const baseline = (at: Date) =>
    db()
      .update(vulnerabilityTargetChecks)
      .set({ baselineAt: at })
      .where(eq(vulnerabilityTargetChecks.branchId, main));
  const kev = (vulnerabilityId: string, dateAdded: string, delistedAt: Date | null = null) =>
    db().insert(vulnerabilityKev).values({ vulnerabilityId, dateAdded, delistedAt });
  const priority = (): Partial<JiraJobDeps> => {
    const limits = communityLimits();
    return { limits: () => ({ vulnerabilities: { ...limits.vulnerabilities, priority: true } }) };
  };
  const context = async (over: Partial<JiraJobDeps> = {}) =>
    (await openRun({ ...deps, ...over }, h.organizationId))!;
  /** The rule alone, as step 3 of a pass runs it. */
  const auto = async (over: Partial<JiraJobDeps> = {}) => runAutoRule(await context(over));
  /** One full pass. */
  const pass = async (over: Partial<JiraJobDeps> = {}) => runSyncPass(await context(over));
  const links = () => db().select().from(jiraLinks).where(eq(jiraLinks.kind, 'vulnerability'));
  const linkedKeys = async () =>
    (await links())
      .map((l) => keyOf({ packageName: l.packageName!, vulnerabilityId: l.vulnerabilityId! }))
      .sort();
  const sorted = (pairs: Pair[]) => pairs.map(keyOf).sort();
  /** A version of the project, checked first at {@link BASELINE}. */
  const seedVersion = async (label: string, tracking: 'pinned' | 'unsupported') => {
    const [v] = await db()
      .insert(projectVersions)
      .values({
        projectId,
        label,
        source: 'tag',
        tag: `v${label}`,
        analyzedAt: new Date(),
        tracking,
      })
      .returning({ id: projectVersions.id });
    await seedCheck(db(), { projectId, versionId: v!.id, baselineAt: BASELINE });
    return v!.id;
  };
  const monitoring = (enabled: boolean) =>
    db()
      .insert(projectVulnerabilitySettings)
      .values({ projectId, enabled })
      .onConflictDoUpdate({ target: projectVulnerabilitySettings.projectId, set: { enabled } });

  beforeAll(async () => {
    fake = await createFakeJira({ deployment: 'data_center' });
    fake.addProject(QUAL);
    h = await createIngestHarness({ config: jiraTestConfig(fake) });
    projectId = (await h.project('JAUTO')).id;
    main = await mainBranchId(db(), projectId);
    adminId = (await db().select().from(users).where(eq(users.username, 'ingest-admin')))[0]!.id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(async () => {
    connectionId = await connectJira(h, fake);
    await mapJira(h, projectId);
    await monitoring(true);
    await seedCheck(db(), { projectId, branchId: main, baselineAt: BASELINE });
    deps = jiraJobDeps(h);
    fake.clearRequests();
  });
  afterEach(async () => {
    await db().delete(jiraConnections);
    // An Azure DevOps connection a test made, with its Boards links.
    await db().delete(scmConnections);
    await db().delete(jobs).where(eq(jobs.queue, JIRA_QUEUE));
    await db().delete(targetVulnerabilities);
    await db().delete(vulnerabilityTargetChecks);
    await db().delete(vulnerabilityDecisions);
    await db().delete(vulnerabilityKev);
  });

  it('no backlog (spec §11.10): switched on over 300 new high rows first seen before it, it opens nothing', async () => {
    await mapJira(h, projectId, { autoCreate: { minSeverity: 'high', exploited: false } });
    const since = await storedSince();
    // The backlog: new on the tab (after main's baseline), first seen an hour before the switch.
    await baseline(shifted(since, -DAY));
    await seedPairs(300, { firstSeenAt: () => shifted(since, -HOUR) });

    expect(await pass()).toMatchObject({ auto: 0, created: 0, stop: null });
    expect(await links()).toEqual([]);

    // A row first seen after the switch is the rule's.
    const fresh = await seedPair({ firstSeenAt: () => shifted(since, MINUTE) });
    expect(await pass()).toMatchObject({ auto: 1, created: 1 });
    expect(await linkedKeys()).toEqual([keyOf(fresh)]);
  });

  it('a new batch (spec §11.10): 120 new high rows make 50, 50, then 20 links, oldest first', async () => {
    await rule({ minSeverity: 'high' });
    const pairs = await seedPairs(120, { firstSeenAt: (i) => after((i + 1) * MINUTE) });
    const issuesBefore = fake.issues().length;
    expect(AUTO_PER_PASS).toBe(50);

    expect(await pass()).toMatchObject({ auto: 50, created: 50, stop: null });
    expect(await linkedKeys()).toEqual(sorted(pairs.slice(0, 50)));
    expect(await pass()).toMatchObject({ auto: 50, created: 50 });
    expect(await linkedKeys()).toEqual(sorted(pairs.slice(0, 100)));
    expect(await pass()).toMatchObject({ auto: 20, created: 20 });
    expect(await linkedKeys()).toEqual(sorted(pairs));
    expect(await pass()).toMatchObject({ auto: 0, created: 0 });
    expect(fake.issues()).toHaveLength(issuesBefore + 120);
  });

  it('the cap counts across the organisation: two projects of 30 new rows make 50, then 10', async () => {
    const other = (await h.project('JAUTO2')).id;
    const otherMain = await mainBranchId(db(), other);
    await mapJira(h, other);
    await seedCheck(db(), { projectId: other, branchId: otherMain, baselineAt: BASELINE });
    await rule({ minSeverity: 'high' });
    await rule({ minSeverity: 'critical' }, other);
    await seedPairs(30, { firstSeenAt: (i) => after((i + 1) * MINUTE) });
    await seedPairs(30, {
      projectId: other,
      branchId: otherMain,
      severity: 'critical',
      firstSeenAt: (i) => after((i + 1) * MINUTE),
    });

    expect(await auto()).toBe(50);
    expect(await auto()).toBe(10);
    expect(await auto()).toBe(0);
    const made = await links();
    expect(made.filter((l) => l.projectId === projectId)).toHaveLength(30);
    expect(made.filter((l) => l.projectId === other)).toHaveLength(30);
  });

  it("a new target's baseline: rows first seen at its first check open nothing", async () => {
    await rule({ minSeverity: 'high' });
    // Main is first checked after the rule's since (a newly tracked target, an SBOM upload,
    // monitoring switched on): its rows are the baseline, not new.
    const checked = after(HOUR);
    await baseline(checked);
    await seedPairs(5, { firstSeenAt: () => checked });
    expect(await auto()).toBe(0);

    const fresh = await seedPair({ firstSeenAt: () => after(2 * HOUR) });
    expect(await auto()).toBe(1);
    expect(await linkedKeys()).toEqual([keyOf(fresh)]);
  });

  it('lowering the threshold (spec §11.10) moves since: the medium rows seen before it open nothing', async () => {
    await mapJira(h, projectId, { autoCreate: { minSeverity: 'high', exploited: false } });
    const high = await storedSince();
    await baseline(shifted(high, -DAY));
    // Medium rows first seen just after the first since (1 ms: the stored value is in µs).
    const seen = shifted(high, 1);
    await seedPairs(5, { severity: 'medium', firstSeenAt: () => seen });
    expect(await auto()).toBe(0);
    // Under a medium rule from that first since, they would all qualify.
    const asSaved = (await mappingOf(db(), projectId))!;
    expect(
      await qualifyingPairs(
        db(),
        { ...asSaved, autoMinSeverity: 'medium' },
        { exploited: false, limit: AUTO_PER_PASS, tracker: 'jira' },
      ),
    ).toHaveLength(5);

    await mapJira(h, projectId, { autoCreate: { minSeverity: 'medium', exploited: false } });
    const medium = await storedSince();
    expect(medium.getTime()).toBeGreaterThan(seen.getTime());
    expect(await auto()).toBe(0);

    const fresh = await seedPair({
      severity: 'medium',
      firstSeenAt: () => shifted(medium, MINUTE),
    });
    expect(await auto()).toBe(1);
    expect(await linkedKeys()).toEqual([keyOf(fresh)]);
  });

  it('dismissed never comes back (spec §11.10): a link row in any state keeps the rule away', async () => {
    await rule({ minSeverity: 'high' });
    const states: JiraLinkState[] = ['dismissed', 'failed', 'missing', 'pending', 'created'];
    const seeded = new Map<string, JiraLinkState>();
    for (const [i, state] of states.entries()) {
      const pair = await seedPair({ firstSeenAt: () => after(MINUTE) });
      const jira =
        state === 'created' || state === 'missing'
          ? { jiraIssueId: String(20_000 + i), jiraKey: `QUAL-${900 + i}` }
          : {};
      const id = await seedJiraLink(db(), { projectId, connectionId, ...pair, state, ...jira });
      seeded.set(id, state);
    }

    expect(await auto()).toBe(0);
    const kept = await links();
    expect(kept).toHaveLength(states.length);
    for (const l of kept) {
      expect(l).toMatchObject({ state: seeded.get(l.id), origin: 'manual', generation: 1 });
    }

    const unlinked = await seedPair({ firstSeenAt: () => after(MINUTE) });
    expect(await auto()).toBe(1);
    expect(await linkedKeys()).toHaveLength(states.length + 1);
    expect(await linkedKeys()).toContain(keyOf(unlinked));
  });

  it('a pair whose Azure Boards link failed before its work item was made qualifies; outcome_unknown, a work item or a dismissal keeps the rule away', async () => {
    await rule({ minSeverity: 'high' });
    const azure = await azureConnection(db(), {
      organizationId: h.organizationId,
      baseUrl: 'https://dev.azure.com/jauto-boards',
      secretKey: h.ctx.config.secretKey,
    });
    const inBoards = async (over: Partial<typeof boardsLinks.$inferInsert>) => {
      const pair = await seedPair({ firstSeenAt: () => after(MINUTE) });
      await db()
        .insert(boardsLinks)
        .values({
          projectId,
          connectionId: azure.id,
          azureProjectId: '6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c',
          kind: 'vulnerability',
          ...pair,
          state: 'failed',
          origin: 'manual',
          ...over,
        });
      return pair;
    };
    const neverMade = await inBoards({ failure: { code: 'type_unsupported', message: 'x' } });
    await inBoards({ failure: { code: 'outcome_unknown', message: 'x' } });
    await inBoards({ failure: { code: 'field_refused', message: 'x' }, workItemId: 4 });
    await inBoards({ state: 'dismissed' });

    expect(await auto()).toBe(1);
    expect(await linkedKeys()).toEqual([keyOf(neverMade)]);
    expect(await auto()).toBe(0);
  });

  it('unknown never qualifies by severity', async () => {
    await rule({ minSeverity: 'low' });
    await seedPair({ severity: 'unknown', firstSeenAt: () => after(MINUTE) });
    expect(await auto()).toBe(0);

    const low = await seedPair({ severity: 'low', firstSeenAt: () => after(MINUTE) });
    expect(await auto()).toBe(1);
    expect(await linkedKeys()).toEqual([keyOf(low)]);
  });

  it('triaged, ignored or untracked: a false positive, an ignored row and a row off the tracked targets open nothing', async () => {
    await rule({ minSeverity: 'high' });
    const triaged = await seedPair({ firstSeenAt: () => after(MINUTE) });
    await db()
      .insert(vulnerabilityDecisions)
      .values({ projectId, ...triaged, status: 'false_positive', decidedBy: adminId });
    await seedPair({ ignored: true, firstSeenAt: () => after(MINUTE) });
    const [feature] = await db()
      .insert(branches)
      .values({ projectId, kind: 'branch', name: 'feature/auto', isMain: false })
      .returning({ id: branches.id });
    await seedCheck(db(), { projectId, branchId: feature!.id, baselineAt: BASELINE });
    await seedPair({ branchId: feature!.id, firstSeenAt: () => after(MINUTE) });
    expect(await auto()).toBe(0);

    const open = await seedPair({ firstSeenAt: () => after(MINUTE) });
    expect(await auto()).toBe(1);
    expect(await linkedKeys()).toEqual([keyOf(open)]);
  });

  it('versions: a new row on a tracked version qualifies, one on a version no longer tracked does not', async () => {
    await rule({ minSeverity: 'high' });
    const tracked = await seedVersion('2.0.0', 'pinned');
    const dropped = await seedVersion('1.0.0', 'unsupported');
    const onTracked = freshPair();
    await seedTargetRow(db(), {
      projectId,
      versionId: tracked,
      ...onTracked,
      firstSeenAt: after(MINUTE),
    });
    await seedTargetRow(db(), {
      projectId,
      versionId: dropped,
      ...freshPair(),
      firstSeenAt: after(MINUTE),
    });

    expect(await auto()).toBe(1);
    expect(await linkedKeys()).toEqual([keyOf(onTracked)]);
  });

  it('a target tracked again (ruling T9b): the rows its re-check adds are new, capped like any other', async () => {
    await rule({ minSeverity: 'high' });
    // Checked long before since, then not tracked any more; its baseline row is kept.
    const version = await seedVersion('3.0.0', 'unsupported');
    const kept = freshPair();
    await seedTargetRow(db(), { projectId, versionId: version, ...kept, firstSeenAt: BASELINE });
    expect(await auto()).toBe(0);

    // Tracked again after since: the re-check diffs against the kept rows, so what it adds is
    // first seen then, after the old baseline: new, as the tab counts it.
    await db()
      .update(projectVersions)
      .set({ tracking: 'pinned' })
      .where(eq(projectVersions.id, version));
    const added = [freshPair(), freshPair(), freshPair()];
    for (const [i, pair] of added.entries()) {
      await seedTargetRow(db(), {
        projectId,
        versionId: version,
        ...pair,
        firstSeenAt: after(HOUR + i * MINUTE),
      });
    }

    const ctx = await context();
    expect(await runAutoRule(ctx, 2)).toBe(2);
    expect(await linkedKeys()).toEqual(sorted(added.slice(0, 2)));
    expect(await runAutoRule(ctx, 2)).toBe(1);
    expect(await runAutoRule(ctx, 2)).toBe(0);
    expect(await linkedKeys()).toEqual(sorted(added));
  });

  it("exploited: CISA's date_added on or after the day of since, or a new row of any severity; never Qualor's listed_at", async () => {
    await rule({ exploited: true });
    const old = () => new Date(BASELINE.getTime() - DAY);
    // Listed on the day of since (before its time of day), with only an old row: qualifies.
    const sameDay = await seedPair({ severity: 'low', firstSeenAt: old });
    await kev(sameDay.vulnerabilityId, dayOf(SINCE));
    // Listed the day before, no new row: nothing.
    const dayBefore = await seedPair({ firstSeenAt: old });
    await kev(dayBefore.vulnerabilityId, dayOf(new Date(SINCE.getTime() - DAY)));
    // The KEV table filled again today (listed_at now) with an old date_added: nothing.
    const refilled = await seedPair({ firstSeenAt: old });
    await kev(refilled.vulnerabilityId, '2021-12-10');
    // An old listing whose pair has a new row, of a severity no threshold takes: qualifies.
    const fresh = await seedPair({ severity: 'unknown', firstSeenAt: () => after(MINUTE) });
    await kev(fresh.vulnerabilityId, '2021-12-10');
    // Delisted since: nothing.
    const delisted = await seedPair({ firstSeenAt: old });
    await kev(delisted.vulnerabilityId, dayOf(after(DAY)), new Date());
    // A new row not in the catalogue, with no threshold: nothing.
    await seedPair({ firstSeenAt: () => after(MINUTE) });
    // Listed on the day of since, but its only row triaged, or ignored: nothing.
    const triaged = await seedPair({ firstSeenAt: old });
    await kev(triaged.vulnerabilityId, dayOf(SINCE));
    await db()
      .insert(vulnerabilityDecisions)
      .values({ projectId, ...triaged, status: 'wont_fix', decidedBy: adminId });
    const ignored = await seedPair({ ignored: true, firstSeenAt: old });
    await kev(ignored.vulnerabilityId, dayOf(SINCE));

    expect(await auto(priority())).toBe(2);
    expect(await linkedKeys()).toEqual(sorted([sameDay, fresh]));
  });

  it('lapse and return (spec §11.11): a stored exploited creates nothing without vuln.priority; back, only what its since admits', async () => {
    await rule({ minSeverity: 'high', exploited: true });
    const old = () => new Date(BASELINE.getTime() - DAY);
    const dated = await seedPair({ severity: 'low', firstSeenAt: old });
    await kev(dated.vulnerabilityId, dayOf(after(DAY)));
    const backlog = await seedPair({ firstSeenAt: old });
    await kev(backlog.vulnerabilityId, dayOf(new Date(SINCE.getTime() - 365 * DAY)));
    const severe = await seedPair({ firstSeenAt: () => after(MINUTE) });

    // Community: the threshold still applies, the exploited part does not.
    expect(await pass()).toMatchObject({ auto: 1, created: 1 });
    expect(await linkedKeys()).toEqual([keyOf(severe)]);
    expect(await auto()).toBe(0);

    // vuln.priority back: the KEV rows filled again bring only the pair dated after since.
    expect(await auto(priority())).toBe(1);
    expect(await linkedKeys()).toEqual(sorted([severe, dated]));
    expect(await auto(priority())).toBe(0);
  });

  it('monitoring off for the project or the instance: nothing', async () => {
    await rule({ minSeverity: 'high' });
    const fresh = await seedPair({ firstSeenAt: () => after(MINUTE) });
    await monitoring(false);
    expect(await auto()).toBe(0);
    await monitoring(true);
    await writeVulndbSettings(db(), { enabled: false }, h.ctx.config.secretKey);
    try {
      expect(await auto()).toBe(0);
    } finally {
      await writeVulndbSettings(db(), { enabled: true }, h.ctx.config.secretKey);
    }
    expect(await links()).toEqual([]);

    expect(await auto()).toBe(1);
    expect(await linkedKeys()).toEqual([keyOf(fresh)]);
  });

  it('off: a mapping without a rule makes nothing', async () => {
    await seedPair({ firstSeenAt: () => after(MINUTE) });
    expect(await auto(priority())).toBe(0);
    await rule({ minSeverity: 'high' });
    expect(await auto(priority())).toBe(1);
  });

  it('rows: pending, origin auto, no created_by, no audit; one full pass creates them', async () => {
    await rule({ minSeverity: 'high' });
    const pairs = await seedPairs(3, { firstSeenAt: (i) => after((i + 1) * MINUTE) });
    const audited = (await db().select().from(auditEvents)).length;

    // The rule alone leaves them pending, for the create step.
    expect(await auto(), 'made by the rule').toBe(3);
    const pending = await links();
    expect(pending.map((l) => [l.state, l.origin, l.createdBy, l.attemptedAt])).toEqual(
      Array.from({ length: 3 }, () => ['pending', 'auto', null, null]),
    );
    await db().delete(jiraLinks);

    expect(await pass()).toMatchObject({ auto: 3, created: 3, stop: null });
    expect(await linkedKeys()).toEqual(sorted(pairs));
    for (const l of await links()) {
      expect(l).toMatchObject({ state: 'created', origin: 'auto', createdBy: null });
      expect(fake.issue(l.jiraKey!)).toBeDefined();
    }
    expect((await db().select().from(auditEvents)).length).toBe(audited);
  });
});
