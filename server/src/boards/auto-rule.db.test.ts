import { eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { azureServerConfig, servicesUrlOf } from '../../test/azure';
import { boardsJobDeps } from '../../test/boards';
import {
  createFakeAzureDevOps,
  type FakeAzureDevOps,
  type FakeAzureProject,
} from '../../test/fake-azure-devops';
import { createFakeJira, type FakeJira } from '../../test/fake-jira';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { connectJira, jiraTestConfig, seedJiraLink } from '../../test/jira';
import { seedCheck, seedTargetRow } from '../../test/vulnerabilities';
import type { Db } from '../db/client';
import {
  auditEvents,
  boardsLinks,
  jiraConnections,
  jobs,
  projectBoardsSettings,
  projectVulnerabilitySettings,
  scmConnections,
  targetVulnerabilities,
  users,
  vulnerabilityKev,
  vulnerabilityTargetChecks,
  type JiraAutoSeverity,
} from '../db/schema';
import { AUTO_PER_PASS, qualifyingPairs } from '../jira/auto-rule';
import { communityLimits } from '../limits';
import { runBoardsAutoRule } from './auto-rule';
import { insertPendingBoardsLinks } from './links';
import { openBoardsRun, type BoardsJobDeps } from './run';
import { runBoardsPass } from './sync';

const BUG = 'Microsoft.VSTS.WorkItemTypes.Bug';
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
/** The rule's `since` where a test sets it directly: a week ago, at a time of day not midnight. */
const SINCE = new Date(Math.floor((Date.now() - 7 * DAY) / DAY) * DAY + 10 * HOUR);
/** The main branch's baseline: a row first seen after it is new. */
const BASELINE = new Date(SINCE.getTime() - 7 * DAY);
const after = (ms: number) => new Date(SINCE.getTime() + ms);

interface Pair {
  packageName: string;
  vulnerabilityId: string;
}

describe('the automatic Boards rule (design §7.8, plan Task 7)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let jira: FakeJira;
  let payments: FakeAzureProject;
  let projectId: string;
  let main: string;
  let adminId: string;
  let connectionId: string;
  let deps: BoardsJobDeps;
  let pkgs = 0;

  const db = (): Db => h.ctx.db;
  const freshPair = (): Pair => ({
    packageName: `pkg-bauto-${++pkgs}`,
    vulnerabilityId: `CVE-2026-${20_000 + pkgs}`,
  });
  const keyOf = (p: Pair) => `${p.packageName} ${p.vulnerabilityId}`;
  /** `n` pairs, each with one high row on main (unless given), the i-th first seen at `firstSeenAt(i)`. */
  const seedPairs = async (
    n: number,
    row: { firstSeenAt: (i: number) => Date; projectId?: string; branchId?: string },
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
          severity: 'high',
          firstSeenAt: row.firstSeenAt(i),
        },
        { recheck: false },
      );
      pairs.push(pair);
    }
    return pairs;
  };
  const map = (project: string, azureProjectId = payments.id) =>
    db().insert(projectBoardsSettings).values({
      projectId: project,
      connectionId,
      azureProjectId,
      azureProjectName: 'Payments',
      workItemTypeRef: BUG,
      workItemTypeName: 'Bug',
    });
  const rule = (
    set: { minSeverity?: JiraAutoSeverity | null; exploited?: boolean; since?: Date | 'now' },
    project = projectId,
  ) =>
    db()
      .update(projectBoardsSettings)
      .set({
        autoMinSeverity: set.minSeverity ?? null,
        autoExploited: set.exploited ?? false,
        autoSince: set.since === 'now' ? sql`now()` : (set.since ?? SINCE),
      })
      .where(eq(projectBoardsSettings.projectId, project));
  const storedSince = async (): Promise<Date> => {
    const [row] = await db()
      .select({ since: projectBoardsSettings.autoSince })
      .from(projectBoardsSettings)
      .where(eq(projectBoardsSettings.projectId, projectId));
    return row!.since!;
  };
  const priority = (): Partial<BoardsJobDeps> => {
    const limits = communityLimits();
    return { limits: () => ({ vulnerabilities: { ...limits.vulnerabilities, priority: true } }) };
  };
  const context = async (over: Partial<BoardsJobDeps> = {}) =>
    (await openBoardsRun({ ...deps, ...over }, connectionId))!;
  const auto = async (over: Partial<BoardsJobDeps> = {}) => runBoardsAutoRule(await context(over));
  const links = () => db().select().from(boardsLinks).where(eq(boardsLinks.kind, 'vulnerability'));
  const linkedKeys = async () =>
    (await links())
      .map((l) => keyOf({ packageName: l.packageName!, vulnerabilityId: l.vulnerabilityId! }))
      .sort();

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({ deployment: 'services' });
    payments = fake.addProject({ name: 'Payments', process: 'agile' });
    jira = await createFakeJira({ deployment: 'data_center' });
    jira.addProject({ id: '10000', key: 'QUAL', name: 'Qualor findings' });
    h = await createIngestHarness({
      config: { ...azureServerConfig(fake), ...jiraTestConfig(jira) },
    });
    projectId = (await h.project('BAUTO')).id;
    main = await mainBranchId(db(), projectId);
    adminId = (await db().select().from(users).where(eq(users.username, 'ingest-admin')))[0]!.id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
    await jira.close();
  });
  beforeEach(async () => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'azure',
        baseUrl: servicesUrlOf(fake),
        azureAuth: 'pat',
        token: fake.pat,
      },
    });
    expect(res.statusCode, res.body).toBe(201);
    connectionId = (res.json() as { id: string }).id;
    await map(projectId);
    await db()
      .insert(projectVulnerabilitySettings)
      .values({ projectId, enabled: true })
      .onConflictDoUpdate({
        target: projectVulnerabilitySettings.projectId,
        set: { enabled: true },
      });
    await seedCheck(db(), { projectId, branchId: main, baselineAt: BASELINE });
    deps = boardsJobDeps(h);
    fake.clearRequests();
  });
  afterEach(async () => {
    await db().delete(scmConnections);
    await db().delete(jiraConnections);
    // The Boards jobs, and the Jira pass a Jira connection queues.
    await db().delete(jobs);
    await db().delete(targetVulnerabilities);
    await db().delete(vulnerabilityTargetChecks);
    await db().delete(vulnerabilityKev);
  });

  it('no backlog: switched on over 300 new high rows first seen before it, it opens nothing', async () => {
    await rule({ minSeverity: 'high', since: 'now' });
    const since = await storedSince();
    await db()
      .update(vulnerabilityTargetChecks)
      .set({ baselineAt: new Date(since.getTime() - DAY) })
      .where(eq(vulnerabilityTargetChecks.branchId, main));
    await seedPairs(300, { firstSeenAt: () => new Date(since.getTime() - HOUR) });

    expect(await runBoardsPass(await context())).toMatchObject({
      auto: 0,
      created: 0,
      stop: null,
    });
    expect(await links()).toEqual([]);
    expect(fake.requests).toHaveLength(0);

    // A row first seen after the switch is the rule's, created in the same pass.
    const [fresh] = await seedPairs(1, { firstSeenAt: () => new Date(since.getTime() + MINUTE) });
    expect(await runBoardsPass(await context())).toMatchObject({ auto: 1, created: 1 });
    expect(await linkedKeys()).toEqual([keyOf(fresh!)]);
  });

  it('the auto rule skips a pair with a Jira link and one with a dismissed Boards link', async () => {
    await rule({ minSeverity: 'high' });
    const [inJira, dismissed, free] = await seedPairs(3, {
      firstSeenAt: (i) => after((i + 1) * MINUTE),
    });
    const jiraConnectionId = await connectJira(h, jira);
    await seedJiraLink(db(), { projectId, connectionId: jiraConnectionId, ...inJira! });
    const [old] = await insertPendingBoardsLinks(
      db(),
      { projectId, connectionId, azureProjectId: payments.id, userId: adminId },
      [{ kind: 'vulnerability', ...dismissed! }],
    );
    await db().update(boardsLinks).set({ state: 'dismissed' }).where(eq(boardsLinks.id, old!.id));
    const audited = (await db().select().from(auditEvents)).length;

    // A cap of one: the linked pairs (first seen earlier) take no place of the free one.
    expect(await runBoardsAutoRule(await context(), 1)).toBe(1);
    const made = (await links()).filter((l) => l.id !== old!.id);
    expect(made).toHaveLength(1);
    expect(made[0]).toMatchObject({
      ...free,
      state: 'pending',
      origin: 'auto',
      createdBy: null,
      attemptedAt: null,
      connectionId,
      azureProjectId: payments.id,
    });
    expect(await db().select().from(boardsLinks).where(eq(boardsLinks.id, old!.id))).toEqual([
      expect.objectContaining({ state: 'dismissed', origin: 'manual' }),
    ]);
    expect((await db().select().from(auditEvents)).length).toBe(audited);
    expect(await auto()).toBe(0);

    // Jira's rule asks the same: a pair with a Boards link row (any state) is not Jira's either.
    const asJira = { projectId, autoMinSeverity: 'high' as const, autoSince: SINCE };
    expect(await qualifyingPairs(db(), asJira, { exploited: false, limit: AUTO_PER_PASS })).toEqual(
      [],
    );
    await db().delete(boardsLinks);
    expect(
      (await qualifyingPairs(db(), asJira, { exploited: false, limit: AUTO_PER_PASS }))
        .map(keyOf)
        .sort(),
    ).toEqual([dismissed!, free!].map(keyOf).sort());
  });

  it("the cap counts across the connection's mapped projects: two projects of 30 make 50, then 10", async () => {
    const other = (await h.project('BAUTO2')).id;
    const otherMain = await mainBranchId(db(), other);
    await map(other);
    await seedCheck(db(), { projectId: other, branchId: otherMain, baselineAt: BASELINE });
    await rule({ minSeverity: 'high' });
    await rule({ minSeverity: 'high' }, other);
    await seedPairs(30, { firstSeenAt: (i) => after((i + 1) * MINUTE) });
    await seedPairs(30, {
      projectId: other,
      branchId: otherMain,
      firstSeenAt: (i) => after((i + 1) * MINUTE),
    });

    expect(await auto()).toBe(50);
    expect(await auto()).toBe(10);
    expect(await auto()).toBe(0);
    const made = await links();
    expect(made.filter((l) => l.projectId === projectId)).toHaveLength(30);
    expect(made.filter((l) => l.projectId === other)).toHaveLength(30);
  });

  it('exploited applies only while vuln.priority is active', async () => {
    await rule({ exploited: true });
    const [pair] = await seedPairs(1, { firstSeenAt: () => after(MINUTE) });
    await db()
      .insert(vulnerabilityKev)
      .values({
        vulnerabilityId: pair!.vulnerabilityId,
        dateAdded: SINCE.toISOString().slice(0, 10),
      });
    expect(await auto()).toBe(0);
    expect(await auto(priority())).toBe(1);
    expect(await linkedKeys()).toEqual([keyOf(pair!)]);
  });
});
