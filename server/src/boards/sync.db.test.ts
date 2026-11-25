import { and, eq, inArray, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { azureServerConfig, servicesUrlOf } from '../../test/azure';
import { boardsJobDeps, runBoardsJobs } from '../../test/boards';
import {
  createFakeAzureDevOps,
  recordedAnswer,
  type FakeAzureDevOps,
  type FakeAzureProject,
} from '../../test/fake-azure-devops';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { seedCheck, seedTargetRow } from '../../test/vulnerabilities';
import type { PgUpdateSetSource } from 'drizzle-orm/pg-core';
import type { Db } from '../db/client';
import {
  analyses,
  boardsLinks,
  issues,
  jobs,
  projectBoardsSettings,
  projectVulnerabilitySettings,
  scmConnections,
  targetVulnerabilities,
  users,
  vulnerabilityTargetChecks,
} from '../db/schema';
import type { WorkerLogger } from '../queue/worker';
import type { AzureJsonPatch } from '../scm/azure/client';
import { recordScmProblem } from '../scm/problems';
import { keyOfDescription } from './content';
import { BOARDS_FAILURE_TEXT, createPendingWorkItems } from './create';
import { BOARDS_QUEUE, boardsSyncKey, scheduleBoardsSync } from './jobs';
import { insertPendingBoardsLinks } from './links';
import { openBoardsRun, type BoardsJobDeps, type BoardsRunContext } from './run';
import { PASS_BUDGET, runBoardsPass, STATE_PER_PASS, type BoardsPassOutcome } from './sync';

const PUBLIC_URL = 'https://qualor.example.com';
const BUG = 'Microsoft.VSTS.WorkItemTypes.Bug';
const CREATE_PATH = /\/_apis\/wit\/workitems\/\$/;
const TYPES_PATH = /\/_apis\/wit\/workitemtypes$/;
const WIQL_PATH = /\/_apis\/wit\/wiql$/;
const BATCH_PATH = /\/_apis\/wit\/workitemsbatch$/;
const PATCH_PATH = /\/_apis\/wit\/workitems\/\d+$/;
const PROJECTS_PATH = /^\/_apis\/projects$/;
const STATE_FIELDS = ['System.State', 'System.TeamProject', 'System.WorkItemType', 'System.Tags'];
const DAY = 24 * 3_600_000;

describe('the Boards pass (design §7.8, plan Task 7)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let payments: FakeAzureProject;
  let basic: FakeAzureProject;
  let projectId: string;
  let main: string;
  let codeRule: string;
  let adminId: string;
  let connectionId: string;
  let deps: BoardsJobDeps;
  let pkgs = 0;

  const db = (): Db => h.ctx.db;
  const issue = (message = 'finding', status?: 'closed') =>
    seedIssue(db(), {
      projectId,
      branchId: main,
      ruleId: codeRule,
      message,
      ...(status === undefined ? {} : { status }),
    });
  /** Pending code-issue links (no create job queued); their ids. */
  const pending = async (issueIds: string[]): Promise<string[]> =>
    (
      await insertPendingBoardsLinks(
        db(),
        { projectId, connectionId, azureProjectId: payments.id, userId: adminId },
        issueIds.map((issueId) => ({ kind: 'issue' as const, issueId })),
      )
    ).map((r) => r.id);
  const row = async (id: string) =>
    (await db().select().from(boardsLinks).where(eq(boardsLinks.id, id)))[0]!;
  const setRow = (id: string, set: PgUpdateSetSource<typeof boardsLinks>) =>
    db().update(boardsLinks).set(set).where(eq(boardsLinks.id, id));
  const connection = async () =>
    (await db().select().from(scmConnections).where(eq(scmConnections.id, connectionId)))[0]!;
  const context = async (over: Partial<BoardsJobDeps> = {}): Promise<BoardsRunContext> =>
    (await openBoardsRun({ ...deps, ...over }, connectionId))!;
  const runPass = async (over: Partial<BoardsJobDeps> = {}): Promise<BoardsPassOutcome> =>
    runBoardsPass(await context(over));
  const creates = () =>
    fake.requests.filter((r) => r.method === 'POST' && CREATE_PATH.test(r.path));
  const keyOf = (linkId: string, generation = 1) =>
    `qualor-${linkId.replaceAll('-', '')}-${generation}`;
  /** The send `minutes` ago, stamped to the millisecond as a create run stamps it. */
  const sentAgo = (linkId: string, minutes: number) =>
    setRow(linkId, {
      attemptedAt: sql`date_trunc('milliseconds', now() - make_interval(mins => ${minutes}))`,
    });
  /**
   * A lost create: Azure DevOps makes the work item, the answer never comes; the row is left
   * pending with `attempted_at`.
   */
  const lostCreate = async (): Promise<{ linkId: string; itemId: number }> => {
    const [linkId] = await pending([await issue('lost')]);
    fake.inject('POST', CREATE_PATH, { status: 200, afterCreate: 'reset' });
    await createPendingWorkItems(await context());
    const stored = await row(linkId!);
    expect(stored).toMatchObject({ state: 'pending' });
    expect(stored.attemptedAt).not.toBeNull();
    return { linkId: linkId!, itemId: fake.workItems().at(-1)!.id };
  };
  const ops = (title: string): AzureJsonPatch[] => [
    { op: 'add', path: '/fields/System.Title', value: title },
    { op: 'add', path: '/fields/System.Description', value: '<p>Made by a test</p>' },
    { op: 'add', path: '/fields/System.Tags', value: 'qualor' },
  ];
  /** `n` Bugs in Payments made by the connection's identity; their ids. */
  const workItems = async (n: number): Promise<number[]> => {
    const ids: number[] = [];
    let ctx = await context();
    for (let i = 0; i < n; i++) {
      if (ctx.client.remaining === 0) ctx = await context();
      ids.push((await ctx.client.createWorkItem(payments.id, 'Bug', ops(`item ${i}`))).id);
    }
    return ids;
  };
  /** A created code-issue link for each work item (its issue `status`); their ids. */
  const createdLinks = async (
    itemIds: number[],
    status: 'open' | 'closed' = 'open',
  ): Promise<{ linkId: string; issueId: string }[]> => {
    const issueIds: string[] = [];
    for (const [i] of itemIds.entries()) {
      issueIds.push(await issue(`created ${i}`, status === 'closed' ? 'closed' : undefined));
    }
    const made = await db()
      .insert(boardsLinks)
      .values(
        itemIds.map((workItemId, i) => ({
          projectId,
          connectionId,
          azureProjectId: payments.id,
          kind: 'issue' as const,
          issueId: issueIds[i]!,
          state: 'created' as const,
          origin: 'manual' as const,
          workItemId,
          stateName: 'New',
          stateCategory: 'proposed' as const,
        })),
      )
      .returning({ id: boardsLinks.id, issueId: boardsLinks.issueId });
    return made.map((m) => ({ linkId: m.id, issueId: m.issueId! }));
  };
  const close = (issueIds: string[], at: string) =>
    db()
      .update(issues)
      .set({ status: 'closed', closedAt: new Date(at) })
      .where(inArray(issues.id, issueIds));
  /** Open again, last seen by a succeeded analysis of `at`. */
  const reopen = async (issueId: string, at: string) => {
    const [analysis] = await db()
      .insert(analyses)
      .values({
        projectId,
        branchId: main,
        status: 'succeeded',
        revision: 'c'.repeat(40),
        analysisDate: new Date(at),
        baselineStatus: 'first_analysis',
        scannerVersion: '0.0.0-test',
      })
      .returning({ id: analyses.id });
    await db()
      .update(issues)
      .set({ status: 'open', closedAt: null, lastSeenAnalysisId: analysis!.id })
      .where(eq(issues.id, issueId));
  };
  const monitoring = (enabled: boolean) =>
    db()
      .insert(projectVulnerabilitySettings)
      .values({ projectId, enabled })
      .onConflictDoUpdate({ target: projectVulnerabilitySettings.projectId, set: { enabled } });
  const freshPair = () => ({
    packageName: `pkg-pass-${++pkgs}`,
    vulnerabilityId: `CVE-2026-${7_000 + pkgs}`,
  });
  const capture = () => {
    const lines: [string, ...unknown[]][] = [];
    const logger: WorkerLogger = {
      info: (...a: unknown[]) => void lines.push(['info', ...a]),
      warn: (...a: unknown[]) => void lines.push(['warn', ...a]),
      error: (...a: unknown[]) => void lines.push(['error', ...a]),
    };
    return { lines, logger };
  };

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({ deployment: 'services' });
    payments = fake.addProject({ name: 'Payments', process: 'agile' });
    basic = fake.addProject({ name: 'Basic', process: 'basic' });
    h = await createIngestHarness({
      config: { ...azureServerConfig(fake), publicUrl: PUBLIC_URL },
    });
    projectId = (await h.project('BPASS')).id;
    main = await mainBranchId(db(), projectId);
    codeRule = await seedRule(db(), { key: 'eslint:no-eval', name: 'No eval' });
    adminId = (await db().select().from(users).where(eq(users.username, 'ingest-admin')))[0]!.id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
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
    await db().insert(projectBoardsSettings).values({
      projectId,
      connectionId,
      azureProjectId: payments.id,
      azureProjectName: 'Payments',
      workItemTypeRef: BUG,
      workItemTypeName: 'Bug',
    });
    await monitoring(true);
    deps = boardsJobDeps(h);
    fake.clearRequests();
  });
  afterEach(async () => {
    await db().delete(scmConnections);
    await db().delete(jobs).where(eq(jobs.queue, BOARDS_QUEUE));
    await db().delete(targetVulnerabilities);
    await db().delete(vulnerabilityTargetChecks);
  });

  it('reconcile (spec §7.8): a lost create is found by its tag and key, one work item', async () => {
    const { linkId, itemId } = await lostCreate();
    fake.clearRequests();
    // Under 2 minutes it is not looked for yet.
    expect(await runPass()).toMatchObject({ reconciled: 0, stop: null });
    expect(fake.requests).toHaveLength(0);

    await sentAgo(linkId, 3);
    const sent = (await row(linkId)).attemptedAt!;
    expect(await runPass()).toMatchObject({ reconciled: 1, created: 0, stop: null });
    expect(await row(linkId)).toMatchObject({
      state: 'created',
      workItemId: itemId,
      stateName: 'New',
      stateCategory: 'proposed',
      failure: null,
    });
    expect(
      fake.workItems().filter((w) => keyOfDescription(w.description) === keyOf(linkId)),
    ).toHaveLength(1);
    expect(creates()).toHaveLength(0);

    // Part B f: the WIQL by tag, identity and time (ms, UTC, a minute before the send) on the
    // link's project, then one batch read with the descriptions.
    const [wiql] = fake.requests.filter((r) => WIQL_PATH.test(r.path));
    expect(wiql!.path).toBe(`/${payments.id}/_apis/wit/wiql`);
    const since = new Date(sent.getTime() - 60_000).toISOString();
    expect((JSON.parse(wiql!.body) as { query: string }).query).toBe(
      `SELECT [System.Id] FROM WorkItems WHERE [System.TeamProject] = @project AND [System.Tags] CONTAINS 'qualor' AND [System.CreatedBy] = @Me AND [System.CreatedDate] >= '${since}' ORDER BY [System.Id] DESC`,
    );
    const [batch] = fake.requests.filter((r) => BATCH_PATH.test(r.path));
    expect((JSON.parse(batch!.body) as { fields: string[] }).fields).toContain(
      'System.Description',
    );
  });

  it('a lost create not found waits at 3 minutes and is resent after 10', async () => {
    const { linkId, itemId } = await lostCreate();
    fake.deleteWorkItem(itemId); // Azure DevOps never made it.
    await sentAgo(linkId, 3);
    fake.clearRequests();
    await runPass();
    expect(await row(linkId)).toMatchObject({ state: 'pending' });
    expect((await row(linkId)).attemptedAt).not.toBeNull();
    expect(creates()).toHaveLength(0);

    await sentAgo(linkId, 11);
    fake.clearRequests();
    // Reset by reconcile, sent again by the create step of the same pass.
    expect(await runPass()).toMatchObject({ reconciled: 0, created: 1, stop: null });
    expect(creates()).toHaveLength(1);
    const stored = await row(linkId);
    expect(stored.state).toBe('created');
    expect(stored.workItemId).not.toBe(itemId);
  });

  it('a person removed the key → resend after 10 minutes, the old item not adopted', async () => {
    const { linkId, itemId } = await lostCreate();
    fake.workItem(itemId).description = '<p>Rewritten by a person </p>';
    await sentAgo(linkId, 3);
    await runPass();
    expect(await row(linkId)).toMatchObject({ state: 'pending', workItemId: null });

    await sentAgo(linkId, 11);
    fake.clearRequests();
    await runPass();
    expect(creates()).toHaveLength(1);
    const stored = await row(linkId);
    expect(stored.state).toBe('created');
    expect(stored.workItemId).not.toBe(itemId);
    expect(fake.workItem(itemId).description).toBe('<p>Rewritten by a person </p>');
  });

  it('a row a create run sent again between the read and the reset is not reset', async () => {
    const { linkId, itemId } = await lostCreate();
    fake.deleteWorkItem(itemId);
    await sentAgo(linkId, 11);
    // A create run takes the row again and stamps its send while the WIQL is on its way.
    let stamped: Date | null = null;
    fake.inject('POST', WIQL_PATH, {
      status: 200,
      passThrough: true,
      before: async () => {
        await setRow(linkId, { attemptedAt: sql`date_trunc('milliseconds', now())` });
        stamped = (await row(linkId)).attemptedAt;
      },
    });
    fake.clearRequests();
    await runPass();
    const stored = await row(linkId);
    expect(stored.state).toBe('pending');
    expect(stored.attemptedAt).toEqual(stamped);
    expect(creates()).toHaveLength(0);
  });

  it('the WIQL refused (400) → failed outcome_unknown; a full WIQL answer cannot tell either', async () => {
    const refused = await lostCreate();
    await sentAgo(refused.linkId, 3);
    fake.inject('POST', WIQL_PATH, recordedAnswer('services', '30-pat-f-wiql-plain-time'));
    expect(await runPass()).toMatchObject({ reconciled: 0, stop: null });
    expect(await row(refused.linkId)).toMatchObject({
      state: 'failed',
      failure: { code: 'outcome_unknown', message: BOARDS_FAILURE_TEXT.outcome_unknown },
    });
    expect((await connection()).problem).toBeNull();

    // 200 newer work items of Qualor's: the oldest is cut off the answer, so a stale row is not
    // sent again blindly.
    const cut = await lostCreate();
    fake.deleteWorkItem(cut.itemId);
    await workItems(200);
    await sentAgo(cut.linkId, 11);
    fake.clearRequests();
    await runPass();
    expect(await row(cut.linkId)).toMatchObject({
      state: 'failed',
      failure: { code: 'outcome_unknown' },
    });
    expect(creates()).toHaveLength(0);
  });

  it('states read in batches of 200, with the category', async () => {
    const ids = await workItems(201);
    const links = await createdLinks(ids);
    const states = ['Active', 'Resolved', 'Closed', 'Strange'];
    for (const [i, state] of states.entries()) fake.workItem(ids[i]!).state = state;
    fake.clearRequests();
    expect(await runPass()).toMatchObject({ states: 201, missing: 0, notes: 0, stop: null });

    const batches = fake.requests.filter((r) => BATCH_PATH.test(r.path));
    const bodies = batches.map((b) => JSON.parse(b.body) as { ids: number[]; fields: string[] });
    expect(bodies.map((b) => b.ids.length)).toEqual([200, 1]);
    expect(bodies.every((b) => JSON.stringify(b.fields) === JSON.stringify(STATE_FIELDS))).toBe(
      true,
    );
    expect(batches[0]!.path).toBe('/_apis/wit/workitemsbatch');
    expect(fake.countRequests('GET', TYPES_PATH)).toBe(1);
    const expected = [
      ['Active', 'inprogress'],
      ['Resolved', 'resolved'],
      ['Closed', 'completed'],
      ['Strange', null],
    ];
    for (const [i, [name, category]] of expected.entries()) {
      expect(await row(links[i]!.linkId)).toMatchObject({
        stateName: name,
        stateCategory: category,
      });
    }
    const last = await row(links.at(-1)!.linkId);
    expect(last).toMatchObject({ stateName: 'New', stateCategory: 'proposed', missedPasses: 0 });
    expect(last.stateCheckedAt).not.toBeNull();
  });

  it('an unreadable batch is halved; a lone id that still fails is skipped this pass', async () => {
    const ids = await workItems(3);
    const links = await createdLinks(ids);
    for (const id of ids) fake.workItem(id).state = 'Active';
    const bad = { status: 200, headers: { 'content-type': 'application/json' }, body: 'nope' };
    const pass = { status: 200, passThrough: true };
    // [a b c] fails → [a b] passes, [c] fails: c is skipped.
    fake.inject('POST', BATCH_PATH, bad, pass, bad);
    fake.clearRequests();
    expect(await runPass()).toMatchObject({ states: 2, missing: 0, stop: null });
    expect(fake.countRequests('POST', BATCH_PATH)).toBe(3);
    expect(await row(links[0]!.linkId)).toMatchObject({ stateName: 'Active' });
    expect(await row(links[1]!.linkId)).toMatchObject({ stateName: 'Active' });
    const skipped = await row(links[2]!.linkId);
    expect(skipped).toMatchObject({ state: 'created', stateName: 'New', missedPasses: 0 });
    expect(skipped.stateCheckedAt).not.toBeNull();

    // The next pass reads it as any other.
    await runPass();
    expect(await row(links[2]!.linkId)).toMatchObject({ stateName: 'Active' });
  });

  it('an id missing twice → missing', async () => {
    const [itemId] = await workItems(1);
    const [link] = await createdLinks([itemId!]);
    fake.deleteWorkItem(itemId!);
    expect(await runPass()).toMatchObject({ missing: 0 });
    expect(await row(link!.linkId)).toMatchObject({ state: 'created', missedPasses: 1 });
    expect(await runPass()).toMatchObject({ missing: 1 });
    expect(await row(link!.linkId)).toMatchObject({ state: 'missing', workItemId: itemId });
  });

  it('a moved work item keeps its id and reads its new state; unmapped, the link still syncs', async () => {
    const [itemId] = await workItems(1);
    const [link] = await createdLinks([itemId!]);
    const item = fake.workItem(itemId!);
    item.projectId = basic.id;
    item.typeName = 'Issue';
    item.state = 'To Do';
    item.rev += 1;
    await db().delete(projectBoardsSettings).where(eq(projectBoardsSettings.projectId, projectId));
    fake.clearRequests();
    expect(await runPass()).toMatchObject({ states: 1, stop: null });
    expect(await row(link!.linkId)).toMatchObject({
      state: 'created',
      workItemId: itemId,
      stateName: 'To Do',
      stateCategory: 'proposed',
    });
    // The project is named only: one project list, then the type list of the project it is in.
    expect(fake.countRequests('GET', PROJECTS_PATH)).toBe(1);
    expect(fake.requests.filter((r) => TYPES_PATH.test(r.path)).map((r) => r.path)).toEqual([
      `/${basic.id}/_apis/wit/workitemtypes`,
    ]);
  });

  it('the fixed note, then the found-again note, on the link’s project', async () => {
    const issueId = await issue('Do not use eval');
    const [linkId] = await pending([issueId]);
    await runPass();
    const { workItemId } = await row(linkId!);
    const link = `<a href="${PUBLIC_URL}/projects/${projectId}/issues/${issueId}">Open in Qualor</a>`;
    const fixed = `<p>Qualor no longer finds this issue on <code>main</code> (analysis of 2026-11-10). ${link}</p>`;
    const again = `<p>Qualor finds this again: <code>eslint:no-eval</code> on <code>main</code> (analysis of 2026-11-12). ${link}</p>`;

    await close([issueId], '2026-11-10T08:00:00Z');
    fake.clearRequests();
    expect(await runPass()).toMatchObject({ notes: 1, stop: null });
    const [patch] = fake.requests.filter((r) => r.method === 'PATCH');
    expect(patch!.path).toBe(`/${payments.id}/_apis/wit/workitems/${workItemId}`);
    expect(patch!.headers['content-type']).toMatch(/^application\/json-patch\+json/);
    // A plain History note: no `test /rev`.
    expect(JSON.parse(patch!.body)).toEqual([
      { op: 'add', path: '/fields/System.History', value: fixed },
    ]);
    expect(fake.workItem(workItemId!).history).toEqual([fixed]);
    expect((await row(linkId!)).reportedFixedAt).not.toBeNull();

    // A closed work item takes the note too (Part B i).
    fake.workItem(workItemId!).state = 'Closed';
    await reopen(issueId, '2026-11-12T09:00:00Z');
    expect(await runPass()).toMatchObject({ notes: 1 });
    expect(fake.workItem(workItemId!).history).toEqual([fixed, again]);
    expect((await row(linkId!)).reportedFixedAt).toBeNull();
    expect(await runPass()).toMatchObject({ notes: 0 });
  });

  it('a refused note (403) is recorded on the link as note_refused, not counted and not tried again', async () => {
    const [itemId] = await workItems(1);
    const [link] = await createdLinks([itemId!], 'closed');
    const { lines, logger } = capture();
    fake.inject('PATCH', PATCH_PATH, {
      status: 403,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        message: 'TF401027: You need the Edit work items permission',
        typeKey: 'UnauthorizedAccessException',
      }),
    });
    expect(await runPass({ logger })).toMatchObject({ notes: 0, stop: null });
    const stored = await row(link!.linkId);
    expect(stored).toMatchObject({
      state: 'created',
      failure: { code: 'note_refused', message: BOARDS_FAILURE_TEXT.note_refused },
    });
    expect(stored.reportedFixedAt).not.toBeNull();
    expect(lines.filter((l) => l[0] === 'warn')).toHaveLength(1);
    expect(JSON.stringify(lines)).toContain('permission_missing');
    expect((await connection()).problem).toBeNull();
    fake.clearRequests();
    await runPass();
    expect(fake.countRequests('PATCH')).toBe(0);
  });

  it('monitoring off → vulnerability links not judged; a code issue still gets its note', async () => {
    const pair = freshPair();
    await seedTargetRow(db(), { projectId, branchId: main, ...pair });
    const [vulnLink] = (
      await insertPendingBoardsLinks(
        db(),
        { projectId, connectionId, azureProjectId: payments.id, userId: adminId },
        [{ kind: 'vulnerability', ...pair }],
      )
    ).map((r) => r.id);
    const issueId = await issue('code');
    const [codeLink] = await pending([issueId]);
    await runPass();
    const codeItem = (await row(codeLink!)).workItemId!;
    const vulnItem = (await row(vulnLink!)).workItemId!;
    await db()
      .delete(targetVulnerabilities)
      .where(eq(targetVulnerabilities.packageName, pair.packageName));
    await close([issueId], '2026-11-10T08:00:00Z');
    await monitoring(false);
    await runPass();
    expect(fake.workItem(codeItem).history).toHaveLength(1);
    expect(fake.workItem(vulnItem).history).toEqual([]);
    expect((await row(vulnLink!)).reportedFixedAt).toBeNull();

    await monitoring(true);
    await runPass();
    expect(fake.workItem(vulnItem).history).toEqual([
      `<p>Qualor no longer finds <code>${pair.vulnerabilityId}</code> in <code>${pair.packageName}</code> on the tracked branches and versions of <code>BPASS</code>. <a href="${PUBLIC_URL}/projects/${projectId}/vulnerabilities?view=vulnerability">Open in Qualor</a></p>`,
    ]);
  });

  it('probe: a stored token_refused is probed and cleared; a stored permission_missing is not probed', async () => {
    await recordScmProblem(db(), connectionId, 'permission_missing');
    const [first] = await pending([await issue('first')]);
    expect(await runPass()).toMatchObject({ created: 1, stop: null });
    expect(fake.countRequests('GET', /connectionData$/)).toBe(0);
    expect((await connection()).problem?.code).toBe('permission_missing');
    expect(await row(first!)).toMatchObject({ state: 'created' });

    await db().update(scmConnections).set({ problem: null });
    await recordScmProblem(db(), connectionId, 'token_refused');
    const [second] = await pending([await issue('second')]);
    // The probe refused: recorded again, the pass ends after one request.
    fake.inject('GET', /connectionData$/, recordedAnswer('services', '10-wrong-pat'));
    fake.clearRequests();
    expect(await runPass()).toMatchObject({ created: 0, stop: 'credential' });
    expect(fake.requests.map((r) => r.path)).toEqual(['/_apis/connectionData']);
    expect((await connection()).problem?.code).toBe('token_refused');

    // A probe failing for another reason (a 403) ends the pass as transient and records nothing.
    fake.inject('GET', /connectionData$/, {
      status: 403,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        message: 'TF400813: no access',
        typeKey: 'UnauthorizedAccessException',
      }),
    });
    fake.clearRequests();
    expect(await runPass()).toMatchObject({ created: 0, stop: 'transient' });
    expect(fake.requests).toHaveLength(1);
    expect((await connection()).problem?.code).toBe('token_refused');

    // The probe passes: the problem is cleared and the pass goes on.
    fake.clearRequests();
    expect(await runPass()).toMatchObject({ created: 1, stop: null });
    expect(fake.requests[0]!.path).toBe('/_apis/connectionData');
    expect((await connection()).problem).toBeNull();
    expect(await row(second!)).toMatchObject({ state: 'created' });
  });

  it('a 401 mid-pass → problem recorded, later steps skipped, no link marked failed', async () => {
    const [itemId] = await workItems(1);
    const [gone] = await createdLinks([itemId!], 'closed');
    const [linkId] = await pending([await issue('pending')]);
    fake.inject('POST', BATCH_PATH, recordedAnswer('services', '10-wrong-pat'));
    fake.clearRequests();
    expect(await runPass()).toMatchObject({ created: 1, notes: 0, stop: 'credential' });
    expect((await connection()).problem?.code).toBe('token_refused');
    expect(fake.countRequests('PATCH')).toBe(0);
    expect(await row(linkId!)).toMatchObject({ state: 'created', failure: null });
    expect(await row(gone!.linkId)).toMatchObject({
      state: 'created',
      failure: null,
      reportedFixedAt: null,
    });
    expect(
      await db().select().from(boardsLinks).where(eq(boardsLinks.state, 'failed')),
    ).toHaveLength(0);
  });

  it(
    `the budget split: 150 pending, ${STATE_PER_PASS + 1_000} created and 150 notes due stay within every step's cap`,
    { timeout: 120_000 },
    async () => {
      // 150 pending code-issue links, 30 pairs for the automatic rule.
      const pendingIds: string[] = [];
      for (let i = 0; i < 150; i++) pendingIds.push(await issue(`pending ${i}`));
      await pending(pendingIds);
      const since = new Date(Date.now() - 7 * DAY);
      await seedCheck(db(), {
        projectId,
        branchId: main,
        baselineAt: new Date(since.getTime() - DAY),
      });
      for (let i = 0; i < 30; i++) {
        await seedTargetRow(
          db(),
          {
            projectId,
            branchId: main,
            ...freshPair(),
            severity: 'high',
            firstSeenAt: new Date(since.getTime() + (i + 1) * 60_000),
          },
          { recheck: false },
        );
      }
      await db()
        .update(projectBoardsSettings)
        .set({ autoMinSeverity: 'high', autoSince: since })
        .where(eq(projectBoardsSettings.projectId, projectId));
      // 6 000 created vulnerability links, gone and already reported fixed (no note), whose work
      // items are not found.
      await db().execute(sql`
        INSERT INTO boards_links (id, project_id, connection_id, azure_project_id, kind, package_name,
                                  vulnerability_id, state, origin, work_item_id, reported_fixed_at)
        SELECT gen_random_uuid(), ${projectId}, ${connectionId}, ${payments.id}, 'vulnerability',
               'bulk-pkg', 'CVE-BULK-' || g, 'created', 'manual', 1000000 + g, now()
          FROM generate_series(1, ${STATE_PER_PASS + 1_000}) g`);
      // 150 created links whose code issues are closed: 150 notes due.
      await createdLinks(await workItems(150), 'closed');
      fake.clearRequests();

      const ctx = await context();
      const outcome = await runBoardsPass(ctx);
      expect(outcome).toMatchObject({ auto: 30, created: 180, notes: 100, stop: null });
      expect(ctx.client.requestCount).toBeLessThanOrEqual(366);
      expect(ctx.client.requestCount).toBe(fake.requests.length);
      expect(fake.countRequests('POST', CREATE_PATH)).toBe(180);
      expect(fake.countRequests('POST', BATCH_PATH)).toBe(PASS_BUDGET.states);
      expect(fake.countRequests('PATCH', PATCH_PATH)).toBe(PASS_BUDGET.notes);
      expect(fake.countRequests('POST', WIQL_PATH)).toBe(0);
      expect(
        fake.countRequests('GET', TYPES_PATH) + fake.countRequests('GET', PROJECTS_PATH),
      ).toBeLessThanOrEqual(PASS_BUDGET.typeLists);
    },
  );

  it('a client whose budget is nearly spent ends the pass with budget before the step that would exceed it', async () => {
    const { linkId: lost } = await lostCreate();
    await sentAgo(lost, 3);
    const waitingIds = await pending([await issue('a'), await issue('b')]);
    const small: Partial<BoardsJobDeps> = {
      scm: { ...deps.scm, azureClientOptions: { timeoutMs: 2_000, maxRequests: 110 } },
    };
    fake.clearRequests();
    // Reconcile fits (its WIQL and batch, then the type list for the state's category); the create
    // step's 100 creates and 19 type lists left do not.
    expect(await runPass(small)).toMatchObject({ reconciled: 1, created: 0, stop: 'budget' });
    expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      `POST /${payments.id}/_apis/wit/wiql`,
      'POST /_apis/wit/workitemsbatch',
      `GET /${payments.id}/_apis/wit/workitemtypes`,
    ]);
    for (const id of waitingIds) {
      expect(await row(id)).toMatchObject({ state: 'pending', attemptedAt: null });
    }
  });

  it('through the queue: one info line per pass, then the next pass in 15 minutes', async () => {
    const { lines, logger } = capture();
    const [linkId] = await pending([await issue('queued')]);
    expect(await scheduleBoardsSync(db(), connectionId, 0)).toBe(true);
    expect(await runBoardsJobs(h, { ...deps, logger }, 'sync')).toBe(1);
    expect(await row(linkId!)).toMatchObject({ state: 'created' });
    const info = lines.filter((l) => l[0] === 'info' && l[2] === 'Azure Boards pass');
    expect(info).toHaveLength(1);
    expect(info[0]![1]).toMatchObject({
      organizationId: h.organizationId,
      connectionId,
      // The type list, the create, then the states' batch read.
      requests: 3,
      created: 1,
      states: 1,
      stop: null,
    });
    const queued = await db()
      .select()
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, BOARDS_QUEUE),
          eq(jobs.status, 'queued'),
          eq(jobs.concurrencyKey, boardsSyncKey(connectionId)),
        ),
      );
    expect(queued).toHaveLength(1);
    expect(queued[0]!.runAt.getTime()).toBeGreaterThan(Date.now() + 14 * 60_000);
  });
});
