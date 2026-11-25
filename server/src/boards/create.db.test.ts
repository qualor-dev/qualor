import { and, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { azureServerConfig, servicesUrlOf } from '../../test/azure';
import { boardsJobDeps, runBoardsJobs } from '../../test/boards';
import {
  createFakeAzureDevOps,
  recordedAnswer,
  type FakeAzureDevOps,
  type FakeAzureProject,
  type FakeAzureWorkItemType,
  type InjectedAnswer,
} from '../../test/fake-azure-devops';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { seedTargetRow } from '../../test/vulnerabilities';
import type { Db } from '../db/client';
import { boardsLinks, jobs, projectBoardsSettings, scmConnections, users } from '../db/schema';
import type { WorkerLogger } from '../queue/worker';
import type { AzureJsonPatch } from '../scm/azure/client';
import {
  BOARDS_FAILURE_TEXT,
  claimPendingLinks,
  CREATE_PER_RUN,
  createPendingWorkItems,
} from './create';
import {
  BOARDS_QUEUE,
  BOARDS_SYNC_INTERVAL_SECONDS,
  boardsCreateKey,
  boardsSyncKey,
  enqueueBoardsCreate,
  scheduleBoardsSync,
} from './jobs';
import { BOARDS_BLOCKING_CODES, insertPendingBoardsLinks } from './links';
import { openBoardsRun, type BoardsJobDeps } from './run';

const PUBLIC_URL = 'https://qualor.example.com';
const BUG = 'Microsoft.VSTS.WorkItemTypes.Bug';
const ISSUE = 'Microsoft.VSTS.WorkItemTypes.Issue';
const CREATE_PATH = /\/_apis\/wit\/workitems\/\$/;
const TYPES_PATH = /\/_apis\/wit\/workitemtypes$/;

describe('the Boards create job (design §7.8, plan Task 6)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let payments: FakeAzureProject;
  let basic: FakeAzureProject;
  let backend: string;
  let project: IngestProject;
  let projectId: string;
  let main: string;
  let codeRule: string;
  let adminId: string;
  let connectionId: string;
  let deps: BoardsJobDeps;
  let pkgs = 0;

  const db = (): Db => h.ctx.db;
  const issue = (message?: string, over: { projectId?: string; status?: 'closed' } = {}) =>
    seedIssue(db(), {
      projectId: over.projectId ?? projectId,
      branchId: main,
      ruleId: codeRule,
      ...(message === undefined ? {} : { message }),
      ...(over.status === undefined ? {} : { status: over.status }),
    });
  /** Pending code-issue links of the project on the connection, oldest first; their ids. */
  const pending = async (
    issueIds: string[],
    at: { projectId?: string; azureProjectId?: string } = {},
  ): Promise<string[]> => {
    const rows = await insertPendingBoardsLinks(
      db(),
      {
        projectId: at.projectId ?? projectId,
        connectionId,
        azureProjectId: at.azureProjectId ?? payments.id,
        userId: adminId,
      },
      issueIds.map((issueId) => ({ kind: 'issue' as const, issueId })),
    );
    return rows.map((r) => r.id);
  };
  /** `n` pending code-issue links, oldest first. */
  const pendingLinks = async (n: number): Promise<string[]> => {
    const issueIds: string[] = [];
    for (let i = 0; i < n; i++) issueIds.push(await issue(`finding ${i}`));
    return pending(issueIds);
  };
  /** The project mapped to an Azure DevOps project and type, as the mapping PUT stores it. */
  const map = (
    over: Partial<typeof projectBoardsSettings.$inferInsert> & { projectId?: string } = {},
  ) =>
    db()
      .insert(projectBoardsSettings)
      .values({
        projectId,
        connectionId,
        azureProjectId: payments.id,
        azureProjectName: 'Payments',
        workItemTypeRef: BUG,
        workItemTypeName: 'Bug',
        areaPath: backend,
        tags: ['team-a'],
        ...over,
      })
      .onConflictDoUpdate({
        target: projectBoardsSettings.projectId,
        set: { connectionId, azureProjectId: payments.id, workItemTypeRef: BUG, ...over },
      });
  const row = async (id: string) =>
    (await db().select().from(boardsLinks).where(eq(boardsLinks.id, id)))[0]!;
  const rows = () => db().select().from(boardsLinks);
  const connection = async () =>
    (await db().select().from(scmConnections).where(eq(scmConnections.id, connectionId)))[0];
  const createJobs = () =>
    db()
      .select()
      .from(jobs)
      .where(
        and(eq(jobs.queue, BOARDS_QUEUE), eq(jobs.concurrencyKey, boardsCreateKey(connectionId))),
      );
  const queuedCreates = async () => (await createJobs()).filter((j) => j.status === 'queued');
  const waitOf = async (jobId: string): Promise<number> => {
    const [found] = (
      await db().execute<{ wait: number }>(
        sql`SELECT extract(epoch FROM run_at - now())::float AS wait FROM jobs WHERE id = ${jobId}`,
      )
    ).rows;
    return found!.wait;
  };
  /** Queues the connection's create job and runs the `boards` queue until idle. */
  const run = async (over: Partial<BoardsJobDeps> = {}) => {
    await enqueueBoardsCreate(db(), connectionId);
    return runBoardsJobs(h, { ...deps, ...over }, 'create');
  };
  const creates = () =>
    fake.requests.filter((r) => r.method === 'POST' && CREATE_PATH.test(r.path));
  const opsOf = (i: number): AzureJsonPatch[] => JSON.parse(creates()[i]!.body) as AzureJsonPatch[];
  const keyOf = (linkId: string, generation = 1) =>
    `qualor-${linkId.replaceAll('-', '')}-${generation}`;
  const typeOf = (azureProject: FakeAzureProject, referenceName: string): FakeAzureWorkItemType =>
    fake.workItemTypes(azureProject.id).find((t) => t.referenceName === referenceName)!;
  /** A refused create: the recorded RuleValidationException with `message` as Azure's words. */
  const refusedCreate = (message: string): InjectedAnswer => {
    const recorded = recordedAnswer('services', '30-pat-e-no-title');
    const parsed = JSON.parse(recorded.body as string) as Record<string, unknown>;
    return { ...recorded, body: JSON.stringify({ ...parsed, message }) };
  };

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({ deployment: 'services' });
    payments = fake.addProject({ name: 'Payments', process: 'agile' });
    basic = fake.addProject({ name: 'Basic', process: 'basic' });
    backend = fake.addClassificationNode(payments.id, 'areas', 'Backend');
    h = await createIngestHarness({
      config: { ...azureServerConfig(fake), publicUrl: PUBLIC_URL },
    });
    project = await h.project('BC');
    projectId = project.id;
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
    await map();
    deps = boardsJobDeps(h);
    fake.clearRequests();
  });
  afterEach(async () => {
    await db().delete(scmConnections);
    await db().delete(jobs).where(eq(jobs.queue, BOARDS_QUEUE));
  });

  it('one work item: POST with the mapped fields, then created with its state', async () => {
    const issueId = await issue('Do not use eval');
    const [linkId] = await pending([issueId]);
    expect(await run()).toBe(1);

    expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      `GET /${payments.id}/_apis/wit/workitemtypes`,
      `POST /${payments.id}/_apis/wit/workitems/$Bug`,
    ]);
    expect(creates()[0]!.headers['content-type']).toMatch(/^application\/json-patch\+json/);
    const key = keyOf(linkId!);
    expect(opsOf(0)).toEqual([
      { op: 'add', path: '/fields/System.Title', value: 'Do not use eval' },
      {
        op: 'add',
        path: '/fields/System.Description',
        value: expect.stringMatching(new RegExp(`<p>Qualor reference: ${key}</p>$`)),
      },
      {
        op: 'add',
        path: '/fields/Microsoft.VSTS.TCM.ReproSteps',
        value: expect.stringContaining(key),
      },
      { op: 'add', path: '/fields/System.Tags', value: 'qualor; team-a' },
      { op: 'add', path: '/fields/System.AreaPath', value: 'Payments\\Backend' },
      {
        op: 'add',
        path: '/relations/-',
        value: { rel: 'Hyperlink', url: `${PUBLIC_URL}/projects/${projectId}/issues/${issueId}` },
      },
    ]);
    const [made] = fake.workItems();
    expect(made).toMatchObject({
      projectId: payments.id,
      typeName: 'Bug',
      title: 'Do not use eval',
      areaPath: 'Payments\\Backend',
      tags: ['qualor', 'team-a'],
    });
    const stored = await row(linkId!);
    expect(stored).toMatchObject({
      state: 'created',
      workItemId: made!.id,
      stateName: 'New',
      stateCategory: 'proposed',
      failure: null,
    });
    expect(stored.stateCheckedAt).not.toBeNull();
    expect(stored.attemptedAt).not.toBeNull();
    // The job ran to its end: nothing is queued after it.
    expect(await queuedCreates()).toHaveLength(0);
  });

  it('ReproSteps for a Bug, not for an Issue; a vulnerability links to its tab', async () => {
    const other = await h.project('BCI');
    await map({
      projectId: other.id,
      azureProjectId: basic.id,
      azureProjectName: 'Basic',
      workItemTypeRef: ISSUE,
      workItemTypeName: 'Issue',
      areaPath: null,
      tags: [],
    });
    const otherMain = await mainBranchId(db(), other.id);
    const pair = { packageName: `pkg-boards-${++pkgs}`, vulnerabilityId: 'CVE-2026-7001' };
    await seedTargetRow(db(), {
      projectId: other.id,
      branchId: otherMain,
      ...pair,
      severity: 'high',
    });
    const [vulnerability] = await insertPendingBoardsLinks(
      db(),
      { projectId: other.id, connectionId, azureProjectId: basic.id, userId: adminId },
      [{ kind: 'vulnerability', ...pair }],
    );
    const [bug] = await pending([await issue('a bug')]);
    await run();

    const byPath = (path: string) => creates().find((r) => r.path.endsWith(path))!;
    const issueOps = JSON.parse(byPath('$Issue').body) as AzureJsonPatch[];
    expect(issueOps.map((o) => o.path)).toEqual([
      '/fields/System.Title',
      '/fields/System.Description',
      '/fields/System.Tags',
      '/relations/-',
    ]);
    expect(issueOps[0]!.value).toBe(`CVE-2026-7001 in ${pair.packageName} (high)`);
    expect(issueOps[2]!.value).toBe('qualor');
    expect(issueOps[3]!.value).toEqual({
      rel: 'Hyperlink',
      url: `${PUBLIC_URL}/projects/${other.id}/vulnerabilities?view=vulnerability`,
    });
    const bugOps = JSON.parse(byPath('$Bug').body) as AzureJsonPatch[];
    expect(bugOps.map((o) => o.path)).toContain('/fields/Microsoft.VSTS.TCM.ReproSteps');

    expect(await row(vulnerability!.id)).toMatchObject({
      state: 'created',
      stateName: 'To Do',
      stateCategory: 'proposed',
    });
    expect(await row(bug!)).toMatchObject({ state: 'created', stateName: 'New' });
    // One type list per Azure DevOps project in the run.
    expect(fake.countRequests('GET', TYPES_PATH)).toBe(2);
  });

  it('a type renamed since mapping still creates (resolved by reference name)', async () => {
    const bug = typeOf(payments, BUG);
    bug.name = 'Defect';
    try {
      const [linkId] = await pending([await issue('renamed type')]);
      await run();
      expect(creates().map((r) => r.path)).toEqual([`/${payments.id}/_apis/wit/workitems/$Defect`]);
      expect(await row(linkId!)).toMatchObject({ state: 'created', stateName: 'New' });
      expect(fake.workItems().at(-1)!.typeName).toBe('Defect');
    } finally {
      bug.name = 'Bug';
    }
  });

  it('a type removed → type_unsupported, nothing left pending', async () => {
    const types = fake.workItemTypes(payments.id);
    const bug = typeOf(payments, BUG);
    types.splice(types.indexOf(bug), 1);
    try {
      const ids = await pendingLinks(3);
      await run();
      expect(creates()).toHaveLength(0);
      for (const id of ids) {
        expect(await row(id)).toMatchObject({
          state: 'failed',
          failure: { code: 'type_unsupported', message: BOARDS_FAILURE_TEXT.type_unsupported },
          workItemId: null,
        });
      }
    } finally {
      types.push(bug);
    }
    expect(BOARDS_FAILURE_TEXT.type_unsupported).toBe(
      'The mapped work item type no longer exists or needs fields Qualor does not set: map the project again',
    );

    // A required field Qualor does not set, added since mapping, is unsupported too.
    bug.fields.push({
      referenceName: 'Custom.Team',
      name: 'Team',
      alwaysRequired: true,
      defaultValue: null,
    });
    try {
      const [linkId] = await pending([await issue('needs a team')]);
      await run();
      expect(creates()).toHaveLength(0);
      expect((await row(linkId!)).failure?.code).toBe('type_unsupported');
    } finally {
      bug.fields = bug.fields.filter((f) => f.referenceName !== 'Custom.Team');
    }

    // Removed between the type list and the create: Azure's 404 WorkItemTypeNotFoundException.
    const [late] = await pending([await issue('type gone at the create')]);
    fake.inject('POST', CREATE_PATH, recordedAnswer('services', '30-pat-d-validate-no-type'));
    await run();
    expect(await row(late!)).toMatchObject({
      state: 'failed',
      failure: { code: 'type_unsupported', message: BOARDS_FAILURE_TEXT.type_unsupported },
    });
    expect((await rows()).filter((r) => r.state === 'pending')).toHaveLength(0);
  });

  it("a 400 → field_refused with Azure's words cut to 500, an empty message without any; 403, 404 and the long text too", async () => {
    const words = `TF401320: Rule Error for field Team. ${'x'.repeat(600)}`;
    const [refused] = await pending([await issue('refused')]);
    fake.inject('POST', CREATE_PATH, refusedCreate(words));
    await run();
    const stored = await row(refused!);
    expect(stored).toMatchObject({ state: 'failed', workItemId: null });
    expect(stored.failure?.code).toBe('field_refused');
    expect(stored.failure!.message).toHaveLength(500);
    expect(stored.failure!.message).toBe(`${words.slice(0, 499)}…`);

    const cases: [InjectedAnswer, string, string][] = [
      [
        {
          status: 403,
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify({
            message: 'TF401027: You need the Git permission',
            typeKey: 'UnauthorizedAccessException',
          }),
        },
        'permission_missing',
        BOARDS_FAILURE_TEXT.permission_missing,
      ],
      [
        recordedAnswer('services', '30-pat-e-no-project'),
        'not_found',
        BOARDS_FAILURE_TEXT.not_found,
      ],
      [
        recordedAnswer('services', '30-pat-e-big-description'),
        'field_refused',
        'TF401262: Value of long text field System.Description exceeds the maximum allowed length of 1048576.',
      ],
      // No words of Azure DevOps': the message stays empty, never a stand-in text.
      [
        { status: 400, headers: { 'content-type': 'application/json' }, body: '{}' },
        'field_refused',
        '',
      ],
    ];
    for (const [answer, code, message] of cases) {
      const [linkId] = await pending([await issue(`case ${code}`)]);
      fake.inject('POST', CREATE_PATH, answer);
      await run();
      expect(await row(linkId!), code).toMatchObject({
        state: 'failed',
        failure: { code, message },
      });
    }
    // A refusal concerns the row only: the connection records nothing.
    expect((await connection())?.problem).toBeNull();
  });

  it('a 401 → the connection problem recorded and the rows released', async () => {
    const linkIds = await pendingLinks(3);
    fake.inject('POST', CREATE_PATH, recordedAnswer('services', '10-wrong-pat'));
    await run();
    expect((await connection())?.problem).toMatchObject({ code: 'token_refused' });
    for (const id of linkIds) {
      expect(await row(id)).toMatchObject({ state: 'pending', attemptedAt: null, failure: null });
    }
    expect(creates()).toHaveLength(1);
    expect(await queuedCreates()).toHaveLength(0);

    // While the problem is set, a create job sends nothing and claims nothing.
    fake.clearRequests();
    await run();
    expect(fake.requests).toHaveLength(0);
    for (const id of linkIds) expect((await row(id)).attemptedAt).toBeNull();

    // A sign-in answer (TF401444) is a credential problem too, at the type list as at the create.
    await db()
      .update(scmConnections)
      .set({ problem: null })
      .where(eq(scmConnections.id, connectionId));
    const message = 'TF401444: Please sign-in at least once in a web browser to enable access.';
    fake.inject('GET', TYPES_PATH, {
      status: 401,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'x-tfs-serviceerror': encodeURIComponent(message),
      },
      body: JSON.stringify({ message, typeKey: 'UnauthorizedRequestException' }),
    });
    await run();
    expect((await connection())?.problem?.code).toBe('sign_in_required');
    expect(fake.countRequests('POST', CREATE_PATH)).toBe(0);
    for (const id of linkIds) {
      expect(await row(id)).toMatchObject({ state: 'pending', attemptedAt: null });
    }
  });

  it('a stored permission_missing does not stop creates; a stored token_refused does', async () => {
    const setProblem = (code: 'permission_missing' | 'token_refused' | 'hook_disabled') =>
      db()
        .update(scmConnections)
        .set({ problem: { code, at: new Date().toISOString() } })
        .where(eq(scmConnections.id, connectionId));
    for (const code of ['permission_missing', 'hook_disabled'] as const) {
      await setProblem(code);
      const [linkId] = await pending([await issue(`despite ${code}`)]);
      await run();
      expect(await row(linkId!), code).toMatchObject({ state: 'created' });
      // Creating work items clears nothing either: the problem is decoration's.
      expect((await connection())?.problem?.code).toBe(code);
    }
    expect(BOARDS_BLOCKING_CODES).toEqual([
      'token_refused',
      'sign_in_required',
      'html_answer',
      'token_endpoint',
      'undecryptable',
      'url_not_allowed',
    ]);

    await setProblem('token_refused');
    fake.clearRequests();
    const [blocked] = await pending([await issue('blocked')]);
    await run();
    expect(fake.requests).toHaveLength(0);
    expect(await row(blocked!)).toMatchObject({ state: 'pending', attemptedAt: null });
  });

  it('a 429 → stop with Retry-After', async () => {
    const linkIds = await pendingLinks(3);
    fake.inject(
      'POST',
      CREATE_PATH,
      { passThrough: true, status: 200 },
      { status: 429, headers: { 'Retry-After': '30' } },
    );
    await run();
    const stored = await Promise.all(linkIds.map(row));
    expect(stored.filter((r) => r.state === 'created')).toHaveLength(1);
    const released = stored.filter((r) => r.state !== 'created');
    expect(released).toHaveLength(2);
    for (const r of released) expect(r).toMatchObject({ state: 'pending', attemptedAt: null });
    expect(creates()).toHaveLength(2);
    const queued = await queuedCreates();
    expect(queued).toHaveLength(1);
    const wait = await waitOf(queued[0]!.id);
    expect(wait).toBeGreaterThan(25);
    expect(wait).toBeLessThanOrEqual(30);
    // A 429 records no background problem.
    expect((await connection())?.problem).toBeNull();
  });

  it('150 pending → 100 created and a follow-up create at 0', async () => {
    const ids = await pendingLinks(150);
    const ctx = (await openBoardsRun(deps, connectionId))!;
    expect(await createPendingWorkItems(ctx)).toEqual({
      created: CREATE_PER_RUN,
      failed: 0,
      unanswered: 0,
      stop: null,
    });
    // One type list and one create per row: well within the 400 requests of a client.
    expect(ctx.client.requestCount).toBe(CREATE_PER_RUN + 1);
    expect(creates()).toHaveLength(100);
    const [next] = await queuedCreates();
    expect(next).toBeDefined();
    expect(await waitOf(next!.id)).toBeLessThanOrEqual(5);

    await runBoardsJobs(h, deps, 'create');
    const stored = await rows();
    expect(stored.filter((r) => ids.includes(r.id) && r.state === 'created')).toHaveLength(150);
    expect(new Set(stored.map((r) => r.workItemId)).size).toBe(150);
    expect(creates()).toHaveLength(150);
    expect(await queuedCreates()).toHaveLength(0);
  });

  it('the connection deleted mid-run → no write', async () => {
    const lines: unknown[][] = [];
    const logger: WorkerLogger = {
      info: (...a: unknown[]) => void lines.push(['info', ...a]),
      warn: (...a: unknown[]) => void lines.push(['warn', ...a]),
      error: (...a: unknown[]) => void lines.push(['error', ...a]),
    };
    await pendingLinks(3);
    fake.inject('POST', CREATE_PATH, {
      passThrough: true,
      status: 200,
      before: async () => {
        await db().delete(scmConnections).where(eq(scmConnections.id, connectionId));
      },
    });
    expect(await run({ logger })).toBe(1);
    // The call in flight was made; none after it.
    expect(creates()).toHaveLength(1);
    expect(await rows()).toHaveLength(0);
    expect(await connection()).toBeUndefined();
    expect((await createJobs()).map((j) => j.status)).toEqual(['succeeded']);
    expect(lines.filter(([level]) => level !== 'info')).toEqual([]);
  });

  it('moved: a run that outlived an address change sends nothing more and records no problem', async () => {
    const move = (baseUrl: string) =>
      db().update(scmConnections).set({ baseUrl }).where(eq(scmConnections.id, connectionId));
    const [linkId] = await pending([await issue('moved')]);
    const stale = (await openBoardsRun(deps, connectionId))!;
    await move(`${servicesUrlOf(fake)}-moved`);
    expect(await createPendingWorkItems(stale)).toEqual({
      created: 0,
      failed: 0,
      unanswered: 0,
      stop: null,
    });
    expect(fake.requests).toHaveLength(0);
    expect(await row(linkId!)).toMatchObject({ state: 'pending', attemptedAt: null });

    // Moved while its call is out: the old organisation's 401 is not the new address's problem.
    await move(servicesUrlOf(fake));
    const inFlight = (await openBoardsRun(deps, connectionId))!;
    fake.inject('POST', CREATE_PATH, {
      ...recordedAnswer('services', '10-wrong-pat'),
      before: () => move(`${servicesUrlOf(fake)}-moved`).then(() => undefined),
    });
    expect((await createPendingWorkItems(inFlight)).stop).toBe('credential');
    expect(creates()).toHaveLength(1);
    expect((await connection())?.problem).toBeNull();
    expect((await row(linkId!)).state).toBe('pending');
  });

  it('a row dismissed meanwhile keeps its work item id', async () => {
    const [linkId] = await pending([await issue('dismissed in flight')]);
    fake.inject('POST', CREATE_PATH, {
      passThrough: true,
      status: 200,
      before: async () => {
        await db()
          .update(boardsLinks)
          .set({ state: 'dismissed' })
          .where(eq(boardsLinks.id, linkId!));
      },
    });
    await run();
    const stored = await row(linkId!);
    expect(stored.state).toBe('dismissed');
    expect(stored.workItemId).toBe(fake.workItems().at(-1)!.id);
    expect(stored.failure).toBeNull();

    // Dismissed after its claim but before its call, a row is not sent at all.
    const [first, second] = await pendingLinks(2);
    fake.clearRequests();
    fake.inject('POST', CREATE_PATH, {
      passThrough: true,
      status: 200,
      before: async () => {
        await db()
          .update(boardsLinks)
          .set({ state: 'dismissed' })
          .where(eq(boardsLinks.id, second!));
      },
    });
    await run();
    expect(creates()).toHaveLength(1);
    expect(await row(first!)).toMatchObject({ state: 'created' });
    expect(await row(second!)).toMatchObject({ state: 'dismissed', workItemId: null });
  });

  it('a row reset and claimed by another run after this run’s claim is neither sent nor written by it', async () => {
    const other = (await openBoardsRun(deps, connectionId))!;
    /** The pass’s reconcile resets the row, then another run claims it: the stamp it got. */
    const steal = async (id: string): Promise<Date | null> => {
      await new Promise((resolve) => setTimeout(resolve, 5));
      await db().update(boardsLinks).set({ attemptedAt: null }).where(eq(boardsLinks.id, id));
      const [taken] = await claimPendingLinks(other, 1);
      expect(taken?.id).toBe(id);
      return taken!.attemptedAt;
    };
    const [first, second] = await pendingLinks(2);
    let stolen: Date | null = null;
    fake.inject('POST', CREATE_PATH, {
      passThrough: true,
      status: 200,
      before: async () => {
        stolen = await steal(second!);
      },
    });
    await run();
    expect(creates()).toHaveLength(1);
    expect(await row(first!)).toMatchObject({ state: 'created' });
    expect(await row(second!)).toMatchObject({
      state: 'pending',
      workItemId: null,
      attemptedAt: stolen,
    });

    // Taken over while its own create is out: the late answer writes nothing on the other claim.
    const [inFlight] = await pendingLinks(1);
    fake.clearRequests();
    fake.inject('POST', CREATE_PATH, {
      passThrough: true,
      status: 200,
      before: async () => {
        stolen = await steal(inFlight!);
      },
    });
    await run();
    expect(creates()).toHaveLength(1);
    expect(await row(inFlight!)).toMatchObject({
      state: 'pending',
      workItemId: null,
      attemptedAt: stolen,
    });
  });

  it('an unexpected error in a send releases the rows after it, never the one in flight', async () => {
    const ids = await pendingLinks(4);
    const ctx = (await openBoardsRun(deps, connectionId))!;
    const real = ctx.client.createWorkItem.bind(ctx.client);
    let calls = 0;
    ctx.client.createWorkItem = async (projectId, typeName, ops) => {
      calls += 1;
      if (calls === 2) throw new Error('boom');
      return real(projectId, typeName, ops);
    };
    await expect(createPendingWorkItems(ctx)).rejects.toThrow('boom');
    const [created, inFlight, ...after] = await Promise.all(ids.map(row));
    expect(created).toMatchObject({ state: 'created' });
    expect(inFlight!.state).toBe('pending');
    expect(inFlight!.attemptedAt).not.toBeNull();
    expect(after).toHaveLength(2);
    for (const r of after) expect(r).toMatchObject({ state: 'pending', attemptedAt: null });
  });

  it('a lost answer: the work item is made, the row waits with attempted_at, never resent', async () => {
    const [linkId] = await pending([await issue('lost')]);
    const before = fake.workItems().length;
    fake.inject('POST', CREATE_PATH, { status: 200, afterCreate: 'reset' });
    await run();
    const stored = await row(linkId!);
    expect(stored.state).toBe('pending');
    expect(stored.attemptedAt).not.toBeNull();
    expect(fake.workItems().length - before).toBe(1);
    await run();
    expect(creates()).toHaveLength(1);
    // A transient failure records nothing on the connection (it passes by itself).
    expect((await connection())?.problem).toBeNull();
  });

  it('an unreadable type list holds its project’s rows for the next run, asked once', async () => {
    const ids = await pendingLinks(25);
    fake.inject('GET', TYPES_PATH, {
      status: 200,
      headers: { 'content-type': 'application/json' },
      body: 'not json',
    });
    await run();
    expect(fake.countRequests('GET', TYPES_PATH)).toBe(1);
    expect(creates()).toHaveLength(0);
    for (const id of ids) {
      expect(await row(id)).toMatchObject({ state: 'pending', attemptedAt: null });
    }
    // Nothing was answered: no follow-up is queued for them (the pass sends them).
    expect(await queuedCreates()).toHaveLength(0);
    // A bad answer records nothing on the connection.
    expect((await connection())?.problem).toBeNull();
  });

  it('unmapped → not_mapped and a closed code issue → finding_gone, both unsent', async () => {
    const [closed] = await pending([await issue('closed', { status: 'closed' })]);
    const other = await h.project('BCU');
    const [unmapped] = await pending([await issue('unmapped', { projectId: other.id })], {
      projectId: other.id,
    });
    await run();
    expect(await row(closed!)).toMatchObject({
      state: 'failed',
      failure: { code: 'finding_gone', message: BOARDS_FAILURE_TEXT.finding_gone },
    });
    expect(await row(unmapped!)).toMatchObject({
      state: 'failed',
      failure: { code: 'not_mapped', message: BOARDS_FAILURE_TEXT.not_mapped },
    });
    expect(fake.requests).toHaveLength(0);
  });

  it('the pass creates, then queues the next pass while wanted', async () => {
    const queuedSyncs = () =>
      db()
        .select()
        .from(jobs)
        .where(
          and(
            eq(jobs.queue, BOARDS_QUEUE),
            eq(jobs.status, 'queued'),
            eq(jobs.concurrencyKey, boardsSyncKey(connectionId)),
          ),
        );
    const [linkId] = await pending([await issue('by the pass')]);
    expect(await scheduleBoardsSync(db(), connectionId, 0)).toBe(true);
    expect(await runBoardsJobs(h, deps, 'sync')).toBe(1);
    expect(await row(linkId!)).toMatchObject({ state: 'created' });
    const [next] = await queuedSyncs();
    expect(await waitOf(next!.id)).toBeGreaterThan(BOARDS_SYNC_INTERVAL_SECONDS - 10);

    // Unmapped, its links dismissed: the connection wants no pass, so none follows this one.
    await db()
      .delete(projectBoardsSettings)
      .where(eq(projectBoardsSettings.connectionId, connectionId));
    await db().update(boardsLinks).set({ state: 'dismissed' });
    expect(await runBoardsJobs(h, deps, 'sync')).toBe(1);
    expect(await queuedSyncs()).toHaveLength(0);
  });

  it("a link keeps its own Azure DevOps project; the mapping's paths only go to the mapping's project", async () => {
    // A retried link of an earlier mapping (Platform) after the project was mapped to Payments.
    const platform = fake.addProject({ name: 'Platform', process: 'agile' });
    const [linkId] = await pending([await issue('earlier project')], {
      azureProjectId: platform.id,
    });
    await run();
    expect(creates().map((r) => r.path)).toEqual([`/${platform.id}/_apis/wit/workitems/$Bug`]);
    const paths = opsOf(0).map((o) => o.path);
    expect(paths).toContain('/fields/System.Tags');
    expect(paths).not.toContain('/fields/System.AreaPath');
    expect(await row(linkId!)).toMatchObject({ state: 'created', azureProjectId: platform.id });
    expect(fake.workItems().at(-1)!.projectId).toBe(platform.id);
  });
});
