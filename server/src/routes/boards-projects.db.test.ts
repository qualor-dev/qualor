import { and, eq, gt, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addMember, createUser, login, type Session } from '../../test/app';
import { azureServerConfig, servicesUrlOf } from '../../test/azure';
import { azureConnection } from '../../test/azure-pending';
import {
  createFakeAzureDevOps,
  recordedAnswer,
  type FakeAzureDevOps,
  type FakeAzureProject,
} from '../../test/fake-azure-devops';
import { createFakeJira, type FakeJira } from '../../test/fake-jira';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { connectJira, jiraTestConfig, mapJira } from '../../test/jira';
import { rbacPlugins } from '../../test/rbac';
import { BOARDS_QUEUE, boardsSyncKey } from '../boards/jobs';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import {
  auditEvents,
  boardsLinks,
  jiraConnections,
  jobs,
  organizations,
  projectBoardsSettings,
  projectJiraSettings,
  scmConnections,
} from '../db/schema';
import { JIRA_QUEUE } from '../jira/jobs';
import { AZURE_TEXT } from '../scm/azure/client';
import { SCM_TOKEN_AAD } from '../scm/connections';

const NOW = new Date('2027-01-01T00:00:00Z');
const BUG = 'Microsoft.VSTS.WorkItemTypes.Bug';
const TASK = 'Microsoft.VSTS.WorkItemTypes.Task';

interface TypeItem {
  referenceName: string;
  name: string;
  supported: boolean;
  missingFields: string[];
}

describe('the project Azure Boards mapping (design §7.8)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let jira: FakeJira;
  let viewer: Session;
  let member: Session;
  let outsider: Session;
  let projectId: string;
  let otherOrganizationId: string;
  let payments: FakeAzureProject;
  let basic: FakeAzureProject;
  let platform: FakeAzureProject;
  /** Whether the test edition licenses `vuln.priority`. */
  let priorityLicensed = false;
  let since = 0;
  const url = (suffix = '') => `/api/v0/projects/${projectId}/boards${suffix}`;
  const call = (
    method: 'GET' | 'PUT' | 'DELETE',
    path: string,
    payload?: object,
    headers: Record<string, string> = h.orgAdmin.headers,
  ) =>
    h.ctx.app.inject({
      method,
      url: path,
      headers,
      ...(payload === undefined ? {} : { payload }),
    });
  const body = (connectionId: string, over: object = {}) => ({
    connectionId,
    azureProject: { id: payments.id, name: 'Payments' },
    workItemType: { referenceName: BUG },
    areaPath: null,
    iterationPath: null,
    tags: [],
    autoCreate: { minSeverity: null, exploited: false },
    ...over,
  });
  const put = (connectionId: string, over: object = {}, headers?: Record<string, string>) =>
    call('PUT', url(), body(connectionId, over), headers);
  const jiraBody = {
    jiraProject: { id: '10000', key: 'QUAL', name: 'Qualor findings' },
    issueType: { id: '10001', name: 'Bug' },
    labels: [],
    priorities: null,
    autoCreate: { minSeverity: null, exploited: false },
  };
  const events = async () =>
    (
      await h.ctx.db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, 'project.boards_updated'), gt(auditEvents.seq, since)))
        .orderBy(auditEvents.seq)
    ).map((e) => e.details);
  const stored = async () =>
    (
      await h.ctx.db
        .select()
        .from(projectBoardsSettings)
        .where(eq(projectBoardsSettings.projectId, projectId))
    )[0];
  const lastSeq = async () =>
    Number(
      (
        await h.ctx.db
          .select({ seq: sql<number>`coalesce(max(${auditEvents.seq}), 0)` })
          .from(auditEvents)
      )[0]?.seq ?? 0,
    );
  /** An Azure DevOps connection of the organisation to the Services fake, made through the API. */
  const connect = async (): Promise<string> => {
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
    return (res.json() as { id: string }).id;
  };
  /** A GitHub App connection of the organisation (nothing calls it). */
  const github = async (): Promise<string> => {
    const [row] = await h.ctx.db
      .insert(scmConnections)
      .values({
        organizationId: h.organizationId,
        provider: 'github',
        baseUrl: 'https://api.github.com',
        appId: '123456',
        tokenEnc: encryptSecret(encryptionKey(h.ctx.config.secretKey), 'pem', SCM_TOKEN_AAD),
      })
      .returning({ id: scmConnections.id });
    return row!.id;
  };
  /** An Azure DevOps connection of another organisation, to the same fake. */
  const foreign = async (): Promise<string> =>
    (
      await azureConnection(h.ctx.db, {
        organizationId: otherOrganizationId,
        baseUrl: servicesUrlOf(fake),
        secretKey: h.ctx.config.secretKey,
      })
    ).id;
  const validations = () =>
    fake.requests.filter((r) => r.method === 'POST' && /validateOnly=true/.test(r.query));
  const monitoring = (enabled: boolean) =>
    call('PUT', `/api/v0/projects/${projectId}/vulnerability-monitoring`, {
      enabled,
      branchPatterns: [],
      versionRule: { kind: 'none' },
      labelVersions: false,
    });
  /** The fake's Bug of Payments, which a test changes in place and must restore. */
  const paymentsBug = () => fake.workItemTypes(payments.id).find((t) => t.referenceName === BUG)!;
  const requireTeam = () => {
    paymentsBug().fields.push({
      referenceName: 'Custom.Team',
      name: 'Team',
      alwaysRequired: true,
      defaultValue: null,
    });
    return () => {
      const bug = paymentsBug();
      bug.fields = bug.fields.filter((f) => f.referenceName !== 'Custom.Team');
    };
  };
  /** A refused dry run: the recorded RuleValidationException with `message` as Azure's words. */
  const refusedCreate = (message: string) => {
    const recorded = recordedAnswer('services', '30-pat-e-no-title');
    const parsed = JSON.parse(recorded.body as string) as Record<string, unknown>;
    return { ...recorded, body: JSON.stringify({ ...parsed, message }) };
  };

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({ deployment: 'services' });
    payments = fake.addProject({ name: 'Payments', process: 'agile' });
    basic = fake.addProject({ name: 'Basic', process: 'basic' });
    platform = fake.addProject({ name: 'Platform', process: 'agile' });
    fake.addClassificationNode(payments.id, 'areas', 'Backend');
    jira = await createFakeJira({ deployment: 'data_center' });
    jira.addProject({ id: '10000', key: 'QUAL', name: 'Qualor findings' });
    h = await createIngestHarness({
      config: { ...azureServerConfig(fake), ...jiraTestConfig(jira) },
      pluginsFor: rbacPlugins({
        now: () => NOW,
        edition: (edition) => ({
          ...edition,
          limits: () => ({
            ...edition.limits(),
            vulnerabilities: { ...edition.limits().vulnerabilities, priority: priorityLicensed },
          }),
        }),
      }),
    });
    const make = async (username: string, role?: 'viewer' | 'member') => {
      const user = await createUser(h.ctx, { username });
      if (role) await addMember(h.ctx, h.organizationId, user.id, role);
      return login(h.ctx, user.username, user.password);
    };
    viewer = await make('bp-viewer', 'viewer');
    member = await make('bp-member', 'member');
    outsider = await make('bp-outsider');
    projectId = (await h.project('BP')).id;
    const [other] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'boards-other', name: 'Other' })
      .returning({ id: organizations.id });
    otherOrganizationId = other!.id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
    await jira.close();
  });
  beforeEach(async () => {
    priorityLicensed = false;
    since = await lastSeq();
  });
  afterEach(async () => {
    fake.clearRequests();
    await h.ctx.db.delete(scmConnections);
    await h.ctx.db.delete(jiraConnections);
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, JIRA_QUEUE));
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, BOARDS_QUEUE));
  });

  it("GET: a viewer sees no mapping and the organisation's Azure connections", async () => {
    const azure = await connect();
    await github();
    await foreign();
    expect((await monitoring(false)).statusCode).toBe(200);
    const res = await call('GET', url(), undefined, viewer.headers);
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toEqual({
      mapping: null,
      connections: [{ id: azure, name: 'probe-org', baseUrl: servicesUrlOf(fake), problem: null }],
      monitoringOn: false,
      exploitedAvailable: false,
    });
    expect(fake.requests).toHaveLength(0);
  });

  it("GET: a connection's background problem, and exploitedAvailable follows vuln.priority", async () => {
    priorityLicensed = true;
    const azure = await connect();
    await h.ctx.db
      .update(scmConnections)
      .set({ problem: { code: 'token_refused', at: '2027-01-01T00:00:00.000Z' } })
      .where(eq(scmConnections.id, azure));
    const res = await call('GET', url(), undefined, viewer.headers);
    expect(res.json()).toMatchObject({
      connections: [
        { id: azure, problem: { code: 'token_refused', at: '2027-01-01T00:00:00.000Z' } },
      ],
      exploitedAvailable: true,
    });
  });

  describe('the pickers', () => {
    it('lists the Azure DevOps projects by name', async () => {
      const azure = await connect();
      const res = await call('GET', url(`/projects?connection=${azure}`));
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toEqual({
        items: [
          { id: basic.id, name: 'Basic' },
          { id: payments.id, name: 'Payments' },
          { id: platform.id, name: 'Platform' },
        ],
      });
    });

    it('lists the work item types by name without the hidden ones, with what Qualor cannot fill', async () => {
      const azure = await connect();
      const res = await call(
        'GET',
        url(`/work-item-types?connection=${azure}&azureProject=${payments.id.toUpperCase()}`),
      );
      expect(res.statusCode, res.body).toBe(200);
      const { items } = res.json() as { items: TypeItem[] };
      expect(items.map((t) => t.name)).toEqual([
        'Bug',
        'Epic',
        'Feature',
        'Issue',
        'Task',
        'Test Case',
        'User Story',
      ]);
      expect(items[0]).toEqual({
        referenceName: BUG,
        name: 'Bug',
        supported: true,
        missingFields: [],
      });
      expect(items.every((t) => t.supported)).toBe(true);
      const onBasic = await call(
        'GET',
        url(`/work-item-types?connection=${azure}&azureProject=${basic.id}`),
      );
      // Basic hides Test Case too (probe item 30b).
      expect((onBasic.json() as { items: TypeItem[] }).items.map((t) => t.name)).toEqual([
        'Epic',
        'Issue',
        'Task',
      ]);
    });

    it('marks a type with a required field Qualor cannot fill unsupported, naming the field', async () => {
      const azure = await connect();
      const restore = requireTeam();
      try {
        const res = await call(
          'GET',
          url(`/work-item-types?connection=${azure}&azureProject=${payments.id}`),
        );
        const bug = (res.json() as { items: TypeItem[] }).items.find((t) => t.name === 'Bug');
        expect(bug).toEqual({
          referenceName: BUG,
          name: 'Bug',
          supported: false,
          missingFields: ['Custom.Team'],
        });
      } finally {
        restore();
      }
    });

    it('lists the area and iteration paths in the create form, the root first', async () => {
      const azure = await connect();
      const res = await call('GET', url(`/paths?connection=${azure}&azureProject=${payments.id}`));
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toEqual({
        areas: ['Payments', 'Payments\\Backend'],
        iterations: [
          'Payments',
          'Payments\\Iteration 1',
          'Payments\\Iteration 2',
          'Payments\\Iteration 3',
        ],
      });
    });

    it("answers 409 BOARDS_NOT_CONNECTED for a GitHub connection, another organisation's and none", async () => {
      await connect();
      const ids = [await github(), await foreign(), '0192f5a4-7c1e-7d3a-9b2e-5f1a2c3d4e5f'];
      for (const id of ids) {
        for (const path of [
          `/projects?connection=${id}`,
          `/work-item-types?connection=${id}&azureProject=${payments.id}`,
          `/paths?connection=${id}&azureProject=${payments.id}`,
        ]) {
          const res = await call('GET', url(path));
          expect(res.statusCode, `${id} ${path}`).toBe(409);
          expect(res.json()).toMatchObject({ code: 'BOARDS_NOT_CONNECTED' });
        }
      }
      expect(fake.requests).toHaveLength(0);
    });

    it("answers 502 BOARDS_UNAVAILABLE with the fixed text and its code, never Azure DevOps' words", async () => {
      const azure = await connect();
      fake.inject('GET', /\/_apis\/projects$/, {
        status: 401,
        body: { message: 'Azure says: go away' },
      });
      const res = await call('GET', url(`/projects?connection=${azure}`));
      expect(res.statusCode).toBe(502);
      expect(res.json()).toMatchObject({
        code: 'BOARDS_UNAVAILABLE',
        detail: AZURE_TEXT.refused,
        problemCode: 'token_refused',
      });
      expect(res.body).not.toContain('go away');
    });

    it('validates the query', async () => {
      const azure = await connect();
      for (const path of [
        '/projects',
        '/projects?connection=nope',
        `/work-item-types?connection=${azure}`,
        `/work-item-types?connection=${azure}&azureProject=Payments`,
        `/paths?connection=${azure}&azureProject=${payments.id}&extra=1`,
      ]) {
        expect((await call('GET', url(path))).statusCode, path).toBe(422);
      }
    });
  });

  describe('saving', () => {
    it('stores the mapping after a dry run that makes nothing, and audits it as created', async () => {
      const azure = await connect();
      const res = await put(azure, {
        azureProject: { id: payments.id.toUpperCase(), name: 'Payments' },
        areaPath: 'Payments\\Backend',
        iterationPath: 'payments\\iteration 1',
        tags: ['sec', 'team a'],
      });
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toEqual({
        mapping: {
          connectionId: azure,
          azureProject: { id: payments.id, name: 'Payments' },
          workItemType: { referenceName: BUG, name: 'Bug' },
          areaPath: 'Payments\\Backend',
          // As the project lists it.
          iterationPath: 'Payments\\Iteration 1',
          tags: ['sec', 'team a'],
          autoCreate: { minSeverity: null, exploited: false, since: null },
          updatedAt: expect.any(String),
        },
        connections: [expect.objectContaining({ id: azure })],
        monitoringOn: expect.any(Boolean),
        exploitedAvailable: false,
      });
      const [dryRun, ...more] = validations();
      expect(more).toEqual([]);
      expect(dryRun?.path).toBe(`/${payments.id}/_apis/wit/workitems/$Bug`);
      const ops = JSON.parse(dryRun!.body) as { op: string; path: string; value: unknown }[];
      expect(Object.fromEntries(ops.map((o) => [o.path, o.value]))).toMatchObject({
        '/fields/System.Title': 'Qualor mapping check',
        '/fields/Microsoft.VSTS.TCM.ReproSteps': expect.any(String),
        '/fields/System.Tags': 'qualor; sec; team a',
        '/fields/System.AreaPath': 'Payments\\Backend',
        '/fields/System.IterationPath': 'Payments\\Iteration 1',
      });
      expect(fake.workItems()).toEqual([]);
      expect(await stored()).toMatchObject({
        connectionId: azure,
        azureProjectId: payments.id,
        workItemTypeRef: BUG,
        workItemTypeName: 'Bug',
        autoSince: null,
      });
      expect(await events()).toEqual([{ changed: ['mapping'] }]);
      const again = await call('GET', url(), undefined, viewer.headers);
      expect((again.json() as { mapping: unknown }).mapping).not.toBeNull();
    });

    it("stores a renamed type's current name and dry-runs it by that name", async () => {
      const azure = await connect();
      paymentsBug().name = 'Defect';
      try {
        const res = await put(azure);
        expect(res.statusCode, res.body).toBe(200);
        expect(res.json()).toMatchObject({
          mapping: { workItemType: { referenceName: BUG, name: 'Defect' } },
        });
        expect(validations()[0]?.path).toBe(`/${payments.id}/_apis/wit/workitems/$Defect`);
      } finally {
        paymentsBug().name = 'Bug';
      }
    });

    it('lists what changed on an update, nothing when nothing did, and the whole mapping on remove', async () => {
      const azure = await connect();
      const second = await connect();
      const high = { minSeverity: 'high', exploited: false };
      const paths = { areaPath: 'Payments\\Backend', iterationPath: 'Payments\\Iteration 2' };
      for (const [connectionId, over] of [
        [azure, {}],
        [azure, {}],
        [azure, { tags: ['sec'], autoCreate: high }],
        [azure, { tags: ['sec'], autoCreate: high, ...paths }],
        [second, { tags: ['sec'], autoCreate: high, ...paths }],
        [
          second,
          { tags: ['sec'], autoCreate: high, ...paths, workItemType: { referenceName: TASK } },
        ],
        [
          second,
          {
            tags: ['sec'],
            autoCreate: high,
            azureProject: { id: platform.id, name: 'Platform' },
            workItemType: { referenceName: TASK },
          },
        ],
      ] as const) {
        const res = await put(connectionId, over);
        expect(res.statusCode, res.body).toBe(200);
      }
      expect((await call('DELETE', url())).statusCode).toBe(204);
      expect(await events()).toEqual([
        { changed: ['mapping'] },
        { changed: ['tags', 'autoCreate'] },
        { changed: ['areaPath', 'iterationPath'] },
        { changed: ['connection'] },
        { changed: ['workItemType'] },
        { changed: ['azureProject', 'areaPath', 'iterationPath'] },
        { changed: ['mapping'] },
      ]);
    });

    it("pulls the connection's pass to now when it changed something, and queues none when nothing", async () => {
      const azure = await connect();
      const passes = () =>
        h.ctx.db
          .select()
          .from(jobs)
          .where(
            and(
              eq(jobs.queue, BOARDS_QUEUE),
              eq(jobs.status, 'queued'),
              eq(jobs.concurrencyKey, boardsSyncKey(azure)),
            ),
          );
      const dueNow = async () => {
        const [pass, ...more] = await passes();
        expect(more).toEqual([]);
        expect(pass?.payload).toEqual({ kind: 'sync', connectionId: azure });
        expect(pass!.runAt.getTime()).toBeLessThanOrEqual(Date.now() + 60_000);
      };
      expect((await put(azure)).statusCode).toBe(200);
      await dueNow();

      await h.ctx.db.delete(jobs).where(eq(jobs.queue, BOARDS_QUEUE));
      expect((await put(azure)).statusCode).toBe(200);
      expect(await passes()).toEqual([]);

      expect((await put(azure, { tags: ['sec'] })).statusCode).toBe(200);
      await dueNow();
    });
  });

  describe('refusing', () => {
    it('checks in order: the connection, the other tracker, the type, the paths, the dry run, the licence', async () => {
      const azure = await connect();
      const githubId = await github();
      await connectJira(h, jira);
      await mapJira(h, projectId);
      const restore = requireTeam();
      const everything = {
        areaPath: 'Payments\\Nowhere',
        autoCreate: { minSeverity: null, exploited: true },
      };
      const code = (res: { json(): unknown }) => (res.json() as { code: string }).code;
      try {
        const notConnected = await put(githubId, everything);
        expect([notConnected.statusCode, code(notConnected)]).toEqual([
          409,
          'BOARDS_NOT_CONNECTED',
        ]);
        const inUse = await put(azure, everything);
        expect([inUse.statusCode, code(inUse)]).toEqual([409, 'TRACKER_IN_USE']);
        expect(fake.requests).toHaveLength(0);

        expect((await call('DELETE', `/api/v0/projects/${projectId}/jira`)).statusCode).toBe(204);
        const type = await put(azure, everything);
        expect([type.statusCode, code(type)]).toEqual([422, 'BOARDS_WORK_ITEM_TYPE_UNSUPPORTED']);
        expect(type.json()).toMatchObject({ missingFields: ['Custom.Team'] });
      } finally {
        restore();
      }
      const path = await put(azure, everything);
      expect([path.statusCode, code(path)]).toEqual([422, 'BOARDS_PATH_UNKNOWN']);
      expect(validations()).toEqual([]);

      const known = { ...everything, areaPath: 'Payments\\Backend' };
      fake.inject('POST', /\/_apis\/wit\/workitems\/\$Bug$/, refusedCreate('TF401320: refused'));
      const refused = await put(azure, known);
      expect([refused.statusCode, code(refused)]).toEqual([422, 'BOARDS_CREATE_REFUSED']);
      const licence = await put(azure, known);
      expect([licence.statusCode, code(licence)]).toEqual([403, 'FEATURE_NOT_LICENSED']);
      expect(await stored()).toBeUndefined();
      expect(await events()).toEqual([]);

      priorityLicensed = true;
      const saved = await put(azure, known);
      expect(saved.statusCode, saved.body).toBe(200);
      expect(await events()).toEqual([{ changed: ['mapping'] }]);
    });

    it('PUT refuses while a Jira mapping exists, and the Jira PUT refuses while a Boards mapping exists', async () => {
      const azure = await connect();
      await connectJira(h, jira);
      await mapJira(h, projectId);
      const boards = await put(azure);
      expect(boards.statusCode).toBe(409);
      expect(boards.json()).toMatchObject({ code: 'TRACKER_IN_USE' });
      expect(boards.json()).toMatchObject({ title: expect.stringMatching(/Jira/) });
      expect(await stored()).toBeUndefined();

      expect((await call('DELETE', `/api/v0/projects/${projectId}/jira`)).statusCode).toBe(204);
      expect((await put(azure)).statusCode).toBe(200);
      const jiraPut = await call('PUT', `/api/v0/projects/${projectId}/jira`, jiraBody);
      expect(jiraPut.statusCode).toBe(409);
      expect(jiraPut.json()).toMatchObject({
        code: 'TRACKER_IN_USE',
        title: expect.stringMatching(/Azure Boards/),
      });
      expect(
        await h.ctx.db
          .select()
          .from(projectJiraSettings)
          .where(eq(projectJiraSettings.projectId, projectId)),
      ).toEqual([]);

      expect((await call('DELETE', url())).statusCode).toBe(204);
      const after = await call('PUT', `/api/v0/projects/${projectId}/jira`, jiraBody);
      expect(after.statusCode, after.body).toBe(200);
      await call('DELETE', `/api/v0/projects/${projectId}/jira`);
    });

    it('refuses tags beyond the rules: 11, qualor, a ; or a , and duplicates in another case', async () => {
      const azure = await connect();
      const bad = [
        Array.from({ length: 11 }, (_, i) => `t${i}`),
        ['qualor'],
        ['Qualor'],
        ['a;b'],
        ['a,b'],
        ['Sec', 'sec'],
        [''],
        ['x'.repeat(101)],
        [' padded'],
        ['line\nbreak'],
      ];
      for (const tags of bad) {
        const res = await put(azure, { tags });
        expect(res.statusCode, JSON.stringify(tags)).toBe(422);
        expect(res.json()).toMatchObject({ code: 'VALIDATION_FAILED' });
        const paths = (res.json() as { errors: { path: string }[] }).errors.map((e) => e.path);
        expect(
          paths.every((p) => p.startsWith('body.tags')),
          JSON.stringify(paths),
        ).toBe(true);
      }
      expect(fake.requests).toHaveLength(0);
      expect(await stored()).toBeUndefined();
      const ten = Array.from({ length: 10 }, (_, i) => `team ${i}`);
      const res = await put(azure, { tags: ten });
      expect(res.statusCode, res.body).toBe(200);
      expect((await stored())?.tags).toEqual(ten);
    });

    it('validates the rest of the body', async () => {
      const azure = await connect();
      const bad = [
        { connectionId: 'nope' },
        { azureProject: { id: 'Payments', name: 'Payments' } },
        { azureProject: { id: payments.id, name: '' } },
        { workItemType: { referenceName: '' } },
        { workItemType: { referenceName: BUG, name: 'Bug' } },
        { areaPath: '' },
        { iterationPath: 'x'.repeat(4001) },
        { autoCreate: { minSeverity: 'unknown', exploited: false } },
        { extra: true },
      ];
      for (const over of bad) {
        const res = await put(azure, over);
        expect(res.statusCode, JSON.stringify(over)).toBe(422);
      }
      expect(await stored()).toBeUndefined();
    });

    it('refuses an area or iteration path the project does not list', async () => {
      const azure = await connect();
      for (const [over, field] of [
        [{ areaPath: 'Payments\\Nowhere' }, 'body.areaPath'],
        [{ areaPath: 'Basic' }, 'body.areaPath'],
        [{ iterationPath: 'Payments\\Iteration 9' }, 'body.iterationPath'],
      ] as const) {
        const res = await put(azure, over);
        expect(res.statusCode, JSON.stringify(over)).toBe(422);
        expect(res.json()).toMatchObject({
          code: 'BOARDS_PATH_UNKNOWN',
          errors: [{ path: field, message: expect.any(String) }],
        });
      }
      expect(validations()).toEqual([]);
      expect(await stored()).toBeUndefined();
    });

    it("refuses with Azure DevOps' words, cut to 500, when the dry run is refused", async () => {
      const azure = await connect();
      const words = `TF401320: Rule Error for field Title. ${'x'.repeat(600)}`;
      fake.inject('POST', /\/_apis\/wit\/workitems\/\$Bug$/, refusedCreate(words));
      const res = await put(azure);
      expect(res.statusCode).toBe(422);
      const problem = res.json() as { code: string; detail: string };
      expect(problem.code).toBe('BOARDS_CREATE_REFUSED');
      expect(problem.detail).toHaveLength(500);
      expect(problem.detail.startsWith('TF401320: Rule Error for field Title. xxx')).toBe(true);
      expect(problem.detail.endsWith('…')).toBe(true);
      expect(await stored()).toBeUndefined();
    });

    it('refuses a type the project does not have, hides, or no longer has at the dry run', async () => {
      const azure = await connect();
      for (const referenceName of [
        'Custom.Nothing',
        'Microsoft.VSTS.WorkItemTypes.TestPlan',
        // Basic has no Bug.
      ]) {
        const res = await put(azure, { workItemType: { referenceName } });
        expect(res.statusCode, referenceName).toBe(422);
        expect(res.json()).toMatchObject({
          code: 'BOARDS_WORK_ITEM_TYPE_UNSUPPORTED',
          missingFields: [],
        });
      }
      const onBasic = await put(azure, { azureProject: { id: basic.id, name: 'Basic' } });
      expect(onBasic.json()).toMatchObject({ code: 'BOARDS_WORK_ITEM_TYPE_UNSUPPORTED' });
      // A type gone between the list and the dry run (probe item 30d: a 404).
      fake.inject(
        'POST',
        /\/_apis\/wit\/workitems\/\$Bug$/,
        recordedAnswer('services', '30-pat-d-validate-no-type'),
      );
      const gone = await put(azure);
      expect(gone.statusCode).toBe(422);
      expect(gone.json()).toMatchObject({
        code: 'BOARDS_WORK_ITEM_TYPE_UNSUPPORTED',
        missingFields: [],
      });
      expect(gone.body).not.toContain('VS402323');
      expect(await stored()).toBeUndefined();
    });

    it('answers 502 BOARDS_UNAVAILABLE with the fixed text when Azure DevOps fails, and stores nothing', async () => {
      const azure = await connect();
      fake.inject('GET', /\/_apis\/wit\/workitemtypes$/, {
        status: 401,
        body: { message: 'secret words' },
      });
      const refused = await put(azure);
      expect(refused.statusCode).toBe(502);
      expect(refused.json()).toMatchObject({
        code: 'BOARDS_UNAVAILABLE',
        detail: AZURE_TEXT.refused,
        problemCode: 'token_refused',
      });
      expect(refused.body).not.toContain('secret words');
      fake.inject('POST', /\/_apis\/wit\/workitems\/\$Bug$/, {
        status: 403,
        body: { message: 'TF401027: no permission in the area' },
      });
      const forbidden = await put(azure);
      expect(forbidden.statusCode).toBe(502);
      expect(forbidden.json()).toMatchObject({
        code: 'BOARDS_UNAVAILABLE',
        detail: AZURE_TEXT.forbidden,
        problemCode: 'permission_missing',
      });
      expect(forbidden.body).not.toContain('TF401027');
      expect(await stored()).toBeUndefined();
    });

    it("answers 409 BOARDS_NOT_CONNECTED for a GitHub connection's id", async () => {
      await connect();
      for (const id of [await github(), await foreign()]) {
        const res = await put(id);
        expect(res.statusCode).toBe(409);
        expect(res.json()).toMatchObject({ code: 'BOARDS_NOT_CONNECTED' });
      }
      expect(fake.requests).toHaveLength(0);
      expect(await stored()).toBeUndefined();
    });
  });

  describe('the automatic rule', () => {
    it('refuses turning exploited on without vuln.priority, keeps a stored true (R10)', async () => {
      const azure = await connect();
      const on = { minSeverity: null, exploited: true };
      const refused = await put(azure, { autoCreate: on });
      expect(refused.statusCode).toBe(403);
      expect(refused.json()).toMatchObject({ code: 'FEATURE_NOT_LICENSED' });
      expect(await stored()).toBeUndefined();

      priorityLicensed = true;
      expect((await put(azure, { autoCreate: on })).statusCode).toBe(200);
      priorityLicensed = false;
      const kept = await put(azure, { autoCreate: on });
      expect(kept.statusCode, kept.body).toBe(200);
      expect(await stored()).toMatchObject({ autoExploited: true });
    });

    it('sets since whenever the rule changes, and clears it when the rule goes off', async () => {
      const azure = await connect();
      const high = { minSeverity: 'high', exploited: false };
      await put(azure, { autoCreate: high });
      expect((await stored())?.autoSince).toBeInstanceOf(Date);
      const old = new Date('2026-01-01T00:00:00Z');
      await h.ctx.db
        .update(projectBoardsSettings)
        .set({ autoSince: old })
        .where(eq(projectBoardsSettings.projectId, projectId));
      await put(azure, { tags: ['sec'], autoCreate: high });
      expect((await stored())?.autoSince?.getTime()).toBe(old.getTime());
      await put(azure, { tags: ['sec'], autoCreate: { minSeverity: 'medium', exploited: false } });
      expect((await stored())?.autoSince?.getTime()).toBeGreaterThan(old.getTime());
      await put(azure, { tags: ['sec'], autoCreate: { minSeverity: null, exploited: false } });
      expect(await stored()).toMatchObject({ autoMinSeverity: null, autoSince: null });
    });
  });

  describe('removing', () => {
    it('answers 204, keeps the links and audits mapping', async () => {
      const azure = await connect();
      expect((await put(azure)).statusCode).toBe(200);
      const [link] = await h.ctx.db
        .insert(boardsLinks)
        .values({
          projectId,
          connectionId: azure,
          azureProjectId: payments.id,
          kind: 'vulnerability',
          packageName: 'lodash',
          vulnerabilityId: 'CVE-2021-23337',
          state: 'pending',
          origin: 'manual',
        })
        .returning({ id: boardsLinks.id });
      since = await lastSeq();
      expect((await call('DELETE', url())).statusCode).toBe(204);
      expect(await stored()).toBeUndefined();
      expect(
        await h.ctx.db.select().from(boardsLinks).where(eq(boardsLinks.id, link!.id)),
      ).toHaveLength(1);
      expect(await events()).toEqual([{ changed: ['mapping'] }]);
    });

    it('answers 404 without a mapping and records nothing', async () => {
      const res = await call('DELETE', url());
      expect(res.statusCode).toBe(404);
      expect(res.json()).toMatchObject({ title: 'Boards mapping not found' });
      expect(await events()).toEqual([]);
    });
  });

  describe('access', () => {
    it('refuses a member the settings routes and a non-member everything', async () => {
      const azure = await connect();
      for (const [method, path, payload] of [
        ['PUT', url(), body(azure)],
        ['DELETE', url(), undefined],
        ['GET', url(`/projects?connection=${azure}`), undefined],
        ['GET', url(`/work-item-types?connection=${azure}&azureProject=${payments.id}`), undefined],
        ['GET', url(`/paths?connection=${azure}&azureProject=${payments.id}`), undefined],
      ] as const) {
        const asMember = await call(method, path, payload, member.headers);
        expect(asMember.statusCode, `${method} ${path}`).toBe(403);
        const asOutsider = await call(method, path, payload, outsider.headers);
        expect(asOutsider.statusCode, `${method} ${path}`).toBe(404);
      }
      expect((await call('GET', url(), undefined, outsider.headers)).statusCode).toBe(404);
      expect((await call('GET', url(), undefined, member.headers)).statusCode).toBe(200);
      expect(fake.requests).toHaveLength(0);
    });
  });
});
