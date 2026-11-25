import { hex32 } from '@qualor/shared';
import { and, eq, gt, inArray, sql } from 'drizzle-orm';
import type { Pool, PoolClient } from 'pg';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { azureConnection } from '../../test/azure-pending';
import { createFakeJira, type FakeJira } from '../../test/fake-jira';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule, type IssueSeed } from '../../test/issues';
import { connectJira, jiraTestConfig, mapJira, seedJiraLink } from '../../test/jira';
import { rbacPlugins } from '../../test/rbac';
import { trustTestCa } from '../../test/tls';
import { seedTargetRow } from '../../test/vulnerabilities';
import { BOARDS_QUEUE, boardsCreateKey } from '../boards/jobs';
import { uuidv7 } from '../db/ids';
import {
  auditEvents,
  boardsLinks,
  branches,
  issues,
  jiraLinks,
  jobs,
  projectBoardsSettings,
  projectJiraSettings,
  scmConnections,
  users,
} from '../db/schema';

const NOW = new Date('2027-01-01T00:00:00Z');
const CVE = 'CVE-2026-1111';
const BASE_URL = 'https://dev.azure.com/boards-links';
const AZURE_PROJECT = '6ce954b1-ce1f-45d1-b94d-e6bf2464ba2c';
/** The Azure DevOps project of an earlier mapping. */
const OLD_PROJECT = '0b1d2c3e-4f50-4617-8a9b-0c1d2e3f4a5b';

interface Link {
  id: string;
  state: string;
  origin: string;
  workItemId: number | null;
  url: string | null;
  workItemState: { name: string; category: string | null } | null;
  stateCheckedAt: string | null;
  failure: { code: string; message: string } | null;
  reportedFixedAt: string | null;
  createdAt: string;
}
interface Item {
  issueId?: string;
  packageName?: string;
  vulnerabilityId?: string;
  link: Link | null;
  skipped: 'NOT_FOUND' | 'NOT_ELIGIBLE' | 'ALREADY_LINKED' | null;
}
interface Trackers {
  jira: { id: string } | null;
  jiraLinkable: boolean;
  boards: Link | null;
  boardsLinkable: boolean;
}

/** The SQL a pool's clients send, captured at checkout (pool.query and transactions alike). */
function captureQueries(pool: Pool): string[] {
  const seen: string[] = [];
  const wrapped = new WeakSet<PoolClient>();
  pool.on('acquire', (client) => {
    if (wrapped.has(client)) return;
    wrapped.add(client);
    const original = client.query.bind(client) as (...args: unknown[]) => unknown;
    const query = (...args: unknown[]): unknown => {
      const [first] = args;
      if (typeof first === 'string') seen.push(first);
      else if (first !== null && typeof first === 'object' && 'text' in first) {
        seen.push((first as { text: string }).text);
      }
      return original(...args);
    };
    client.query = query as never;
  });
  return seen;
}

describe('Azure Boards links: request, retry, dismiss, embedded (design Â§7.8, plan Ruling 9)', () => {
  let h: IngestHarness;
  let jira: FakeJira;
  let untrust: () => void;
  let viewer: Session;
  let outsider: Session;
  let rater: Session;
  let project: IngestProject;
  let other: IngestProject;
  let projectId: string;
  let adminId: string;
  let connectionId: string;
  let jiraConnectionId: string;
  let main: string;
  let feature: string;
  let release: string;
  let mr: string;
  let codeRule: string;
  let trivyRule: string;
  let queries: string[];
  let since = 0;
  let pkgs = 0;

  const db = () => h.ctx.db;
  const post = (payload: object, session: Session = h.orgAdmin, id = projectId) =>
    h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/${id}/boards/links`,
      headers: session.headers,
      payload,
    });
  const items = async (payload: object, session?: Session): Promise<Item[]> => {
    const res = await post(payload, session);
    expect(res.statusCode, res.body).toBe(202);
    return (res.json() as { items: Item[] }).items;
  };
  const postJira = (payload: object) =>
    h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/${projectId}/jira/links`,
      headers: h.orgAdmin.headers,
      payload,
    });
  const retry = (id: string, headers: Record<string, string> = h.orgAdmin.headers) =>
    h.ctx.app.inject({ method: 'POST', url: `/api/v0/boards-links/${id}/retry`, headers });
  const dismiss = (id: string, headers: Record<string, string> = h.orgAdmin.headers) =>
    h.ctx.app.inject({ method: 'DELETE', url: `/api/v0/boards-links/${id}`, headers });
  const get = async <T>(url: string): Promise<T> => {
    const res = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0${url}`,
      headers: h.orgAdmin.headers,
    });
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as T;
  };
  const row = async (id: string) =>
    (await db().select().from(boardsLinks).where(eq(boardsLinks.id, id)))[0]!;
  const code = (branchId: string, over: Partial<IssueSeed> = {}) =>
    seedIssue(db(), { projectId, branchId, ruleId: codeRule, ...over });
  /** A Trivy issue of `lodash` and CVE unless `packageName` says otherwise. */
  const trivy = (branchId: string, packageName = 'lodash') =>
    seedIssue(db(), {
      projectId,
      branchId,
      ruleId: trivyRule,
      path: 'package-lock.json',
      packageName,
      quality: 'security',
    });
  const freshPackage = () => `pkg-boards-${++pkgs}`;
  /** The project's Boards mapping on `connection`, as the mapping PUT stores it. */
  const mapBoards = (connection = connectionId) =>
    db()
      .insert(projectBoardsSettings)
      .values({
        projectId,
        connectionId: connection,
        azureProjectId: AZURE_PROJECT,
        azureProjectName: 'Payments',
        workItemTypeRef: 'Microsoft.VSTS.WorkItemTypes.Bug',
        workItemTypeName: 'Bug',
      })
      .onConflictDoNothing();
  const unmapBoards = () =>
    db().delete(projectBoardsSettings).where(eq(projectBoardsSettings.projectId, projectId));
  /** A Boards link row, a pending issue one on the connection unless `over` says otherwise. */
  const seedBoardsLink = async (
    over: Partial<typeof boardsLinks.$inferInsert> & { issueId?: string },
  ): Promise<string> => {
    const [made] = await db()
      .insert(boardsLinks)
      .values({
        projectId,
        connectionId,
        azureProjectId: AZURE_PROJECT,
        kind: 'issue',
        state: 'pending',
        origin: 'manual',
        ...over,
      })
      .returning({ id: boardsLinks.id });
    return made!.id;
  };
  const lastSeq = async () =>
    Number(
      (
        await db()
          .select({ seq: sql<number>`coalesce(max(${auditEvents.seq}), 0)` })
          .from(auditEvents)
      )[0]?.seq ?? 0,
    );
  const events = async (action: string) =>
    (
      await db()
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, action), gt(auditEvents.seq, since)))
        .orderBy(auditEvents.seq)
    ).map((e) => ({ details: e.details, targetType: e.targetType, targetId: e.targetId }));
  const setProblem = (id: string, code: string | null) =>
    db()
      .update(scmConnections)
      .set({ problem: code === null ? null : { code: code as never, at: NOW.toISOString() } })
      .where(eq(scmConnections.id, id));

  beforeAll(async () => {
    untrust = trustTestCa();
    jira = await createFakeJira({ deployment: 'data_center' });
    jira.addProject({ id: '10000', key: 'QUAL', name: 'Qualor findings' });
    h = await createIngestHarness({
      config: jiraTestConfig(jira),
      pluginsFor: rbacPlugins({ now: () => NOW }),
    });
    queries = captureQueries(h.ctx.database.pool);
    const make = async (username: string, role?: 'viewer' | 'member') => {
      const user = await createUser(h.ctx, { username });
      if (role) await addMember(h.ctx, h.organizationId, user.id, role);
      return login(h.ctx, user.username, user.password);
    };
    viewer = await make('bl-viewer', 'viewer');
    outsider = await make('bl-outsider');
    rater = await make('bl-rater', 'member');
    project = await h.project('BL');
    other = await h.project('BL-OTHER');
    projectId = project.id;
    adminId = (await db().select().from(users).where(eq(users.username, 'ingest-admin')))[0]!.id;
    main = await mainBranchId(db(), projectId);
    const branch = async (name: string, kind: 'branch' | 'merge_request' = 'branch') =>
      (await db().insert(branches).values({ projectId, kind, name, isMain: false }).returning())[0]!
        .id;
    feature = await branch('feature/x');
    release = await branch('release/1');
    mr = await branch('42', 'merge_request');
    const monitoring = await h.ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/projects/${projectId}/vulnerability-monitoring`,
      headers: h.orgAdmin.headers,
      payload: {
        enabled: true,
        branchPatterns: ['release/*'],
        versionRule: { kind: 'none' },
        labelVersions: false,
      },
    });
    expect(monitoring.statusCode, monitoring.body).toBe(200);
    codeRule = await seedRule(db(), { key: 'eslint:no-eval' });
    trivyRule = await seedRule(db(), { key: `trivy:${CVE}`, quality: 'security' });
    jiraConnectionId = await connectJira(h, jira);
  });
  afterAll(async () => {
    await h.close();
    await jira.close();
    untrust();
  });
  beforeEach(async () => {
    connectionId = (
      await azureConnection(db(), {
        organizationId: h.organizationId,
        baseUrl: BASE_URL,
        secretKey: h.ctx.config.secretKey,
      })
    ).id;
    await mapBoards();
    since = await lastSeq();
  });
  afterEach(async () => {
    // The mapping and every Boards link go with the connection (CASCADE).
    await db().delete(scmConnections);
    await db().delete(jiraLinks);
    await db().delete(projectJiraSettings);
    await db().delete(jobs).where(eq(jobs.queue, BOARDS_QUEUE));
  });

  it('checks the preconditions in order: connected, no credential problem, mapped', async () => {
    const issueId = await code(main);
    await db().delete(scmConnections);
    const none = await post({ issueIds: [issueId] });
    expect([none.statusCode, none.json().code]).toEqual([409, 'BOARDS_NOT_CONNECTED']);

    connectionId = (
      await azureConnection(db(), {
        organizationId: h.organizationId,
        baseUrl: BASE_URL,
        secretKey: h.ctx.config.secretKey,
      })
    ).id;
    await mapBoards();
    await setProblem(connectionId, 'token_refused');
    const broken = await post({ issueIds: [issueId] });
    expect([broken.statusCode, broken.json().code, broken.json().problemCode]).toEqual([
      409,
      'BOARDS_CONNECTION_BROKEN',
      'token_refused',
    ]);
    // A service hook on probation or a timeout is not the credential: it refuses nothing.
    await setProblem(connectionId, 'hook_probation');
    const probation = await post({ issueIds: [issueId] });
    expect(probation.statusCode, probation.body).toBe(202);
    expect((probation.json() as { items: Item[] }).items[0]?.link?.state).toBe('pending');
    const [held] = await db()
      .select({ problem: scmConnections.problem })
      .from(scmConnections)
      .where(eq(scmConnections.id, connectionId));
    expect(held?.problem).toMatchObject({ code: 'hook_probation' });
    await db().delete(boardsLinks);
    await unmapBoards();
    const unmapped = await post({ issueIds: [issueId] });
    expect([unmapped.statusCode, unmapped.json().code]).toEqual([409, 'BOARDS_PROJECT_NOT_MAPPED']);
    await setProblem(connectionId, 'timeout');
    // Another Azure DevOps connection's credential problem is not the mapping's.
    const second = await azureConnection(db(), {
      organizationId: h.organizationId,
      baseUrl: 'https://dev.azure.com/boards-links-two',
      secretKey: h.ctx.config.secretKey,
    });
    await setProblem(second.id, 'token_refused');
    await mapBoards();
    const [item] = await items({ issueIds: [issueId] });
    expect(item?.link?.state).toBe('pending');
    expect(await db().select().from(boardsLinks)).toHaveLength(1);
    expect(await db().select().from(boardsLinks)).toMatchObject([{ connectionId }]);
  });

  it('links a code issue of main; other branches, merge requests and closed issues are not eligible', async () => {
    const open = await code(main);
    const onFeature = await code(feature);
    const onMr = await code(mr);
    const closed = await code(main, { status: 'closed' });
    const foreign = await seedIssue(db(), {
      projectId: other.id,
      branchId: await mainBranchId(db(), other.id),
      ruleId: codeRule,
    });
    const unknown = uuidv7();
    const answer = await items({ issueIds: [open, onFeature, onMr, closed, foreign, unknown] });
    expect(answer.map((i) => [i.issueId, i.skipped])).toEqual([
      [open, null],
      [onFeature, 'NOT_ELIGIBLE'],
      [onMr, 'NOT_ELIGIBLE'],
      [closed, 'NOT_ELIGIBLE'],
      [foreign, 'NOT_FOUND'],
      [unknown, 'NOT_FOUND'],
    ]);
    expect(answer.slice(1).every((i) => i.link === null)).toBe(true);
    const link = answer[0]!.link!;
    expect(link).toEqual({
      id: link.id,
      state: 'pending',
      origin: 'manual',
      workItemId: null,
      url: null,
      workItemState: null,
      stateCheckedAt: null,
      failure: null,
      reportedFixedAt: null,
      createdAt: link.createdAt,
    });
    const stored = await row(link.id);
    expect(stored).toMatchObject({
      kind: 'issue',
      issueId: open,
      projectId,
      connectionId,
      azureProjectId: AZURE_PROJECT,
      createdBy: adminId,
      generation: 1,
      attemptedAt: null,
    });
    expect(link.createdAt).toBe(stored.createdAt.toISOString());
  });

  it('answers a Trivy issue under its id with the vulnerability link of its pair, and links a pair', async () => {
    const onMain = await trivy(main);
    const [first] = await items({ issueIds: [onMain] });
    expect(first).toMatchObject({ issueId: onMain, skipped: null, link: { state: 'pending' } });
    expect(await row(first!.link!.id)).toMatchObject({
      kind: 'vulnerability',
      issueId: null,
      packageName: 'lodash',
      vulnerabilityId: CVE,
    });
    const [again] = await items({
      vulnerabilities: [{ packageName: 'lodash', vulnerabilityId: CVE }],
    });
    expect(again).toMatchObject({
      packageName: 'lodash',
      vulnerabilityId: CVE,
      skipped: 'ALREADY_LINKED',
      link: { id: first!.link!.id },
    });

    const pkg = freshPackage();
    await seedTargetRow(db(), {
      projectId,
      branchId: release,
      packageName: pkg,
      vulnerabilityId: 'CVE-2026-2222',
    });
    const answer = await items({
      vulnerabilities: [
        { packageName: pkg, vulnerabilityId: 'CVE-2026-2222' },
        { packageName: pkg, vulnerabilityId: 'CVE-2026-0404' },
      ],
    });
    expect(answer).toMatchObject([
      { packageName: pkg, vulnerabilityId: 'CVE-2026-2222', skipped: null },
      { packageName: pkg, vulnerabilityId: 'CVE-2026-0404', skipped: 'NOT_FOUND', link: null },
    ]);
    for (const body of [{}, { issueIds: [onMain], vulnerabilities: [] }, { issueIds: [] }]) {
      const res = await post(body);
      expect([res.statusCode, res.json().code], JSON.stringify(body)).toEqual([
        422,
        'VALIDATION_FAILED',
      ]);
    }
  });

  it('a finding linked in Jira is skipped as ALREADY_LINKED, and the Jira create skips a finding linked in Boards', async () => {
    // Boards side: a Jira row in any state, dismissed included, keeps the finding in Jira.
    const inJira = await code(main);
    const dismissedInJira = await code(main);
    const pkg = freshPackage();
    await seedTargetRow(db(), {
      projectId,
      branchId: main,
      packageName: pkg,
      vulnerabilityId: CVE,
    });
    await seedJiraLink(db(), {
      projectId,
      connectionId: jiraConnectionId,
      kind: 'issue',
      issueId: inJira,
      state: 'created',
      jiraKey: 'QUAL-1',
      jiraIssueId: '10001',
    });
    await seedJiraLink(db(), {
      projectId,
      connectionId: jiraConnectionId,
      kind: 'issue',
      issueId: dismissedInJira,
      state: 'dismissed',
    });
    await seedJiraLink(db(), {
      projectId,
      connectionId: jiraConnectionId,
      packageName: pkg,
      vulnerabilityId: CVE,
    });
    const free = await code(main);
    const answer = await items({ issueIds: [inJira, dismissedInJira, free] });
    expect(answer.map((i) => [i.issueId, i.skipped, i.link?.state ?? null])).toEqual([
      [inJira, 'ALREADY_LINKED', null],
      [dismissedInJira, 'ALREADY_LINKED', null],
      [free, null, 'pending'],
    ]);
    const [pair] = await items({ vulnerabilities: [{ packageName: pkg, vulnerabilityId: CVE }] });
    expect(pair).toMatchObject({ skipped: 'ALREADY_LINKED', link: null });
    expect(
      await db()
        .select()
        .from(boardsLinks)
        .where(inArray(boardsLinks.issueId, [inJira, dismissedInJira])),
    ).toEqual([]);
    expect(await db().select().from(boardsLinks).where(eq(boardsLinks.packageName, pkg))).toEqual(
      [],
    );

    // Jira side: a Boards row in any state keeps the finding in Boards.
    await unmapBoards();
    await mapJira(h, projectId);
    const dismissedInBoards = await code(main);
    await seedBoardsLink({ issueId: dismissedInBoards, state: 'dismissed', workItemId: 9 });
    const jiraFree = await code(main);
    const res = await postJira({ issueIds: [free, dismissedInBoards, jiraFree] });
    expect(res.statusCode, res.body).toBe(202);
    const jiraItems = (res.json() as { items: Item[] }).items;
    expect(jiraItems.map((i) => [i.issueId, i.skipped, i.link?.state ?? null])).toEqual([
      [free, 'ALREADY_LINKED', null],
      [dismissedInBoards, 'ALREADY_LINKED', null],
      [jiraFree, null, 'pending'],
    ]);
    expect(
      await db()
        .select()
        .from(jiraLinks)
        .where(inArray(jiraLinks.issueId, [free, dismissedInBoards])),
    ).toEqual([]);
  });

  it("a finding whose other tracker's link failed before its item was made may go to this one; outcome_unknown, an item or a dismissal keeps it there", async () => {
    type Detail = Trackers & { id: string };
    const detail = (id: string) => get<Detail>(`/issues/${id}`);
    type VulnItem = Trackers & { packageName: string };
    const vuln = async (packageName: string) =>
      (
        await get<{ items: VulnItem[] }>(`/projects/${projectId}/vulnerabilities?pageSize=100`)
      ).items.find((v) => v.packageName === packageName);

    // Boards side: the Jira rows.
    const inJira = async (over: Partial<typeof jiraLinks.$inferInsert>) => {
      const issueId = await code(main);
      await seedJiraLink(db(), {
        projectId,
        connectionId: jiraConnectionId,
        kind: 'issue',
        issueId,
        state: 'failed',
        ...over,
      });
      return issueId;
    };
    const jiraNeverMade = await inJira({ failure: { code: 'not_found', message: 'x' } });
    const jiraUnknown = await inJira({ failure: { code: 'outcome_unknown', message: 'x' } });
    const jiraMade = await inJira({
      failure: { code: 'field_refused', message: 'x' },
      jiraIssueId: '10009',
      jiraKey: 'QUAL-9',
    });
    const jiraDismissed = await inJira({ state: 'dismissed' });
    const jiraPkg = freshPackage();
    await seedTargetRow(db(), {
      projectId,
      branchId: main,
      packageName: jiraPkg,
      vulnerabilityId: CVE,
    });
    await seedJiraLink(db(), {
      projectId,
      connectionId: jiraConnectionId,
      packageName: jiraPkg,
      vulnerabilityId: CVE,
      state: 'failed',
      failure: { code: 'not_mapped', message: 'x' },
    });

    expect(await detail(jiraNeverMade)).toMatchObject({
      jira: { state: 'failed' },
      boardsLinkable: true,
    });
    for (const id of [jiraUnknown, jiraMade, jiraDismissed]) {
      expect((await detail(id)).boardsLinkable, id).toBe(false);
    }
    expect(await vuln(jiraPkg)).toMatchObject({ jira: { state: 'failed' }, boardsLinkable: true });
    const boardsAnswer = await items({
      issueIds: [jiraNeverMade, jiraUnknown, jiraMade, jiraDismissed],
    });
    expect(boardsAnswer.map((i) => [i.issueId, i.skipped, i.link?.state ?? null])).toEqual([
      [jiraNeverMade, null, 'pending'],
      [jiraUnknown, 'ALREADY_LINKED', null],
      [jiraMade, 'ALREADY_LINKED', null],
      [jiraDismissed, 'ALREADY_LINKED', null],
    ]);
    const [pair] = await items({
      vulnerabilities: [{ packageName: jiraPkg, vulnerabilityId: CVE }],
    });
    expect(pair).toMatchObject({ skipped: null, link: { state: 'pending' } });
    // A pending work item holds the finding now: Jira offers nothing more.
    expect(await detail(jiraNeverMade)).toMatchObject({
      boards: { state: 'pending' },
      jiraLinkable: false,
    });

    // Jira side: the Boards rows.
    await unmapBoards();
    await mapJira(h, projectId);
    const inBoards = async (over: Partial<typeof boardsLinks.$inferInsert>) => {
      const issueId = await code(main);
      await seedBoardsLink({ state: 'failed', ...over, issueId });
      return issueId;
    };
    const neverMade = await inBoards({ failure: { code: 'type_unsupported', message: 'x' } });
    const unknown = await inBoards({ failure: { code: 'outcome_unknown', message: 'x' } });
    const made = await inBoards({
      failure: { code: 'field_refused', message: 'x' },
      workItemId: 12,
    });
    const dismissed = await inBoards({ state: 'dismissed' });
    expect(await detail(neverMade)).toMatchObject({
      boards: { state: 'failed' },
      jiraLinkable: true,
    });
    for (const id of [unknown, made, dismissed]) {
      expect((await detail(id)).jiraLinkable, id).toBe(false);
    }
    const res = await postJira({ issueIds: [neverMade, unknown, made, dismissed] });
    expect(res.statusCode, res.body).toBe(202);
    expect(
      (res.json() as { items: Item[] }).items.map((i) => [
        i.issueId,
        i.skipped,
        i.link?.state ?? null,
      ]),
    ).toEqual([
      [neverMade, null, 'pending'],
      [unknown, 'ALREADY_LINKED', null],
      [made, 'ALREADY_LINKED', null],
      [dismissed, 'ALREADY_LINKED', null],
    ]);
  });

  it('re-arms a failed or dismissed row onto the mapping connection and project; a created row is already linked', async () => {
    const old = await azureConnection(db(), {
      organizationId: h.organizationId,
      baseUrl: 'https://dev.azure.com/boards-links-old',
      secretKey: h.ctx.config.secretKey,
    });
    const failedIssue = await code(main);
    const failed = await seedBoardsLink({
      issueId: failedIssue,
      connectionId: old.id,
      azureProjectId: OLD_PROJECT,
      state: 'failed',
      origin: 'auto',
      workItemId: 9,
      stateName: 'Closed',
      stateCategory: 'completed',
      stateCheckedAt: NOW,
      failure: { code: 'field_refused', message: 'TF401320' },
      attemptedAt: NOW,
      missedPasses: 1,
      reportedFixedAt: NOW,
    });
    const dismissedIssue = await code(main);
    const dismissed = await seedBoardsLink({
      issueId: dismissedIssue,
      state: 'dismissed',
      workItemId: 10,
    });
    const createdIssue = await code(main);
    const created = await seedBoardsLink({
      issueId: createdIssue,
      state: 'created',
      workItemId: 11,
      stateName: 'Active',
      stateCategory: 'inprogress',
      stateCheckedAt: NOW,
    });
    const answer = await items({ issueIds: [failedIssue, dismissedIssue, createdIssue] });
    expect(answer.map((i) => [i.link?.id, i.skipped])).toEqual([
      [failed, null],
      [dismissed, null],
      [created, 'ALREADY_LINKED'],
    ]);
    expect(answer[0]!.link).toMatchObject({
      state: 'pending',
      origin: 'manual',
      workItemId: null,
      url: null,
      workItemState: null,
      stateCheckedAt: null,
      failure: null,
      reportedFixedAt: null,
    });
    expect(await row(failed)).toMatchObject({
      state: 'pending',
      origin: 'manual',
      connectionId,
      azureProjectId: AZURE_PROJECT,
      generation: 2,
      workItemId: null,
      stateName: null,
      stateCategory: null,
      stateCheckedAt: null,
      failure: null,
      attemptedAt: null,
      missedPasses: 0,
      reportedFixedAt: null,
      createdBy: adminId,
    });
    expect(await row(dismissed)).toMatchObject({
      state: 'pending',
      generation: 2,
      workItemId: null,
    });
    expect(await row(created)).toMatchObject({ state: 'created', generation: 1, workItemId: 11 });
    expect(answer[2]!.link).toMatchObject({
      state: 'created',
      workItemId: 11,
      url: `${BASE_URL}/${AZURE_PROJECT}/_workitems/edit/11`,
      workItemState: { name: 'Active', category: 'inprogress' },
      stateCheckedAt: NOW.toISOString(),
    });
  });

  it('makes one row of two simultaneous requests for one issue', async () => {
    const issueId = await code(main);
    const [one, two] = await Promise.all([
      post({ issueIds: [issueId] }),
      post({ issueIds: [issueId] }),
    ]);
    expect([one!.statusCode, two!.statusCode]).toEqual([202, 202]);
    const answers = [one!, two!]
      .map((r) => (r.json() as { items: Item[] }).items[0]!)
      .sort((a, b) => String(a.skipped).localeCompare(String(b.skipped)));
    expect(answers.map((a) => [a.skipped, a.link?.state])).toEqual([
      ['ALREADY_LINKED', 'pending'],
      [null, 'pending'],
    ]);
    expect(answers[0]!.link!.id).toBe(answers[1]!.link!.id);
    expect(
      await db().select().from(boardsLinks).where(eq(boardsLinks.issueId, issueId)),
    ).toHaveLength(1);
  });

  it('charges one issue change per new link and refuses a request over the limit whole', async () => {
    const values = Array.from({ length: 501 }, (_, i) => ({
      projectId,
      branchId: main,
      ruleId: codeRule,
      fingerprint: hex32(`boards-rate:${i}`),
      lineHash: hex32(`boards-rate-line:${i}`),
      contextHash: hex32(`boards-rate-context:${i}`),
      path: 'src/rate.ts',
      startLine: i + 1,
      message: `Rate ${i}`,
      severity: 'medium',
      quality: 'maintainability',
      kind: 'issue' as const,
      status: 'open',
      inNewCode: false,
      firstSeenAt: sql`now()`,
    }));
    const ids = (await db().insert(issues).values(values).returning({ id: issues.id })).map(
      (r) => r.id,
    );
    const answer = await items({ issueIds: ids.slice(0, 500) }, rater);
    expect(answer.filter((i) => i.skipped === null)).toHaveLength(500);
    const over = await post({ issueIds: [ids[500]!] }, rater);
    expect([over.statusCode, over.json().code]).toEqual([429, 'RATE_LIMITED']);
    expect(Number(over.headers['retry-after'])).toBeGreaterThanOrEqual(1);
    expect(await db().select().from(boardsLinks).where(eq(boardsLinks.issueId, ids[500]!))).toEqual(
      [],
    );
  });

  it('retries a failed or missing link with generation + 1 onto the current mapping; refuses another state and an invisible one', async () => {
    const old = await azureConnection(db(), {
      organizationId: h.organizationId,
      baseUrl: 'https://dev.azure.com/boards-links-old',
      secretKey: h.ctx.config.secretKey,
    });
    const remapped = await seedBoardsLink({
      issueId: await code(main),
      connectionId: old.id,
      azureProjectId: OLD_PROJECT,
      state: 'failed',
      failure: { code: 'not_found', message: 'x' },
      attemptedAt: NOW,
    });
    // The project was mapped again (the mapping: another connection and Azure DevOps project): the
    // retry goes there, and only the mapping's connection is checked, as for a request.
    await setProblem(old.id, 'token_refused');
    const res = await retry(remapped);
    expect(res.statusCode, res.body).toBe(202);
    expect(res.json()).toMatchObject({ id: remapped, state: 'pending', failure: null, url: null });
    expect(await row(remapped)).toMatchObject({
      state: 'pending',
      generation: 2,
      attemptedAt: null,
      connectionId,
      azureProjectId: AZURE_PROJECT,
    });
    expect(await events('boards_link.requested')).toEqual([
      { details: { count: 1, kind: 'issue' }, targetType: 'project', targetId: projectId },
    ]);
    // The mapping's connection with a credential problem refuses, whatever the link's has.
    const unmovedLink = await seedBoardsLink({
      issueId: await code(main),
      connectionId: old.id,
      azureProjectId: OLD_PROJECT,
      state: 'failed',
      failure: { code: 'not_found', message: 'x' },
    });
    await setProblem(old.id, null);
    await setProblem(connectionId, 'sign_in_required');
    const mappingBroken = await retry(unmovedLink);
    expect([
      mappingBroken.statusCode,
      mappingBroken.json().code,
      mappingBroken.json().problemCode,
    ]).toEqual([409, 'BOARDS_CONNECTION_BROKEN', 'sign_in_required']);
    expect(await row(unmovedLink)).toMatchObject({ state: 'failed', connectionId: old.id });
    await setProblem(connectionId, null);

    // As Jira's ruling P15, no mapping refuses nothing: the link keeps its own connection, which is
    // checked, and Azure DevOps project, and the create step fails it `not_mapped`.
    await unmapBoards();
    await setProblem(old.id, 'token_refused');
    const oldBroken = await retry(unmovedLink);
    expect([oldBroken.statusCode, oldBroken.json().code]).toEqual([
      409,
      'BOARDS_CONNECTION_BROKEN',
    ]);
    await setProblem(old.id, null);
    const kept = await retry(unmovedLink);
    expect(kept.statusCode, kept.body).toBe(202);
    expect(await row(unmovedLink)).toMatchObject({
      state: 'pending',
      generation: 2,
      connectionId: old.id,
      azureProjectId: OLD_PROJECT,
    });

    const missing = await seedBoardsLink({
      issueId: await code(main),
      state: 'missing',
      workItemId: 31,
      missedPasses: 2,
    });
    const back = await retry(missing);
    expect(back.statusCode, back.body).toBe(202);
    expect(await row(missing)).toMatchObject({
      state: 'pending',
      generation: 2,
      workItemId: null,
      missedPasses: 0,
    });

    const created = await seedBoardsLink({
      issueId: await code(main),
      state: 'created',
      workItemId: 3,
    });
    const refused = await retry(created);
    expect([refused.statusCode, refused.json().code]).toEqual([409, 'BOARDS_LINK_NOT_RETRYABLE']);
    // The pending row just re-armed is not retryable either.
    expect((await retry(remapped)).json().code).toBe('BOARDS_LINK_NOT_RETRYABLE');

    await db().update(boardsLinks).set({ state: 'missing' }).where(eq(boardsLinks.id, created));
    await setProblem(connectionId, 'sign_in_required');
    const broken = await retry(created);
    expect([broken.statusCode, broken.json().code, broken.json().problemCode]).toEqual([
      409,
      'BOARDS_CONNECTION_BROKEN',
      'sign_in_required',
    ]);
    const hidden = await retry(created, outsider.headers);
    expect([hidden.statusCode, hidden.json().code]).toEqual([404, 'NOT_FOUND']);
    expect((await retry(uuidv7())).statusCode).toBe(404);
  });

  it('retries only a finding that may still have a work item; else 409, unchanged', async () => {
    const closed = await seedBoardsLink({
      issueId: await code(main, { status: 'closed' }),
      state: 'failed',
    });
    const offMain = await seedBoardsLink({
      issueId: await code(feature),
      state: 'missing',
      workItemId: 9,
    });
    since = await lastSeq();
    for (const id of [closed, offMain]) {
      const before = await row(id);
      const res = await retry(id);
      expect([res.statusCode, res.json().code], res.body).toEqual([
        409,
        'BOARDS_LINK_NOT_RETRYABLE',
      ]);
      expect(await row(id)).toEqual(before);
    }
    expect(await events('boards_link.requested')).toEqual([]);
  });

  it('dismiss audits the id: the row becomes dismissed and keeps its work item', async () => {
    const created = await seedBoardsLink({
      issueId: await code(main),
      state: 'created',
      workItemId: 42,
    });
    const res = await dismiss(created);
    expect(res.statusCode, res.body).toBe(204);
    expect(await row(created)).toMatchObject({ state: 'dismissed', workItemId: 42 });
    expect(await events('boards_link.dismissed')).toEqual([
      { details: { workItemId: 42 }, targetType: 'project', targetId: projectId },
    ]);
    // Again: nothing changes and nothing more is recorded.
    expect((await dismiss(created)).statusCode).toBe(204);
    expect(await events('boards_link.dismissed')).toHaveLength(1);
    expect((await dismiss(created, outsider.headers)).statusCode).toBe(404);

    const pending = await seedBoardsLink({ issueId: await code(main) });
    expect((await dismiss(pending)).statusCode).toBe(204);
    expect((await events('boards_link.dismissed')).map((e) => e.details)).toEqual([
      { workItemId: 42 },
      { workItemId: null },
    ]);
  });

  it('queues one create job on the connection of the rows a request or a retry made pending', async () => {
    const queuedCreates = (connection: string) =>
      db()
        .select()
        .from(jobs)
        .where(
          and(
            eq(jobs.queue, BOARDS_QUEUE),
            eq(jobs.status, 'queued'),
            eq(jobs.concurrencyKey, boardsCreateKey(connection)),
          ),
        );
    // A permission decoration recorded for one right of its own does not stop Boards.
    await setProblem(connectionId, 'permission_missing');
    const a = await code(main);
    const b = await code(main);
    const made = await items({ issueIds: [a, b] });
    expect(made.map((i) => i.link?.state)).toEqual(['pending', 'pending']);
    const [queued, ...more] = await queuedCreates(connectionId);
    expect(more).toEqual([]);
    expect(queued?.payload).toEqual({ kind: 'create', connectionId });

    // A request that makes nothing queues nothing.
    await db().delete(jobs).where(eq(jobs.queue, BOARDS_QUEUE));
    await items({ issueIds: [a, b] });
    expect(await queuedCreates(connectionId)).toEqual([]);

    // A retry of a link made on an earlier connection queues the create on the mapping's
    // connection, which the row moved to; without a mapping, on the link's own.
    const earlier = await azureConnection(db(), {
      organizationId: h.organizationId,
      baseUrl: 'https://dev.azure.com/boards-links-earlier',
      secretKey: h.ctx.config.secretKey,
    });
    const earlierLink = () =>
      code(main).then((issueId) =>
        seedBoardsLink({
          issueId,
          connectionId: earlier.id,
          state: 'failed',
          failure: { code: 'field_refused', message: 'x' },
        }),
      );
    const res = await retry(await earlierLink());
    expect(res.statusCode, res.body).toBe(202);
    expect(await queuedCreates(connectionId)).toHaveLength(1);
    expect(await queuedCreates(earlier.id)).toEqual([]);
    await db().delete(jobs).where(eq(jobs.queue, BOARDS_QUEUE));
    await unmapBoards();
    const unmapped = await retry(await earlierLink());
    expect(unmapped.statusCode, unmapped.body).toBe(202);
    expect(await queuedCreates(earlier.id)).toHaveLength(1);
    expect(await queuedCreates(connectionId)).toEqual([]);
  });

  it('records one boards_link.requested per request that made rows, with the form as kind', async () => {
    const a = await code(main);
    const b = await code(main);
    await items({ issueIds: [a, b] });
    expect(await events('boards_link.requested')).toEqual([
      { details: { count: 2, kind: 'issue' }, targetType: 'project', targetId: projectId },
    ]);
    await items({ issueIds: [a, b] });
    expect(await events('boards_link.requested')).toHaveLength(1);
    const pkg = freshPackage();
    await seedTargetRow(db(), {
      projectId,
      branchId: main,
      packageName: pkg,
      vulnerabilityId: CVE,
    });
    await items({ vulnerabilities: [{ packageName: pkg, vulnerabilityId: CVE }] });
    expect((await events('boards_link.requested')).map((e) => e.details)).toEqual([
      { count: 2, kind: 'issue' },
      { count: 1, kind: 'vulnerability' },
    ]);
  });

  it('the issue and vulnerability DTOs carry boards and boardsLinkable, in one query per page', async () => {
    type ListItem = Trackers & { id: string };
    // Newest first: main holds the rate test's 501 issues too.
    const list = async (branchId: string) =>
      (
        await get<{ items: ListItem[] }>(
          `/issues?branchId=${branchId}&status=open&sort=createdAt&limit=50`,
        )
      ).items;
    const pkg = freshPackage();
    const inBoards = await code(main);
    const inJira = await code(main);
    const plain = await code(main);
    const trivyIssue = await trivy(main, pkg);
    const onFeature = await code(feature);
    await seedTargetRow(db(), {
      projectId,
      branchId: main,
      packageName: pkg,
      vulnerabilityId: CVE,
    });
    const boardsLink = await seedBoardsLink({
      issueId: inBoards,
      state: 'created',
      workItemId: 7,
      stateName: 'Active',
      stateCategory: 'inprogress',
      stateCheckedAt: NOW,
    });
    const pairLink = await seedBoardsLink({
      kind: 'vulnerability',
      packageName: pkg,
      vulnerabilityId: CVE,
      state: 'created',
      workItemId: 8,
      stateName: 'Renamed state',
    });
    const jiraLink = await seedJiraLink(db(), {
      projectId,
      connectionId: jiraConnectionId,
      kind: 'issue',
      issueId: inJira,
      state: 'created',
      jiraKey: 'QUAL-2',
      jiraIssueId: '10002',
    });

    const start = queries.length;
    const onMain = await list(main);
    const boardsQueries = queries.slice(start).filter((q) => /\bboards_links\b/.test(q));
    expect(boardsQueries).toHaveLength(1);
    expect(onMain.find((i) => i.id === inBoards)).toMatchObject({
      boards: {
        id: boardsLink,
        state: 'created',
        workItemId: 7,
        url: `${BASE_URL}/${AZURE_PROJECT}/_workitems/edit/7`,
        workItemState: { name: 'Active', category: 'inprogress' },
        stateCheckedAt: NOW.toISOString(),
      },
      boardsLinkable: true,
      jira: null,
      jiraLinkable: false,
    });
    expect(onMain.find((i) => i.id === inJira)).toMatchObject({
      boards: null,
      boardsLinkable: false,
      jira: { id: jiraLink },
      jiraLinkable: true,
    });
    expect(onMain.find((i) => i.id === plain)).toMatchObject({
      boards: null,
      boardsLinkable: true,
      jira: null,
      jiraLinkable: true,
    });
    expect(onMain.find((i) => i.id === trivyIssue)).toMatchObject({
      boards: { id: pairLink, workItemState: { name: 'Renamed state', category: null } },
      boardsLinkable: true,
      jiraLinkable: false,
    });
    expect((await list(feature)).find((i) => i.id === onFeature)).toMatchObject({
      boards: null,
      boardsLinkable: false,
      jiraLinkable: false,
    });
    expect(await get<ListItem>(`/issues/${inBoards}`)).toMatchObject({
      boards: { id: boardsLink, workItemId: 7 },
      boardsLinkable: true,
      jiraLinkable: false,
    });
    expect(await get<ListItem>(`/issues/${inJira}`)).toMatchObject({
      boards: null,
      boardsLinkable: false,
      jiraLinkable: true,
    });

    type VulnItem = Trackers & { packageName: string; vulnerabilityId: string };
    const vulns = async () =>
      (await get<{ items: VulnItem[] }>(`/projects/${projectId}/vulnerabilities?pageSize=100`))
        .items;
    const vulnStart = queries.length;
    expect((await vulns()).find((v) => v.packageName === pkg)).toMatchObject({
      vulnerabilityId: CVE,
      boards: { id: pairLink, state: 'created', workItemId: 8 },
      boardsLinkable: true,
      jira: null,
      jiraLinkable: false,
    });
    expect(queries.slice(vulnStart).filter((q) => /\bboards_links\b/.test(q))).toHaveLength(1);

    // A pair linked in Jira (a dismissed row too) offers no Boards create.
    const jiraPkg = freshPackage();
    await seedTargetRow(db(), {
      projectId,
      branchId: main,
      packageName: jiraPkg,
      vulnerabilityId: CVE,
    });
    await seedJiraLink(db(), {
      projectId,
      connectionId: jiraConnectionId,
      packageName: jiraPkg,
      vulnerabilityId: CVE,
      state: 'dismissed',
    });
    expect((await vulns()).find((v) => v.packageName === jiraPkg)).toMatchObject({
      boards: null,
      boardsLinkable: false,
      jira: null,
      jiraLinkable: true,
    });

    // Without a mapping nothing is linkable in Boards; the links stay with their URLs.
    await unmapBoards();
    const unmapped = await list(main);
    expect(unmapped.find((i) => i.id === plain)).toMatchObject({ boardsLinkable: false });
    expect(unmapped.find((i) => i.id === inBoards)).toMatchObject({
      boards: {
        id: boardsLink,
        workItemId: 7,
        url: `${BASE_URL}/${AZURE_PROJECT}/_workitems/edit/7`,
      },
      boardsLinkable: false,
    });
    // A link made on an earlier mapping's Azure DevOps project keeps that project's URL.
    const earlier = await seedBoardsLink({
      issueId: await code(main),
      azureProjectId: OLD_PROJECT,
      state: 'created',
      workItemId: 70,
    });
    expect((await list(main)).find((i) => i.boards?.id === earlier)?.boards?.url).toBe(
      `${BASE_URL}/${OLD_PROJECT}/_workitems/edit/70`,
    );
    expect((await vulns()).find((v) => v.packageName === pkg)).toMatchObject({
      boardsLinkable: false,
    });
    await mapBoards();

    // A dismissed link reads as none, and still keeps the finding out of Jira.
    expect((await dismiss(boardsLink)).statusCode).toBe(204);
    expect((await list(main)).find((i) => i.id === inBoards)).toMatchObject({
      boards: null,
      boardsLinkable: true,
      jiraLinkable: false,
    });
  });

  it('refuses a viewer and a project token', async () => {
    const issueId = await code(main);
    const link = await seedBoardsLink({ issueId, state: 'failed' });
    const forbidden = [
      await post({ issueIds: [issueId] }, viewer),
      await retry(link, viewer.headers),
      await dismiss(link, viewer.headers),
    ];
    expect(forbidden.map((r) => [r.statusCode, r.json().code])).toEqual([
      [403, 'FORBIDDEN'],
      [403, 'FORBIDDEN'],
      [403, 'FORBIDDEN'],
    ]);
    const token = bearer(project.token);
    const tokens = [
      await h.ctx.app.inject({
        method: 'POST',
        url: `/api/v0/projects/${projectId}/boards/links`,
        headers: token,
        payload: { issueIds: [issueId] },
      }),
      await retry(link, token),
      await dismiss(link, token),
    ];
    expect(tokens.map((r) => [r.statusCode, r.json().code])).toEqual([
      [403, 'TOKEN_NOT_ALLOWED'],
      [403, 'TOKEN_NOT_ALLOWED'],
      [403, 'TOKEN_NOT_ALLOWED'],
    ]);
    expect(await row(link)).toMatchObject({ state: 'failed', generation: 1 });
  });
});
