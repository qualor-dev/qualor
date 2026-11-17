import { inspect } from 'node:util';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeJira, type FakeJira } from '../../test/fake-jira';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { connectJira, jiraJobDeps, jiraTestConfig, mapJira, runJiraJobs } from '../../test/jira';
import { seedTargetRow } from '../../test/vulnerabilities';
import type { Db } from '../db/client';
import {
  jiraConnections,
  jiraLinks,
  jobs,
  targetVulnerabilities,
  users,
  vulnerabilityEpss,
  vulnerabilityKev,
} from '../db/schema';
import { communityLimits } from '../limits';
import { claimJob, completeJob, enqueueMany } from '../queue/queue';
import type { WorkerLogger } from '../queue/worker';
import { CREATE_PER_RUN, createPending } from './create';
import { enqueueJiraCreate, JIRA_QUEUE, jiraCreateKey } from './jobs';
import { insertPendingLinks, JIRA_FAILURE_TEXT } from './links';
import { JIRA_PROBLEM_TEXT, setConnectionProblem } from './problems';
import { JIRA_LEASE_MS, openRun, type JiraJobDeps } from './run';

const PUBLIC_URL = 'https://qualor.example.com';
const QUAL = { id: '10000', key: 'QUAL', name: 'Qualor findings' };
const NEW = { id: '10100', key: 'NEW', name: 'New findings' };

interface SentRequest {
  fields: Record<string, unknown>;
}

describe('the Jira create job (spec §6.4, §11.2–11.5)', () => {
  let h: IngestHarness;
  let fake: FakeJira;
  let project: IngestProject;
  let projectId: string;
  let main: string;
  let codeRule: string;
  let adminId: string;
  let connectionId: string;
  let deps: JiraJobDeps;
  let pkgs = 0;

  const db = (): Db => h.ctx.db;
  const issue = (message?: string, severity: 'blocker' | 'high' | 'medium' = 'medium') =>
    seedIssue(db(), {
      projectId,
      branchId: main,
      ruleId: codeRule,
      severity,
      ...(message === undefined ? {} : { message }),
    });
  /** Pending links made through the links route (Task 6); their ids in request order. */
  const request = async (payload: object): Promise<string[]> => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/${projectId}/jira/links`,
      headers: h.orgAdmin.headers,
      payload,
    });
    expect(res.statusCode, res.body).toBe(202);
    return (res.json() as { items: { link: { id: string } | null }[] }).items.map(
      (i) => i.link!.id,
    );
  };
  const requestIssues = (issueIds: string[]) => request({ issueIds });
  /** `n` pending code-issue links inserted directly (no limiter), oldest first. */
  const pendingLinks = async (n: number): Promise<string[]> => {
    const issueIds: string[] = [];
    for (let i = 0; i < n; i++) issueIds.push(await issue(`finding ${i}`));
    const rows = await insertPendingLinks(
      db(),
      { projectId, connectionId, userId: adminId },
      issueIds.map((issueId) => ({ kind: 'issue' as const, issueId })),
    );
    return rows.map((r) => r.id);
  };
  const row = async (id: string) =>
    (await db().select().from(jiraLinks).where(eq(jiraLinks.id, id)))[0]!;
  const rows = () => db().select().from(jiraLinks);
  const connection = async () =>
    (await db().select().from(jiraConnections).where(eq(jiraConnections.id, connectionId)))[0];
  /** The organisation's create jobs (its pass waits a day ahead, connectJira). */
  const createJobs = () =>
    db()
      .select()
      .from(jobs)
      .where(
        and(eq(jobs.queue, JIRA_QUEUE), eq(jobs.concurrencyKey, jiraCreateKey(h.organizationId))),
      );
  const queuedCreates = async () => (await createJobs()).filter((j) => j.status === 'queued');
  const run = (over: Partial<JiraJobDeps> = {}) => runJiraJobs(h, { ...deps, ...over }, 'create');
  const sent = (path: RegExp): FakeJira['requests'] =>
    fake.requests.filter((r) => r.method === 'POST' && path.test(r.path));
  const creates = () => sent(/\/rest\/api\/2\/issue(\/bulk)?$/);
  /** Every element sent to a create, in the order sent. */
  const elements = (): SentRequest[] =>
    creates().flatMap((r) => {
      const body = JSON.parse(r.body) as { fields?: object; issueUpdates?: SentRequest[] };
      return body.issueUpdates ?? [{ fields: body.fields as Record<string, unknown> }];
    });
  const freshPackage = () => `pkg-create-${++pkgs}`;

  beforeAll(async () => {
    fake = await createFakeJira({ deployment: 'data_center' });
    fake.addProject(QUAL);
    fake.addProject(NEW);
    h = await createIngestHarness({ config: { ...jiraTestConfig(fake), publicUrl: PUBLIC_URL } });
    project = await h.project('JC');
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
    connectionId = await connectJira(h, fake);
    await mapJira(h, projectId, {
      labels: ['team-a'],
      priorities: { blocker: '1', high: '2', medium: '3', low: '4', info: '5' },
    });
    deps = jiraJobDeps(h);
    fake.clearRequests();
  });
  afterEach(async () => {
    await db().delete(jiraConnections);
    await db().delete(jobs).where(eq(jobs.queue, JIRA_QUEUE));
  });

  // First in the file: the fake's first issue is QUAL-1.
  it('one issue: POST /issue with the mapped fields, then created with its status read', async () => {
    const issueId = await issue('Do not use eval', 'high');
    const [linkId] = await requestIssues([issueId]);
    expect(await run()).toBe(1);

    expect(fake.requests.map((r) => `${r.method} ${r.path}`)).toEqual([
      'POST /rest/api/2/issue',
      'POST /rest/api/2/search',
    ]);
    const [element] = elements();
    expect(element!.fields).toEqual({
      project: { id: QUAL.id },
      issuetype: { id: '10001' },
      summary: 'Do not use eval',
      description: expect.stringContaining(
        `[Open in Qualor|${PUBLIC_URL}/projects/${projectId}/issues/${issueId}]`,
      ),
      labels: ['qualor', 'team-a', `qualor-${linkId!.replaceAll('-', '')}-1`],
      priority: { id: '2' },
    });
    const stored = await row(linkId!);
    expect(stored).toMatchObject({
      state: 'created',
      jiraIssueId: fake.issue('QUAL-1')!.id,
      jiraKey: 'QUAL-1',
      statusName: 'To Do',
      statusCategory: 'new',
      failure: null,
    });
    expect(stored.statusCheckedAt).not.toBeNull();
    expect(stored.attemptedAt).not.toBeNull();
    // The job ran to its end: nothing is queued after it.
    expect(await queuedCreates()).toHaveLength(0);
  });

  it('bulk: 120 rows in calls of 50, 50 and 20; 250 rows are 200 in a run and a job for the rest (R18)', async () => {
    const ids = await pendingLinks(120);
    await enqueueJiraCreate(db(), h.organizationId);
    await run();
    expect(
      sent(/\/issue\/bulk$/).map(
        (r) => (JSON.parse(r.body) as { issueUpdates: unknown[] }).issueUpdates.length,
      ),
    ).toEqual([50, 50, 20]);
    const all = await rows();
    expect(all.filter((r) => ids.includes(r.id)).every((r) => r.state === 'created')).toBe(true);
    expect(all.every((r) => r.statusName === 'To Do')).toBe(true);
    await db().delete(jiraLinks);

    fake.clearRequests();
    await pendingLinks(250);
    const ctx = (await openRun(deps, h.organizationId))!;
    expect(await createPending(ctx)).toEqual({
      created: CREATE_PER_RUN,
      failed: 0,
      unanswered: 0,
      stop: null,
    });
    expect(elements()).toHaveLength(200);
    const [next] = await queuedCreates();
    expect(next).toBeDefined();
    expect(next!.runAt.getTime()).toBeLessThanOrEqual(Date.now() + 5_000);
    await run();
    expect((await rows()).every((r) => r.state === 'created')).toBe(true);
    expect(elements()).toHaveLength(250);
    expect(await queuedCreates()).toHaveLength(0);
  });

  it('partial (spec §11.3): elements 2 and 5 of 7 refused, each success on its own finding', async () => {
    const messages = Array.from({ length: 7 }, (_, i) => `partial finding ${i}`);
    const issueIds: string[] = [];
    for (const m of messages) issueIds.push(await issue(m));
    const linkIds = await requestIssues(issueIds);
    fake.rejectElements([2, 5], {
      customfield_10010: 'Components is\nrequired.',
      description: 'd'.repeat(600),
    });
    await run();

    expect(sent(/\/issue\/bulk$/)).toHaveLength(1);
    const stored = await Promise.all(linkIds.map(row));
    const created = stored.filter((r) => r.state === 'created');
    const failed = stored.filter((r) => r.state === 'failed');
    expect(created).toHaveLength(5);
    expect(failed).toHaveLength(2);
    for (const r of created) {
      const message = messages[issueIds.indexOf(r.issueId!)];
      expect(fake.issue(r.jiraKey!)?.fields['summary']).toBe(message);
      expect(r.statusName).toBe('To Do');
    }
    expect(new Set(created.map((r) => r.jiraKey)).size).toBe(5);
    for (const r of failed) {
      expect(r.failure?.code).toBe('field_refused');
      expect(r.failure?.message).toMatch(/^Components is required\.; d+$/);
      expect(r.failure!.message.length).toBeLessThanOrEqual(500);
      expect(r.failure?.message).not.toContain('\n');
      expect(r.jiraKey).toBeNull();
    }
    // The refused elements are the third and the sixth sent.
    const sentLabels = elements().map((e) => (e.fields['labels'] as string[])[2]);
    for (const r of failed) {
      expect([2, 5]).toContain(
        sentLabels.indexOf(`qualor-${r.id.replaceAll('-', '')}-${r.generation}`),
      );
    }
  });

  it('refused: a single create answering 403, 404, 413 or 422 fails with its code', async () => {
    const cases = [
      [403, 'permission_missing'],
      [404, 'not_found'],
      [413, 'limit_reached'],
      [422, 'limit_reached'],
    ] as const;
    const before = fake.issues().length;
    for (const [status, code] of cases) {
      const [linkId] = await requestIssues([await issue()]);
      fake.inject('POST', /\/rest\/api\/2\/issue$/, { status });
      await run();
      expect(await row(linkId!), String(status)).toMatchObject({
        state: 'failed',
        failure: { code, message: JIRA_FAILURE_TEXT[code] },
        jiraKey: null,
      });
    }
    expect(fake.issues()).toHaveLength(before);
    expect(creates()).toHaveLength(cases.length);
  });

  it('a bulk answered 403 as a whole fails every row of the call (P6)', async () => {
    const linkIds = await requestIssues([await issue(), await issue(), await issue()]);
    fake.inject('POST', /\/issue\/bulk$/, { status: 403 });
    await run();
    for (const id of linkIds) {
      expect(await row(id)).toMatchObject({
        state: 'failed',
        failure: { code: 'permission_missing', message: JIRA_FAILURE_TEXT.permission_missing },
      });
    }
  });

  it('lost answer (spec §11.2): the issue is made, the answer lost; the row waits, never resent', async () => {
    for (const lost of ['hang', 'reset'] as const) {
      fake.clearRequests();
      const before = fake.issues().length;
      const [linkId] = await requestIssues([await issue()]);
      fake.inject('POST', /\/rest\/api\/2\/issue$/, { afterCreate: lost });
      await run();
      const stored = await row(linkId!);
      expect(stored.state, lost).toBe('pending');
      expect(stored.attemptedAt, lost).not.toBeNull();
      expect(fake.issues().length - before, lost).toBe(1);
      expect(creates(), lost).toHaveLength(1);
      // A later job does not send it again either.
      await enqueueJiraCreate(db(), h.organizationId);
      await run();
      expect(creates(), lost).toHaveLength(1);
      expect((await row(linkId!)).state).toBe('pending');
    }
  });

  it('a late answer: a row the pass failed outcome_unknown meanwhile becomes created, its reason gone', async () => {
    const [linkId] = await requestIssues([await issue()]);
    fake.inject('POST', /\/rest\/api\/2\/issue$/, {
      passThrough: true,
      before: async () => {
        await db()
          .update(jiraLinks)
          .set({
            state: 'failed',
            failure: { code: 'outcome_unknown', message: JIRA_FAILURE_TEXT.outcome_unknown },
          })
          .where(eq(jiraLinks.id, linkId!));
      },
    });
    await run();
    expect(await row(linkId!)).toMatchObject({
      state: 'created',
      failure: null,
      jiraKey: fake.issues().at(-1)!.key,
    });
  });

  it('R18: a run whose every call went unanswered queues no follow-up', async () => {
    await pendingLinks(CREATE_PER_RUN + 10);
    const html = {
      status: 200,
      headers: { 'content-type': 'text/html' },
      body: '<html><body>Sign in</body></html>',
    };
    fake.inject('POST', /\/issue\/bulk$/, html, html, html, html);
    const ctx = (await openRun(deps, h.organizationId))!;
    expect(await createPending(ctx)).toMatchObject({ unanswered: CREATE_PER_RUN, stop: null });
    expect(await queuedCreates()).toHaveLength(0);
  });

  it('HTML answer (Review Focus 2): a 200 sign-in page to a bulk keeps the rows pending, the job succeeds', async () => {
    const linkIds = await requestIssues([await issue(), await issue()]);
    fake.inject('POST', /\/issue\/bulk$/, {
      status: 200,
      headers: { 'content-type': 'text/html' },
      body: '<html><body>Sign in</body></html>',
    });
    await run();
    for (const id of linkIds) {
      const stored = await row(id);
      expect(stored.state).toBe('pending');
      expect(stored.attemptedAt).not.toBeNull();
    }
    expect(await createJobs()).toMatchObject([{ status: 'succeeded', lastError: null }]);
    // R16: a bad answer records no background problem.
    expect((await connection())?.problem).toBeNull();
  });

  it('credential: 401 records token_refused and releases the rows; no request while it is set; captcha too', async () => {
    const linkIds = await requestIssues([await issue(), await issue()]);
    fake.inject('POST', /\/issue\/bulk$/, { status: 401 });
    await run();
    expect((await connection())?.problem).toMatchObject({
      code: 'token_refused',
      message: JIRA_PROBLEM_TEXT.token_refused,
    });
    for (const id of linkIds) {
      expect(await row(id)).toMatchObject({ state: 'pending', attemptedAt: null });
    }
    expect(fake.requests).toHaveLength(1);

    // A second job while the problem is set makes no request.
    await enqueueJiraCreate(db(), h.organizationId);
    await run();
    expect(fake.requests).toHaveLength(1);
    for (const id of linkIds) expect((await row(id)).attemptedAt).toBeNull();

    // Data Center's CAPTCHA lockout.
    await setConnectionProblem(db(), connectionId, null);
    fake.inject('POST', /\/issue\/bulk$/, {
      status: 401,
      headers: { 'X-Seraph-LoginReason': 'AUTHENTICATION_DENIED' },
    });
    await enqueueJiraCreate(db(), h.organizationId);
    await run();
    expect((await connection())?.problem?.code).toBe('captcha');
    for (const id of linkIds) {
      expect(await row(id)).toMatchObject({ state: 'pending', attemptedAt: null });
    }
  });

  it('429: the rows are released and the create runs again after Retry-After', async () => {
    const linkIds = await requestIssues([await issue(), await issue()]);
    fake.inject('POST', /\/issue\/bulk$/, {
      status: 429,
      headers: { 'Retry-After': '30' },
      // A link request while the job runs queues a create job due now; the 429 moves it.
      before: async () => {
        await enqueueJiraCreate(db(), h.organizationId);
      },
    });
    await run();
    for (const id of linkIds) {
      expect(await row(id)).toMatchObject({ state: 'pending', attemptedAt: null });
    }
    expect(creates()).toHaveLength(1);
    const queued = await queuedCreates();
    expect(queued).toHaveLength(1);
    const [{ wait } = { wait: 0 }] = (
      await db().execute<{ wait: number }>(
        sql`SELECT extract(epoch FROM run_at - now())::float AS wait FROM jobs WHERE id = ${queued[0]!.id}`,
      )
    ).rows;
    expect(wait).toBeGreaterThan(25);
    expect(wait).toBeLessThanOrEqual(30);
    // R16: a 429 records no background problem.
    expect((await connection())?.problem).toBeNull();
  });

  it('transient: a hang records timeout; the next answered call clears it', async () => {
    const [hung] = await requestIssues([await issue()]);
    fake.inject('POST', /\/rest\/api\/2\/issue$/, { hang: true });
    await run();
    expect((await connection())?.problem).toMatchObject({
      code: 'timeout',
      message: JIRA_PROBLEM_TEXT.timeout,
    });
    expect((await row(hung!)).state).toBe('pending');

    // A transient problem refuses nothing: the next request runs and its answer clears it.
    const [next] = await requestIssues([await issue()]);
    await run();
    expect((await row(next!)).state).toBe('created');
    expect((await connection())?.problem).toBeNull();
  });

  it('unmapped (Review Focus 4): fails not_mapped; mapped again and retried, it lands in the new project', async () => {
    const [linkId] = await requestIssues([await issue('unmapped finding')]);
    const unmap = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/projects/${projectId}/jira`,
      headers: h.orgAdmin.headers,
    });
    expect(unmap.statusCode, unmap.body).toBe(204);
    await run();
    expect(await row(linkId!)).toMatchObject({
      state: 'failed',
      failure: { code: 'not_mapped', message: JIRA_FAILURE_TEXT.not_mapped },
    });
    expect(creates()).toHaveLength(0);

    await mapJira(h, projectId, { jiraProject: NEW });
    const retry = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/jira-links/${linkId}/retry`,
      headers: h.orgAdmin.headers,
    });
    expect(retry.statusCode, retry.body).toBe(202);
    await run();
    const stored = await row(linkId!);
    expect(stored).toMatchObject({ state: 'created', jiraKey: 'NEW-1', generation: 2 });
    expect(fake.issue('NEW-1')?.fields).toMatchObject({
      project: { id: NEW.id },
      summary: 'unmapped finding',
    });
  });

  it('finding gone (R8): a pair whose rows were deleted fails finding_gone, unsent', async () => {
    const pair = { packageName: freshPackage(), vulnerabilityId: 'CVE-2026-5001' };
    await seedTargetRow(db(), { projectId, branchId: main, ...pair });
    const [linkId] = await request({ vulnerabilities: [pair] });
    await db()
      .delete(targetVulnerabilities)
      .where(
        and(
          eq(targetVulnerabilities.projectId, projectId),
          eq(targetVulnerabilities.packageName, pair.packageName),
        ),
      );
    await run();
    expect(await row(linkId!)).toMatchObject({
      state: 'failed',
      failure: { code: 'finding_gone', message: JIRA_FAILURE_TEXT.finding_gone },
    });
    expect(creates()).toHaveLength(0);
  });

  it('finding gone (R7, R8): a pending row of a closed code issue fails finding_gone, unsent', async () => {
    // Re-armed before its issue closed, or made before Retry checked the finding (T12b).
    const issueId = await seedIssue(db(), {
      projectId,
      branchId: main,
      ruleId: codeRule,
      status: 'closed',
    });
    const [pending] = await insertPendingLinks(db(), { projectId, connectionId, userId: adminId }, [
      { kind: 'issue', issueId },
    ]);
    await enqueueJiraCreate(db(), h.organizationId);
    await run();
    expect(await row(pending!.id)).toMatchObject({
      state: 'failed',
      failure: { code: 'finding_gone', message: JIRA_FAILURE_TEXT.finding_gone },
    });
    expect(creates()).toHaveLength(0);
  });

  it('dismissed in flight (R19): the row stays dismissed and keeps the key Jira gave', async () => {
    const [linkId] = await requestIssues([await issue()]);
    fake.inject('POST', /\/rest\/api\/2\/issue$/, {
      passThrough: true,
      before: async () => {
        const res = await h.ctx.app.inject({
          method: 'DELETE',
          url: `/api/v0/jira-links/${linkId}`,
          headers: h.orgAdmin.headers,
        });
        expect(res.statusCode).toBe(204);
      },
    });
    await run();
    const stored = await row(linkId!);
    expect(stored.state).toBe('dismissed');
    expect(stored.jiraKey).toBe(fake.issues().at(-1)!.key);
    expect(stored.jiraIssueId).toBe(fake.issues().at(-1)!.id);
  });

  it('connection deleted in flight (Review Focus 5), or before the job: it ends quietly', async () => {
    const lines: unknown[][] = [];
    const logger: WorkerLogger = {
      info: (...a: unknown[]) => void lines.push(['info', ...a]),
      warn: (...a: unknown[]) => void lines.push(['warn', ...a]),
      error: (...a: unknown[]) => void lines.push(['error', ...a]),
    };
    await requestIssues([await issue()]);
    fake.inject('POST', /\/rest\/api\/2\/issue$/, {
      passThrough: true,
      before: async () => {
        await db().delete(jiraConnections).where(eq(jiraConnections.id, connectionId));
      },
    });
    expect(await run({ logger })).toBe(1);
    expect(await rows()).toHaveLength(0);
    expect((await createJobs()).map((j) => j.status)).toEqual(['succeeded']);
    expect(lines.filter(([level]) => level !== 'info')).toEqual([]);

    // T3b: a create job queued for a connection that is gone does nothing and queues nothing.
    connectionId = await connectJira(h, fake);
    await mapJira(h, projectId);
    await requestIssues([await issue()]);
    await db().delete(jiraConnections).where(eq(jiraConnections.id, connectionId));
    fake.clearRequests();
    expect(await run({ logger })).toBe(1);
    expect(fake.requests).toHaveLength(0);
    expect((await createJobs()).map((j) => j.status)).toEqual(['succeeded', 'succeeded']);
    expect(lines.filter(([level]) => level !== 'info')).toEqual([]);
  });

  it('moved (M1): a run that outlived an address change sends nothing more and records no problem', async () => {
    // The PUT that moves a connection keeps its id; the rows left stand for the new site's.
    const move = async (siteUrl: string) => {
      await db()
        .update(jiraConnections)
        .set({ siteUrl })
        .where(eq(jiraConnections.id, connectionId));
    };
    const [linkId] = await requestIssues([await issue()]);
    const stale = (await openRun(deps, h.organizationId))!;
    await move(`${fake.url}/moved`);
    expect(await createPending(stale)).toEqual({
      created: 0,
      failed: 0,
      unanswered: 0,
      stop: null,
    });
    expect(fake.requests).toHaveLength(0);
    expect(await row(linkId!)).toMatchObject({ state: 'pending', attemptedAt: null });

    // Moved while its call is out: the old site's 401 is not the new address's problem.
    await move(fake.url);
    const inFlight = (await openRun(deps, h.organizationId))!;
    fake.inject('POST', /\/rest\/api\/2\/issue$/, {
      status: 401,
      before: () => move(`${fake.url}/moved`),
    });
    expect((await createPending(inFlight)).stop).toBe('credential');
    expect(creates()).toHaveLength(1);
    expect((await connection())?.problem).toBeNull();
    expect((await row(linkId!)).state).toBe('pending');
  });

  it('one row, one send (R1, spec §11.4): two runs of the organisation at once send each row once', async () => {
    const ids = await pendingLinks(60);
    const [a, b] = await Promise.all([
      openRun(deps, h.organizationId),
      openRun(deps, h.organizationId),
    ]);
    const outcomes = await Promise.all([createPending(a!), createPending(b!)]);
    expect(outcomes.reduce((n, o) => n + o.created, 0)).toBe(60);
    const labels = elements().map((e) => (e.fields['labels'] as string[])[2]);
    expect(labels).toHaveLength(60);
    expect(new Set(labels).size).toBe(60);
    expect(
      fake.issues().filter((i) => labels.includes((i.fields['labels'] as string[])[2]!)),
    ).toHaveLength(60);
    const stored = await rows();
    expect(stored.filter((r) => ids.includes(r.id) && r.state === 'created')).toHaveLength(60);

    // P16: two queued create jobs of one organisation are never claimed together.
    const key = jiraCreateKey(h.organizationId);
    const payload = { kind: 'create', organizationId: h.organizationId };
    const [first, second] = await enqueueMany(db(), [
      { queue: JIRA_QUEUE, concurrencyKey: key, payload },
      { queue: JIRA_QUEUE, concurrencyKey: key, payload },
    ]);
    const claims = await Promise.all([
      claimJob(db(), JIRA_QUEUE, 'jira-a', JIRA_LEASE_MS),
      claimJob(db(), JIRA_QUEUE, 'jira-b', JIRA_LEASE_MS),
    ]);
    const claimed = claims.filter((j) => j !== null);
    expect(claimed.map((j) => j.id)).toEqual([first]);
    expect(await claimJob(db(), JIRA_QUEUE, 'jira-c', JIRA_LEASE_MS)).toBeNull();
    const owner = claims[0] === null ? 'jira-b' : 'jira-a';
    expect(await completeJob(db(), claimed[0]!, owner)).toBe('completed');
    expect((await claimJob(db(), JIRA_QUEUE, 'jira-c', JIRA_LEASE_MS))?.id).toBe(second);
  });

  it('never the token (spec §11.5): not in failure.message, jobs.last_error or a log line', async () => {
    const lines: unknown[][] = [];
    const logger: WorkerLogger = {
      info: (...a: unknown[]) => void lines.push(a),
      warn: (...a: unknown[]) => void lines.push(a),
      error: (...a: unknown[]) => void lines.push(a),
    };
    // A Data Center connection's one secret is its token (Cloud's email: create-cloud.db.test.ts).
    const [refused] = await requestIssues([await issue()]);
    fake.inject('POST', /\/rest\/api\/2\/issue$/, {
      status: 400,
      body: {
        errorMessages: [`Authorization: Bearer ${fake.token}`],
        errors: { reporter: `No user ${fake.email} for ${fake.token}` },
      },
    });
    await run({ logger });
    const failure = (await row(refused!)).failure;
    expect(failure?.code).toBe('field_refused');
    expect(failure?.message).toContain('[redacted]');

    // A job that fails after its Jira call: the database write that follows it throws.
    let failNext = true;
    const failing = new Proxy(db(), {
      get(target, prop, receiver) {
        if (prop === 'transaction' && failNext) {
          failNext = false;
          return () => Promise.reject(new Error('the database connection was lost'));
        }
        return Reflect.get(target, prop, receiver) as unknown;
      },
    });
    await requestIssues([await issue()]);
    await run({ logger, db: failing });
    expect(failNext).toBe(false);
    const failed = (await createJobs()).filter((j) => j.lastError !== null);
    expect(failed.map((j) => [j.status, j.lastError])).toEqual([
      ['queued', 'the database connection was lost'],
    ]);
    const texts = [
      failure?.message ?? '',
      ...failed.map((j) => j.lastError ?? ''),
      inspect(lines, { depth: 10, showHidden: true }),
    ];
    expect(lines.length).toBeGreaterThan(0);
    for (const text of texts) expect(text).not.toContain(fake.token);
  });

  it('priority lines (spec §11.11): Exploited and EPSS only with vuln.priority', async () => {
    const cve = 'CVE-2026-7001';
    await db().insert(vulnerabilityKev).values({ vulnerabilityId: cve, dateAdded: '2026-10-01' });
    await db()
      .insert(vulnerabilityEpss)
      .values({ vulnerabilityId: cve, score: 0.42, percentile: 0.97 });
    const descriptionOf = async (linkId: string): Promise<string> =>
      String(fake.issue((await row(linkId)).jiraKey!)!.fields['description']);

    const licensed = { packageName: freshPackage(), vulnerabilityId: cve };
    await seedTargetRow(db(), {
      projectId,
      branchId: main,
      ...licensed,
      title: 'Prototype pollution',
    });
    const [withPriority] = await request({ vulnerabilities: [licensed] });
    const limits = communityLimits();
    await run({
      limits: () => ({ vulnerabilities: { ...limits.vulnerabilities, priority: true } }),
    });
    const summary = fake.issue((await row(withPriority!)).jiraKey!)!.fields['summary'];
    expect(summary).toBe(`${cve} in ${licensed.packageName} (high)`);
    const licensedText = await descriptionOf(withPriority!);
    expect(licensedText).toContain('Exploited: CISA KEV, added 2026-10-01');
    expect(licensedText).toContain('EPSS: 42.0% (percentile 97)');

    const community = { packageName: freshPackage(), vulnerabilityId: cve };
    await seedTargetRow(db(), { projectId, branchId: main, ...community });
    const [without] = await request({ vulnerabilities: [community] });
    await run();
    const communityText = await descriptionOf(without!);
    expect(communityText).toContain(`Package: ${community.packageName.replaceAll('-', '\\-')}`);
    expect(communityText).not.toContain('Exploited:');
    expect(communityText).not.toContain('EPSS:');
  });

  it('a pair only a Trivy issue holds: the newest open issue gives the title and the severity (spec §6.4)', async () => {
    const cve = 'CVE-2026-7002';
    const trivyRule = await seedRule(db(), { key: `trivy:${cve}`, quality: 'security' });
    const packageName = freshPackage();
    const trivy = (message: string, severity: 'blocker' | 'high', status?: 'closed') =>
      seedIssue(db(), {
        projectId,
        branchId: main,
        ruleId: trivyRule,
        path: 'package-lock.json',
        packageName,
        quality: 'security',
        message,
        severity,
        ...(status === undefined ? {} : { status }),
      });
    await trivy('Older text', 'high');
    const newest = await trivy('Prototype pollution', 'blocker');
    await trivy('Closed text', 'high', 'closed');
    const [linkId] = await requestIssues([newest]);
    await run();
    const created = fake.issue((await row(linkId!)).jiraKey!)!;
    expect(created.fields['summary']).toBe(`${cve} in ${packageName} (critical)`);
    const description = String(created.fields['description']);
    expect(description.split('\n')[0]).toBe(
      `h3. ${cve.replaceAll('-', '\\-')}: Prototype pollution`,
    );
    expect(description).toContain('Found in: main');
    expect(description).toContain('Fixed in: no fixed version yet');
    expect(created.fields['priority']).toEqual({ id: '1' });
  });
});
