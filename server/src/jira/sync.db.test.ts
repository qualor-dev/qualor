import { inspect } from 'node:util';
import { and, eq, inArray, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeJira, type FakeJira } from '../../test/fake-jira';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule } from '../../test/issues';
import { connectJira, jiraJobDeps, jiraTestConfig, mapJira, runJiraJobs } from '../../test/jira';
import { seedTargetRow } from '../../test/vulnerabilities';
import type { PgUpdateSetSource } from 'drizzle-orm/pg-core';
import type { Db } from '../db/client';
import {
  analyses,
  issues,
  jiraConnections,
  jiraLinks,
  jobs,
  projectJiraSettings,
  projectVersions,
  projectVulnerabilitySettings,
  targetVulnerabilities,
  users,
  vulnerabilityDecisions,
} from '../db/schema';
import type { WorkerLogger } from '../queue/worker';
import { createPending } from './create';
import { JIRA_QUEUE, jiraSyncKey } from './jobs';
import { insertPendingLinks, JIRA_FAILURE_TEXT, type LinkTarget } from './links';
import { JIRA_PROBLEM_TEXT, replaceConnectionProblem, setConnectionProblem } from './problems';
import { openRun, type JiraJobDeps } from './run';
import { runSyncPass, STATUS_PER_PASS, type PassOutcome } from './sync';

const PUBLIC_URL = 'https://qualor.example.com';
const QUAL = { id: '10000', key: 'QUAL', name: 'Qualor findings' };
const MINUTE = 60_000;
const ISSUE = /\/rest\/api\/2\/issue$/;
const SEARCH = /\/rest\/api\/2\/search$/;

interface Created {
  linkId: string;
  issueId: string;
  key: string;
}

describe('the Jira sync pass (spec §6.5, §11.2, §11.6–11.9)', () => {
  let h: IngestHarness;
  let fake: FakeJira;
  /** The fake's clock runs this far ahead of the real one (its search lag reads it). */
  let shift = 0;
  let projectId: string;
  let main: string;
  let codeRule: string;
  let adminId: string;
  let connectionId: string;
  let deps: JiraJobDeps;
  let pkgs = 0;
  let labels = 0;

  const db = (): Db => h.ctx.db;
  const freshPair = () => ({
    packageName: `pkg-sync-${++pkgs}`,
    vulnerabilityId: `CVE-2026-${4200 + pkgs}`,
  });
  const row = async (id: string) =>
    (await db().select().from(jiraLinks).where(eq(jiraLinks.id, id)))[0]!;
  const setRow = (id: string, set: PgUpdateSetSource<typeof jiraLinks>) =>
    db().update(jiraLinks).set(set).where(eq(jiraLinks.id, id));
  const connection = async () =>
    (await db().select().from(jiraConnections).where(eq(jiraConnections.id, connectionId)))[0];
  const ago = (minutes: number) => sql`now() - make_interval(mins => ${minutes})`;
  const sent = (): string[] => fake.requests.map((r) => `${r.method} ${r.path}`);
  const commentsSent = () => sent().filter((r) => r.endsWith('/comment'));

  /** Pending links inserted directly: no create job is queued. */
  const pendingTargets = async (targets: LinkTarget[]): Promise<string[]> =>
    (await insertPendingLinks(db(), { projectId, connectionId, userId: adminId }, targets)).map(
      (r) => r.id,
    );
  const pendingIssues = async (n: number): Promise<{ linkId: string; issueId: string }[]> => {
    const issueIds: string[] = [];
    for (let i = 0; i < n; i++) {
      issueIds.push(
        await seedIssue(db(), { projectId, branchId: main, ruleId: codeRule, message: `f${i}` }),
      );
    }
    const linkIds = await pendingTargets(issueIds.map((issueId) => ({ kind: 'issue', issueId })));
    return linkIds.map((linkId, i) => ({ linkId, issueId: issueIds[i]! }));
  };
  const pendingIssue = async () => (await pendingIssues(1))[0]!;
  const create = async (over: Partial<JiraJobDeps> = {}) =>
    createPending((await openRun({ ...deps, ...over }, h.organizationId))!);
  /** `n` code-issue links created in the fake by the create step, with their Jira keys. */
  const createdIssues = async (n: number): Promise<Created[]> => {
    const pending = await pendingIssues(n);
    await create();
    return Promise.all(
      pending.map(async (p) => {
        const stored = await row(p.linkId);
        expect(stored.state).toBe('created');
        return { ...p, key: stored.jiraKey! };
      }),
    );
  };
  const createdIssue = async () => (await createdIssues(1))[0]!;
  /** One pass, run directly. */
  const runPass = async (over: Partial<JiraJobDeps> = {}): Promise<PassOutcome> =>
    runSyncPass((await openRun({ ...deps, ...over }, h.organizationId))!);
  /** The organisation's waiting pass, run through the queue (its reschedule included). */
  const runPassJob = (over: Partial<JiraJobDeps> = {}) =>
    runJiraJobs(h, { ...deps, ...over }, 'sync');
  const syncJobs = () =>
    db()
      .select()
      .from(jobs)
      .where(
        and(eq(jobs.queue, JIRA_QUEUE), eq(jobs.concurrencyKey, jiraSyncKey(h.organizationId))),
      );
  const queuedSyncs = async () => (await syncJobs()).filter((j) => j.status === 'queued');
  const close = (issueIds: string[], at: string) =>
    db()
      .update(issues)
      .set({ status: 'closed', closedAt: new Date(at) })
      .where(inArray(issues.id, issueIds));
  /** Open again, last seen by a succeeded analysis of `at` (the row keeps its id, spec §6.3). */
  const reopen = async (issueId: string, at: string) => {
    const [analysis] = await db()
      .insert(analyses)
      .values({
        projectId,
        branchId: main,
        status: 'succeeded',
        revision: 'b'.repeat(40),
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
  const setProblem = (code: 'captcha' | 'token_refused', minutesAgo: number) =>
    db()
      .update(jiraConnections)
      .set({
        problem: sql`jsonb_build_object('code', ${code}::text, 'message', ${JIRA_PROBLEM_TEXT[code]}::text, 'at', to_jsonb(${ago(minutesAgo)}))`,
      })
      .where(eq(jiraConnections.id, connectionId));
  /** A lost create (spec §11.2): Jira makes the issue, the answer never comes; `attempted_at` set. */
  const lostCreate = async (): Promise<string> => {
    const { linkId } = await pendingIssue();
    fake.inject('POST', ISSUE, { afterCreate: 'hang' });
    await create();
    const stored = await row(linkId);
    expect(stored).toMatchObject({ state: 'pending' });
    expect(stored.attemptedAt).not.toBeNull();
    return linkId;
  };
  const labelOf = (linkId: string, generation = 1) =>
    `qualor-${linkId.replaceAll('-', '')}-${generation}`;
  const fakeIssuesLabelled = (label: string) =>
    fake.issues().filter((i) => (i.fields['labels'] as string[] | undefined)?.includes(label));
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
    fake = await createFakeJira({ deployment: 'data_center', now: () => Date.now() + shift });
    fake.addProject(QUAL);
    h = await createIngestHarness({ config: { ...jiraTestConfig(fake), publicUrl: PUBLIC_URL } });
    projectId = (await h.project('JSYNC')).id;
    main = await mainBranchId(db(), projectId);
    codeRule = await seedRule(db(), { key: 'eslint:no-eval', name: 'No eval' });
    adminId = (await db().select().from(users).where(eq(users.username, 'ingest-admin')))[0]!.id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(async () => {
    shift = 0;
    fake.searchLag(0);
    connectionId = await connectJira(h, fake);
    await mapJira(h, projectId, { labels: [`team-${++labels}`] });
    await monitoring(true);
    deps = jiraJobDeps(h);
    fake.clearRequests();
  });
  afterEach(async () => {
    await db().delete(jiraConnections);
    await db().delete(jobs).where(eq(jobs.queue, JIRA_QUEUE));
  });

  it('reconcile (spec §11.2): a lost create with labels is found by its label, one Jira issue', async () => {
    const linkId = await lostCreate();
    const before = fake.issues().length;
    await setRow(linkId, { attemptedAt: ago(3) });
    fake.clearRequests();
    const outcome = await runPass();
    const stored = await row(linkId);
    const [made, ...more] = fakeIssuesLabelled(labelOf(linkId));
    expect(more).toEqual([]);
    expect(stored).toMatchObject({
      state: 'created',
      jiraIssueId: made!.id,
      jiraKey: made!.key,
      statusName: 'To Do',
      statusCategory: 'new',
    });
    expect(stored.statusCheckedAt).not.toBeNull();
    expect(fake.issues()).toHaveLength(before);
    expect(sent().filter((r) => ISSUE.test(r))).toEqual([]);
    expect(outcome).toMatchObject({ reconciled: 1, stop: null });
    // The answered search cleared the timeout the lost answer recorded.
    expect((await connection())?.problem).toBeNull();
  });

  it('search lag: nothing found at 3 minutes waits unchanged; a never-made issue at 11 minutes is sent again in the pass', async () => {
    fake.searchLag(15 * MINUTE);
    const lagging = await lostCreate();
    await setRow(lagging, { attemptedAt: ago(3) });
    const attempted = (await row(lagging)).attemptedAt;
    fake.clearRequests();
    await runPass();
    expect(await row(lagging)).toMatchObject({ state: 'pending', attemptedAt: attempted });
    expect(sent()).toEqual(['POST /rest/api/2/search']);
    // Once the search sees it, it is the issue Jira made.
    shift = 16 * MINUTE;
    await runPass();
    expect((await row(lagging)).state).toBe('created');
    expect(fakeIssuesLabelled(labelOf(lagging))).toHaveLength(1);

    // A hang before Jira made anything: after 10 minutes it is cleared and sent in the same pass.
    shift = 0;
    fake.searchLag(0);
    const { linkId: hung } = await pendingIssue();
    fake.inject('POST', ISSUE, { hang: true });
    await create();
    expect(fakeIssuesLabelled(labelOf(hung))).toEqual([]);
    await setRow(hung, { attemptedAt: ago(11) });
    fake.clearRequests();
    const outcome = await runPass();
    expect(sent().slice(0, 2)).toEqual(['POST /rest/api/2/search', 'POST /rest/api/2/issue']);
    expect(await row(hung)).toMatchObject({ state: 'created' });
    expect(fakeIssuesLabelled(labelOf(hung))).toHaveLength(1);
    expect(outcome).toMatchObject({ reconciled: 0, created: 1 });
  });

  it('no labels: an attempted row fails outcome_unknown and is never sent again; unmapped, it is searched first', async () => {
    await db()
      .update(projectJiraSettings)
      .set({ labelsAvailable: false })
      .where(eq(projectJiraSettings.projectId, projectId));
    const { linkId } = await pendingIssue();
    await setRow(linkId, { attemptedAt: ago(3) });
    await runPass();
    expect(await row(linkId)).toMatchObject({
      state: 'failed',
      failure: { code: 'outcome_unknown', message: JIRA_FAILURE_TEXT.outcome_unknown },
    });
    expect(sent()).toEqual([]);
    await runPass();
    expect((await row(linkId)).state).toBe('failed');
    expect(sent().filter((r) => ISSUE.test(r))).toEqual([]);

    // A project without a mapping: still searched by its label; not found after 10 minutes, failed.
    const res = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/projects/${projectId}/jira`,
      headers: h.orgAdmin.headers,
    });
    expect(res.statusCode, res.body).toBe(204);
    const { linkId: young } = await pendingIssue();
    const { linkId: old } = await pendingIssue();
    await setRow(young, { attemptedAt: ago(3) });
    await setRow(old, { attemptedAt: ago(11) });
    fake.clearRequests();
    await runPass();
    expect(sent()).toEqual(['POST /rest/api/2/search']);
    expect((await row(young)).state).toBe('pending');
    expect(await row(old)).toMatchObject({
      state: 'failed',
      failure: { code: 'outcome_unknown' },
    });
  });

  it('status: stored, a moved issue keeps its id, a deleted one is missing after two passes (spec §11.8)', async () => {
    const [moving, moved, deleted, back, odd] = await createdIssues(5);
    const before = await row(moving!.linkId);
    const movedId = (await row(moved!.linkId)).jiraIssueId;
    fake.setStatus(moving!.key, 'In Progress', 'indeterminate');
    fake.moveIssue(moved!.key, 'SEC-9');
    fake.deleteIssue(deleted!.key);
    await setRow(back!.linkId, { missedPasses: 1 });
    // T6b: a key Jira returns that is not of Jira's form is never stored.
    fake.moveIssue(odd!.key, 'not a key');
    fake.clearRequests();

    let outcome = await runPass();
    expect(await row(moving!.linkId)).toMatchObject({
      state: 'created',
      statusName: 'In Progress',
      statusCategory: 'indeterminate',
    });
    expect((await row(moving!.linkId)).statusCheckedAt!.getTime()).toBeGreaterThan(
      before.statusCheckedAt!.getTime(),
    );
    expect(await row(moved!.linkId)).toMatchObject({
      state: 'created',
      jiraKey: 'SEC-9',
      jiraIssueId: movedId,
    });
    expect(await row(deleted!.linkId)).toMatchObject({ state: 'created', missedPasses: 1 });
    expect((await row(back!.linkId)).missedPasses).toBe(0);
    expect((await row(odd!.linkId)).jiraKey).toBe(odd!.key);
    expect(outcome).toMatchObject({ statuses: 3, missing: 0, stop: null });
    expect(sent()).toEqual(['POST /rest/api/2/search']);

    outcome = await runPass();
    expect(await row(deleted!.linkId)).toMatchObject({ state: 'missing', missedPasses: 2 });
    expect(outcome.missing).toBe(1);

    // The mapping deleted: the link still gets its status.
    const res = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/projects/${projectId}/jira`,
      headers: h.orgAdmin.headers,
    });
    expect(res.statusCode, res.body).toBe(204);
    fake.setStatus(moving!.key, 'Done', 'done');
    await runPass();
    expect(await row(moving!.linkId)).toMatchObject({ statusName: 'Done', statusCategory: 'done' });
  });

  it(`cap: ${STATUS_PER_PASS + 100} created rows, ${STATUS_PER_PASS} read in a pass, the oldest checked first`, async () => {
    // Synthetic Jira ids the fake does not know: a read row counts one missed pass. Each row was
    // reported fixed already, so no comment is due.
    await db().execute(sql`
      INSERT INTO jira_links (id, project_id, connection_id, kind, package_name, vulnerability_id,
                              state, origin, jira_issue_id, jira_key, status_checked_at,
                              reported_fixed_at)
      SELECT uuidv7(), ${projectId}, ${connectionId}, 'vulnerability', 'cap-pkg-' || g, 'CVE-2026-9999',
             'created', 'manual', (900000 + g)::text, 'CAP-' || g,
             CASE WHEN g > 5090 THEN NULL ELSE now() - make_interval(secs => g) END, now()
        FROM generate_series(1, 5100) AS g`);
    const outcome = await runPass();
    expect(sent().filter((r) => SEARCH.test(r))).toHaveLength(STATUS_PER_PASS / 100);
    const read = await db().execute<{ g: number; missed: number }>(sql`
      SELECT substr(package_name, 9)::int AS g, missed_passes AS missed
        FROM jira_links WHERE connection_id = ${connectionId}`);
    const missed = read.rows.filter((r) => r.missed === 1).map((r) => r.g);
    expect(missed).toHaveLength(STATUS_PER_PASS);
    expect(read.rows.filter((r) => r.g > 5000).every((r) => r.missed === 1)).toBe(true);
    expect(read.rows.filter((r) => r.g <= 100).every((r) => r.missed === 0)).toBe(true);
    expect(outcome).toMatchObject({ statuses: 0, missing: 0, comments: 0, stop: null });
  });

  it('comments, code issue: fixed, found again, fixed again; nothing more after that', async () => {
    const { linkId, issueId, key } = await createdIssue();
    const link = `[Open in Qualor|${PUBLIC_URL}/projects/${projectId}/issues/${issueId}]`;
    await close([issueId], '2026-11-10T08:00:00Z');
    let outcome = await runPass();
    expect(fake.issue(key)!.comments).toEqual([
      `Qualor no longer finds this issue on main (analysis of 2026-11-10).\n${link}`,
    ]);
    expect(outcome.comments).toBe(1);
    expect((await row(linkId)).reportedFixedAt).not.toBeNull();

    // Reopened within 30 days: the same issue row.
    await reopen(issueId, '2026-11-12T09:00:00Z');
    await runPass();
    expect(fake.issue(key)!.comments[1]).toBe(
      `Qualor finds this again: eslint:no\\-eval on main (analysis of 2026-11-12).\n${link}`,
    );
    expect((await row(linkId)).reportedFixedAt).toBeNull();

    await close([issueId], '2026-11-14T10:00:00Z');
    await runPass();
    outcome = await runPass();
    expect(fake.issue(key)!.comments).toHaveLength(3);
    expect(fake.issue(key)!.comments[2]).toBe(
      `Qualor no longer finds this issue on main (analysis of 2026-11-14).\n${link}`,
    );
    expect(outcome.comments).toBe(0);
  });

  it('comments, vulnerability (spec §11.9): triage is not gone; an untracked last version is; gone, back, gone is three comments', async () => {
    const pair = freshPair();
    const [version] = await db()
      .insert(projectVersions)
      .values({
        projectId,
        label: '2.0.0',
        source: 'tag',
        tag: 'v2.0.0',
        analyzedAt: new Date(),
        tracking: 'pinned',
      })
      .returning();
    const track = (tracking: 'pinned' | 'unsupported') =>
      db().update(projectVersions).set({ tracking }).where(eq(projectVersions.id, version!.id));
    await seedTargetRow(db(), { projectId, versionId: version!.id, ...pair });
    const [linkId] = await pendingTargets([{ kind: 'vulnerability', ...pair }]);
    await create();
    const { jiraKey } = await row(linkId!);
    const comments = () => fake.issue(jiraKey!)!.comments;

    await db()
      .insert(vulnerabilityDecisions)
      .values({
        projectId,
        ...pair,
        status: 'false_positive',
        decidedBy: adminId,
      });
    await runPass();
    expect(comments()).toEqual([]);

    const escaped = (s: string) => s.replaceAll('-', '\\-');
    const link = `[Open in Qualor|${PUBLIC_URL}/projects/${projectId}/vulnerabilities?view=vulnerability]`;
    const fixed = `Qualor no longer finds ${escaped(pair.vulnerabilityId)} in ${escaped(pair.packageName)} on the tracked branches and versions of JSYNC.\n${link}`;
    await track('unsupported');
    await runPass();
    expect(comments()).toEqual([fixed]);
    expect((await row(linkId!)).reportedFixedAt).not.toBeNull();

    await track('pinned');
    await runPass();
    expect(comments()[1]).toBe(
      `Qualor finds this again: ${escaped(pair.vulnerabilityId)} in ${escaped(pair.packageName)} on 2.0.0.\n${link}`,
    );
    expect((await row(linkId!)).reportedFixedAt).toBeNull();

    await track('unsupported');
    await runPass();
    await runPass();
    expect(comments()).toEqual([fixed, expect.any(String), fixed]);
  });

  it('monitoring off: vulnerability links are not judged, a code issue still gets its comment', async () => {
    const pair = freshPair();
    await seedTargetRow(db(), { projectId, branchId: main, ...pair });
    const [vulnLink] = await pendingTargets([{ kind: 'vulnerability', ...pair }]);
    const { linkId: codeLink, issueId } = await pendingIssue();
    await create();
    const codeKey = (await row(codeLink)).jiraKey!;
    const vulnKey = (await row(vulnLink!)).jiraKey!;
    expect([codeKey, vulnKey]).not.toContain(null);
    await db()
      .delete(targetVulnerabilities)
      .where(
        and(
          eq(targetVulnerabilities.projectId, projectId),
          eq(targetVulnerabilities.packageName, pair.packageName),
        ),
      );
    await close([issueId], '2026-11-10T08:00:00Z');
    await monitoring(false);
    await runPass();
    expect(fake.issue(codeKey)!.comments).toHaveLength(1);
    expect(fake.issue(vulnKey)!.comments).toEqual([]);
    expect((await row(vulnLink!)).reportedFixedAt).toBeNull();

    // Judging resumes when monitoring comes back.
    await monitoring(true);
    await runPass();
    expect(fake.issue(vulnKey)!.comments).toHaveLength(1);
  });

  it('comment cap: 101 gone rows are 100 comments, the last in the next pass', async () => {
    const links = await createdIssues(101);
    await close(
      links.map((l) => l.issueId),
      '2026-11-10T08:00:00Z',
    );
    const commented = () => links.filter((l) => fake.issue(l.key)!.comments.length === 1).length;
    expect((await runPass()).comments).toBe(100);
    expect(commented()).toBe(100);
    expect((await runPass()).comments).toBe(1);
    expect(commented()).toBe(101);
  });

  it('refused comment (R14): a 403 still records the transition, warns, and is not tried again', async () => {
    const { lines, logger } = capture();
    const { linkId, issueId, key } = await createdIssue();
    await close([issueId], '2026-11-10T08:00:00Z');
    fake.inject('POST', /\/comment$/, { status: 403 });
    const outcome = await runPass({ logger });
    expect((await row(linkId)).reportedFixedAt).not.toBeNull();
    expect(fake.issue(key)!.comments).toEqual([]);
    expect(outcome.comments).toBe(0);
    const warns = lines.filter(([level]) => level === 'warn');
    expect(warns).toHaveLength(1);
    expect(inspect(warns)).toContain(linkId);
    expect(inspect(warns)).toContain('permission_missing');
    fake.clearRequests();
    await runPass({ logger });
    expect(commentsSent()).toEqual([]);
  });

  it('comment answered with a 200 sign-in page (M2): not recorded; the next pass posts it', async () => {
    const { linkId, issueId, key } = await createdIssue();
    await close([issueId], '2026-11-10T08:00:00Z');
    fake.inject('POST', /\/comment$/, {
      status: 200,
      headers: { 'content-type': 'text/html' },
      body: '<html><body>Sign in</body></html>',
    });
    expect(await runPass()).toMatchObject({ comments: 0, stop: null });
    expect((await row(linkId)).reportedFixedAt).toBeNull();
    // R16: a bad answer records no background problem.
    expect((await connection())?.problem).toBeNull();
    expect(await runPass()).toMatchObject({ comments: 1, stop: null });
    expect(fake.issue(key)!.comments).toHaveLength(1);
    expect((await row(linkId)).reportedFixedAt).not.toBeNull();
  });

  it('expired token (spec §11.6): the pass ends at the 401, probes only after, and a new token lets it go on', async () => {
    const { issueId } = await createdIssue();
    // A comment is due: a pass that went on after the 401 would send it.
    await close([issueId], '2026-11-10T08:00:00Z');
    fake.clearRequests();
    fake.inject('POST', SEARCH, { status: 401 });
    expect(await runPassJob()).toBe(1);
    expect((await connection())?.problem).toMatchObject({
      code: 'token_refused',
      message: JIRA_PROBLEM_TEXT.token_refused,
    });
    expect(sent()).toEqual(['POST /rest/api/2/search']);

    fake.clearRequests();
    fake.inject('GET', /\/myself$/, { status: 401 });
    expect(await runPassJob()).toBe(1);
    expect(sent()).toEqual(['GET /rest/api/2/myself']);
    expect((await connection())?.problem?.code).toBe('token_refused');

    const other = await seedIssue(db(), { projectId, branchId: main, ruleId: codeRule });
    const refused = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/${projectId}/jira/links`,
      headers: h.orgAdmin.headers,
      payload: { issueIds: [other] },
    });
    expect([refused.statusCode, refused.json().code]).toEqual([409, 'JIRA_CONNECTION_BROKEN']);

    // R5: a new token clears the problem and makes the waiting pass due now.
    const put = await h.ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/organizations/${h.organizationId}/jira`,
      headers: h.orgAdmin.headers,
      payload: { deployment: 'data_center', siteUrl: fake.url, token: fake.token },
    });
    expect(put.statusCode, put.body).toBe(200);
    expect((await connection())?.problem).toBeNull();
    const due = await db().execute<{ due: boolean }>(sql`
      SELECT run_at <= now() AS due FROM jobs
       WHERE queue = ${JIRA_QUEUE} AND status = 'queued'
         AND concurrency_key = ${jiraSyncKey(h.organizationId)}`);
    expect(due.rows).toEqual([{ due: true }]);
    const [linkId] = await pendingTargets([{ kind: 'issue', issueId: other }]);
    fake.clearRequests();
    expect(await runPassJob()).toBe(1);
    expect(sent()).not.toContain('GET /rest/api/2/myself');
    expect(sent()).toContain('POST /rest/api/2/issue');
    expect((await row(linkId!)).state).toBe('created');
    expect(commentsSent()).toHaveLength(1);
    expect((await connection())?.problem).toBeNull();
  });

  it('captcha: no probe within the hour; one an hour later, which clears the problem when it passes', async () => {
    const { key } = await createdIssue();
    fake.setStatus(key, 'In Progress', 'indeterminate');
    await setProblem('captcha', 10);
    fake.clearRequests();
    expect((await runPass()).stop).toBe('captcha_wait');
    expect(sent()).toEqual([]);

    // An hour later: one probe, refused again; the hour starts from it.
    await setProblem('captcha', 61);
    const old = (await connection())!.problem!.at;
    fake.inject('GET', /\/myself$/, {
      status: 401,
      headers: { 'X-Seraph-LoginReason': 'AUTHENTICATION_DENIED' },
    });
    expect((await runPass()).stop).toBe('credential');
    expect(sent()).toEqual(['GET /rest/api/2/myself']);
    const fresh = (await connection())!.problem!;
    expect(fresh.code).toBe('captcha');
    expect(Date.parse(fresh.at)).toBeGreaterThan(Date.parse(old));
    fake.clearRequests();
    expect((await runPass()).stop).toBe('captcha_wait');
    expect(sent()).toEqual([]);

    // The lockout reset: the probe passes, the problem goes and the pass goes on.
    await setProblem('captcha', 61);
    const outcome = await runPass();
    expect(sent()).toEqual(['GET /rest/api/2/myself', 'POST /rest/api/2/search']);
    expect((await connection())?.problem).toBeNull();
    expect(outcome).toMatchObject({ statuses: 1, stop: null });
  });

  it('captcha (F1): a probe that hangs or gets an HTML page still starts the hour', async () => {
    await createdIssue();
    const answers = [
      { hang: true },
      { status: 200, headers: { 'content-type': 'text/html' }, body: '<html>Sign in</html>' },
    ];
    for (const answer of answers) {
      await setProblem('captcha', 61);
      const old = (await connection())!.problem!.at;
      fake.inject('GET', /\/myself$/, answer);
      fake.clearRequests();
      await runPass();
      expect(sent()).toEqual(['GET /rest/api/2/myself']);
      const fresh = (await connection())!.problem!;
      expect(fresh.code).toBe('captcha');
      expect(Date.parse(fresh.at)).toBeGreaterThan(Date.parse(old) + 60 * MINUTE);
      // The next pass, 15 minutes on, makes no request.
      await db()
        .update(jiraConnections)
        .set({
          problem: sql`jsonb_set(problem, '{at}', to_jsonb(${ago(15)}))`,
        })
        .where(eq(jiraConnections.id, connectionId));
      fake.clearRequests();
      expect((await runPass()).stop).toBe('captcha_wait');
      expect(sent()).toEqual([]);
    }
  });

  it('credential over transient (F2): a 401 is recorded over a timeout a create job stored meanwhile', async () => {
    await createdIssue();
    const other = await seedIssue(db(), { projectId, branchId: main, ruleId: codeRule });
    fake.inject('POST', SEARCH, {
      status: 401,
      before: () => setConnectionProblem(db(), connectionId, 'timeout'),
    });
    expect((await runPass()).stop).toBe('credential');
    expect((await connection())?.problem?.code).toBe('token_refused');
    const refused = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/${projectId}/jira/links`,
      headers: h.orgAdmin.headers,
      payload: { issueIds: [other] },
    });
    expect([refused.statusCode, refused.json().code]).toEqual([409, 'JIRA_CONNECTION_BROKEN']);

    // Never the reverse: a transient code does not replace a credential one.
    const view = { ...(await connection())!, problem: null };
    expect(await replaceConnectionProblem(db(), view, 'timeout')).toBe(false);
    const stored = (await connection())!.problem!;
    expect(stored.code).toBe('token_refused');
    expect(
      await replaceConnectionProblem(
        db(),
        { ...(await connection())!, problem: stored },
        'unreachable',
      ),
    ).toBe(false);
    expect((await connection())?.problem?.code).toBe('token_refused');
  });

  it('transient: a hang on status records timeout and ends the pass; the next pass clears it', async () => {
    const { linkId, issueId, key } = await createdIssue();
    fake.setStatus(key, 'In Progress', 'indeterminate');
    await close([issueId], '2026-11-10T08:00:00Z');
    fake.inject('POST', SEARCH, { hang: true });
    fake.clearRequests();
    expect((await runPass()).stop).toBe('transient');
    expect((await connection())?.problem).toMatchObject({
      code: 'timeout',
      message: JIRA_PROBLEM_TEXT.timeout,
    });
    expect(sent()).toEqual(['POST /rest/api/2/search']);

    const outcome = await runPass();
    expect(outcome).toMatchObject({ statuses: 1, comments: 1, stop: null });
    expect((await connection())?.problem).toBeNull();
    expect((await row(linkId)).statusName).toBe('In Progress');
  });

  it('budget: a pass stops at its last request; the next pass does the rest', async () => {
    const links = await createdIssues(7);
    await close(
      links.map((l) => l.issueId),
      '2026-11-10T08:00:00Z',
    );
    const tight = { clientOptions: { timeoutMs: 1_000, maxRequests: 5 } };
    fake.clearRequests();
    let outcome = await runPass(tight);
    expect(fake.requests).toHaveLength(5);
    expect(outcome).toMatchObject({ statuses: 7, comments: 4, stop: 'budget' });
    fake.clearRequests();
    outcome = await runPass(tight);
    expect(fake.requests).toHaveLength(4);
    expect(outcome).toMatchObject({ comments: 3, stop: null });
    expect(links.every((l) => fake.issue(l.key)!.comments.length === 1)).toBe(true);
  });

  it('rescheduled: after a pass one sync is queued, due in 15 minutes; one info line per pass', async () => {
    const { lines, logger } = capture();
    expect(await runPassJob({ logger })).toBe(1);
    const queued = await queuedSyncs();
    expect(queued).toHaveLength(1);
    const [{ wait } = { wait: 0 }] = (
      await db().execute<{ wait: number }>(
        sql`SELECT extract(epoch FROM run_at - now())::float AS wait FROM jobs WHERE id = ${queued[0]!.id}`,
      )
    ).rows;
    expect(wait).toBeGreaterThan(890);
    expect(wait).toBeLessThanOrEqual(900);
    const passLines = lines.filter(
      ([level, , message]) => level === 'info' && message === 'Jira sync pass',
    );
    expect(passLines).toHaveLength(1);
    expect(passLines[0]![1]).toMatchObject({
      organizationId: h.organizationId,
      connectionId,
      durationMs: expect.any(Number),
      reconciled: 0,
      created: 0,
      statuses: 0,
      comments: 0,
      stop: null,
    });
    expect(inspect(lines, { depth: 10 })).not.toContain(fake.token);
  });

  it('moved (M1): a pass that outlived an address change reads, comments and writes nothing', async () => {
    const { linkId, issueId } = await createdIssue();
    // A comment and a status read are due; the rows left stand for the new site's.
    await close([issueId], '2026-11-10T08:00:00Z');
    await setRow(linkId, { statusCheckedAt: null });
    const stale = (await openRun(deps, h.organizationId))!;
    await db()
      .update(jiraConnections)
      .set({ siteUrl: `${fake.url}/moved` })
      .where(eq(jiraConnections.id, connectionId));
    fake.clearRequests();
    expect(await runSyncPass(stale)).toMatchObject({
      reconciled: 0,
      created: 0,
      statuses: 0,
      comments: 0,
      stop: null,
    });
    expect(sent()).toEqual([]);
    expect(await row(linkId)).toMatchObject({ reportedFixedAt: null, statusCheckedAt: null });
  });

  it('connection gone (Review Focus 5): the job ends without an error and queues nothing', async () => {
    const { lines, logger } = capture();
    await db().delete(jiraConnections).where(eq(jiraConnections.id, connectionId));
    fake.clearRequests();
    expect(await runPassJob({ logger })).toBe(1);
    expect((await syncJobs()).map((j) => [j.status, j.lastError])).toEqual([['succeeded', null]]);
    expect(fake.requests).toHaveLength(0);
    expect(lines.filter(([level]) => level !== 'info')).toEqual([]);
  });
});
