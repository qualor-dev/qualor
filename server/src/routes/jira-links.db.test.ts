import { hex32 } from '@qualor/shared';
import { and, eq, gt, inArray, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createFakeJira, type FakeJira } from '../../test/fake-jira';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule, type IssueSeed } from '../../test/issues';
import { connectJira, jiraTestConfig, mapJira, seedJiraLink } from '../../test/jira';
import { rbacPlugins } from '../../test/rbac';
import { trustTestCa } from '../../test/tls';
import { seedTargetRow } from '../../test/vulnerabilities';
import { uuidv7 } from '../db/ids';
import {
  auditEvents,
  branches,
  issues,
  jiraConnections,
  jiraLinks,
  jobs,
  projectVersions,
  users,
} from '../db/schema';
import { JIRA_QUEUE, jiraCreateKey } from '../jira/jobs';
import { setConnectionProblem } from '../jira/problems';

const NOW = new Date('2027-01-01T00:00:00Z');
const CVE = 'CVE-2026-1111';

interface Link {
  id: string;
  state: string;
  origin: string;
  key: string | null;
  url: string | null;
  status: { name: string; category: string } | null;
  statusCheckedAt: string | null;
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

describe('Jira links: request, retry, unlink, embedded (0.16 Jira §6.3, §6.4, §6.8)', () => {
  let h: IngestHarness;
  let fake: FakeJira;
  let untrust: () => void;
  let viewer: Session;
  let outsider: Session;
  let rater: Session;
  /** A member of its own bucket of issue changes, for the race test. */
  let racer: Session;
  let project: IngestProject;
  let other: IngestProject;
  let projectId: string;
  let adminId: string;
  let connectionId: string;
  let main: string;
  let feature: string;
  let release: string;
  let mr: string;
  let codeRule: string;
  let trivyRule: string;
  let since = 0;
  let pkgs = 0;

  const db = () => h.ctx.db;
  const post = (payload: object, session: Session = h.orgAdmin, id = projectId) =>
    h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/${id}/jira/links`,
      headers: session.headers,
      payload,
    });
  const items = async (payload: object, session?: Session): Promise<Item[]> => {
    const res = await post(payload, session);
    expect(res.statusCode, res.body).toBe(202);
    return (res.json() as { items: Item[] }).items;
  };
  const retry = (id: string, headers: Record<string, string> = h.orgAdmin.headers) =>
    h.ctx.app.inject({ method: 'POST', url: `/api/v0/jira-links/${id}/retry`, headers });
  const dismiss = (id: string, headers: Record<string, string> = h.orgAdmin.headers) =>
    h.ctx.app.inject({ method: 'DELETE', url: `/api/v0/jira-links/${id}`, headers });
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
    (await db().select().from(jiraLinks).where(eq(jiraLinks.id, id)))[0]!;
  const rowsOfIssue = (issueId: string) =>
    db().select().from(jiraLinks).where(eq(jiraLinks.issueId, issueId));
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
  const freshPackage = () => `pkg-links-${++pkgs}`;
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

  beforeAll(async () => {
    untrust = trustTestCa();
    fake = await createFakeJira({ deployment: 'data_center' });
    fake.addProject({ id: '10000', key: 'QUAL', name: 'Qualor findings' });
    h = await createIngestHarness({
      config: jiraTestConfig(fake),
      pluginsFor: rbacPlugins({ now: () => NOW }),
    });
    const make = async (username: string, role?: 'viewer' | 'member') => {
      const user = await createUser(h.ctx, { username });
      if (role) await addMember(h.ctx, h.organizationId, user.id, role);
      return login(h.ctx, user.username, user.password);
    };
    viewer = await make('jl-viewer', 'viewer');
    outsider = await make('jl-outsider');
    rater = await make('jl-rater', 'member');
    racer = await make('jl-racer', 'member');
    project = await h.project('JL');
    other = await h.project('JL-OTHER');
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
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
    untrust();
  });
  beforeEach(async () => {
    connectionId = await connectJira(h, fake);
    await mapJira(h, projectId);
    since = await lastSeq();
  });
  afterEach(async () => {
    await db().delete(jiraConnections);
    await db().delete(jobs).where(eq(jobs.queue, JIRA_QUEUE));
  });

  it('checks the preconditions in order: connected, no credential problem, mapped', async () => {
    const issueId = await code(main);
    await db().delete(jiraConnections);
    const none = await post({ issueIds: [issueId] });
    expect([none.statusCode, none.json().code]).toEqual([409, 'JIRA_NOT_CONNECTED']);

    // A new connection has no mapping yet: the credential problem is answered first.
    connectionId = await connectJira(h, fake);
    await setConnectionProblem(db(), connectionId, 'token_refused');
    const broken = await post({ issueIds: [issueId] });
    expect([broken.statusCode, broken.json().code, broken.json().problemCode]).toEqual([
      409,
      'JIRA_CONNECTION_BROKEN',
      'token_refused',
    ]);

    // A transient problem refuses nothing.
    await setConnectionProblem(db(), connectionId, 'timeout');
    const unmapped = await post({ issueIds: [issueId] });
    expect([unmapped.statusCode, unmapped.json().code]).toEqual([409, 'JIRA_PROJECT_NOT_MAPPED']);
    await mapJira(h, projectId);
    const [item] = await items({ issueIds: [issueId] });
    expect(item?.link?.state).toBe('pending');
    expect(await db().select().from(jiraLinks)).toHaveLength(1);
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
    expect(link).toMatchObject({
      state: 'pending',
      origin: 'manual',
      key: null,
      url: null,
      status: null,
      statusCheckedAt: null,
      failure: null,
      reportedFixedAt: null,
    });
    const stored = await row(link.id);
    expect(stored).toMatchObject({
      kind: 'issue',
      issueId: open,
      projectId,
      connectionId,
      createdBy: adminId,
      generation: 1,
      attemptedAt: null,
    });
    expect(link.createdAt).toBe(stored.createdAt.toISOString());

    // A second request while the create job waits queues nothing more.
    await items({ issueIds: [await code(main)] });
    const queued = await db()
      .select()
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, JIRA_QUEUE),
          eq(jobs.status, 'queued'),
          eq(jobs.concurrencyKey, jiraCreateKey(h.organizationId)),
        ),
      );
    expect(queued).toHaveLength(1);
    expect(queued[0]!.payload).toEqual({ kind: 'create', organizationId: h.organizationId });
  });

  it('answers a Trivy issue under its id with the vulnerability link of its pair (R21)', async () => {
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

    // Two Trivy issues of one pair in one request (main and a tracked branch) make one row.
    const pkg = freshPackage();
    const a = await trivy(main, pkg);
    const b = await trivy(release, pkg);
    const onMr = await trivy(mr, pkg);
    const untracked = await trivy(feature, pkg);
    const both = await items({ issueIds: [a, b, onMr, untracked] });
    expect(both.map((i) => [i.issueId, i.skipped])).toEqual([
      [a, null],
      [b, 'ALREADY_LINKED'],
      [onMr, 'NOT_ELIGIBLE'],
      [untracked, 'NOT_ELIGIBLE'],
    ]);
    expect(both[1]!.link!.id).toBe(both[0]!.link!.id);
    const pairRows = await db().select().from(jiraLinks).where(eq(jiraLinks.packageName, pkg));
    expect(pairRows).toHaveLength(1);
  });

  it('links a pair of the Vulnerabilities tab; refuses an unknown pair and a malformed body', async () => {
    const pkg = freshPackage();
    await seedTargetRow(db(), {
      projectId,
      branchId: main,
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
      {
        packageName: pkg,
        vulnerabilityId: 'CVE-2026-2222',
        skipped: null,
        link: { state: 'pending' },
      },
      { packageName: pkg, vulnerabilityId: 'CVE-2026-0404', skipped: 'NOT_FOUND', link: null },
    ]);
    const pair = { packageName: pkg, vulnerabilityId: 'CVE-2026-2222' };
    const ids = (n: number) => Array.from({ length: n }, () => uuidv7());
    for (const body of [
      { vulnerabilities: Array.from({ length: 101 }, () => pair) },
      { issueIds: ids(1), vulnerabilities: [pair] },
      {},
      { issueIds: ids(501) },
      { issueIds: [] },
    ]) {
      const res = await post(body);
      expect([res.statusCode, res.json().code], JSON.stringify(body).slice(0, 80)).toEqual([
        422,
        'VALIDATION_FAILED',
      ]);
    }
  });

  it('links a pair only where the sync pass sees it: tracked targets or a Trivy issue (T6d)', async () => {
    // The project's version rule is `none`: no version is tracked.
    const [version] = await db()
      .insert(projectVersions)
      .values({
        projectId,
        label: `0.${++pkgs}.0`,
        source: 'tag',
        tag: `v0.${pkgs}.0`,
        analyzedAt: NOW,
      })
      .returning();
    const pkg = freshPackage();
    const pair = { packageName: pkg, vulnerabilityId: 'CVE-2026-3333' };
    await seedTargetRow(db(), { projectId, versionId: version!.id, ...pair });
    // A pair only a merge request's Trivy issue reports is not linkable either.
    const mrOnly = { packageName: freshPackage(), vulnerabilityId: CVE };
    await trivy(mr, mrOnly.packageName);
    const [untracked, onMr] = await items({ vulnerabilities: [pair, mrOnly] });
    expect([untracked?.skipped, untracked?.link, onMr?.skipped]).toEqual([
      'NOT_ELIGIBLE',
      null,
      'NOT_ELIGIBLE',
    ]);
    type VulnItem = { packageName: string; jira: Link | null; jiraLinkable: boolean };
    const onVersion = async () =>
      (
        await get<{ items: VulnItem[] }>(
          `/projects/${projectId}/vulnerabilities?target=version:${version!.id}&pageSize=100`,
        )
      ).items.find((v) => v.packageName === pkg);
    expect(await onVersion()).toMatchObject({ jira: null, jiraLinkable: false });

    // The same pair on a tracked branch too: linkable, wherever it is viewed.
    await seedTargetRow(db(), { projectId, branchId: release, ...pair });
    expect(await onVersion()).toMatchObject({ jira: null, jiraLinkable: true });
    const [linked] = await items({ vulnerabilities: [pair] });
    expect(linked).toMatchObject({ skipped: null, link: { state: 'pending' } });
    expect(await onVersion()).toMatchObject({ jiraLinkable: true, jira: { id: linked!.link!.id } });
  });

  it('re-arms a failed or dismissed row; a created row is already linked', async () => {
    const failedIssue = await code(main);
    const failed = await seedJiraLink(db(), {
      projectId,
      connectionId,
      kind: 'issue',
      issueId: failedIssue,
      state: 'failed',
      origin: 'auto',
      jiraKey: 'QUAL-9',
      jiraIssueId: '10009',
      statusName: 'Done',
      statusCategory: 'done',
      statusCheckedAt: NOW,
      failure: { code: 'field_refused', message: 'Components is required' },
      attemptedAt: NOW,
      missedPasses: 1,
      reportedFixedAt: NOW,
    });
    const dismissedIssue = await code(main);
    const dismissed = await seedJiraLink(db(), {
      projectId,
      connectionId,
      kind: 'issue',
      issueId: dismissedIssue,
      state: 'dismissed',
      jiraKey: 'QUAL-10',
      jiraIssueId: '10010',
    });
    const createdIssue = await code(main);
    const created = await seedJiraLink(db(), {
      projectId,
      connectionId,
      kind: 'issue',
      issueId: createdIssue,
      state: 'created',
      jiraKey: 'QUAL-11',
      jiraIssueId: '10011',
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
      key: null,
      url: null,
      status: null,
      statusCheckedAt: null,
      failure: null,
      reportedFixedAt: null,
    });
    expect(await row(failed)).toMatchObject({
      state: 'pending',
      origin: 'manual',
      generation: 2,
      jiraKey: null,
      jiraIssueId: null,
      statusName: null,
      statusCategory: null,
      statusCheckedAt: null,
      failure: null,
      attemptedAt: null,
      missedPasses: 0,
      reportedFixedAt: null,
      createdBy: adminId,
    });
    expect(await row(dismissed)).toMatchObject({ state: 'pending', generation: 2, jiraKey: null });
    expect(await row(created)).toMatchObject({
      state: 'created',
      generation: 1,
      jiraKey: 'QUAL-11',
    });
    expect(answer[2]!.link).toMatchObject({ state: 'created', key: 'QUAL-11' });
  });

  it('makes one row of two simultaneous requests for one issue (spec §11.4)', async () => {
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
    expect(await rowsOfIssue(issueId)).toHaveLength(1);
  });

  /**
   * Starts the requests while a transaction holds the project row (which a link request locks
   * first), waits until all of them queue behind it, then lets them go at once: their writes
   * overlap every time.
   */
  const inLockstep = async <T>(start: () => Promise<T>[]): Promise<T[]> => {
    let started: Promise<T>[] = [];
    await db().transaction(async (tx) => {
      await tx.execute(sql`SELECT 1 FROM projects WHERE id = ${projectId} FOR UPDATE`);
      started = start();
      for (let i = 0; i < 200; i += 1) {
        const waiting = await db().execute<{ n: number }>(sql`
          SELECT count(*)::int AS n FROM pg_stat_activity
           WHERE datname = current_database() AND wait_event_type = 'Lock'`);
        if ((waiting.rows[0]?.n ?? 0) >= started.length) return;
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
      throw new Error('the requests never queued behind the project row');
    });
    return Promise.all(started);
  };

  it('writes in one order whatever the request order, so overlapping requests never deadlock', async () => {
    // Two requests for the same findings, in opposite orders, released at once. Unordered, each
    // would write its first finding and then wait on the other's (a new row's unique-index entry,
    // or a re-armed row's lock): 40P01. Many new rows widen the window of the one INSERT.
    const fresh = await Promise.all(Array.from({ length: 150 }, () => code(main)));
    const inserted = await inLockstep(() => [
      post({ issueIds: fresh }, racer),
      post({ issueIds: [...fresh].reverse() }, racer),
    ]);
    expect(
      inserted.map((r) => r.statusCode),
      inserted
        .filter((r) => r.statusCode !== 202)
        .map((r) => r.body)
        .join(' '),
    ).toEqual([202, 202]);
    const failed = await Promise.all(
      Array.from({ length: 20 }, async () => {
        const issueId = await code(main);
        await seedJiraLink(db(), {
          projectId,
          connectionId,
          kind: 'issue',
          issueId,
          state: 'failed',
        });
        return issueId;
      }),
    );
    const rearmed = await inLockstep(() => [
      post({ issueIds: failed }, racer),
      post({ issueIds: [...failed].reverse() }, racer),
    ]);
    expect(
      rearmed.map((r) => r.statusCode),
      rearmed
        .filter((r) => r.statusCode !== 202)
        .map((r) => r.body)
        .join(' '),
    ).toEqual([202, 202]);
    for (const [findings, answers] of [
      [fresh, inserted],
      [failed, rearmed],
    ] as const) {
      const rows = await db()
        .select()
        .from(jiraLinks)
        .where(inArray(jiraLinks.issueId, [...findings]));
      expect(rows).toHaveLength(findings.length);
      expect(rows.every((r) => r.state === 'pending')).toBe(true);
      const made = answers
        .flatMap((r) => (r.json() as { items: Item[] }).items)
        .filter((i) => i.skipped === null);
      expect(made).toHaveLength(findings.length);
    }
  });

  it('charges one issue change per new link and refuses a request over the limit whole', async () => {
    const values = Array.from({ length: 501 }, (_, i) => ({
      projectId,
      branchId: main,
      ruleId: codeRule,
      fingerprint: hex32(`rate:${i}`),
      lineHash: hex32(`rate-line:${i}`),
      contextHash: hex32(`rate-context:${i}`),
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
    expect(await rowsOfIssue(ids[500]!)).toHaveLength(0);
  });

  it('retries a failed link; refuses another state (R9) and an invisible one', async () => {
    const issueId = await code(main);
    const failed = await seedJiraLink(db(), {
      projectId,
      connectionId,
      kind: 'issue',
      issueId,
      state: 'failed',
      failure: { code: 'permission_missing', message: 'x' },
      attemptedAt: NOW,
    });
    // Ruling P15: the mapping is not checked; the create job fails the row `not_mapped`.
    const unmapped = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/projects/${projectId}/jira`,
      headers: h.orgAdmin.headers,
    });
    expect(unmapped.statusCode).toBe(204);
    since = await lastSeq();
    const res = await retry(failed);
    expect(res.statusCode, res.body).toBe(202);
    expect(res.json()).toMatchObject({ id: failed, state: 'pending', failure: null });
    expect(await row(failed)).toMatchObject({ state: 'pending', generation: 2, attemptedAt: null });
    expect(await events('jira_link.requested')).toEqual([
      { details: { count: 1, kind: 'issue' }, targetType: 'project', targetId: projectId },
    ]);

    const created = await seedJiraLink(db(), {
      projectId,
      connectionId,
      kind: 'issue',
      issueId: await code(main),
      state: 'created',
      jiraKey: 'QUAL-3',
      jiraIssueId: '10003',
    });
    const refused = await retry(created);
    expect([refused.statusCode, refused.json().code]).toEqual([409, 'JIRA_LINK_NOT_RETRYABLE']);
    // The pending row just re-armed is not retryable either.
    expect((await retry(failed)).json().code).toBe('JIRA_LINK_NOT_RETRYABLE');

    await db().update(jiraLinks).set({ state: 'missing' }).where(eq(jiraLinks.id, created));
    await setConnectionProblem(db(), connectionId, 'captcha');
    const broken = await retry(created);
    expect([broken.statusCode, broken.json().code, broken.json().problemCode]).toEqual([
      409,
      'JIRA_CONNECTION_BROKEN',
      'captcha',
    ]);
    const hidden = await retry(created, outsider.headers);
    expect([hidden.statusCode, hidden.json().code]).toEqual([404, 'NOT_FOUND']);
    expect((await retry(uuidv7())).statusCode).toBe(404);
  });

  it('retries only a finding that may still have a Jira issue (R7, T6d, T12b); else 409, unchanged', async () => {
    const seed = (over: Partial<typeof jiraLinks.$inferInsert>) =>
      seedJiraLink(db(), {
        projectId,
        connectionId,
        state: 'failed',
        failure: { code: 'permission_missing', message: 'x' },
        attemptedAt: NOW,
        ...over,
      });
    const closed = await seed({ kind: 'issue', issueId: await code(main, { status: 'closed' }) });
    const offMain = await seedJiraLink(db(), {
      projectId,
      connectionId,
      kind: 'issue',
      issueId: await code(feature),
      state: 'missing',
      jiraKey: 'QUAL-9',
      jiraIssueId: '10009',
    });
    // A pair only an untracked version holds (the version rule is `none`).
    const [version] = await db()
      .insert(projectVersions)
      .values({
        projectId,
        label: `0.${++pkgs}.0`,
        source: 'tag',
        tag: `v0.${pkgs}.0`,
        analyzedAt: NOW,
      })
      .returning();
    const pair = { packageName: freshPackage(), vulnerabilityId: 'CVE-2026-4444' };
    await seedTargetRow(db(), { projectId, versionId: version!.id, ...pair });
    const untracked = await seed({ kind: 'vulnerability', ...pair });
    since = await lastSeq();
    for (const id of [closed, offMain, untracked]) {
      const before = await row(id);
      const res = await retry(id);
      expect([res.statusCode, res.json().code], res.body).toEqual([409, 'JIRA_LINK_NOT_RETRYABLE']);
      expect(await row(id)).toEqual(before);
    }
    expect(await events('jira_link.requested')).toEqual([]);
    const createJobs = await db()
      .select()
      .from(jobs)
      .where(
        and(eq(jobs.queue, JIRA_QUEUE), eq(jobs.concurrencyKey, jiraCreateKey(h.organizationId))),
      );
    expect(createJobs).toHaveLength(0);

    // The same pair on a tracked branch too: linkable again, so retried.
    await seedTargetRow(db(), { projectId, branchId: release, ...pair });
    const res = await retry(untracked);
    expect(res.statusCode, res.body).toBe(202);
    expect(await row(untracked)).toMatchObject({ state: 'pending', generation: 2 });
  });

  it('unlinks: the row becomes dismissed and keeps its key', async () => {
    const created = await seedJiraLink(db(), {
      projectId,
      connectionId,
      kind: 'issue',
      issueId: await code(main),
      state: 'created',
      jiraKey: 'QUAL-1',
      jiraIssueId: '10001',
    });
    const res = await dismiss(created);
    expect(res.statusCode, res.body).toBe(204);
    expect(await row(created)).toMatchObject({
      state: 'dismissed',
      jiraKey: 'QUAL-1',
      jiraIssueId: '10001',
    });
    expect(await events('jira_link.dismissed')).toEqual([
      { details: { key: 'QUAL-1' }, targetType: 'project', targetId: projectId },
    ]);
    // Again: nothing changes and nothing more is recorded.
    expect((await dismiss(created)).statusCode).toBe(204);
    expect(await events('jira_link.dismissed')).toHaveLength(1);
    expect((await dismiss(created, outsider.headers)).statusCode).toBe(404);
  });

  it('embeds the link in the issue list, the detail and the vulnerability list', async () => {
    type ListItem = { id: string; jira: Link | null; jiraLinkable: boolean };
    // Newest first: main holds the rate test's 501 issues too.
    const list = async (branchId: string, status = 'open') =>
      (
        await get<{ items: ListItem[] }>(
          `/issues?branchId=${branchId}&status=${status}&sort=createdAt&limit=50`,
        )
      ).items;
    const pkg = freshPackage();
    const codeIssue = await code(main);
    const trivyIssue = await trivy(main, pkg);
    const trivyOnMr = await trivy(mr, pkg);
    const onFeature = await code(feature);
    await seedTargetRow(db(), {
      projectId,
      branchId: main,
      packageName: pkg,
      vulnerabilityId: CVE,
    });
    const answer = await items({ issueIds: [codeIssue, trivyIssue] });
    const [codeLink, pairLink] = answer.map((i) => i.link!.id);
    await db()
      .update(jiraLinks)
      .set({
        state: 'created',
        jiraKey: 'QUAL-1',
        jiraIssueId: '10001',
        statusName: 'To Do',
        statusCategory: 'new',
        statusCheckedAt: NOW,
      })
      .where(eq(jiraLinks.id, codeLink!));

    const onMain = await list(main);
    const codeItem = onMain.find((i) => i.id === codeIssue)!;
    expect(codeItem.jiraLinkable).toBe(true);
    expect(codeItem.jira).toMatchObject({
      id: codeLink,
      state: 'created',
      key: 'QUAL-1',
      url: `${fake.url}/browse/QUAL-1`,
      status: { name: 'To Do', category: 'new' },
      statusCheckedAt: NOW.toISOString(),
    });
    expect(onMain.find((i) => i.id === trivyIssue)).toMatchObject({
      jiraLinkable: true,
      jira: { id: pairLink, state: 'pending' },
    });
    // A merge request's Trivy issue embeds nothing; a feature branch's issue is not linkable.
    expect((await list(mr)).find((i) => i.id === trivyOnMr)).toMatchObject({
      jira: null,
      jiraLinkable: false,
    });
    expect((await list(feature)).find((i) => i.id === onFeature)).toMatchObject({
      jira: null,
      jiraLinkable: false,
    });
    expect(await get<ListItem>(`/issues/${codeIssue}`)).toMatchObject({
      jiraLinkable: true,
      jira: { id: codeLink, key: 'QUAL-1' },
    });
    expect(await get<ListItem>(`/issues/${onFeature}`)).toMatchObject({
      jiraLinkable: false,
      jira: null,
    });
    type VulnItem = {
      packageName: string;
      vulnerabilityId: string;
      jira: Link | null;
      jiraLinkable: boolean;
    };
    const vulns = async () =>
      (await get<{ items: VulnItem[] }>(`/projects/${projectId}/vulnerabilities?pageSize=100`))
        .items;
    expect((await vulns()).find((v) => v.packageName === pkg)).toMatchObject({
      vulnerabilityId: CVE,
      jiraLinkable: true,
      jira: { id: pairLink, state: 'pending' },
    });

    // A closed issue still shows its link, and is not linkable.
    await db().update(issues).set({ status: 'closed' }).where(eq(issues.id, codeIssue));
    expect((await list(main, 'closed')).find((i) => i.id === codeIssue)).toMatchObject({
      jiraLinkable: false,
      jira: { id: codeLink },
    });
    await db().update(issues).set({ status: 'open' }).where(eq(issues.id, codeIssue));

    // A dismissed link reads as none everywhere.
    expect((await dismiss(codeLink!)).statusCode).toBe(204);
    expect((await dismiss(pairLink!)).statusCode).toBe(204);
    const after = await list(main);
    expect(after.find((i) => i.id === codeIssue)?.jira).toBeNull();
    expect(after.find((i) => i.id === trivyIssue)?.jira).toBeNull();
    expect((await get<ListItem>(`/issues/${codeIssue}`)).jira).toBeNull();
    expect((await vulns()).find((v) => v.packageName === pkg)?.jira).toBeNull();
  });

  it('records one jira_link.requested per request that made rows, with the form as kind', async () => {
    const a = await code(main);
    const b = await code(main);
    await items({ issueIds: [a, b] });
    expect(await events('jira_link.requested')).toEqual([
      { details: { count: 2, kind: 'issue' }, targetType: 'project', targetId: projectId },
    ]);
    await items({ issueIds: [a, b] });
    expect(await events('jira_link.requested')).toHaveLength(1);
    const pkg = freshPackage();
    await seedTargetRow(db(), {
      projectId,
      branchId: main,
      packageName: pkg,
      vulnerabilityId: CVE,
    });
    await items({ vulnerabilities: [{ packageName: pkg, vulnerabilityId: CVE }] });
    expect((await events('jira_link.requested')).map((e) => e.details)).toEqual([
      { count: 2, kind: 'issue' },
      { count: 1, kind: 'vulnerability' },
    ]);
  });

  it('refuses a viewer and a project token', async () => {
    const issueId = await code(main);
    const link = await seedJiraLink(db(), {
      projectId,
      connectionId,
      kind: 'issue',
      issueId,
      state: 'failed',
    });
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
        url: `/api/v0/projects/${projectId}/jira/links`,
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
