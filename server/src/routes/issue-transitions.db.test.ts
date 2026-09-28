import { randomUUID } from 'node:crypto';
import { eq, sql } from 'drizzle-orm';
import pg from 'pg';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { expectPgError } from '../../test/db';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { mainBranchId, seedIssue, seedRule, type IssueSeed } from '../../test/issues';
import { finding, reportWith } from '../../test/reports';
import type { Db } from '../db/client';
import { branches, issueChanges, issues, organizations, projects, users } from '../db/schema';
import type { IngestionStage } from '../ingest/process';
import { DEFAULT_STAGES } from '../ingest/stages';
import { transitionIssues } from '../issues/transitions';

/** Polls until `n` backends of this file's own database wait on a lock (never a fixed sleep). */
async function waitForLockWaiters(db: Db, n: number, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = await db.execute(sql`
      SELECT count(*)::int AS n FROM pg_stat_activity
       WHERE wait_event_type = 'Lock' AND datname = current_database()`);
    if (Number(result.rows[0]?.n) >= n) return;
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${n} lock waiter(s)`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

function deferred(): { promise: Promise<void>; resolve: () => void } {
  let resolve!: () => void;
  const promise = new Promise<void>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe('issue transitions, severity override and changelog (data-model.md §6, api.md §3)', () => {
  let h: IngestHarness;
  let member: Session;
  let memberId: string;
  let outsider: Session;
  let projectId: string;
  let branchId: string;
  let ruleId: string;
  let semgrepRule: string;
  const call = (
    method: 'GET' | 'POST' | 'PATCH',
    url: string,
    session: Session | Record<string, string> = member,
    payload?: unknown,
  ) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: 'headers' in session ? (session as Session).headers : session,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const transition = (
    id: string,
    body: unknown,
    session: Session | Record<string, string> = member,
  ) => call('POST', `/issues/${id}/transition`, session, body);
  const issue = (overrides: Partial<IssueSeed> = {}) =>
    seedIssue(h.ctx.db, { projectId, branchId, ruleId, ...overrides });
  const statusOf = async (id: string) =>
    (await h.ctx.db.select().from(issues).where(eq(issues.id, id)))[0]!;
  const changesOf = (id: string) =>
    h.ctx.db
      .select()
      .from(issueChanges)
      .where(eq(issueChanges.issueId, id))
      .orderBy(issueChanges.id);

  beforeAll(async () => {
    h = await createIngestHarness();
    const m = await createUser(h.ctx, { username: 'triager' });
    memberId = m.id;
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
    const o = await createUser(h.ctx, { username: 'stranger' });
    outsider = await login(h.ctx, o.username, o.password);
    const project = await h.project('acme/triage');
    projectId = project.id;
    branchId = await mainBranchId(h.ctx.db, projectId);
    ruleId = await seedRule(h.ctx.db, { key: 'eslint:no-console' });
    semgrepRule = await seedRule(h.ctx.db, { key: 'semgrep:eval', quality: 'security' });
  });
  afterAll(async () => {
    await h.close();
  });

  it('bounds the issue changes of one user (ruling G7): 429 with Retry-After, single and bulk alike', async () => {
    const u = await createUser(h.ctx, { username: 'toggler' });
    await addMember(h.ctx, h.organizationId, u.id, 'member');
    const toggler = await login(h.ctx, u.username, u.password);
    // A full bulk transition is the burst; every id named counts, found or not.
    const ids = Array.from({ length: 500 }, () => randomUUID());
    const bulk = await call('POST', '/issues/bulk-transition', toggler, { ids, to: 'resolved' });
    expect(bulk.statusCode, bulk.body).toBe(200);
    const id = await issue();
    const refused = await transition(id, { to: 'resolved' }, toggler);
    expect([refused.statusCode, refused.json().code]).toEqual([429, 'RATE_LIMITED']);
    expect(refused.headers['retry-after']).toBe('1');
    expect((await statusOf(id)).status).toBe('open');
    expect(await changesOf(id)).toHaveLength(0);
    const override = await call('PATCH', `/issues/${id}`, toggler, { severity: 'low' });
    expect([override.statusCode, override.json().code]).toEqual([429, 'RATE_LIMITED']);
    const again = await call('POST', '/issues/bulk-transition', toggler, {
      ids: [id],
      to: 'resolved',
    });
    expect(again.statusCode).toBe(429);
    // Another user has their own bound.
    expect((await transition(id, { to: 'resolved' })).statusCode).toBe(200);
  });

  it('charges a bulk transition once per distinct id (ruling G7)', async () => {
    const u = await createUser(h.ctx, { username: 'repeater' });
    await addMember(h.ctx, h.organizationId, u.id, 'member');
    const repeater = await login(h.ctx, u.username, u.password);
    const ids = Array.from({ length: 500 }, () => randomUUID());
    const bulk = (ids: string[]) =>
      call('POST', '/issues/bulk-transition', repeater, { ids, to: 'resolved' });
    // One id named 500 times costs one change, so 499 others still fit in the burst ...
    expect((await bulk(Array.from({ length: 500 }, () => ids[0]!))).statusCode).toBe(200);
    expect((await bulk(ids.slice(1))).statusCode).toBe(200);
    // ... and then the bound is reached.
    expect((await bulk([randomUUID()])).statusCode).toBe(429);
  });

  it('resolves an open issue: status, resolver, time and a changelog row with the comment', async () => {
    const id = await issue();
    const res = await transition(id, { to: 'resolved', comment: '  fixed in !42 ' });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({
      id,
      status: 'resolved',
      resolvedAt: expect.any(String),
      resolvedBy: { id: memberId, username: 'triager' },
    });
    const [change] = await changesOf(id);
    expect(change).toMatchObject({
      userId: memberId,
      analysisId: null,
      field: 'status',
      oldValue: 'open',
      newValue: 'resolved',
      comment: 'fixed in !42',
    });
  });

  it('requires a non-blank comment for wont_fix and false_positive (422 COMMENT_REQUIRED)', async () => {
    const id = await issue();
    for (const body of [{ to: 'wont_fix' }, { to: 'false_positive', comment: '   ' }]) {
      const res = await transition(id, body);
      expect(res.statusCode).toBe(422);
      expect(res.json()).toMatchObject({
        code: 'COMMENT_REQUIRED',
        errors: [{ path: 'body.comment' }],
      });
    }
    expect((await statusOf(id)).status).toBe('open');
    expect(await changesOf(id)).toEqual([]);
    const ok = await transition(id, { to: 'wont_fix', comment: 'legacy module, accepted' });
    expect(ok.json()).toMatchObject({ status: 'wont_fix' });
  });

  it('refuses transitions §6 does not allow (409 INVALID_TRANSITION) and `closed` as a target (422)', async () => {
    const resolved = await issue({ status: 'resolved' });
    const closed = await issue({ status: 'closed' });
    const open = await issue();
    const cases: [string, unknown][] = [
      [resolved, { to: 'wont_fix', comment: 'x' }],
      [resolved, { to: 'resolved' }],
      [closed, { to: 'open' }],
      [open, { to: 'open' }],
    ];
    for (const [id, body] of cases) {
      const res = await transition(id, body);
      expect(res.statusCode, JSON.stringify(body)).toBe(409);
      expect(res.json().code).toBe('INVALID_TRANSITION');
    }
    const toClosed = await transition(open, { to: 'closed' });
    expect(toClosed.statusCode).toBe(422);
    expect(toClosed.json().errors[0].path).toBe('body.to');
    const long = await transition(open, { to: 'resolved', comment: 'x'.repeat(2_001) });
    expect(long.json().errors[0].path).toBe('body.comment');
    const nul = await transition(open, { to: 'wont_fix', comment: 'legacy\u0000module' });
    expect([nul.statusCode, nul.json().errors[0].path]).toEqual([422, 'body.comment']);
    const bulkNul = await call('POST', '/issues/bulk-transition', member, {
      ids: [open],
      to: 'wont_fix',
      comment: '\u0000',
    });
    expect([bulkNul.statusCode, bulkNul.json().errors[0].path]).toEqual([422, 'body.comment']);
    expect((await statusOf(open)).status).toBe('open');
  });

  it('reopens a false positive and clears resolvedAt and resolvedBy', async () => {
    const id = await issue();
    await transition(id, { to: 'false_positive', comment: 'test data' });
    const res = await transition(id, { to: 'open' });
    expect(res.json()).toMatchObject({ status: 'open', resolvedAt: null, resolvedBy: null });
    expect((await changesOf(id)).map((c) => [c.oldValue, c.newValue])).toEqual([
      ['open', 'false_positive'],
      ['false_positive', 'open'],
    ]);
  });

  it('mirrors a transition onto the duplicates whose status allows it, each with a changelog row', async () => {
    const primary = await issue({ path: 'src/dup.ts', startLine: 7 });
    const openDuplicate = await issue({
      ruleId: semgrepRule,
      path: 'src/dup.ts',
      startLine: 7,
      duplicateOfIssueId: primary,
    });
    const acceptedDuplicate = await issue({
      ruleId: semgrepRule,
      path: 'src/dup.ts',
      startLine: 7,
      status: 'wont_fix',
      duplicateOfIssueId: primary,
    });
    const res = await transition(primary, { to: 'false_positive', comment: 'fixture secret' });
    expect(res.statusCode).toBe(200);
    expect((await statusOf(openDuplicate)).status).toBe('false_positive');
    expect((await statusOf(openDuplicate)).resolvedBy).toBe(memberId);
    expect((await statusOf(acceptedDuplicate)).status).toBe('wont_fix');
    expect(await changesOf(openDuplicate)).toEqual([
      expect.objectContaining({
        userId: memberId,
        oldValue: 'open',
        newValue: 'false_positive',
        comment: 'fixture secret',
      }),
    ]);
    expect(await changesOf(acceptedDuplicate)).toEqual([]);
    // A duplicate's own transition does not travel back to its primary.
    await transition(openDuplicate, { to: 'open' });
    expect((await statusOf(primary)).status).toBe('false_positive');
  });

  it('mirrors a reopen onto a duplicate (clearing its resolver) and skips a closed duplicate', async () => {
    const primary = await issue({ path: 'src/mirror.ts', startLine: 4 });
    const duplicate = await issue({
      ruleId: semgrepRule,
      path: 'src/mirror.ts',
      startLine: 4,
      duplicateOfIssueId: primary,
    });
    const closedDuplicate = await issue({
      ruleId: semgrepRule,
      path: 'src/mirror.ts',
      startLine: 4,
      status: 'closed',
      duplicateOfIssueId: primary,
    });
    expect((await transition(primary, { to: 'resolved' })).statusCode).toBe(200);
    expect(await statusOf(duplicate)).toMatchObject({ status: 'resolved', resolvedBy: memberId });
    expect((await statusOf(duplicate)).resolvedAt).not.toBeNull();
    expect((await transition(primary, { to: 'open' })).statusCode).toBe(200);
    expect(await statusOf(duplicate)).toMatchObject({
      status: 'open',
      resolvedAt: null,
      resolvedBy: null,
    });
    expect((await changesOf(duplicate)).map((c) => [c.oldValue, c.newValue])).toEqual([
      ['open', 'resolved'],
      ['resolved', 'open'],
    ]);
    expect((await statusOf(closedDuplicate)).status).toBe('closed');
    expect(await changesOf(closedDuplicate)).toEqual([]);
  });

  it('bulk-transitions a primary and its duplicate named together: each changes once', async () => {
    const primary = await issue({ path: 'src/both.ts', startLine: 2 });
    const duplicate = await issue({
      ruleId: semgrepRule,
      path: 'src/both.ts',
      startLine: 2,
      duplicateOfIssueId: primary,
    });
    for (const ids of [
      [duplicate, primary],
      [primary, duplicate],
    ]) {
      const to = (await statusOf(primary)).status === 'open' ? 'resolved' : 'open';
      const res = await call('POST', '/issues/bulk-transition', member, { ids, to });
      expect(res.json()).toEqual({ succeeded: ids, failed: [] });
      expect((await statusOf(primary)).status).toBe(to);
      expect((await statusOf(duplicate)).status).toBe(to);
    }
    for (const id of [primary, duplicate]) {
      expect((await changesOf(id)).map((c) => [c.oldValue, c.newValue])).toEqual([
        ['open', 'resolved'],
        ['resolved', 'open'],
      ]);
    }
  });

  it('bulk-transitions: each id succeeds or fails on its own, in one request', async () => {
    const a = await issue();
    const b = await issue();
    const resolved = await issue({ status: 'resolved' });
    // An issue of another organisation, which the member does not belong to.
    const [org] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'other-org', name: 'Other' })
      .returning();
    const [other] = await h.ctx.db
      .insert(projects)
      .values({ organizationId: org!.id, key: 'other/project', name: 'Other' })
      .returning();
    const [otherBranch] = await h.ctx.db
      .insert(branches)
      .values({ projectId: other!.id, kind: 'branch', name: 'main', isMain: true })
      .returning();
    const invisible = await seedIssue(h.ctx.db, {
      projectId: other!.id,
      branchId: otherBranch!.id,
      ruleId,
    });
    const unknown = '019a0000-0000-7000-8000-000000000000';
    const res = await call('POST', '/issues/bulk-transition', outsider, {
      ids: [a],
      to: 'resolved',
    });
    expect(res.json()).toEqual({ succeeded: [], failed: [{ id: a, code: 'NOT_FOUND' }] });
    const bulk = await call('POST', '/issues/bulk-transition', member, {
      ids: [a, b, a, resolved, unknown, invisible],
      to: 'resolved',
    });
    expect(bulk.statusCode).toBe(200);
    expect(bulk.json()).toEqual({
      succeeded: [a, b],
      failed: [
        { id: resolved, code: 'INVALID_TRANSITION' },
        { id: unknown, code: 'NOT_FOUND' },
        { id: invisible, code: 'NOT_FOUND' },
      ],
    });
    expect((await statusOf(invisible)).status).toBe('open');
    expect((await statusOf(a)).status).toBe('resolved');
    expect(await changesOf(a)).toHaveLength(1);
    const tooMany = await call('POST', '/issues/bulk-transition', member, {
      ids: Array.from({ length: 501 }, () => a),
      to: 'open',
    });
    expect(tooMany.statusCode).toBe(422);
    const noComment = await call('POST', '/issues/bulk-transition', member, {
      ids: [b],
      to: 'wont_fix',
    });
    expect(noComment.json().code).toBe('COMMENT_REQUIRED');
  });

  it('checks access: 401 anonymous, 404 outsider, 403 for a read token or a project token', async () => {
    const id = await issue();
    expect((await transition(id, { to: 'resolved' }, {})).statusCode).toBe(401);
    expect((await transition(id, { to: 'resolved' }, outsider)).statusCode).toBe(404);
    const token = async (scopes: string[]) => {
      const res = await call('POST', '/tokens', member, { name: scopes.join('+'), scopes });
      return (res.json() as { token: string }).token;
    };
    const read = await transition(id, { to: 'resolved' }, bearer(await token(['read'])));
    expect([read.statusCode, read.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    const write = await transition(id, { to: 'resolved' }, bearer(await token(['write'])));
    expect(write.statusCode).toBe(200);
    const project = await h.project('acme/triage-token');
    const prj = await transition(id, { to: 'open' }, bearer(project.token));
    expect([prj.statusCode, prj.json().code]).toEqual([403, 'TOKEN_NOT_ALLOWED']);
    expect((await call('PATCH', `/issues/${id}`, outsider, { severity: 'low' })).statusCode).toBe(
      404,
    );
    expect((await call('GET', `/issues/${id}/changelog`, outsider)).statusCode).toBe(404);
  });

  it('serialises concurrent transitions of one issue: the second is judged on the first result', async () => {
    const id = await issue();
    const [x, y] = await Promise.all([
      transition(id, { to: 'resolved' }),
      transition(id, { to: 'wont_fix', comment: 'accepted' }),
    ]);
    expect([x.statusCode, y.statusCode].sort()).toEqual([200, 409]);
    expect(await changesOf(id)).toHaveLength(1);
  });

  it('gives up after the lock timeout while an ingestion holds the issue (55P03, 503 over HTTP)', async () => {
    const id = await issue();
    const holder = new pg.Client({ connectionString: h.ctx.database.url });
    await holder.connect();
    try {
      await holder.query('BEGIN');
      await holder.query('SELECT 1 FROM issues WHERE id = $1 FOR UPDATE', [id]);
      const [user] = await h.ctx.db.select().from(users).where(eq(users.id, memberId));
      await expectPgError(
        transitionIssues(
          { db: h.ctx.db },
          { kind: 'session', user: user!, sessionSecret: 'unused' },
          [id],
          'resolved',
          null,
          { lockTimeoutMs: 100 },
        ),
        '55P03',
      );
      // Over HTTP: the route's own 5 s lock_timeout expires and the client is told to retry.
      const res = await transition(id, { to: 'resolved' });
      expect([res.statusCode, res.json().code]).toEqual([503, 'CONCURRENCY_CONFLICT']);
      expect(res.headers['retry-after']).toBe('1');
    } finally {
      await holder.query('ROLLBACK');
      await holder.end();
    }
    expect((await statusOf(id)).status).toBe('open');
  });

  it('a transition racing an ingestion that closes the issue waits for it and is judged against `closed` (409)', async () => {
    const project = await h.project('acme/race-close');
    const report = reportWith({ projectKey: project.key, findings: [finding({ line: 3 })] });
    await project.ingestOk(report);
    const [row] = await h.ctx.db
      .select()
      .from(issues)
      .where(eq(issues.branchId, await mainBranchId(h.ctx.db, project.id)));
    // A stage after tracking that holds the ingestion transaction open: the issue is closed (not
    // yet committed) and its row lock is held until the transition is seen blocked on it.
    const closedAndHolding = deferred();
    const release = deferred();
    const hold: IngestionStage = {
      name: 'hold',
      async run() {
        closedAndHolding.resolve();
        await release.promise;
      },
    };
    const ingestion = project.ingestOk(
      { ...report, findings: [], analysisDate: '2026-09-23T10:15:00Z' },
      [...DEFAULT_STAGES, hold],
    );
    await closedAndHolding.promise;
    const racing = transition(row!.id, { to: 'resolved' });
    await waitForLockWaiters(h.ctx.db, 1);
    release.resolve();
    const [, res] = await Promise.all([ingestion, racing]);
    expect([res.statusCode, res.json().code]).toEqual([409, 'INVALID_TRANSITION']);
    expect(await statusOf(row!.id)).toMatchObject({ status: 'closed', resolvedBy: null });
    expect((await changesOf(row!.id)).map((c) => [c.userId, c.oldValue, c.newValue])).toEqual([
      [null, 'open', 'closed'],
    ]);
  });

  it('an ingestion planned before a racing transition committed does not overwrite it', async () => {
    const project = await h.project('acme/race-user-first');
    const report = reportWith({ projectKey: project.key, findings: [finding({ line: 3 })] });
    await project.ingestOk(report);
    const [row] = await h.ctx.db
      .select()
      .from(issues)
      .where(eq(issues.branchId, await mainBranchId(h.ctx.db, project.id)));
    const holder = new pg.Client({ connectionString: h.ctx.database.url });
    await holder.connect();
    let racing: ReturnType<typeof transition> | undefined;
    let ingestion: Promise<string> | undefined;
    try {
      // The holder keeps the row locked while, in this order, the transition queues on it and
      // the ingestion — whose plan (read without locks) still says `open` → `closed` — queues
      // behind the transition.
      await holder.query('BEGIN');
      await holder.query('SELECT 1 FROM issues WHERE id = $1 FOR UPDATE', [row!.id]);
      racing = transition(row!.id, { to: 'resolved', comment: 'fixed' });
      await waitForLockWaiters(h.ctx.db, 1);
      ingestion = project.ingestOk({
        ...report,
        findings: [],
        analysisDate: '2026-09-23T10:15:00Z',
      });
      await waitForLockWaiters(h.ctx.db, 2);
    } finally {
      await holder.query('ROLLBACK');
      await holder.end();
    }
    const [res] = await Promise.all([racing, ingestion]);
    expect(res!.statusCode, res!.body).toBe(200);
    // The ingestion's lost-update guard saw `resolved`, not the `open` it planned from.
    expect(await statusOf(row!.id)).toMatchObject({ status: 'resolved', resolvedBy: memberId });
    expect((await changesOf(row!.id)).map((c) => [c.userId, c.oldValue, c.newValue])).toEqual([
      [memberId, 'open', 'resolved'],
    ]);
  });

  it('an ingestion no longer deadlocks with a transition holding a row it closes while waiting on one it matches', async () => {
    const project = await h.project('acme/race-cycle');
    const report = (lines: number[], minute: number) =>
      reportWith({
        projectKey: project.key,
        analysisDate: `2026-09-23T10:${String(minute).padStart(2, '0')}:00Z`,
        findings: lines.map((line) => finding({ line })),
      });
    await project.ingestOk(report([3], 0));
    await project.ingestOk(report([3, 5], 1));
    const branch = await mainBranchId(h.ctx.db, project.id);
    const rows = await h.ctx.db.select().from(issues).where(eq(issues.branchId, branch));
    // c is closed by the next analysis, u is matched by it; UUIDv7 ids: c (older) < u.
    const c = rows.find((r) => r.startLine === 3)!.id;
    const u = rows.find((r) => r.startLine === 5)!.id;
    expect(c < u).toBe(true);
    // A test-only pause inside writePlan: inserting issues first takes a shared advisory lock,
    // which the holder keeps exclusively. Before fix round 1 the ingestion held only the matched
    // row u at that point (the close set was locked later), so a transition of [c, u] took c and
    // waited on u, the ingestion then waited on c — a cycle Postgres broke with 40P01.
    await h.ctx.db.execute(sql`
      CREATE FUNCTION test_pause_issue_insert() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN PERFORM pg_advisory_xact_lock_shared(4242); RETURN NULL; END $$`);
    await h.ctx.db.execute(sql`
      CREATE TRIGGER test_pause_issue_insert BEFORE INSERT ON issues
        FOR EACH STATEMENT EXECUTE FUNCTION test_pause_issue_insert()`);
    const holder = new pg.Client({ connectionString: h.ctx.database.url });
    await holder.connect();
    let ingestion: Promise<string> | undefined;
    let bulk: ReturnType<typeof call> | undefined;
    try {
      await holder.query('BEGIN');
      await holder.query('SELECT pg_advisory_xact_lock(4242)');
      // Matches u, inserts line 9 (the pause), closes c.
      ingestion = project.ingestOk(report([5, 9], 2));
      await waitForLockWaiters(h.ctx.db, 1);
      bulk = call('POST', '/issues/bulk-transition', member, { ids: [c, u], to: 'resolved' });
      await waitForLockWaiters(h.ctx.db, 2);
    } finally {
      await holder.query('ROLLBACK');
      await holder.end();
    }
    try {
      const [, res] = await Promise.all([ingestion, bulk]);
      // The ingestion held c and u from its first write on, so the transition simply waited for
      // it to commit and was then judged against its result.
      expect(res!.statusCode, res!.body).toBe(200);
      expect(res!.json()).toEqual({
        succeeded: [u],
        failed: [{ id: c, code: 'INVALID_TRANSITION' }],
      });
    } finally {
      await h.ctx.db.execute(sql`DROP TRIGGER test_pause_issue_insert ON issues`);
      await h.ctx.db.execute(sql`DROP FUNCTION test_pause_issue_insert()`);
    }
    expect((await statusOf(c)).status).toBe('closed');
    expect(await statusOf(u)).toMatchObject({ status: 'resolved', resolvedBy: memberId });
    expect((await changesOf(c)).map((x) => [x.userId, x.oldValue, x.newValue])).toEqual([
      [null, 'open', 'closed'],
    ]);
    expect((await changesOf(u)).map((x) => [x.userId, x.oldValue, x.newValue])).toEqual([
      [memberId, 'open', 'resolved'],
    ]);
    // One attempt: the ingestion's job was never aborted and retried.
    const jobs = await h.ctx.db.execute<{ attempts: number }>(sql`
      SELECT attempts FROM jobs WHERE payload->>'analysisId' = ${await ingestion}`);
    expect(jobs.rows.map((j) => Number(j.attempts))).toEqual([1]);
  });

  it('keeps a user status and severity override through the next analysis', async () => {
    const project = await h.project('acme/triage-ingest');
    const report = reportWith({ projectKey: project.key, findings: [finding({ line: 3 })] });
    await project.ingestOk(report);
    const branch = await mainBranchId(h.ctx.db, project.id);
    const [row] = await h.ctx.db.select().from(issues).where(eq(issues.branchId, branch));
    await transition(row!.id, { to: 'wont_fix', comment: 'accepted' });
    await call('PATCH', `/issues/${row!.id}`, member, { severity: 'blocker' });
    await project.ingestOk({ ...report, analysisDate: '2026-09-23T10:15:00Z' });
    expect(await statusOf(row!.id)).toMatchObject({
      status: 'wont_fix',
      severity: 'blocker',
      severityOverridden: true,
    });
  });

  describe('severity override and changelog', () => {
    let id: string;
    beforeEach(async () => {
      id = await issue({ severity: 'medium' });
    });

    it('overrides the severity once, logs it, and ignores a repeat', async () => {
      const res = await call('PATCH', `/issues/${id}`, member, { severity: 'high' });
      expect(res.statusCode).toBe(200);
      expect(res.json()).toMatchObject({ severity: 'high', severityOverridden: true });
      await call('PATCH', `/issues/${id}`, member, { severity: 'high' });
      expect((await changesOf(id)).map((c) => [c.field, c.oldValue, c.newValue])).toEqual([
        ['severity', 'medium', 'high'],
      ]);
      const bad = await call('PATCH', `/issues/${id}`, member, { severity: 'urgent' });
      expect(bad.json().errors[0].path).toBe('body.severity');
    });

    it('lists the changelog oldest first, with the user, in keyset pages', async () => {
      await call('PATCH', `/issues/${id}`, member, { severity: 'low' });
      await transition(id, { to: 'resolved', comment: 'done' });
      await transition(id, { to: 'open' });
      await h.ctx.db.insert(issueChanges).values({
        issueId: id,
        field: 'status',
        oldValue: 'open',
        newValue: 'closed',
        createdAt: sql`now()`,
      });
      const first = await call('GET', `/issues/${id}/changelog?limit=2`);
      expect(first.statusCode).toBe(200);
      const page1 = first.json() as {
        items: { field: string; user: unknown }[];
        nextCursor: string;
      };
      expect(page1.items.map((c) => c.field)).toEqual(['severity', 'status']);
      expect(page1.items[0]!.user).toEqual({ id: memberId, username: 'triager' });
      const second = await call(
        'GET',
        `/issues/${id}/changelog?limit=2&cursor=${encodeURIComponent(page1.nextCursor)}`,
      );
      const page2 = second.json() as {
        items: { newValue: string; user: unknown; comment: string | null }[];
        nextCursor: string | null;
      };
      expect(page2.items.map((c) => c.newValue)).toEqual(['open', 'closed']);
      expect(page2.items[1]!.user).toBeNull();
      expect(page2.nextCursor).toBeNull();
    });
  });
});
