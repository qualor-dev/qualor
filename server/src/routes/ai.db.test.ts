import { and, eq, inArray, ne, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createFakeLlm, type FakeLlm } from '../../test/fake-llm';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { configureLlm } from '../../test/llm';
import { engine, file, finding, reportWith } from '../../test/reports';
import { LOCKS } from '../db/locks';
import { issues, llmRequests, organizations, projects, rules } from '../db/schema';
import { DEFAULT_LLM_SETTINGS, type StoredLlmSettings } from '../llm/settings';
import { parseInternalHosts } from '../scm/url';

const LINES = ['const a = 1;', 'if (a == 1) {}', 'export {};'];
const ALL_ON = {
  enabled: true,
  features: { explain: true, triage: true, fix: true },
  excludedProjectIds: [] as string[],
};

describe('AI requests (llm.md §5, §10, §12, §16)', () => {
  let fake: FakeLlm;
  let h: IngestHarness;
  let p: IngestProject;
  let outsider: Session;
  let orgB: string;
  let eqIssue: string;
  let eqIssueB: string;
  /** eqIssue's twin: the same finding on another branch of the same project. */
  let twinIssue: string;
  let secretIssue: string;
  let envIssue: string;
  const ask = (
    issueId: string,
    feature: string,
    payload: object = {},
    session: Session = h.orgAdmin,
  ) =>
    h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${issueId}/ai/${feature}`,
      headers: session.headers,
      payload,
    });
  const get = (url: string, headers: Record<string, string> = h.orgAdmin.headers) =>
    h.ctx.app.inject({ method: 'GET', url, headers });
  const configure = (over: Partial<StoredLlmSettings> = {}) =>
    configureLlm(h.ctx.db, h.ctx.config.secretKey, fake, h.organizationId, over);
  const report = (projectKey: string, branch?: string) => {
    const snippet = { startLine: 1, lines: LINES };
    return reportWith({
      projectKey,
      ...(branch === undefined ? {} : { branch }),
      engines: [engine('eslint'), engine('gitleaks')],
      files: [file('src/a.ts', { lines: 3 }), file('.env', { lines: 1 })],
      findings: [
        finding({ ruleId: 'eqeqeq', line: 2, snippet }),
        finding({
          engineId: 'gitleaks',
          ruleId: 'generic-api-key',
          path: 'src/a.ts',
          line: 1,
          snippet,
        }),
        finding({ ruleId: 'no-undef', path: '.env', line: 1 }),
      ],
    });
  };
  /** Holds the organisation's quota lock (llm.md §12.1) in another transaction until released. */
  const holdOrganizationLock = async () => {
    const gate: { open?: () => void } = {};
    const held = new Promise<void>((resolve) => {
      gate.open = resolve;
    });
    let signal: (() => void) | undefined;
    const locked = new Promise<void>((resolve) => {
      signal = resolve;
    });
    const holder = h.ctx.db.transaction(async (tx) => {
      await tx.execute(
        sql`SELECT pg_advisory_xact_lock(${LOCKS.llmQuota}, hashtext(${h.organizationId}))`,
      );
      signal?.();
      await held;
    });
    await locked;
    return { release: () => gate.open?.(), holder };
  };
  const tokenOf = async (session: Session, scopes: string[]): Promise<Record<string, string>> => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/tokens',
      headers: session.headers,
      payload: { name: `t-${scopes.join('-')}-${Math.random()}`, scopes },
    });
    expect(res.statusCode, res.body).toBe(201);
    return bearer((res.json() as { token: string }).token);
  };

  beforeAll(async () => {
    fake = await createFakeLlm();
    h = await createIngestHarness({ config: { llmInternalHosts: parseInternalHosts(fake.host) } });
    p = await h.project('acme/ai');
    await p.ingestOk(report('acme/ai'));
    const rows = await h.ctx.db
      .select({ id: issues.id, key: rules.key, path: issues.path })
      .from(issues)
      .innerJoin(rules, eq(rules.id, issues.ruleId));
    eqIssue = rows.find((r) => r.key === 'eslint:eqeqeq')!.id;
    secretIssue = rows.find((r) => r.key.startsWith('gitleaks:'))!.id;
    envIssue = rows.find((r) => r.path === '.env')!.id;
    await p.ingestOk(report('acme/ai', 'release/1'));
    const [twin] = await h.ctx.db
      .select({ id: issues.id })
      .from(issues)
      .innerJoin(rules, eq(rules.id, issues.ruleId))
      .where(
        and(eq(issues.projectId, p.id), eq(rules.key, 'eslint:eqeqeq'), ne(issues.id, eqIssue)),
      );
    twinIssue = twin!.id;

    // A second organisation with the same code: its outsider admin sees none of the first's.
    const [b] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'beta', name: 'Beta' })
      .returning();
    orgB = b!.id;
    const other = await createUser(h.ctx, { username: 'ai-outsider' });
    await addMember(h.ctx, orgB, other.id, 'admin');
    outsider = await login(h.ctx, other.username, other.password);
    const pb = await h.project('beta/ai', { organizationId: orgB, session: outsider });
    await pb.ingestOk(report('beta/ai'));
    const rowsB = await h.ctx.db
      .select({ id: issues.id, key: rules.key })
      .from(issues)
      .innerJoin(rules, eq(rules.id, issues.ruleId))
      .where(eq(issues.projectId, pb.id));
    eqIssueB = rowsB.find((r) => r.key === 'eslint:eqeqeq')!.id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(async () => {
    await h.ctx.db.delete(llmRequests);
    fake.requests.length = 0;
  });
  afterEach(async () => {
    // Every row a test left: its organisation is its project's (the service derives it from there).
    const { rows } = await h.ctx.db.execute<{ n: number }>(sql`
      SELECT count(*)::int AS n FROM llm_requests r JOIN projects p ON p.id = r.project_id
       WHERE r.organization_id <> p.organization_id`);
    expect(rows[0]!.n).toBe(0);
  });

  it('is 409 AI_DISABLED without a provider, for a disabled organisation and for a disabled feature', async () => {
    await configure({ provider: null });
    expect((await ask(eqIssue, 'explain')).json().code).toBe('AI_DISABLED');
    await configure({ organizations: {} });
    expect((await ask(eqIssue, 'explain')).json().code).toBe('AI_DISABLED');
    await configure({
      organizations: {
        [h.organizationId]: { ...ALL_ON, features: { explain: false, triage: true, fix: true } },
      },
    });
    expect((await ask(eqIssue, 'explain')).statusCode).toBe(409);
    expect(await h.ctx.db.select().from(llmRequests)).toHaveLength(0);
    expect(fake.requests).toHaveLength(0);
  });

  it('queues a request with metadata only, and answers the in-flight one again', async () => {
    await configure();
    const res = await ask(eqIssue, 'explain');
    expect(res.statusCode, res.body).toBe(202);
    const body = res.json();
    expect(body).toMatchObject({
      feature: 'explain',
      status: 'queued',
      model: 'fake-model',
      promptVersion: 'explain.v1',
      result: null,
      error: null,
      post: null,
    });
    const [row] = await h.ctx.db.select().from(llmRequests);
    expect(row).toMatchObject({
      fields: ['rule', 'message', 'path', 'language', 'snippet'],
      prompt: null,
      redactions: 0,
      providerHost: fake.host,
    });
    expect(row!.inputSha256).toMatch(/^[0-9a-f]{64}$/);
    const again = await ask(eqIssue, 'explain');
    expect([again.statusCode, again.json().id]).toEqual([202, body.id]);
    const polled = await get(`/api/v0/ai-requests/${body.id}`);
    expect(polled.statusCode).toBe(200);
    expect(polled.headers['retry-after']).toBe('2');
    // Nothing was sent: the job of Task 11 does that.
    expect(fake.requests).toHaveLength(0);
  });

  it('takes the organisation from the project row, never from the request', async () => {
    await configure({
      organizations: { [h.organizationId]: ALL_ON, [orgB]: ALL_ON },
    });
    const smuggled = await ask(eqIssue, 'explain', { organizationId: orgB });
    expect(smuggled.statusCode).toBe(422);
    const res = await ask(eqIssue, 'explain');
    expect(res.statusCode).toBe(202);
    const [row] = await h.ctx.db.select().from(llmRequests);
    const [project] = await h.ctx.db.select().from(projects).where(eq(projects.id, p.id));
    expect(row).toMatchObject({
      organizationId: project!.organizationId,
      projectId: p.id,
      issueId: eqIssue,
    });
    expect(row!.organizationId).toBe(h.organizationId);
  });

  it('never answers from another organisation’s cache', async () => {
    await configure({
      organizations: { [h.organizationId]: ALL_ON, [orgB]: ALL_ON },
    });
    const a = (await ask(eqIssue, 'explain')).json();
    await h.ctx.db
      .update(llmRequests)
      .set({
        status: 'succeeded',
        result: { kind: 'explain', summary: 's', explanation: 'e', howToFix: '' },
      })
      .where(eq(llmRequests.id, a.id));
    const b = await ask(eqIssueB, 'explain', {}, outsider);
    expect(b.statusCode, b.body).toBe(202);
    expect(b.json().id).not.toBe(a.id);
    const rows = await h.ctx.db.select().from(llmRequests);
    const rowA = rows.find((r) => r.id === a.id)!;
    const rowB = rows.find((r) => r.id === b.json().id)!;
    // Same code, same rule, same fingerprint and hash: only the organisation differs.
    expect(rowB.inputSha256).toBe(rowA.inputSha256);
    expect(rowB.organizationId).toBe(orgB);
    expect(rowB.cacheKey).not.toBe(rowA.cacheKey);
  });

  it('never serves another organisation’s answer, even one filed under the same issue and key', async () => {
    await configure({
      organizations: { [h.organizationId]: ALL_ON, [orgB]: ALL_ON },
    });
    const a = (await ask(eqIssue, 'explain')).json();
    const [rowA] = await h.ctx.db.select().from(llmRequests).where(eq(llmRequests.id, a.id));
    await h.ctx.db.delete(llmRequests);
    // A forged row: another organisation's, for this very issue and cache key.
    const [forged] = await h.ctx.db
      .insert(llmRequests)
      .values({
        ...rowA!,
        id: undefined,
        organizationId: orgB,
        status: 'succeeded',
        result: { kind: 'explain', summary: 'other org', explanation: 'e', howToFix: '' },
      })
      .returning();
    const res = await ask(eqIssue, 'explain');
    expect(res.statusCode, res.body).toBe(202);
    expect(res.json().id).not.toBe(forged!.id);
    expect(res.body).not.toContain('other org');
    // Nor as the request in flight.
    await h.ctx.db
      .update(llmRequests)
      .set({ status: 'queued', result: null })
      .where(eq(llmRequests.id, forged!.id));
    await h.ctx.db.delete(llmRequests).where(ne(llmRequests.id, forged!.id));
    expect((await ask(eqIssue, 'explain')).json().id).not.toBe(forged!.id);
    await h.ctx.db.delete(llmRequests);
  });

  it('looks at the cache again under the lock: an answer that arrived meanwhile is served', async () => {
    await configure();
    const first = (await ask(eqIssue, 'explain')).json();
    const { release, holder } = await holdOrganizationLock();
    // Past the first look (the request is in flight), then waiting for the lock.
    const waiting = ask(eqIssue, 'explain');
    await new Promise((r) => setTimeout(r, 200));
    await h.ctx.db
      .update(llmRequests)
      .set({
        status: 'succeeded',
        result: { kind: 'explain', summary: 's', explanation: 'e', howToFix: '' },
      })
      .where(eq(llmRequests.id, first.id));
    release();
    await holder;
    const res = await waiting;
    expect([res.statusCode, res.json().id]).toEqual([200, first.id]);
    expect(await h.ctx.db.select().from(llmRequests)).toHaveLength(1);
  });

  it('refuses a user over their bound without waiting for the organisation’s lock', async () => {
    await configure({ budgets: { ...DEFAULT_LLM_SETTINGS.budgets, perUserPerHour: 1 } });
    const u = await createUser(h.ctx, { username: 'ai-no-wait' });
    await addMember(h.ctx, h.organizationId, u.id, 'member');
    const s = await login(h.ctx, u.username, u.password);
    expect((await ask(eqIssue, 'explain', {}, s)).statusCode).toBe(202);
    const { release, holder } = await holdOrganizationLock();
    try {
      // Waiting for the lock would never end while it is held here: at most 5 s.
      const res = await Promise.race([
        ask(eqIssue, 'triage', {}, s),
        new Promise<'waited'>((r) => setTimeout(() => r('waited'), 5_000)),
      ]);
      expect(res).not.toBe('waited');
      if (res !== 'waited') {
        expect([res.statusCode, res.json().code]).toEqual([429, 'RATE_LIMITED']);
      }
    } finally {
      release();
      await holder;
    }
  });

  it('gives the user their token back when the request could not be stored', async () => {
    await configure({ budgets: { ...DEFAULT_LLM_SETTINGS.budgets, perUserPerHour: 1 } });
    const u = await createUser(h.ctx, { username: 'ai-refund' });
    await addMember(h.ctx, h.organizationId, u.id, 'member');
    const s = await login(h.ctx, u.username, u.password);
    await h.ctx.db.execute(sql`
      CREATE FUNCTION test_refuse_llm_insert() RETURNS trigger LANGUAGE plpgsql AS
        $$ BEGIN RAISE EXCEPTION 'refused by the test'; END $$`);
    await h.ctx.db.execute(sql`
      CREATE TRIGGER test_refuse_llm_insert BEFORE INSERT ON llm_requests
        FOR EACH ROW EXECUTE FUNCTION test_refuse_llm_insert()`);
    try {
      expect((await ask(eqIssue, 'explain', {}, s)).statusCode).toBe(500);
    } finally {
      await h.ctx.db.execute(sql`DROP TRIGGER test_refuse_llm_insert ON llm_requests`);
      await h.ctx.db.execute(sql`DROP FUNCTION test_refuse_llm_insert()`);
    }
    // The one token of the hour is still there.
    expect((await ask(eqIssue, 'explain', {}, s)).statusCode).toBe(202);
    expect((await ask(eqIssue, 'triage', {}, s)).json().code).toBe('RATE_LIMITED');
  });

  it('answers from the cache without a new row, and refresh asks again', async () => {
    await configure();
    const first = (await ask(eqIssue, 'explain')).json();
    await h.ctx.db
      .update(llmRequests)
      .set({
        status: 'succeeded',
        result: { kind: 'explain', summary: 's', explanation: 'e', howToFix: '' },
      })
      .where(eq(llmRequests.id, first.id));
    const cached = await ask(eqIssue, 'explain');
    expect([cached.statusCode, cached.json().id]).toEqual([200, first.id]);
    expect(cached.json().result).toMatchObject({ kind: 'explain', summary: 's' });
    expect(await h.ctx.db.select().from(llmRequests)).toHaveLength(1);
    const fresh = await ask(eqIssue, 'explain', { refresh: true });
    expect(fresh.statusCode).toBe(202);
    expect(fresh.json().id).not.toBe(first.id);
  });

  it('keeps an issue and its twin on another branch apart: in flight and cached (C1)', async () => {
    await configure();
    const [a, b] = await Promise.all([ask(eqIssue, 'triage'), ask(twinIssue, 'triage')]);
    expect([a.statusCode, b.statusCode]).toEqual([202, 202]);
    expect(a.json().issueId).toBe(eqIssue);
    expect(b.json().issueId).toBe(twinIssue);
    expect(b.json().id).not.toBe(a.json().id);
    // In flight: each issue's request is answered again to that issue only.
    expect((await ask(twinIssue, 'triage')).json().id).toBe(b.json().id);
    expect((await ask(eqIssue, 'triage')).json().id).toBe(a.json().id);
    await h.ctx.db
      .update(llmRequests)
      .set({
        status: 'succeeded',
        result: { kind: 'triage', verdict: 'uncertain', confidence: 'low', reasons: ['r'] },
      })
      .where(inArray(llmRequests.id, [a.json().id, b.json().id]));
    // Cached: likewise.
    const cachedTwin = await ask(twinIssue, 'triage');
    expect([cachedTwin.statusCode, cachedTwin.json().id]).toEqual([200, b.json().id]);
    const cachedIssue = await ask(eqIssue, 'triage');
    expect([cachedIssue.statusCode, cachedIssue.json().id]).toEqual([200, a.json().id]);
    // Same organisation, rule, fingerprint and data: only the issue tells them apart.
    const rows = await h.ctx.db.select().from(llmRequests);
    expect(rows).toHaveLength(2);
    expect(rows[0]!.cacheKey).toBe(rows[1]!.cacheKey);
  });

  it('stores the redacted data object only with storePrompts', async () => {
    await configure({ storePrompts: true });
    await ask(eqIssue, 'triage');
    const [row] = await h.ctx.db.select().from(llmRequests);
    expect((row!.prompt as { task: string }).task).toBe('triage');
  });

  it.each([
    ['secret_rule', () => secretIssue, {}],
    ['credentials_file', () => envIssue, {}],
    ['excluded_path', () => eqIssue, { excludePaths: ['src/**'] }],
  ])('refuses %s with 409 AI_NOT_ELIGIBLE', async (reason, id, over) => {
    await configure(over);
    const res = await ask(id(), 'explain');
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({ code: 'AI_NOT_ELIGIBLE', detail: reason });
    expect(await h.ctx.db.select().from(llmRequests)).toHaveLength(0);
  });

  it('re-checks eligibility from the database, not from what a client last saw', async () => {
    await configure();
    const [rule] = await h.ctx.db
      .select({ id: issues.ruleId, tags: rules.tags })
      .from(issues)
      .innerJoin(rules, eq(rules.id, issues.ruleId))
      .where(eq(issues.id, eqIssue));
    await h.ctx.db
      .update(rules)
      .set({ tags: [...rule!.tags, 'Secrets'] })
      .where(eq(rules.id, rule!.id));
    try {
      expect((await ask(eqIssue, 'explain')).json().detail).toBe('secret_rule');
    } finally {
      await h.ctx.db.update(rules).set({ tags: rule!.tags }).where(eq(rules.id, rule!.id));
    }
  });

  it('refuses an excluded project, and triage of an issue that is not open', async () => {
    await configure({
      organizations: { [h.organizationId]: { ...ALL_ON, excludedProjectIds: [p.id] } },
    });
    expect((await ask(eqIssue, 'explain')).json().detail).toBe('excluded_project');
    await configure();
    await h.ctx.db.update(issues).set({ status: 'wont_fix' }).where(eq(issues.id, eqIssue));
    try {
      expect((await ask(eqIssue, 'triage')).json().detail).toBe('not_open');
      expect((await ask(eqIssue, 'explain')).statusCode).toBe(202);
    } finally {
      await h.ctx.db.update(issues).set({ status: 'open' }).where(eq(issues.id, eqIssue));
    }
  });

  it('keeps the community ceiling of 25 fixes a day whatever fixPerDay says', async () => {
    await configure({ budgets: { ...DEFAULT_LLM_SETTINGS.budgets, fixPerDay: 1_000 } });
    const first = (await ask(eqIssue, 'fix')).json();
    const [template] = await h.ctx.db
      .select()
      .from(llmRequests)
      .where(eq(llmRequests.id, first.id));
    const copy = { ...template!, id: undefined };
    await h.ctx.db
      .insert(llmRequests)
      .values(Array.from({ length: 24 }, () => ({ ...copy, status: 'failed' as const })));
    const res = await ask(eqIssue, 'fix', { refresh: true });
    expect(res.statusCode).toBe(429);
    expect(res.json().code).toBe('AI_QUOTA_EXCEEDED');
    expect(Number(res.headers['retry-after'])).toBeGreaterThan(0);
    expect(Number(res.headers['retry-after'])).toBeLessThanOrEqual(86_400);
  });

  it('does not count a request the provider refused without using tokens, but counts others', async () => {
    await configure({ budgets: { ...DEFAULT_LLM_SETTINGS.budgets, explainPerDay: 2 } });
    const first = (await ask(eqIssue, 'explain')).json();
    const [template] = await h.ctx.db
      .select()
      .from(llmRequests)
      .where(eq(llmRequests.id, first.id));
    const copy = { ...template!, id: undefined };
    // The first request, and five more, all refused at the key: none counts.
    await h.ctx.db
      .update(llmRequests)
      .set({ status: 'failed', errorCode: 'PROVIDER_REFUSED_KEY' })
      .where(eq(llmRequests.id, first.id));
    await h.ctx.db.insert(llmRequests).values(
      Array.from({ length: 5 }, () => ({
        ...copy,
        status: 'failed' as const,
        errorCode: 'PROVIDER_REFUSED_KEY',
      })),
    );
    const usage = async () =>
      (await get(`/api/v0/organizations/${h.organizationId}/ai`)).json().usage;
    expect(await usage()).toMatchObject({ explain: 0 });
    // A timeout counts (the provider may have worked), and so does one that used tokens.
    await h.ctx.db.insert(llmRequests).values([
      { ...copy, status: 'failed' as const, errorCode: 'PROVIDER_TIMEOUT' },
      { ...copy, status: 'failed' as const, errorCode: 'PROVIDER_REFUSED_KEY', inputTokens: 5 },
    ]);
    expect(await usage()).toMatchObject({ explain: 2 });
    const res = await ask(eqIssue, 'explain', { refresh: true });
    expect([res.statusCode, res.json().code]).toEqual([429, 'AI_QUOTA_EXCEEDED']);
  });

  it('applies the token budget and the per-user bound', async () => {
    await configure({ budgets: { ...DEFAULT_LLM_SETTINGS.budgets, tokensPerDay: 100 } });
    const first = (await ask(eqIssue, 'explain')).json();
    await h.ctx.db
      .update(llmRequests)
      .set({ inputTokens: 90, outputTokens: 20 })
      .where(eq(llmRequests.id, first.id));
    expect((await ask(eqIssue, 'triage')).json().code).toBe('AI_QUOTA_EXCEEDED');
    await h.ctx.db.delete(llmRequests);
    await configure({ budgets: { ...DEFAULT_LLM_SETTINGS.budgets, perUserPerHour: 1 } });
    const u = await createUser(h.ctx, { username: 'ai-hourly' });
    await addMember(h.ctx, h.organizationId, u.id, 'member');
    const s = await login(h.ctx, u.username, u.password);
    expect((await ask(eqIssue, 'triage', {}, s)).statusCode).toBe(202);
    const second = await ask(eqIssue, 'triage', { refresh: true }, s);
    expect([second.statusCode, second.json().code]).toEqual([429, 'RATE_LIMITED']);
    expect(Number(second.headers['retry-after'])).toBeGreaterThan(0);
  });

  it('cannot overshoot a budget with concurrent requests', async () => {
    await configure({
      budgets: { ...DEFAULT_LLM_SETTINGS.budgets, fixPerDay: 3, perUserPerHour: 10_000 },
    });
    const answers = await Promise.all(
      Array.from({ length: 12 }, () => ask(eqIssue, 'fix', { refresh: true })),
    );
    const codes = answers.map((r) => r.statusCode).sort();
    expect(codes.filter((c) => c === 202)).toHaveLength(3);
    expect(codes.filter((c) => c === 429)).toHaveLength(9);
    expect(await h.ctx.db.select().from(llmRequests)).toHaveLength(3);
  });

  it('cannot overshoot the per-user bound with concurrent requests', async () => {
    await configure({ budgets: { ...DEFAULT_LLM_SETTINGS.budgets, perUserPerHour: 3 } });
    const u = await createUser(h.ctx, { username: 'ai-burst' });
    await addMember(h.ctx, h.organizationId, u.id, 'member');
    const s = await login(h.ctx, u.username, u.password);
    const answers = await Promise.all(
      Array.from({ length: 10 }, () => ask(eqIssue, 'explain', { refresh: true }, s)),
    );
    expect(answers.filter((r) => r.statusCode === 202)).toHaveLength(3);
    expect(answers.filter((r) => r.json().code === 'RATE_LIMITED')).toHaveLength(7);
    expect(await h.ctx.db.select().from(llmRequests)).toHaveLength(3);
  });

  it('asks once for concurrent identical requests', async () => {
    await configure({ budgets: { ...DEFAULT_LLM_SETTINGS.budgets, perUserPerHour: 10_000 } });
    const answers = await Promise.all(Array.from({ length: 8 }, () => ask(eqIssue, 'triage')));
    expect(answers.map((r) => r.statusCode)).toEqual(Array(8).fill(202));
    expect(new Set(answers.map((r) => r.json().id)).size).toBe(1);
    expect(await h.ctx.db.select().from(llmRequests)).toHaveLength(1);
  });

  it('lets a member with write ask; a read token gets 403; another organisation gets 404', async () => {
    await configure({ budgets: { ...DEFAULT_LLM_SETTINGS.budgets, perUserPerHour: 10_000 } });
    const u = await createUser(h.ctx, { username: 'ai-member' });
    await addMember(h.ctx, h.organizationId, u.id, 'member');
    const member = await login(h.ctx, u.username, u.password);
    const writeToken = await tokenOf(member, ['write']);
    const readToken = await tokenOf(member, ['read']);

    // POST /issues/{id}/ai/{feature}
    expect((await ask(eqIssue, 'explain', {}, member)).statusCode).toBe(202);
    const viaToken = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${eqIssue}/ai/triage`,
      headers: writeToken,
      payload: {},
    });
    expect(viaToken.statusCode, viaToken.body).toBe(202);
    const read = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${eqIssue}/ai/fix`,
      headers: readToken,
      payload: {},
    });
    expect([read.statusCode, read.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    const project = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${eqIssue}/ai/fix`,
      headers: bearer(p.token),
      payload: {},
    });
    expect(project.statusCode).toBe(403);
    const foreign = await ask(eqIssue, 'explain', {}, outsider);
    expect([foreign.statusCode, foreign.json().code]).toEqual([404, 'NOT_FOUND']);
    const missing = await ask('01900000-0000-7000-8000-000000000000', 'explain');
    expect(missing.statusCode).toBe(404);
    expect(missing.json().title).toBe(foreign.json().title);
    expect((await ask(eqIssue, 'summarise')).statusCode).toBe(422);

    // GET /ai-requests/{id}
    const id = viaToken.json().id as string;
    expect((await get(`/api/v0/ai-requests/${id}`, readToken)).statusCode).toBe(200);
    const foreignGet = await get(`/api/v0/ai-requests/${id}`, outsider.headers);
    expect(foreignGet.statusCode).toBe(404);
    const missingGet = await get(
      '/api/v0/ai-requests/01900000-0000-7000-8000-000000000000',
      outsider.headers,
    );
    expect(missingGet.json().title).toBe(foreignGet.json().title);

    // GET /issues/{id}/ai
    expect((await get(`/api/v0/issues/${eqIssue}/ai`, readToken)).statusCode).toBe(200);
    expect((await get(`/api/v0/issues/${eqIssue}/ai`, outsider.headers)).statusCode).toBe(404);

    // GET /organizations/{id}/ai
    const orgRead = await get(`/api/v0/organizations/${h.organizationId}/ai`, readToken);
    expect(orgRead.statusCode).toBe(200);
    const orgForeign = await get(`/api/v0/organizations/${h.organizationId}/ai`, outsider.headers);
    expect(orgForeign.statusCode).toBe(404);
  });

  it('lists the latest request per feature and the organisation’s status', async () => {
    await configure();
    await ask(eqIssue, 'explain');
    const second = (await ask(eqIssue, 'explain', { refresh: true })).json();
    const latest = await get(`/api/v0/issues/${eqIssue}/ai`);
    expect(latest.json()).toMatchObject({
      explain: { feature: 'explain', id: second.id },
      triage: null,
      fix: null,
    });
    const org = await get(`/api/v0/organizations/${h.organizationId}/ai`);
    expect(org.json()).toMatchObject({
      enabled: true,
      features: { explain: true, triage: true, fix: true },
      provider: { kind: 'openai', host: fake.host, model: 'fake-model' },
      dataSent: ['rule', 'message', 'path', 'language', 'snippet'],
      usage: { explain: 2, triage: 0, fix: 0, tokens: 0, costUsd: null },
      budgets: { fixPerDay: 25 },
    });
    expect(org.body).not.toContain(fake.apiKey);
    expect(org.body).not.toContain(fake.openAiBaseUrl);
  });

  it('shows a disabled organisation as disabled, without a provider when there is none', async () => {
    await configure({ provider: null });
    const none = (await get(`/api/v0/organizations/${h.organizationId}/ai`)).json();
    expect(none).toMatchObject({
      enabled: false,
      provider: null,
      features: { explain: false, triage: false, fix: false },
    });
    await configure({ organizations: {} });
    const off = (await get(`/api/v0/organizations/${h.organizationId}/ai`)).json();
    expect(off).toMatchObject({ enabled: false, features: { explain: false } });
  });

  it('writes neither the snippet nor the key to the log', async () => {
    await configure({ storePrompts: true });
    await ask(eqIssue, 'explain');
    await ask(eqIssue, 'triage');
    const logs = h.ctx.logs.join('\n');
    expect(logs).not.toContain(fake.apiKey);
    expect(logs).not.toContain('a == 1');
    expect(logs).not.toContain('QUALOR-DATA');
  });
});
