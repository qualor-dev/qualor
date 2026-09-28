import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeLlm, openAiAnswer, type FakeLlm } from '../../test/fake-llm';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { configuredProvider, configureLlm, llmJobDeps, runLlmJobs } from '../../test/llm';
import { engine, file, finding, reportWith } from '../../test/reports';
import { issues, jobs, llmRequests } from '../db/schema';
import { claimJob, reapExpiredLeases } from '../queue/queue';
import { parseInternalHosts } from '../scm/url';
import {
  createLlmRuntime,
  jsonbTextBytes,
  LLM_RESULT_MAX_BYTES,
  reconcileStuckLlmRequests,
} from './job';
import { LLM_QUEUE } from './service';
import { DEFAULT_BUDGETS } from './settings';

const token = ['gh', 'p_', 'Z9y8'.repeat(9)].join('');
const LINES = ['const a = 1;', `const t = "${token}";`, 'if (a == 1) {}', 'export {};'];

describe('the llm worker (llm.md §9, §10, §14)', () => {
  let fake: FakeLlm;
  let h: IngestHarness;
  let issueId: string;
  const ask = async (feature: string, payload: object = {}) => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${issueId}/ai/${feature}`,
      headers: h.orgAdmin.headers,
      payload,
    });
    expect(res.statusCode, res.body).toBe(202);
    return res.json() as { id: string };
  };
  const row = async (id: string) =>
    (await h.ctx.db.select().from(llmRequests).where(eq(llmRequests.id, id)))[0]!;
  const llmJobs = () => h.ctx.db.select().from(jobs).where(eq(jobs.queue, LLM_QUEUE));
  const logs = () => h.ctx.logs.join('\n');
  // Every test asks as the same person: the per-user bound (30 an hour) is not under test here.
  const configure = (over: Parameters<typeof configureLlm>[4] = {}) =>
    configureLlm(h.ctx.db, h.ctx.config.secretKey, fake, h.organizationId, {
      budgets: { ...DEFAULT_BUDGETS, perUserPerHour: 1_000 },
      ...over,
    });

  beforeAll(async () => {
    fake = await createFakeLlm();
    h = await createIngestHarness({ config: { llmInternalHosts: parseInternalHosts(fake.host) } });
    const p = await h.project('acme/ai-job');
    await p.ingestOk(
      reportWith({
        projectKey: 'acme/ai-job',
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 4 })],
        findings: [finding({ ruleId: 'eqeqeq', line: 3, snippet: { startLine: 1, lines: LINES } })],
      }),
    );
    issueId = (await h.ctx.db.select({ id: issues.id }).from(issues))[0]!.id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(async () => {
    await h.ctx.db.delete(llmRequests);
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, LLM_QUEUE));
    fake.requests.length = 0;
    h.ctx.logs.length = 0;
    await configure();
  });

  it('explains through the fake, redacted, and records metadata only', async () => {
    const { id } = await ask('explain');
    await runLlmJobs(h, llmJobDeps(h));
    const r = await row(id);
    expect(r).toMatchObject({
      status: 'succeeded',
      attempts: 1,
      inputTokens: 412,
      outputTokens: 96,
      errorCode: null,
      redactions: 1,
      prompt: null,
    });
    expect(r.durationMs).not.toBeNull();
    expect(r.finishedAt).not.toBeNull();
    expect(r.result).toMatchObject({
      kind: 'explain',
      summary: 'Loose equality compares after type coercion.',
    });
    expect(fake.requests).toHaveLength(1);
    const sent = fake.requests[0]!.body;
    expect(sent).not.toContain(token);
    expect(sent).toContain('«redacted»');
    expect(logs()).toContain('AI request finished');
    expect(logs()).toContain(r.inputSha256);
    expect(logs()).not.toContain('if (a == 1)');
    expect(logs()).not.toContain('QUALOR-DATA');
    expect(logs()).not.toContain('Loose equality');
    expect(logs()).not.toContain(fake.apiKey);
    expect(logs()).not.toContain(fake.openAiBaseUrl);
  });

  it('works with the Anthropic shape too', async () => {
    await configure({
      kind: 'anthropic',
    });
    const { id } = await ask('triage');
    await runLlmJobs(h, llmJobDeps(h));
    expect((await row(id)).result).toMatchObject({
      kind: 'triage',
      verdict: 'likely_true_positive',
    });
    expect(fake.requests[0]!.path).toBe('/v1/messages');
  });

  it('draws a fresh random nonce for every request', async () => {
    await ask('explain');
    await ask('triage');
    await runLlmJobs(h, llmJobDeps(h));
    const nonces = fake.requests.map(
      (r) => /<<<QUALOR-DATA-([0-9a-f]{32})\\n/.exec(r.body)?.[1] ?? null,
    );
    expect(nonces).toHaveLength(2);
    expect(nonces[0]).toMatch(/^[0-9a-f]{32}$/);
    expect(nonces[1]).toMatch(/^[0-9a-f]{32}$/);
    expect(nonces[0]).not.toBe(nonces[1]);
  });

  it('suggests a fix that passes checkFix, and refuses an unsafe one', async () => {
    const good = await ask('fix');
    await runLlmJobs(h, llmJobDeps(h));
    expect((await row(good.id)).result).toMatchObject({
      kind: 'fix',
      status: 'fixed',
      original: ['if (a == 1) {}'],
      replacement: ['if (a === 1) {}'],
    });
    fake.say(
      JSON.stringify({
        status: 'fixed',
        startLine: 3,
        endLine: 3,
        replacement: ['```', 'x'],
        explanation: '',
      }),
    );
    const bad = await ask('fix', { refresh: true });
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(bad.id)).toMatchObject({
      status: 'failed',
      errorCode: 'OUTPUT_REFUSED:fence',
      result: null,
      attempts: 1,
    });
    expect(fake.requests).toHaveLength(2);
  });

  it('refuses a fix whose stored result would not fit the 16 KiB bound, without a database error', async () => {
    // 30 lines of 400 three-byte characters: each line passes checkFix, together 36 000 bytes.
    const wide = '字'.repeat(400);
    fake.say(
      JSON.stringify({
        status: 'fixed',
        startLine: 3,
        endLine: 3,
        replacement: Array.from({ length: 30 }, () => wide),
        explanation: 'x',
      }),
    );
    const { id } = await ask('fix');
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(id)).toMatchObject({
      status: 'failed',
      errorCode: 'OUTPUT_REFUSED:size',
      result: null,
    });
    const [dead] = await h.ctx.db
      .select()
      .from(jobs)
      .where(sql`${jobs.queue} = ${LLM_QUEUE} AND ${jobs.status} <> 'succeeded'`);
    expect(dead).toBeUndefined();
  });

  it('measures a result as PostgreSQL writes jsonb as text', async () => {
    const samples: unknown[] = [
      {
        kind: 'explain',
        summary: 'a "quoted"\\ line\nand\ttab',
        explanation: 'é字😀',
        howToFix: '',
      },
      {
        kind: 'fix',
        status: 'fixed',
        startLine: 3,
        endLine: 12,
        original: ['a', ''],
        replacement: [],
      },
      { a: [1, 2.5, -3, true, false, null, { b: [] }, {}], c: '\u0001\u001f\u007f ' },
    ];
    for (const value of samples) {
      const { rows } = await h.ctx.db.execute<{ n: number }>(
        sql`SELECT octet_length((${JSON.stringify(value)})::jsonb::text) AS n`,
      );
      expect(jsonbTextBytes(value)).toBe(rows[0]!.n);
    }
    expect(LLM_RESULT_MAX_BYTES).toBeLessThan(16_384);
  });

  it.each([
    [
      'prose around the object',
      { status: 200, body: openAiAnswer('Sure! Here is the JSON: {}') },
      'MALFORMED_OUTPUT',
    ],
    [
      'a truncated answer',
      { status: 200, body: openAiAnswer('{"summary": "a', { finishReason: 'length' }) },
      'OUTPUT_TRUNCATED',
    ],
    [
      'a content filter',
      { status: 200, body: openAiAnswer('', { finishReason: 'content_filter' }) },
      'MODEL_REFUSED',
    ],
  ])('fails %s at once, without a retry', async (_name, reply, code) => {
    fake.enqueue(reply);
    const { id } = await ask('explain');
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(id)).toMatchObject({ status: 'failed', errorCode: code, attempts: 1 });
    expect(fake.requests).toHaveLength(1);
    expect(await llmJobs()).toHaveLength(1);
  });

  it('does not retry a refused key, and keeps the key and the provider body out of the row and the logs', async () => {
    fake.enqueue({ status: 401, body: { error: { message: 'bad key sk-provider-echo' } } });
    const { id } = await ask('explain');
    await runLlmJobs(h, llmJobDeps(h));
    const r = await row(id);
    expect(r).toMatchObject({ status: 'failed', errorCode: 'PROVIDER_REFUSED_KEY', attempts: 1 });
    expect(JSON.stringify(r)).not.toContain(fake.apiKey);
    expect(logs()).not.toContain('sk-provider-echo');
    expect(logs()).not.toContain(fake.apiKey);
    expect(fake.requests).toHaveLength(1);
  });

  /**
   * How far `runAt` is ahead of the database's clock, in ms. The retry is scheduled with the
   * database's `now()`, so the test reads the same clock: Date.now() may differ from Docker's clock
   * by tens of milliseconds.
   */
  const dbWait = async (runAt: Date): Promise<number> => {
    const { rows } = await h.ctx.db.execute<{ ms: number }>(
      sql`SELECT (extract(epoch FROM ${runAt.toISOString()}::timestamptz - clock_timestamp()) * 1000)::float8 AS ms`,
    );
    return Number(rows[0]!.ms);
  };

  it('retries a 429 after Retry-After, then succeeds', async () => {
    fake.enqueue({
      status: 429,
      // Longer than the first backoff (5 s) and shorter than the second (30 s): only Retry-After
      // explains the wait.
      headers: { 'retry-after': '12' },
      body: { error: { message: 'x' } },
    });
    const { id } = await ask('explain');
    const deps = llmJobDeps(h);
    await runLlmJobs(h, deps);
    const retry = (await llmJobs()).find((j) => j.status === 'queued');
    expect(retry).toBeDefined();
    const wait = await dbWait(retry!.runAt);
    expect(wait).toBeGreaterThan(10_000);
    expect(wait).toBeLessThanOrEqual(13_000);
    expect(await row(id)).toMatchObject({ status: 'queued', attempts: 1 });
    await runLlmJobs(h, deps);
    expect(await row(id)).toMatchObject({ status: 'succeeded', attempts: 2 });
  });

  it('honours a long Retry-After, clamped to two minutes', async () => {
    fake.enqueue({
      status: 429,
      headers: { 'retry-after': '90' },
      body: { error: { message: 'x' } },
    });
    await ask('explain');
    await runLlmJobs(h, llmJobDeps(h));
    let retry = (await llmJobs()).find((j) => j.status === 'queued');
    let wait = await dbWait(retry!.runAt);
    expect(wait).toBeGreaterThan(80_000);
    expect(wait).toBeLessThanOrEqual(91_000);

    await h.ctx.db.delete(llmRequests);
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, LLM_QUEUE));
    fake.enqueue({
      status: 429,
      headers: { 'retry-after': '3600' },
      body: { error: { message: 'x' } },
    });
    await ask('explain');
    await runLlmJobs(h, llmJobDeps(h));
    retry = (await llmJobs()).find((j) => j.status === 'queued');
    wait = await dbWait(retry!.runAt);
    expect(wait).toBeGreaterThan(110_000);
    expect(wait).toBeLessThanOrEqual(121_000);
  });

  it('gives up after three attempts, and opens the circuit after five transient failures', async () => {
    const deps = llmJobDeps(h, { runtime: createLlmRuntime() });
    for (let i = 0; i < 5; i += 1) fake.enqueue({ status: 500, body: {} });
    const a = await ask('explain');
    await runLlmJobs(h, deps);
    await runLlmJobs(h, deps);
    await runLlmJobs(h, deps);
    expect(await row(a.id)).toMatchObject({
      status: 'failed',
      errorCode: 'PROVIDER_UNAVAILABLE',
      attempts: 3,
    });
    const b = await ask('triage');
    await runLlmJobs(h, deps);
    await runLlmJobs(h, deps);
    expect(fake.requests).toHaveLength(5);
    await runLlmJobs(h, deps);
    expect(fake.requests).toHaveLength(5);
    expect(await row(b.id)).toMatchObject({ status: 'failed', errorCode: 'PROVIDER_UNAVAILABLE' });
    // Another provider (another base URL) has its own circuit.
    await configure({
      kind: 'anthropic',
    });
    const c = await ask('explain');
    await runLlmJobs(h, deps);
    expect(await row(c.id)).toMatchObject({ status: 'succeeded' });
  });

  it('scrubs the API key from an answer before storing it', async () => {
    fake.enqueue({
      status: 200,
      body: openAiAnswer(
        JSON.stringify({ summary: `key ${fake.apiKey}`, explanation: 'e', howToFix: '' }),
      ),
    });
    const { id } = await ask('explain');
    await runLlmJobs(h, llmJobDeps(h));
    const r = await row(id);
    expect(r.status).toBe('succeeded');
    expect(JSON.stringify(r.result)).not.toContain(fake.apiKey);
  });

  it('sends nothing when the model changed or the organisation was turned off since the click', async () => {
    const a = await ask('explain');
    await configure({
      provider: { ...configuredProvider(h.ctx.config.secretKey, fake), model: 'other-model' },
    });
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(a.id)).toMatchObject({ status: 'failed', errorCode: 'SETTINGS_CHANGED' });
    await configure();
    const b = await ask('triage');
    await configure({
      organizations: {},
    });
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(b.id)).toMatchObject({ status: 'failed', errorCode: 'AI_DISABLED' });
    await configure();
    const c = await ask('fix');
    await configure({
      excludePaths: ['src/**'],
    });
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(c.id)).toMatchObject({ status: 'failed', errorCode: 'AI_DISABLED' });
    expect(fake.requests).toHaveLength(0);
  });

  it('computes the cost from the admin’s prices', async () => {
    await configure({
      pricing: { inputUsdPerMTok: 3, outputUsdPerMTok: 15 },
    });
    const { id } = await ask('explain', { refresh: true });
    await runLlmJobs(h, llmJobDeps(h));
    // 412 × 3 + 96 × 15 micro-USD
    expect((await row(id)).costMicroUsd).toBe(412 * 3 + 96 * 15);
  });

  it('records the tokens and the cost of an answer that failed validation (they were spent)', async () => {
    await configure({ pricing: { inputUsdPerMTok: 3, outputUsdPerMTok: 15 } });
    fake.enqueue({ status: 200, body: openAiAnswer('Sure! {}') });
    const { id } = await ask('explain');
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(id)).toMatchObject({
      status: 'failed',
      errorCode: 'MALFORMED_OUTPUT',
      inputTokens: 412,
      outputTokens: 96,
      costMicroUsd: 412 * 3 + 96 * 15,
    });
  });

  it('stores an out-of-range token count as unknown, and then no cost', async () => {
    await configure({ pricing: { inputUsdPerMTok: 3, outputUsdPerMTok: 15 } });
    fake.enqueue({
      status: 200,
      body: {
        ...(openAiAnswer(
          JSON.stringify({ summary: 's', explanation: 'e', howToFix: '' }),
        ) as object),
        usage: { prompt_tokens: 3_000_000_000, completion_tokens: 5 },
      },
    });
    const { id } = await ask('explain');
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(id)).toMatchObject({
      status: 'succeeded',
      inputTokens: null,
      outputTokens: 5,
      costMicroUsd: null,
    });
  });

  it('records nothing, and retries nothing, when the job lost its lease while the model answered', async () => {
    // The sweep failed the row (REQUEST_ABANDONED) while the call was in flight.
    const abandon = async (id: string) => {
      await h.ctx.db
        .update(llmRequests)
        .set({ status: 'failed', errorCode: 'REQUEST_ABANDONED', finishedAt: sql`now()` })
        .where(eq(llmRequests.id, id));
    };
    let current = '';
    fake.enqueue(async () => {
      await abandon(current);
      return {
        status: 200,
        body: openAiAnswer(JSON.stringify({ summary: 's', explanation: 'e', howToFix: '' })),
      };
    });
    current = (await ask('explain')).id;
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(current)).toMatchObject({
      status: 'failed',
      errorCode: 'REQUEST_ABANDONED',
      result: null,
    });
    expect(logs()).toContain('no longer running');
    // A transient failure: no requeue, no second job.
    fake.enqueue(async () => {
      await abandon(current);
      return { status: 503, body: {} };
    });
    current = (await ask('triage')).id;
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(current)).toMatchObject({ status: 'failed', errorCode: 'REQUEST_ABANDONED' });
    const queued = (await llmJobs()).filter((j) => j.status === 'queued');
    expect(queued).toEqual([]);
    // A row finished before its job ran: nothing is sent.
    const before = fake.requests.length;
    current = (await ask('fix')).id;
    await abandon(current);
    await runLlmJobs(h, llmJobDeps(h));
    expect(fake.requests).toHaveLength(before);
    expect((await row(current)).attempts).toBe(0);
  });

  it('scrubs the key from the final strings, also when the answer spells it with JSON escapes', async () => {
    const escaped = `\\u${fake.apiKey.charCodeAt(0).toString(16).padStart(4, '0')}${fake.apiKey.slice(1)}`;
    fake.say(`{"summary": "key ${escaped}", "explanation": "e", "howToFix": ""}`);
    const { id } = await ask('explain');
    await runLlmJobs(h, llmJobDeps(h));
    const r = await row(id);
    expect(r.status).toBe('succeeded');
    expect(JSON.stringify(r.result)).not.toContain(fake.apiKey);
    expect(r.result).toMatchObject({ summary: 'key «redacted»' });
  });

  it('sends nothing when the base URL changed on the same host since the click', async () => {
    const { id } = await ask('explain');
    const provider = configuredProvider(h.ctx.config.secretKey, fake);
    await configure({ provider: { ...provider, baseUrl: `${provider.baseUrl}/other` } });
    await runLlmJobs(h, llmJobDeps(h));
    expect(await row(id)).toMatchObject({ status: 'failed', errorCode: 'SETTINGS_CHANGED' });
    expect(fake.requests).toHaveLength(0);
  });

  it('fails a request whose job died with its worker, and leaves live ones alone', async () => {
    const crashed = await ask('explain');
    // A worker claims the job, marks the row running, and dies: its lease expires and the reaper
    // makes the job dead (one attempt: the handler schedules its own retries).
    const job = await claimJob(h.ctx.db, LLM_QUEUE, 'crashed-worker', 60_000);
    expect(job).not.toBeNull();
    await h.ctx.db
      .update(llmRequests)
      .set({ status: 'running', attempts: 1 })
      .where(eq(llmRequests.id, crashed.id));
    await h.ctx.db
      .update(jobs)
      .set({ lockedUntil: sql`now() - interval '1 second'` })
      .where(eq(jobs.id, job!.id));
    expect(await reapExpiredLeases(h.ctx.db)).toBe(1);
    expect((await llmJobs())[0]!.status).toBe('dead');

    // Live: a queued request waiting long behind a backlog (the row's age decides nothing), and a
    // running one whose worker still holds the lease.
    const queued = await ask('triage');
    await h.ctx.db
      .update(llmRequests)
      .set({ createdAt: sql`now() - interval '3 days'`, updatedAt: sql`now() - interval '3 days'` })
      .where(eq(llmRequests.id, queued.id));
    await h.ctx.db
      .update(jobs)
      .set({ runAt: sql`now() + interval '1 hour'`, createdAt: sql`now() - interval '3 days'` })
      .where(sql`${jobs.queue} = ${LLM_QUEUE} AND ${jobs.payload} ->> 'requestId' = ${queued.id}`);
    const running = await ask('fix');
    const [runningJob] = await h.ctx.db
      .select()
      .from(jobs)
      .where(sql`${jobs.queue} = ${LLM_QUEUE} AND ${jobs.payload} ->> 'requestId' = ${running.id}`);
    await h.ctx.db
      .update(jobs)
      .set({ status: 'running', lockedBy: 'alive', lockedUntil: sql`now() + interval '1 minute'` })
      .where(eq(jobs.id, runningJob!.id));
    await h.ctx.db
      .update(llmRequests)
      .set({ status: 'running' })
      .where(eq(llmRequests.id, running.id));

    expect(await reconcileStuckLlmRequests(h.ctx.db)).toBe(1);
    const r = await row(crashed.id);
    expect(r).toMatchObject({ status: 'failed', errorCode: 'REQUEST_ABANDONED', result: null });
    expect(r.finishedAt).not.toBeNull();
    expect((await row(queued.id)).status).toBe('queued');
    expect((await row(running.id)).status).toBe('running');
    expect(await reconcileStuckLlmRequests(h.ctx.db)).toBe(0);

    const res = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/ai-requests/${crashed.id}`,
      headers: h.orgAdmin.headers,
    });
    expect(res.json()).toMatchObject({ error: { code: 'REQUEST_ABANDONED' } });
  });

  it('fails a request whose handler threw, once the sweep runs', async () => {
    const { id } = await ask('explain');
    // A nonce that is not 32 hex characters: buildPrompt refuses it, and the handler throws.
    const deps = llmJobDeps(h, { nonce: () => 'not-hex' });
    await runLlmJobs(h, deps);
    expect((await llmJobs())[0]!.status).toBe('dead');
    expect((await row(id)).status).toBe('running');
    expect(await reconcileStuckLlmRequests(h.ctx.db)).toBe(1);
    expect(await row(id)).toMatchObject({ status: 'failed', errorCode: 'REQUEST_ABANDONED' });
    expect(fake.requests).toHaveLength(0);
  });
});
