import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { file, finding, reportWith } from '../../test/reports';
import {
  analyses,
  analysisReports,
  branches,
  instanceSettings,
  issues,
  jobs,
  llmRequests,
  sessions,
  webhookDeliveries,
  webhookSubscriptions,
} from '../db/schema';
import { appendEvents, type AuditActorContext } from '../audit/recorder';
import { AUDIT_CHAIN_KEY, AUDIT_SETTINGS_KEY } from '../audit/settings';
import { verifyAuditChain } from '../audit/verify';
import { uuidv7 } from '../db/ids';
import { DEFAULT_LLM_SETTINGS, LLM_SETTINGS_KEY } from '../llm/settings';
import { runUntilIdle } from '../queue/worker';
import { WEBHOOK_QUEUE } from '../webhooks/deliveries';
import {
  ensureHousekeepingScheduled,
  HOUSEKEEPING_QUEUE,
  housekeepingHandlers,
  runHousekeeping,
} from './run';

describe('daily housekeeping (data-model.md §7)', () => {
  let h: IngestHarness;
  let p: IngestProject;
  const ago = (days: number) => sql`now() - make_interval(days => ${days})`;
  const housekeepingJobs = () =>
    h.ctx.db.select().from(jobs).where(eq(jobs.queue, HOUSEKEEPING_QUEUE));

  beforeAll(async () => {
    h = await createIngestHarness();
    p = await h.project('housekeeping/p');
  });
  beforeEach(async () => {
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, HOUSEKEEPING_QUEUE));
  });
  afterAll(async () => {
    await h.close();
  });

  it('deletes what is past retention and keeps everything else', async () => {
    const old = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: 'feature/old',
        analysisDate: '2026-09-20T10:00:00Z',
        files: [file('src/a.ts')],
        findings: [finding({ line: 1 }), finding({ line: 2, ruleId: 'r2' })],
      }),
    );
    const recent = await p.ingestOk(
      reportWith({
        projectKey: p.key,
        analysisDate: '2026-09-21T10:00:00Z',
        files: [file('src/a.ts')],
        findings: [],
      }),
    );
    // The processing job just finished: its report is kept for debugging, 7 days by default.
    await h.ctx.db.execute(sql`UPDATE analyses SET finished_at = ${ago(8)} WHERE id = ${old}`);
    await h.ctx.db.execute(sql`UPDATE analyses SET finished_at = ${ago(6)} WHERE id = ${recent}`);
    const [a, b] = await h.ctx.db.select().from(issues).where(eq(issues.projectId, p.id));
    await h.ctx.db.execute(sql`
      UPDATE issues SET status = 'closed',
        closed_at = CASE id WHEN ${a!.id}::uuid THEN ${ago(31)} ELSE ${ago(29)} END
      WHERE id IN (${a!.id}::uuid, ${b!.id}::uuid)`);
    const [empty] = await h.ctx.db
      .insert(branches)
      .values({ projectId: p.id, kind: 'branch', name: 'feature/never-analysed' })
      .returning();
    await h.ctx.db.execute(
      sql`UPDATE branches SET created_at = ${ago(31)} WHERE id = ${empty!.id}`,
    );
    await h.ctx.db.execute(sql`
      INSERT INTO jobs (id, queue, payload, status, updated_at) VALUES
        (gen_random_uuid(), 'analysis', '{}'::jsonb, 'succeeded', ${ago(8)}),
        (gen_random_uuid(), 'analysis', '{}'::jsonb, 'dead', ${ago(8)}),
        (gen_random_uuid(), 'analysis', '{}'::jsonb, 'queued', ${ago(8)})`);
    await h.ctx.db.execute(sql`
      INSERT INTO sessions (id, user_id, expires_at)
      VALUES (decode('00', 'hex'), ${h.ctx.adminId}, now() - interval '1 minute')`);

    const result = await runHousekeeping(h.ctx.db);
    expect(result).toMatchObject({
      analysisReports: 1,
      closedIssues: 1,
      branches: 1,
      jobs: 2,
      sessions: 1,
    });
    const reports = await h.ctx.db.select().from(analysisReports);
    expect(reports.map((r) => r.analysisId)).not.toContain(old);
    expect(reports.map((r) => r.analysisId)).toContain(recent);
    expect((await h.ctx.db.select().from(issues).where(eq(issues.id, a!.id))).length).toBe(0);
    expect((await h.ctx.db.select().from(issues).where(eq(issues.id, b!.id))).length).toBe(1);
    expect(
      await h.ctx.db
        .select()
        .from(branches)
        .where(and(eq(branches.projectId, p.id), eq(branches.name, 'feature/never-analysed'))),
    ).toEqual([]);
    // A branch with an analysis, and the main branch, are never pruned.
    expect(
      (await h.ctx.db.select().from(branches).where(eq(branches.projectId, p.id))).map(
        (r) => r.name,
      ),
    ).toEqual(expect.arrayContaining(['main', 'feature/old']));
    expect(
      (await h.ctx.db.select().from(jobs).where(eq(jobs.status, 'queued'))).length,
    ).toBeGreaterThan(0);
    expect(
      await h.ctx.db
        .select()
        .from(sessions)
        .where(sql`expires_at < now()`),
    ).toEqual([]);
    expect((await h.ctx.db.select().from(analyses).where(eq(analyses.id, old))).length).toBe(1);
  });

  it('prunes audit events past the audit setting, without audit-log, as an anchored prefix', async () => {
    const DAY = 24 * 60 * 60 * 1000;
    const daysAgo = (n: number) => new Date(Date.now() - n * DAY);
    const alice: AuditActorContext = {
      actor: { type: 'user', userId: h.ctx.adminId, username: 'admin', tokenId: null },
      ip: null,
      userAgent: null,
    };
    const signOut = { action: 'auth.sign_out' as const, details: {} };
    await appendEvents(h.ctx.db, alice, [signOut, signOut], daysAgo(400));
    await appendEvents(h.ctx.db, alice, [signOut], daysAgo(100));
    await appendEvents(h.ctx.db, alice, [signOut], daysAgo(1));
    // The default period is 365 days (rbac-audit.md §11.1); no licence is loaded here.
    expect((await runHousekeeping(h.ctx.db)).auditEvents).toBe(2);
    expect((await runHousekeeping(h.ctx.db)).auditEvents).toBe(0);
    await h.ctx.db
      .insert(instanceSettings)
      .values({ key: AUDIT_SETTINGS_KEY, value: { retentionDays: 30, stream: null } });
    try {
      expect((await runHousekeeping(h.ctx.db)).auditEvents).toBe(1);
    } finally {
      await h.ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, AUDIT_SETTINGS_KEY));
    }
    const pruned = await h.ctx.db.execute<{ n: number }>(
      sql`SELECT count(*)::int AS n FROM audit_events WHERE action = 'audit.pruned'`,
    );
    expect(pruned.rows).toEqual([{ n: 2 }]);
    expect(await verifyAuditChain(h.ctx.db)).toMatchObject({ ok: true, checked: 3 });
  });

  it('skips audit retention on a malformed audit-chain row, logs it once, and completes', async () => {
    const signOut = { action: 'auth.sign_out' as const, details: {} };
    await appendEvents(
      h.ctx.db,
      {
        actor: { type: 'user', userId: h.ctx.adminId, username: 'admin', tokenId: null },
        ip: null,
        userAgent: null,
      },
      [signOut],
      new Date(Date.now() - 400 * 24 * 60 * 60 * 1000),
    );
    const events = async () =>
      (
        await h.ctx.db.execute<{ seq: string; hash: string }>(
          sql`SELECT seq::text, hash FROM audit_events ORDER BY audit_events.seq`,
        )
      ).rows;
    const before = await events();
    const malformed = { throughSeq: 'x', note: 'hand-edited' };
    await h.ctx.db
      .insert(instanceSettings)
      .values({ key: AUDIT_CHAIN_KEY, value: malformed })
      .onConflictDoUpdate({ target: instanceSettings.key, set: { value: malformed } });
    const errors: { obj: object; msg: string }[] = [];
    const logger = {
      info: () => undefined,
      error: (obj: object, msg: string) => errors.push({ obj, msg }),
    };
    try {
      await ensureHousekeepingScheduled(h.ctx.db);
      expect(
        await runUntilIdle(h.ctx.db, housekeepingHandlers({ db: h.ctx.db, logger }), h.ctx.app.log),
      ).toBe(1);
      expect((await housekeepingJobs()).map((j) => j.status).sort()).toEqual([
        'queued',
        'succeeded',
      ]);
      expect(await events()).toEqual(before);
      const [row] = await h.ctx.db
        .select({ value: instanceSettings.value })
        .from(instanceSettings)
        .where(eq(instanceSettings.key, AUDIT_CHAIN_KEY));
      expect(row?.value).toEqual(malformed);
      expect(errors).toHaveLength(1);
      expect(errors[0]?.msg).toMatch(/audit-chain is malformed; audit retention was skipped/);
      expect(JSON.stringify(errors)).not.toContain('hand-edited');
      expect((await runHousekeeping(h.ctx.db)).auditEvents).toBe(0);
    } finally {
      await h.ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, AUDIT_CHAIN_KEY));
    }
  });

  it('honours retention overrides from instance_settings and ignores invalid ones', async () => {
    // Self-contained: its own project and analyses, and assertions on its own rows only.
    const q = await h.project('housekeeping/overrides');
    const reportOf = async (daysAgo: number, hour: number) => {
      const id = await q.ingestOk(
        reportWith({
          projectKey: q.key,
          analysisDate: `2026-09-22T${String(hour).padStart(2, '0')}:00:00Z`,
          files: [file('src/a.ts')],
        }),
      );
      await h.ctx.db.execute(
        sql`UPDATE analyses SET finished_at = ${ago(daysAgo)} WHERE id = ${id}`,
      );
      return id;
    };
    const threeDays = await reportOf(3, 10);
    const oneDay = await reportOf(1, 11);
    const stored = async () =>
      (await h.ctx.db.select().from(analysisReports)).map((r) => r.analysisId);
    try {
      await h.ctx.db
        .insert(instanceSettings)
        .values({ key: 'retention', value: { analysisReportsDays: 'soon' } });
      await runHousekeeping(h.ctx.db);
      // The invalid override is ignored: the default 7 days keeps both.
      expect(await stored()).toEqual(expect.arrayContaining([threeDays, oneDay]));
      await h.ctx.db
        .update(instanceSettings)
        .set({ value: { analysisReportsDays: 2 } })
        .where(eq(instanceSettings.key, 'retention'));
      await runHousekeeping(h.ctx.db);
      expect(await stored()).not.toContain(threeDays);
      expect(await stored()).toContain(oneDay);
    } finally {
      await h.ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'retention'));
    }
  });

  it('deletes webhook deliveries past retention and keeps the recent ones', async () => {
    const [project] = await h.ctx.db
      .execute<{ organization_id: string }>(
        sql`SELECT organization_id FROM projects WHERE id = ${p.id}`,
      )
      .then((r) => r.rows);
    const [subscription] = await h.ctx.db
      .insert(webhookSubscriptions)
      .values({
        organizationId: project!.organization_id,
        url: 'https://ci.example.test/hook',
        secretEnc: { v: 1, iv: 'x', ct: 'x', tag: 'x' },
        events: ['analysis.completed'],
      })
      .returning();
    const delivery = (daysAgo: number) =>
      h.ctx.db.execute<{ id: string }>(sql`
        INSERT INTO webhook_deliveries (id, subscription_id, event, payload, status, created_at)
        VALUES (gen_random_uuid(), ${subscription!.id}, 'analysis.completed', '{}'::jsonb,
                'succeeded', ${ago(daysAgo)})
        RETURNING id`);
    const old = (await delivery(31)).rows[0]!.id;
    const recent = (await delivery(29)).rows[0]!.id;
    expect((await runHousekeeping(h.ctx.db)).webhookDeliveries).toBe(1);
    const left = (await h.ctx.db.select().from(webhookDeliveries)).map((d) => d.id);
    expect(left).not.toContain(old);
    expect(left).toContain(recent);
  });

  describe('llm_requests (llm.md §10.1)', () => {
    const request = async (daysAgo: number, over: { status?: string; prompt?: unknown } = {}) => {
      const { organization_id } = (
        await h.ctx.db.execute<{ organization_id: string }>(
          sql`SELECT organization_id FROM projects WHERE id = ${p.id}`,
        )
      ).rows[0]!;
      const status = over.status ?? 'succeeded';
      const [row] = await h.ctx.db
        .insert(llmRequests)
        .values({
          organizationId: organization_id,
          projectId: p.id,
          feature: 'explain',
          cacheKey: 'a'.repeat(64),
          provider: 'openai',
          providerHost: 'api.example.com',
          model: 'm',
          promptVersion: 'explain.v1',
          inputSha256: 'b'.repeat(64),
          inputBytes: 10,
          fields: ['rule'],
          status: status as 'succeeded',
          result: status === 'succeeded' ? { kind: 'explain' } : null,
          prompt: over.prompt ?? null,
        })
        .returning();
      await h.ctx.db.execute(
        sql`UPDATE llm_requests SET created_at = ${ago(daysAgo)} WHERE id = ${row!.id}`,
      );
      return row!.id;
    };
    const byId = async (id: string) =>
      (await h.ctx.db.select().from(llmRequests).where(eq(llmRequests.id, id)))[0];

    it('deletes finished requests after 90 days and keeps the recent ones', async () => {
      const old = await request(91);
      const oldFailed = await request(91, { status: 'failed' });
      const recent = await request(89);
      expect((await runHousekeeping(h.ctx.db)).llmRequests).toBe(2);
      expect(await byId(old)).toBeUndefined();
      expect(await byId(oldFailed)).toBeUndefined();
      expect(await byId(recent)).toBeDefined();
    });

    it('deletes a request older than the retention whatever its status: it cannot be in flight', async () => {
      const queued = await request(91, { status: 'queued' });
      const running = await request(91, { status: 'running' });
      const recentQueued = await request(1, { status: 'queued' });
      expect((await runHousekeeping(h.ctx.db)).llmRequests).toBe(2);
      expect(await byId(queued)).toBeUndefined();
      expect(await byId(running)).toBeUndefined();
      expect(await byId(recentQueued)).toBeDefined();
    });

    it('honours llmRequestsDays from the retention setting', async () => {
      const tenDays = await request(10);
      try {
        await h.ctx.db
          .insert(instanceSettings)
          .values({ key: 'retention', value: { llmRequestsDays: 5 } });
        await runHousekeeping(h.ctx.db);
        expect(await byId(tenDays)).toBeUndefined();
      } finally {
        await h.ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'retention'));
      }
    });

    it('clears a stored prompt after promptRetentionDays (default 7) and keeps the row', async () => {
      const prompt = { rule: 'eqeqeq' };
      const eightDays = await request(8, { prompt });
      const sixDays = await request(6, { prompt });
      expect((await runHousekeeping(h.ctx.db)).llmPromptsCleared).toBe(1);
      expect(await byId(eightDays)).toMatchObject({ prompt: null, result: { kind: 'explain' } });
      expect(await byId(sixDays)).toMatchObject({ prompt });
      // The instance admin's setting decides: 3 days clears the 6-day prompt too.
      try {
        await h.ctx.db.insert(instanceSettings).values({
          key: LLM_SETTINGS_KEY,
          value: { ...DEFAULT_LLM_SETTINGS, promptRetentionDays: 3 },
        });
        expect((await runHousekeeping(h.ctx.db)).llmPromptsCleared).toBe(1);
        expect(await byId(sixDays)).toMatchObject({ prompt: null });
      } finally {
        await h.ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, LLM_SETTINGS_KEY));
      }
    });
  });

  it('fails pending webhook deliveries whose next attempt is long overdue and has no job', async () => {
    const [project] = await h.ctx.db
      .execute<{ organization_id: string }>(
        sql`SELECT organization_id FROM projects WHERE id = ${p.id}`,
      )
      .then((r) => r.rows);
    const [subscription] = await h.ctx.db
      .insert(webhookSubscriptions)
      .values({
        organizationId: project!.organization_id,
        url: 'https://ci.example.test/stuck',
        secretEnc: { v: 1, iv: 'x', ct: 'x', tag: 'x' },
        events: ['analysis.completed'],
      })
      .returning();
    const pending = async (overdue: string) =>
      (
        await h.ctx.db.execute<{ id: string }>(sql`
          INSERT INTO webhook_deliveries (id, subscription_id, event, payload, status, attempts,
                                          response_code, next_attempt_at)
          VALUES (gen_random_uuid(), ${subscription!.id}, 'analysis.completed', '{}'::jsonb,
                  'pending', 2, 503, now() - ${overdue}::interval)
          RETURNING id`)
      ).rows[0]!.id;
    // Its job died (every attempt failed on the database): stuck for good.
    const stuck = await pending('2 hours');
    await h.ctx.db.insert(jobs).values({
      queue: WEBHOOK_QUEUE,
      payload: { deliveryId: stuck, attempts: 2 },
      status: 'dead',
    });
    // Overdue but its job is still queued (a busy worker): left alone.
    const queued = await pending('2 hours');
    await h.ctx.db.insert(jobs).values({
      queue: WEBHOOK_QUEUE,
      payload: { deliveryId: queued, attempts: 2 },
    });
    // Due a moment ago, no job visible (a worker about to write it): left alone.
    const recent = await pending('5 minutes');
    expect((await runHousekeeping(h.ctx.db)).stalledWebhookDeliveries).toBe(1);
    const rows = new Map(
      (await h.ctx.db.select().from(webhookDeliveries)).map((d) => [d.id, d] as const),
    );
    expect(rows.get(stuck)).toMatchObject({
      status: 'failed',
      attempts: 2,
      responseCode: 503,
      nextAttemptAt: null,
      responseExcerpt: 'The delivery was abandoned: its next attempt was never run',
    });
    expect(rows.get(queued)!.status).toBe('pending');
    expect(rows.get(recent)!.status).toBe('pending');
  });

  it('never deletes a branch that an analysis refers to, even a failed one', async () => {
    const [b] = await h.ctx.db
      .insert(branches)
      .values({ projectId: p.id, kind: 'branch', name: 'feature/failed-only' })
      .returning();
    await h.ctx.db.execute(sql`UPDATE branches SET created_at = ${ago(31)} WHERE id = ${b!.id}`);
    // A STALE_ANALYSIS rejection records the branch but never sets its last_analysis_id; deleting
    // the branch would cascade to the analysis, which is kept forever (§7).
    await h.ctx.db.insert(analyses).values({
      projectId: p.id,
      branchId: b!.id,
      status: 'failed',
      finishedAt: new Date(),
    });
    expect((await runHousekeeping(h.ctx.db)).branches).toBe(0);
    expect((await h.ctx.db.select().from(branches).where(eq(branches.id, b!.id))).length).toBe(1);
  });

  it('leaves closed issues alone while an ingestion holds their branch, and deletes them after', async () => {
    await p.ingestOk(
      reportWith({
        projectKey: p.key,
        branch: 'feature/locked',
        analysisDate: '2026-09-23T10:00:00Z',
        files: [file('src/a.ts')],
        findings: [finding({ line: 3, ruleId: 'r3' })],
      }),
    );
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, p.id), eq(branches.name, 'feature/locked')));
    await h.ctx.db.execute(sql`
      UPDATE issues SET status = 'closed', closed_at = ${ago(31)} WHERE branch_id = ${branch!.id}`);
    // The ingestion transaction holds its branch row from its upsert until it commits.
    let release!: () => void;
    const released = new Promise<void>((resolve) => (release = resolve));
    let locked!: () => void;
    const isLocked = new Promise<void>((resolve) => (locked = resolve));
    const ingestion = h.ctx.db.transaction(async (tx) => {
      await tx.execute(sql`UPDATE branches SET updated_at = now() WHERE id = ${branch!.id}`);
      locked();
      await released;
    });
    await isLocked;
    try {
      expect((await runHousekeeping(h.ctx.db)).closedIssues).toBe(0);
    } finally {
      release();
      await ingestion;
    }
    expect((await runHousekeeping(h.ctx.db)).closedIssues).toBe(1);
  });

  it('keeps a dead analysis job until its analysis is reconciled, and deletes in batches', async () => {
    const [live] = await h.ctx.db
      .insert(analyses)
      .values({ projectId: p.id, status: 'processing' })
      .returning();
    await h.ctx.db.execute(sql`
      INSERT INTO jobs (id, queue, payload, status, updated_at) VALUES
        (gen_random_uuid(), 'analysis', ${JSON.stringify({ analysisId: live!.id })}::jsonb,
         'dead', ${ago(8)}),
        (gen_random_uuid(), 'analysis', '{"analysisId":"not-a-uuid"}'::jsonb, 'dead', ${ago(8)})`);
    // More expired sessions than one DELETE batch takes.
    await h.ctx.db.execute(sql`
      INSERT INTO sessions (id, user_id, expires_at)
      SELECT decode(lpad(to_hex(g), 8, '0'), 'hex'), ${h.ctx.adminId}, now() - interval '1 day'
        FROM generate_series(1, 12001) AS g`);
    const result = await runHousekeeping(h.ctx.db);
    expect(result).toMatchObject({ jobs: 1, sessions: 12_001 });
    const kept = await h.ctx.db.execute<{ n: number }>(sql`
      SELECT count(*)::int AS n FROM jobs WHERE payload ->> 'analysisId' = ${live!.id}`);
    expect(kept.rows).toEqual([{ n: 1 }]);
  });

  it('prunes expired SSO flow state and keeps live flows (sso-scim.md §7.1)', async () => {
    const connectionId = uuidv7();
    await h.ctx.db.execute(sql`
      INSERT INTO sso_connections (id, name, protocol, config)
      VALUES (${connectionId}, 'housekeeping', 'oidc', '{}')`);
    await h.ctx.db.execute(sql`
      INSERT INTO sso_states (key, kind, connection_id, expires_at) VALUES
        ('oidc:expired', 'oidc', ${connectionId}, now() - interval '1 minute'),
        ('finish:expired', 'finish', ${connectionId}, now() - interval '1 second'),
        ('oidc:live', 'oidc', ${connectionId}, now() + interval '10 minutes')`);
    expect((await runHousekeeping(h.ctx.db)).ssoStates).toBe(2);
    const left = await h.ctx.db.execute<{ key: string }>(sql`
      SELECT key FROM sso_states WHERE connection_id = ${connectionId}`);
    expect(left.rows).toEqual([{ key: 'oidc:live' }]);
    expect((await runHousekeeping(h.ctx.db)).ssoStates).toBe(0);
  });

  it('keeps exactly one run scheduled, however many replicas ask at once', async () => {
    const created = await Promise.all(
      Array.from({ length: 5 }, () => ensureHousekeepingScheduled(h.ctx.db)),
    );
    expect(created.filter(Boolean)).toHaveLength(1);
    expect(await housekeepingJobs()).toHaveLength(1);
  });

  it('runs due work and schedules the next run a day later', async () => {
    await ensureHousekeepingScheduled(h.ctx.db);
    expect(
      await runUntilIdle(h.ctx.db, housekeepingHandlers({ db: h.ctx.db }), h.ctx.app.log),
    ).toBe(1);
    const rows = await housekeepingJobs();
    expect(rows.map((r) => r.status).sort()).toEqual(['queued', 'succeeded']);
    const next = await h.ctx.db.execute<{ later: boolean }>(sql`
      SELECT run_at > now() + interval '23 hours' AS later
        FROM jobs WHERE queue = ${HOUSEKEEPING_QUEUE} AND status = 'queued'`);
    expect(next.rows).toEqual([{ later: true }]);
  });

  it('waits an hour after a dead housekeeping job before scheduling the next run (no retry storm)', async () => {
    const runIn = async () =>
      (
        await h.ctx.db.execute<{ minutes: number }>(sql`
          SELECT round(extract(epoch FROM run_at - now()) / 60)::int AS minutes
            FROM jobs WHERE queue = ${HOUSEKEEPING_QUEUE} AND status = 'queued'`)
      ).rows.map((r) => r.minutes);
    const deadJob = (minutesAgo: number) =>
      h.ctx.db.execute(sql`
        INSERT INTO jobs (id, queue, concurrency_key, payload, status, updated_at)
        VALUES (${uuidv7()}, ${HOUSEKEEPING_QUEUE}, ${HOUSEKEEPING_QUEUE}, '{}'::jsonb, 'dead',
                now() - make_interval(mins => ${minutesAgo}))`);

    // Died 10 minutes ago: the next run is 50 minutes away, however often a reap asks.
    await deadJob(10);
    expect(await ensureHousekeepingScheduled(h.ctx.db)).toBe(true);
    expect(await ensureHousekeepingScheduled(h.ctx.db)).toBe(false);
    expect(await runIn()).toEqual([50]);

    // Died 2 hours ago: run now.
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, HOUSEKEEPING_QUEUE));
    await deadJob(120);
    await ensureHousekeepingScheduled(h.ctx.db);
    expect(await runIn()).toEqual([0]);

    // A later job that succeeded: the older dead one no longer delays anything.
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, HOUSEKEEPING_QUEUE));
    await deadJob(10);
    await h.ctx.db.execute(sql`
      INSERT INTO jobs (id, queue, concurrency_key, payload, status, updated_at)
      VALUES (${uuidv7()}, ${HOUSEKEEPING_QUEUE}, ${HOUSEKEEPING_QUEUE}, '{}'::jsonb, 'succeeded',
              now() - interval '5 minutes')`);
    await ensureHousekeepingScheduled(h.ctx.db);
    expect(await runIn()).toEqual([0]);
  });
});
