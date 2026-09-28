import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { finding, reportWith } from '../../test/reports';
import type { Db } from '../db/client';
import { analyses, issues, rules } from '../db/schema';
import { type IngestionStage } from '../ingest/process';
import { DEFAULT_STAGES } from '../ingest/stages';
import { removeBareRules } from '../routes/profiles';
import { rulesStage } from './stage';

/** A promise and the function that resolves it: a barrier the test controls. */
function barrier(): { promise: Promise<void>; open: () => void } {
  let open: (() => void) | undefined;
  const promise = new Promise<void>((resolve) => {
    open = resolve;
  });
  return { promise, open: () => open?.() };
}

/** Resolves once another backend of this database waits on a lock (a barrier on the database). */
async function someoneWaitsOnLock(
  db: Db,
  until: { done: boolean },
): Promise<'waiting' | 'stopped'> {
  while (!until.done) {
    const result = await db.execute<{ n: number }>(sql`
      SELECT count(*)::int AS n FROM pg_stat_activity
       WHERE datname = current_database() AND wait_event_type = 'Lock'
         AND pid <> pg_backend_pid()`);
    if ((result.rows[0]?.n ?? 0) > 0) return 'waiting';
    await new Promise((resolve) => setImmediate(resolve));
  }
  return 'stopped';
}

/**
 * Follow-up to the E1 wave: a bare rule deleted by a profile change (removeBareRules) must never
 * fail an in-flight ingestion that references it, whichever of the two locks first.
 */
describe('bare-rule cleanup racing an ingestion', () => {
  let h: IngestHarness;
  let project: IngestProject;
  let profileId: string;
  let day = 1;

  const call = (method: 'POST' | 'PUT' | 'DELETE', url: string, payload?: unknown) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: h.orgAdmin.headers,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const report = (ruleId: string) => {
    day += 1;
    return reportWith({
      projectKey: project.key,
      analysisDate: `2026-08-${String(day).padStart(2, '0')}T10:00:00Z`,
      findings: [finding({ ruleId, line: day })],
    });
  };
  const ruleRow = async (key: string) =>
    (await h.ctx.db.select().from(rules).where(eq(rules.key, key)))[0];
  const issuesOf = async (analysisId: string, key: string) => {
    const [analysis] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    const rule = await ruleRow(key);
    return h.ctx.db
      .select()
      .from(issues)
      .where(and(eq(issues.branchId, analysis!.branchId!), eq(issues.ruleId, rule!.id)));
  };

  beforeAll(async () => {
    h = await createIngestHarness();
    project = await h.project('acme/cleanup-race');
    const res = await call('POST', '/quality-profiles', {
      organizationId: h.organizationId,
      name: 'Race profile',
      language: '*',
    });
    expect(res.statusCode, res.body).toBe(201);
    profileId = (res.json() as { id: string }).id;
  });
  afterAll(async () => {
    await h.close();
  });

  it('the cleanup runs while the ingestion is between the rule lookup and the issue insert', async () => {
    const key = 'eslint:race-after-lookup';
    // A bare rule only a profile sets (ruling X5).
    const put = await call('PUT', `/quality-profiles/${profileId}/rules/${key}`, { active: true });
    expect(put.statusCode, put.body).toBe(200);
    const looked = barrier();
    const resume = barrier();
    const pause: IngestionStage = {
      name: 'pause',
      async run() {
        looked.open();
        await resume.promise;
      },
    };
    const stages = [rulesStage, pause, ...DEFAULT_STAGES.filter((stage) => stage !== rulesStage)];
    const ingesting = project.ingest(report('race-after-lookup'), stages);
    await looked.promise;
    // The profile drops the rule; the cleanup must leave the rule the ingestion now holds.
    const removed = await call('DELETE', `/quality-profiles/${profileId}/rules/${key}`);
    expect(removed.statusCode).toBe(204);
    resume.open();
    const analysisId = await ingesting;
    const [analysis] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    expect(analysis!.status, JSON.stringify(analysis!.error)).toBe('succeeded');
    expect(await issuesOf(analysisId, key)).toHaveLength(1);
  });

  it('the cleanup holds the rule first: the ingestion waits, re-creates the rule and succeeds', async () => {
    const key = 'eslint:race-before-lookup';
    const [bare] = await h.ctx.db
      .insert(rules)
      .values({
        key,
        engineId: 'eslint',
        engineRuleId: 'race-before-lookup',
        name: 'race-before-lookup',
        defaultSeverity: 'medium',
        quality: 'maintainability',
        kind: 'issue',
        origin: 'reported',
      })
      .returning();
    let ingesting: Promise<string> | undefined;
    await h.ctx.db.transaction(async (tx) => {
      // The cleanup's first step: the rule locked FOR UPDATE.
      await tx.execute(sql`SELECT id FROM rules WHERE id = ${bare!.id} FOR UPDATE`);
      ingesting = project.ingest(report('race-before-lookup'));
      const until = { done: false };
      const first = await Promise.race([
        ingesting.then(() => 'ingested' as const),
        someoneWaitsOnLock(h.ctx.db, until),
      ]);
      until.done = true;
      expect(first).toBe('waiting');
      // Then it deletes the rule and commits while the ingestion waits.
      await removeBareRules(tx, [bare!.id]);
      expect((await tx.select().from(rules).where(eq(rules.id, bare!.id))).length).toBe(0);
    });
    const analysisId = await ingesting!;
    const [analysis] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    expect(analysis!.status, JSON.stringify(analysis!.error)).toBe('succeeded');
    const recreated = await ruleRow(key);
    expect(recreated).toBeDefined();
    expect(recreated!.id).not.toBe(bare!.id);
    expect(await issuesOf(analysisId, key)).toHaveLength(1);
  });
});
