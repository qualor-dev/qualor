import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { encryptionKey, encryptSecret } from '../crypto/secrets';
import { jiraConnections, jobs, organizations } from '../db/schema';
import { JIRA_TOKEN_AAD } from './connection';
import {
  enqueueJiraCreate,
  ensureJiraSyncScheduled,
  JIRA_QUEUE,
  JIRA_SYNC_INTERVAL_SECONDS,
  jiraCreateKey,
  jiraSyncKey,
  scheduleJiraSync,
  syncJiraNow,
} from './jobs';

describe('the Jira job schedule', () => {
  let h: IngestHarness;
  let orgs: string[];

  const connect = async (organizationId: string) => {
    await h.ctx.db.insert(jiraConnections).values({
      organizationId,
      deployment: 'data_center',
      siteUrl: 'https://jira.example.com',
      tokenEnc: encryptSecret(encryptionKey(h.ctx.config.secretKey), 'tok', JIRA_TOKEN_AAD),
    });
  };
  const queued = (organizationId: string, kind: 'create' | 'sync') =>
    h.ctx.db
      .select()
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, JIRA_QUEUE),
          eq(jobs.status, 'queued'),
          eq(
            jobs.concurrencyKey,
            kind === 'sync' ? jiraSyncKey(organizationId) : jiraCreateKey(organizationId),
          ),
        ),
      );

  beforeAll(async () => {
    h = await createIngestHarness();
    const [second] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'second', name: 'Second' })
      .returning({ id: organizations.id });
    orgs = [h.organizationId, second!.id];
    for (const o of orgs) await connect(o);
  });
  afterAll(async () => {
    await h.close();
  });

  it('queues one pass per connection when two replicas boot at once', async () => {
    const counts = await Promise.all([
      ensureJiraSyncScheduled(h.ctx.db),
      ensureJiraSyncScheduled(h.ctx.db),
    ]);
    expect(counts.reduce((a, b) => a + b, 0)).toBe(2);
    for (const o of orgs) {
      const rows = await queued(o, 'sync');
      expect(rows).toHaveLength(1);
      expect(rows[0]?.payload).toEqual({ kind: 'sync', organizationId: o });
    }
    expect(await ensureJiraSyncScheduled(h.ctx.db)).toBe(0);
  });

  it('skips a connection whose pass is running, while the pass may queue its successor', async () => {
    const org = orgs[0]!;
    await h.ctx.db.execute(
      sql`UPDATE jobs SET status = 'running', locked_by = 'w', locked_until = now() + interval '1 minute'
           WHERE concurrency_key = ${jiraSyncKey(org)}`,
    );
    expect(await ensureJiraSyncScheduled(h.ctx.db)).toBe(0);
    // Ruling P1: the running pass reschedules itself from its own finally.
    expect(await scheduleJiraSync(h.ctx.db, org, JIRA_SYNC_INTERVAL_SECONDS)).toBe(true);
    expect(await scheduleJiraSync(h.ctx.db, org, JIRA_SYNC_INTERVAL_SECONDS)).toBe(false);
    expect(await queued(org, 'sync')).toHaveLength(1);
    await h.ctx.db.execute(
      sql`DELETE FROM jobs WHERE concurrency_key = ${jiraSyncKey(org)} AND status = 'running'`,
    );
  });

  it('queues one create job at a time, under a key of its own', async () => {
    const org = orgs[0]!;
    const results = await Promise.all([
      enqueueJiraCreate(h.ctx.db, org),
      enqueueJiraCreate(h.ctx.db, org),
    ]);
    expect(results.filter(Boolean)).toHaveLength(1);
    expect(await enqueueJiraCreate(h.ctx.db, org)).toBe(false);
    const rows = await queued(org, 'create');
    expect(rows).toHaveLength(1);
    expect(rows[0]?.payload).toEqual({ kind: 'create', organizationId: org });
    // The pass waiting under its own key does not hold the create back.
    expect(await queued(org, 'sync')).toHaveLength(1);
  });

  it('moves a pass due in 15 minutes to now, or queues one', async () => {
    const org = orgs[1]!;
    await h.ctx.db.execute(
      sql`UPDATE jobs SET run_at = now() + interval '15 minutes' WHERE concurrency_key = ${jiraSyncKey(org)}`,
    );
    await syncJiraNow(h.ctx.db, org);
    const [moved] = await queued(org, 'sync');
    expect(moved!.runAt.getTime()).toBeLessThanOrEqual(Date.now() + 60_000);
    expect(await queued(org, 'sync')).toHaveLength(1);
    await h.ctx.db.execute(sql`DELETE FROM jobs WHERE concurrency_key = ${jiraSyncKey(org)}`);
    await syncJiraNow(h.ctx.db, org);
    expect(await queued(org, 'sync')).toHaveLength(1);
  });
});
