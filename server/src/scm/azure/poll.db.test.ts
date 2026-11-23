import { eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { azureServerConfig, servicesUrlOf, AZURE_TEST_PRINCIPAL } from '../../../test/azure';
import { createFakeAzureDevOps, type FakeAzureDevOps } from '../../../test/fake-azure-devops';
import { createFakeGitHub, type FakeGitHub } from '../../../test/fake-github';
import { createFakeLlm, type FakeLlm } from '../../../test/fake-llm';
import { githubConnection } from '../../../test/github';
import { createIngestHarness, type IngestHarness } from '../../../test/ingest';
import { reviewOn, reviewOff } from '../../../test/replies';
import { PUBLIC_URL } from '../../../test/scm';
import { trustTestCa } from '../../../test/tls';
import { first } from '../../db/rows';
import { analyses, branches, jobs, projects, reviewRuns, scmConnections } from '../../db/schema';
import { createScmRuntime } from '../runtime';
import {
  AZURE_POLL_INTERVAL_SECONDS,
  AZURE_POLL_QUEUE,
  MAX_POLLED_BRANCHES,
  azurePollHandlers,
  azurePollKey,
  ensureAzurePollScheduled,
  runAzurePass,
  type AzurePollDeps,
} from './poll';

/*
 * The backstop pass of an Azure DevOps connection (sub-plan 5, task 9): reply scans for recent
 * AI-reviewed pull requests, and the state of Qualor's service hooks recorded as the connection's
 * background problem.
 */

const DAY = 86_400_000;

describe('the Azure DevOps backstop pass (sub-plan 5, task 9)', () => {
  let untrust: () => void;
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let github: FakeGitHub;
  let llm: FakeLlm;
  let connectionId: string;
  let projectSeq = 0;

  const deps = (over: Partial<AzurePollDeps> = {}): AzurePollDeps => ({
    db: h.ctx.db,
    scm: {
      secretKey: h.ctx.config.secretKey,
      internalHosts: h.ctx.config.scmInternalHosts,
      azureTokenOrigin: h.ctx.config.azureTokenOrigin,
      azureTestOrigin: h.ctx.config.azureTestOrigin,
      clientOptions: { timeoutMs: 2_000 },
      githubClientOptions: { timeoutMs: 2_000 },
    },
    runtime: createScmRuntime(),
    publicUrl: PUBLIC_URL,
    logger: h.ctx.app.log,
    ...over,
  });
  const call = (method: 'POST' | 'GET', url: string) =>
    h.ctx.app.inject({ method, url: `/api/v0${url}`, headers: h.orgAdmin.headers });
  const connect = async () => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'azure',
        baseUrl: servicesUrlOf(fake),
        azureAuth: 'pat',
        token: fake.pat,
      },
    });
    expect(res.statusCode, res.body).toBe(201);
    return (res.json() as { id: string }).id;
  };
  /** A project mapped to the connection's first repository. */
  const mapped = async (connection = connectionId) => {
    projectSeq += 1;
    const project = await h.project(`poll/p${projectSeq}`);
    await h.ctx.db
      .update(projects)
      .set({ scmConnectionId: connection, scmProjectRef: fake.repositories[0]!.id })
      .where(eq(projects.id, project.id));
    return project.id;
  };
  /** A pull request branch whose analysis is `ageDays` old and whose review run is `status`. */
  const branchWithReview = async (
    projectId: string,
    name: string,
    ageDays: number,
    status: 'done' | 'failed' = 'done',
    kind: 'merge_request' | 'branch' = 'merge_request',
  ) => {
    const db = h.ctx.db;
    const at = new Date(Date.now() - ageDays * DAY);
    const branch = first(await db.insert(branches).values({ projectId, kind, name }).returning());
    const analysis = first(
      await db
        .insert(analyses)
        .values({
          projectId,
          branchId: branch.id,
          status: 'succeeded',
          revision: 'a'.repeat(40),
          analysisDate: at,
          baselineStatus: 'ok',
          scannerVersion: '1.0.0',
          createdAt: at,
        })
        .returning(),
    );
    await db.insert(reviewRuns).values({
      projectId,
      branchId: branch.id,
      analysisId: analysis.id,
      status,
      ...(status === 'failed' ? { reason: 'internal' as const } : {}),
      deadlineAt: at,
    });
    return branch.id;
  };
  const scanned = async () =>
    (await h.ctx.db.select().from(jobs))
      .filter((j) => j.queue === 'ai-reply' && (j.payload as { kind?: string }).kind === 'scan')
      .map((j) => (j.payload as { branchId: string }).branchId)
      .sort();
  const problemOf = async () =>
    first(await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, connectionId)))
      .problem;
  /** Qualor's two subscriptions in the fake, made by the settings route. */
  const subscribe = async () => {
    const secret = await call('POST', `/scm-connections/${connectionId}/azure-hooks/secret`);
    expect(secret.statusCode).toBe(200);
    const res = await call('POST', `/scm-connections/${connectionId}/azure-hooks`);
    expect(res.statusCode, res.body).toBe(200);
  };

  beforeAll(async () => {
    untrust = trustTestCa();
    fake = await createFakeAzureDevOps({
      deployment: 'services',
      principal: AZURE_TEST_PRINCIPAL,
      repositories: [{ name: 'api', projectName: 'Payments' }],
    });
    github = await createFakeGitHub();
    llm = await createFakeLlm();
    h = await createIngestHarness({
      config: {
        ...azureServerConfig(fake),
        scmInternalHosts: new Set([new URL(fake.url).host, new URL(github.url).host]),
        publicUrl: PUBLIC_URL,
      },
    });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
    await github.close();
    await llm.close();
    untrust();
  });
  afterEach(async () => {
    await h.ctx.db.delete(jobs);
    await h.ctx.db.delete(scmConnections);
    await h.ctx.db.delete(projects);
    (fake.subscriptions as unknown[]).length = 0;
    fake.clearRequests();
  });

  const start = async () => {
    await reviewOn(h, llm);
    connectionId = await connect();
  };

  describe('the scans of the candidates', () => {
    it('queues a scan for a done review within 30 days, and for no older review, failed run, branch or review-off project', async () => {
      await start();
      const p = await mapped();
      const recent = await branchWithReview(p, '11', 29);
      await branchWithReview(p, '12', 31);
      await branchWithReview(p, '13', 1, 'failed');
      await branchWithReview(p, 'feature', 1, 'done', 'branch');
      await runAzurePass(deps(), connectionId);
      expect(await scanned()).toEqual([recent]);
      await h.ctx.db.delete(jobs);
      await reviewOff(h);
      await runAzurePass(deps(), connectionId);
      expect(await scanned()).toEqual([]);
    });

    it('queues the 50 newest of 60 candidates', async () => {
      await start();
      const p = await mapped();
      const ids: string[] = [];
      for (let i = 0; i < 60; i += 1) ids.push(await branchWithReview(p, String(100 + i), i / 3));
      await runAzurePass(deps(), connectionId);
      expect(MAX_POLLED_BRANCHES).toBe(50);
      expect(await scanned()).toEqual(ids.slice(0, 50).sort());
    });

    it('limits the candidate query itself to 50 rows and reads none without an active project', async () => {
      await start();
      const p = await mapped();
      for (let i = 0; i < 60; i += 1) await branchWithReview(p, String(300 + i), i / 3);
      const queries: string[] = [];
      const spy = new Proxy(h.ctx.db, {
        get: (target, key, receiver) =>
          key === 'select'
            ? (...args: unknown[]) => {
                const query = (target.select as (...a: unknown[]) => { from: unknown })(...args);
                queries.push('select');
                return query;
              }
            : Reflect.get(target, key, receiver),
      });
      // The candidate statement's own row count, read off the pool's answer.
      const pool = (h.ctx.db as unknown as { $client: { query: (...a: unknown[]) => unknown } })
        .$client;
      const original = pool.query.bind(pool);
      const counts: number[] = [];
      pool.query = (...args: unknown[]) => {
        const result = original(...args) as Promise<{ rowCount: number }>;
        const text =
          typeof args[0] === 'string' ? args[0] : ((args[0] as { text?: string })?.text ?? '');
        if (text.includes('"review_runs"') && text.includes('group by')) {
          void result.then((r) => counts.push(r.rowCount));
        }
        return result;
      };
      try {
        await runAzurePass(deps({ db: spy }), connectionId);
      } finally {
        pool.query = original;
      }
      expect(counts).toEqual([50]);
      expect(await scanned()).toHaveLength(50);
      const withCandidates = queries.length;
      queries.length = 0;
      await h.ctx.db.delete(jobs);
      await reviewOff(h);
      await runAzurePass(deps({ db: spy }), connectionId);
      // The candidate query is the one read less when no project has AI review active.
      expect(withCandidates - queries.length).toBe(1);
      expect(await scanned()).toEqual([]);
    });

    it('one failing scan does not skip the other candidates', async () => {
      await start();
      const p = await mapped();
      const ids = [await branchWithReview(p, '51', 1), await branchWithReview(p, '52', 2)];
      const warnings: unknown[] = [];
      const logger = {
        info: () => undefined,
        error: () => undefined,
        warn: (o: unknown) => warnings.push(o),
      };
      // The newest candidate's scan fails: its branch row is locked out by a failing insert.
      await h.ctx.db.execute(
        sql.raw(
          `CREATE OR REPLACE FUNCTION poll_fail() RETURNS trigger AS $$ BEGIN IF NEW.payload->>'branchId' = '${ids[0]}' THEN RAISE EXCEPTION 'no'; END IF; RETURN NEW; END $$ LANGUAGE plpgsql`,
        ),
      );
      await h.ctx.db.execute(
        sql`CREATE TRIGGER poll_fail BEFORE INSERT ON jobs FOR EACH ROW EXECUTE FUNCTION poll_fail()`,
      );
      try {
        await runAzurePass(deps({ logger }), connectionId);
      } finally {
        await h.ctx.db.execute(sql`DROP TRIGGER poll_fail ON jobs`);
        await h.ctx.db.execute(sql`DROP FUNCTION poll_fail()`);
      }
      expect(await scanned()).toEqual([ids[1]!]);
      expect(warnings).toEqual([{ connectionId, branchId: ids[0] }]);
    });

    it('leaves the pull requests of another connection alone', async () => {
      await start();
      const other = await connect();
      const p = await mapped(other);
      await branchWithReview(p, '21', 1);
      await runAzurePass(deps(), connectionId);
      expect(await scanned()).toEqual([]);
    });

    it('queues scans without a public URL, and reads no subscriptions', async () => {
      await start();
      const p = await mapped();
      const b = await branchWithReview(p, '31', 1);
      await runAzurePass(deps({ publicUrl: null }), connectionId);
      expect(await scanned()).toEqual([b]);
      expect(fake.requests.filter((r) => r.path.includes('/hooks/'))).toEqual([]);
    });
  });

  describe('the hook problems', () => {
    const SEEDED = { code: 'token_refused' as const, at: '2026-11-20T10:00:00.000Z' };

    it('records hook_probation, then hook_disabled, and clears them when all are enabled', async () => {
      await start();
      await mapped();
      await subscribe();
      await runAzurePass(deps(), connectionId);
      expect(await problemOf()).toBeNull();
      fake.setSubscriptionStatus(fake.subscriptions[0]!.id, 'onProbation');
      await runAzurePass(deps(), connectionId);
      expect(await problemOf()).toMatchObject({ code: 'hook_probation' });
      fake.setSubscriptionStatus(fake.subscriptions[1]!.id, 'disabledBySystem');
      await runAzurePass(deps(), connectionId);
      expect(await problemOf()).toMatchObject({ code: 'hook_disabled' });
      for (const s of fake.subscriptions) fake.setSubscriptionStatus(s.id, 'enabled');
      await runAzurePass(deps(), connectionId);
      expect(await problemOf()).toBeNull();
    });

    it('records nothing without an own subscription, and leaves another problem as it was', async () => {
      await start();
      await mapped();
      await runAzurePass(deps(), connectionId);
      expect(await problemOf()).toBeNull();
      await h.ctx.db.update(scmConnections).set({ problem: SEEDED });
      await runAzurePass(deps(), connectionId);
      expect(await problemOf()).toEqual(SEEDED);
    });

    it('never overwrites a credential problem with a hook code, and keeps it when hooks are fine', async () => {
      await start();
      await mapped();
      await subscribe();
      await h.ctx.db.update(scmConnections).set({ problem: SEEDED });
      fake.setSubscriptionStatus(fake.subscriptions[0]!.id, 'disabledBySystem');
      await runAzurePass(deps(), connectionId);
      expect(await problemOf()).toEqual(SEEDED);
      fake.setSubscriptionStatus(fake.subscriptions[0]!.id, 'enabled');
      await runAzurePass(deps(), connectionId);
      expect(await problemOf()).toEqual(SEEDED);
    });

    it('records nothing when reading the subscriptions fails, and still queues the scans', async () => {
      await start();
      const p = await mapped();
      const b = await branchWithReview(p, '41', 1);
      await subscribe();
      fake.setSubscriptionStatus(fake.subscriptions[0]!.id, 'onProbation');
      await runAzurePass(deps(), connectionId);
      expect(await problemOf()).toMatchObject({ code: 'hook_probation' });
      await h.ctx.db.delete(jobs);
      fake.inject('GET', /\/hooks\/subscriptions/, { status: 401, body: {} });
      await runAzurePass(deps(), connectionId);
      expect(await problemOf()).toMatchObject({ code: 'hook_probation' });
      expect(await scanned()).toEqual([b]);
    });
  });

  describe('the schedule', () => {
    const passJobs = async () =>
      (await h.ctx.db.select().from(jobs)).filter((j) => j.queue === AZURE_POLL_QUEUE);

    it('queues one pass per Azure connection with a mapped project, none for GitHub or an unmapped one', async () => {
      await start();
      await mapped();
      await connect();
      await githubConnection(h, github);
      expect(await ensureAzurePollScheduled(h.ctx.db)).toBe(1);
      const queued = await passJobs();
      expect(queued).toHaveLength(1);
      expect(queued[0]).toMatchObject({
        concurrencyKey: azurePollKey(connectionId),
        payload: { connectionId },
      });
      expect(azurePollKey(connectionId)).toBe(`azure-poll:${connectionId}`);
      expect(await ensureAzurePollScheduled(h.ctx.db)).toBe(0);
    });

    it('queues the next pass 900 seconds later, also when the pass fails', async () => {
      await start();
      await mapped();
      const handler = azurePollHandlers(deps())[AZURE_POLL_QUEUE]!;
      const job = { payload: { connectionId } } as Parameters<typeof handler>[0];
      await handler(job);
      const [next] = await passJobs();
      expect(next).toBeDefined();
      const delay = (next!.runAt.getTime() - Date.now()) / 1000;
      expect(AZURE_POLL_INTERVAL_SECONDS).toBe(900);
      expect(delay).toBeGreaterThan(880);
      expect(delay).toBeLessThanOrEqual(901);
      await h.ctx.db.delete(jobs);
      // The pass itself rejects: its second read of the database (the candidates) throws.
      let reads = 0;
      const failing = new Proxy(h.ctx.db, {
        get: (target, key, receiver) =>
          key === 'select'
            ? (...args: unknown[]) => {
                reads += 1;
                if (reads > 1) throw new Error('boom');
                return (target.select as (...a: unknown[]) => unknown)(...args);
              }
            : Reflect.get(target, key, receiver),
      });
      await expect(
        azurePollHandlers(deps({ db: failing }))[AZURE_POLL_QUEUE]!(job),
      ).rejects.toThrow('boom');
      expect(await passJobs()).toHaveLength(1);
    });

    it('queues no next pass once the connection has no mapped project', async () => {
      await start();
      const handler = azurePollHandlers(deps())[AZURE_POLL_QUEUE]!;
      await handler({ payload: { connectionId } } as Parameters<typeof handler>[0]);
      expect(await passJobs()).toEqual([]);
    });
  });
});
