import { eq } from 'drizzle-orm';
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
      const failing = {
        ...deps(),
        runtime: undefined as never,
        scm: undefined as never,
      } satisfies AzurePollDeps;
      await expect(azurePollHandlers(failing)[AZURE_POLL_QUEUE]!(job)).resolves.toBeUndefined();
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
