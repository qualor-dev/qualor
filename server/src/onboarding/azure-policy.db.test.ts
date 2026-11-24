import { and, eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  createFakeAzureDevOps,
  type FakeAzureDevOps,
  type FakeAzureRepository,
} from '../../test/fake-azure-devops';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { reportWith } from '../../test/reports';
import { decorationDeps, silentLogger } from '../../test/scm';
import { jobs, projects, repositorySetupItems, repositorySetupRuns } from '../db/schema';
import { runUntilIdle } from '../queue/worker';
import { parseInternalHosts } from '../scm/url';
import { AZURE_POLICY_QUEUE, AZURE_POLICY_TEXT, azurePolicyHandlers } from './azure-policy';

describe('the deferred Build validation policy (Azure sub-plan 7, task 7)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let connectionId: string;
  let day = 1;
  let repoNumber = 1;

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({ deployment: 'server' });
    h = await createIngestHarness({
      config: { scmInternalHosts: parseInternalHosts(new URL(fake.url).host) },
    });
    const created = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'azure',
        baseUrl: fake.url,
        azureAuth: 'pat',
        token: fake.pat,
      },
    });
    expect(created.statusCode, created.body).toBe(201);
    connectionId = (created.json() as { id: string }).id;
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(() => fake.clearRequests());

  /** A project mapped to a repository with Qualor's pipeline and pending setup items. */
  const setup = async (key: string, pipelines: (number | 'new')[] = ['new']) => {
    const repository: FakeAzureRepository = fake.addRepository({
      name: `r${repoNumber++}`,
      projectName: 'Payments',
    });
    const project = await h.project(key);
    await h.ctx.db
      .update(projects)
      .set({ scmConnectionId: connectionId, scmProjectRef: repository.id })
      .where(eq(projects.id, project.id));
    const definitions = pipelines.map((p) =>
      p === 'new'
        ? fake.addDefinition(repository.id, { name: `Qualor ${repoNumber}-${day++}` }).id
        : p,
    );
    const items: { runId: string; position: number }[] = [];
    for (const [i, pipelineId] of definitions.entries()) {
      const [run] = await h.ctx.db
        .insert(repositorySetupRuns)
        .values({
          organizationId: h.organizationId,
          connectionId,
          ciSetup: true,
          // Later runs are newer.
          createdAt: new Date(Date.UTC(2026, 10, 1, 10, i)),
        })
        .returning();
      await h.ctx.db.insert(repositorySetupItems).values({
        runId: run!.id,
        position: 0,
        repositoryRef: repository.id,
        repositoryName: repository.name,
        projectId: project.id,
        azurePipelineId: pipelineId,
        azureQueue: 'authorized',
        azurePolicy: 'pending',
      });
      items.push({ runId: run!.id, position: 0 });
    }
    return { project, repository, definitions, items };
  };

  const stateOf = async (item: { runId: string; position: number }) => {
    const [row] = await h.ctx.db
      .select({
        policy: repositorySetupItems.azurePolicy,
        error: repositorySetupItems.azurePolicyError,
      })
      .from(repositorySetupItems)
      .where(
        and(
          eq(repositorySetupItems.runId, item.runId),
          eq(repositorySetupItems.position, item.position),
        ),
      );
    return row!;
  };

  const ingest = (
    s: Awaited<ReturnType<typeof setup>>,
    options: { branch?: string; pullRequest?: boolean } = {},
  ) => {
    const branch = options.branch ?? 'main';
    const report = reportWith({
      projectKey: s.project.key,
      branch,
      ...(options.pullRequest
        ? { mergeRequest: { id: '5', targetBranch: 'main', sourceBranch: branch } }
        : {}),
      revision: 'c'.repeat(40),
      analysisDate: new Date(Date.UTC(2026, 10, 2, 10) + 86_400_000 * day++).toISOString(),
    });
    return s.project.ingestOk({
      ...report,
      scm: { ...report.scm, provider: 'azure', azure: { repositoryId: s.repository.id } },
    });
  };

  const queued = (projectId: string) =>
    h.ctx.db
      .select()
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, AZURE_POLICY_QUEUE),
          sql`${jobs.payload} ->> 'projectId' = ${projectId}`,
          eq(jobs.status, 'queued'),
        ),
      );

  const runJobs = async () => {
    await h.ctx.db
      .update(jobs)
      .set({ runAt: sql`now()` })
      .where(eq(jobs.queue, AZURE_POLICY_QUEUE));
    await runUntilIdle(h.ctx.db, azurePolicyHandlers(decorationDeps(h)), silentLogger);
  };

  it('queues the job once for a main-branch analysis, not for a branch or a pull request, nor after it is on', async () => {
    const s = await setup('policy/queue');
    await ingest(s, { branch: 'feature/x' });
    await ingest(s, { branch: 'feature/y', pullRequest: true });
    expect(await queued(s.project.id)).toEqual([]);

    await ingest(s);
    const jobsQueued = await queued(s.project.id);
    expect(jobsQueued).toHaveLength(1);
    expect(jobsQueued[0]).toMatchObject({
      concurrencyKey: `azure-policy:${s.project.id}`,
      payload: { projectId: s.project.id },
    });

    await runJobs();
    expect(await stateOf(s.items[0]!)).toEqual({ policy: 'on', error: null });
    await ingest(s);
    expect(await queued(s.project.id)).toEqual([]);
  });

  it('creates a non-blocking policy with the exact settings', async () => {
    const s = await setup('policy/create');
    await ingest(s);
    await runJobs();
    const policy = fake.policies.find((p) => JSON.stringify(p.settings).includes(s.repository.id));
    expect(policy).toMatchObject({
      isEnabled: true,
      isBlocking: false,
      type: '0609b952-1397-4640-95ec-e00a01b2c241',
      settings: {
        buildDefinitionId: s.definitions[0],
        queueOnSourceUpdateOnly: false,
        manualQueueOnly: false,
        displayName: 'Qualor',
        validDuration: 0,
        scope: [{ repositoryId: s.repository.id, refName: 'refs/heads/main', matchKind: 'Exact' }],
      },
    });
    expect(await stateOf(s.items[0]!)).toEqual({ policy: 'on', error: null });
  });

  it('adopts an equal existing policy and leaves a blocking one alone', async () => {
    const s = await setup('policy/adopt');
    await ingest(s);
    await runJobs();
    const before = fake.policies.length;

    const again = await setup('policy/adopt-2');
    // The same pipeline and branch already carry a policy (made by a person, blocking).
    await h.ctx.db
      .update(repositorySetupItems)
      .set({ azurePipelineId: s.definitions[0]!, repositoryRef: s.repository.id })
      .where(eq(repositorySetupItems.runId, again.items[0]!.runId));
    await h.ctx.db
      .update(projects)
      .set({ scmProjectRef: s.repository.id })
      .where(eq(projects.id, again.project.id));
    await ingest({ ...again, repository: s.repository });
    await runJobs();
    expect(fake.policies).toHaveLength(before);
    expect(await stateOf(again.items[0]!)).toEqual({ policy: 'on', error: null });
  });

  it('settles every pending item of the repository with the newest one pipeline', async () => {
    const s = await setup('policy/two', ['new', 'new']);
    await ingest(s);
    await runJobs();
    expect(
      fake.policies.filter((p) => p.settings.buildDefinitionId === s.definitions[1]),
    ).toHaveLength(1);
    expect(
      fake.policies.filter((p) => p.settings.buildDefinitionId === s.definitions[0]),
    ).toHaveLength(0);
    for (const item of s.items) expect(await stateOf(item)).toEqual({ policy: 'on', error: null });
  });

  it('a 403 becomes manual with the fixed text, never Azure words', async () => {
    const s = await setup('policy/403');
    await ingest(s);
    fake.inject('POST', /\/_apis\/policy\/configurations$/, {
      status: 403,
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ message: 'TF401027: You need the Edit policies permission' }),
    });
    await runJobs();
    expect(await stateOf(s.items[0]!)).toEqual({
      policy: 'manual',
      error: AZURE_POLICY_TEXT.manual,
    });
  });

  it('a transient failure is retried, then failed with a fixed text', async () => {
    const s = await setup('policy/transient');
    await ingest(s);
    const down = { status: 503, headers: {}, body: 'down' };
    fake.inject('GET', /\/_apis\/git\/repositories\/[^/]+$/, down);
    await runJobs();
    // Retried: still pending, and a later job is queued.
    expect((await stateOf(s.items[0]!)).policy).toBe('pending');
    expect(await queued(s.project.id)).toHaveLength(1);

    // Every later attempt fails too, until the attempts are used up.
    for (let i = 0; i < 6; i++) {
      fake.inject('GET', /\/_apis\/git\/repositories\/[^/]+$/, down);
      await runJobs();
    }
    expect(await stateOf(s.items[0]!)).toEqual({
      policy: 'failed',
      error: AZURE_POLICY_TEXT.unreachable,
    });
    expect(await queued(s.project.id)).toEqual([]);
  });
});
