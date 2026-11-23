import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { azureCommitId, seedAzurePullRequest } from '../../../test/azure';
import {
  createFakeAzureDevOps,
  type FakeAzureDevOps,
  type FakeAzurePullRequestInput,
} from '../../../test/fake-azure-devops';
import { createIngestHarness, type IngestHarness } from '../../../test/ingest';
import { engine, file, finding, reportWith } from '../../../test/reports';
import { decorationDeps, PUBLIC_URL, runDecorations } from '../../../test/scm';
import {
  analyses,
  branches,
  jobs,
  projects,
  reviewSnapshots,
  scmConnections,
} from '../../db/schema';
import { decorateAnalysis } from '../decorate';
import { markerOf, summaryMarker } from '../markdown';
import { statusName } from '../render';
import { parseInternalHosts } from '../url';
import { AZURE_REPOSITORY_MISMATCH } from './decorate';

const STALE = 'Inline comments wait for the analysis of the pull request’s latest commit.';
const CHECKOUT_OTHER =
  'The analyzers’ issues are not commented inline: the pipeline did not check out the pull request’s head. Use the Qualor task or the head checkout of the Azure Pipelines examples.';
const PR = 7;

describe('Azure DevOps decoration: status and summary (Azure sub-plan 4)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let connectionId: string;
  let day = 1;
  let repoNumber = 1;

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({ deployment: 'server' });
    h = await createIngestHarness({
      config: {
        publicUrl: PUBLIC_URL,
        scmInternalHosts: parseInternalHosts(new URL(fake.url).host),
      },
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

  /** A project mapped to a repository of its own, with pull request #7 (a status policy on it). */
  const setup = async (
    key: string,
    options: {
      pullRequest?: FakeAzurePullRequestInput;
      sourceCommit?: string;
    } = {},
  ) => {
    const repository = fake.addRepository({ name: `r${repoNumber++}`, projectName: 'Payments' });
    const sourceCommit = options.sourceCommit ?? azureCommitId(`${key}-head`);
    const seeded = seedAzurePullRequest(fake, repository.id, {
      pullRequest: { id: PR, statusPolicy: true, ...options.pullRequest },
      sourceCommit,
    });
    const project = await h.project(key);
    await h.ctx.db
      .update(projects)
      .set({ scmConnectionId: connectionId, scmProjectRef: repository.id })
      .where(eq(projects.id, project.id));
    const ingest = (
      opts: {
        revision?: string;
        findings?: number;
        azure?: { repositoryId?: string; checkout?: 'head' | 'other' } | null;
        pullRequestId?: number | null;
      } = {},
    ) => {
      const report = reportWith({
        projectKey: project.key,
        branch: 'feature/x',
        ...(opts.pullRequestId === null
          ? {}
          : {
              mergeRequest: {
                id: String(opts.pullRequestId ?? PR),
                targetBranch: 'main',
                sourceBranch: 'feature/x',
              },
            }),
        revision: opts.revision ?? sourceCommit,
        baseline: { revision: 'b'.repeat(40), kind: 'merge_base', status: 'ok' },
        analysisDate: new Date(Date.UTC(2026, 10, 1, 10) + 86_400_000 * day++).toISOString(),
        engines: [engine('eslint')],
        files: [file('src/a.ts', { newLines: [[1, 60]] })],
        findings: Array.from({ length: opts.findings ?? 0 }, (_, i) =>
          finding({ path: 'src/a.ts', line: i + 1 }),
        ),
      });
      const azure =
        opts.azure === undefined
          ? { repositoryId: repository.id, checkout: 'head' as const }
          : opts.azure;
      return project.ingestOk({
        ...report,
        scm: { ...report.scm, provider: 'azure', ...(azure === null ? {} : { azure }) },
      });
    };
    return { project, repository, ...seeded, sourceCommit, ingest };
  };

  const requestsOf = () =>
    fake.requests.map((r) => `${r.method} ${r.path.replace(/^.*\/_apis\//, '')}`);
  const writesOf = () => requestsOf().filter((r) => !r.startsWith('GET'));
  const decorate = () => runDecorations(h, decorationDeps(h));
  const summaries = (repositoryId: string) =>
    fake
      .pullRequest(repositoryId, PR)
      .threads.filter((t) => markerOf(t.comments[0]?.content ?? '')?.kind === 'summary');
  const iterationStatus = (repositoryId: string, iteration: number) =>
    fake.pullRequest(repositoryId, PR).iterations[iteration - 1]!.statuses;

  it('posts succeeded on the analysed iteration, and nothing new the second time', async () => {
    const s = await setup('az/pass');
    await s.ingest();
    expect(await decorate()).toBe(1);
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, s.project.id), eq(branches.kind, 'merge_request')));
    expect(iterationStatus(s.repository.id, 1)).toEqual([
      {
        id: expect.any(Number),
        iterationId: 1,
        state: 'succeeded',
        description: 'Quality gate passed',
        targetUrl: `${PUBLIC_URL}/projects/${s.project.id}/branches/${branch!.id}`,
        genre: 'qualor',
        name: statusName(s.project.key),
      },
    ]);
    // The same analysis decorated again: nothing is written, the status policy stays satisfied.
    const [analysis] = await h.ctx.db
      .select()
      .from(analyses)
      .where(eq(analyses.projectId, s.project.id));
    fake.clearRequests();
    const outcome = await decorateAnalysis(decorationDeps(h), {
      analysisId: analysis!.id,
      attempt: 0,
      gitlab: null,
      azure: { repositoryId: s.repository.id, checkout: 'head' },
    });
    expect(outcome.kind).toBe('done');
    expect(writesOf()).toEqual([]);
    expect(summaries(s.repository.id)).toHaveLength(1);
  });

  it('a newer status wins over an older one whatever the list’s order, so a failed gate is posted', async () => {
    const s = await setup('az/order');
    const name = statusName(s.project.key);
    const base = { iterationId: 1, description: 'old', targetUrl: null, genre: 'qualor', name };
    // Seeded out of order: the highest id (the newest) is a succeeded status.
    s.iteration.statuses.push(
      { ...base, id: 20, state: 'succeeded' },
      { ...base, id: 10, state: 'failed', description: 'Quality gate failed: new_issues 1 > 0' },
    );
    await s.ingest({ findings: 1 });
    await decorate();
    expect(writesOf().filter((w) => w.includes('/statuses'))).toHaveLength(1);
    const newest = iterationStatus(s.repository.id, 1).reduce((a, b) =>
      (b.id ?? 0) > (a.id ?? 0) ? b : a,
    );
    expect(newest).toMatchObject({
      state: 'failed',
      description: 'Quality gate failed: new_issues 1 > 0',
    });
    expect(newest.id).toBeGreaterThan(20);
    // Decorated again: the newest already says it, nothing is posted.
    fake.clearRequests();
    await s.ingest({ findings: 1 });
    await decorate();
    expect(writesOf().filter((w) => w.includes('/statuses'))).toEqual([]);
  });

  it('posts failed for a failed gate', async () => {
    const s = await setup('az/fail');
    await s.ingest({ findings: 1 });
    await decorate();
    expect(iterationStatus(s.repository.id, 1)).toEqual([
      expect.objectContaining({
        state: 'failed',
        description: 'Quality gate failed: new_issues 1 > 0',
      }),
    ]);
  });

  it('puts the status on the analysed iteration when the head moved, and comments wait', async () => {
    const s = await setup('az/stale');
    fake.addIteration(s.repository.id, PR, {
      sourceRefCommit: azureCommitId('az/stale-newer'),
      commonRefCommit: s.baseCommit,
    });
    // A new issue the head would get a thread for, were the analysis of the newest iteration.
    await s.ingest({ findings: 1 });
    await decorate();
    expect(iterationStatus(s.repository.id, 1)).toEqual([
      expect.objectContaining({ state: 'failed' }),
    ]);
    expect(iterationStatus(s.repository.id, 2)).toEqual([]);
    // Nothing of the threads is read or written: no changes, no file, only the summary's listing.
    expect(requestsOf().filter((r) => /\/changes|\/items/.test(r))).toEqual([]);
    expect(requestsOf().filter((r) => /GET .*\/threads$/.test(r))).toHaveLength(1);
    const [summary] = summaries(s.repository.id);
    expect(summary?.comments[0]?.content).toContain(STALE);
    // No thread but the summary was asked for or written.
    expect(fake.pullRequest(s.repository.id, PR).threads).toHaveLength(1);
    expect(writesOf().filter((w) => w.includes('/threads'))).toEqual([
      expect.stringMatching(/^POST .*\/threads$/),
    ]);
  });

  it('posts no status when no iteration has the analysed commit, and still the summary', async () => {
    const s = await setup('az/no-iteration');
    await s.ingest({ revision: azureCommitId('az/elsewhere') });
    await decorate();
    expect(iterationStatus(s.repository.id, 1)).toEqual([]);
    expect(writesOf().some((w) => w.includes('/statuses'))).toBe(false);
    expect(summaries(s.repository.id)[0]?.comments[0]?.content).toContain(STALE);
  });

  it('says in the summary that the pipeline did not check out the head', async () => {
    const s = await setup('az/other');
    await s.ingest({ azure: { repositoryId: s.repository.id, checkout: 'other' } });
    await decorate();
    expect(summaries(s.repository.id)[0]?.comments[0]?.content).toContain(CHECKOUT_OTHER);
    expect(iterationStatus(s.repository.id, 1)).toHaveLength(1);
  });

  it.each(['completed', 'abandoned'] as const)(
    'a %s pull request: nothing after its GET, and the snapshots are deleted',
    async (status) => {
      const s = await setup(`az/${status}`, { pullRequest: { status } });
      const analysisId = await s.ingest();
      const [branch] = await h.ctx.db
        .select()
        .from(branches)
        .where(eq(branches.projectId, s.project.id));
      await h.ctx.db.insert(reviewSnapshots).values({
        analysisId,
        projectId: s.project.id,
        branchId: branch!.id,
        status: 'rejected',
        error: 'SNAPSHOT_INVALID:test',
        compressedBytes: 0,
      });
      await decorate();
      expect(requestsOf().filter((r) => !r.includes('connectionData'))).toEqual([
        expect.stringMatching(/^GET git\/repositories\/.+\/pullrequests\/7$/),
      ]);
      expect(await h.ctx.db.select().from(reviewSnapshots)).toEqual([]);
    },
  );

  it('decorates a draft pull request', async () => {
    const s = await setup('az/draft', { pullRequest: { isDraft: true } });
    await s.ingest();
    await decorate();
    expect(iterationStatus(s.repository.id, 1)).toHaveLength(1);
    expect(summaries(s.repository.id)).toHaveLength(1);
  });

  it('creates the summary once, closed and without a file, and edits it in place', async () => {
    const s = await setup('az/summary');
    await s.ingest();
    await decorate();
    const [thread] = summaries(s.repository.id);
    expect(thread).toMatchObject({ status: 'closed', filePath: null });
    expect(thread?.comments).toHaveLength(1);
    expect(thread?.comments[0]?.content.split('\n')[0]).toBe(summaryMarker(s.project.id));
    expect(thread?.comments[0]?.content).toContain('quality gate passed');
    // A newer analysis of the same commit with a finding: the same thread's comment is edited.
    await s.ingest({ findings: 1 });
    fake.clearRequests();
    await decorate();
    const after = summaries(s.repository.id);
    expect(after).toHaveLength(1);
    expect(after[0]?.id).toBe(thread?.id);
    expect(after[0]?.comments[0]?.content).toContain('quality gate failed');
    expect(writesOf().filter((w) => w.includes('/threads'))).toEqual([
      expect.stringMatching(/PATCH .*\/threads\/\d+\/comments\/1$/),
    ]);
  });

  it('ignores a summary-looking thread of another identity', async () => {
    const s = await setup('az/foreign');
    const foreign = fake.addThread(s.repository.id, PR, {
      status: 'closed',
      comments: [
        { content: `${summaryMarker(s.project.id)}\nsomeone else`, authorId: 'someone-else' },
      ],
    });
    await s.ingest();
    await decorate();
    const own = summaries(s.repository.id).filter((t) => t.id !== foreign.id);
    expect(own).toHaveLength(1);
    expect(foreign.comments[0]?.content).toContain('someone else');
    expect(writesOf().some((w) => w.includes(`/threads/${foreign.id}`))).toBe(false);
  });

  it('fails retryably when a refused status is followed by a transient summary failure', async () => {
    const s = await setup('az/two-failures');
    fake.inject('POST', /\/statuses$/, { status: 403, body: {} });
    fake.inject('POST', /\/threads$/, { status: 503, body: {} });
    const analysisId = await s.ingest();
    fake.clearRequests();
    const outcome = await decorateAnalysis(decorationDeps(h), {
      analysisId,
      attempt: 0,
      gitlab: null,
      azure: { repositoryId: s.repository.id, checkout: 'head' },
    });
    // The job its ingestion queued is not run here.
    await h.ctx.db.delete(jobs);
    expect(outcome).toMatchObject({ kind: 'failed', retry: true, error: { kind: 'transient' } });
    expect(writesOf()).toHaveLength(2);
  });

  it('posts one commit status for a branch analysis', async () => {
    const s = await setup('az/branch');
    const revision = azureCommitId('az/branch-main');
    await s.ingest({ revision, pullRequestId: null });
    await decorate();
    expect(fake.commitStatuses).toEqual([
      {
        repositoryId: s.repository.id,
        sha: revision,
        status: expect.objectContaining({
          state: 'succeeded',
          genre: 'qualor',
          name: statusName(s.project.key),
        }),
      },
    ]);
    expect(writesOf()).toHaveLength(1);
  });

  it('refuses when the pipeline’s repository is not the mapped one', async () => {
    const s = await setup('az/mismatch');
    const other = fake.addRepository({ name: 'other', projectName: 'Payments' });
    const analysisId = await s.ingest({ azure: { repositoryId: other.id, checkout: 'head' } });
    fake.clearRequests();
    const outcome = await decorateAnalysis(decorationDeps(h), {
      analysisId,
      attempt: 0,
      gitlab: null,
      azure: { repositoryId: other.id, checkout: 'head' },
    });
    expect(outcome).toMatchObject({
      kind: 'failed',
      retry: false,
      error: { kind: 'refused', message: AZURE_REPOSITORY_MISMATCH },
    });
    expect(fake.requests).toEqual([]);
  });

  describe('the connection’s background problem', () => {
    const problemOf = async () =>
      (await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, connectionId)))[0]!
        .problem;

    it('records a refused credential, and a later successful decoration clears it', async () => {
      const s = await setup('az/problem-refused');
      fake.inject('GET', /\/connectionData$/, { status: 401, body: {} });
      const analysisId = await s.ingest();
      const outcome = await decorateAnalysis(decorationDeps(h), {
        analysisId,
        attempt: 0,
        gitlab: null,
        azure: { repositoryId: s.repository.id, checkout: 'head' },
      });
      await h.ctx.db.delete(jobs);
      expect(outcome).toMatchObject({ kind: 'failed', retry: false });
      expect(await problemOf()).toEqual({ code: 'token_refused', at: expect.any(String) });
      await s.ingest();
      expect(await decorate()).toBe(1);
      expect(await problemOf()).toBeNull();
    });

    const SEEDED = { code: 'token_refused' as const, at: '2026-11-20T10:00:00.000Z' };
    const seed = () =>
      h.ctx.db
        .update(scmConnections)
        .set({ problem: SEEDED })
        .where(eq(scmConnections.id, connectionId));

    it('leaves a recorded problem as it was after a failure that is not the credential’s', async () => {
      await seed();
      // A transient failure.
      const a = await setup('az/keep-transient');
      fake.inject('POST', /\/statuses$/, { status: 503, body: {} });
      await a.ingest();
      await decorate();
      await h.ctx.db.delete(jobs);
      expect(await problemOf()).toEqual(SEEDED);
      // A rate limit.
      const b = await setup('az/keep-rate-limit');
      fake.inject('POST', /\/statuses$/, {
        status: 429,
        headers: { 'retry-after': '30' },
        body: {},
      });
      await b.ingest();
      await decorate();
      await h.ctx.db.delete(jobs);
      expect(await problemOf()).toEqual(SEEDED);
      // A repository that is not the mapped one.
      const c = await setup('az/keep-mismatch');
      const other = fake.addRepository({ name: 'other3', projectName: 'Payments' });
      const analysisId = await c.ingest({ azure: { repositoryId: other.id, checkout: 'head' } });
      await decorateAnalysis(decorationDeps(h), {
        analysisId,
        attempt: 0,
        gitlab: null,
        azure: { repositoryId: other.id, checkout: 'head' },
      });
      await h.ctx.db.delete(jobs);
      expect(await problemOf()).toEqual(SEEDED);
      await h.ctx.db
        .update(scmConnections)
        .set({ problem: null })
        .where(eq(scmConnections.id, connectionId));
    });

    /** Deps whose writes to scm_connections fail, as a database error would. */
    const failingWrites = () => {
      const warn = vi.fn();
      const db = new Proxy(h.ctx.db, {
        get(target, prop) {
          if (prop === 'update') {
            return (table: unknown) => {
              if (table === scmConnections) throw new Error('connection refused by the database');
              return target.update(table as never);
            };
          }
          const value = Reflect.get(target, prop, target) as unknown;
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
      return { warn, deps: { ...decorationDeps(h), db, logger: { info: vi.fn(), warn } } };
    };

    it('keeps the outcome when clearing the problem fails, and logs a warning', async () => {
      await seed();
      const s = await setup('az/clear-fails');
      const analysisId = await s.ingest();
      await h.ctx.db.delete(jobs);
      const { warn, deps } = failingWrites();
      const outcome = await decorateAnalysis(deps, {
        analysisId,
        attempt: 0,
        gitlab: null,
        azure: { repositoryId: s.repository.id, checkout: 'head' },
      });
      expect(outcome).toMatchObject({ kind: 'done' });
      expect(warn).toHaveBeenCalledTimes(1);
      expect(JSON.stringify(warn.mock.calls)).not.toContain('connection refused');
      await h.ctx.db
        .update(scmConnections)
        .set({ problem: null })
        .where(eq(scmConnections.id, connectionId));
    });

    it('keeps the failed outcome when recording the problem fails, and logs a warning', async () => {
      const s = await setup('az/record-fails');
      fake.inject('GET', /\/connectionData$/, { status: 401, body: {} });
      const analysisId = await s.ingest();
      await h.ctx.db.delete(jobs);
      const { warn, deps } = failingWrites();
      const outcome = await decorateAnalysis(deps, {
        analysisId,
        attempt: 0,
        gitlab: null,
        azure: { repositoryId: s.repository.id, checkout: 'head' },
      });
      expect(outcome).toMatchObject({ kind: 'failed', retry: false });
      expect(warn).toHaveBeenCalledTimes(1);
      expect(await problemOf()).toBeNull();
    });

    it('records a refused status step as the decisive failure, and never a transient failure', async () => {
      const s = await setup('az/problem-transient');
      fake.inject('POST', /\/statuses$/, { status: 503, body: {} });
      await s.ingest();
      await decorate();
      // The retry its failure queued is not run here.
      await h.ctx.db.delete(jobs);
      expect(await problemOf()).toBeNull();
      const t = await setup('az/problem-forbidden');
      fake.inject('POST', /\/statuses$/, { status: 401, body: {} });
      await t.ingest();
      await decorate();
      expect(await problemOf()).toMatchObject({ code: 'token_refused' });
      await (await setup('az/problem-clear')).ingest();
      expect(await decorate()).toBe(1);
      expect(await problemOf()).toBeNull();
    });

    it('records an unreadable credential', async () => {
      const [row] = await h.ctx.db
        .select()
        .from(scmConnections)
        .where(eq(scmConnections.id, connectionId));
      const s = await setup('az/problem-unreadable');
      await s.ingest();
      await h.ctx.db
        .update(scmConnections)
        .set({ tokenEnc: { ...row!.tokenEnc, ct: 'AAAA' } })
        .where(eq(scmConnections.id, connectionId));
      try {
        await decorate();
        expect(await problemOf()).toMatchObject({ code: 'undecryptable' });
      } finally {
        await h.ctx.db
          .update(scmConnections)
          .set({ tokenEnc: row!.tokenEnc, problem: null })
          .where(eq(scmConnections.id, connectionId));
      }
    });

    it('does not record a repository mismatch', async () => {
      const s = await setup('az/problem-mismatch');
      const other = fake.addRepository({ name: 'other2', projectName: 'Payments' });
      const analysisId = await s.ingest({ azure: { repositoryId: other.id, checkout: 'head' } });
      await decorateAnalysis(decorationDeps(h), {
        analysisId,
        attempt: 0,
        gitlab: null,
        azure: { repositoryId: other.id, checkout: 'head' },
      });
      await h.ctx.db.delete(jobs);
      expect(await problemOf()).toBeNull();
    });
  });
});
