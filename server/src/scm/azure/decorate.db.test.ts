import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { azureCommitId, seedAzurePullRequest } from '../../../test/azure';
import {
  createFakeAzureDevOps,
  type FakeAzureDevOps,
  type FakeAzurePullRequestInput,
} from '../../../test/fake-azure-devops';
import { createIngestHarness, type IngestHarness } from '../../../test/ingest';
import { engine, file, finding, reportWith } from '../../../test/reports';
import { decorationDeps, PUBLIC_URL, runDecorations } from '../../../test/scm';
import { analyses, branches, projects, reviewSnapshots } from '../../db/schema';
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
    await s.ingest();
    await decorate();
    expect(iterationStatus(s.repository.id, 1)).toEqual([
      expect.objectContaining({ state: 'succeeded' }),
    ]);
    expect(iterationStatus(s.repository.id, 2)).toEqual([]);
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
});
