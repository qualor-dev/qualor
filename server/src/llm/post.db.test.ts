import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { azureCommitId, seedAzurePullRequest } from '../../test/azure';
import {
  createFakeAzureDevOps,
  type FakeAzureChange,
  type FakeAzureDevOps,
  type FakeAzurePullRequest,
} from '../../test/fake-azure-devops';
import { createFakeGitHub, type FakeGitHub } from '../../test/fake-github';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { createFakeLlm, type FakeLlm } from '../../test/fake-llm';
import { githubDeps, mappedGitHubProject, pullRequestReport } from '../../test/github';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { configureLlm, llmJobDeps, runLlmJobs } from '../../test/llm';
import { engine, file, finding, reportWith } from '../../test/reports';
import {
  decorationDeps,
  mappedProject,
  mergeRequestReport,
  PUBLIC_URL,
  runDecorations,
} from '../../test/scm';
import { analyses, issues, jobs, llmRequests, projects } from '../db/schema';
import { communityLimits } from '../limits';
import { defaultReview } from '../review/settings';
import { codeSpan, markerOf } from '../scm/markdown';
import { parseInternalHosts } from '../scm/url';
import { AI_FIX_QUEUE, queueFixPost } from './post';
import { DEFAULT_AUTO_FIX, DEFAULT_BUDGETS } from './settings';

const HEAD = 'a'.repeat(40);
const BASE = 'b'.repeat(40);
const LINES = ['const a = 1;', 'if (a == 1) {}', 'export {};'];
const SNIPPET = { startLine: 1, lines: LINES };
/** Line 1 is context; lines 2 and 3 are added. */
const DIFF = '@@ -1,1 +1,3 @@\n const a = 1;\n+if (a == 1) {}\n+export {};';

describe('posting a fix suggestion (llm.md §8)', () => {
  let llm: FakeLlm;
  let gitlab: FakeGitLab;
  let github: FakeGitHub;
  let azure: FakeAzureDevOps;
  let azureConnectionId: string;
  let nextAzure = 1;
  let h: IngestHarness;
  let nextGitLab = 500;
  let nextRepo = 9_000;
  let day = 1;

  const aiFix = (body: string) => body.startsWith('<!-- qualor:ai-fix ');
  const fixThreads = (gitlabId: number) =>
    gitlab.discussions(gitlabId, 7).filter((d) => aiFix(d.notes[0]!.body));
  /**
   * The fix suggestions posted to a GitHub pull request: its review comments but the issue threads,
   * which the pull request's decoration makes beside them (github.md §6.4).
   */
  const fixComments = (repoId: number) =>
    github.reviewComments.filter((c) => c.repoId === repoId && aiFix(c.body));
  const request = async (id: string) =>
    (await h.ctx.db.select().from(llmRequests).where(eq(llmRequests.id, id)))[0]!;
  const post = (requestId: string, headers: Record<string, string> = h.orgAdmin.headers) =>
    h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/ai-requests/${requestId}/post`,
      headers,
      payload: {},
    });

  async function suggestFix(
    project: IngestProject,
  ): Promise<{ issueId: string; requestId: string }> {
    const [issue] = await h.ctx.db
      .select({ id: issues.id })
      .from(issues)
      .where(eq(issues.projectId, project.id));
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${issue!.id}/ai/fix`,
      headers: h.orgAdmin.headers,
      // Every case its own request: some cases ask twice for one issue, with other answers.
      payload: { refresh: true },
    });
    expect(res.statusCode, res.body).toBe(202);
    await runLlmJobs(h, llmJobDeps(h));
    const requestId = res.json().id as string;
    expect((await request(requestId)).status).toBe('succeeded');
    // Yesterday's: this file asks for more fixes than the default budget of 25 a day.
    await h.ctx.db
      .update(llmRequests)
      .set({ createdAt: sql`now() - interval '1 day'` })
      .where(eq(llmRequests.id, requestId));
    return { issueId: issue!.id, requestId };
  }

  /** A GitLab merge request !7 whose diff is `diff`, analysed at `HEAD` with an eqeqeq issue on `line`. */
  async function gitlabCase(
    key: string,
    options: { diff?: string; line?: number; pipelineProjectId?: string } = {},
  ) {
    const gitlabId = nextGitLab++;
    gitlab.addProject({ id: gitlabId, path: `acme/${key}` });
    gitlab.addMergeRequest(gitlabId, {
      iid: 7,
      title: 'Fix',
      state: 'opened',
      sourceBranch: 'feature/x',
      targetBranch: 'main',
      headSha: HEAD,
      baseSha: BASE,
      startSha: BASE,
      diffs: [{ oldPath: 'src/a.ts', newPath: 'src/a.ts', diff: options.diff ?? DIFF }],
    });
    const project = await mappedProject(h, gitlab, `acme/${key}`, gitlabId);
    await project.ingestOk(
      mergeRequestReport(7, HEAD, {
        projectKey: project.key,
        analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
        gitlab: { projectId: options.pipelineProjectId ?? String(gitlabId) },
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] })],
        findings: [
          finding({
            ruleId: 'eqeqeq',
            path: 'src/a.ts',
            line: options.line ?? 2,
            snippet: SNIPPET,
          }),
        ],
      }),
    );
    return { project, gitlabId };
  }

  /**
   * An Azure DevOps pull request 7 on a repository of its own: the head holds LINES, the common
   * commit only line 1 (so lines 2 and 3 are added), analysed at the head with an eqeqeq issue on
   * line 2.
   */
  async function azureCase(
    key: string,
    options: {
      files?: Record<string, string | Buffer>;
      base?: string;
      changes?: FakeAzureChange[];
      checkout?: 'head' | 'other';
      message?: string;
    } = {},
  ) {
    const repository = azure.addRepository({ name: `fix${nextAzure++}`, projectName: 'Payments' });
    const sourceCommit = azureCommitId(`${key}-head`);
    const seeded = seedAzurePullRequest(azure, repository.id, {
      pullRequest: { id: 7, statusPolicy: true },
      sourceCommit,
      files: options.files ?? { 'src/a.ts': `${LINES.join('\n')}\n` },
      ...(options.changes ? { changes: options.changes } : {}),
    });
    azure.addFile(repository.id, seeded.baseCommit, 'src/a.ts', options.base ?? 'const a = 1;\n');
    const project = await h.project(key);
    await h.ctx.db
      .update(projects)
      .set({ scmConnectionId: azureConnectionId, scmProjectRef: repository.id })
      .where(eq(projects.id, project.id));
    const report = reportWith({
      projectKey: project.key,
      branch: 'feature/x',
      mergeRequest: { id: '7', targetBranch: 'main', sourceBranch: 'feature/x' },
      revision: sourceCommit,
      baseline: { revision: BASE, kind: 'merge_base', status: 'ok' },
      analysisDate: new Date(Date.UTC(2026, 10, 1, 10) + 86_400_000 * day++).toISOString(),
      engines: [engine('eslint')],
      files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] })],
      findings: [
        finding({
          ruleId: 'eqeqeq',
          path: 'src/a.ts',
          line: 2,
          snippet: SNIPPET,
          ...(options.message === undefined ? {} : { message: options.message }),
        }),
      ],
    });
    await project.ingestOk({
      ...report,
      scm: {
        ...report.scm,
        provider: 'azure',
        azure: { repositoryId: repository.id, checkout: options.checkout ?? 'head' },
      },
    });
    const pr = () => azure.pullRequest(repository.id, 7);
    return { project, repository, sourceCommit, pr };
  }
  const azureFixThreads = (pr: () => FakeAzurePullRequest) =>
    pr().threads.filter((t) => aiFix(t.comments[0]?.content ?? ''));
  /** Changes what the analysis stored of the pipeline's Azure Repos side. */
  async function storedAzure(projectId: string, patch: Record<string, string>): Promise<void> {
    const [issue] = await h.ctx.db.select().from(issues).where(eq(issues.projectId, projectId));
    const [row] = await h.ctx.db
      .select({ scmContext: analyses.scmContext })
      .from(analyses)
      .where(eq(analyses.id, issue!.lastSeenAnalysisId!));
    const context = row!.scmContext as { azure: Record<string, string> };
    await h.ctx.db
      .update(analyses)
      .set({ scmContext: { ...context, azure: { ...context.azure, ...patch } } })
      .where(eq(analyses.id, issue!.lastSeenAnalysisId!));
  }

  beforeAll(async () => {
    llm = await createFakeLlm();
    gitlab = await createFakeGitLab();
    github = await createFakeGitHub();
    azure = await createFakeAzureDevOps({ deployment: 'server' });
    h = await createIngestHarness({
      config: {
        publicUrl: PUBLIC_URL,
        scmInternalHosts: parseInternalHosts(
          `${new URL(gitlab.url).host},${new URL(github.url).host},${new URL(azure.url).host}`,
        ),
        llmInternalHosts: parseInternalHosts(llm.host),
      },
    });
    await configureLlm(h.ctx.db, h.ctx.config.secretKey, llm, h.organizationId, {
      budgets: { ...DEFAULT_BUDGETS, perUserPerHour: 1_000 },
    });
    const created = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'azure',
        baseUrl: azure.url,
        azureAuth: 'pat',
        token: azure.pat,
      },
    });
    expect(created.statusCode, created.body).toBe(201);
    azureConnectionId = (created.json() as { id: string }).id;
  });
  afterAll(async () => {
    await h.close();
    await Promise.all([llm.close(), gitlab.close(), github.close(), azure.close()]);
  });
  beforeEach(() => {
    llm.requests.length = 0;
  });

  it('posts a GitLab suggestion only after Post, once, on the analysed head', async () => {
    const { project, gitlabId } = await gitlabCase('fix-gl');
    const { issueId, requestId } = await suggestFix(project);
    const deps = decorationDeps(h);
    await runDecorations(h, deps);
    expect(fixThreads(gitlabId)).toHaveLength(0);
    const res = await post(requestId);
    expect(res.statusCode, res.body).toBe(202);
    expect(res.json().post).toMatchObject({ status: 'queued' });
    await runDecorations(h, deps);
    const [thread] = fixThreads(gitlabId);
    const note = thread!.notes[0]!;
    expect(note.body.split('\n')[0]).toBe(`<!-- qualor:ai-fix ${issueId} ${requestId} -->`);
    expect(note.body).toContain('**AI-generated fix suggestion**');
    expect(note.body).toContain('```suggestion:-0+0\nif (a === 1) {}\n```');
    expect(note.body).toContain(
      `[View the issue in Qualor](${PUBLIC_URL}/projects/${project.id}/issues/${issueId})`,
    );
    expect(note.position).toMatchObject({ new_path: 'src/a.ts', new_line: 2, head_sha: HEAD });
    expect((await request(requestId)).post).toMatchObject({ status: 'posted' });
    const again = await post(requestId);
    expect([again.statusCode, again.json()]).toMatchObject([
      409,
      { code: 'AI_POST_NOT_POSSIBLE', detail: 'already_posted' },
    ]);
    // A lost outcome (the row reset to failed) posts nothing twice: the marker is found.
    await h.ctx.db
      .update(llmRequests)
      .set({ post: { status: 'failed', reason: 'unreachable', at: new Date().toISOString() } })
      .where(eq(llmRequests.id, requestId));
    expect((await post(requestId)).statusCode).toBe(202);
    await runDecorations(h, deps);
    expect(fixThreads(gitlabId)).toHaveLength(1);
    expect((await request(requestId)).post).toMatchObject({ status: 'posted' });
    // The log lines carry ids and outcomes only.
    const logs = h.ctx.logs.join('\n');
    expect(logs).toContain('AI fix suggestion posted');
    expect(logs).not.toContain(gitlab.token);
    expect(logs).not.toContain('if (a === 1)');
  });

  it('queues one post for many concurrent clicks', async () => {
    const { project, gitlabId } = await gitlabCase('fix-race');
    const { requestId } = await suggestFix(project);
    const answers = await Promise.all(Array.from({ length: 6 }, () => post(requestId)));
    expect(answers.map((a) => a.statusCode).sort()).toEqual([202, 409, 409, 409, 409, 409]);
    const queued = await h.ctx.db.select().from(jobs).where(eq(jobs.queue, AI_FIX_QUEUE));
    const mine = queued.filter((j) => (j.payload as { requestId: string }).requestId === requestId);
    expect(mine).toHaveLength(1);
    // Its own key, not the branch's decoration key (llm.md §8.4).
    expect(mine[0]!.concurrencyKey).toBe(`scm-ai-fix:${requestId}`);
    await runDecorations(h, decorationDeps(h));
    expect(fixThreads(gitlabId)).toHaveLength(1);
  });

  it('does not post when the head is no longer the analysed revision (not_head)', async () => {
    const { project, gitlabId } = await gitlabCase('fix-moved');
    const { requestId } = await suggestFix(project);
    gitlab.updateMergeRequest(gitlabId, 7, { headSha: 'c'.repeat(40) });
    await post(requestId);
    await runDecorations(h, decorationDeps(h));
    expect((await request(requestId)).post).toMatchObject({ status: 'failed', reason: 'not_head' });
    expect(fixThreads(gitlabId)).toHaveLength(0);
  });

  it('does not post when the diff text of the lines differs from the snippet (changed)', async () => {
    const { project, gitlabId } = await gitlabCase('fix-changed', {
      diff: '@@ -1,1 +1,3 @@\n const a = 1;\n+if (a == 2) {}\n+export {};',
    });
    const { requestId } = await suggestFix(project);
    await post(requestId);
    await runDecorations(h, decorationDeps(h));
    expect((await request(requestId)).post).toMatchObject({ status: 'failed', reason: 'changed' });
    expect(fixThreads(gitlabId)).toHaveLength(0);
  });

  it('does not post on lines that are not added lines (not_on_diff)', async () => {
    const { project, gitlabId } = await gitlabCase('fix-context', {
      diff: '@@ -1,2 +1,3 @@\n const a = 1;\n if (a == 1) {}\n+export {};',
    });
    const { requestId } = await suggestFix(project);
    await post(requestId);
    await runDecorations(h, decorationDeps(h));
    expect((await request(requestId)).post).toMatchObject({
      status: 'failed',
      reason: 'not_on_diff',
    });
    expect(fixThreads(gitlabId)).toHaveLength(0);
  });

  it('checks the stored answer again before posting, and never trusts it (llm.md §9.5)', async () => {
    const { project, gitlabId } = await gitlabCase('fix-tampered');
    const { requestId } = await suggestFix(project);
    const stored = (await request(requestId)).result as Record<string, unknown>;
    const deps = decorationDeps(h);
    const tamper = async (result: Record<string, unknown>) => {
      await h.ctx.db
        .update(llmRequests)
        .set({ result, post: null })
        .where(eq(llmRequests.id, requestId));
      return post(requestId);
    };
    // A quick action and a fence the checks refuse, written straight into the row.
    for (const replacement of [['/merge'], ['```', '@all'], ['ok‮']]) {
      expect((await tamper({ ...stored, replacement })).statusCode).toBe(202);
      await runDecorations(h, deps);
      expect((await request(requestId)).post).toMatchObject({
        status: 'failed',
        reason: 'not_possible',
      });
    }
    // Lines the model never saw.
    expect((await tamper({ ...stored, original: ['if (b == 1) {}'] })).statusCode).toBe(202);
    await runDecorations(h, deps);
    expect((await request(requestId)).post).toMatchObject({ reason: 'not_possible' });
    // Not a fix at all: refused before anything is queued.
    const odd = await tamper({ kind: 'fix', status: 'fixed', startLine: 2 });
    expect([odd.statusCode, odd.json().detail]).toEqual([409, 'not_fix']);
    expect(fixThreads(gitlabId)).toHaveLength(0);
  });

  it('posts a GitHub review comment with a suggestion, idempotently', async () => {
    const repoId = nextRepo++;
    github.addRepository({ id: repoId, owner: 'acme', name: 'fix-gh', installationId: 777 });
    github.addPull(repoId, {
      number: 7,
      title: 'Fix',
      state: 'open',
      headSha: HEAD,
      baseSha: BASE,
      files: [{ filename: 'src/a.ts', patch: DIFF }],
    });
    const project = await mappedGitHubProject(h, github, 'acme/fix-gh', 'acme/fix-gh');
    await project.ingestOk(
      pullRequestReport(7, HEAD, {
        projectKey: project.key,
        github: { repositoryId: String(repoId), checkout: 'head' },
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] })],
        findings: [finding({ ruleId: 'eqeqeq', path: 'src/a.ts', line: 2, snippet: SNIPPET })],
      }),
    );
    const { requestId } = await suggestFix(project);
    const deps = githubDeps(h);
    await runDecorations(h, deps);
    expect((await post(requestId)).statusCode).toBe(202);
    await runDecorations(h, deps);
    const mine = fixComments(repoId);
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({
      path: 'src/a.ts',
      line: 2,
      startLine: null,
      side: 'RIGHT',
      commitId: HEAD,
      user: { login: `${github.slug}[bot]` },
    });
    expect(mine[0]!.body).toContain('```suggestion\nif (a === 1) {}\n```');
    // The decoration's thread for the issue is the pull request's other review comment: the post
    // is not mistaken for it, and it does not take the post's place.
    const issueThreads = github.reviewComments.filter((c) => c.repoId === repoId && !aiFix(c.body));
    expect(issueThreads.map((c) => [c.line, markerOf(c.body)?.kind])).toEqual([[2, 'issue']]);
    const posted = (await request(requestId)).post;
    expect(posted).toMatchObject({ status: 'posted' });
    expect(posted?.url).toMatch(/\/acme\/fix-gh\/pull\/7#discussion_r\d+$/);
    await h.ctx.db.update(llmRequests).set({ post: null }).where(eq(llmRequests.id, requestId));
    await post(requestId);
    await runDecorations(h, deps);
    expect(fixComments(repoId)).toHaveLength(1);
    expect((await request(requestId)).post).toMatchObject({ status: 'posted' });
  });

  it('refuses to post what cannot be posted', async () => {
    const { project } = await gitlabCase('fix-refused');
    const { issueId, requestId } = await suggestFix(project);
    const explain = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${issueId}/ai/explain`,
      headers: h.orgAdmin.headers,
      payload: {},
    });
    await runLlmJobs(h, llmJobDeps(h));
    expect((await post(explain.json().id)).json()).toMatchObject({
      code: 'AI_POST_NOT_POSSIBLE',
      detail: 'not_fix',
    });
    await h.ctx.db.update(issues).set({ status: 'wont_fix' }).where(eq(issues.id, issueId));
    expect((await post(requestId)).json().detail).toBe('not_open');
    await h.ctx.db.update(issues).set({ status: 'open' }).where(eq(issues.id, issueId));
    llm.say(
      JSON.stringify({
        status: 'not_applicable',
        startLine: 2,
        endLine: 2,
        replacement: [],
        explanation: 'No safe change.',
      }),
    );
    const na = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${issueId}/ai/fix`,
      headers: h.orgAdmin.headers,
      payload: { refresh: true },
    });
    await runLlmJobs(h, llmJobDeps(h));
    expect((await post(na.json().id)).json().detail).toBe('not_applicable');
    // A project whose issue lives on its main branch.
    const onMain = await h.project('acme/fix-main-branch');
    await onMain.ingestOk(
      reportWith({
        projectKey: onMain.key,
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3 })],
        findings: [finding({ ruleId: 'eqeqeq', line: 2, snippet: SNIPPET })],
      }),
    );
    const mainFix = await suggestFix(onMain);
    expect((await post(mainFix.requestId)).json().detail).toBe('not_merge_request');
    // A merge request analysed again at a later commit without the finding: the issue is closed.
    const { project: moved } = await gitlabCase('fix-not-latest');
    const stale = await suggestFix(moved);
    await moved.ingestOk(
      mergeRequestReport(7, 'd'.repeat(40), {
        projectKey: moved.key,
        analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] })],
        findings: [],
      }),
    );
    expect((await post(stale.requestId)).json().detail).toBe('not_open');
    // The analysis the issue was last seen in is not the branch's latest.
    const { project: behind } = await gitlabCase('fix-behind');
    const late = await suggestFix(behind);
    await h.ctx.db
      .update(issues)
      .set({ lastSeenAnalysisId: null })
      .where(eq(issues.id, late.issueId));
    expect((await post(late.requestId)).json().detail).toBe('not_latest');
    // The latest analysis has no stored SCM context of the connection's provider.
    const { project: bare } = await gitlabCase('fix-no-context');
    const noContext = await suggestFix(bare);
    const [issue] = await h.ctx.db.select().from(issues).where(eq(issues.id, noContext.issueId));
    await h.ctx.db
      .update(analyses)
      .set({ scmContext: null })
      .where(eq(analyses.id, issue!.lastSeenAnalysisId!));
    expect((await post(noContext.requestId)).json().detail).toBe('no_scm_context');
    // The project is no longer mapped.
    await h.ctx.db
      .update(projects)
      .set({ scmConnectionId: null, scmProjectRef: null })
      .where(eq(projects.id, bare.id));
    expect((await post(noContext.requestId)).json().detail).toBe('not_mapped');
    const missing = await post('01900000-0000-7000-8000-000000000000');
    expect(missing.statusCode).toBe(404);
  });

  describe('on Azure DevOps (Azure sub-plan 6)', () => {
    const postedUrl = async (requestId: string) =>
      ((await request(requestId)).post as { url?: string }).url;
    const twoLines = JSON.stringify({
      status: 'fixed',
      startLine: 2,
      endLine: 3,
      replacement: ['if (a === 1) {', '}', 'export {};'],
      explanation: 'Use strict equality.',
    });

    it('posts an Azure suggestion thread only after Post, once, on the analysed head', async () => {
      const { project, pr } = await azureCase('fix-az');
      const { issueId, requestId } = await suggestFix(project);
      const deps = decorationDeps(h);
      await runDecorations(h, deps);
      expect(azureFixThreads(pr)).toHaveLength(0);
      const res = await post(requestId);
      expect(res.statusCode, res.body).toBe(202);
      await runDecorations(h, deps);
      const [thread] = azureFixThreads(pr);
      expect(azureFixThreads(pr)).toHaveLength(1);
      const body = thread!.comments[0]!.content;
      expect(thread).toMatchObject({ status: 'active', filePath: 'src/a.ts', line: 2 });
      expect(body.split('\n')[0]).toBe(`<!-- qualor:ai-fix ${issueId} ${requestId} -->`);
      expect(body).toContain('**AI-generated fix suggestion**');
      expect(body).toContain('```suggestion\nif (a === 1) {}\n```');
      expect(body).toContain(
        `[View the issue in Qualor](${PUBLIC_URL}/projects/${project.id}/issues/${issueId})`,
      );
      expect(thread!.threadContext).toEqual({
        filePath: '/src/a.ts',
        rightFileStart: { line: 2, offset: 1 },
        rightFileEnd: { line: 2, offset: 'if (a == 1) {}'.length + 1 },
      });
      // The link keeps to the connection's host: the pull request's address and the thread.
      const url = await postedUrl(requestId);
      expect(url).toMatch(/\/pullrequest\/7\?discussionId=\d+$/);
      expect(url).toBe(`${(url ?? '').split('?')[0]}?discussionId=${thread!.id}`);
      expect(url!.startsWith(azure.url)).toBe(true);
      expect((await request(requestId)).post).toMatchObject({ status: 'posted' });
      const again = await post(requestId);
      expect([again.statusCode, again.json()]).toMatchObject([
        409,
        { code: 'AI_POST_NOT_POSSIBLE', detail: 'already_posted' },
      ]);
      // A lost outcome (the row reset to failed) posts nothing twice: the marker is found.
      await h.ctx.db
        .update(llmRequests)
        .set({ post: { status: 'failed', reason: 'unreachable', at: new Date().toISOString() } })
        .where(eq(llmRequests.id, requestId));
      expect((await post(requestId)).statusCode).toBe(202);
      await runDecorations(h, deps);
      expect(azureFixThreads(pr)).toHaveLength(1);
      expect((await request(requestId)).post).toMatchObject({ status: 'posted', url });
      // Also when the pull request has meanwhile closed: the lost post is found first.
      await h.ctx.db
        .update(llmRequests)
        .set({ post: { status: 'failed', reason: 'unreachable', at: new Date().toISOString() } })
        .where(eq(llmRequests.id, requestId));
      expect((await post(requestId)).statusCode).toBe(202);
      pr().status = 'abandoned';
      await runDecorations(h, deps);
      expect(azureFixThreads(pr)).toHaveLength(1);
      expect((await request(requestId)).post).toMatchObject({ status: 'posted', url });
      const logs = h.ctx.logs.join('\n');
      expect(logs).toContain('AI fix suggestion posted');
      expect(logs).not.toContain(azure.pat);
      expect(logs).not.toContain('if (a === 1)');
    });

    it('does not take a thread of another identity with the marker for a lost post', async () => {
      const { project, pr, repository } = await azureCase('fix-az-foreign');
      const { issueId, requestId } = await suggestFix(project);
      const deps = decorationDeps(h);
      await runDecorations(h, deps);
      const foreign = azure.addThread(repository.id, 7, {
        filePath: 'src/a.ts',
        line: 2,
        comments: [
          {
            content: `<!-- qualor:ai-fix ${issueId} ${requestId} -->\nsomeone else`,
            authorId: 'someone-else',
          },
        ],
      });
      expect((await post(requestId)).statusCode).toBe(202);
      await runDecorations(h, deps);
      const threads = azureFixThreads(pr);
      expect(threads).toHaveLength(2);
      const mine = threads.find((t) => t.id !== foreign.id)!;
      expect(mine.comments[0]!.content).toContain('**AI-generated fix suggestion**');
      const url = await postedUrl(requestId);
      expect(url).toBe(`${(url ?? '').split('?')[0]}?discussionId=${mine.id}`);
    });

    it('selects whole lines: rightFileStart {2, 1}, rightFileEnd {3, length of line 3 + 1}', async () => {
      const { project, pr } = await azureCase('fix-az-range');
      llm.say(twoLines);
      const { requestId } = await suggestFix(project);
      await post(requestId);
      await runDecorations(h, decorationDeps(h));
      const [thread] = azureFixThreads(pr);
      expect(thread!.comments[0]!.content).toContain(
        '```suggestion\nif (a === 1) {\n}\nexport {};\n```',
      );
      expect(thread!.threadContext).toEqual({
        filePath: '/src/a.ts',
        rightFileStart: { line: 2, offset: 1 },
        rightFileEnd: { line: 3, offset: 'export {};'.length + 1 },
      });
      // A deletion is an empty fence over the whole lines.
      const gone = await azureCase('fix-az-delete');
      llm.say(
        JSON.stringify({
          status: 'fixed',
          startLine: 2,
          endLine: 2,
          replacement: [],
          explanation: 'The line is not needed.',
        }),
      );
      const deletion = await suggestFix(gone.project);
      await post(deletion.requestId);
      await runDecorations(h, decorationDeps(h));
      const [removal] = azureFixThreads(gone.pr);
      expect(removal!.comments[0]!.content).toContain('```suggestion\n```');
      expect(removal!.threadContext).toMatchObject({
        rightFileStart: { line: 2, offset: 1 },
        rightFileEnd: { line: 2, offset: 'if (a == 1) {}'.length + 1 },
      });
    });

    it('does not post to an abandoned or completed PR, a moved head, lines that are not added, or changed text', async () => {
      const outcomes: [string, string][] = [];
      const run = async (
        name: string,
        reason: string,
        options: Parameters<typeof azureCase>[1] = {},
        change: (c: Awaited<ReturnType<typeof azureCase>>) => void = () => undefined,
      ) => {
        const c = await azureCase(`fix-az-${name}`, options);
        const { requestId } = await suggestFix(c.project);
        await runDecorations(h, decorationDeps(h));
        change(c);
        expect((await post(requestId)).statusCode).toBe(202);
        await runDecorations(h, decorationDeps(h));
        expect((await request(requestId)).post, name).toMatchObject({ status: 'failed', reason });
        expect(azureFixThreads(c.pr), name).toHaveLength(0);
        outcomes.push([name, reason]);
        return c;
      };
      await run('abandoned', 'closed', {}, (c) => (c.pr().status = 'abandoned'));
      await run('completed', 'closed', {}, (c) => azure.completePullRequest(c.repository.id, 7));
      await run('moved', 'not_head', {}, (c) => (c.pr().headSha = 'c'.repeat(40)));
      await run('no-iteration', 'not_head', {}, (c) => c.pr().iterations.splice(0));
      await run('context', 'not_on_diff', { base: 'const a = 1;\nif (a == 1) {}\n' });
      await run('not-changed', 'not_on_diff', { changes: [{ path: 'src/b.ts' }] });
      await run('text', 'changed', {
        files: { 'src/a.ts': 'const a = 1;\nif (a == 2) {}\nexport {};\n' },
      });
      await run('binary', 'not_possible', {
        files: { 'src/a.ts': Buffer.from([0x63, 0x00, 0x01]) },
      });
      // The changes cannot all be listed: nothing is placed.
      const c = await azureCase('fix-az-pages');
      const { requestId } = await suggestFix(c.project);
      await runDecorations(h, decorationDeps(h));
      azure.inject(
        'GET',
        /\/iterations\/1\/changes$/,
        ...Array.from({ length: 10 }, (_, i) => ({
          status: 200,
          body: { changeEntries: [], nextSkip: (i + 1) * 100 },
        })),
      );
      await post(requestId);
      await runDecorations(h, decorationDeps(h));
      expect((await request(requestId)).post).toMatchObject({
        status: 'failed',
        reason: 'not_possible',
      });
      expect(azureFixThreads(c.pr)).toHaveLength(0);
      expect(outcomes).toHaveLength(8);
    });

    it('does not post to a PR analysed at checkout other: no_scm_context at Post, not_possible in the job', async () => {
      const other = await azureCase('fix-az-other', { checkout: 'other' });
      const refused = await suggestFix(other.project);
      expect((await post(refused.requestId)).json().detail).toBe('no_scm_context');
      const { project, pr } = await azureCase('fix-az-late');
      const { requestId } = await suggestFix(project);
      await runDecorations(h, decorationDeps(h));
      expect((await post(requestId)).statusCode).toBe(202);
      await storedAzure(project.id, { checkout: 'other' });
      await runDecorations(h, decorationDeps(h));
      expect((await request(requestId)).post).toMatchObject({
        status: 'failed',
        reason: 'not_possible',
      });
      expect(azureFixThreads(pr)).toHaveLength(0);
    });

    it('refuses a post when the stored repository id differs', async () => {
      const { project, pr } = await azureCase('fix-az-repo');
      const { requestId } = await suggestFix(project);
      await runDecorations(h, decorationDeps(h));
      await storedAzure(project.id, { repositoryId: '0f6c1a5e-3b0d-4c39-9a51-fa6e00000001' });
      expect((await post(requestId)).statusCode).toBe(202);
      await runDecorations(h, decorationDeps(h));
      expect((await request(requestId)).post).toMatchObject({
        status: 'failed',
        reason: 'refused',
      });
      expect(azureFixThreads(pr)).toHaveLength(0);
    });

    it('retries an unreachable Azure as a decoration does, and never posts twice', async () => {
      const { project, pr } = await azureCase('fix-az-retry');
      const { requestId } = await suggestFix(project);
      await runDecorations(h, decorationDeps(h));
      azure.inject('POST', /\/pullrequests\/7\/threads$/, {
        status: 503,
        body: { message: 'down' },
      });
      expect((await post(requestId)).statusCode).toBe(202);
      await runDecorations(h, decorationDeps(h));
      // The retry waits its backoff; the post stays queued meanwhile.
      expect((await request(requestId)).post).toMatchObject({ status: 'queued' });
      expect((await post(requestId)).json().detail).toBe('already_posted');
      const [retry] = (
        await h.ctx.db.select().from(jobs).where(eq(jobs.queue, AI_FIX_QUEUE))
      ).filter(
        (j) =>
          j.status === 'queued' && (j.payload as { requestId: string }).requestId === requestId,
      );
      expect(retry?.payload).toEqual({ requestId, attempt: 1 });
      await runDecorations(h, decorationDeps(h));
      expect((await request(requestId)).post).toMatchObject({ status: 'posted' });
      expect(azureFixThreads(pr)).toHaveLength(1);

      // Every attempt failing: 6 in all, then failed `unreachable`.
      const other = await azureCase('fix-az-down');
      const down = await suggestFix(other.project);
      await runDecorations(h, decorationDeps(h));
      azure.inject(
        'GET',
        new RegExp(`/repositories/${other.repository.id}/pullrequests/7$`),
        ...Array.from({ length: 6 }, () => ({ status: 502 })),
      );
      await post(down.requestId);
      for (let i = 0; i < 6; i++) await runDecorations(h, decorationDeps(h));
      expect((await request(down.requestId)).post).toMatchObject({
        status: 'failed',
        reason: 'unreachable',
      });
      expect(azureFixThreads(other.pr)).toHaveLength(0);
    });

    it('posts an automatic fix on Azure with the automatic notice', async () => {
      const { project, pr } = await azureCase('fix-az-auto');
      const { requestId } = await suggestFix(project);
      const limits = communityLimits();
      limits.llm.automaticFixSuggestions = true;
      const on = {
        enabled: true,
        features: { explain: true, triage: true, fix: true },
        excludedProjectIds: [] as string[],
        autoFix: { ...DEFAULT_AUTO_FIX, enabled: true },
        autoFixDisabledProjectIds: [] as string[],
        review: defaultReview(),
      };
      const settingsWith = (org: typeof on) =>
        configureLlm(h.ctx.db, h.ctx.config.secretKey, llm, h.organizationId, {
          budgets: { ...DEFAULT_BUDGETS, perUserPerHour: 1_000 },
          organizations: { [h.organizationId]: org },
        });
      try {
        await settingsWith(on);
        const queued = await queueFixPost(
          h.ctx.db,
          await request(requestId),
          undefined,
          undefined,
          {
            auto: true,
          },
        );
        expect(queued.ok).toBe(true);
        await runDecorations(h, decorationDeps(h, { limits: () => limits }));
        const [thread] = azureFixThreads(pr);
        expect(thread!.comments[0]!.content.split('\n')[2]).toBe(
          "Posted automatically for new findings of this pull request. A person can switch this off in Qualor's AI settings.",
        );
        expect((await request(requestId)).post).toMatchObject({ status: 'posted' });
      } finally {
        await settingsWith({ ...on, autoFix: { ...DEFAULT_AUTO_FIX } });
      }
    });

    it('hostile model text stays inert in the Azure thread', async () => {
      const hostile = 'See #12, !34, @<7a1b0c3e-0000-4000-8000-000000000001>, $x$ and <!-- x -->';
      const { project, pr } = await azureCase('fix-az-hostile', { message: hostile });
      llm.say(
        JSON.stringify({
          status: 'fixed',
          startLine: 2,
          endLine: 2,
          replacement: ['if (a === 1) {}'],
          explanation: hostile,
        }),
      );
      const { requestId } = await suggestFix(project);
      await post(requestId);
      await runDecorations(h, decorationDeps(h));
      const lines = azureFixThreads(pr)[0]!.comments[0]!.content.split('\n');
      const issue = lines.find((l) => l.startsWith('Issue: '))!;
      const why = lines.find((l) => l.startsWith('Why: '))!;
      expect(issue).toContain(codeSpan(hostile, 300));
      expect(why).toBe(`Why: ${codeSpan(hostile, 600)}`);
      // Outside the code spans nothing is left that Azure DevOps would turn into a link or a mention.
      for (const line of [issue, why]) {
        const outside = line.replace(/(`+) .*? \1/g, '');
        expect(outside).not.toMatch(/[#!@$<]/);
      }
      expect(lines.slice(1).some((l) => l.startsWith('<!--'))).toBe(false);
    });

    it('does not post where Azure DevOps rejects the position (position_rejected)', async () => {
      const { project, pr } = await azureCase('fix-az-gone');
      const { requestId } = await suggestFix(project);
      await runDecorations(h, decorationDeps(h));
      azure.inject('POST', /\/pullrequests\/7\/threads$/, {
        status: 400,
        body: { message: 'The comment position is not valid' },
      });
      await post(requestId);
      await runDecorations(h, decorationDeps(h));
      expect((await request(requestId)).post).toMatchObject({
        status: 'failed',
        reason: 'position_rejected',
      });
      expect(azureFixThreads(pr)).toHaveLength(0);
    });
  });

  it('retries an unreachable GitLab as a decoration does, and never posts twice', async () => {
    const { project, gitlabId } = await gitlabCase('fix-retry');
    const { requestId } = await suggestFix(project);
    await runDecorations(h, decorationDeps(h));
    gitlab.inject('POST', /\/discussions$/, { status: 503, body: { message: 'down' } });
    expect((await post(requestId)).statusCode).toBe(202);
    await runDecorations(h, decorationDeps(h));
    // The retry waits its backoff (1 minute); the post stays queued meanwhile.
    expect((await request(requestId)).post).toMatchObject({ status: 'queued' });
    expect((await post(requestId)).json().detail).toBe('already_posted');
    const [retry] = (await h.ctx.db.select().from(jobs).where(eq(jobs.queue, AI_FIX_QUEUE))).filter(
      (j) => j.status === 'queued' && (j.payload as { requestId: string }).requestId === requestId,
    );
    expect(retry?.payload).toEqual({ requestId, attempt: 1 });
    await runDecorations(h, decorationDeps(h));
    expect((await request(requestId)).post).toMatchObject({ status: 'posted' });
    expect(fixThreads(gitlabId)).toHaveLength(1);

    // Every attempt failing: 6 in all, then failed `unreachable`.
    const other = await gitlabCase('fix-down');
    const down = await suggestFix(other.project);
    await runDecorations(h, decorationDeps(h));
    gitlab.inject(
      'GET',
      new RegExp(`/projects/${other.gitlabId}/merge_requests/7$`),
      ...Array.from({ length: 6 }, () => ({ status: 502 })),
    );
    await post(down.requestId);
    for (let i = 0; i < 6; i++) await runDecorations(h, decorationDeps(h));
    expect((await request(down.requestId)).post).toMatchObject({
      status: 'failed',
      reason: 'unreachable',
    });
    expect(fixThreads(other.gitlabId)).toHaveLength(0);
  });

  it('places a suggestion of several lines: GitLab -0+N on the first, GitHub start_line..line', async () => {
    const twoLines = JSON.stringify({
      status: 'fixed',
      startLine: 2,
      endLine: 3,
      replacement: ['if (a === 1) {', '}', 'export {};'],
      explanation: 'Use strict equality.',
    });
    const { project, gitlabId } = await gitlabCase('fix-range');
    llm.say(twoLines);
    const gl = await suggestFix(project);
    await post(gl.requestId);
    await runDecorations(h, decorationDeps(h));
    const note = fixThreads(gitlabId)[0]!.notes[0]!;
    expect(note.body).toContain('```suggestion:-0+1\nif (a === 1) {\n}\nexport {};\n```');
    expect(note.position).toMatchObject({ new_line: 2 });

    const repoId = nextRepo++;
    github.addRepository({ id: repoId, owner: 'acme', name: 'fix-range', installationId: 777 });
    github.addPull(repoId, {
      number: 7,
      title: 'Fix',
      state: 'open',
      headSha: HEAD,
      baseSha: BASE,
      files: [{ filename: 'src/a.ts', patch: DIFF }],
    });
    const gh = await mappedGitHubProject(h, github, 'acme/fix-range-gh', 'acme/fix-range');
    await gh.ingestOk(
      pullRequestReport(7, HEAD, {
        projectKey: gh.key,
        github: { repositoryId: String(repoId), checkout: 'head' },
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] })],
        findings: [finding({ ruleId: 'eqeqeq', path: 'src/a.ts', line: 2, snippet: SNIPPET })],
      }),
    );
    llm.say(twoLines);
    const ghFix = await suggestFix(gh);
    const deps = githubDeps(h);
    await post(ghFix.requestId);
    await runDecorations(h, deps);
    const [comment] = fixComments(repoId);
    expect(comment).toMatchObject({ startLine: 2, line: 3, side: 'RIGHT' });
    expect(comment!.body).toContain('```suggestion\nif (a === 1) {\n}\nexport {};\n```');
  });

  it('does not post to a GitHub pull request analysed at a checkout other than its head', async () => {
    const repoId = nextRepo++;
    github.addRepository({ id: repoId, owner: 'acme', name: 'fix-merge', installationId: 777 });
    github.addPull(repoId, {
      number: 7,
      title: 'Fix',
      state: 'open',
      headSha: HEAD,
      baseSha: BASE,
      files: [{ filename: 'src/a.ts', patch: DIFF }],
    });
    const project = await mappedGitHubProject(h, github, 'acme/fix-merge', 'acme/fix-merge');
    await project.ingestOk(
      pullRequestReport(7, HEAD, {
        projectKey: project.key,
        github: { repositoryId: String(repoId), checkout: 'other' },
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] })],
        findings: [finding({ ruleId: 'eqeqeq', path: 'src/a.ts', line: 2, snippet: SNIPPET })],
      }),
    );
    const { requestId } = await suggestFix(project);
    expect((await post(requestId)).json().detail).toBe('no_scm_context');
  });

  it('lets a write member post; a read token gets 403; a non-member gets 404', async () => {
    const { project } = await gitlabCase('fix-access');
    const { requestId } = await suggestFix(project);
    const tokenOf = async (session: Session, scopes: string[]) => {
      const res = await h.ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: session.headers,
        payload: { name: `t-${scopes.join('-')}`, scopes },
      });
      expect(res.statusCode, res.body).toBe(201);
      return bearer((res.json() as { token: string }).token);
    };
    const u = await createUser(h.ctx, { username: 'fix-member' });
    await addMember(h.ctx, h.organizationId, u.id, 'member');
    const member = await login(h.ctx, u.username, u.password);
    const read = await post(requestId, await tokenOf(member, ['read']));
    expect([read.statusCode, read.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    expect((await post(requestId, bearer(project.token))).statusCode).toBe(403);
    const o = await createUser(h.ctx, { username: 'fix-outsider' });
    const outsider = await login(h.ctx, o.username, o.password);
    const foreign = await post(requestId, outsider.headers);
    expect([foreign.statusCode, foreign.json().code]).toEqual([404, 'NOT_FOUND']);
    const ok = await post(requestId, await tokenOf(member, ['write']));
    expect(ok.statusCode, ok.body).toBe(202);
  });

  it('charges the G7 bound only for a post that is queued', async () => {
    const { project } = await gitlabCase('fix-charge');
    const { requestId } = await suggestFix(project);
    const row = await request(requestId);
    let charged = 0;
    const charge = () => {
      charged++;
    };
    expect(await queueFixPost(h.ctx.db, row, charge)).toMatchObject({ ok: true });
    expect(charged).toBe(1);
    // Refused: already posted (queued with a live job), not a fix; nothing charged.
    expect(await queueFixPost(h.ctx.db, row, charge)).toMatchObject({
      ok: false,
      refusal: 'already_posted',
    });
    expect(await queueFixPost(h.ctx.db, { ...row, feature: 'explain' }, charge)).toMatchObject({
      ok: false,
      refusal: 'not_fix',
    });
    expect(charged).toBe(1);
    // A charge that throws (the bound is used up): nothing is queued.
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, AI_FIX_QUEUE));
    await h.ctx.db.update(llmRequests).set({ post: null }).where(eq(llmRequests.id, requestId));
    await expect(
      queueFixPost(h.ctx.db, row, () => {
        throw new Error('RATE_LIMITED');
      }),
    ).rejects.toThrow('RATE_LIMITED');
    expect((await request(requestId)).post).toBeNull();
    expect(await h.ctx.db.select().from(jobs).where(eq(jobs.queue, AI_FIX_QUEUE))).toEqual([]);
  });

  it('refuses a post, and posts nothing, once the fix feature is off or the project excluded', async () => {
    const { project, gitlabId } = await gitlabCase('fix-turned-off');
    const { requestId } = await suggestFix(project);
    const on = {
      enabled: true,
      features: { explain: true, triage: true, fix: true },
      excludedProjectIds: [] as string[],
      autoFix: { ...DEFAULT_AUTO_FIX },
      autoFixDisabledProjectIds: [] as string[],
      review: defaultReview(),
    };
    const settingsWith = (org: typeof on) =>
      configureLlm(h.ctx.db, h.ctx.config.secretKey, llm, h.organizationId, {
        budgets: { ...DEFAULT_BUDGETS, perUserPerHour: 1_000 },
        organizations: { [h.organizationId]: org },
      });
    try {
      for (const org of [
        { ...on, features: { ...on.features, fix: false } },
        { ...on, enabled: false },
        { ...on, excludedProjectIds: [project.id] },
      ]) {
        await settingsWith(org);
        const refused = await post(requestId);
        expect([refused.statusCode, refused.json().code]).toEqual([409, 'AI_DISABLED']);
      }
      // Queued while on, turned off before the job runs: nothing is posted.
      await settingsWith(on);
      expect((await post(requestId)).statusCode).toBe(202);
      await settingsWith({ ...on, features: { ...on.features, fix: false } });
      await runDecorations(h, decorationDeps(h));
      expect((await request(requestId)).post).toMatchObject({
        status: 'failed',
        reason: 'not_possible',
      });
      expect(fixThreads(gitlabId)).toHaveLength(0);
    } finally {
      await settingsWith(on);
    }
  });

  it('does not post to a GitLab project other than the pipeline’s (refused), and logs the SCM error kind only', async () => {
    const { project, gitlabId } = await gitlabCase('fix-other-project', {
      pipelineProjectId: '424242',
    });
    const { requestId } = await suggestFix(project);
    expect((await post(requestId)).statusCode).toBe(202);
    await runDecorations(h, decorationDeps(h));
    expect((await request(requestId)).post).toMatchObject({ status: 'failed', reason: 'refused' });
    expect(fixThreads(gitlabId)).toHaveLength(0);

    // A refusal by GitLab itself: its kind and status are logged, never its message.
    const { project: p2 } = await gitlabCase('fix-forbidden');
    const second = await suggestFix(p2);
    // The analysis's own decoration first: the injected answer is for the post.
    await runDecorations(h, decorationDeps(h));
    gitlab.inject('POST', /\/discussions$/, {
      status: 403,
      body: { message: 'secret-looking gitlab message' },
    });
    await post(second.requestId);
    await runDecorations(h, decorationDeps(h));
    expect((await request(second.requestId)).post).toMatchObject({ reason: 'refused' });
    const line = h.ctx.logs.filter((l) => l.includes(second.requestId)).at(-1)!;
    expect(line).toContain('"errorKind":"auth"');
    expect(line).toContain('"httpStatus":403');
    expect(h.ctx.logs.join('\n')).not.toContain('secret-looking gitlab message');
  });

  it('does not post to a closed merge request, nor where GitLab rejects the position', async () => {
    const closed = await gitlabCase('fix-closed');
    const a = await suggestFix(closed.project);
    gitlab.updateMergeRequest(closed.gitlabId, 7, { state: 'closed' });
    await post(a.requestId);
    await runDecorations(h, decorationDeps(h));
    expect((await request(a.requestId)).post).toMatchObject({ status: 'failed', reason: 'closed' });

    const rejected = await gitlabCase('fix-position');
    const b = await suggestFix(rejected.project);
    await runDecorations(h, decorationDeps(h));
    gitlab.inject('POST', /\/discussions$/, {
      status: 400,
      body: { message: { line_code: ['must be a valid line code'] } },
    });
    await post(b.requestId);
    await runDecorations(h, decorationDeps(h));
    expect((await request(b.requestId)).post).toMatchObject({
      status: 'failed',
      reason: 'position_rejected',
    });
    expect(fixThreads(rejected.gitlabId)).toHaveLength(0);
  });

  it('does not post a body over 8 KiB even without the explanation (not_possible)', async () => {
    const { project, gitlabId } = await gitlabCase('fix-huge');
    llm.say(
      JSON.stringify({
        status: 'fixed',
        startLine: 2,
        endLine: 2,
        replacement: Array.from({ length: 30 }, (_, i) => `const v${i} = '${'x'.repeat(380)}';`),
        explanation: 'Long.',
      }),
    );
    const { requestId } = await suggestFix(project);
    await post(requestId);
    await runDecorations(h, decorationDeps(h));
    expect((await request(requestId)).post).toMatchObject({
      status: 'failed',
      reason: 'not_possible',
    });
    expect(fixThreads(gitlabId)).toHaveLength(0);
  });

  it('waits while the circuit is open or the organisation is busy, then posts once', async () => {
    const { project, gitlabId } = await gitlabCase('fix-wait');
    const { requestId } = await suggestFix(project);
    const deps = decorationDeps(h);
    await runDecorations(h, deps);
    const aiJobs = async () =>
      (await h.ctx.db.select().from(jobs).where(eq(jobs.queue, AI_FIX_QUEUE))).filter(
        (j) =>
          j.status === 'queued' && (j.payload as { requestId: string }).requestId === requestId,
      );
    // The organisation's slots are all taken: the same attempt again shortly.
    let held = 0;
    while (deps.runtime.slots.tryTake(h.organizationId)) held++;
    await post(requestId);
    await runDecorations(h, deps);
    expect((await aiJobs()).map((j) => j.payload)).toEqual([{ requestId, attempt: 0 }]);
    expect((await request(requestId)).post).toMatchObject({ status: 'queued' });
    for (let i = 0; i < held; i++) deps.runtime.slots.release(h.organizationId);
    // The circuit of the connection is open: nothing is sent, and the attempt counts.
    for (let i = 0; i < 10; i++) deps.runtime.circuit.failure(project.connectionId);
    await runDecorations(h, deps);
    expect((await aiJobs()).map((j) => j.payload)).toEqual([{ requestId, attempt: 1 }]);
    expect(fixThreads(gitlabId)).toHaveLength(0);
    // Closed again: posted, once.
    deps.runtime.circuit.success(project.connectionId);
    await runDecorations(h, deps);
    expect((await request(requestId)).post).toMatchObject({ status: 'posted' });
    expect(fixThreads(gitlabId)).toHaveLength(1);
  });

  it('refuses a GitHub post without the stored repository id, and re-checks the head checkout', async () => {
    const setup = async (name: string, withId: boolean) => {
      const repoId = nextRepo++;
      github.addRepository({ id: repoId, owner: 'acme', name, installationId: 777 });
      github.addPull(repoId, {
        number: 7,
        title: 'Fix',
        state: 'open',
        headSha: HEAD,
        baseSha: BASE,
        files: [{ filename: 'src/a.ts', patch: DIFF }],
      });
      const project = await mappedGitHubProject(h, github, `acme/${name}`, `acme/${name}`);
      await project.ingestOk(
        pullRequestReport(7, HEAD, {
          projectKey: project.key,
          github: withId
            ? { repositoryId: String(repoId), checkout: 'head' }
            : { checkout: 'head' },
          engines: [engine('eslint')],
          files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] })],
          findings: [finding({ ruleId: 'eqeqeq', path: 'src/a.ts', line: 2, snippet: SNIPPET })],
        }),
      );
      return { repoId, project, ...(await suggestFix(project)) };
    };
    const deps = githubDeps(h);
    const noId = await setup('fix-no-repo-id', false);
    await runDecorations(h, deps);
    expect((await post(noId.requestId)).statusCode).toBe(202);
    await runDecorations(h, deps);
    expect((await request(noId.requestId)).post).toMatchObject({ reason: 'refused' });
    expect(fixComments(noId.repoId)).toHaveLength(0);

    // Queued on a head checkout; the stored context no longer says head when the job runs.
    const moved = await setup('fix-checkout-moved', true);
    await runDecorations(h, deps);
    expect((await post(moved.requestId)).statusCode).toBe(202);
    const [issue] = await h.ctx.db.select().from(issues).where(eq(issues.id, moved.issueId));
    const [analysis] = await h.ctx.db
      .select()
      .from(analyses)
      .where(eq(analyses.id, issue!.lastSeenAnalysisId!));
    const context = analysis!.scmContext as { github: Record<string, unknown> };
    await h.ctx.db
      .update(analyses)
      .set({ scmContext: { ...context, github: { ...context.github, checkout: 'other' } } })
      .where(eq(analyses.id, analysis!.id));
    await runDecorations(h, deps);
    expect((await request(moved.requestId)).post).toMatchObject({ reason: 'not_possible' });
    expect(fixComments(moved.repoId)).toHaveLength(0);

    // Lines GitHub will not place (422): position_rejected.
    const placed = await setup('fix-gh-position', true);
    await runDecorations(h, deps);
    github.inject('POST', /\/pulls\/7\/comments$/, { status: 422, body: { message: 'x' } });
    expect((await post(placed.requestId)).statusCode).toBe(202);
    await runDecorations(h, deps);
    expect((await request(placed.requestId)).post).toMatchObject({
      status: 'failed',
      reason: 'position_rejected',
    });
  });

  it('leaves ai-fix threads alone in inline reconciliation', async () => {
    const { project, gitlabId } = await gitlabCase('fix-inline');
    const { requestId } = await suggestFix(project);
    const deps = decorationDeps(h);
    await post(requestId);
    await runDecorations(h, deps);
    const before = JSON.stringify(fixThreads(gitlabId));
    expect(fixThreads(gitlabId)).toHaveLength(1);
    await project.ingestOk(
      mergeRequestReport(7, HEAD, {
        projectKey: project.key,
        analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
        gitlab: { projectId: String(gitlabId) },
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 3, newLines: [[2, 3]] })],
        findings: [],
      }),
    );
    await runDecorations(h, deps);
    expect(JSON.stringify(fixThreads(gitlabId))).toBe(before);
  });
});
