import type { Severity } from '@qualor/shared';
import { and, eq, inArray, isNull, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { QUIET_AUDIT_LOG } from '../../test/audit-log';
import { createFakeGitHub, type FakeGitHub } from '../../test/fake-github';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { createFakeLlm, type FakeLlm } from '../../test/fake-llm';
import { githubDeps, mappedGitHubProject, pullRequestReport } from '../../test/github';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { configureLlm, llmJobDeps } from '../../test/llm';
import { engine, file, finding, reportWith } from '../../test/reports';
import {
  decorationDeps,
  mappedProject,
  mergeRequestReport,
  PUBLIC_URL,
  silentLogger,
} from '../../test/scm';
import { createAuditRecorder } from '../audit/recorder';
import { auditEvents, branches, issues, jobs, llmRequests } from '../db/schema';
import type { Limits } from '../limits';
import { claimJob, type Job } from '../queue/queue';
import { runUntilIdle, type JobHandlers } from '../queue/worker';
import { defaultReview } from '../review/settings';
import { scmHandlers, type DecorationDeps } from '../scm/decorate';
import { SCM_QUEUE } from '../scm/queue';
import { parseInternalHosts } from '../scm/url';
import { AUTO_FIX_QUEUE, autoFixHandlers, autoFixKey, type AutoFixDeps } from './auto-fix';
import { llmHandlers, type LlmJobDeps } from './job';
import { AI_FIX_QUEUE } from './post';
import { createAiRequest, LLM_QUEUE } from './service';
import {
  DEFAULT_AUTO_FIX,
  DEFAULT_BUDGETS,
  type OrgLlmSettings,
  type StoredLlmSettings,
} from './settings';

const HEAD = 'a'.repeat(40);
const NEXT = 'c'.repeat(40);
const BASE = 'b'.repeat(40);
const LINES = [
  'const a = 1;',
  'if (a == 1) {}',
  'if (a == 2) {}',
  'if (a == 3) {}',
  'if (a == 4) {}',
  'export {};',
];
const SNIPPET = { startLine: 1, lines: LINES };
/** Line 1 is context; lines 2 to 6 are added. */
const DIFF = `@@ -1,1 +1,6 @@\n ${LINES[0]}\n${LINES.slice(1)
  .map((l) => `+${l}`)
  .join('\n')}`;
/** The jobs whose payload names one of the requests, in their order. */
function jobsOfRequests<J extends { payload: unknown }>(
  queued: readonly J[],
  requests: readonly { id: string }[],
): J[] {
  const ids = new Set(requests.map((r) => r.id));
  return queued.filter((j) => ids.has((j.payload as { requestId: string }).requestId));
}
/** Verbatim (4E-3a §3 step 5). */
const AUTO_LINE =
  "Posted automatically for new findings of this merge request. A person can switch this off in Qualor's AI settings.";
/** Three high findings and a low one, on lines 2 to 5. */
const MIXED: readonly [number, Severity][] = [
  [2, 'high'],
  [3, 'high'],
  [4, 'low'],
  [5, 'high'],
];
const ALL_HIGH: readonly [number, Severity][] = [
  [2, 'high'],
  [3, 'high'],
  [4, 'high'],
  [5, 'high'],
];

describe('automatic fix suggestions (4E-3a §3)', () => {
  let llm: FakeLlm;
  let gitlab: FakeGitLab;
  let github: FakeGitHub;
  let h: IngestHarness;
  let nextGitLab = 800;
  let nextRepo = 9_800;
  let day = 1;
  /** The licence's seam, changed by the tests (the app and the workers read it on every call). */
  const limits: Limits = {
    llm: { automaticFixSuggestions: true },
    licenses: { policy: false },
    vulnerabilities: { priority: false, alerts: false, sbom: false },
  };
  const autoDeps = (over: Partial<AutoFixDeps> = {}): AutoFixDeps => ({
    db: h.ctx.db,
    limits: () => limits,
    logger: h.ctx.app.log,
    ...over,
  });
  /**
   * The `scm` worker's deps with the same live limits, as main.ts builds them, and timeouts long
   * enough that a slow moment of the fakes never becomes a retry scheduled for later.
   */
  const scmOverrides = (): Partial<DecorationDeps> => ({
    limits: () => limits,
    scm: {
      ...decorationDeps(h).scm,
      clientOptions: { timeoutMs: 15_000 },
      githubClientOptions: { timeoutMs: 15_000 },
    },
  });
  const scmDeps = () => decorationDeps(h, scmOverrides());

  const aiFixThreads = (gitlabId: number) =>
    gitlab
      .discussions(gitlabId, 7)
      .filter((d) => d.notes[0]!.body.startsWith('<!-- qualor:ai-fix '));
  const fixRows = (projectId: string) =>
    h.ctx.db
      .select()
      .from(llmRequests)
      .where(and(eq(llmRequests.projectId, projectId), eq(llmRequests.feature, 'fix')));
  const issueLines = async (projectId: string) =>
    new Map(
      (
        await h.ctx.db
          .select({ id: issues.id, line: issues.startLine })
          .from(issues)
          .where(eq(issues.projectId, projectId))
      ).map((i) => [i.id, i.line]),
    );
  const requestedLines = async (projectId: string) => {
    const lines = await issueLines(projectId);
    return (await fixRows(projectId)).map((r) => lines.get(r.issueId ?? '')).sort();
  };
  const autoJobs = () => h.ctx.db.select().from(jobs).where(eq(jobs.queue, AUTO_FIX_QUEUE));

  /** The settings of every test: auto-fix on at high, 10 per analysis; `org` and `over` change them. */
  async function configure(
    org: Partial<OrgLlmSettings> = {},
    over: Partial<StoredLlmSettings> = {},
  ): Promise<void> {
    await configureLlm(h.ctx.db, h.ctx.config.secretKey, llm, h.organizationId, {
      budgets: { ...DEFAULT_BUDGETS, fixPerDay: 100, perUserPerHour: 1_000 },
      organizations: {
        [h.organizationId]: {
          enabled: true,
          features: { explain: true, triage: true, fix: true },
          excludedProjectIds: [],
          autoFix: { ...DEFAULT_AUTO_FIX, enabled: true },
          autoFixDisabledProjectIds: [],
          review: defaultReview(),
          ...org,
        },
      },
      ...over,
    });
  }

  const reportFindings = (lines: readonly [number, Severity][]) =>
    lines.map(([line, severity]) =>
      finding({ ruleId: 'eqeqeq', path: 'src/a.ts', line, severity, snippet: SNIPPET }),
    );

  /** A GitLab merge request !7 at `HEAD` whose diff adds lines 2 to 6, mapped and analysed. */
  async function gitlabCase(key: string, lines: readonly [number, Severity][] = MIXED) {
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
      diffs: [{ oldPath: 'src/a.ts', newPath: 'src/a.ts', diff: DIFF }],
    });
    const project = await mappedProject(h, gitlab, `acme/${key}`, gitlabId);
    const analyse = (revision: string = HEAD) =>
      project.ingestOk(
        mergeRequestReport(7, revision, {
          projectKey: project.key,
          analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
          gitlab: { projectId: String(gitlabId) },
          engines: [engine('eslint')],
          files: [file('src/a.ts', { lines: 6, newLines: [[2, 6]] })],
          findings: reportFindings(lines),
        }),
      );
    const analysisId = await analyse();
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    return { project, gitlabId, analysisId, branchId: branch!.id, analyse };
  }

  /**
   * Runs the queues until none of their jobs is left queued, also those a job requeued for later
   * (a retry, a busy slot's defer): `runUntilIdle` alone stops at the first moment nothing is due.
   */
  async function drain(handlers: JobHandlers, queues: string[]): Promise<void> {
    for (let round = 0; round < 5; round++) {
      const queued = and(inArray(jobs.queue, queues), eq(jobs.status, 'queued'));
      await h.ctx.db
        .update(jobs)
        .set({ runAt: sql`now()` })
        .where(queued);
      await runUntilIdle(h.ctx.db, handlers, silentLogger);
      const left = await h.ctx.db.select({ id: jobs.id }).from(jobs).where(queued);
      if (left.length === 0) return;
    }
    throw new Error(`jobs of ${queues.join(', ')} still queued after 5 rounds`);
  }
  const runAutoFix = (deps = autoDeps()) => drain(autoFixHandlers(deps), [AUTO_FIX_QUEUE]);
  const runLlm = (over: Partial<LlmJobDeps> = {}) =>
    drain(llmHandlers(llmJobDeps(h, { limits: () => limits, ...over })), [LLM_QUEUE]);
  /** The `scm` worker's queues: decorations and fix posts. */
  const runScm = (deps = scmDeps()) => drain(scmHandlers(deps), [SCM_QUEUE, AI_FIX_QUEUE]);
  /** The stage's job, the `llm` jobs it queued, then the `scm` worker (decorations and posts). */
  async function runAll(deps = scmDeps()): Promise<void> {
    await runAutoFix();
    await runLlm();
    await runScm(deps);
  }

  beforeAll(async () => {
    llm = await createFakeLlm();
    gitlab = await createFakeGitLab();
    github = await createFakeGitHub();
    h = await createIngestHarness({
      limits,
      config: {
        publicUrl: PUBLIC_URL,
        scmInternalHosts: parseInternalHosts(
          `${new URL(gitlab.url).host},${new URL(github.url).host}`,
        ),
        llmInternalHosts: parseInternalHosts(llm.host),
      },
    });
  });
  afterAll(async () => {
    await h.close();
    await Promise.all([llm.close(), gitlab.close(), github.close()]);
  });
  beforeEach(async () => {
    limits.llm.automaticFixSuggestions = true;
    await configure();
    // Every test starts with today's budget unused (earlier tests' requests become yesterday's).
    await h.ctx.db.update(llmRequests).set({ createdAt: sql`now() - interval '1 day'` });
    // Nothing of an earlier test runs in this one (a decoration, a job a test never ran).
    await h.ctx.db.delete(jobs);
    llm.requests.length = 0;
    h.ctx.logs.length = 0;
  });
  afterEach(async () => {
    // No job failed or was retried behind a test's back.
    const failed = await h.ctx.db
      .select({
        queue: jobs.queue,
        status: jobs.status,
        attempts: jobs.attempts,
        error: jobs.lastError,
      })
      .from(jobs)
      .where(sql`${jobs.status} = 'dead' OR ${jobs.attempts} > 1`);
    expect(failed, JSON.stringify(failed)).toEqual([]);
  });

  it('posts a suggestion for each new high finding of a GitLab merge request, with the automatic line', async () => {
    const { project, gitlabId, branchId } = await gitlabCase('auto-gl');
    const [queued] = await autoJobs();
    expect(queued).toMatchObject({ concurrencyKey: autoFixKey(branchId), status: 'queued' });
    expect(autoFixKey(branchId)).toBe(`llm-auto-fix:${branchId}`);
    await runAutoFix();
    const rows = await fixRows(project.id);
    // No person: user_id null, and the `llm` job knows it is automatic.
    expect(rows.map((r) => [r.userId, r.status])).toEqual([
      [null, 'queued'],
      [null, 'queued'],
      [null, 'queued'],
    ]);
    const llmJobs = await h.ctx.db.select().from(jobs).where(eq(jobs.queue, LLM_QUEUE));
    const mine = llmJobs.filter((j) =>
      rows.some((r) => r.id === (j.payload as { requestId: string }).requestId),
    );
    expect(mine.map((j) => (j.payload as { auto?: boolean }).auto)).toEqual([true, true, true]);
    expect(await requestedLines(project.id)).toEqual([2, 3, 5]);
    await runLlm();
    await runScm();
    expect(llm.requests).toHaveLength(3);
    const threads = aiFixThreads(gitlabId);
    expect(threads).toHaveLength(3);
    for (const thread of threads) {
      const body = thread.notes[0]!.body.split('\n');
      expect(body[1]).toMatch(/^\*\*AI-generated fix suggestion\*\*/);
      expect(body[2]).toBe(AUTO_LINE);
    }
    expect(threads.map((t) => t.notes[0]!.position?.new_line).sort()).toEqual([2, 3, 5]);
    for (const row of await fixRows(project.id)) {
      expect(row.post).toMatchObject({ status: 'posted' });
    }
    // The issue view shows it as suggested automatically (4E-3a §4).
    const read = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/ai-requests/${rows[0]!.id}`,
      headers: h.orgAdmin.headers,
    });
    expect(read.statusCode, read.body).toBe(200);
    expect(read.json()).toMatchObject({ feature: 'fix', automatic: true });
  });

  it('posts a GitHub review comment with the automatic line', async () => {
    const repoId = nextRepo++;
    github.addRepository({ id: repoId, owner: 'acme', name: 'auto-gh', installationId: 777 });
    github.addPull(repoId, {
      number: 7,
      title: 'Fix',
      state: 'open',
      headSha: HEAD,
      baseSha: BASE,
      files: [{ filename: 'src/a.ts', patch: DIFF }],
    });
    const project = await mappedGitHubProject(h, github, 'acme/auto-gh', 'acme/auto-gh');
    await project.ingestOk(
      pullRequestReport(7, HEAD, {
        projectKey: project.key,
        github: { repositoryId: String(repoId), checkout: 'head' },
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 6, newLines: [[2, 6]] })],
        findings: reportFindings([[3, 'blocker']]),
      }),
    );
    await runAll(githubDeps(h, scmOverrides()));
    // The fix is one of the pull request's review comments; the other is the issue's own thread.
    const comments = github.reviewComments.filter(
      (c) => c.repoId === repoId && c.body.startsWith('<!-- qualor:ai-fix '),
    );
    expect(comments).toHaveLength(1);
    expect(comments[0]).toMatchObject({ path: 'src/a.ts', line: 3, commitId: HEAD });
    expect(comments[0]!.body.split('\n')[2]).toBe(AUTO_LINE);
    expect(comments[0]!.body).toContain('```suggestion\nif (a === 2) {}\n```');
  });

  it('never suggests again for an issue: neither a second analysis nor a new commit asks again', async () => {
    const { project, gitlabId, analyse } = await gitlabCase('auto-once');
    await runAll();
    expect(await fixRows(project.id)).toHaveLength(3);
    expect(aiFixThreads(gitlabId)).toHaveLength(3);
    // The same head analysed again.
    await analyse();
    await runAll();
    // A new commit that carries the tracked issues.
    gitlab.updateMergeRequest(gitlabId, 7, { headSha: NEXT });
    await analyse(NEXT);
    await runAll();
    expect(await fixRows(project.id)).toHaveLength(3);
    expect(llm.requests).toHaveLength(3);
    expect(aiFixThreads(gitlabId)).toHaveLength(3);
    // Not even after a failure: a failed automatic request counts as one.
    await h.ctx.db
      .update(llmRequests)
      .set({ status: 'failed', errorCode: 'PROVIDER_UNAVAILABLE', result: null })
      .where(eq(llmRequests.projectId, project.id));
    await analyse(NEXT);
    await runAll();
    expect(await fixRows(project.id)).toHaveLength(3);
  });

  it('asks at most maxPerAnalysis per analysis, most severe first, then the rest next time', async () => {
    await configure({ autoFix: { enabled: true, minSeverity: 'high', maxPerAnalysis: 2 } });
    const { project, analyse } = await gitlabCase('auto-cap', [
      [2, 'high'],
      [3, 'blocker'],
      [4, 'high'],
      [5, 'high'],
    ]);
    await runAutoFix();
    expect(await requestedLines(project.id)).toEqual([2, 3]);
    await runLlm();
    await analyse();
    await runAutoFix();
    expect(await requestedLines(project.id)).toEqual([2, 3, 4, 5]);
  });

  it('honours the threshold: at low every new finding is asked about', async () => {
    await configure({ autoFix: { enabled: true, minSeverity: 'low', maxPerAnalysis: 10 } });
    const { project } = await gitlabCase('auto-low');
    await runAutoFix();
    expect(await requestedLines(project.id)).toEqual([2, 3, 4, 5]);
  });

  it('asks only about open issues in new code that are not duplicates and have a snippet', async () => {
    await configure({ autoFix: { enabled: true, minSeverity: 'low', maxPerAnalysis: 10 } });
    const { project } = await gitlabCase('auto-select', [
      [2, 'high'],
      [3, 'high'],
      [4, 'high'],
      [5, 'high'],
    ]);
    const byLine = new Map([...(await issueLines(project.id))].map(([id, line]) => [line, id]));
    const set = (line: number, values: Partial<typeof issues.$inferInsert>) =>
      h.ctx.db
        .update(issues)
        .set(values)
        .where(eq(issues.id, byLine.get(line)!));
    await set(2, { inNewCode: false });
    await set(3, { duplicateOfIssueId: byLine.get(5)! });
    await set(4, { snippet: null });
    await runAutoFix();
    expect(await requestedLines(project.id)).toEqual([5]);
  });

  it('stops when the organisation fix budget for the day is used up', async () => {
    await configure({}, { budgets: { ...DEFAULT_BUDGETS, fixPerDay: 2, perUserPerHour: 1_000 } });
    const { project } = await gitlabCase('auto-budget', ALL_HIGH);
    await runAutoFix();
    expect(await fixRows(project.id)).toHaveLength(2);
    const lines = h.ctx.logs.filter((l) => l.includes('budget_exhausted'));
    expect(lines).toHaveLength(1);
  });

  it('keeps two merge requests of one organisation analysed at once within the budget', async () => {
    await configure({}, { budgets: { ...DEFAULT_BUDGETS, fixPerDay: 3, perUserPerHour: 1_000 } });
    const one = await gitlabCase('auto-race-1', ALL_HIGH);
    const two = await gitlabCase('auto-race-2', ALL_HIGH);
    const queued = await autoJobs();
    expect(queued).toHaveLength(2);
    // Both jobs at the same moment, as two workers would run them.
    const handler = autoFixHandlers(autoDeps())[AUTO_FIX_QUEUE]!;
    const asJob = (j: (typeof queued)[number]): Job => ({
      id: j.id,
      queue: j.queue,
      concurrencyKey: j.concurrencyKey,
      payload: j.payload,
      attempts: 1,
      maxAttempts: j.maxAttempts,
    });
    await Promise.all(queued.map((j) => handler(asJob(j))));
    const total = (await fixRows(one.project.id)).length + (await fixRows(two.project.id)).length;
    expect(total).toBe(3);
  });

  it('serialises the jobs of one merge request, and one job run twice asks once per issue', async () => {
    const { project, analyse, analysisId, branchId } = await gitlabCase('auto-serial');
    await analyse();
    const queued = await autoJobs();
    expect(queued).toHaveLength(2);
    expect(new Set(queued.map((j) => j.concurrencyKey)).size).toBe(1);
    const first = await claimJob(h.ctx.db, AUTO_FIX_QUEUE, 'test-a', 60_000);
    expect(first).not.toBeNull();
    // The second job of the branch waits while the first runs.
    expect(await claimJob(h.ctx.db, AUTO_FIX_QUEUE, 'test-b', 60_000)).toBeNull();
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, AUTO_FIX_QUEUE));
    // A job run again while it still runs (a lost lease): each issue gets one request only.
    const handler = autoFixHandlers(autoDeps())[AUTO_FIX_QUEUE]!;
    const job = (id: string): Job => ({
      id,
      queue: AUTO_FIX_QUEUE,
      concurrencyKey: null,
      payload: { analysisId },
      attempts: 1,
      maxAttempts: 3,
    });
    // The first analysis is no longer the latest: it asks nothing.
    await handler(job(first!.id));
    expect(await fixRows(project.id)).toHaveLength(0);
    const [latest] = await h.ctx.db
      .select({ id: branches.lastAnalysisId })
      .from(branches)
      .where(eq(branches.id, branchId));
    const again = (id: string): Job => ({ ...job(id), payload: { analysisId: latest!.id } });
    await Promise.all([handler(again(first!.id)), handler(again(first!.id))]);
    expect(await requestedLines(project.id)).toEqual([2, 3, 5]);
  });

  it('refuses a second automatic request for an issue under the lock, even one the job did not select', async () => {
    const { project } = await gitlabCase('auto-twice', [[2, 'high']]);
    const [issue] = await h.ctx.db
      .select({ id: issues.id })
      .from(issues)
      .where(eq(issues.projectId, project.id));
    const ask = () =>
      createAiRequest(
        { db: h.ctx.db, limits },
        { kind: 'automatic' },
        { issueId: issue!.id, projectId: project.id },
        'fix',
        // Past the cache and the request in flight: only the automatic rule can refuse it.
        { refresh: true },
      );
    const first = await ask();
    expect([first.kind, first.row.userId]).toEqual(['queued', null]);
    const second = await ask();
    expect([second.kind, second.row.id]).toEqual(['already_requested', first.row.id]);
    expect(await fixRows(project.id)).toHaveLength(1);
  });

  describe('enqueues nothing when a rule does not hold at ingestion', () => {
    const cases: [string, () => Promise<void>][] = [
      ['auto-fix off', () => configure({ autoFix: { ...DEFAULT_AUTO_FIX, enabled: false } })],
      [
        'the feature not licensed',
        async () => {
          limits.llm.automaticFixSuggestions = false;
        },
      ],
      [
        'the fix feature off',
        () => configure({ features: { explain: true, triage: true, fix: false } }),
      ],
      ['the organisation switched off', () => configure({ enabled: false })],
      ['no provider', () => configure({}, { provider: null })],
    ];
    for (const [name, change] of cases) {
      it(name, async () => {
        await change();
        await gitlabCase(`auto-off-${name.replace(/\W+/g, '-')}`);
        expect(await autoJobs()).toHaveLength(0);
      });
    }

    it('the project opted out, or excluded from AI', async () => {
      for (const list of ['autoFixDisabledProjectIds', 'excludedProjectIds'] as const) {
        const gitlabId = nextGitLab++;
        gitlab.addProject({ id: gitlabId, path: `acme/auto-opt-${list}` });
        const project = await mappedProject(h, gitlab, `acme/auto-opt-${list}`, gitlabId);
        await configure({ [list]: [project.id] });
        await project.ingestOk(
          mergeRequestReport(7, HEAD, {
            projectKey: project.key,
            gitlab: { projectId: String(gitlabId) },
            engines: [engine('eslint')],
            files: [file('src/a.ts', { lines: 6, newLines: [[2, 6]] })],
            findings: reportFindings(MIXED),
          }),
        );
        expect(await autoJobs()).toHaveLength(0);
      }
    });

    it('a branch that is not a merge request', async () => {
      const gitlabId = nextGitLab++;
      gitlab.addProject({ id: gitlabId, path: 'acme/auto-branch' });
      const project = await mappedProject(h, gitlab, 'acme/auto-branch', gitlabId);
      const report = reportWith({
        projectKey: project.key,
        branch: 'main',
        revision: HEAD,
        engines: [engine('eslint')],
        files: [file('src/a.ts', { lines: 6, newLines: [[2, 6]] })],
        findings: reportFindings(MIXED),
      });
      const analysisId = await project.ingestOk({
        ...report,
        scm: { ...report.scm, gitlab: { projectId: String(gitlabId) } },
      });
      // The branch's decoration is queued; its automatic suggestions are not.
      const decorations = await h.ctx.db.select().from(jobs).where(eq(jobs.queue, 'scm'));
      expect(
        decorations.filter((j) => (j.payload as { analysisId: string }).analysisId === analysisId),
      ).toHaveLength(1);
      expect(await autoJobs()).toHaveLength(0);
    });
  });

  describe('asks nothing when a rule no longer holds when the job runs (Review Focus 1)', () => {
    const cases: [string, (project: IngestProject) => Promise<void>][] = [
      [
        'the feature no longer licensed',
        async () => {
          limits.llm.automaticFixSuggestions = false;
        },
      ],
      [
        'auto-fix switched off',
        () => configure({ autoFix: { ...DEFAULT_AUTO_FIX, enabled: false } }),
      ],
      [
        'the fix feature off',
        () => configure({ features: { explain: true, triage: true, fix: false } }),
      ],
      ['the organisation switched off', () => configure({ enabled: false })],
      ['the provider removed', () => configure({}, { provider: null })],
      ['the project opted out', (p) => configure({ autoFixDisabledProjectIds: [p.id] })],
      ['the project excluded from AI', (p) => configure({ excludedProjectIds: [p.id] })],
      ['the path excluded from AI', () => configure({}, { excludePaths: ['src/**'] })],
      [
        'the analysis no longer the latest',
        async (p) => {
          await h.ctx.db
            .update(branches)
            .set({ lastAnalysisId: null })
            .where(eq(branches.projectId, p.id));
        },
      ],
    ];
    for (const [name, change] of cases) {
      it(name, async () => {
        const { project, gitlabId } = await gitlabCase(`auto-late-${name.replace(/\W+/g, '-')}`);
        expect(await autoJobs()).toHaveLength(1);
        await change(project);
        await runAll();
        expect(await fixRows(project.id)).toHaveLength(0);
        expect(llm.requests).toHaveLength(0);
        expect(aiFixThreads(gitlabId)).toHaveLength(0);
      });
    }

    it('auto-fix switched off after the requests were queued: nothing is sent or posted', async () => {
      const { project, gitlabId } = await gitlabCase('auto-late-llm');
      await runAutoFix();
      expect(await fixRows(project.id)).toHaveLength(3);
      await configure({ autoFix: { ...DEFAULT_AUTO_FIX, enabled: false } });
      await runLlm();
      await runScm();
      expect(llm.requests).toHaveLength(0);
      expect((await fixRows(project.id)).map((r) => r.errorCode)).toEqual([
        'AI_DISABLED',
        'AI_DISABLED',
        'AI_DISABLED',
      ]);
      expect(aiFixThreads(gitlabId)).toHaveLength(0);
    });

    it('the licence lapsed after the requests were queued: nothing is sent or posted', async () => {
      const { project, gitlabId } = await gitlabCase('auto-late-licence');
      await runAutoFix();
      limits.llm.automaticFixSuggestions = false;
      await runLlm();
      await runScm();
      expect(llm.requests).toHaveLength(0);
      expect(aiFixThreads(gitlabId)).toHaveLength(0);
      expect((await fixRows(project.id)).map((r) => r.errorCode)).toEqual([
        'AI_DISABLED',
        'AI_DISABLED',
        'AI_DISABLED',
      ]);
    });
  });

  describe('posts nothing when a rule no longer holds when the post job runs', () => {
    const cases: [string, (project: IngestProject) => Promise<void>][] = [
      [
        'auto-fix switched off',
        () => configure({ autoFix: { ...DEFAULT_AUTO_FIX, enabled: false } }),
      ],
      ['the project opted out', (p) => configure({ autoFixDisabledProjectIds: [p.id] })],
      [
        'the licence lapsed',
        async () => {
          limits.llm.automaticFixSuggestions = false;
        },
      ],
    ];
    for (const [name, change] of cases) {
      it(name, async () => {
        const { project, gitlabId } = await gitlabCase(`auto-post-${name.replace(/\W+/g, '-')}`);
        await runAutoFix();
        await runLlm();
        const queued = await h.ctx.db.select().from(jobs).where(eq(jobs.queue, AI_FIX_QUEUE));
        const rows = await fixRows(project.id);
        const mine = jobsOfRequests(queued, rows);
        // Queued by the automatic path, and marked so.
        expect(mine.map((j) => (j.payload as { auto?: boolean }).auto)).toEqual([true, true, true]);
        await change(project);
        await runScm();
        for (const row of await fixRows(project.id)) {
          expect(row.post).toMatchObject({ status: 'failed', reason: 'not_possible' });
        }
        expect(aiFixThreads(gitlabId)).toHaveLength(0);
      });
    }

    it('a person posting a suggestion is not held to the automatic rule', async () => {
      const { project, gitlabId } = await gitlabCase('auto-post-person', [[2, 'high']]);
      await h.ctx.db.delete(jobs).where(eq(jobs.queue, AUTO_FIX_QUEUE));
      const [issue] = await h.ctx.db
        .select({ id: issues.id })
        .from(issues)
        .where(eq(issues.projectId, project.id));
      const asked = await h.ctx.app.inject({
        method: 'POST',
        url: `/api/v0/issues/${issue!.id}/ai/fix`,
        headers: h.orgAdmin.headers,
        payload: {},
      });
      expect(asked.statusCode, asked.body).toBe(202);
      expect(asked.json()).toMatchObject({ automatic: false });
      await runLlm();
      await configure({ autoFix: { ...DEFAULT_AUTO_FIX, enabled: false } });
      const posted = await h.ctx.app.inject({
        method: 'POST',
        url: `/api/v0/ai-requests/${asked.json<{ id: string }>().id}/post`,
        headers: h.orgAdmin.headers,
        payload: {},
      });
      expect(posted.statusCode, posted.body).toBe(202);
      await runScm();
      expect(aiFixThreads(gitlabId)).toHaveLength(1);
    });

    it('a person posting an automatic suggestion by hand gets no automatic line', async () => {
      const { project, gitlabId } = await gitlabCase('auto-post-by-hand', [[2, 'high']]);
      await runAutoFix();
      await runLlm();
      // The automatic post finds auto-fix off and posts nothing; a person then posts it.
      await configure({ autoFix: { ...DEFAULT_AUTO_FIX, enabled: false } });
      await runScm();
      const [row] = await fixRows(project.id);
      expect(row).toMatchObject({ userId: null, post: { status: 'failed' } });
      expect(aiFixThreads(gitlabId)).toHaveLength(0);
      const posted = await h.ctx.app.inject({
        method: 'POST',
        url: `/api/v0/ai-requests/${row!.id}/post`,
        headers: h.orgAdmin.headers,
        payload: {},
      });
      expect(posted.statusCode, posted.body).toBe(202);
      await runScm();
      const [thread] = aiFixThreads(gitlabId);
      const body = thread!.notes[0]!.body.split('\n');
      expect(body[1]).toMatch(/^\*\*AI-generated fix suggestion\*\*/);
      expect(body).not.toContain(AUTO_LINE);
    });
  });

  it('keeps the cap after a job that failed midway: it is not retried', async () => {
    await configure({ autoFix: { enabled: true, minSeverity: 'high', maxPerAnalysis: 2 } });
    const { project } = await gitlabCase('auto-retry', ALL_HIGH);
    // The second automatic insert of this project fails, as a database failure would.
    await h.ctx.db.execute(
      sql.raw(`CREATE OR REPLACE FUNCTION test_fail_second_auto() RETURNS trigger AS $$
        BEGIN
          IF NEW.user_id IS NULL AND NEW.project_id = '${project.id}' AND (SELECT count(*)
               FROM llm_requests WHERE user_id IS NULL AND project_id = NEW.project_id) >= 1 THEN
            RAISE EXCEPTION 'injected failure';
          END IF;
          RETURN NEW;
        END $$ LANGUAGE plpgsql`),
    );
    await h.ctx.db.execute(
      sql.raw(`CREATE TRIGGER test_fail_second_auto BEFORE INSERT ON llm_requests
        FOR EACH ROW EXECUTE FUNCTION test_fail_second_auto()`),
    );
    try {
      await runAutoFix();
    } finally {
      await h.ctx.db.execute(sql.raw('DROP TRIGGER test_fail_second_auto ON llm_requests'));
      await h.ctx.db.execute(sql.raw('DROP FUNCTION test_fail_second_auto()'));
    }
    expect(await requestedLines(project.id)).toEqual([2]);
    const [job] = await autoJobs();
    expect(job).toMatchObject({ status: 'dead', maxAttempts: 1 });
    // Nothing runs it again: a retry would ask for two more and break the cap.
    await runAutoFix();
    expect(await requestedLines(project.id)).toEqual([2]);
    // The one dead job this test expects.
    await h.ctx.db.delete(jobs).where(eq(jobs.id, job!.id));
  });

  it('records the automatic request and post as the system actor (ai.requested, ai.fix_posted)', async () => {
    const audit = createAuditRecorder({ log: QUIET_AUDIT_LOG, isActive: () => true });
    const { project } = await gitlabCase('auto-audit', [[2, 'high']]);
    await runAutoFix(autoDeps({ audit }));
    await runLlm({ audit });
    const [row] = await fixRows(project.id);
    const events = await h.ctx.db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.projectId, project.id))
      .orderBy(auditEvents.seq);
    expect(
      events.map((e) => [e.action, e.actorType, e.actorUserId, e.targetId, e.details.requestId]),
    ).toEqual([
      ['ai.requested', 'system', null, row!.issueId, row!.id],
      ['ai.fix_posted', 'system', null, row!.issueId, row!.id],
    ]);
  });

  it('posts nothing when the head moved (not_head)', async () => {
    const { project, gitlabId } = await gitlabCase('auto-moved');
    await runAutoFix();
    await runLlm();
    gitlab.updateMergeRequest(gitlabId, 7, { headSha: NEXT });
    await runScm();
    const rows = await fixRows(project.id);
    expect(rows).toHaveLength(3);
    for (const row of rows)
      expect(row.post).toMatchObject({ status: 'failed', reason: 'not_head' });
    expect(aiFixThreads(gitlabId)).toHaveLength(0);
  });

  it('leaves a person’s own requests alone: they are neither counted as automatic nor posted', async () => {
    const { project, gitlabId } = await gitlabCase('auto-person', [[2, 'high']]);
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, AUTO_FIX_QUEUE));
    const [issue] = await h.ctx.db
      .select({ id: issues.id })
      .from(issues)
      .where(eq(issues.projectId, project.id));
    const asked = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${issue!.id}/ai/fix`,
      headers: h.orgAdmin.headers,
      payload: {},
    });
    expect(asked.statusCode, asked.body).toBe(202);
    await runLlm();
    await runScm();
    // A person's suggestion is posted only when the person clicks.
    expect(aiFixThreads(gitlabId)).toHaveLength(0);
    const [person] = await h.ctx.db
      .select()
      .from(llmRequests)
      .where(and(eq(llmRequests.projectId, project.id), isNull(llmRequests.userId)));
    expect(person).toBeUndefined();
  });
});
