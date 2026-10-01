import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createFakeGitHub, type FakeGitHub } from '../../../test/fake-github';
import {
  githubConnection,
  githubDeps,
  githubTestConfig,
  mappedGitHubProject,
  pullRequestReport,
} from '../../../test/github';
import { createIngestHarness, type IngestHarness } from '../../../test/ingest';
import { engine, file, finding } from '../../../test/reports';
import { queuedDecorations, runDecorations, silentLogger } from '../../../test/scm';
import { analyses, branches, issues } from '../../db/schema';
import { gateHandlers } from '../../gates/reevaluate';
import { runUntilIdle } from '../../queue/worker';
import { markerOf } from '../markdown';

const HEAD = '1'.repeat(40);
type GateLogger = NonNullable<Parameters<typeof gateHandlers>[0]['logger']>;

describe('a false positive re-decorates the pull request (github.md §8, G5)', () => {
  let h: IngestHarness;
  let fake: FakeGitHub;
  const runGateJobs = (logger: GateLogger = silentLogger) =>
    runUntilIdle(h.ctx.db, gateHandlers({ db: h.ctx.db, logger }), silentLogger);

  /** The open issue of the project's pull request branch, marked a false positive through the API. */
  async function falsePositive(projectId: string): Promise<string> {
    const [pr] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, projectId), eq(branches.kind, 'merge_request')));
    const [issue] = await h.ctx.db
      .select()
      .from(issues)
      .where(and(eq(issues.branchId, pr!.id), eq(issues.status, 'open')));
    const transition = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/issues/${issue!.id}/transition`,
      headers: h.orgAdmin.headers,
      payload: { to: 'false_positive', comment: 'intended' },
    });
    expect(transition.statusCode, transition.body).toBe(200);
    return pr!.id;
  }

  beforeAll(async () => {
    fake = await createFakeGitHub();
    fake.addRepository({ id: 424242, owner: 'acme', name: 'api', installationId: 777 });
    fake.addPull(424242, {
      number: 7,
      title: 'x',
      state: 'open',
      headSha: HEAD,
      baseSha: 'b'.repeat(40),
      files: [{ filename: 'src/a.ts', patch: '@@ -1,2 +1,5 @@\n a\n b\n+c\n+d\n+e' }],
    });
    fake.addRepository({ id: 434343, owner: 'acme', name: 'web', installationId: 777 });
    fake.addPull(434343, {
      number: 8,
      title: 'y',
      state: 'open',
      headSha: HEAD,
      baseSha: 'b'.repeat(40),
      files: [{ filename: 'src/a.ts', patch: '@@ -1,2 +1,5 @@\n a\n b\n+c\n+d\n+e' }],
    });
    h = await createIngestHarness({ config: githubTestConfig(fake) });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });

  it('turns the check run to success without the annotation, and edits the summary, without a scan', async () => {
    const connectionId = await githubConnection(h, fake);
    const project = await mappedGitHubProject(h, fake, 'gh/fp', 'acme/api', { connectionId });
    await project.ingestOk(
      pullRequestReport(7, HEAD, {
        projectKey: project.key,
        engines: [engine('eslint')],
        files: [file('src/a.ts', { newLines: [[1, 60]] })],
        findings: [finding({ path: 'src/a.ts', line: 3 })],
      }),
    );
    await runDecorations(h, githubDeps(h));
    expect(fake.checkRuns.at(-1)).toMatchObject({
      conclusion: 'failure',
      annotations: [expect.objectContaining({ start_line: 3 })],
    });

    await falsePositive(project.id);
    await runGateJobs();
    await runDecorations(h, githubDeps(h));
    expect(fake.checkRuns.at(-1)).toMatchObject({ conclusion: 'success', annotations: [] });
    const summary = fake.comments.find((c) => markerOf(c.body)?.kind === 'summary');
    expect(summary?.body).toContain('### ✅ Qualor: quality gate passed');

    fake.clearRequests();
    await runGateJobs();
    await runDecorations(h, githubDeps(h));
    // Nothing changed: only reads (and a fresh installation token: each githubDeps has its own cache).
    expect(
      fake.requests.filter((r) => r.method !== 'GET' && !r.path.endsWith('/access_tokens')),
    ).toEqual([]);
  });

  it('re-evaluates, but does not decorate again, an analysis whose GitHub context was not sent (older CLI, ruling C1)', async () => {
    const connectionId = await githubConnection(h, fake);
    const project = await mappedGitHubProject(h, fake, 'gh/old-cli', 'acme/web', { connectionId });
    const report = pullRequestReport(8, HEAD, {
      projectKey: project.key,
      engines: [engine('eslint')],
      files: [file('src/a.ts', { newLines: [[1, 60]] })],
      findings: [finding({ path: 'src/a.ts', line: 3 })],
    });
    // A CLI from before `scm.github`: provider "github", no GitHub context at all.
    const { github: omitted, ...scm } = report.scm;
    expect(omitted).toBeDefined();
    await project.ingestOk({ ...report, scm });
    const [stored] = await h.ctx.db
      .select({ scmContext: analyses.scmContext })
      .from(analyses)
      .innerJoin(branches, eq(branches.lastAnalysisId, analyses.id))
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    expect(stored?.scmContext).toMatchObject({ provider: 'github' });
    expect(stored?.scmContext).not.toHaveProperty('github');
    await runDecorations(h, githubDeps(h));

    const branchId = await falsePositive(project.id);
    const warnings: { details: unknown; message: string }[] = [];
    await runGateJobs({
      ...silentLogger,
      warn: (details: unknown, message?: string) => {
        warnings.push({ details, message: message ?? '' });
      },
    });
    const [analysis] = await h.ctx.db
      .select({ gateStatus: analyses.gateStatus })
      .from(analyses)
      .innerJoin(branches, eq(branches.lastAnalysisId, analyses.id))
      .where(eq(branches.id, branchId));
    expect(analysis?.gateStatus).toBe('passed');
    expect(await queuedDecorations(h)).toEqual([]);
    expect(warnings).toEqual([
      {
        details: expect.objectContaining({ branchId }) as unknown,
        message: expect.stringContaining('not decorated again on GitHub') as unknown as string,
      },
    ]);
  });
});
