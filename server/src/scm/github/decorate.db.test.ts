import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitHub, githubShape, type FakeGitHub } from '../../../test/fake-github';
import {
  githubConnection,
  githubDeps,
  githubTestConfig,
  mappedGitHubProject,
  pullRequestReport,
} from '../../../test/github';
import { createIngestHarness, type IngestHarness } from '../../../test/ingest';
import { engine, file, finding, reportWith } from '../../../test/reports';
import { PUBLIC_URL, queuedDecorations, runDecorations } from '../../../test/scm';
import { encryptionKey, encryptSecret } from '../../crypto/secrets';
import { analyses, branches, scmConnections } from '../../db/schema';
import { SCM_TOKEN_AAD } from '../connections';
import { markerOf } from '../markdown';
import { enqueueDecoration } from '../queue';
import { statusName } from '../render';
import { annotationsDigest, parseCheckRunExternalId } from './render';

const HEAD = '1'.repeat(40);
const PATCH = '@@ -1,2 +1,5 @@\n a\n b\n+c\n+d\n+e';

describe('GitHub decoration (github.md §5–§6)', () => {
  let h: IngestHarness;
  let fake: FakeGitHub;
  let nextRepo = 1000;
  let day = 1;
  let connectionId: string;

  /** A mapped project on its own repository with an open pull request #7 at HEAD. */
  const setup = async (
    key: string,
    options: {
      files?: { filename: string; patch?: string }[];
      repo?: { id: number; name: string };
    } = {},
  ) => {
    const repo = options.repo ?? { id: nextRepo++, name: key.replace(/\W/g, '-') };
    if (!options.repo) {
      fake.addRepository({ id: repo.id, owner: 'acme', name: repo.name, installationId: 777 });
      fake.addPull(repo.id, {
        number: 7,
        title: 'Refunds @all',
        state: 'open',
        headSha: HEAD,
        baseSha: 'b'.repeat(40),
        files: options.files ?? [{ filename: 'src/a.ts', patch: PATCH }],
      });
    }
    const project = await mappedGitHubProject(h, fake, key, `acme/${repo.name}`, { connectionId });
    const ingest = (
      lines: number[],
      github: NonNullable<Parameters<typeof pullRequestReport>[2]>['github'] = {
        repositoryId: String(repo.id),
        checkout: 'head',
      },
      revision = HEAD,
    ) =>
      project.ingestOk(
        pullRequestReport(7, revision, {
          projectKey: project.key,
          analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
          engines: [engine('eslint')],
          files: [file('src/a.ts', { newLines: [[1, 60]] })],
          findings: lines.map((line) => finding({ path: 'src/a.ts', line })),
          github,
        }),
      );
    return { project, repo, ingest };
  };
  const runsOf = (repoId: number) => fake.checkRuns.filter((r) => r.repoId === repoId);
  const newestRun = (repoId: number) => runsOf(repoId).at(-1);
  const summaries = (repoId: number) =>
    fake.comments.filter((c) => c.repoId === repoId && markerOf(c.body)?.kind === 'summary');
  /** Writes to the repository (an installation token request is not one: it changes nothing). */
  const writes = () =>
    fake.requests
      .filter((r) => r.method !== 'GET' && !r.path.endsWith('/access_tokens'))
      .map((r) => `${r.method} ${r.path}`);

  /** Enqueues the decoration of `analysisId` again, as its ingestion did: the same job. */
  const enqueueAgain = async (analysisId: string, repoId: number) => {
    const [analysis] = await h.ctx.db
      .select({ branchId: analyses.branchId })
      .from(analyses)
      .where(eq(analyses.id, analysisId));
    await enqueueDecoration(h.ctx.db, {
      analysisId,
      branchId: analysis!.branchId!,
      gitlab: null,
      github: { repositoryId: String(repoId), checkout: 'head' },
    });
  };

  beforeAll(async () => {
    fake = await createFakeGitHub();
    h = await createIngestHarness({ config: githubTestConfig(fake) });
    connectionId = await githubConnection(h, fake);
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(() => fake.clearRequests());

  it('sets a check run on a main-branch analysis, with its name, verdict and link', async () => {
    const repoId = nextRepo++;
    fake.addRepository({ id: repoId, owner: 'acme', name: 'main-only', installationId: 777 });
    const project = await mappedGitHubProject(h, fake, 'gh/main', 'acme/main-only', {
      connectionId,
    });
    const report = reportWith({ projectKey: project.key, revision: 'c'.repeat(40) });
    await project.ingestOk({
      ...report,
      scm: { ...report.scm, provider: 'github', github: { repositoryId: String(repoId) } },
    });
    expect(await runDecorations(h, githubDeps(h))).toBe(1);
    const [main] = await h.ctx.db.select().from(branches).where(eq(branches.projectId, project.id));
    expect(runsOf(repoId)).toEqual([
      expect.objectContaining({
        name: statusName(project.key),
        headSha: 'c'.repeat(40),
        conclusion: 'failure',
        title: 'Quality gate failed: new_issues 1 > 0',
        detailsUrl: `${PUBLIC_URL}/projects/${project.id}/branches/${main!.id}`,
        annotations: [],
      }),
    ]);
    expect(runsOf(repoId)[0]?.summary?.startsWith('### ❌ Qualor: quality gate failed')).toBe(true);
    expect(fake.comments.filter((c) => c.repoId === repoId)).toEqual([]);
  });

  it('annotates new issues on added lines, posts one summary, and a rerun only reads', async () => {
    const { repo, ingest } = await setup('gh/pr');
    const analysisId = await ingest([1, 3, 4]); // line 1 is new code for Qualor, but not an added line of the diff
    await runDecorations(h, githubDeps(h));
    const run = newestRun(repo.id)!;
    expect(run.annotations.map((a) => a.start_line).sort()).toEqual([3, 4]);
    expect(run.annotations[0]).toMatchObject({ path: 'src/a.ts', annotation_level: 'warning' });
    expect(parseCheckRunExternalId(run.externalId)).not.toBeNull();
    expect(summaries(repo.id)).toHaveLength(1);
    expect(summaries(repo.id)[0]?.body).toContain(
      '2 new issues are annotated inline; 1 could not be placed on the diff.',
    );
    expect(summaries(repo.id)[0]?.user.login).toBe(`${fake.slug}[bot]`);
    // The same job again (github.md §11 #1): nothing but reads.
    fake.clearRequests();
    await enqueueAgain(analysisId, repo.id);
    await runDecorations(h, githubDeps(h));
    expect(writes()).toEqual([]);
    // A new analysis with the same result: only the check run's analysis id moves (§6.1, a PATCH).
    fake.clearRequests();
    await ingest([1, 3, 4]);
    await runDecorations(h, githubDeps(h));
    expect(writes()).toEqual([`PATCH /repos/acme/${repo.name}/check-runs/${run.id}`]);
    expect(runsOf(repo.id)).toHaveLength(1);
  });

  it('sends tied annotations in one order, so the same job again keeps the check run', async () => {
    const { project, repo } = await setup('gh/tied');
    // Two issues of the same severity on the same line, from two rules.
    const analysisId = await project.ingestOk(
      pullRequestReport(7, HEAD, {
        projectKey: project.key,
        analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
        engines: [engine('eslint')],
        files: [file('src/a.ts', { newLines: [[1, 60]] })],
        findings: ['no-debugger', 'no-console'].map((ruleId) =>
          finding({ path: 'src/a.ts', line: 3, ruleId }),
        ),
        github: { repositoryId: String(repo.id), checkout: 'head' },
      }),
    );
    await runDecorations(h, githubDeps(h));
    expect(newestRun(repo.id)?.annotations.map((a) => a.title)).toEqual([
      'Medium · maintainability · eslint:no-console',
      'Medium · maintainability · eslint:no-debugger',
    ]);
    fake.clearRequests();
    await enqueueAgain(analysisId, repo.id);
    await runDecorations(h, githubDeps(h));
    expect(writes()).toEqual([]);
    expect(runsOf(repo.id)).toHaveLength(1);
  });

  it('links each rule to its live documentation in annotations, the check run and the summary', async () => {
    const { project, repo } = await setup('gh/rule-links');
    const dead = 'https://rules.sonarsource.com/javascript/RSPEC-1871';
    const live =
      'https://sonarcloud.io/organizations/sonarsource/rules?open=javascript%3AS1871&rule_key=javascript%3AS1871';
    const ingest = () =>
      project.ingestOk(
        pullRequestReport(7, HEAD, {
          projectKey: project.key,
          analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
          engines: [engine('eslint', [{ id: 'no-alert', helpUri: dead }])],
          files: [file('src/a.ts', { newLines: [[1, 60]] })],
          findings: [finding({ path: 'src/a.ts', line: 3, ruleId: 'no-alert' })],
          github: { repositoryId: String(repo.id), checkout: 'head' },
        }),
      );
    const analysisId = await ingest();
    await runDecorations(h, githubDeps(h));
    const run = newestRun(repo.id)!;
    expect(run.annotations[0]?.['message']).toContain(`\n\nRule: ${live}`);
    expect(run.summary).toContain(`[\` eslint:no-alert \`](${live})`);
    expect(summaries(repo.id)[0]?.body).toContain(`[\` eslint:no-alert \`](${live})`);
    // The same job again changes nothing: the bodies and the digest are the same.
    fake.clearRequests();
    await enqueueAgain(analysisId, repo.id);
    await runDecorations(h, githubDeps(h));
    expect(writes()).toEqual([]);
  });

  it('replaces the check run when an issue is fixed, and edits the summary in place', async () => {
    const { repo, ingest } = await setup('gh/fix');
    await ingest([3, 4]);
    await runDecorations(h, githubDeps(h));
    const commentId = summaries(repo.id)[0]?.id;
    await ingest([3]);
    await runDecorations(h, githubDeps(h));
    expect(runsOf(repo.id)).toHaveLength(2);
    expect(newestRun(repo.id)?.annotations.map((a) => a.start_line)).toEqual([3]);
    expect(summaries(repo.id).map((c) => c.id)).toEqual([commentId]);
    expect(summaries(repo.id)[0]?.body).toContain('1 new issue is annotated inline.');
  });

  it('annotates nothing for a merge-commit checkout or a stale head, and says why', async () => {
    const { repo, ingest } = await setup('gh/merge');
    await ingest([3], { repositoryId: String(repo.id), checkout: 'other' });
    await runDecorations(h, githubDeps(h));
    expect(newestRun(repo.id)?.annotations).toEqual([]);
    expect(summaries(repo.id)[0]?.body).toContain(
      'No inline annotations: the workflow analysed a commit other than',
    );
    fake.updatePull(repo.id, 7, { headSha: '2'.repeat(40) });
    await ingest([3]);
    await runDecorations(h, githubDeps(h));
    expect(summaries(repo.id)[0]?.body).toContain(
      'Inline annotations wait for the analysis of the pull request’s latest commit.',
    );
  });

  it('counts issues on a file without a patch as not placed', async () => {
    const { repo, ingest } = await setup('gh/binary', { files: [{ filename: 'src/a.ts' }] });
    await ingest([3]);
    await runDecorations(h, githubDeps(h));
    expect(newestRun(repo.id)?.annotations).toEqual([]);
    expect(summaries(repo.id)[0]?.body).toContain(
      '0 new issues are annotated inline; 1 could not be placed on the diff.',
    );
  });

  it('keeps one check run and one summary per Qualor project of a monorepo', async () => {
    const first = await setup('gh/mono-a');
    const second = await setup('gh/mono-b', { repo: first.repo });
    await first.ingest([3]);
    await second.ingest([4]);
    await runDecorations(h, githubDeps(h));
    expect(new Set(runsOf(first.repo.id).map((r) => r.name))).toEqual(
      new Set([statusName(first.project.key), statusName(second.project.key)]),
    );
    expect(summaries(first.repo.id).map((c) => markerOf(c.body))).toEqual(
      expect.arrayContaining([
        { kind: 'summary', projectId: first.project.id },
        { kind: 'summary', projectId: second.project.id },
      ]),
    );
  });

  it('never edits a person’s comment that carries a Qualor marker', async () => {
    const { project, repo, ingest } = await setup('gh/person');
    fake.addComment(repo.id, 7, {
      body: `<!-- qualor:summary ${project.id} -->\nI copied this`,
      login: 'dev',
    });
    await ingest([3]);
    await runDecorations(h, githubDeps(h));
    expect(fake.comments.find((c) => c.user.login === 'dev')?.body).toBe(
      `<!-- qualor:summary ${project.id} -->\nI copied this`,
    );
    expect(summaries(repo.id).filter((c) => c.user.type === 'Bot')).toHaveLength(1);
  });

  it('stops without retry when the workflow’s repository is not the mapped one', async () => {
    const { ingest } = await setup('gh/mismatch');
    await ingest([3], { repositoryId: '1', checkout: 'head' });
    await runDecorations(h, githubDeps(h));
    expect(writes()).toEqual([]);
    expect(await queuedDecorations(h)).toEqual([]);
  });

  it('waits as long as a secondary rate limit says', async () => {
    const { ingest } = await setup('gh/limited');
    fake.inject('POST', /check-runs$/, {
      status: 403,
      body: { message: 'You have exceeded a secondary rate limit.' },
      headers: { 'retry-after': '90' },
    });
    await ingest([3]);
    await runDecorations(h, githubDeps(h));
    const [retry] = await queuedDecorations(h);
    expect(retry?.payload).toMatchObject({ attempt: 1 });
    // On the database clock: the retry is created and scheduled by it. Node's clock may differ
    // from the database container's by more than a second (the old check against Date.now()
    // failed with 88 904 ms against 89 000).
    const waits = (retry!.runAt.getTime() - retry!.createdAt.getTime()) / 1000;
    expect(waits).toBeGreaterThan(89);
    expect(waits).toBeLessThan(95);
    // The retry (made due now) then decorates; no job is left for the next test.
    await runDecorations(h, githubDeps(h));
    expect(await queuedDecorations(h)).toEqual([]);
  });

  it('recreates the check run without annotations when GitHub refuses them', async () => {
    const { repo, ingest } = await setup('gh/refused');
    fake.inject('POST', /check-runs$/, { status: 422, body: { message: 'Invalid request.' } });
    await ingest([3, 4]);
    await runDecorations(h, githubDeps(h));
    expect(newestRun(repo.id)?.annotations).toEqual([]);
    expect(summaries(repo.id)[0]?.body).toContain(
      '0 new issues are annotated inline; 2 could not be placed on the diff.',
    );
  });

  it('converges after GitHub refuses the annotations for good: a rerun posts nothing (C2)', async () => {
    const { repo, ingest } = await setup('gh/refused-always');
    fake.rejectAnnotations = true;
    try {
      const analysisId = await ingest([3, 4]);
      await runDecorations(h, githubDeps(h));
      expect(runsOf(repo.id)).toHaveLength(1);
      const fallback = newestRun(repo.id)!;
      expect(fallback.annotations).toEqual([]);
      // The fallback carries the digest of the annotations it tried, not that of none.
      const digest = parseCheckRunExternalId(fallback.externalId)?.digest;
      expect(digest).toBeDefined();
      expect(digest).not.toBe(annotationsDigest([]));
      const rejected = '0 new issues are annotated inline; 2 could not be placed on the diff.';
      expect(fallback.summary).toContain(rejected);
      // The same job again: nothing but reads, although every annotated POST would be refused.
      fake.clearRequests();
      await enqueueAgain(analysisId, repo.id);
      await runDecorations(h, githubDeps(h));
      expect(writes()).toEqual([]);
      // A new analysis with the same result: one PATCH of the fallback, which keeps its text.
      fake.clearRequests();
      await ingest([3, 4]);
      await runDecorations(h, githubDeps(h));
      expect(writes()).toEqual([`PATCH /repos/acme/${repo.name}/check-runs/${fallback.id}`]);
      expect(runsOf(repo.id)).toHaveLength(1);
      expect(newestRun(repo.id)?.summary).toContain(rejected);
      expect(summaries(repo.id)[0]?.body).toContain(rejected);
    } finally {
      fake.rejectAnnotations = false;
    }
  });

  it('keeps the annotations and their count in the summary when the pull request part fails', async () => {
    const { repo, ingest } = await setup('gh/pr-fails');
    await ingest([3, 4]);
    await runDecorations(h, githubDeps(h));
    const run = newestRun(repo.id)!;
    expect(run.summary).toContain('2 new issues are annotated inline.');
    fake.inject('GET', new RegExp(`^/repos/acme/${repo.name}/pulls/7$`), {
      status: 404,
      body: { message: 'Not Found' },
    });
    fake.clearRequests();
    await ingest([3, 4]);
    await runDecorations(h, githubDeps(h));
    expect(runsOf(repo.id)).toHaveLength(1);
    expect(newestRun(repo.id)?.annotations).toHaveLength(2);
    expect(newestRun(repo.id)?.summary).toContain('2 new issues are annotated inline.');
    expect(writes()).toEqual([`PATCH /repos/acme/${repo.name}/check-runs/${run.id}`]);
  });

  it('leaves the annotations alone when it decorates an analysis that is not the latest', async () => {
    const { repo, ingest } = await setup('gh/older');
    const older = await ingest([3, 4]);
    await runDecorations(h, githubDeps(h));
    expect(newestRun(repo.id)?.annotations).toHaveLength(2);
    fake.updatePull(repo.id, 7, { headSha: '2'.repeat(40) });
    await ingest([3, 4], undefined, '2'.repeat(40));
    await runDecorations(h, githubDeps(h));
    const onHead = runsOf(repo.id).filter((r) => r.headSha === HEAD);
    expect(onHead).toHaveLength(1);
    fake.clearRequests();
    await enqueueAgain(older, repo.id);
    await runDecorations(h, githubDeps(h));
    expect(writes().filter((w) => w.startsWith('POST'))).toEqual([]);
    expect(runsOf(repo.id).filter((r) => r.headSha === HEAD)).toHaveLength(1);
    expect(onHead[0]?.annotations).toHaveLength(2);
  });

  it('never edits another App’s bot comment that carries a Qualor marker', async () => {
    const { project, repo, ingest } = await setup('gh/other-bot');
    const foreign = `<!-- qualor:summary ${project.id} -->\nAnother App wrote this`;
    fake.addComment(repo.id, 7, { body: foreign, login: 'other-app[bot]', type: 'Bot' });
    await ingest([3]);
    await runDecorations(h, githubDeps(h));
    expect(fake.comments.find((c) => c.user.login === 'other-app[bot]')?.body).toBe(foreign);
    expect(summaries(repo.id).filter((c) => c.user.login === `${fake.slug}[bot]`)).toHaveLength(1);
  });

  it('never touches another App’s check run of the same name', async () => {
    const { project, repo, ingest } = await setup('gh/other-run');
    const analysisId = await ingest([3]);
    fake.checkRuns.push({
      id: 900_000 + repo.id,
      repoId: repo.id,
      appId: 1,
      name: statusName(project.key),
      headSha: HEAD,
      conclusion: 'success',
      externalId: `qualor:v1:${analysisId}:${annotationsDigest([])}`,
      detailsUrl: null,
      title: 'theirs',
      summary: 'theirs',
      annotations: [],
    });
    fake.clearRequests();
    await runDecorations(h, githubDeps(h));
    const theirs = runsOf(repo.id).find((r) => r.appId === 1);
    expect(theirs).toMatchObject({ title: 'theirs', summary: 'theirs', conclusion: 'success' });
    expect(writes()).not.toContain(`PATCH /repos/acme/${repo.name}/check-runs/${theirs!.id}`);
    expect(runsOf(repo.id).filter((r) => r.appId === fake.appId)).toHaveLength(1);
  });

  it('creates no summary when the comment list is longer than it reads', async () => {
    const { repo, ingest } = await setup('gh/many-comments');
    fake.inject(
      'GET',
      new RegExp(`^/repos/acme/${repo.name}/issues/7/comments`),
      ...Array.from({ length: 50 }, () => ({
        status: 200,
        body: [],
        headers: { link: '<https://x.example/?page=2>; rel="next"' },
      })),
    );
    await ingest([3]);
    fake.clearRequests();
    await runDecorations(h, githubDeps(h));
    expect(fake.requests.filter((r) => r.path.includes('/issues/7/comments'))).toHaveLength(50);
    expect(writes().filter((w) => w.includes('/comments'))).toEqual([]);
    expect(summaries(repo.id)).toEqual([]);
    expect(runsOf(repo.id)).toHaveLength(1);
  });

  it('records the pull request link only on the connection’s web base (GH13)', async () => {
    const { project, repo, ingest } = await setup('gh/links');
    await ingest([3]);
    await runDecorations(h, githubDeps(h));
    const branchOf = async () =>
      (
        await h.ctx.db
          .select({ mrUrl: branches.mrUrl, mrTitle: branches.mrTitle })
          .from(branches)
          .where(eq(branches.projectId, project.id))
      ).find((b) => b.mrTitle !== null);
    const webBase = fake.url.slice(0, -'/api/v3'.length);
    expect((await branchOf())?.mrUrl).toBe(`${webBase}/acme/${repo.name}/pull/7`);
    fake.inject('GET', new RegExp(`^/repos/acme/${repo.name}/pulls/7$`), {
      status: 200,
      body: {
        ...githubShape('pull_request'),
        number: 7,
        state: 'open',
        title: 'Refunds @all',
        html_url: `https://elsewhere.example/acme/${repo.name}/pull/7`,
        head: { ref: 'feature/x', sha: HEAD, label: 'x' },
        base: { ref: 'main', sha: 'b'.repeat(40), label: 'y' },
      },
    });
    await ingest([3]);
    await runDecorations(h, githubDeps(h));
    expect(await branchOf()).toMatchObject({ mrTitle: 'Refunds @all', mrUrl: null });
  });

  it('sets only the check run of a closed pull request, and of one GitHub does not have', async () => {
    const closed = await setup('gh/closed');
    fake.updatePull(closed.repo.id, 7, { state: 'closed' });
    await closed.ingest([3]);
    const gone = await setup('gh/gone');
    await gone.project.ingestOk(
      pullRequestReport(99, HEAD, {
        projectKey: gone.project.key,
        github: { repositoryId: String(gone.repo.id), checkout: 'head' },
      }),
    );
    await runDecorations(h, githubDeps(h));
    expect(runsOf(closed.repo.id)).toHaveLength(1);
    expect(summaries(closed.repo.id)).toEqual([]);
    expect(runsOf(gone.repo.id)).toHaveLength(1);
    expect(await queuedDecorations(h)).toEqual([]); // a 404 on the pull request is not retried
  });

  it('decorates only a report of its own provider', async () => {
    const { project, repo } = await setup('gh/provider');
    const gitlabReport = reportWith({ projectKey: project.key, revision: 'd'.repeat(40) }); // provider gitlab
    await project.ingestOk(gitlabReport);
    expect(await queuedDecorations(h)).toEqual([]);
    expect(runsOf(repo.id)).toEqual([]);
  });

  it('sends nothing with a private key that no longer decrypts', async () => {
    const own = await githubConnection(h, fake);
    const repoId = nextRepo++;
    fake.addRepository({ id: repoId, owner: 'acme', name: 'rotated', installationId: 777 });
    const project = await mappedGitHubProject(h, fake, 'gh/rotated', 'acme/rotated', {
      connectionId: own,
    });
    await h.ctx.db
      .update(scmConnections)
      .set({ tokenEnc: encryptSecret(encryptionKey('z'.repeat(32)), 'x', SCM_TOKEN_AAD) })
      .where(eq(scmConnections.id, own));
    const report = reportWith({ projectKey: project.key, revision: 'e'.repeat(40) });
    await project.ingestOk({ ...report, scm: { ...report.scm, provider: 'github' } });
    fake.clearRequests();
    await runDecorations(h, githubDeps(h));
    expect(fake.requests).toEqual([]);
  });
});
