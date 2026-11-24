import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { azureCommitId, seedAzurePullRequest } from '../../../test/azure';
import {
  createFakeAzureDevOps,
  type FakeAzureChange,
  type FakeAzureComment,
  type FakeAzureDevOps,
  type FakeAzureThread,
} from '../../../test/fake-azure-devops';
import { createIngestHarness, type IngestHarness } from '../../../test/ingest';
import { engine, file, finding, reportWith } from '../../../test/reports';
import { seedAiIssue, storeTestSnapshot } from '../../../test/review';
import { decorationDeps, PUBLIC_URL, runDecorations } from '../../../test/scm';
import {
  branches,
  issues,
  jobs,
  projects,
  reviewFindings,
  reviewRuns,
  type AiCategory,
} from '../../db/schema';
import { decorateAnalysis } from '../decorate';
import { MAX_FIXED_NOTES } from '../inline';
import { enqueueDecoration } from '../queue';
import { fixedMarker, issueMarker, markerOf } from '../markdown';
import { reopenedNote, resolvedNote } from '../render';
import { parseInternalHosts } from '../url';
import { MAX_AZURE_THREAD_UPDATES } from './threads';

const PR = 7;
const NOT_UPDATED = 'Inline comments could not be updated this time.';

interface At {
  path: string;
  line: number;
}

describe('Azure DevOps inline threads (Azure sub-plan 4, task 6)', () => {
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

  /**
   * A project on a repository of its own with pull request #7: `files` as the head holds them,
   * `base` as the common commit holds them, `changes` what the iteration lists (default: the keys
   * of `files`).
   */
  const setup = async (
    key: string,
    options: {
      files?: Record<string, string | Buffer>;
      base?: Record<string, string | Buffer>;
      changes?: FakeAzureChange[];
    } = {},
  ) => {
    const repository = fake.addRepository({ name: `t${repoNumber++}`, projectName: 'Payments' });
    const sourceCommit = azureCommitId(`${key}-head`);
    const seeded = seedAzurePullRequest(fake, repository.id, {
      pullRequest: { id: PR, statusPolicy: true },
      sourceCommit,
      ...(options.files ? { files: options.files } : {}),
      ...(options.changes ? { changes: options.changes } : {}),
    });
    for (const [path, content] of Object.entries(options.base ?? {})) {
      fake.addFile(repository.id, seeded.baseCommit, path, content);
    }
    const project = await h.project(key);
    await h.ctx.db
      .update(projects)
      .set({ scmConnectionId: connectionId, scmProjectRef: repository.id })
      .where(eq(projects.id, project.id));
    const ingest = (
      findings: At[],
      opts: { checkout?: 'head' | 'other'; revision?: string } = {},
    ) => {
      const paths = [...new Set(findings.map((f) => f.path))];
      const report = reportWith({
        projectKey: project.key,
        branch: 'feature/x',
        mergeRequest: { id: String(PR), targetBranch: 'main', sourceBranch: 'feature/x' },
        revision: opts.revision ?? sourceCommit,
        baseline: { revision: 'b'.repeat(40), kind: 'merge_base', status: 'ok' },
        analysisDate: new Date(Date.UTC(2026, 10, 1, 10) + 86_400_000 * day++).toISOString(),
        engines: [engine('eslint')],
        files: paths.map((path) => file(path, { newLines: [[1, 500]] })),
        findings: findings.map((f) => finding(f)),
      });
      return project.ingestOk({
        ...report,
        scm: {
          ...report.scm,
          provider: 'azure',
          azure: { repositoryId: repository.id, checkout: opts.checkout ?? 'head' },
        },
      });
    };
    const pr = () => fake.pullRequest(repository.id, PR);
    /** Qualor's threads on the pull request: their first comment carries an issue marker. */
    const ownThreads = () =>
      pr().threads.filter((t) => markerOf(t.comments[0]?.content ?? '')?.kind === 'issue');
    const issueRows = () =>
      h.ctx.db
        .select({ id: issues.id, path: issues.path, line: issues.startLine, status: issues.status })
        .from(issues)
        .where(eq(issues.projectId, project.id));
    const issueAt = async (path: string, line: number) => {
      const row = (await issueRows()).find((r) => r.path === path && r.line === line);
      if (!row) throw new Error(`no issue at ${path}:${line}`);
      return row;
    };
    const summary = () =>
      pr().threads.find((t) => markerOf(t.comments[0]?.content ?? '')?.kind === 'summary')
        ?.comments[0]?.content ?? '';
    return {
      project,
      repository,
      ...seeded,
      ingest,
      pr,
      ownThreads,
      issueRows,
      issueAt,
      summary,
      projectId: project.id,
    };
  };

  const requestsOf = () =>
    fake.requests.map((r) => `${r.method} ${r.path.replace(/^.*\/_apis\//, '')}`);
  const writesOf = () => requestsOf().filter((r) => !r.startsWith('GET'));
  /** Writes to a thread (not to the summary's comment). */
  const threadWrites = () =>
    writesOf().filter((w) => /\/threads\/\d+/.test(w) && !/comments\/1$/.test(w));
  const decorate = () => runDecorations(h, decorationDeps(h));
  const person = (threadId: number, content = 'A person replied'): FakeAzureComment => ({
    id: threadId * 100,
    authorId: 'a-person',
    content,
    commentType: 'text',
    parentCommentId: 0,
    publishedDate: '2026-11-23T10:00:00Z',
    isDeleted: false,
  });
  const lastComment = (t: FakeAzureThread) => t.comments[t.comments.length - 1]?.content ?? '';

  // Head: lines 1-2 are context (also in the base), 3-5 are added.
  const BASE_A = 'one\ntwo\n';
  const HEAD_A = 'one\ntwo\nthree\nfour\nfive\n';

  it('creates one active thread on an added line, selecting the whole line, with the issue marker', async () => {
    const s = await setup('thr/placed', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const [thread] = s.ownThreads();
    const issue = await s.issueAt('src/a.ts', 3);
    expect(s.ownThreads()).toHaveLength(1);
    expect(thread).toMatchObject({ status: 'active', filePath: 'src/a.ts', line: 3 });
    expect(thread?.threadContext).toEqual({
      filePath: '/src/a.ts',
      rightFileStart: { line: 3, offset: 1 },
      rightFileEnd: { line: 3, offset: 'three'.length + 1 },
    });
    expect(thread?.comments).toHaveLength(1);
    expect(thread?.comments[0]?.content.split('\n')[0]).toBe(issueMarker(issue.id));
    expect(s.summary()).toContain('1 new issue is commented inline');
    // Decorated again: nothing new is written for the thread.
    fake.clearRequests();
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    expect(s.ownThreads()).toHaveLength(1);
    expect(writesOf().filter((w) => /threads$/.test(w))).toEqual([]);
  });

  it('counts a context line, a deleted file, a binary file and a file over 1 MiB as unplaced', async () => {
    const big = `${'x'.repeat(100)}\n`.repeat(11_000);
    const s = await setup('thr/unplaced', {
      files: {
        'src/a.ts': HEAD_A,
        'src/bin.ts': Buffer.from([0x61, 0x00, 0x62, 0x0a]),
        'src/big.ts': big,
      },
      base: { 'src/a.ts': BASE_A, 'src/gone.ts': 'x\n' },
      changes: [
        { path: 'src/a.ts' },
        { path: 'src/gone.ts', changeType: 'delete' },
        { path: 'src/bin.ts', changeType: 'add' },
        { path: 'src/big.ts', changeType: 'add' },
      ],
    });
    await s.ingest([
      { path: 'src/a.ts', line: 1 }, // a context line
      { path: 'src/a.ts', line: 4 }, // placed
      { path: 'src/gone.ts', line: 1 },
      { path: 'src/bin.ts', line: 1 },
      { path: 'src/big.ts', line: 2 },
      { path: 'src/untouched.ts', line: 1 }, // not in the pull request's changes
    ]);
    await decorate();
    expect(s.ownThreads().map((t) => t.line)).toEqual([4]);
    expect(s.summary()).toContain(
      '1 new issue is commented inline; 5 could not be placed on the diff',
    );
  });

  it('diffs a renamed file against its original path', async () => {
    const s = await setup('thr/rename', {
      files: { 'src/new.ts': HEAD_A },
      base: { 'src/old.ts': BASE_A },
      changes: [{ path: 'src/new.ts', originalPath: 'src/old.ts', changeType: 'rename, edit' }],
    });
    await s.ingest([
      { path: 'src/new.ts', line: 2 },
      { path: 'src/new.ts', line: 5 },
    ]);
    await decorate();
    expect(s.ownThreads().map((t) => t.line)).toEqual([5]);
  });

  it('puts nothing on a file whose base differs only in line endings', async () => {
    const s = await setup('thr/crlf', {
      files: { 'src/a.ts': 'one\ntwo\nthree\n' },
      base: { 'src/a.ts': 'one\r\ntwo\r\nthree\r\n' },
    });
    await s.ingest([{ path: 'src/a.ts', line: 2 }]);
    await decorate();
    expect(s.ownThreads()).toEqual([]);
    expect(s.summary()).toContain('1 could not be placed on the diff');
  });

  it('selects a CRLF line without its carriage return', async () => {
    const s = await setup('thr/crlf-head', {
      files: { 'src/a.ts': 'one\r\ntwo\r\nthree\r\n' },
      base: { 'src/a.ts': 'one\r\n' },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    expect(s.ownThreads()[0]?.threadContext).toMatchObject({
      rightFileEnd: { line: 3, offset: 'three'.length + 1 },
    });
  });

  it('resolves a thread when its issue is gone, with Qualor’s fixed comment, and reopens it when the issue returns', async () => {
    const s = await setup('thr/cycle', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const issue = await s.issueAt('src/a.ts', 3);
    const [thread] = s.ownThreads();
    expect(thread?.status).toBe('active');

    await s.ingest([]);
    fake.clearRequests();
    await decorate();
    expect(thread?.status).toBe('fixed');
    expect(thread?.comments).toHaveLength(2);
    expect(lastComment(thread!)).toMatch(
      new RegExp(`^<!-- qualor:fixed ${issue.id} ${s.sourceCommit} -->`),
    );
    expect(lastComment(thread!)).toBe(resolvedNote(issue.id, s.sourceCommit));
    expect(lastComment(thread!)).toContain('The issue is no longer open in the analysis of');
    expect(thread?.comments[1]?.authorId).toBe(thread?.comments[0]?.authorId);
    // The first comment is never edited.
    expect(
      writesOf().some(
        (w) => w.startsWith('PATCH') && w.includes(`/threads/${thread!.id}/comments`),
      ),
    ).toBe(false);
    expect(s.summary()).not.toContain('is commented inline');

    // Decorated again with the issue still gone: nothing is written.
    fake.clearRequests();
    await s.ingest([]);
    await decorate();
    expect(writesOf().filter((w) => /threads\/\d+/.test(w))).toEqual([]);

    // The finding comes back: the same thread is reopened, with Qualor's comment.
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    expect(s.ownThreads()).toHaveLength(1);
    expect(thread?.status).toBe('active');
    expect(thread?.comments).toHaveLength(3);
    expect(lastComment(thread!).split('\n')[0]).toBe(`<!-- qualor:reopened ${issue.id} -->`);
    expect(lastComment(thread!)).toBe(reopenedNote(issue.id, s.sourceCommit));
    expect(s.summary()).toContain('1 new issue is commented inline');
  });

  it('never reopens a thread a person resolved, and still counts its issue', async () => {
    const s = await setup('thr/person', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const [thread] = s.ownThreads();
    thread!.status = 'fixed';
    fake.clearRequests();
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    expect(thread?.status).toBe('fixed');
    expect(thread?.comments).toHaveLength(1);
    expect(s.ownThreads()).toHaveLength(1);
    expect(writesOf().filter((w) => /threads\/\d+/.test(w))).toEqual([]);
    expect(s.summary()).toContain('1 new issue is commented inline');
  });

  it('never reopens a pending thread, whoever wrote its last comment: pending is open, not resolved by Qualor', async () => {
    const s = await setup('thr/pending', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    await s.ingest([]);
    await decorate();
    const [thread] = s.ownThreads();
    // Qualor resolved it: its fixed comment is last, no person replied.
    expect(thread?.status).toBe('fixed');
    // A person sets it Pending, as an open state, and the finding returns.
    thread!.status = 'pending';
    fake.clearRequests();
    const count = thread!.comments.length;
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    expect(thread?.status).toBe('pending');
    expect(thread?.comments).toHaveLength(count);
    expect(threadWrites()).toEqual([]);
    expect(s.ownThreads()).toHaveLength(1);
    expect(s.summary()).toContain('1 new issue is commented inline');
  });

  it('leaves a pending thread of a finding that is gone as it is: Qualor resolves only active threads', async () => {
    const s = await setup('thr/pending-gone', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const [thread] = s.ownThreads();
    thread!.status = 'pending';
    fake.clearRequests();
    await s.ingest([]);
    await decorate();
    expect(thread?.status).toBe('pending');
    expect(thread?.comments).toHaveLength(1);
    expect(threadWrites()).toEqual([]);
  });

  it('writes the fixed note into a pending thread a person replied in, once per revision', async () => {
    const s = await setup('thr/pending-note', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const [thread] = s.ownThreads();
    thread!.comments.push(person(thread!.id));
    thread!.status = 'pending';
    await s.ingest([]);
    await decorate();
    expect(thread?.status).toBe('pending');
    expect(thread?.comments.map((c) => markerOf(c.content)?.kind)).toContain('fixed');
  });

  it('does not take a resolution as Qualor’s once someone commented after its fixed comment', async () => {
    const s = await setup('thr/after', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    await s.ingest([]);
    await decorate();
    const [thread] = s.ownThreads();
    expect(thread?.status).toBe('fixed');
    thread!.comments.push(person(thread!.id, 'works for me'));
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    expect(thread?.status).toBe('fixed');
  });

  it('never reopens a thread a person resolved after Qualor’s fixed note, and still counts its issue', async () => {
    const s = await setup('thr/note-resolved', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const [thread] = s.ownThreads();
    thread!.comments.push(person(thread!.id));
    await s.ingest([]);
    await decorate();
    // Qualor's note is the last comment and the thread is active; the person then resolves it.
    expect(thread?.status).toBe('active');
    expect(markerOf(lastComment(thread!))?.kind).toBe('fixed');
    thread!.status = 'fixed';
    const comments = thread!.comments.length;
    fake.clearRequests();
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    expect(thread?.status).toBe('fixed');
    expect(thread?.comments).toHaveLength(comments);
    expect(threadWrites()).toEqual([]);
    expect(s.summary()).toContain('1 new issue is commented inline');
  });

  it('sends only the status when its resolution failed after the comment, and after a silent reopen', async () => {
    const s = await setup('thr/one-note', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const [thread] = s.ownThreads();
    const fixedComments = () =>
      thread!.comments.filter((c) => markerOf(c.content)?.kind === 'fixed').length;
    // The comment is written, the status change fails.
    fake.inject('PATCH', /\/threads\/\d+$/, { status: 503, body: {} });
    const analysisId = await s.ingest([]);
    const outcome = await decorateOnce(s, analysisId);
    expect(outcome).toMatchObject({ kind: 'failed', retry: true });
    expect(thread?.status).toBe('active');
    expect(fixedComments()).toBe(1);
    // The next job sends the status only.
    await s.ingest([]);
    fake.clearRequests();
    await decorate();
    expect(thread?.status).toBe('fixed');
    expect(fixedComments()).toBe(1);
    expect(threadWrites()).toEqual([expect.stringMatching(/^PATCH .*\/threads\/\d+$/)]);
    // A person reopens it without a word, the issue stays fixed: the status only again.
    thread!.status = 'active';
    await s.ingest([]);
    fake.clearRequests();
    await decorate();
    expect(thread?.status).toBe('fixed');
    expect(fixedComments()).toBe(1);
    expect(thread?.comments).toHaveLength(2);
    expect(threadWrites()).toEqual([expect.stringMatching(/^PATCH .*\/threads\/\d+$/)]);
  });

  const reopenedMarkerOf = (issueId: string) => `<!-- qualor:reopened ${issueId} -->`;

  it('writes the lost reopened comment alone, so a person’s later silent resolution stays', async () => {
    const s = await setup('thr/reopen-lost', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const issue = await s.issueAt('src/a.ts', 3);
    await s.ingest([]);
    await decorate();
    const [thread] = s.ownThreads();
    expect(thread?.status).toBe('fixed');
    // The issue returns: the thread is reopened, and its comment fails.
    fake.inject('POST', /\/threads\/\d+\/comments$/, { status: 503, body: {} });
    const analysisId = await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    expect(await decorateOnce(s, analysisId)).toMatchObject({ kind: 'failed', retry: true });
    expect(thread?.status).toBe('active');
    expect(markerOf(lastComment(thread!))?.kind).toBe('fixed');
    // The next job writes the reopened comment only: no status change.
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    fake.clearRequests();
    await decorate();
    expect(threadWrites()).toEqual([expect.stringMatching(/^POST .*\/threads\/\d+\/comments$/)]);
    expect(thread?.status).toBe('active');
    expect(lastComment(thread!).split('\n')[0]).toBe(reopenedMarkerOf(issue.id));
    expect(s.summary()).toContain('1 new issue is commented inline');
    // A person resolves it without a word: it is theirs, and stays resolved.
    thread!.status = 'fixed';
    const comments = thread!.comments.length;
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    fake.clearRequests();
    await decorate();
    expect(thread?.status).toBe('fixed');
    expect(thread?.comments).toHaveLength(comments);
    expect(threadWrites()).toEqual([]);
  });

  it('writes only the reopened comment when the issue returns after a resolution whose status change failed', async () => {
    const s = await setup('thr/resolve-lost', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const issue = await s.issueAt('src/a.ts', 3);
    const [thread] = s.ownThreads();
    // The fixed comment is written, the status change fails.
    fake.inject('PATCH', /\/threads\/\d+$/, { status: 503, body: {} });
    const analysisId = await s.ingest([]);
    expect(await decorateOnce(s, analysisId)).toMatchObject({ kind: 'failed', retry: true });
    expect(thread?.status).toBe('active');
    expect(markerOf(lastComment(thread!))?.kind).toBe('fixed');
    // The issue returns before a retry: the reopened comment only.
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    fake.clearRequests();
    await decorate();
    expect(threadWrites()).toEqual([expect.stringMatching(/^POST .*\/threads\/\d+\/comments$/)]);
    expect(thread?.status).toBe('active');
    expect(lastComment(thread!).split('\n')[0]).toBe(reopenedMarkerOf(issue.id));
    // Decorated again: nothing more.
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    fake.clearRequests();
    await decorate();
    expect(threadWrites()).toEqual([]);
  });

  it('leaves a thread a person replied in open, with one fixed note per revision', async () => {
    const s = await setup('thr/reply', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const issue = await s.issueAt('src/a.ts', 3);
    const [thread] = s.ownThreads();
    thread!.comments.push(person(thread!.id));
    await s.ingest([]);
    fake.clearRequests();
    await decorate();
    expect(thread?.status).toBe('active');
    expect(thread?.comments).toHaveLength(3);
    expect(lastComment(thread!).split('\n')[0]).toBe(fixedMarker(issue.id, s.sourceCommit));
    expect(writesOf().some((w) => w.startsWith('PATCH') && /threads\/\d+$/.test(w))).toBe(false);
    // Decorated again at the same revision: no second note.
    await s.ingest([]);
    await decorate();
    expect(thread?.comments).toHaveLength(3);
  });

  it('writes at most the bound of fixed notes in a job', async () => {
    const lines = Array.from({ length: MAX_FIXED_NOTES + 1 }, (_, i) => i + 1);
    const s = await setup('thr/notes', {
      files: { 'src/a.ts': 'x\n'.repeat(60) },
      base: { 'src/a.ts': '' },
    });
    await s.ingest(
      lines.map((line) => ({ path: 'src/a.ts', line })),
      { checkout: 'other' },
    );
    await decorate();
    const rows = await s.issueRows();
    for (const row of rows) {
      s.pr().threads.push({
        id: 1000 + row.line!,
        status: 'active',
        filePath: 'src/a.ts',
        line: row.line,
        threadContext: null,
        publishedDate: '2026-11-23T10:00:00Z',
        comments: [
          {
            id: 1,
            authorId: fake.patUser.id,
            content: issueMarker(row.id),
            commentType: 'text',
            parentCommentId: 0,
            publishedDate: '2026-11-23T10:00:00Z',
            isDeleted: false,
          },
          person(1000 + row.line!),
        ],
      });
    }
    await s.ingest([]);
    await decorate();
    const noted = () =>
      s.ownThreads().filter((t) => markerOf(lastComment(t))?.kind === 'fixed').length;
    expect(noted()).toBe(MAX_FIXED_NOTES);
    await s.ingest([]);
    await decorate();
    expect(noted()).toBe(MAX_FIXED_NOTES + 1);
  });

  it('ignores system threads and a second thread of one issue', async () => {
    const s = await setup('thr/ignored', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    const system = fake.addSystemThread(s.repository.id, PR);
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const issue = await s.issueAt('src/a.ts', 3);
    const duplicate = fake.addThread(s.repository.id, PR, {
      filePath: 'src/a.ts',
      line: 3,
      comments: [{ content: issueMarker(issue.id) }],
    });
    await s.ingest([]);
    fake.clearRequests();
    await decorate();
    const [first] = s.ownThreads();
    expect(first?.status).toBe('fixed');
    expect(duplicate.status).toBe('active');
    expect(system.comments).toHaveLength(1);
    expect(writesOf().some((w) => w.includes(`/threads/${system.id}`))).toBe(false);
    expect(writesOf().some((w) => w.includes(`/threads/${duplicate.id}`))).toBe(false);
  });

  it('never touches a thread of another identity that carries an issue marker', async () => {
    const s = await setup('thr/foreign', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    const issue = await s.issueAt('src/a.ts', 3);
    const [own] = s.ownThreads();
    own!.comments[0]!.authorId = 'someone-else';
    await s.ingest([]);
    fake.clearRequests();
    await decorate();
    expect(own?.status).toBe('active');
    expect(own?.comments).toHaveLength(1);
    expect(markerOf(own!.comments[0]!.content)).toEqual({ kind: 'issue', issueId: issue.id });
  });

  it(`does ${MAX_AZURE_THREAD_UPDATES} updates in a job and the rest in the next`, async () => {
    const count = MAX_AZURE_THREAD_UPDATES + 1;
    const s = await setup('thr/bound', {
      files: { 'src/a.ts': 'x\n'.repeat(count + 5) },
      base: { 'src/a.ts': '' },
    });
    await s.ingest(
      Array.from({ length: count }, (_, i) => ({ path: 'src/a.ts', line: i + 1 })),
      { checkout: 'other' },
    );
    await decorate();
    for (const row of await s.issueRows()) {
      fake.addThread(s.repository.id, PR, {
        filePath: 'src/a.ts',
        line: row.line!,
        comments: [{ content: issueMarker(row.id) }],
      });
    }
    await s.ingest([]);
    fake.clearRequests();
    await decorate();
    const status = () => s.ownThreads().filter((t) => t.status === 'fixed').length;
    expect(status()).toBe(MAX_AZURE_THREAD_UPDATES);
    expect(writesOf().filter((w) => /threads\/\d+$/.test(w))).toHaveLength(
      MAX_AZURE_THREAD_UPDATES,
    );
    expect(writesOf().filter((w) => /threads\/\d+\/comments$/.test(w))).toHaveLength(
      MAX_AZURE_THREAD_UPDATES,
    );
    await s.ingest([]);
    await decorate();
    expect(status()).toBe(count);
  });

  it(`counts a lost reopened comment as one of the ${MAX_AZURE_THREAD_UPDATES} updates of a job`, async () => {
    const count = MAX_AZURE_THREAD_UPDATES + 1;
    const s = await setup('thr/note-bound', {
      files: { 'src/a.ts': 'x\n'.repeat(count + 5) },
      base: { 'src/a.ts': '' },
    });
    const findings = Array.from({ length: count }, (_, i) => ({ path: 'src/a.ts', line: i + 1 }));
    await s.ingest(findings, { checkout: 'other' });
    await decorate();
    // Each open issue's active thread ends with Qualor's fixed comment: its reopened one was lost.
    for (const row of await s.issueRows()) {
      fake.addThread(s.repository.id, PR, {
        filePath: 'src/a.ts',
        line: row.line!,
        comments: [
          { content: issueMarker(row.id) },
          { content: `${fixedMarker(row.id, s.sourceCommit)}\nThe issue is no longer open.` },
        ],
      });
    }
    await s.ingest(findings);
    fake.clearRequests();
    await decorate();
    const repaired = () =>
      s.ownThreads().filter((t) => lastComment(t).startsWith('<!-- qualor:reopened ')).length;
    expect(repaired()).toBe(MAX_AZURE_THREAD_UPDATES);
    expect(threadWrites().filter((w) => w.startsWith('PATCH'))).toEqual([]);
    await s.ingest(findings);
    await decorate();
    expect(repaired()).toBe(count);
    expect(s.ownThreads().every((t) => t.status === 'active')).toBe(true);
  });

  it('creates nothing when the changes are cut by their page bound', async () => {
    const changes: FakeAzureChange[] = Array.from({ length: 1001 }, (_, i) => ({
      path: `src/f${i}.ts`,
    }));
    const s = await setup('thr/pages', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
      changes: [{ path: 'src/a.ts' }, ...changes],
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    await decorate();
    expect(s.ownThreads()).toEqual([]);
  });

  it('files beyond the diff bound count as unplaced', async () => {
    const files: Record<string, string> = {};
    const at: At[] = [];
    for (let i = 0; i < 42; i++) {
      files[`src/f${String(i).padStart(2, '0')}.ts`] = 'x\n';
      at.push({ path: `src/f${String(i).padStart(2, '0')}.ts`, line: 1 });
    }
    const s = await setup('thr/files', {
      files,
      changes: Object.keys(files).map((path) => ({ path, changeType: 'add' })),
    });
    await s.ingest(at);
    await decorate();
    // 42 files, but only 40 are read, and the findings of the creation bound are 50 at most.
    expect(s.ownThreads()).toHaveLength(40);
    expect(s.summary()).toContain('40 new issues are commented inline; 2 could not be placed');
  });

  it('creates no thread when the pipeline did not check out the head', async () => {
    const s = await setup('thr/other', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    await s.ingest([{ path: 'src/a.ts', line: 3 }], { checkout: 'other' });
    await decorate();
    expect(s.ownThreads()).toEqual([]);
    expect(requestsOf().some((r) => r.includes('/changes') || r.includes('/items'))).toBe(false);
  });

  it('says so in the summary when the threads cannot be read, and fails the job retryably', async () => {
    const s = await setup('thr/failed', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    const analysisId = await s.ingest([{ path: 'src/a.ts', line: 3 }]);
    fake.inject('GET', /\/threads$/, { status: 503, body: {} });
    fake.clearRequests();
    const outcome = await decorateAnalysis(decorationDeps(h), {
      analysisId,
      attempt: 0,
      gitlab: null,
      azure: { repositoryId: s.repository.id, checkout: 'head' },
    });
    expect(outcome).toMatchObject({ kind: 'failed', retry: true, error: { kind: 'transient' } });
    expect(s.ownThreads()).toEqual([]);
    expect(s.summary()).toContain(NOT_UPDATED);
    expect(requestsOf().some((r) => r.includes('/items'))).toBe(false);
  });

  const decorateOnce = async (s: Awaited<ReturnType<typeof setup>>, analysisId: string) => {
    const outcome = await decorateAnalysis(decorationDeps(h), {
      analysisId,
      attempt: 0,
      gitlab: null,
      azure: { repositoryId: s.repository.id, checkout: 'head' },
    });
    // The job its ingestion queued is not run here.
    await h.ctx.db.delete(jobs);
    return outcome;
  };

  it('keeps going after a thread creation fails', async () => {
    const s = await setup('thr/write', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    // The first thread creation fails; the other thread and the summary are still written.
    fake.inject('POST', /\/threads$/, { status: 503, body: {} });
    const analysisId = await s.ingest([
      { path: 'src/a.ts', line: 3 },
      { path: 'src/a.ts', line: 4 },
    ]);
    const outcome = await decorateOnce(s, analysisId);
    expect(outcome).toMatchObject({ kind: 'failed', retry: true });
    expect(s.ownThreads().map((t) => t.line)).toEqual([4]);
    expect(s.summary()).toContain('1 new issue is commented inline');
  });

  it('stops the job on a rate limit, before the summary', async () => {
    const s = await setup('thr/limit', {
      files: { 'src/a.ts': HEAD_A },
      base: { 'src/a.ts': BASE_A },
    });
    fake.inject('POST', /\/threads$/, { status: 429, headers: { 'retry-after': '30' }, body: {} });
    const analysisId = await s.ingest([
      { path: 'src/a.ts', line: 3 },
      { path: 'src/a.ts', line: 4 },
    ]);
    const outcome = await decorateOnce(s, analysisId);
    expect(outcome).toMatchObject({ kind: 'failed', retry: true, error: { kind: 'rate_limited' } });
    expect(s.ownThreads()).toEqual([]);
    expect(s.summary()).toBe('');
  });

  // The AI review's threads (sub-plan 5, task 5).
  type Suggestion = { startLine: number; endLine: number; lines: string[] };
  const THREE: Suggestion = { startLine: 3, endLine: 3, lines: ['THREE'] };

  /** A project with pull request #7 whose review of the source commit is done, its snapshot stored. */
  const reviewed = async (
    key: string,
    findings: At[] = [],
    opts: { checkout?: 'head' | 'other' } = {},
  ) => {
    const s = await setup(key, { files: { 'src/a.ts': HEAD_A }, base: { 'src/a.ts': BASE_A } });
    const analysisId = await s.ingest(findings, opts);
    const [branch] = await h.ctx.db
      .select()
      .from(branches)
      .where(and(eq(branches.projectId, s.project.id), eq(branches.kind, 'merge_request')));
    const branchId = branch!.id;
    await h.ctx.db.insert(reviewRuns).values({
      projectId: s.project.id,
      branchId,
      analysisId,
      status: 'done',
      deadlineAt: new Date(),
      headSha: s.sourceCommit,
      summary: { verdict: 'It has problems.', walkthrough: [], notes: [] },
    });
    await storeTestSnapshot(
      h.ctx.db,
      analysisId,
      [
        {
          type: 'change',
          path: 'src/a.ts',
          oldPath: null,
          status: 'modified',
          patch: '@@ -2,0 +3,3 @@\n+three\n+four\n+five',
          since: null,
        },
        { type: 'file', path: 'src/a.ts', text: HEAD_A },
      ],
      {
        headSha: s.sourceCommit,
        mergeRequest: { id: String(PR), title: 'A change', description: null },
      },
    );
    const aiFinding = async (o: {
      line: number;
      severity?: 'blocker' | 'high' | 'medium' | 'low' | 'info';
      anchorLine?: number;
      suggestion?: Suggestion | null;
      category?: AiCategory;
    }) => {
      const category = o.category ?? 'logic';
      const id = await seedAiIssue(h.ctx.db, {
        branchId,
        category,
        path: 'src/a.ts',
        line: o.line,
        severity: o.severity ?? 'high',
      });
      await h.ctx.db
        .update(issues)
        .set({ message: `Line ${o.line} is wrong` })
        .where(eq(issues.id, id));
      await h.ctx.db.insert(reviewFindings).values({
        issueId: id,
        category,
        body: `Why line ${o.line} is wrong.`,
        assumption: null,
        suggestion: o.suggestion ?? null,
        anchorLine: o.anchorLine ?? o.line,
        reviewedHeadSha: s.sourceCommit,
      });
      return id;
    };
    const aiThread = (issueId: string) =>
      s.ownThreads().find((t) => t.comments[0]?.content.startsWith(issueMarker(issueId)));
    return { ...s, analysisId, branchId, aiFinding, aiThread };
  };

  it('posts a high AI finding at the reviewed head as one active thread on its line', async () => {
    const s = await reviewed('ai/posted');
    const id = await s.aiFinding({ line: 4 });
    await decorate();
    const thread = s.aiThread(id);
    expect(thread).toMatchObject({ status: 'active', filePath: 'src/a.ts', line: 4 });
    expect(thread?.threadContext).toEqual({
      filePath: '/src/a.ts',
      rightFileStart: { line: 4, offset: 1 },
      rightFileEnd: { line: 4, offset: 'four'.length + 1 },
    });
    expect(thread?.comments[0]?.content.split('\n')[0]).toBe(issueMarker(id));
    expect(thread?.comments[0]?.content).not.toContain('```suggestion');
    // Decorated again: no second thread.
    fake.clearRequests();
    await decorate();
    expect(s.ownThreads()).toHaveLength(1);
    expect(writesOf().filter((w) => /threads$/.test(w))).toEqual([]);
  });

  it('does not count AI threads in the summary’s "commented inline"', async () => {
    const s = await reviewed('ai/count', [{ path: 'src/a.ts', line: 3 }]);
    await s.aiFinding({ line: 4 });
    await decorate();
    expect(s.ownThreads()).toHaveLength(2);
    expect(s.summary()).toContain('1 new issue is commented inline');
  });

  it('writes a one-line suggestion as a suggestion fence', async () => {
    const s = await reviewed('ai/fence');
    const id = await s.aiFinding({ line: 3, suggestion: THREE });
    await decorate();
    expect(s.aiThread(id)?.comments[0]?.content).toContain('```suggestion\nTHREE\n```');
  });

  it('writes a suggestion over two lines as a range thread', async () => {
    const s = await reviewed('ai/multi');
    const id = await s.aiFinding({
      line: 3,
      suggestion: { startLine: 3, endLine: 4, lines: ['3', '4'] },
    });
    await decorate();
    const thread = s.aiThread(id);
    expect(thread?.threadContext).toEqual({
      filePath: '/src/a.ts',
      rightFileStart: { line: 3, offset: 1 },
      rightFileEnd: { line: 4, offset: 'four'.length + 1 },
    });
    expect(thread?.comments[0]?.content).toContain('```suggestion\n3\n4\n```');
  });

  it('writes a deletion as an empty fence over its lines', async () => {
    const s = await reviewed('ai/delete');
    const id = await s.aiFinding({
      line: 3,
      suggestion: { startLine: 3, endLine: 5, lines: [] },
    });
    await decorate();
    const thread = s.aiThread(id);
    expect(thread?.threadContext).toEqual({
      filePath: '/src/a.ts',
      rightFileStart: { line: 3, offset: 1 },
      rightFileEnd: { line: 5, offset: 'five'.length + 1 },
    });
    expect(thread?.comments[0]?.content).toContain('```suggestion\n```');
  });

  it('posts no AI thread once the pull request head moved, and the summary says it waits', async () => {
    const s = await reviewed('ai/moved');
    const id = await s.aiFinding({ line: 4 });
    s.pr().headSha = azureCommitId('ai/moved-newer');
    await decorate();
    expect(s.aiThread(id)).toBeUndefined();
    expect(s.summary()).toContain('the pull request is now at');
    expect(s.summary()).toContain('Line 4 is wrong');
  });

  it('lists an AI finding anchored on a context line as not posted', async () => {
    const s = await reviewed('ai/context');
    const id = await s.aiFinding({ line: 1 });
    await decorate();
    expect(s.aiThread(id)).toBeUndefined();
    expect(s.summary()).toContain('**Not on changed lines:**');
    expect(s.summary()).toContain('Line 1 is wrong');
  });

  it('lists an AI finding whose thread Azure DevOps refuses with a 400, and goes on', async () => {
    const s = await reviewed('ai/refused');
    const refused = await s.aiFinding({ line: 3 });
    const accepted = await s.aiFinding({ line: 4, severity: 'medium' });
    fake.inject('POST', /\/threads$/, { status: 400, body: { message: 'TF401019: no' } });
    const outcome = await decorateOnce(s, s.analysisId);
    expect(outcome).toMatchObject({ kind: 'done' });
    expect(s.aiThread(refused)).toBeUndefined();
    expect(s.aiThread(accepted)).toBeDefined();
    expect(s.summary()).toContain('**Not on changed lines:**');
    expect(s.summary()).toContain('Line 3 is wrong');
  });

  it('resolves the thread of a fixed AI finding, and never reopens one a person resolved', async () => {
    const s = await reviewed('ai/cycle');
    const fixed = await s.aiFinding({ line: 3 });
    const kept = await s.aiFinding({ line: 4 });
    await decorate();
    const fixedThread = s.aiThread(fixed);
    const keptThread = s.aiThread(kept);
    expect([fixedThread?.status, keptThread?.status]).toEqual(['active', 'active']);
    keptThread!.status = 'fixed';
    await h.ctx.db
      .update(issues)
      .set({ status: 'closed', closedAt: new Date() })
      .where(eq(issues.id, fixed));
    fake.clearRequests();
    await enqueueDecoration(h.ctx.db, {
      analysisId: s.analysisId,
      branchId: s.branchId,
      gitlab: null,
      azure: { repositoryId: s.repository.id, checkout: 'head' },
    });
    await decorate();
    expect(fixedThread?.status).toBe('fixed');
    expect(lastComment(fixedThread!)).toMatch(new RegExp(`^<!-- qualor:fixed ${fixed} `));
    expect(keptThread?.status).toBe('fixed');
    expect(keptThread?.comments).toHaveLength(1);
  });

  it('FW5: a failed reopen of an AI thread leaves the analyzers’ "commented inline" count as it is', async () => {
    const s = await reviewed('ai/lost-reopen', [{ path: 'src/a.ts', line: 3 }]);
    const id = await s.aiFinding({ line: 4 });
    await decorate();
    const close = (status: 'closed' | 'open') =>
      h.ctx.db
        .update(issues)
        .set({ status, closedAt: status === 'closed' ? new Date() : null })
        .where(eq(issues.id, id));
    await close('closed');
    await enqueueDecoration(h.ctx.db, {
      analysisId: s.analysisId,
      branchId: s.branchId,
      gitlab: null,
      azure: { repositoryId: s.repository.id, checkout: 'head' },
    });
    await decorate();
    expect(s.aiThread(id)?.status).toBe('fixed');
    // The AI finding returns, and the reopening's status change fails.
    await close('open');
    fake.inject('PATCH', /\/threads\/\d+$/, { status: 503, body: {} });
    expect(await decorateOnce(s, s.analysisId)).toMatchObject({ kind: 'failed', retry: true });
    expect(s.aiThread(id)?.status).toBe('fixed');
    expect(s.summary()).toContain('1 new issue is commented inline');
  });

  it('with the head not checked out, posts and resolves the AI threads but no analyzer thread', async () => {
    const s = await reviewed('ai/other', [{ path: 'src/a.ts', line: 3 }], { checkout: 'other' });
    const fixed = await s.aiFinding({ line: 4 });
    const fresh = await s.aiFinding({ line: 5 });
    // A thread of an earlier job for the finding that is fixed since.
    s.pr().threads.push({
      id: 5000,
      status: 'active',
      filePath: 'src/a.ts',
      line: 4,
      threadContext: null,
      publishedDate: '2026-11-23T10:00:00Z',
      comments: [
        {
          id: 1,
          authorId: fake.patUser.id,
          content: `${issueMarker(fixed)}
old`,
          commentType: 'text',
          parentCommentId: 0,
          publishedDate: '2026-11-23T10:00:00Z',
          isDeleted: false,
        },
      ],
    });
    await h.ctx.db
      .update(issues)
      .set({ status: 'closed', closedAt: new Date() })
      .where(eq(issues.id, fixed));
    await decorate();
    expect(s.aiThread(fresh)).toMatchObject({ status: 'active', line: 5 });
    expect(s.aiThread(fixed)?.status).toBe('fixed');
    // No thread for the analyzer's issue at line 3.
    expect(s.ownThreads().map((t) => t.line)).toEqual([4, 5]);
    expect(s.summary()).toContain('did not check out');
  });

  it('lists the AI findings as not posted when the iteration’s changes are cut by their bound', async () => {
    const s = await reviewed('ai/cut');
    await s.aiFinding({ line: 4 });
    // Ten pages that each say more follow: the listing is cut by its page bound.
    fake.inject(
      'GET',
      /\/iterations\/\d+\/changes/,
      ...Array.from({ length: 10 }, (_, i) => ({
        status: 200,
        body: {
          changeEntries: [
            { changeTrackingId: i + 1, changeType: 'edit', item: { path: '/src/a.ts' } },
          ],
          nextSkip: i + 1,
        },
      })),
    );
    await decorate();
    expect(s.ownThreads()).toEqual([]);
    expect(s.summary()).toContain('**Not on changed lines:**');
    expect(s.summary()).toContain('Line 4 is wrong');
  });
});
