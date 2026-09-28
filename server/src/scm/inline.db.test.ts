import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { engine, file, finding } from '../../test/reports';
import {
  decorationDeps,
  mappedProject,
  mergeRequestReport,
  queuedDecorations,
  runDecorations,
  scmTestConfig,
} from '../../test/scm';
import { MAX_GITLAB_REQUESTS } from './gitlab/client';
import {
  addedLines,
  MAX_DIFF_PAGES,
  MAX_DISCUSSION_PAGES,
  MAX_INLINE_THREADS,
  MAX_THREAD_UPDATES,
  REQUESTS_OUTSIDE_INLINE,
} from './inline';
import { markerOf } from './markdown';

const HEAD = '1'.repeat(40);
const BASE = 'b'.repeat(40);
/** src/a.ts: lines 3–5 added. src/renamed.ts: renamed from src/old.ts, line 2 added. */
const DIFFS = [
  { oldPath: 'src/a.ts', newPath: 'src/a.ts', diff: '@@ -1,2 +1,5 @@\n a\n b\n+c\n+d\n+e\n' },
  {
    oldPath: 'src/old.ts',
    newPath: 'src/renamed.ts',
    diff: '@@ -1,2 +1,3 @@\n x\n+y\n z\n',
    renamedFile: true,
  },
];
const HUMAN = 5;

describe('addedLines', () => {
  it('numbers the added lines of every hunk in the new file', () => {
    expect([...addedLines(DIFFS[0]!.diff)]).toEqual([3, 4, 5]);
    expect([...addedLines('@@ -1 +1,2 @@\n-a\n+b\n+c\n@@ -9,2 +10,2 @@\n x\n+y\n')]).toEqual([
      1, 2, 11,
    ]);
    expect(addedLines('Binary files differ').size).toBe(0);
  });
});

describe('the request budget (scm.md §4.3)', () => {
  it('leaves room for the inline work of a job that reads every page it may', () => {
    // Project, user, merge request, commit status (read, post and its retry without the pipeline),
    // the summary, and every page of discussions and diffs.
    expect(REQUESTS_OUTSIDE_INLINE).toBe(7 + MAX_DISCUSSION_PAGES + MAX_DIFF_PAGES);
    expect(REQUESTS_OUTSIDE_INLINE + MAX_INLINE_THREADS + MAX_THREAD_UPDATES).toBeLessThanOrEqual(
      MAX_GITLAB_REQUESTS,
    );
  });
});

describe('GitLab inline discussions (scm.md §5.4)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;
  let nextGitLabProject = 200;
  let day = 1;

  /** A mapped project and merge request !7; `shared` maps it to another project's GitLab project. */
  const setup = async (key: string, shared?: number) => {
    const gitlabId = shared ?? nextGitLabProject++;
    if (shared === undefined) {
      fake.addProject({ id: gitlabId, path: `acme/${key.replace(/\W/g, '-')}` });
      fake.addMergeRequest(gitlabId, {
        iid: 7,
        title: 'Inline',
        state: 'opened',
        sourceBranch: 'feature/x',
        targetBranch: 'main',
        headSha: HEAD,
        baseSha: BASE,
        startSha: BASE,
        diffs: DIFFS,
      });
    }
    const project = await mappedProject(h, fake, key, gitlabId);
    const ingest = (lines: number[], extra: Parameters<typeof mergeRequestReport>[2] = {}) =>
      project.ingestOk(
        mergeRequestReport(7, HEAD, {
          projectKey: project.key,
          analysisDate: new Date(Date.UTC(2026, 8, 1, 10) + 86_400_000 * day++).toISOString(),
          engines: [engine('eslint')],
          files: [
            file('src/a.ts', { newLines: [[1, 60]] }),
            file('src/renamed.ts', { newLines: [[2, 2]] }),
          ],
          findings: lines.map((line) => finding({ path: 'src/a.ts', line })),
          ...extra,
        }),
      );
    return { project, gitlabId, ingest };
  };
  const threads = (gitlabId: number) =>
    fake
      .discussions(gitlabId, 7)
      .filter((d) => d.notes[0] && markerOf(d.notes[0].body)?.kind === 'issue');
  const summary = (gitlabId: number, projectId?: string) =>
    fake
      .discussions(gitlabId, 7)
      .flatMap((d) => d.notes)
      .find((n) => {
        const marker = markerOf(n.body);
        return (
          marker?.kind === 'summary' && (projectId === undefined || marker.projectId === projectId)
        );
      })?.body ?? '';
  const lineOf = (d: ReturnType<typeof threads>[number]) => d.notes[0]?.position?.['new_line'];
  const resolvedByLine = (gitlabId: number) =>
    Object.fromEntries(threads(gitlabId).map((d) => [lineOf(d), d.notes[0]?.resolved]));
  const threadAt = (gitlabId: number, line: number) => {
    const found = threads(gitlabId).find((d) => lineOf(d) === line);
    if (!found) throw new Error(`no thread on line ${line}`);
    return found;
  };
  const threadWrites = () =>
    fake.requests.filter((r) => r.method !== 'GET' && r.path.includes('/discussions'));

  beforeAll(async () => {
    fake = await createFakeGitLab();
    h = await createIngestHarness({ config: scmTestConfig(fake) });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(() => fake.clearRequests());

  it('comments the new issues on added lines, counts the others, and does it once', async () => {
    const { gitlabId, ingest } = await setup('inline/place');
    // Line 1 is new code for Qualor but not an added line of GitLab's diff.
    await ingest([1, 3, 4]);
    await runDecorations(h, decorationDeps(h));
    const placed = threads(gitlabId);
    expect(placed.map((d) => d.notes[0]?.position?.['new_line']).sort()).toEqual([3, 4]);
    expect(placed[0]?.notes[0]?.position).toMatchObject({
      position_type: 'text',
      base_sha: BASE,
      start_sha: BASE,
      head_sha: HEAD,
      old_path: 'src/a.ts',
      new_path: 'src/a.ts',
    });
    expect(placed[0]?.notes[0]?.body).toMatch(
      /^<!-- qualor:issue [0-9a-f-]{36} -->\n\*\*Medium\*\*/,
    );
    expect(summary(gitlabId)).toContain(
      '2 new issues are commented inline; 1 could not be placed on the diff.',
    );
    fake.clearRequests();
    await ingest([1, 3, 4]);
    await runDecorations(h, decorationDeps(h));
    expect(threads(gitlabId)).toHaveLength(2);
    expect(fake.requests.some((r) => r.method === 'POST' && r.path.endsWith('/discussions'))).toBe(
      false,
    );
  });

  it('resolves the thread of a fixed issue and reopens it when the issue comes back', async () => {
    const { gitlabId, ingest } = await setup('inline/fix');
    await ingest([3, 4]);
    await runDecorations(h, decorationDeps(h));
    await ingest([3]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(gitlabId)).toEqual({ 3: false, 4: true });
    expect(threadAt(gitlabId, 4).notes[0]?.resolvedBy).toBe(fake.botUserId);
    expect(summary(gitlabId)).toContain('1 new issue is commented inline.');
    // Resolving again changes nothing; the issue coming back reopens its own thread.
    fake.clearRequests();
    await ingest([3]);
    await runDecorations(h, decorationDeps(h));
    expect(fake.requests.filter((r) => r.path.includes('/discussions/'))).toHaveLength(0);
    await ingest([3, 4]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(gitlabId)).toEqual({ 3: false, 4: false });
    expect(threads(gitlabId)).toHaveLength(2);
  });

  it('never reopens a thread a person resolved, and still counts its issue (ruling G3)', async () => {
    const { gitlabId, ingest } = await setup('inline/human-resolved');
    await ingest([3, 4]);
    await runDecorations(h, decorationDeps(h));
    fake.resolveAs(gitlabId, 7, threadAt(gitlabId, 3).id, HUMAN, true);
    // The issue is still open: the reviewer's decision stands.
    fake.clearRequests();
    await ingest([3, 4]);
    await runDecorations(h, decorationDeps(h));
    expect(threadWrites()).toEqual([]);
    expect(resolvedByLine(gitlabId)).toEqual({ 3: true, 4: false });
    expect(threadAt(gitlabId, 3).notes[0]?.resolvedBy).toBe(HUMAN);
    expect(summary(gitlabId)).toContain('2 new issues are commented inline.');
    // Fixed, then back: a thread a person resolved is still never reopened, and never duplicated.
    await ingest([4]);
    await runDecorations(h, decorationDeps(h));
    await ingest([3, 4]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(gitlabId)).toEqual({ 3: true, 4: false });
    expect(threads(gitlabId)).toHaveLength(2);
  });

  it('leaves a person the thread of a fixed issue they reopened and replied to', async () => {
    const { gitlabId, ingest } = await setup('inline/human-reply');
    await ingest([3, 4]);
    await runDecorations(h, decorationDeps(h));
    await ingest([]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(gitlabId)).toEqual({ 3: true, 4: true });
    // Line 3: reopened without a word, so Qualor resolves it again (the issue is still fixed).
    fake.resolveAs(gitlabId, 7, threadAt(gitlabId, 3).id, HUMAN, false);
    // Line 4: reopened with a reply, so the conversation is the people's now.
    fake.resolveAs(gitlabId, 7, threadAt(gitlabId, 4).id, HUMAN, false);
    fake.reply(gitlabId, 7, threadAt(gitlabId, 4).id, {
      body: 'Not so fast: the fix moved it.',
      authorId: HUMAN,
    });
    await ingest([]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(gitlabId)).toEqual({ 3: true, 4: false });
    // A reply by Qualor's own user is not a person's.
    const own = await setup('inline/bot-reply');
    await own.ingest([3]);
    await runDecorations(h, decorationDeps(h));
    fake.reply(own.gitlabId, 7, threadAt(own.gitlabId, 3).id, {
      body: 'a note by the bot',
      authorId: fake.botUserId,
    });
    await own.ingest([]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(own.gitlabId)).toEqual({ 3: true });
  });

  it('leaves a person the thread they replied to after Qualor resolved it, when its issue returns', async () => {
    const { gitlabId, ingest } = await setup('inline/reply-to-resolved');
    await ingest([3]);
    await runDecorations(h, decorationDeps(h));
    await ingest([]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(gitlabId)).toEqual({ 3: true });
    // GitLab creates a reply in a resolved thread resolved, by its author (seen on GitLab CE
    // 18.11.11): the thread stays resolved, and one of its notes is now resolved by a person.
    const reply = fake.reply(gitlabId, 7, threadAt(gitlabId, 3).id, {
      body: 'Agreed, fixed.',
      authorId: HUMAN,
    });
    expect(reply).toMatchObject({ resolvable: true, resolved: true, resolvedBy: HUMAN });
    // The issue comes back: the thread is not Qualor's alone any more, so it stays resolved (G3).
    fake.clearRequests();
    await ingest([3]);
    await runDecorations(h, decorationDeps(h));
    expect(threadWrites()).toEqual([]);
    expect(resolvedByLine(gitlabId)).toEqual({ 3: true });
    expect(threads(gitlabId)).toHaveLength(1);
    expect(summary(gitlabId)).toContain('1 new issue is commented inline.');
  });

  it('reopens only a thread every resolvable note of which Qualor resolved', async () => {
    const { gitlabId, ingest } = await setup('inline/partly-human');
    await ingest([3]);
    await runDecorations(h, decorationDeps(h));
    const thread = threadAt(gitlabId, 3);
    fake.reply(gitlabId, 7, thread.id, { body: 'looking', authorId: HUMAN });
    // Resolved note by note: Qualor's note by Qualor, the reply by a person.
    const [first, reply] = thread.notes;
    Object.assign(first!, { resolved: true, resolvedBy: fake.botUserId });
    Object.assign(reply!, { resolved: true, resolvedBy: HUMAN });
    fake.clearRequests();
    await ingest([3]);
    await runDecorations(h, decorationDeps(h));
    expect(threadWrites()).toEqual([]);
    expect(resolvedByLine(gitlabId)).toEqual({ 3: true });
  });

  it(`resolves or reopens at most the bound of threads per job, the rest in later jobs`, async () => {
    const { gitlabId, ingest } = await setup('inline/update-cap');
    await ingest([3, 4, 5]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(gitlabId)).toEqual({ 3: false, 4: false, 5: false });
    const resolvedCount = () => threads(gitlabId).filter((d) => d.notes[0]?.resolved).length;
    const capped = decorationDeps(h, { maxThreadUpdates: 2 });
    fake.clearRequests();
    await ingest([]);
    await runDecorations(h, capped);
    expect(threadWrites()).toHaveLength(2);
    expect(resolvedCount()).toBe(2);
    await ingest([]);
    await runDecorations(h, capped);
    expect(resolvedCount()).toBe(3);
  });

  it('goes on when a thread was deleted meanwhile, and still writes the summary', async () => {
    const { gitlabId, ingest } = await setup('inline/deleted-thread');
    await ingest([3, 4]);
    await runDecorations(h, decorationDeps(h));
    expect(summary(gitlabId)).toContain('quality gate failed');
    const gone = threadAt(gitlabId, 3);
    fake.inject(
      'PUT',
      new RegExp(`^/projects/${gitlabId}/merge_requests/7/discussions/${gone.id}$`),
      { status: 404, body: { message: '404 Not found' } },
    );
    await ingest([]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(gitlabId)).toEqual({ 3: false, 4: true });
    expect(summary(gitlabId)).toContain('quality gate passed');
    // The job ended done: nothing is retried.
    expect(await queuedDecorations(h)).toEqual([]);
  });

  it('places an issue of a renamed file with its old path, and counts a rejected position', async () => {
    const { gitlabId, ingest } = await setup('inline/rename');
    fake.inject('POST', new RegExp(`^/projects/${gitlabId}/merge_requests/7/discussions$`), {
      status: 400,
      body: { message: '400 Bad request - Note {:line_code=>["can\'t be blank"]}' },
    });
    await ingest([3], {
      findings: [
        finding({ path: 'src/a.ts', line: 3 }),
        finding({ path: 'src/renamed.ts', line: 2 }),
      ],
    });
    await runDecorations(h, decorationDeps(h));
    const placed = threads(gitlabId);
    expect(placed).toHaveLength(1);
    expect(placed[0]?.notes[0]?.position).toMatchObject({
      old_path: 'src/old.ts',
      new_path: 'src/renamed.ts',
      new_line: 2,
    });
    expect(summary(gitlabId)).toContain('1 new issue is commented inline; 1 could not be placed');
  });

  it('never comments inline for a merged-results pipeline, and leaves other people’s threads alone', async () => {
    const { gitlabId, ingest } = await setup('inline/merged');
    const human = fake.addNote(gitlabId, 7, {
      body: '<!-- qualor:issue 01920000-0000-7000-8000-000000000001 -->\nnot Qualor',
      authorId: HUMAN,
    });
    await ingest([3], { gitlab: { mergeRequestEventType: 'merged_result' } });
    await runDecorations(h, decorationDeps(h));
    expect(threads(gitlabId).map((d) => d.id)).toEqual([human.id]);
    expect(summary(gitlabId)).toContain('merged-results pipeline');
    expect(fake.requests.some((r) => r.method === 'PUT' && r.path.includes('/discussions/'))).toBe(
      false,
    );
  });

  it('says merged results, not "now at", when a merged-results pipeline is also stale', async () => {
    const { gitlabId, ingest } = await setup('inline/merged-stale');
    fake.updateMergeRequest(gitlabId, 7, { headSha: '2'.repeat(40) });
    await ingest([3], { gitlab: { mergeRequestEventType: 'merge_train' } });
    await runDecorations(h, decorationDeps(h));
    expect(threads(gitlabId)).toEqual([]);
    expect(summary(gitlabId)).toContain('merged-results pipeline');
    expect(summary(gitlabId)).not.toContain('now at');
    expect(summary(gitlabId)).not.toContain('wait for the analysis');
  });

  it('changes no thread while the merge request is ahead of the analysed revision', async () => {
    const { gitlabId, ingest } = await setup('inline/stale');
    await ingest([3]);
    await runDecorations(h, decorationDeps(h));
    fake.updateMergeRequest(gitlabId, 7, { headSha: '3'.repeat(40) });
    fake.clearRequests();
    // Line 3 is fixed and line 4 new, but the line numbers are no longer the merge request's.
    await ingest([4]);
    await runDecorations(h, decorationDeps(h));
    expect(threadWrites()).toEqual([]);
    expect(resolvedByLine(gitlabId)).toEqual({ 3: false });
    expect(summary(gitlabId)).toContain(
      'wait for the analysis of the merge request’s latest commit',
    );
    expect(summary(gitlabId)).toContain('the merge request is now at ` 333333333333 `');
  });

  it('leaves the threads of another Qualor project on the same merge request alone', async () => {
    const a = await setup('inline/mono-a');
    const b = await setup('inline/mono-b', a.gitlabId);
    await a.ingest([3]);
    await b.ingest([4]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(a.gitlabId)).toEqual({ 3: false, 4: false });
    // B's issue is fixed: B resolves its own thread and not A's, whose issue B does not have.
    await b.ingest([]);
    await runDecorations(h, decorationDeps(h));
    expect(resolvedByLine(a.gitlabId)).toEqual({ 3: false, 4: true });
    expect(summary(a.gitlabId, a.project.id)).toContain('1 new issue is commented inline.');
    expect(summary(a.gitlabId, b.project.id)).not.toContain('commented inline');
  });

  it('creates no thread when the discussions run past the page bound (one may exist unseen)', async () => {
    const { gitlabId, ingest } = await setup('inline/paged');
    fake.inject(
      'GET',
      new RegExp(`^/projects/${gitlabId}/merge_requests/7/discussions$`),
      ...Array.from({ length: MAX_DISCUSSION_PAGES }, (_, i) => ({
        status: 200,
        body: [],
        headers: { 'x-next-page': String(i + 2) },
      })),
    );
    await ingest([3]);
    await runDecorations(h, decorationDeps(h));
    expect(fake.requests.filter((r) => r.path.endsWith('/discussions')).length).toBe(
      MAX_DISCUSSION_PAGES,
    );
    expect(fake.requests.some((r) => r.method === 'POST')).toBe(true); // the commit status
    expect(threadWrites()).toEqual([]);
    expect(threads(gitlabId)).toEqual([]);
  });

  it(`comments at most ${MAX_INLINE_THREADS} issues, the most severe first`, async () => {
    const { gitlabId, ingest } = await setup('inline/cap');
    fake.updateMergeRequest(gitlabId, 7, {
      diffs: [
        {
          oldPath: 'src/a.ts',
          newPath: 'src/a.ts',
          diff: `@@ -0,0 +1,60 @@\n${Array.from({ length: 60 }, (_, i) => `+l${i + 1}`).join('\n')}\n`,
        },
      ],
    });
    const lines = Array.from({ length: 60 }, (_, i) => i + 1);
    await ingest(lines, {
      findings: lines.map((line) =>
        finding({ path: 'src/a.ts', line, severity: line === 60 ? 'blocker' : 'low' }),
      ),
    });
    await runDecorations(h, decorationDeps(h));
    const placed = threads(gitlabId);
    expect(placed).toHaveLength(MAX_INLINE_THREADS);
    expect(placed.some((d) => d.notes[0]?.position?.['new_line'] === 60)).toBe(true);
    expect(summary(gitlabId)).toContain('50 new issues are commented inline.');
    expect(summary(gitlabId)).toContain('- … and 50 more');
  });
});
