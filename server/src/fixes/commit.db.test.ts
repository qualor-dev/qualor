import { and, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitLab, type FakeGitLab, type FakeMergeRequest } from '../../test/fake-gitlab';
import {
  acceptedQfA,
  claimFix,
  enableFixes,
  openQfA,
  qfaPackageJson as packageJson,
  qfaPackageLock as packageLock,
  runFixJobs as runQueuedFixJobs,
  seedMainVulnerability,
  uploadQfA,
} from '../../test/fixes';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { mappedProject, PUBLIC_URL, scmTestConfig, silentLogger } from '../../test/scm';
import {
  dependencyFixes,
  jobs,
  projects,
  scmConnections,
  targetVulnerabilities,
} from '../db/schema';
import { communityLimits } from '../limits';
import { MAX_DECORATIONS_PER_ORGANIZATION, createScmRuntime } from '../scm/runtime';
import { cancelComment } from './body';
import { FIX_QUEUE } from './jobs';
import type { FixJobDeps } from './run';

const CVE = 'CVE-2026-9301';
const BRANCH = 'qualor/fix/js/qf-a';
/** The commit message: plain (R30). */
const TITLE = 'Bump qf-a from 1.2.5 to 1.2.6';
/** Rulings FW2, FW2b: GitLab reads mentions in titles, so the name and versions are code spans. */
const GITLAB_TITLE = 'Bump ` qf-a ` from ` 1.2.5 ` to ` 1.2.6 `';

/** A GitLab project of the fake, mapped to a Qualor project with fix MRs on and qf-a vulnerable. */
interface Repo {
  gitlabId: number;
  project: IngestProject & { connectionId: string };
}

describe('the fix commit and close jobs on GitLab (0.16 fix MRs §6.7, B10, R8, R10, R17)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;
  let runtime = createScmRuntime();
  let gitlabIds = 300;

  const db = () => h.ctx.db;
  const deps = (): FixJobDeps => ({
    db: db(),
    scm: {
      secretKey: h.ctx.config.secretKey,
      internalHosts: h.ctx.config.scmInternalHosts,
      azureTokenOrigin: null,
      azureTestOrigin: null,
      clientOptions: { timeoutMs: 2_000 },
    },
    runtime,
    publicUrl: PUBLIC_URL,
    limits: () => communityLimits(),
    logger: silentLogger,
  });

  const freshRepo = async (options: { ownConnection?: boolean } = {}): Promise<Repo> => {
    const gitlabId = ++gitlabIds;
    fake.addProject({ id: gitlabId, path: `acme/fix-commit-${gitlabId}` });
    fake.addFile(gitlabId, 'main', 'package.json', packageJson('^1.2.5'));
    fake.addFile(gitlabId, 'main', 'package-lock.json', packageLock('1.2.5'));
    fake.addFile(gitlabId, 'main', 'README.md', '# app\n');
    const project = await mappedProject(h, fake, `FC-${gitlabId}`, gitlabId, options);
    await enableFixes(h, project.id, { maxOpen: 20 });
    await seedMainVulnerability(
      db(),
      { id: project.id, mainBranchId: await mainBranchId(db(), project.id) },
      {
        ecosystem: 'npm',
        packageName: 'qf-a',
        version: '1.2.5',
        vulnerabilityId: CVE,
        severity: 'high',
        fixedVersion: '1.2.6',
      },
    );
    return { gitlabId, project };
  };

  const claim = (repo: Repo) => claimFix(h, repo.project);
  /** The good upload of qf-a 1.2.5 → 1.2.6 on main's head; 202, the fix `committing`. */
  const upload = (repo: Repo, item: Awaited<ReturnType<typeof claim>>) =>
    uploadQfA(h, repo.project, item, fake.headOf(repo.gitlabId, 'main'));
  /** A requested fix of qf-a, claimed and uploaded (Task 9's routes): `committing`. */
  const accepted = (repo: Repo) => acceptedQfA(h, repo.project, fake.headOf(repo.gitlabId, 'main'));
  /** An open fix to refresh (a conflict, a higher target): claimed and uploaded again. */
  const refreshed = async (repo: Repo, fixId: string) => {
    await db().update(dependencyFixes).set({ refresh: true }).where(eq(dependencyFixes.id, fixId));
    await upload(repo, await claim(repo));
  };
  /** The queued commit and close jobs, run now (the sync pass has tests of its own). */
  const runFixJobs = () => runQueuedFixJobs(db(), deps());
  /** An open fix of qf-a with its MR (the first commit), with the requests cleared. */
  const openFix = async (repo: Repo): Promise<string> => {
    const fixId = await openQfA(h, repo.project, fake.headOf(repo.gitlabId, 'main'), deps());
    fake.clearRequests();
    return fixId;
  };
  const row = async (id: string) =>
    (await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, id)))[0]!;
  /** The fix's queued job and how many seconds from now it runs. */
  const queuedJob = async (fixId: string) => {
    const found = await db()
      .select({
        payload: jobs.payload,
        inSeconds: sql<number>`extract(epoch from ${jobs.runAt} - now())::float8`,
      })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, FIX_QUEUE),
          eq(jobs.status, 'queued'),
          eq(jobs.concurrencyKey, `fix:${fixId}`),
        ),
      );
    return found;
  };
  const writes = () => fake.requests.filter((r) => r.method !== 'GET');
  const commitRequests = () =>
    fake.requests.filter((r) => r.method === 'POST' && r.path.endsWith('/repository/commits'));
  const mrWrites = () =>
    fake.requests.filter((r) => r.method !== 'GET' && /\/merge_requests(\/\d+)?$/.test(r.path));
  const notes = (repo: Repo, iid: number) =>
    fake.discussions(repo.gitlabId, iid).flatMap((d) => d.notes.map((n) => n.body));

  beforeAll(async () => {
    fake = await createFakeGitLab();
    h = await createIngestHarness({ config: scmTestConfig(fake) });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(() => {
    runtime = createScmRuntime();
    fake.clearRequests();
  });
  afterEach(async () => {
    await db().delete(jobs).where(eq(jobs.queue, FIX_QUEUE));
  });

  it('first commit: one commit of the uploaded files on baseSha, the MR opened, the fix open', async () => {
    const repo = await freshRepo();
    const fixId = await accepted(repo);
    const base = fake.headOf(repo.gitlabId, 'main')!;
    fake.clearRequests();
    await runFixJobs();

    const head = fake.headOf(repo.gitlabId, BRANCH)!;
    expect(head).not.toBeNull();
    const commits = commitRequests();
    expect(commits).toHaveLength(1);
    const sent = JSON.parse(commits[0]!.body) as Record<string, unknown>;
    expect(sent).toMatchObject({
      branch: BRANCH,
      start_sha: base,
      force: false,
      commit_message: TITLE,
    });
    expect(sent['actions']).toEqual([
      { action: 'update', file_path: 'package.json', content: packageJson('^1.2.6') },
      { action: 'update', file_path: 'package-lock.json', content: packageLock('1.2.6') },
    ]);
    // The branch head holds exactly the uploaded files over the base.
    expect(fake.fileAt(repo.gitlabId, head, 'package.json')).toBe(packageJson('^1.2.6'));
    expect(fake.fileAt(repo.gitlabId, head, 'package-lock.json')).toBe(packageLock('1.2.6'));
    expect(fake.fileAt(repo.gitlabId, head, 'README.md')).toBe('# app\n');

    const [mr, ...others] = fake.mergeRequestsOf(repo.gitlabId);
    expect(others).toEqual([]);
    expect(mr).toMatchObject({
      title: GITLAB_TITLE,
      state: 'opened',
      sourceBranch: BRANCH,
      targetBranch: 'main',
    });
    expect(mr!.description).toContain(`| \` ${CVE} \` | high |`);
    expect(mr!.description).toContain('- ` package-lock.json `: direct');
    expect(mr!.description).toContain(
      `[Vulnerabilities in Qualor](${PUBLIC_URL}/projects/${repo.project.id}/vulnerabilities?view=vulnerability)`,
    );
    expect(mr!.description).toMatch(/Qualor keeps this MR current/);

    expect(await row(fixId)).toMatchObject({
      state: 'open',
      refresh: false,
      mrNumber: mr!.iid,
      mrUrl: `${fake.url}/acme/fix-commit-${repo.gitlabId}/-/merge_requests/${mr!.iid}`,
      headSha: head,
      baseSha: base,
      prepared: null,
      failure: null,
    });
    expect(await queuedJob(fixId)).toEqual([]);
  });

  it('refresh: the same branch force-updated onto the new base, the same MR updated', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const first = await row(fixId);
    // Main moves on, and a second vulnerability of qf-a appears there.
    fake.addFile(repo.gitlabId, 'main', 'CHANGELOG.md', 'one\n');
    const newBase = fake.headOf(repo.gitlabId, 'main')!;
    await seedMainVulnerability(
      db(),
      { id: repo.project.id, mainBranchId: await mainBranchId(db(), repo.project.id) },
      {
        ecosystem: 'npm',
        packageName: 'qf-a',
        version: '1.2.5',
        vulnerabilityId: 'CVE-2026-9302',
        severity: 'critical',
        fixedVersion: '1.2.6',
      },
    );
    await refreshed(repo, fixId);
    fake.clearRequests();
    await runFixJobs();

    const sent = JSON.parse(commitRequests()[0]!.body) as Record<string, unknown>;
    expect(sent).toMatchObject({ branch: BRANCH, start_sha: newBase, force: true });
    const head = fake.headOf(repo.gitlabId, BRANCH)!;
    expect(head).not.toBe(first.headSha);
    expect(fake.fileAt(repo.gitlabId, head, 'CHANGELOG.md')).toBe('one\n');
    const mrs = fake.mergeRequestsOf(repo.gitlabId);
    expect(mrs).toHaveLength(1);
    expect(mrs[0]!.description).toContain('CVE-2026-9302');
    expect(mrWrites().map((r) => `${r.method} ${r.path}`)).toEqual([
      `PUT /projects/${repo.gitlabId}/merge_requests/${first.mrNumber}`,
    ]);
    expect(await row(fixId)).toMatchObject({
      state: 'open',
      refresh: false,
      mrNumber: first.mrNumber,
      headSha: head,
      baseSha: newBase,
      prepared: null,
    });
  });

  it('taken over (§11.2): a person’s push stops the refresh; a re-arm writes the -2 branch only', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const first = await row(fixId);
    const person = fake.pushAs(repo.gitlabId, BRANCH, { 'package.json': packageJson('^1.2.7') });
    await refreshed(repo, fixId);
    fake.clearRequests();
    await runFixJobs();

    expect(await row(fixId)).toMatchObject({
      state: 'taken_over',
      mrNumber: first.mrNumber,
      prepared: null,
    });
    expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(person);
    expect(writes()).toEqual([]);

    // Retry (Task 8) re-arms it on the next branch; the person's branch and MR stay as they are.
    const retried = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/fixes/${fixId}/retry`,
      headers: h.orgAdmin.headers,
    });
    expect(retried.statusCode, retried.body).toBe(202);
    expect((await row(fixId)).branch).toBe(`${BRANCH}-2`);
    await upload(repo, await claim(repo));
    fake.clearRequests();
    await runFixJobs();

    expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(person);
    expect(commitRequests().map((r) => (JSON.parse(r.body) as { branch: string }).branch)).toEqual([
      `${BRANCH}-2`,
    ]);
    const mrs = fake.mergeRequestsOf(repo.gitlabId);
    expect(mrs.map((m) => [m.sourceBranch, m.state])).toEqual([
      [BRANCH, 'opened'],
      [`${BRANCH}-2`, 'opened'],
    ]);
    expect(mrWrites().map((r) => r.method)).toEqual(['POST']);
    expect(await row(fixId)).toMatchObject({
      state: 'open',
      branch: `${BRANCH}-2`,
      mrNumber: mrs[1]!.iid,
      headSha: fake.headOf(repo.gitlabId, `${BRANCH}-2`),
    });
  });

  it('MR already open (a crash after the branch write): it is found by its branch and updated', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const first = await row(fixId);
    await refreshed(repo, fixId);
    // The job that wrote the branch and opened the MR died before it stored the MR.
    await db()
      .update(dependencyFixes)
      .set({ mrNumber: null, mrUrl: null })
      .where(eq(dependencyFixes.id, fixId));
    fake.clearRequests();
    await runFixJobs();

    expect(fake.mergeRequestsOf(repo.gitlabId)).toHaveLength(1);
    expect(mrWrites().map((r) => `${r.method} ${r.path}`)).toEqual([
      `PUT /projects/${repo.gitlabId}/merge_requests/${first.mrNumber}`,
    ]);
    expect(await row(fixId)).toMatchObject({
      state: 'open',
      mrNumber: first.mrNumber,
      mrUrl: first.mrUrl,
      headSha: fake.headOf(repo.gitlabId, BRANCH),
    });
  });

  it('B10: a push between the head check and the forced write is kept; the fix is taken over', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    await refreshed(repo, fixId);
    let person = '';
    // The first read of the branch is the job's check; the person pushes before the second, the
    // re-read right before the write.
    fake.inject(
      'GET',
      /\/repository\/branches\/qualor%2Ffix%2Fjs%2Fqf-a$/,
      { status: 200, passThrough: true },
      {
        status: 200,
        passThrough: true,
        before: async () => {
          person = fake.pushAs(repo.gitlabId, BRANCH, { 'README.md': 'mine\n' });
        },
      },
    );
    fake.clearRequests();
    await runFixJobs();

    expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(person);
    expect(writes()).toEqual([]);
    expect(await row(fixId)).toMatchObject({ state: 'taken_over', prepared: null });
  });

  it('F8: a merged MR makes the fix merged, a closed one declined, with no branch write', async () => {
    for (const [mrState, fixState] of [
      ['merged', 'merged'],
      ['closed', 'declined'],
    ] as const) {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const first = await row(fixId);
      await refreshed(repo, fixId);
      fake.setMergeRequest(repo.gitlabId, first.mrNumber!, { state: mrState });
      fake.clearRequests();
      await runFixJobs();

      expect(writes()).toEqual([]);
      expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(first.headSha);
      expect(await row(fixId)).toMatchObject({
        state: fixState,
        mrNumber: first.mrNumber,
        headSha: first.headSha,
        prepared: null,
        failure: null,
        declinedTarget: fixState === 'declined' ? '1.2.6' : null,
      });
    }
  });

  it('transient (F10: attempts count from 0): 60 s, 120 s, Retry-After, then scm_unavailable after the sixth', async () => {
    const repo = await freshRepo();
    const fixId = await accepted(repo);
    fake.inject(
      'POST',
      /\/repository\/commits$/,
      { status: 503 },
      { status: 503 },
      { status: 429, headers: { 'retry-after': '300' } },
      { status: 503 },
      { status: 503 },
      { status: 503 },
    );
    const expected = [
      [1, 60],
      [2, 120],
      [3, 300], // max(240, Retry-After 300)
      [4, 480],
      [5, 960],
    ] as const;
    for (const [attempt, delay] of expected) {
      await runFixJobs();
      const [job, ...more] = await queuedJob(fixId);
      expect(more).toEqual([]);
      expect(job!.payload).toEqual({ kind: 'commit', fixId, generation: 1, attempt });
      expect(job!.inSeconds).toBeGreaterThan(delay - 10);
      expect(job!.inSeconds).toBeLessThanOrEqual(delay);
      expect((await row(fixId)).state).toBe('committing');
    }
    await runFixJobs();
    expect(await queuedJob(fixId)).toEqual([]);
    expect(commitRequests()).toHaveLength(6);
    const ended = await row(fixId);
    expect(ended).toMatchObject({ state: 'failed', prepared: null, mrNumber: null });
    expect(ended.failure?.code).toBe('scm_unavailable');
    expect(fake.mergeRequestsOf(repo.gitlabId)).toEqual([]);
  });

  it('permission: a 403 fails the fix scm_permission with GitLab’s fixed text', async () => {
    const repo = await freshRepo();
    const fixId = await accepted(repo);
    fake.inject('POST', /\/repository\/commits$/, { status: 403 });
    await runFixJobs();
    const ended = await row(fixId);
    expect(ended).toMatchObject({ state: 'failed', prepared: null });
    expect(ended.failure?.code).toBe('scm_permission');
    expect(ended.failure?.message).toContain('HTTP 403');
    expect(await queuedJob(fixId)).toEqual([]);
  });

  it('F7, R8: a 403 on the refresh of an open fix keeps it open with the failure shown', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const first = await row(fixId);
    await refreshed(repo, fixId);
    fake.inject('POST', /\/repository\/commits$/, { status: 403 });
    await runFixJobs();
    const kept = await row(fixId);
    expect(kept).toMatchObject({
      state: 'open',
      refresh: false,
      mrNumber: first.mrNumber,
      headSha: first.headSha,
      prepared: null,
    });
    expect(kept.failure?.code).toBe('scm_permission');
    expect(fake.mergeRequestsOf(repo.gitlabId)[0]!.state).toBe('opened');
  });

  it('fails closed (Review Focus 5): fix MRs not allowed, or the project unbound, after the upload', async () => {
    const repo = await freshRepo({ ownConnection: true });
    const disallowed = await accepted(repo);
    await db()
      .update(scmConnections)
      .set({ fixMrsAllowed: false })
      .where(eq(scmConnections.id, repo.project.connectionId));
    fake.clearRequests();
    await runFixJobs();
    expect(await row(disallowed)).toMatchObject({
      state: 'failed',
      prepared: null,
      failure: { code: 'fixes_disabled' },
    });
    expect(fake.requests).toEqual([]);

    await db().delete(dependencyFixes).where(eq(dependencyFixes.id, disallowed));
    await db()
      .update(scmConnections)
      .set({ fixMrsAllowed: true })
      .where(eq(scmConnections.id, repo.project.connectionId));
    const unbound = await accepted(repo);
    await db()
      .update(projects)
      .set({ scmProjectRef: null })
      .where(eq(projects.id, repo.project.id));
    fake.clearRequests();
    await runFixJobs();
    expect(await row(unbound)).toMatchObject({
      state: 'failed',
      prepared: null,
      failure: { code: 'scm_not_bound' },
    });
    expect(fake.requests).toEqual([]);
    expect(fake.branches(repo.gitlabId)).toEqual(['main']);
  });

  it('cancel (R10): the MR closed with the comment and the branch deleted; a foreign head leaves both', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const { mrNumber } = await row(fixId);
    const cancel = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/fixes/${fixId}`,
      headers: h.orgAdmin.headers,
    });
    expect(cancel.statusCode, cancel.body).toBe(204);
    await runFixJobs();
    expect(fake.mergeRequestsOf(repo.gitlabId)[0]!.state).toBe('closed');
    expect(notes(repo, mrNumber!)).toEqual([cancelComment('gitlab')]);
    expect(fake.headOf(repo.gitlabId, BRANCH)).toBeNull();
    expect((await row(fixId)).state).toBe('cancelled');

    const other = await freshRepo();
    const otherFix = await openFix(other);
    const otherMr = (await row(otherFix)).mrNumber!;
    const person = fake.pushAs(other.gitlabId, BRANCH, { 'README.md': 'mine\n' });
    const cancelled = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/fixes/${otherFix}`,
      headers: h.orgAdmin.headers,
    });
    expect(cancelled.statusCode).toBe(204);
    fake.clearRequests();
    await runFixJobs();
    expect(writes()).toEqual([]);
    expect(fake.mergeRequestsOf(other.gitlabId)[0]!.state).toBe('opened');
    expect(notes(other, otherMr)).toEqual([]);
    expect(fake.headOf(other.gitlabId, BRANCH)).toBe(person);
  });

  it('T8c: a close job of an old generation drops; the re-armed fix updates the same MR', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const first = await row(fixId);
    const cancel = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/fixes/${fixId}`,
      headers: h.orgAdmin.headers,
    });
    expect(cancel.statusCode).toBe(204);
    const retried = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/fixes/${fixId}/retry`,
      headers: h.orgAdmin.headers,
    });
    expect(retried.statusCode, retried.body).toBe(202);
    fake.clearRequests();
    expect(await runFixJobs()).toBeGreaterThanOrEqual(1);
    // The close job did nothing.
    expect(fake.requests).toEqual([]);
    expect(fake.mergeRequestsOf(repo.gitlabId)[0]!.state).toBe('opened');
    expect((await row(fixId)).state).toBe('requested');

    await upload(repo, await claim(repo));
    fake.clearRequests();
    await runFixJobs();
    expect(fake.mergeRequestsOf(repo.gitlabId)).toHaveLength(1);
    expect(notes(repo, first.mrNumber!)).toEqual([]);
    expect(mrWrites().map((r) => `${r.method} ${r.path}`)).toEqual([
      `PUT /projects/${repo.gitlabId}/merge_requests/${first.mrNumber}`,
    ]);
    expect(await row(fixId)).toMatchObject({
      state: 'open',
      mrNumber: first.mrNumber,
      headSha: fake.headOf(repo.gitlabId, BRANCH),
    });
  });

  it('slot: with the organisation’s slots taken the job comes back in about 2 s, with no SCM call', async () => {
    const repo = await freshRepo();
    const fixId = await accepted(repo);
    for (let i = 0; i < MAX_DECORATIONS_PER_ORGANIZATION; i++) {
      expect(runtime.slots.tryTake(h.organizationId)).toBe(true);
    }
    fake.clearRequests();
    await runFixJobs();
    expect(fake.requests).toEqual([]);
    const [job] = await queuedJob(fixId);
    expect(job!.payload).toEqual({ kind: 'commit', fixId, generation: 1, attempt: 0 });
    expect(job!.inSeconds).toBeGreaterThan(0);
    expect(job!.inSeconds).toBeLessThanOrEqual(2);
    expect((await row(fixId)).state).toBe('committing');

    for (let i = 0; i < MAX_DECORATIONS_PER_ORGANIZATION; i++) {
      runtime.slots.release(h.organizationId);
    }
    await runFixJobs();
    expect((await row(fixId)).state).toBe('open');
    // The job gave its slot back.
    expect(runtime.slots.tryTake(h.organizationId)).toBe(true);
    expect(runtime.slots.tryTake(h.organizationId)).toBe(true);
  });

  describe('ruling T10a: an MR found by the branch name is the fix’s only when it is Qualor’s', () => {
    /** An open MR into main from a branch named like the fix's, as someone else opened it. */
    const strangerMr = (iid: number, over: Partial<FakeMergeRequest> = {}): FakeMergeRequest => ({
      iid,
      title: 'Their title',
      description: 'their description',
      state: 'opened',
      sourceBranch: BRANCH,
      targetBranch: 'main',
      headSha: 'd'.repeat(40),
      baseSha: 'e'.repeat(40),
      startSha: 'e'.repeat(40),
      diffs: [],
      ...over,
    });

    it('a fork’s MR from a branch of the same name is ignored, never written, and never ends the fix', async () => {
      const repo = await freshRepo();
      const forkId = ++gitlabIds;
      fake.addProject({ id: forkId, path: `mallory/fix-commit-${forkId}` });
      fake.addMergeRequest(repo.gitlabId, strangerMr(1, { sourceProjectId: forkId }));
      const fixId = await accepted(repo);
      fake.clearRequests();
      await runFixJobs();

      const opened = await row(fixId);
      expect(opened.state).toBe('open');
      expect(opened.mrNumber).not.toBe(1);
      expect(mrWrites().map((r) => `${r.method} ${r.path}`)).toEqual([
        `POST /projects/${repo.gitlabId}/merge_requests`,
      ]);
      const [fork, own] = fake.mergeRequestsOf(repo.gitlabId);
      expect(fork).toMatchObject({
        iid: 1,
        title: 'Their title',
        description: 'their description',
      });
      expect(own).toMatchObject({
        iid: opened.mrNumber,
        sourceBranch: BRANCH,
        title: GITLAB_TITLE,
      });

      // F8: whatever becomes of the fork's MR, the fix keeps its own.
      for (const state of ['merged', 'closed'] as const) {
        fake.setMergeRequest(repo.gitlabId, 1, { state });
        await refreshed(repo, fixId);
        await runFixJobs();
        expect(await row(fixId)).toMatchObject({
          state: 'open',
          mrNumber: opened.mrNumber,
          declinedTarget: null,
        });
      }
      expect(fake.mergeRequestsOf(repo.gitlabId)[0]).toMatchObject({
        title: 'Their title',
        description: 'their description',
      });
    });

    it('a re-armed fix (no MR number) finds its own MR by the branch, never a fork’s beside it', async () => {
      const repo = await freshRepo();
      const forkId = ++gitlabIds;
      fake.addProject({ id: forkId, path: `mallory/fix-commit-${forkId}` });
      // The fork's MR comes first in GitLab's list.
      fake.addMergeRequest(repo.gitlabId, strangerMr(1, { sourceProjectId: forkId }));
      const fixId = await openFix(repo);
      const own = (await row(fixId)).mrNumber;
      expect(own).not.toBe(1);
      // Cancel, then Retry before the close job: the MR number is cleared (ruling T8c).
      for (const [method, url] of [
        ['DELETE', `/api/v0/fixes/${fixId}`],
        ['POST', `/api/v0/fixes/${fixId}/retry`],
      ] as const) {
        const res = await h.ctx.app.inject({ method, url, headers: h.orgAdmin.headers });
        expect(res.statusCode, res.body).toBeLessThan(300);
      }
      expect((await row(fixId)).mrNumber).toBeNull();
      await upload(repo, await claim(repo));
      fake.clearRequests();
      await runFixJobs();

      expect(mrWrites().map((r) => `${r.method} ${r.path}`)).toEqual([
        `PUT /projects/${repo.gitlabId}/merge_requests/${own}`,
      ]);
      expect(await row(fixId)).toMatchObject({ state: 'open', mrNumber: own });
      expect(fake.mergeRequestsOf(repo.gitlabId)[0]).toMatchObject({
        title: 'Their title',
        description: 'their description',
        state: 'opened',
      });
    });

    it('rule 3: an MR of the branch whose head is not Qualor’s commit is not adopted', async () => {
      const repo = await freshRepo();
      // A person's MR from the branch, which they deleted since: the MR keeps their head.
      fake.addMergeRequest(repo.gitlabId, strangerMr(1));
      const fixId = await accepted(repo);
      fake.clearRequests();
      await runFixJobs();

      expect(mrWrites().filter((r) => r.method === 'PUT')).toEqual([]);
      expect(fake.mergeRequestsOf(repo.gitlabId)[0]).toMatchObject({
        title: 'Their title',
        description: 'their description',
        headSha: 'd'.repeat(40),
      });
      // GitLab takes one open MR per source branch and target: the new one is refused, so the fix
      // fails with nothing of theirs written.
      const ended = await row(fixId);
      expect(ended).toMatchObject({ state: 'failed', mrNumber: null });
      expect(ended.failure?.code).toBe('scm_refused');
    });
  });

  describe('ruling T10d', () => {
    it('F7: an MR adopted by its branch is stored, so a later 403 keeps the fix open with it', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const first = await row(fixId);
      // Cancel, then Retry before the close job: the MR number is cleared (ruling T8c).
      for (const [method, url] of [
        ['DELETE', `/api/v0/fixes/${fixId}`],
        ['POST', `/api/v0/fixes/${fixId}/retry`],
      ] as const) {
        const res = await h.ctx.app.inject({ method, url, headers: h.orgAdmin.headers });
        expect(res.statusCode, res.body).toBeLessThan(300);
      }
      await upload(repo, await claim(repo));
      fake.inject('POST', /\/repository\/commits$/, { status: 403 });
      await runFixJobs();

      const kept = await row(fixId);
      expect(kept).toMatchObject({
        state: 'open',
        refresh: false,
        mrNumber: first.mrNumber,
        mrUrl: first.mrUrl,
        headSha: first.headSha,
        prepared: null,
      });
      expect(kept.failure?.code).toBe('scm_permission');
      expect(fake.mergeRequestsOf(repo.gitlabId)[0]!.state).toBe('opened');
    });

    it('a fence that misses after the branch write stops the job: no MR is opened or updated', async () => {
      const repo = await freshRepo();
      const fixId = await accepted(repo);
      // The fix moves on (its generation is raised) while the branch is written.
      fake.inject('POST', /\/repository\/commits$/, {
        status: 201,
        passThrough: true,
        before: async () => {
          await db()
            .update(dependencyFixes)
            .set({ generation: sql`${dependencyFixes.generation} + 1` })
            .where(eq(dependencyFixes.id, fixId));
        },
      });
      fake.clearRequests();
      await runFixJobs();

      expect(commitRequests()).toHaveLength(1);
      expect(mrWrites()).toEqual([]);
      expect(fake.mergeRequestsOf(repo.gitlabId)).toEqual([]);
      expect(await row(fixId)).toMatchObject({
        state: 'committing',
        generation: 2,
        headSha: null,
        mrNumber: null,
      });
      expect(await queuedJob(fixId)).toEqual([]);
    });
  });

  it('FW14: an MR deleted on GitLab ends the refresh declined, or fixed once main is clean, with no branch write', async () => {
    for (const gone of [false, true]) {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const first = await row(fixId);
      await refreshed(repo, fixId);
      if (gone) {
        await db()
          .delete(targetVulnerabilities)
          .where(eq(targetVulnerabilities.projectId, repo.project.id));
      }
      // An owner deleted the MR: every read of it answers 404, while main can still be read.
      const deleted = { status: 404, body: { message: '404 Not found' } };
      const mrPath = new RegExp(`^/projects/${repo.gitlabId}/merge_requests/${first.mrNumber}$`);
      fake.inject('GET', mrPath, deleted, deleted, deleted);
      fake.clearRequests();
      await runFixJobs();

      expect(writes()).toEqual([]);
      expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(first.headSha);
      expect(await row(fixId)).toMatchObject({
        state: gone ? 'fixed' : 'declined',
        prepared: null,
        failure: null,
        declinedTarget: gone ? null : '1.2.6',
      });
      expect(await queuedJob(fixId)).toEqual([]);
    }
  });
});
