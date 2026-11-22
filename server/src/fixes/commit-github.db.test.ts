import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitHub, type FakeGitHub } from '../../test/fake-github';
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
import { githubTestConfig, mappedGitHubProject } from '../../test/github';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { PUBLIC_URL, silentLogger } from '../../test/scm';
import { dependencyFixes, jobs } from '../db/schema';
import { communityLimits } from '../limits';
import { MutationPacer } from '../scm/github/app-auth';
import { createScmRuntime } from '../scm/runtime';
import { FIX_QUEUE } from './jobs';
import type { FixJobDeps } from './run';

const BRANCH = 'qualor/fix/js/qf-a';
const TITLE = 'Bump qf-a from 1.2.5 to 1.2.6';

interface Repo {
  id: number;
  name: string;
  project: IngestProject & { connectionId: string };
}

describe('the fix commit job on GitHub (0.16 fix MRs §6.7, B10, R14; Git Data API)', () => {
  let h: IngestHarness;
  let fake: FakeGitHub;
  let repoIds = 60;

  const db = () => h.ctx.db;
  /** Mutations one second apart (GitHub's pacing), on a fake clock: no real sleep. */
  const runtime = () => {
    let t = 0;
    const made = createScmRuntime();
    made.githubPacer = new MutationPacer(
      () => t,
      async (ms) => {
        t += ms;
      },
    );
    return made;
  };
  let deps: FixJobDeps;

  const freshRepo = async (): Promise<Repo> => {
    const id = ++repoIds;
    const name = `fix-commit-${id}`;
    fake.addRepository({ id, owner: 'acme', name, installationId: 777 });
    fake.addFile(id, 'package.json', packageJson('^1.2.5'));
    fake.addFile(id, 'package-lock.json', packageLock('1.2.5'));
    fake.addFile(id, 'README.md', '# app\n');
    const project = await mappedGitHubProject(h, fake, `FG-${id}`, `acme/${name}`);
    await enableFixes(h, project.id, { maxOpen: 20 });
    await seedMainVulnerability(
      db(),
      { id: project.id, mainBranchId: await mainBranchId(db(), project.id) },
      {
        ecosystem: 'npm',
        packageName: 'qf-a',
        version: '1.2.5',
        vulnerabilityId: 'CVE-2026-9401',
        severity: 'critical',
        fixedVersion: '1.2.6',
      },
    );
    return { id, name, project };
  };
  const claim = (repo: Repo) => claimFix(h, repo.project);
  const upload = (repo: Repo, item: Awaited<ReturnType<typeof claim>>) =>
    uploadQfA(h, repo.project, item, fake.headOf(repo.id, 'main'));
  const accepted = (repo: Repo) => acceptedQfA(h, repo.project, fake.headOf(repo.id, 'main'));
  const refreshed = async (repo: Repo, fixId: string) => {
    await db().update(dependencyFixes).set({ refresh: true }).where(eq(dependencyFixes.id, fixId));
    await upload(repo, await claim(repo));
  };
  /** The queued commit and close jobs, run now; the organisation's passes are dropped first. */
  const runFixJobs = () => runQueuedFixJobs(db(), deps);
  const openFix = async (repo: Repo): Promise<string> => {
    const fixId = await openQfA(h, repo.project, fake.headOf(repo.id, 'main'), deps);
    fake.clearRequests();
    return fixId;
  };
  const row = async (id: string) =>
    (await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, id)))[0]!;
  /** What the job asked GitHub to change (an installation token is no change). */
  const writes = () =>
    fake.requests
      .filter((r) => r.method !== 'GET' && !/access_tokens$/.test(r.path))
      .map((r) => `${r.method} ${r.path.replace(/^\/repos\/acme\/[^/]+/, '')}`);
  const bodyOf = (method: string, suffix: string) =>
    JSON.parse(
      fake.requests.find((r) => r.method === method && r.path.endsWith(suffix))?.body ?? 'null',
    ) as Record<string, unknown> | null;

  beforeAll(async () => {
    fake = await createFakeGitHub();
    h = await createIngestHarness({ config: githubTestConfig(fake) });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(() => {
    deps = {
      db: db(),
      scm: {
        secretKey: h.ctx.config.secretKey,
        internalHosts: h.ctx.config.scmInternalHosts,
        azureTokenOrigin: null,
        azureTestOrigin: null,
        githubClientOptions: { timeoutMs: 2_000 },
      },
      runtime: runtime(),
      publicUrl: PUBLIC_URL,
      limits: () => communityLimits(),
      logger: silentLogger,
    };
    fake.clearRequests();
  });
  afterEach(async () => {
    await db().delete(jobs).where(eq(jobs.queue, FIX_QUEUE));
  });

  it('first commit: blobs, a tree on the base tree, a commit on baseSha, the ref and the PR', async () => {
    const repo = await freshRepo();
    const fixId = await accepted(repo);
    const base = fake.headOf(repo.id, 'main')!;
    fake.clearRequests();
    await runFixJobs();

    expect(writes()).toEqual([
      'POST /git/blobs',
      'POST /git/blobs',
      'POST /git/trees',
      'POST /git/commits',
      'POST /git/refs',
      'POST /pulls',
    ]);
    const head = fake.headOf(repo.id, BRANCH)!;
    expect(bodyOf('POST', '/git/commits')).toMatchObject({ message: TITLE, parents: [base] });
    expect(bodyOf('POST', '/git/refs')).toEqual({ ref: `refs/heads/${BRANCH}`, sha: head });
    const tree = bodyOf('POST', '/git/trees') as { base_tree: string; tree: { mode: string }[] };
    expect(tree.tree.map((e) => e.mode)).toEqual(['100644', '100644']);
    expect(fake.fileAt(repo.id, head, 'package.json')).toBe(packageJson('^1.2.6'));
    expect(fake.fileAt(repo.id, head, 'package-lock.json')).toBe(packageLock('1.2.6'));
    expect(fake.fileAt(repo.id, head, 'README.md')).toBe('# app\n');

    const [pull, ...others] = fake.pullsOf(repo.id);
    expect(others).toEqual([]);
    expect(pull).toMatchObject({ head: BRANCH, base: 'main', title: TITLE, state: 'open' });
    expect(pull!.body).toContain('| ` CVE-2026-9401 ` | critical |');
    expect(pull!.body).toMatch(
      /Qualor keeps this PR current and closes it when the vulnerability is gone\. Push to this branch to take it over\.$/,
    );
    expect(await row(fixId)).toMatchObject({
      state: 'open',
      mrNumber: pull!.number,
      mrUrl: expect.stringMatching(new RegExp(`/acme/${repo.name}/pull/${pull!.number}$`)),
      headSha: head,
      prepared: null,
    });
  });

  it('taken over (§11.2): a person’s push stops the refresh, their head and the PR untouched', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const person = fake.pushAs(repo.id, BRANCH, { 'package.json': packageJson('^1.2.7') });
    await refreshed(repo, fixId);
    fake.clearRequests();
    await runFixJobs();

    expect(await row(fixId)).toMatchObject({ state: 'taken_over', prepared: null });
    expect(fake.headOf(repo.id, BRANCH)).toBe(person);
    expect(writes()).toEqual([]);
    expect(fake.pullsOf(repo.id)[0]!.state).toBe('open');
  });

  it('B10: a push between the check and the ref write is kept; the fix is taken over', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    await refreshed(repo, fixId);
    let person = '';
    fake.inject('POST', /\/git\/commits$/, {
      status: 201,
      passThrough: true,
      before: () => {
        person = fake.pushAs(repo.id, BRANCH, { 'README.md': 'mine\n' });
      },
    });
    fake.clearRequests();
    await runFixJobs();

    expect(fake.headOf(repo.id, BRANCH)).toBe(person);
    // The blobs, tree and commit were made; no ref was moved and the PR was not written.
    expect(writes()).toEqual([
      'POST /git/blobs',
      'POST /git/blobs',
      'POST /git/trees',
      'POST /git/commits',
    ]);
    expect(await row(fixId)).toMatchObject({ state: 'taken_over', prepared: null });
  });

  it('refresh and F8 on GitHub: the ref force-moved and the PR updated; a merged PR ends it unwritten', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const first = await row(fixId);
    fake.addFile(repo.id, 'CHANGELOG.md', 'one\n');
    await refreshed(repo, fixId);
    fake.clearRequests();
    await runFixJobs();
    expect(writes()).toEqual([
      'POST /git/blobs',
      'POST /git/blobs',
      'POST /git/trees',
      'POST /git/commits',
      `PATCH /git/refs/heads/${BRANCH}`,
      `PATCH /pulls/${first.mrNumber}`,
    ]);
    expect(bodyOf('PATCH', `/git/refs/heads/${BRANCH}`)).toMatchObject({ force: true });
    expect(fake.fileAt(repo.id, fake.headOf(repo.id, BRANCH)!, 'CHANGELOG.md')).toBe('one\n');
    expect(fake.pullsOf(repo.id)).toHaveLength(1);
    expect((await row(fixId)).state).toBe('open');

    await refreshed(repo, fixId);
    fake.setPull(repo.id, first.mrNumber!, { state: 'closed', merged: true });
    fake.clearRequests();
    await runFixJobs();
    expect(writes()).toEqual([]);
    expect(await row(fixId)).toMatchObject({ state: 'merged', prepared: null });
  });

  it('T10a: a fork’s PR from a branch of the same name (its owner of the same login) is never the fix’s', async () => {
    const repo = await freshRepo();
    const fork = fake.openPullAs(repo.id, {
      head: BRANCH,
      base: 'main',
      title: 'Their title',
      body: 'their body',
      headRepo: { id: 9000 + repo.id, owner: 'acme', name: `${repo.name}-fork` },
    });
    const fixId = await accepted(repo);
    fake.clearRequests();
    await runFixJobs();

    const opened = await row(fixId);
    expect(opened.state).toBe('open');
    expect(opened.mrNumber).not.toBe(fork.number);
    expect(writes()).toContain('POST /pulls');
    expect(writes().filter((w) => w.startsWith('PATCH /pulls/'))).toEqual([]);
    expect(fork).toMatchObject({ title: 'Their title', body: 'their body', state: 'open' });

    // F8: the fork's PR merged never ends the fix, which keeps its own PR.
    fake.setPull(repo.id, fork.number, { merged: true });
    await refreshed(repo, fixId);
    fake.clearRequests();
    await runFixJobs();
    expect(await row(fixId)).toMatchObject({ state: 'open', mrNumber: opened.mrNumber });
    expect(writes()).toContain(`PATCH /pulls/${opened.mrNumber}`);
    expect(fork).toMatchObject({ title: 'Their title', body: 'their body' });
  });
});
