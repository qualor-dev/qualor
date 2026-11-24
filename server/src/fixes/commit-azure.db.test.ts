import { and, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  azureFixDeps,
  azurePatConnection,
  azureRepositoryWith,
  azureTestConfig,
  mappedAzureProject,
} from '../../test/azure';
import { createFakeAzureDevOps, type FakeAzureDevOps } from '../../test/fake-azure-devops';
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
import { seedTargetRow } from '../../test/vulnerabilities';
import { dependencyFixes, jobs } from '../db/schema';
import type { WorkerLogger } from '../queue/worker';
import { cancelComment } from './body';
import { FIX_QUEUE } from './jobs';
import type { FixJobDeps } from './run';

const CVE = 'CVE-2026-9601';
const BRANCH = 'qualor/fix/js/qf-a';
/** The commit message and an Azure DevOps title: plain (R30). */
const TITLE = 'Bump qf-a from 1.2.5 to 1.2.6';
const LAST =
  'Qualor keeps this PR current and closes it when the vulnerability is gone. Push to this branch to take it over.';
const ZERO = '0'.repeat(40);
const TEMPORARY =
  /^refs\/qualor\/fix-tmp\/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
/** Azure DevOps refuses a ref update in a 200 answer (`success: false`), as a branch policy does. */
const REFUSED_REF_UPDATE = {
  status: 200,
  body: { value: [{ success: false, updateStatus: 'rejectedByPolicy' }], count: 1 },
};
/** A description's size where Azure DevOps stores its line breaks as CRLF. */
const crlfBytes = (text: string) => Buffer.byteLength(text.replaceAll('\n', '\r\n'));

/** A repository of the fake, mapped to a Qualor project with fix pull requests on and qf-a vulnerable. */
interface Repo {
  id: string;
  name: string;
  project: IngestProject & { connectionId: string };
}

interface RefUpdate {
  name: string;
  oldObjectId: string;
  newObjectId: string;
}

interface Push {
  refUpdates: { name: string; oldObjectId: string }[];
  commits: {
    comment: string;
    parents: string[];
    changes: { changeType: string; item: { path: string } }[];
  }[];
}

describe('the fix commit and close jobs on Azure DevOps (Azure sub-plan 6; 0.16 fix MRs §6.7, B10, R8, FW4)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let connectionId: string;
  let repoNumber = 0;
  let deps: FixJobDeps;

  const db = () => h.ctx.db;
  const freshRepo = async (): Promise<Repo> => {
    const name = `fix-commit-${++repoNumber}`;
    const { id } = azureRepositoryWith(fake, name, {
      'package.json': packageJson('^1.2.5'),
      'package-lock.json': packageLock('1.2.5'),
      'README.md': '# app\n',
    });
    const project = await mappedAzureProject(h, connectionId, `FAZ-${repoNumber}`, id);
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
    return { id, name, project };
  };
  const mainOf = (repo: Repo) => fake.branches(repo.id)['main']!;
  const headOf = (repo: Repo) => fake.branches(repo.id)[BRANCH] ?? null;
  const claim = (repo: Repo) => claimFix(h, repo.project);
  const upload = (repo: Repo, item: Awaited<ReturnType<typeof claim>>) =>
    uploadQfA(h, repo.project, item, mainOf(repo));
  const accepted = (repo: Repo) => acceptedQfA(h, repo.project, mainOf(repo));
  /** An open fix to refresh: claimed and uploaded again, on main's head. */
  const refreshed = async (repo: Repo, fixId: string) => {
    await db().update(dependencyFixes).set({ refresh: true }).where(eq(dependencyFixes.id, fixId));
    await upload(repo, await claim(repo));
  };
  const runFixJobs = () => runQueuedFixJobs(db(), deps);
  const openFix = async (repo: Repo): Promise<string> => {
    const fixId = await openQfA(h, repo.project, mainOf(repo), deps);
    fake.clearRequests();
    return fixId;
  };
  const row = async (id: string) =>
    (await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, id)))[0]!;
  /** The requests a job sent, under the repository: `POST pushes`, `PATCH pullrequests/3`. */
  const requestsOf = () =>
    fake.requests.map(
      (r) => `${r.method} ${r.path.replace(/^.*\/_apis\/git\/repositories\/[^/]+\//, '')}`,
    );
  const writes = () => requestsOf().filter((r) => !r.startsWith('GET '));
  const bodiesOf = <T>(method: string, route: string): T[] =>
    fake.requests
      .filter((r) => r.method === method && r.path.endsWith(`/${route}`))
      .map((r) => JSON.parse(r.body) as T);
  /** Main moved on: a commit on it adds `CHANGELOG.md`. Its id. */
  const moveMain = (repo: Repo): string => {
    const next = fake.addCommit(repo.id, {
      parents: [mainOf(repo)],
      files: { 'CHANGELOG.md': 'one\n' },
    });
    fake.setBranch(repo.id, 'main', next);
    return next;
  };
  /** A person's commit on the fix branch, on top of `onto`. Its id. */
  const personPushes = (repo: Repo, onto: string): string => {
    const mine = fake.addCommit(repo.id, { parents: [onto], files: { 'README.md': 'mine\n' } });
    fake.setBranch(repo.id, BRANCH, mine);
    return mine;
  };
  const temporaryRefs = (repo: Repo) =>
    Object.keys(fake.refs(repo.id)).filter((name) => name.startsWith('refs/qualor/'));
  /** The fix's queued job and how many seconds from now it runs. */
  const queuedJob = (fixId: string) =>
    db()
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
  const cancel = async (fixId: string) => {
    const res = await h.ctx.app.inject({
      method: 'DELETE',
      url: `/api/v0/fixes/${fixId}`,
      headers: h.orgAdmin.headers,
    });
    expect(res.statusCode, res.body).toBe(204);
  };
  const capture = () => {
    const lines: [string, ...unknown[]][] = [];
    const logger: WorkerLogger = {
      info: (...a: unknown[]) => void lines.push(['info', ...a]),
      warn: (...a: unknown[]) => void lines.push(['warn', ...a]),
      error: (...a: unknown[]) => void lines.push(['error', ...a]),
    };
    return { lines, logger };
  };

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({ deployment: 'server' });
    h = await createIngestHarness({ config: azureTestConfig(fake) });
    connectionId = await azurePatConnection(h, fake, { fixMrsAllowed: true });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(() => {
    deps = azureFixDeps(h);
    fake.clearRequests();
  });
  afterEach(async () => {
    await db().delete(jobs).where(eq(jobs.queue, FIX_QUEUE));
  });

  it('first commit: one push of edit changes on baseSha, the PR opened, the fix open', async () => {
    const repo = await freshRepo();
    const fixId = await accepted(repo);
    const base = mainOf(repo);
    fake.clearRequests();
    await runFixJobs();

    expect(writes()).toEqual(['POST pushes', 'POST pullrequests']);
    const head = headOf(repo)!;
    const [push] = bodiesOf<Push>('POST', 'pushes');
    expect(push!.refUpdates).toEqual([{ name: `refs/heads/${BRANCH}`, oldObjectId: ZERO }]);
    expect(push!.commits).toHaveLength(1);
    expect(push!.commits[0]).toMatchObject({ comment: TITLE, parents: [base] });
    expect(push!.commits[0]!.changes.map((c) => [c.changeType, c.item.path])).toEqual([
      ['edit', '/package.json'],
      ['edit', '/package-lock.json'],
    ]);
    expect(fake.fileAt(repo.id, head, 'package.json')).toBe(packageJson('^1.2.6'));
    expect(fake.fileAt(repo.id, head, 'package-lock.json')).toBe(packageLock('1.2.6'));
    expect(fake.fileAt(repo.id, head, 'README.md')).toBe('# app\n');
    expect(mainOf(repo)).toBe(base);

    const [pr, ...others] = fake.pullRequests(repo.id);
    expect(others).toEqual([]);
    expect(pr).toMatchObject({
      sourceRefName: `refs/heads/${BRANCH}`,
      targetRefName: 'refs/heads/main',
      title: TITLE,
      status: 'active',
    });
    expect(pr!.description).toContain(`| \` ${CVE} \` | high |`);
    expect(pr!.description.endsWith(`\n\n${LAST}`)).toBe(true);
    expect(await row(fixId)).toMatchObject({
      state: 'open',
      mrNumber: pr!.id,
      mrUrl: `${fake.url}/Payments/_git/${repo.name}/pullrequest/${pr!.id}`,
      headSha: head,
      prepared: null,
      failure: null,
    });
  });

  it('refresh force-moves Qualor’s own branch through a temporary ref, updates the PR, and leaves no temporary ref', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const first = await row(fixId);
    const base = moveMain(repo);
    await refreshed(repo, fixId);
    fake.clearRequests();
    await runFixJobs();

    expect(writes()).toEqual([
      'POST pushes',
      'POST refs',
      'POST refs',
      `PATCH pullrequests/${first.mrNumber}`,
    ]);
    const head = headOf(repo)!;
    expect(head).not.toBe(first.headSha);
    const [push] = bodiesOf<Push>('POST', 'pushes');
    const temporary = push!.refUpdates[0]!.name;
    expect(temporary).toMatch(TEMPORARY);
    expect(push!.refUpdates[0]!.oldObjectId).toBe(ZERO);
    expect(push!.commits[0]!.parents).toEqual([base]);
    // The branch moved from Qualor's last commit (not a fast-forward), then the temporary ref went.
    expect(bodiesOf<RefUpdate[]>('POST', 'refs')).toEqual([
      [{ name: `refs/heads/${BRANCH}`, oldObjectId: first.headSha, newObjectId: head }],
      [{ name: temporary, oldObjectId: head, newObjectId: ZERO }],
    ]);
    expect(temporaryRefs(repo)).toEqual([]);
    expect(fake.fileAt(repo.id, head, 'CHANGELOG.md')).toBe('one\n');
    expect(fake.fileAt(repo.id, head, 'package.json')).toBe(packageJson('^1.2.6'));
    expect(fake.pullRequests(repo.id)).toHaveLength(1);
    expect(await row(fixId)).toMatchObject({
      state: 'open',
      mrNumber: first.mrNumber,
      headSha: head,
      refresh: false,
      failure: null,
    });

    // The branch update refused (a branch policy): the temporary ref still goes, nothing else is
    // written, and the fix keeps its PR, open with the failure shown (R8).
    await refreshed(repo, fixId);
    fake.inject('POST', /\/refs$/, REFUSED_REF_UPDATE);
    fake.clearRequests();
    await runFixJobs();
    expect(writes()).toEqual(['POST pushes', 'POST refs', 'POST refs']);
    expect(bodiesOf<RefUpdate[]>('POST', 'refs')[1]![0]).toMatchObject({ newObjectId: ZERO });
    expect(temporaryRefs(repo)).toEqual([]);
    expect(headOf(repo)).toBe(head);
    const kept = await row(fixId);
    expect(kept).toMatchObject({ state: 'open', mrNumber: first.mrNumber, headSha: head });
    expect(kept.failure).toEqual({
      code: 'scm_refused',
      message:
        'The fix branch or MR could not be written: Azure DevOps refused to change the branch',
    });
  });

  it('a push between the read and the write ends taken_over and writes nothing else (RF1)', async () => {
    // A refresh: the person pushes while Qualor's commit goes to the temporary ref, before the
    // second read of the head.
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const first = await row(fixId);
    await refreshed(repo, fixId);
    let person = '';
    fake.inject('POST', /\/pushes$/, {
      status: 201,
      passThrough: true,
      before: async () => {
        person = personPushes(repo, first.headSha!);
      },
    });
    fake.clearRequests();
    await runFixJobs();
    expect(headOf(repo)).toBe(person);
    expect(writes()).toEqual(['POST pushes', 'POST refs']);
    const [drop] = bodiesOf<RefUpdate[]>('POST', 'refs');
    expect(drop![0]).toMatchObject({ name: expect.stringMatching(TEMPORARY), newObjectId: ZERO });
    expect(temporaryRefs(repo)).toEqual([]);
    expect(await row(fixId)).toMatchObject({
      state: 'taken_over',
      headSha: first.headSha,
      prepared: null,
    });

    // A first commit: the branch appears while the push is on its way; Azure DevOps refuses it
    // (the old id is no longer the zero one) and the head read again says whose it is.
    const other = await freshRepo();
    const otherFix = await accepted(other);
    let theirs = '';
    fake.inject('POST', /\/pushes$/, {
      status: 201,
      passThrough: true,
      before: async () => {
        theirs = personPushes(other, mainOf(other));
      },
    });
    fake.clearRequests();
    await runFixJobs();
    expect(headOf(other)).toBe(theirs);
    expect(writes()).toEqual(['POST pushes']);
    expect(fake.pullRequests(other.id)).toEqual([]);
    expect(await row(otherFix)).toMatchObject({
      state: 'taken_over',
      mrNumber: null,
      prepared: null,
    });

    // A refresh again, the person's push landing after the second read: the branch update holds
    // to Qualor's last commit, Azure DevOps answers staleOldObjectId, and their head stays.
    const late = await freshRepo();
    const lateFix = await openFix(late);
    const lateFirst = await row(lateFix);
    await refreshed(late, lateFix);
    let racer = '';
    fake.inject('POST', /\/refs$/, {
      status: 200,
      passThrough: true,
      before: async () => {
        racer = personPushes(late, lateFirst.headSha!);
      },
    });
    fake.clearRequests();
    await runFixJobs();
    expect(headOf(late)).toBe(racer);
    expect(writes()).toEqual(['POST pushes', 'POST refs', 'POST refs']);
    expect(temporaryRefs(late)).toEqual([]);
    expect(fake.pullRequest(late.id, lateFirst.mrNumber!).title).toBe(TITLE);
    expect(await row(lateFix)).toMatchObject({ state: 'taken_over', headSha: lateFirst.headSha });
  });

  it('a refused branch update is taken_over when the head moved, an error when it did not (FW4)', async () => {
    // Azure DevOps has no distinct stale answer for this update: any refusal while the head moved
    // since the read is a person's push.
    const moved = await freshRepo();
    const movedFix = await openFix(moved);
    const first = await row(movedFix);
    await refreshed(moved, movedFix);
    let racer = '';
    fake.inject('POST', /\/refs$/, {
      ...REFUSED_REF_UPDATE,
      before: async () => {
        racer = personPushes(moved, first.headSha!);
      },
    });
    await runFixJobs();
    expect(headOf(moved)).toBe(racer);
    expect(temporaryRefs(moved)).toEqual([]);
    expect(await row(movedFix)).toMatchObject({ state: 'taken_over', headSha: first.headSha });

    // The head did not move: the refusal stands, here a missing right (FW5).
    const still = await freshRepo();
    const stillFix = await openFix(still);
    await refreshed(still, stillFix);
    fake.inject('POST', /\/refs$/, {
      status: 200,
      body: { value: [{ success: false, updateStatus: 'forcePushRequired' }], count: 1 },
    });
    await runFixJobs();
    expect(temporaryRefs(still)).toEqual([]);
    expect(await row(stillFix)).toMatchObject({ state: 'open' });
    expect((await row(stillFix)).failure?.code).toBe('scm_permission');
  });

  it('a temporary ref that cannot be deleted is logged without Azure DevOps’ words, and the refresh stands', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    await refreshed(repo, fixId);
    // The branch update goes through; the delete of the temporary ref fails.
    fake.inject(
      'POST',
      /\/refs$/,
      { status: 200, passThrough: true },
      { status: 500, body: { message: 'internal words of Azure DevOps' } },
    );
    const { lines, logger } = capture();
    deps = azureFixDeps(h, logger);
    await runFixJobs();

    const head = headOf(repo)!;
    expect(await row(fixId)).toMatchObject({ state: 'open', headSha: head, failure: null });
    expect(temporaryRefs(repo)).toHaveLength(1);
    const warned = lines.filter(([level]) => level === 'warn');
    expect(warned).toEqual([
      [
        'warn',
        {
          errorKind: 'transient',
          httpStatus: 500,
          request: expect.stringMatching(/^POST .*\/refs$/),
        },
        'fix commit: the temporary ref of a refresh could not be deleted',
      ],
    ]);
    expect(JSON.stringify(lines)).not.toContain('internal words');
  });

  it('a PR completed or abandoned before the write ends merged or declined', async () => {
    for (const [status, state] of [
      ['completed', 'merged'],
      ['abandoned', 'declined'],
    ] as const) {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const first = await row(fixId);
      await refreshed(repo, fixId);
      fake.pullRequest(repo.id, first.mrNumber!).status = status;
      fake.clearRequests();
      await runFixJobs();

      expect(writes()).toEqual([]);
      expect(headOf(repo)).toBe(first.headSha);
      expect(await row(fixId)).toMatchObject({
        state,
        mrNumber: first.mrNumber,
        prepared: null,
        failure: null,
        declinedTarget: state === 'declined' ? '1.2.6' : null,
      });
    }
  });

  it('a description over 4 000 bytes is cut at whole lines with the closing sentence (RF2)', async () => {
    const repo = await freshRepo();
    const main = await mainBranchId(db(), repo.project.id);
    // Fifty vulnerabilities with long titles, some of them not ASCII: far over 4 000 bytes.
    for (let i = 1; i < 50; i++) {
      await seedTargetRow(db(), {
        projectId: repo.project.id,
        branchId: main,
        ecosystem: 'npm',
        packageName: 'qf-a',
        packageVersion: '1.2.5',
        vulnerabilityId: `CVE-2026-${9700 + i}`,
        severity: 'medium',
        title: `Préfixe ${i}: ${'désérialisation non sûre '.repeat(4)}`,
        fixedVersion: '1.2.6',
      });
    }
    const fixId = await accepted(repo);
    await runFixJobs();

    const [pr] = fake.pullRequests(repo.id);
    const description = pr!.description;
    // Within 4 000 even with CRLF line breaks: UTF-8 bytes plus one per line break.
    expect(crlfBytes(description)).toBeLessThanOrEqual(4_000);
    expect(crlfBytes(description)).toBeGreaterThan(3_000);
    expect(description.endsWith(`\n\n${LAST}`)).toBe(true);
    const table = description.split('\n').filter((line) => line.startsWith('|'));
    expect(table.length).toBeGreaterThan(2);
    expect(table.length).toBeLessThan(52);
    // Whole rows only: each kept row is closed.
    for (const line of table) expect(line.endsWith('|'), line).toBe(true);
    expect((await row(fixId)).state).toBe('open');

    // The refresh's update is bounded the same way (Azure DevOps refuses 4 001 characters).
    await refreshed(repo, fixId);
    fake.clearRequests();
    await runFixJobs();
    const [patch] = bodiesOf<{ description: string }>('PATCH', `pullrequests/${pr!.id}`);
    expect(crlfBytes(patch!.description)).toBeLessThanOrEqual(4_000);
    expect(patch!.description.endsWith(`\n\n${LAST}`)).toBe(true);
    expect(await row(fixId)).toMatchObject({ state: 'open', failure: null });
  });

  it('a 5xx retries as a decoration does; a 403 fails scm_permission', async () => {
    const repo = await freshRepo();
    const fixId = await accepted(repo);
    fake.inject('POST', /\/pushes$/, { status: 503 });
    await runFixJobs();
    const [job, ...more] = await queuedJob(fixId);
    expect(more).toEqual([]);
    expect(job!.payload).toEqual({ kind: 'commit', fixId, generation: 1, attempt: 1 });
    expect(job!.inSeconds).toBeGreaterThan(50);
    expect(job!.inSeconds).toBeLessThanOrEqual(60);
    expect((await row(fixId)).state).toBe('committing');

    fake.inject('POST', /\/pushes$/, { status: 403 });
    await runFixJobs();
    const ended = await row(fixId);
    expect(ended).toMatchObject({ state: 'failed', prepared: null, mrNumber: null });
    expect(ended.failure?.code).toBe('scm_permission');
    expect(ended.failure?.message).toMatch(/^The fix branch or MR could not be written: /);
    expect(await queuedJob(fixId)).toEqual([]);
    expect(headOf(repo)).toBeNull();
    expect(fake.pullRequests(repo.id)).toEqual([]);
  });

  it('T10a: a fork’s PR from a branch of the same name is never the fix’s', async () => {
    const repo = await freshRepo();
    const fork = fake.addPullRequest(repo.id, {
      sourceRefName: `refs/heads/${BRANCH}`,
      targetRefName: 'refs/heads/main',
      title: 'Their title',
      description: 'their description',
      fork: true,
    });
    const fixId = await accepted(repo);
    fake.clearRequests();
    await runFixJobs();

    const opened = await row(fixId);
    expect(opened.state).toBe('open');
    expect(opened.mrNumber).not.toBe(fork.id);
    expect(writes()).toContain('POST pullrequests');
    expect(writes().filter((w) => w.startsWith('PATCH '))).toEqual([]);
    expect(fork).toMatchObject({ title: 'Their title', description: 'their description' });
  });

  it('cancel: a closed thread with the comment, the PR abandoned, the branch deleted', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const { mrNumber, headSha } = await row(fixId);
    await cancel(fixId);
    await runFixJobs();

    expect(writes()).toEqual([
      `POST pullrequests/${mrNumber}/threads`,
      `PATCH pullrequests/${mrNumber}`,
      'POST refs',
    ]);
    const pr = fake.pullRequest(repo.id, mrNumber!);
    expect(pr.status).toBe('abandoned');
    expect(pr.threads.map((t) => [t.status, t.filePath, t.comments.map((c) => c.content)])).toEqual(
      [['closed', null, [cancelComment('azure')]]],
    );
    expect(bodiesOf<RefUpdate[]>('POST', 'refs')).toEqual([
      [{ name: `refs/heads/${BRANCH}`, oldObjectId: headSha, newObjectId: ZERO }],
    ]);
    expect(headOf(repo)).toBeNull();
    expect(await row(fixId)).toMatchObject({ state: 'cancelled', failure: null });
  });

  it('cancel when Azure refuses the delete keeps the branch (FW4)', async () => {
    // A refusal in a 200 answer (`success: false`, a branch policy) and an HTTP 403 (a missing
    // permission): both are for good, so the branch is kept and the fix stays cancelled.
    const forbidden = { status: 403, body: { message: 'TF401027: You need the permission.' } };
    for (const refusal of [REFUSED_REF_UPDATE, forbidden]) {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber, headSha } = await row(fixId);
      await cancel(fixId);
      fake.inject('POST', /\/refs$/, refusal);
      const { lines, logger } = capture();
      deps = azureFixDeps(h, logger);
      await runFixJobs();

      expect(fake.pullRequest(repo.id, mrNumber!).status, String(refusal.status)).toBe('abandoned');
      expect(headOf(repo)).toBe(headSha);
      expect(await row(fixId)).toMatchObject({ state: 'cancelled', failure: null });
      expect(await queuedJob(fixId)).toEqual([]);
      const kept = lines.filter(
        ([level, , message]) => level === 'warn' && /branch is kept/.test(String(message)),
      );
      expect(kept).toHaveLength(1);
      expect(JSON.stringify(lines)).not.toContain('TF401027');
    }
  });

  it('a create whose answer was lost: the retry adopts the pull request by its branch head (ledger ruling)', async () => {
    const repo = await freshRepo();
    const fixId = await accepted(repo);
    // Azure DevOps makes the pull request, but its answer never arrives (a 503 instead). The pull
    // request has no `lastMergeSourceCommit` yet: Azure has not merged it.
    fake.inject('POST', /\/pullrequests$/, {
      status: 503,
      before: async () => {
        const sent = JSON.parse(fake.requests.at(-1)!.body) as {
          sourceRefName: string;
          targetRefName: string;
          title: string;
          description: string;
        };
        fake.addPullRequest(repo.id, { ...sent, headSha: null, mergeStatus: null });
      },
    });
    await runFixJobs();
    const [made, ...none] = fake.pullRequests(repo.id);
    expect(none).toEqual([]);
    expect(made!.headSha).toBeNull();
    expect(await row(fixId)).toMatchObject({
      state: 'committing',
      mrNumber: null,
      headSha: headOf(repo),
    });

    // The retry finds it by its branch: its head is the branch's, Qualor's commit, so it is adopted
    // and updated, never opened twice (Azure DevOps would refuse a second, TF401179).
    fake.clearRequests();
    await runFixJobs();
    expect(fake.pullRequests(repo.id)).toHaveLength(1);
    expect(writes()).not.toContain('POST pullrequests');
    expect(writes()).toContain(`PATCH pullrequests/${made!.id}`);
    expect(fake.pullRequest(repo.id, made!.id).headSha).toBeNull();
    expect(await row(fixId)).toMatchObject({
      state: 'open',
      mrNumber: made!.id,
      mrUrl: `${fake.url}/Payments/_git/${repo.name}/pullrequest/${made!.id}`,
      headSha: headOf(repo),
      failure: null,
    });
  });
});
