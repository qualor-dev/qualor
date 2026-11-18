import { createHash } from 'node:crypto';
import type { FixClaimAnswer, FixClaimItem } from '@qualor/shared/fix';
import { and, eq, like, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { bearer } from '../../test/app';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { enableFixes, seedFix, seedMainVulnerability } from '../../test/fixes';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { mappedProject, PUBLIC_URL, scmTestConfig, silentLogger } from '../../test/scm';
import { seedCheck } from '../../test/vulnerabilities';
import {
  dependencyFixes,
  jobs,
  organizations,
  projectFixSettings,
  projects,
  projectVulnerabilitySettings,
  scmConnections,
  targetVulnerabilities,
  vulnerabilityTargetChecks,
} from '../db/schema';
import { communityLimits } from '../limits';
import { runUntilIdle, type WorkerLogger } from '../queue/worker';
import { createScmRuntime } from '../scm/runtime';
import { goneComment } from './body';
import { FIX_QUEUE, FIX_SYNC_INTERVAL_SECONDS, fixSyncKey, scheduleFixSync } from './jobs';
import { fixHandlers, type FixJobDeps } from './run';
import { expireLeases, runFixSyncPass, type FixPassOutcome } from './sync';

const NPM = 'https://registry.npmjs.org';
const CVE = 'CVE-2026-9401';
const BRANCH = 'qualor/fix/js/qf-a';
const BRANCH_PATH = /\/repository\/branches\/qualor%2Ffix%2Fjs%2Fqf-a$/;
const MR_READ = /\/merge_requests\/\d+$/;
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

const integrity = (version: string) => {
  const digest = createHash('sha512').update(`qf-a-${version}`).digest('base64');
  return `sha512-${digest}`;
};
const packageJson = (range: string) =>
  `{\n  "name": "app",\n  "dependencies": {\n    "qf-a": "${range}"\n  }\n}\n`;
const packageLock = (version: string) =>
  `${JSON.stringify(
    {
      name: 'app',
      lockfileVersion: 3,
      packages: {
        '': { name: 'app', dependencies: { 'qf-a': '^1.2.5' } },
        'node_modules/qf-a': {
          version,
          resolved: `${NPM}/qf-a/-/qf-a-${version}.tgz`,
          integrity: integrity(version),
        },
      },
    },
    null,
    2,
  )}\n`;
const b64 = (text: string) => Buffer.from(text).toString('base64');

/** A GitLab project of the fake, mapped to a Qualor project with fix MRs on and qf-a vulnerable. */
interface Repo {
  gitlabId: number;
  project: IngestProject & { connectionId: string };
  token: Record<string, string>;
  main: string;
}

const ZERO: FixPassOutcome = {
  expired: 0,
  merged: 0,
  declined: 0,
  takenOver: 0,
  fixed: 0,
  refreshed: 0,
  requested: 0,
  stop: null,
};

describe('the fix sync pass (0.16 fix MRs §6.7, R8, R18, B10, rulings T8c, T10c, F28)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;
  let runtime = createScmRuntime();
  let gitlabIds = 500;

  const db = () => h.ctx.db;
  const deps = (over: Partial<FixJobDeps> = {}): FixJobDeps => ({
    db: db(),
    scm: {
      secretKey: h.ctx.config.secretKey,
      internalHosts: h.ctx.config.scmInternalHosts,
      clientOptions: { timeoutMs: 2_000 },
    },
    runtime,
    publicUrl: PUBLIC_URL,
    limits: () => communityLimits(),
    logger: silentLogger,
    ...over,
  });

  const freshRepo = async (options: { ownConnection?: boolean } = {}): Promise<Repo> => {
    const gitlabId = ++gitlabIds;
    fake.addProject({ id: gitlabId, path: `acme/fix-sync-${gitlabId}` });
    fake.addFile(gitlabId, 'main', 'package.json', packageJson('^1.2.5'));
    fake.addFile(gitlabId, 'main', 'package-lock.json', packageLock('1.2.5'));
    const project = await mappedProject(h, fake, `FS-${gitlabId}`, gitlabId, options);
    await enableFixes(h, project.id, { maxOpen: 20 });
    const main = await mainBranchId(db(), project.id);
    const repo = { gitlabId, project, token: bearer(project.token), main };
    await vulnerable(repo, { vulnerabilityId: CVE, fixedVersion: '1.2.6' });
    return repo;
  };
  /** A vulnerability of qf-a 1.2.5 (unless `row` names another package) on the repo's main. */
  const vulnerable = (
    repo: Repo,
    row: {
      vulnerabilityId: string;
      fixedVersion: string | null;
      packageName?: string;
      firstSeenAt?: Date;
    },
  ) =>
    seedMainVulnerability(
      db(),
      { id: repo.project.id, mainBranchId: repo.main },
      {
        ecosystem: 'npm',
        packageName: 'qf-a',
        version: '1.2.5',
        severity: 'high',
        ...row,
      },
    );
  /** The package's main rows deleted: main no longer has a vulnerable qf-a. */
  const goneFromMain = (repo: Repo) =>
    db()
      .delete(targetVulnerabilities)
      .where(
        and(
          eq(targetVulnerabilities.projectId, repo.project.id),
          eq(targetVulnerabilities.packageName, 'qf-a'),
        ),
      );

  const claimAnswer = async (repo: Repo): Promise<FixClaimAnswer> => {
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/fixes/claim?projectKey=${encodeURIComponent(repo.project.key)}`,
      headers: repo.token,
      payload: { families: ['js'], branch: 'main', max: 1 },
    });
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as FixClaimAnswer;
  };
  const claim = async (repo: Repo): Promise<FixClaimItem> => {
    const answer = await claimAnswer(repo);
    expect(answer.items).toHaveLength(1);
    return answer.items[0]!;
  };
  const result = (repo: Repo, item: FixClaimItem, body: object) =>
    h.ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/fixes/${item.id}/result`,
      headers: repo.token,
      payload: { generation: item.generation, leaseToken: item.leaseToken, ...body },
    });
  /** The good upload of qf-a 1.2.5 → 1.2.6 on main's head; 202, the fix `committing`. */
  const upload = async (repo: Repo, item: FixClaimItem) => {
    const res = await result(repo, item, {
      baseSha: fake.headOf(repo.gitlabId, 'main'),
      installedVersion: '1.2.5',
      targetVersion: '1.2.6',
      targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' }],
      files: [
        { path: 'package.json', content: b64(packageJson('^1.2.6')) },
        { path: 'package-lock.json', content: b64(packageLock('1.2.6')) },
      ],
      lockfiles: [
        { path: 'package-lock.json', relation: 'direct', mechanism: null, dependents: [] },
      ],
      unfixable: [],
    });
    expect(res.statusCode, res.body).toBe(202);
  };
  /** A requested fix of qf-a, claimed and uploaded (Task 9's routes): `committing`. */
  const accepted = async (repo: Repo): Promise<string> => {
    await seedFix(db(), { projectId: repo.project.id, family: 'js', packageName: 'qf-a' });
    const item = await claim(repo);
    await upload(repo, item);
    return item.id;
  };
  /**
   * Runs the queued commit and close jobs now. The organisation's queued passes (a settings save
   * queues one) are dropped first: these tests run each pass themselves.
   */
  const runFixJobs = async () => {
    await db()
      .delete(jobs)
      .where(
        and(
          eq(jobs.queue, FIX_QUEUE),
          eq(jobs.status, 'queued'),
          like(jobs.concurrencyKey, 'fix-sync:%'),
        ),
      );
    await db()
      .update(jobs)
      .set({ runAt: sql`now()` })
      .where(and(eq(jobs.queue, FIX_QUEUE), eq(jobs.status, 'queued')));
    return runUntilIdle(db(), fixHandlers(deps()), silentLogger);
  };
  /** An open fix of qf-a with its MR (Task 10's commit job), with the requests cleared. */
  const openFix = async (repo: Repo): Promise<string> => {
    const fixId = await accepted(repo);
    await runFixJobs();
    expect((await row(fixId)).state).toBe('open');
    fake.clearRequests();
    return fixId;
  };
  const row = async (id: string) =>
    (await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, id)))[0]!;
  /** One pass of the organisation, run directly. */
  const pass = (over: Partial<FixJobDeps> = {}) => runFixSyncPass(deps(over), h.organizationId);
  /** The organisation's pass run through the queue, its reschedule included. */
  const passJob = async (organizationId: string, over: Partial<FixJobDeps> = {}) => {
    await db()
      .delete(jobs)
      .where(and(eq(jobs.queue, FIX_QUEUE), eq(jobs.status, 'queued')));
    expect(await scheduleFixSync(db(), organizationId, 0)).toBe(true);
    return runUntilIdle(db(), fixHandlers(deps(over)), silentLogger);
  };
  /** The organisation's queued passes, each with how many seconds from now it runs. */
  const queuedSyncs = (organizationId: string) =>
    db()
      .select({ inSeconds: sql<number>`extract(epoch from ${jobs.runAt} - now())::float8` })
      .from(jobs)
      .where(
        and(
          eq(jobs.queue, FIX_QUEUE),
          eq(jobs.status, 'queued'),
          eq(jobs.concurrencyKey, fixSyncKey(organizationId)),
        ),
      );
  const writes = () => fake.requests.filter((r) => r.method !== 'GET');
  const mrReads = () => fake.requests.filter((r) => r.method === 'GET' && MR_READ.test(r.path));
  const notes = (repo: Repo, iid: number) =>
    fake.discussions(repo.gitlabId, iid).flatMap((d) => d.notes.map((n) => n.body));
  const mrOf = (repo: Repo, iid: number) =>
    fake.mergeRequestsOf(repo.gitlabId).find((m) => m.iid === iid)!;
  const monitoring = (projectId: string, enabled: boolean) =>
    db()
      .insert(projectVulnerabilitySettings)
      .values({ projectId, enabled })
      .onConflictDoUpdate({ target: projectVulnerabilitySettings.projectId, set: { enabled } });
  const capture = () => {
    const lines: [string, ...unknown[]][] = [];
    const logger: WorkerLogger = {
      info: (...a: unknown[]) => {
        lines.push(['info', ...a]);
      },
      warn: (...a: unknown[]) => {
        lines.push(['warn', ...a]);
      },
      error: (...a: unknown[]) => {
        lines.push(['error', ...a]);
      },
    };
    return { lines, logger };
  };
  /** A committing fix's commit job ended for good (the queue's last attempt threw), an hour ago. */
  const deadCommit = async (fixId: string) => {
    const stuck = await row(fixId);
    await db()
      .delete(jobs)
      .where(and(eq(jobs.queue, FIX_QUEUE), eq(jobs.concurrencyKey, `fix:${fixId}`)));
    await db()
      .insert(jobs)
      .values({
        queue: FIX_QUEUE,
        concurrencyKey: `fix:${fixId}`,
        payload: { kind: 'commit', fixId, generation: stuck.generation, attempt: 0 },
        status: 'dead',
        attempts: 5,
        lastError: 'a bug',
      });
    await db()
      .update(dependencyFixes)
      .set({ updatedAt: sql`now() - interval '61 minutes'` })
      .where(eq(dependencyFixes.id, fixId));
  };

  let others = 0;
  /** An organisation with one project, mapped to nothing and with no fix settings. */
  async function otherOrganization(): Promise<{ organizationId: string; projectId: string }> {
    const n = ++others;
    const [org] = await db()
      .insert(organizations)
      .values({ key: `fix-sync-other-${n}`, name: `Other ${n}` })
      .returning({ id: organizations.id });
    const [project] = await db()
      .insert(projects)
      .values({ organizationId: org!.id, key: `FSO-${n}`, name: `FSO ${n}` })
      .returning({ id: projects.id });
    return { organizationId: org!.id, projectId: project!.id };
  }

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
    await db().delete(dependencyFixes);
    await db().delete(vulnerabilityTargetChecks);
    await db()
      .update(projectFixSettings)
      .set({ autoMinSeverity: null, autoExploited: false, autoSince: null });
  });

  it('expire (R8): a lapsed lease is requested again, or open with refresh for a fix with an MR; generation + 1', async () => {
    const repo = await freshRepo();
    const projectId = repo.project.id;
    const past = new Date(Date.now() - MINUTE);
    const plain = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: 'qf-x',
      state: 'preparing',
      leaseUntil: past,
    });
    const withMr = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: 'qf-y',
      state: 'preparing',
      leaseUntil: past,
      mrNumber: 7,
      mrUrl: 'https://scm.example/mr/7',
      headSha: 'c'.repeat(40),
      generation: 3,
    });
    const live = await seedFix(db(), {
      projectId,
      family: 'js',
      packageName: 'qf-z',
      state: 'preparing',
    });

    expect(await expireLeases(db(), h.organizationId)).toBe(2);
    expect(await row(plain)).toMatchObject({
      state: 'requested',
      refresh: false,
      generation: 2,
      leaseTokenHash: null,
      leaseUntil: null,
    });
    expect(await row(withMr)).toMatchObject({
      state: 'open',
      refresh: true,
      generation: 4,
      mrNumber: 7,
      leaseTokenHash: null,
      leaseUntil: null,
    });
    expect(await row(live)).toMatchObject({ state: 'preparing', generation: 1 });
    // Another organisation's lapsed lease is not this pass's.
    expect(await expireLeases(db(), (await otherOrganization()).organizationId)).toBe(0);
    expect(await expireLeases(db(), h.organizationId)).toBe(0);
  });

  describe('ruling T10c: a committing fix whose commit job died', () => {
    it('without an MR, older than an hour: failed scm_unavailable, counted by the pass', async () => {
      const repo = await freshRepo();
      const fixId = await accepted(repo);
      await deadCommit(fixId);
      fake.clearRequests();
      expect(await pass()).toEqual({ ...ZERO, expired: 1 });
      const ended = await row(fixId);
      expect(ended).toMatchObject({ state: 'failed', prepared: null, mrNumber: null });
      expect(ended.failure?.code).toBe('scm_unavailable');
      expect(writes()).toEqual([]);
    });

    it('with an MR: open again with failure scm_unavailable (F7), the MR still tracked', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const first = await row(fixId);
      await db()
        .update(dependencyFixes)
        .set({ refresh: true })
        .where(eq(dependencyFixes.id, fixId));
      await upload(repo, await claim(repo));
      await deadCommit(fixId);
      fake.clearRequests();
      expect(await pass()).toEqual({ ...ZERO, expired: 1 });
      const ended = await row(fixId);
      expect(ended).toMatchObject({
        state: 'open',
        refresh: false,
        prepared: null,
        mrNumber: first.mrNumber,
        headSha: first.headSha,
      });
      expect(ended.failure?.code).toBe('scm_unavailable');
      expect(mrReads()).toHaveLength(1);
      expect(writes()).toEqual([]);
    });

    it('a commit job still queued, or a row younger than an hour, is left committing', async () => {
      const repo = await freshRepo();
      const queued = await accepted(repo);
      // Its job waits (a retry), the row an hour old.
      await db()
        .update(jobs)
        .set({ runAt: sql`now() + interval '5 minutes'` })
        .where(eq(jobs.concurrencyKey, `fix:${queued}`));
      await db()
        .update(dependencyFixes)
        .set({ updatedAt: sql`now() - interval '2 hours'` })
        .where(eq(dependencyFixes.id, queued));
      expect(await pass()).toEqual(ZERO);
      expect((await row(queued)).state).toBe('committing');

      // Its job dead, but the row younger than an hour: it stays.
      await deadCommit(queued);
      await db()
        .update(dependencyFixes)
        .set({ updatedAt: sql`now() - interval '50 minutes'` })
        .where(eq(dependencyFixes.id, queued));
      expect(await pass()).toEqual(ZERO);
      expect((await row(queued)).state).toBe('committing');
    });
  });

  it('merged: the MR merged makes the fix merged', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const first = await row(fixId);
    fake.setMergeRequest(repo.gitlabId, first.mrNumber!, { state: 'merged' });
    expect(await pass()).toEqual({ ...ZERO, merged: 1 });
    expect(await row(fixId)).toMatchObject({
      state: 'merged',
      mrNumber: first.mrNumber,
      generation: first.generation,
    });
    expect(writes()).toEqual([]);
  });

  it('declined (§11.5): a person closed the MR; a re-arm answered noFix declined opens no new MR', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const first = await row(fixId);
    fake.setMergeRequest(repo.gitlabId, first.mrNumber!, { state: 'closed' });
    expect(await pass()).toEqual({ ...ZERO, declined: 1 });
    expect(await row(fixId)).toMatchObject({ state: 'declined', declinedTarget: '1.2.6' });
    expect(writes()).toEqual([]);

    const retried = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/fixes/${fixId}/retry`,
      headers: h.orgAdmin.headers,
    });
    expect(retried.statusCode, retried.body).toBe(202);
    const item = await claim(repo);
    expect(item.declinedTarget).toBe('1.2.6');
    const answered = await result(repo, item, {
      noFix: { reason: 'declined', message: 'The target 1.2.6 was declined' },
    });
    expect([answered.statusCode, answered.json()]).toEqual([202, { state: 'no_fix' }]);
    await runFixJobs();
    expect(await pass()).toEqual(ZERO);
    expect(fake.mergeRequestsOf(repo.gitlabId)).toHaveLength(1);
    expect(await row(fixId)).toMatchObject({ state: 'no_fix', declinedTarget: '1.2.6' });
    expect(writes()).toEqual([]);
  });

  it('taken over (§11.2): a person’s push ends the fix; a later pass writes nothing to the branch', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const person = fake.pushAs(repo.gitlabId, BRANCH, { 'package.json': packageJson('^1.2.7') });
    expect(await pass()).toEqual({ ...ZERO, takenOver: 1 });
    expect((await row(fixId)).state).toBe('taken_over');

    // Main has no vulnerable qf-a any more and the MR has a conflict: still nothing is written.
    await goneFromMain(repo);
    fake.setMergeRequest(repo.gitlabId, (await row(fixId)).mrNumber!, { conflict: true });
    fake.clearRequests();
    expect(await pass()).toEqual(ZERO);
    expect(fake.requests).toEqual([]);
    expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(person);
    expect(fake.mergeRequestsOf(repo.gitlabId)[0]!.state).toBe('opened');
  });

  it('conflict: refresh set, and the next claim hands the fix out', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    fake.setMergeRequest(repo.gitlabId, (await row(fixId)).mrNumber!, { conflict: true });
    expect(await pass()).toEqual({ ...ZERO, refreshed: 1 });
    expect(await row(fixId)).toMatchObject({ state: 'open', refresh: true });
    // A pass while the flag is set counts nothing new.
    expect(await pass()).toEqual(ZERO);
    expect(writes()).toEqual([]);

    const item = await claim(repo);
    expect(item.id).toBe(fixId);
    expect((await row(fixId)).state).toBe('preparing');
  });

  it('gone: main no longer has a vulnerable qf-a: the MR closed with the comment, the branch deleted, fixed', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const { mrNumber } = await row(fixId);
    await goneFromMain(repo);
    expect(await pass()).toEqual({ ...ZERO, fixed: 1 });
    expect(mrOf(repo, mrNumber!).state).toBe('closed');
    expect(notes(repo, mrNumber!)).toEqual([goneComment('qf-a', 'main')]);
    expect(fake.headOf(repo.gitlabId, BRANCH)).toBeNull();
    expect(await row(fixId)).toMatchObject({ state: 'fixed', mrNumber, failure: null });
    // The next pass reads nothing of it.
    fake.clearRequests();
    expect(await pass()).toEqual(ZERO);
    expect(fake.requests).toEqual([]);
  });

  describe('gone, but a person pushed (B10)', () => {
    it('a push before the close: taken over, the MR left open and the branch kept', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber } = await row(fixId);
      await goneFromMain(repo);
      let person = '';
      // The pass's MR step reads the head first; the person pushes before the close re-reads it.
      fake.inject(
        'GET',
        BRANCH_PATH,
        { status: 200, passThrough: true },
        {
          status: 200,
          passThrough: true,
          before: async () => {
            person = fake.pushAs(repo.gitlabId, BRANCH, { 'README.md': 'mine\n' });
          },
        },
      );
      expect(await pass()).toEqual({ ...ZERO, takenOver: 1 });
      expect(await row(fixId)).toMatchObject({ state: 'taken_over', mrNumber });
      expect(writes()).toEqual([]);
      expect(mrOf(repo, mrNumber!).state).toBe('opened');
      expect(notes(repo, mrNumber!)).toEqual([]);
      expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(person);
    });

    it('a push between the close and the delete: the branch kept, taken over', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber } = await row(fixId);
      await goneFromMain(repo);
      let person = '';
      // The MR step's read, the close's read, then the re-read right before the delete.
      fake.inject(
        'GET',
        BRANCH_PATH,
        { status: 200, passThrough: true },
        { status: 200, passThrough: true },
        {
          status: 200,
          passThrough: true,
          before: async () => {
            person = fake.pushAs(repo.gitlabId, BRANCH, { 'README.md': 'mine\n' });
          },
        },
      );
      expect(await pass()).toEqual({ ...ZERO, takenOver: 1 });
      expect((await row(fixId)).state).toBe('taken_over');
      // The MR was closed before the push; the person's branch is kept.
      expect(mrOf(repo, mrNumber!).state).toBe('closed');
      expect(notes(repo, mrNumber!)).toEqual([goneComment('qf-a', 'main')]);
      expect(writes().filter((r) => r.method === 'DELETE')).toEqual([]);
      expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(person);
    });
  });

  it('higher version: a new main row needing 1.2.8 while the target is 1.2.6 sets refresh; 1.2.6 does not', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    await vulnerable(repo, { vulnerabilityId: 'CVE-2026-9402', fixedVersion: '1.2.6' });
    expect(await pass()).toEqual(ZERO);
    expect((await row(fixId)).refresh).toBe(false);

    await vulnerable(repo, { vulnerabilityId: 'CVE-2026-9403', fixedVersion: '1.2.8, 2.0.1' });
    expect(await pass()).toEqual({ ...ZERO, refreshed: 1 });
    expect(await row(fixId)).toMatchObject({ state: 'open', refresh: true });
    expect(writes()).toEqual([]);
  });

  it('monitoring off (F28): no presence step and no automatic step; MR state reads still happen', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const { mrNumber } = await row(fixId);
    // The automatic rule is on, with a new high package on main that it would request.
    const since = new Date(Date.now() - DAY);
    await seedCheck(db(), {
      projectId: repo.project.id,
      branchId: repo.main,
      baselineAt: new Date(since.getTime() - DAY),
    });
    await db()
      .update(projectFixSettings)
      .set({ autoMinSeverity: 'high', autoSince: since })
      .where(eq(projectFixSettings.projectId, repo.project.id));
    await vulnerable(repo, {
      vulnerabilityId: 'CVE-2026-9404',
      fixedVersion: '3.0.1',
      packageName: 'qf-auto',
      firstSeenAt: new Date(since.getTime() + HOUR),
    });
    await goneFromMain(repo);
    fake.setMergeRequest(repo.gitlabId, mrNumber!, { conflict: true });
    await monitoring(repo.project.id, false);
    expect(await pass()).toEqual({ ...ZERO, refreshed: 1 });
    expect(mrReads()).toHaveLength(1);
    expect(writes()).toEqual([]);
    expect(await row(fixId)).toMatchObject({ state: 'open', refresh: true });
    expect(mrOf(repo, mrNumber!).state).toBe('opened');
    const autoRows = () =>
      db()
        .select()
        .from(dependencyFixes)
        .where(
          and(
            eq(dependencyFixes.projectId, repo.project.id),
            eq(dependencyFixes.packageName, 'qf-auto'),
          ),
        );
    expect(await autoRows()).toEqual([]);

    // Monitoring back on: the gone MR is closed and the rule requests its package.
    await monitoring(repo.project.id, true);
    expect(await pass()).toEqual({ ...ZERO, fixed: 1, requested: 1 });
    expect(mrOf(repo, mrNumber!).state).toBe('closed');
    const [auto] = await autoRows();
    expect(auto).toMatchObject({ state: 'requested', origin: 'auto', requestedBy: null });
  });

  describe('R18, F28: fixes switched off, their open MRs still tracked', () => {
    it('the project switched off: a merged MR is still recorded, and a gone one still closed', async () => {
      const repo = await freshRepo();
      const merged = await openFix(repo);
      fake.setMergeRequest(repo.gitlabId, (await row(merged)).mrNumber!, { state: 'merged' });
      await db()
        .update(projectFixSettings)
        .set({ enabled: false })
        .where(eq(projectFixSettings.projectId, repo.project.id));
      expect(await pass()).toEqual({ ...ZERO, merged: 1 });
      expect((await row(merged)).state).toBe('merged');

      const other = await freshRepo();
      const gone = await openFix(other);
      await db()
        .update(projectFixSettings)
        .set({ enabled: false })
        .where(eq(projectFixSettings.projectId, other.project.id));
      await goneFromMain(other);
      expect(await pass()).toEqual({ ...ZERO, fixed: 1 });
      expect((await row(gone)).state).toBe('fixed');
    });

    it('the connection no longer allows fix MRs: a declined MR is recorded; a gone one is left, nothing written', async () => {
      const repo = await freshRepo({ ownConnection: true });
      const declined = await openFix(repo);
      const other = await freshRepo({ ownConnection: true });
      const gone = await openFix(other);
      for (const r of [repo, other]) {
        await db()
          .update(scmConnections)
          .set({ fixMrsAllowed: false })
          .where(eq(scmConnections.id, r.project.connectionId));
      }
      fake.setMergeRequest(repo.gitlabId, (await row(declined)).mrNumber!, { state: 'closed' });
      await goneFromMain(other);
      fake.clearRequests();

      expect(await pass()).toEqual({ ...ZERO, declined: 1 });
      expect((await row(declined)).state).toBe('declined');
      expect(await row(gone)).toMatchObject({ state: 'open', refresh: false });
      expect(writes()).toEqual([]);
      expect(fake.headOf(other.gitlabId, BRANCH)).toBe((await row(gone)).headSha);
    });

    it('the organisation keeps its schedule while it has an active fix, and loses it after', async () => {
      const other = await otherOrganization();
      const fixId = await seedFix(db(), {
        projectId: other.projectId,
        family: 'js',
        packageName: 'qf-a',
        state: 'open',
      });
      expect(await passJob(other.organizationId)).toBe(1);
      expect(await queuedSyncs(other.organizationId)).toHaveLength(1);

      await db()
        .update(dependencyFixes)
        .set({ state: 'merged' })
        .where(eq(dependencyFixes.id, fixId));
      expect(await passJob(other.organizationId)).toBe(1);
      expect(await queuedSyncs(other.organizationId)).toEqual([]);
    });
  });

  it('rate limit: a 429 on the first MR read stops the pass, which is rescheduled', async () => {
    const one = await openFix(await freshRepo());
    const two = await openFix(await freshRepo());
    fake.inject('GET', MR_READ, { status: 429, headers: { 'retry-after': '30' } });
    const { lines, logger } = capture();
    fake.clearRequests();
    expect(await passJob(h.organizationId, { logger })).toBe(1);

    expect(mrReads()).toHaveLength(1);
    expect(fake.requests).toHaveLength(1);
    const [line, ...more] = lines.filter(
      ([level, , m]) => level === 'info' && m === 'fix sync pass',
    );
    expect(more).toEqual([]);
    expect(line![1]).toMatchObject({ ...ZERO, stop: 'rate_limited' });
    const [queued, ...others] = await queuedSyncs(h.organizationId);
    expect(others).toEqual([]);
    expect(queued!.inSeconds).toBeGreaterThan(FIX_SYNC_INTERVAL_SECONDS - 10);
    expect(queued!.inSeconds).toBeLessThanOrEqual(FIX_SYNC_INTERVAL_SECONDS);
    expect((await row(one)).state).toBe('open');
    expect((await row(two)).state).toBe('open');
  });

  it('rescheduled: one pass queued 15 minutes out with one info line; none for an organisation without fixes', async () => {
    await freshRepo();
    const { lines, logger } = capture();
    expect(await passJob(h.organizationId, { logger })).toBe(1);
    const [queued, ...others] = await queuedSyncs(h.organizationId);
    expect(others).toEqual([]);
    expect(queued!.inSeconds).toBeGreaterThan(FIX_SYNC_INTERVAL_SECONDS - 10);
    expect(queued!.inSeconds).toBeLessThanOrEqual(FIX_SYNC_INTERVAL_SECONDS);
    const passLines = lines.filter(([level, , m]) => level === 'info' && m === 'fix sync pass');
    expect(passLines).toHaveLength(1);
    expect(passLines[0]![1]).toMatchObject({
      organizationId: h.organizationId,
      durationMs: expect.any(Number),
      ...ZERO,
    });

    // No enabled project and no active fix: the pass runs and queues nothing.
    const other = await otherOrganization();
    await seedFix(db(), {
      projectId: other.projectId,
      family: 'js',
      packageName: 'qf-a',
      state: 'merged',
    });
    expect(await passJob(other.organizationId)).toBe(1);
    expect(await queuedSyncs(other.organizationId)).toEqual([]);
  });
});
