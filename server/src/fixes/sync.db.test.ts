import type { FixClaimItem } from '@qualor/shared/fix';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import {
  acceptedQfA,
  claimFix,
  enableFixes,
  openQfA,
  putFixResult,
  qfaPackageJson as packageJson,
  qfaPackageLock as packageLock,
  runFixJobs as runQueuedFixJobs,
  seedFix,
  seedMainVulnerability,
  uploadQfA,
} from '../../test/fixes';
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
  users,
  vulnerabilityDecisions,
  vulnerabilityTargetChecks,
} from '../db/schema';
import { communityLimits } from '../limits';
import { runUntilIdle, type WorkerLogger } from '../queue/worker';
import { MAX_RETRY_AFTER_SECONDS } from '../scm/retry-after';
import { createScmRuntime } from '../scm/runtime';
import { goneComment } from './body';
import { FIX_QUEUE, FIX_SYNC_INTERVAL_SECONDS, fixSyncKey, scheduleFixSync } from './jobs';
import { fixHandlers, type FixJobDeps } from './run';
import { expireLeases, FIX_READS_PER_PASS, runFixSyncPass, type FixPassOutcome } from './sync';

const CVE = 'CVE-2026-9401';
const BRANCH = 'qualor/fix/js/qf-a';
const BRANCH_PATH = /\/repository\/branches\/qualor%2Ffix%2Fjs%2Fqf-a$/;
const MR_READ = /\/merge_requests\/\d+$/;
const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** A GitLab project of the fake, mapped to a Qualor project with fix MRs on and qf-a vulnerable. */
interface Repo {
  gitlabId: number;
  project: IngestProject & { connectionId: string };
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
  retryAfterSeconds: null,
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
    const repo = { gitlabId, project, main };
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

  const claim = (repo: Repo) => claimFix(h, repo.project);
  const result = (repo: Repo, item: FixClaimItem, body: object) =>
    putFixResult(h, repo.project, item, body);
  /** The good upload of qf-a 1.2.5 → 1.2.6 on main's head; 202, the fix `committing`. */
  const upload = (repo: Repo, item: FixClaimItem) =>
    uploadQfA(h, repo.project, item, fake.headOf(repo.gitlabId, 'main'));
  /** A requested fix of qf-a, claimed and uploaded (Task 9's routes): `committing`. */
  const accepted = (repo: Repo) => acceptedQfA(h, repo.project, fake.headOf(repo.gitlabId, 'main'));
  /** The queued commit and close jobs, run now; these tests run each pass themselves. */
  const runFixJobs = () => runQueuedFixJobs(db(), deps());
  /** An open fix of qf-a with its MR (Task 10's commit job), with the requests cleared. */
  const openFix = async (repo: Repo): Promise<string> => {
    const fixId = await openQfA(h, repo.project, fake.headOf(repo.gitlabId, 'main'), deps());
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
  /**
   * The project's automatic rule on (high, since a day ago, main checked before then), with a new
   * high package `qf-auto` on main that it would request.
   */
  const autoRuleWithNewPackage = async (repo: Repo) => {
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
  };
  /** The project's fixes of `qf-auto`. */
  const autoRows = (repo: Repo) =>
    db()
      .select()
      .from(dependencyFixes)
      .where(
        and(
          eq(dependencyFixes.projectId, repo.project.id),
          eq(dependencyFixes.packageName, 'qf-auto'),
        ),
      );
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
    await autoRuleWithNewPackage(repo);
    await goneFromMain(repo);
    fake.setMergeRequest(repo.gitlabId, mrNumber!, { conflict: true });
    await monitoring(repo.project.id, false);
    expect(await pass()).toEqual({ ...ZERO, refreshed: 1 });
    expect(mrReads()).toHaveLength(1);
    expect(writes()).toEqual([]);
    expect(await row(fixId)).toMatchObject({ state: 'open', refresh: true });
    expect(mrOf(repo, mrNumber!).state).toBe('opened');
    expect(await autoRows(repo)).toEqual([]);

    // Monitoring back on: the gone MR is closed and the rule requests its package.
    await monitoring(repo.project.id, true);
    expect(await pass()).toEqual({ ...ZERO, fixed: 1, requested: 1 });
    expect(mrOf(repo, mrNumber!).state).toBe('closed');
    const [auto] = await autoRows(repo);
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
    expect(line![1]).toMatchObject({ ...ZERO, stop: 'rate_limited', retryAfterSeconds: 30 });
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
  describe('fix round 1', () => {
    it('T11a: ignored or triaged rows keep qf-a present on main, so the MR stays open; deleted rows are gone', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber, headSha } = await row(fixId);
      const [admin] = await db().select().from(users).where(eq(users.username, 'ingest-admin'));
      // Every remaining vulnerability of qf-a on main: one ignored, one accepted (won't fix).
      await vulnerable(repo, { vulnerabilityId: 'CVE-2026-9406', fixedVersion: '1.2.6' });
      await db()
        .update(targetVulnerabilities)
        .set({ ignored: true })
        .where(
          and(
            eq(targetVulnerabilities.projectId, repo.project.id),
            eq(targetVulnerabilities.vulnerabilityId, CVE),
          ),
        );
      await db().insert(vulnerabilityDecisions).values({
        projectId: repo.project.id,
        packageName: 'qf-a',
        vulnerabilityId: 'CVE-2026-9406',
        status: 'wont_fix',
        decidedBy: admin!.id,
      });
      expect(await pass()).toEqual(ZERO);
      expect(await row(fixId)).toMatchObject({ state: 'open', refresh: false });
      expect(mrOf(repo, mrNumber!).state).toBe('opened');
      expect(notes(repo, mrNumber!)).toEqual([]);
      expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(headSha);
      expect(writes()).toEqual([]);

      // A person closes it: declined, as usual, since qf-a is still on main.
      fake.setMergeRequest(repo.gitlabId, mrNumber!, { state: 'closed' });
      expect(await pass()).toEqual({ ...ZERO, declined: 1 });
      expect(await row(fixId)).toMatchObject({ state: 'declined', declinedTarget: '1.2.6' });

      // The rows deleted (another project's fix): gone, as before.
      const other = await freshRepo();
      const otherFix = await openFix(other);
      await goneFromMain(other);
      expect(await pass()).toEqual({ ...ZERO, fixed: 1 });
      expect((await row(otherFix)).state).toBe('fixed');
    });

    it('I1: a gone-close cut before the branch delete ends fixed on the next pass, the branch deleted, no declined target', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber } = await row(fixId);
      await goneFromMain(repo);
      // The MR step's head read, the close's, then a 503 on the re-read right before the delete.
      fake.inject(
        'GET',
        BRANCH_PATH,
        { status: 200, passThrough: true },
        { status: 200, passThrough: true },
        { status: 503 },
      );
      expect(await pass()).toEqual({ ...ZERO, stop: 'transient' });
      expect(mrOf(repo, mrNumber!).state).toBe('closed');
      expect(notes(repo, mrNumber!)).toEqual([goneComment('qf-a', 'main')]);
      expect(fake.headOf(repo.gitlabId, BRANCH)).not.toBeNull();
      expect((await row(fixId)).state).toBe('open');

      fake.clearRequests();
      expect(await pass()).toEqual({ ...ZERO, fixed: 1 });
      expect(await row(fixId)).toMatchObject({ state: 'fixed', declinedTarget: null });
      expect(fake.headOf(repo.gitlabId, BRANCH)).toBeNull();
      expect(writes().map((r) => r.method)).toEqual(['DELETE']);
      expect(notes(repo, mrNumber!)).toEqual([goneComment('qf-a', 'main')]);
    });

    it('I1: a closed MR whose package is gone, with a person’s head on the branch: taken over, the branch kept', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber } = await row(fixId);
      await goneFromMain(repo);
      fake.setMergeRequest(repo.gitlabId, mrNumber!, { state: 'closed' });
      let person = '';
      // The delete's re-read finds a person's push.
      fake.inject('GET', BRANCH_PATH, {
        status: 200,
        passThrough: true,
        before: async () => {
          person = fake.pushAs(repo.gitlabId, BRANCH, { 'README.md': 'mine\n' });
        },
      });
      expect(await pass()).toEqual({ ...ZERO, takenOver: 1 });
      expect(await row(fixId)).toMatchObject({ state: 'taken_over', declinedTarget: null });
      expect(writes()).toEqual([]);
      expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(person);
    });

    it('T11b: a 429 with Retry-After 3600 puts the next pass at the clamped Retry-After, at least the interval', async () => {
      await openFix(await freshRepo());
      fake.inject('GET', MR_READ, { status: 429, headers: { 'retry-after': '3600' } });
      const { lines, logger } = capture();
      expect(await passJob(h.organizationId, { logger })).toBe(1);
      const [line] = lines.filter(([level, , m]) => level === 'info' && m === 'fix sync pass');
      // The SCM clients clamp a Retry-After to 15 minutes (MAX_RETRY_AFTER_SECONDS).
      expect(line![1]).toMatchObject({
        stop: 'rate_limited',
        retryAfterSeconds: MAX_RETRY_AFTER_SECONDS,
      });
      const due = Math.max(FIX_SYNC_INTERVAL_SECONDS, MAX_RETRY_AFTER_SECONDS);
      const [queued, ...others] = await queuedSyncs(h.organizationId);
      expect(others).toEqual([]);
      expect(queued!.inSeconds).toBeGreaterThan(due - 10);
      expect(queued!.inSeconds).toBeLessThanOrEqual(due);
    });

    it('T11d: a 5xx on an MR read stops the pass as transient', async () => {
      const one = await openFix(await freshRepo());
      const two = await openFix(await freshRepo());
      fake.inject('GET', MR_READ, { status: 503 });
      fake.clearRequests();
      expect(await pass()).toEqual({ ...ZERO, stop: 'transient' });
      expect(fake.requests).toHaveLength(1);
      expect((await row(one)).state).toBe('open');
      expect((await row(two)).state).toBe('open');
    });

    it("T11d: a project's request budget ends its part; another project of the organisation goes on", async () => {
      const spent = await freshRepo();
      const first = await openFix(spent);
      // A second open fix of the same project, whose MR read the spent budget never reaches.
      const second = await seedFix(db(), {
        projectId: spent.project.id,
        family: 'js',
        packageName: 'qf-b',
        state: 'open',
        mrNumber: 9_999,
        headSha: 'c'.repeat(40),
      });
      const other = await freshRepo();
      const merged = await openFix(other);
      fake.setMergeRequest(other.gitlabId, (await row(merged)).mrNumber!, { state: 'merged' });
      // Both projects' automatic rules would request a new package (step 4, no SCM request).
      for (const repo of [spent, other]) await autoRuleWithNewPackage(repo);
      const base = deps();
      // Two requests per project's client: the spent project needs three for its two fixes.
      const tight = { scm: { ...base.scm, clientOptions: { timeoutMs: 2_000, maxRequests: 2 } } };
      const { lines, logger } = capture();
      fake.clearRequests();
      expect(await pass({ ...tight, logger })).toEqual({
        ...ZERO,
        merged: 1,
        requested: 1,
        stop: 'budget',
      });
      expect((await row(merged)).state).toBe('merged');
      expect((await row(first)).state).toBe('open');
      expect((await row(second)).state).toBe('open');
      // The spent project's part ended: no request past its budget, no automatic request.
      const spentRequests = fake.requests.filter((r) =>
        r.path.startsWith(`/projects/${spent.gitlabId}/`),
      );
      expect(spentRequests).toHaveLength(2);
      expect(await autoRows(spent)).toEqual([]);
      expect(await autoRows(other)).toHaveLength(1);
      const budgetWarnings = lines.filter(
        ([level, fields]) =>
          level === 'warn' && (fields as { errorKind?: string }).errorKind === 'budget',
      );
      expect(budgetWarnings).toHaveLength(1);
    });

    it('T11d: with more open fixes than FIX_READS_PER_PASS, a pass reads 200 MRs', async () => {
      expect(FIX_READS_PER_PASS).toBe(200);
      const repo = await freshRepo();
      // 201 open fixes whose MRs were deleted: each read a 404 and a read of main, which ends the
      // fix declined (ruling FW14); monitoring off, so only the MR step sends requests.
      await db()
        .insert(dependencyFixes)
        .values(
          Array.from({ length: FIX_READS_PER_PASS + 1 }, (_, i) => ({
            projectId: repo.project.id,
            family: 'js' as const,
            packageName: `qf-many-${i}`,
            state: 'open' as const,
            origin: 'manual' as const,
            branch: `qualor/fix/js/qf-many-${i}`,
            mrNumber: 10_000 + i,
            mrUrl: `https://scm.example/mr/${10_000 + i}`,
            headSha: 'c'.repeat(40),
          })),
        );
      await monitoring(repo.project.id, false);
      try {
        fake.clearRequests();
        expect(await pass()).toEqual({ ...ZERO, declined: FIX_READS_PER_PASS });
        expect(mrReads()).toHaveLength(FIX_READS_PER_PASS);
        expect(fake.requests).toHaveLength(2 * FIX_READS_PER_PASS);
      } finally {
        await monitoring(repo.project.id, true);
      }
    });
  });

  describe('final fix wave', () => {
    /** The warnings that say a fix ended with its branch kept. */
    const keptWarnings = (lines: [string, ...unknown[]][]) =>
      lines.filter(
        ([level, , message]) => level === 'warn' && /branch.*kept/i.test(String(message)),
      );

    it('FW4: a gone close whose branch delete GitLab refuses (403) ends fixed, keeps the branch, warns once; the pass goes on', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber } = await row(fixId);
      await goneFromMain(repo);
      // The same project's automatic mode, and another project's merged MR, run in the same pass.
      await autoRuleWithNewPackage(repo);
      const other = await freshRepo();
      const merged = await openFix(other);
      fake.setMergeRequest(other.gitlabId, (await row(merged)).mrNumber!, { state: 'merged' });
      fake.inject('DELETE', BRANCH_PATH, { status: 403, body: { message: '403 Forbidden' } });
      const { lines, logger } = capture();
      expect(await pass({ logger })).toEqual({ ...ZERO, fixed: 1, merged: 1, requested: 1 });
      expect(await row(fixId)).toMatchObject({ state: 'fixed', declinedTarget: null });
      expect(mrOf(repo, mrNumber!).state).toBe('closed');
      expect(fake.headOf(repo.gitlabId, BRANCH)).not.toBeNull();
      expect((await row(merged)).state).toBe('merged');
      expect(await autoRows(repo)).toHaveLength(1);
      expect(keptWarnings(lines)).toHaveLength(1);
      // The next pass reads nothing of it.
      fake.clearRequests();
      expect((await pass()).fixed).toBe(0);
      expect(writes()).toEqual([]);
    });

    it('FW4: a closed MR whose package is gone, its branch delete refused (422), ends fixed with the branch kept', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber } = await row(fixId);
      await goneFromMain(repo);
      fake.setMergeRequest(repo.gitlabId, mrNumber!, { state: 'closed' });
      fake.inject('DELETE', BRANCH_PATH, { status: 422, body: { message: 'protected branch' } });
      const { lines, logger } = capture();
      expect(await pass({ logger })).toEqual({ ...ZERO, fixed: 1 });
      expect(await row(fixId)).toMatchObject({ state: 'fixed', declinedTarget: null });
      expect(fake.headOf(repo.gitlabId, BRANCH)).not.toBeNull();
      expect(keptWarnings(lines)).toHaveLength(1);
    });

    it.each([
      [400, 'a pre-receive hook refuses it'],
      [405, 'the branch is protected or the HEAD branch'],
    ])(
      'FW4: a closed MR whose package is gone, its branch delete refused (%i: %s), ends fixed with the branch kept',
      async (status) => {
        const repo = await freshRepo();
        const fixId = await openFix(repo);
        const { mrNumber } = await row(fixId);
        await goneFromMain(repo);
        fake.setMergeRequest(repo.gitlabId, mrNumber!, { state: 'closed' });
        fake.inject('DELETE', BRANCH_PATH, { status, body: { message: 'refused' } });
        const { lines, logger } = capture();
        expect(await pass({ logger })).toEqual({ ...ZERO, fixed: 1 });
        expect(await row(fixId)).toMatchObject({ state: 'fixed', declinedTarget: null });
        expect(fake.headOf(repo.gitlabId, BRANCH)).not.toBeNull();
        expect(keptWarnings(lines)).toHaveLength(1);
      },
    );

    it('FW4: a delete that fails for now (503) still keeps the fix open for the next pass', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber } = await row(fixId);
      await goneFromMain(repo);
      fake.setMergeRequest(repo.gitlabId, mrNumber!, { state: 'closed' });
      fake.inject('DELETE', BRANCH_PATH, { status: 503 });
      expect(await pass()).toEqual({ ...ZERO, stop: 'transient' });
      expect((await row(fixId)).state).toBe('open');
      expect(fake.headOf(repo.gitlabId, BRANCH)).not.toBeNull();
    });

    /** An owner deleted the fix's MR on GitLab: every read of it answers 404. */
    const deletedMr = (repo: Repo, mrNumber: number) => {
      const gone = { status: 404, body: { message: '404 Not found' } };
      const path = new RegExp(`^/projects/${repo.gitlabId}/merge_requests/${mrNumber}$`);
      fake.inject('GET', path, gone, gone, gone);
    };

    it('FW14: a deleted MR ends the fix declined while main has the package, its target kept', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber, headSha } = await row(fixId);
      deletedMr(repo, mrNumber!);
      expect(await pass()).toEqual({ ...ZERO, declined: 1 });
      expect(await row(fixId)).toMatchObject({ state: 'declined', declinedTarget: '1.2.6' });
      expect(writes()).toEqual([]);
      expect(fake.headOf(repo.gitlabId, BRANCH)).toBe(headSha);
    });

    it('FW14: a deleted MR whose package is gone from main ends fixed, its branch deleted', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber } = await row(fixId);
      await goneFromMain(repo);
      deletedMr(repo, mrNumber!);
      expect(await pass()).toEqual({ ...ZERO, fixed: 1 });
      expect(await row(fixId)).toMatchObject({ state: 'fixed', declinedTarget: null });
      expect(fake.headOf(repo.gitlabId, BRANCH)).toBeNull();
    });

    it('FW14: a 404 while main cannot be read either (a token that lost the project) ends nothing', async () => {
      const repo = await freshRepo();
      const fixId = await openFix(repo);
      const { mrNumber } = await row(fixId);
      deletedMr(repo, mrNumber!);
      fake.inject('GET', new RegExp(`^/projects/${repo.gitlabId}/repository/branches/main$`), {
        status: 404,
        body: { message: '404 Project Not Found' },
      });
      expect(await pass()).toEqual(ZERO);
      expect(await row(fixId)).toMatchObject({ state: 'open', declinedTarget: null });
    });
  });
});
