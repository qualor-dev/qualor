import { eq } from 'drizzle-orm';
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
  enableFixes,
  openQfA,
  qfaPackageJson as packageJson,
  qfaPackageLock as packageLock,
  seedMainVulnerability,
} from '../../test/fixes';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { dependencyFixes, jobs } from '../db/schema';
import { FIX_QUEUE } from './jobs';
import type { FixJobDeps } from './run';
import { runFixSyncPass } from './sync';

const BRANCH = 'qualor/fix/js/qf-a';

interface Repo {
  id: string;
  project: IngestProject & { connectionId: string };
}

describe('the fix sync pass on Azure DevOps (Azure sub-plan 6; 0.16 fix MRs §6.7 step 2, §11.2)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let connectionId: string;
  let repoNumber = 0;
  let deps: FixJobDeps;

  const db = () => h.ctx.db;
  const freshRepo = async (): Promise<Repo> => {
    const n = ++repoNumber;
    const { id } = azureRepositoryWith(fake, `fix-sync-${n}`, {
      'package.json': packageJson('^1.2.5'),
      'package-lock.json': packageLock('1.2.5'),
    });
    const project = await mappedAzureProject(h, connectionId, `FSA-${n}`, id);
    await enableFixes(h, project.id, { maxOpen: 20 });
    await seedMainVulnerability(
      db(),
      { id: project.id, mainBranchId: await mainBranchId(db(), project.id) },
      {
        ecosystem: 'npm',
        packageName: 'qf-a',
        version: '1.2.5',
        vulnerabilityId: 'CVE-2026-9611',
        severity: 'high',
        fixedVersion: '1.2.6',
      },
    );
    return { id, project };
  };
  /** An open fix of qf-a with its pull request (the commit job's first commit). */
  const openFix = async (repo: Repo): Promise<{ fixId: string; prId: number; head: string }> => {
    const fixId = await openQfA(h, repo.project, fake.branches(repo.id)['main']!, deps);
    const opened = await row(fixId);
    fake.clearRequests();
    return { fixId, prId: opened.mrNumber!, head: opened.headSha! };
  };
  const row = async (id: string) =>
    (await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, id)))[0]!;
  const pass = () => runFixSyncPass(deps, h.organizationId);
  const writes = () => fake.requests.filter((r) => r.method !== 'GET');

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
    await db().delete(dependencyFixes);
  });

  it('a completed PR makes the fix merged; an abandoned one declined, its target kept', async () => {
    const mergedRepo = await freshRepo();
    const merged = await openFix(mergedRepo);
    const declinedRepo = await freshRepo();
    const declined = await openFix(declinedRepo);
    fake.completePullRequest(mergedRepo.id, merged.prId);
    fake.pullRequest(declinedRepo.id, declined.prId).status = 'abandoned';

    const outcome = await pass();
    expect(outcome).toMatchObject({ merged: 1, declined: 1, stop: null });
    expect(await row(merged.fixId)).toMatchObject({ state: 'merged', failure: null });
    expect(await row(declined.fixId)).toMatchObject({
      state: 'declined',
      declinedTarget: '1.2.6',
    });
    // Tracking reads only: nothing is written to Azure DevOps.
    expect(writes()).toEqual([]);
  });

  it('a PR whose merge has conflicts (mergeStatus) is marked for a refresh', async () => {
    const repo = await freshRepo();
    const { fixId, prId } = await openFix(repo);
    fake.setMergeStatus(repo.id, prId, 'conflicts');

    const outcome = await pass();
    expect(outcome).toMatchObject({ refreshed: 1, stop: null });
    expect(await row(fixId)).toMatchObject({ state: 'open', refresh: true });
    expect(writes()).toEqual([]);

    // Azure DevOps has not computed the merge yet (no mergeStatus, no head): no conflict.
    await db().update(dependencyFixes).set({ refresh: false }).where(eq(dependencyFixes.id, fixId));
    fake.setMergeStatus(repo.id, prId, null);
    fake.pullRequest(repo.id, prId).headSha = null;
    expect(await pass()).toMatchObject({ refreshed: 0, stop: null });
    expect(await row(fixId)).toMatchObject({ state: 'open', refresh: false });
  });

  it('a branch a person moved ends taken_over, and nothing is written', async () => {
    const repo = await freshRepo();
    const { fixId, head } = await openFix(repo);
    const mine = fake.addCommit(repo.id, { parents: [head], files: { 'README.md': 'mine\n' } });
    fake.setBranch(repo.id, BRANCH, mine);

    const outcome = await pass();
    expect(outcome).toMatchObject({ takenOver: 1, stop: null });
    expect(await row(fixId)).toMatchObject({ state: 'taken_over', headSha: head });
    expect(fake.branches(repo.id)[BRANCH]).toBe(mine);
    expect(fake.pullRequest(repo.id, (await row(fixId)).mrNumber!).status).toBe('active');
    expect(writes()).toEqual([]);
  });
});
