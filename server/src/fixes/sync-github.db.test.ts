import { and, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFakeGitHub, type FakeGitHub } from '../../test/fake-github';
import {
  enableFixes,
  openQfA,
  qfaPackageJson as packageJson,
  qfaPackageLock as packageLock,
  seedMainVulnerability,
} from '../../test/fixes';
import { githubTestConfig, mappedGitHubProject } from '../../test/github';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { PUBLIC_URL, silentLogger } from '../../test/scm';
import { dependencyFixes, jobs, targetVulnerabilities } from '../db/schema';
import { communityLimits } from '../limits';
import type { WorkerLogger } from '../queue/worker';
import { MutationPacer } from '../scm/github/app-auth';
import { createScmRuntime } from '../scm/runtime';
import { FIX_QUEUE } from './jobs';
import type { FixJobDeps } from './run';
import { runFixSyncPass } from './sync';

const BRANCH = 'qualor/fix/js/qf-a';
const BRANCH_REF = /\/git\/refs\/heads\/qualor\/fix\/js\/qf-a$/;

interface Repo {
  id: number;
  project: IngestProject & { connectionId: string };
}

describe('the fix sync pass on GitHub (0.16 fix MRs §6.7, ruling FW4)', () => {
  let h: IngestHarness;
  let fake: FakeGitHub;
  let repoIds = 80;
  let deps: FixJobDeps;

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
  const freshRepo = async (): Promise<Repo> => {
    const id = ++repoIds;
    const name = `fix-sync-${id}`;
    fake.addRepository({ id, owner: 'acme', name, installationId: 777 });
    fake.addFile(id, 'package.json', packageJson('^1.2.5'));
    fake.addFile(id, 'package-lock.json', packageLock('1.2.5'));
    const project = await mappedGitHubProject(h, fake, `FSG-${id}`, `acme/${name}`);
    await enableFixes(h, project.id, { maxOpen: 20 });
    await seedMainVulnerability(
      db(),
      { id: project.id, mainBranchId: await mainBranchId(db(), project.id) },
      {
        ecosystem: 'npm',
        packageName: 'qf-a',
        version: '1.2.5',
        vulnerabilityId: 'CVE-2026-9411',
        severity: 'high',
        fixedVersion: '1.2.6',
      },
    );
    return { id, project };
  };
  const openFix = async (repo: Repo): Promise<string> => {
    const fixId = await openQfA(h, repo.project, fake.headOf(repo.id, 'main'), deps);
    fake.clearRequests();
    return fixId;
  };
  const row = async (id: string) =>
    (await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, id)))[0]!;
  const goneFromMain = (repo: Repo) =>
    db()
      .delete(targetVulnerabilities)
      .where(
        and(
          eq(targetVulnerabilities.projectId, repo.project.id),
          eq(targetVulnerabilities.packageName, 'qf-a'),
        ),
      );
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
    await db().delete(dependencyFixes);
  });

  it('FW4: a gone close whose branch delete GitHub refuses (422) ends fixed, keeps the branch, warns once; the next project goes on', async () => {
    const repo = await freshRepo();
    const fixId = await openFix(repo);
    const { mrNumber } = await row(fixId);
    await goneFromMain(repo);
    const other = await freshRepo();
    const merged = await openFix(other);
    fake.setPull(other.id, (await row(merged)).mrNumber!, { state: 'closed', merged: true });
    fake.inject('DELETE', BRANCH_REF, {
      status: 422,
      body: { message: 'Repository rule violations found\n\nCannot delete this branch' },
    });
    const { lines, logger } = capture();
    const outcome = await runFixSyncPass({ ...deps, logger }, h.organizationId);
    expect(outcome).toMatchObject({ fixed: 1, merged: 1, stop: null });
    expect(await row(fixId)).toMatchObject({ state: 'fixed', declinedTarget: null });
    expect(fake.pullsOf(repo.id).find((p) => p.number === mrNumber)?.state).toBe('closed');
    expect(fake.headOf(repo.id, BRANCH)).not.toBeNull();
    expect((await row(merged)).state).toBe('merged');
    const kept = lines.filter(
      ([level, , message]) => level === 'warn' && /branch.*kept/i.test(String(message)),
    );
    expect(kept).toHaveLength(1);
  });
});
