import { createHash } from 'node:crypto';
import type { FixClaimItem } from '@qualor/shared/fix';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import {
  azurePatConnection,
  azureRepositoryWith,
  azureTestConfig,
  mappedAzureProject,
} from '../../test/azure';
import { createFakeAzureDevOps, type FakeAzureDevOps } from '../../test/fake-azure-devops';
import {
  claimFix,
  enableFixes,
  putFixResult,
  qfaPackageJson as packageJson,
  qfaPackageLock as packageLock,
  seedFix,
  seedMainVulnerability,
} from '../../test/fixes';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { dependencyFixes, jobs } from '../db/schema';
import { FIX_QUEUE } from './jobs';

const NPM = 'https://registry.npmjs.org';
const MiB = 1024 * 1024;

const b64 = (text: string | Buffer) => Buffer.from(text).toString('base64');

/** qf-a's lockfile at `version` with `pads` other packages, which the fix leaves as they are. */
function paddedLock(version: string, pads: number): string {
  const lock = JSON.parse(packageLock(version)) as { packages: Record<string, unknown> };
  for (let i = 0; i < pads; i++) {
    lock.packages[`node_modules/qf-pad-${i}`] = {
      version: '1.0.0',
      resolved: `${NPM}/qf-pad-${i}/-/qf-pad-${i}-1.0.0.tgz`,
      integrity: `sha512-${createHash('sha512').update(`qf-pad-${i}`).digest('base64')}`,
    };
  }
  return `${JSON.stringify(lock, null, 2)}\n`;
}

interface Repo {
  id: string;
  project: IngestProject & { connectionId: string };
}

describe('the fix result against Azure DevOps (Azure sub-plan 6; 0.16 fix MRs §6.7, R15; ancestry by diffs/commits)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let connectionId: string;
  let repoNumber = 0;

  const db = () => h.ctx.db;
  const freshRepo = async (lock: string | Buffer = packageLock('1.2.5')): Promise<Repo> => {
    const n = ++repoNumber;
    const { id } = azureRepositoryWith(fake, `fix-result-${n}`, {
      'package.json': packageJson('^1.2.5'),
      'package-lock.json': lock,
    });
    const project = await mappedAzureProject(h, connectionId, `FRA-${n}`, id);
    await enableFixes(h, project.id);
    await seedMainVulnerability(
      db(),
      { id: project.id, mainBranchId: await mainBranchId(db(), project.id) },
      {
        ecosystem: 'npm',
        packageName: 'qf-a',
        version: '1.2.5',
        vulnerabilityId: 'CVE-2026-9621',
        severity: 'critical',
        fixedVersion: '1.2.6',
      },
    );
    return { id, project };
  };
  const mainOf = (repo: Repo) => fake.branches(repo.id)['main']!;
  const claim = async (repo: Repo): Promise<FixClaimItem> => {
    await seedFix(db(), { projectId: repo.project.id, family: 'js', packageName: 'qf-a' });
    return claimFix(h, repo.project);
  };
  const result = (repo: Repo, item: FixClaimItem, baseSha: string, lock = packageLock('1.2.6')) =>
    putFixResult(h, repo.project, item, {
      baseSha,
      installedVersion: '1.2.5',
      targetVersion: '1.2.6',
      targets: [{ installed: '1.2.5', target: '1.2.6', lockfile: 'package-lock.json' }],
      files: [
        { path: 'package.json', content: b64(packageJson('^1.2.6')) },
        { path: 'package-lock.json', content: b64(lock) },
      ],
      lockfiles: [
        { path: 'package-lock.json', relation: 'direct', mechanism: null, dependents: [] },
      ],
      unfixable: [],
    });
  const row = async (id: string) =>
    (await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, id)))[0]!;
  const commitJobs = () =>
    db()
      .select()
      .from(jobs)
      .where(and(eq(jobs.queue, FIX_QUEUE), sql`${jobs.concurrencyKey} LIKE 'fix:%'`));
  const writes = () => fake.requests.filter((r) => r.method !== 'GET');
  /** The raw reads of a file (`$format=octetStream`), at the commits they named. */
  const rawReads = (path: string) =>
    fake.requests
      .filter((r) => r.method === 'GET' && r.path.endsWith('/items'))
      .map((r) => new URLSearchParams(r.query))
      .filter((q) => q.get('path') === `/${path}` && q.get('$format') === 'octetStream')
      .map((q) => q.get('versionDescriptor.version'));
  const expectRefused = async (
    item: FixClaimItem,
    res: Awaited<ReturnType<typeof result>>,
    reason: string,
  ) => {
    expect([res.statusCode, res.json().code, res.json().reason], res.body).toEqual([
      422,
      'UPLOAD_REFUSED',
      reason,
    ]);
    expect(await row(item.id)).toMatchObject({
      state: 'failed',
      failure: { code: 'upload_refused' },
      prepared: null,
    });
    // No commit job for this fix (an accepted fix of another test may have one).
    expect((await commitJobs()).filter((j) => j.concurrencyKey === `fix:${item.id}`)).toEqual([]);
    expect(writes()).toEqual([]);
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
  afterEach(async () => {
    await db().delete(dependencyFixes);
    await db().delete(jobs).where(eq(jobs.queue, FIX_QUEUE));
  });

  it('accepts an upload on the head of main, and one on an older base that main did not change', async () => {
    const repo = await freshRepo();
    const item = await claim(repo);
    fake.clearRequests();
    const res = await result(repo, item, mainOf(repo));
    expect(res.statusCode, res.body).toBe(202);
    expect(res.json()).toEqual({ state: 'committing' });
    expect(await row(item.id)).toMatchObject({ state: 'committing', baseSha: mainOf(repo) });
    expect((await commitJobs()).map((j) => j.payload)).toEqual([
      { kind: 'commit', fixId: item.id, generation: item.generation, attempt: 0 },
    ]);
    // The base files were read raw, at the base commit.
    expect(rawReads('package-lock.json')).toEqual([mainOf(repo)]);
    expect(writes()).toEqual([]);

    await db().delete(dependencyFixes);
    const older = mainOf(repo);
    const next = fake.addCommit(repo.id, { parents: [older], files: { 'README.md': '# app\n' } });
    fake.setBranch(repo.id, 'main', next);
    const again = await claim(repo);
    fake.clearRequests();
    const later = await result(repo, again, older);
    expect(later.statusCode, later.body).toBe(202);
    const ancestry = fake.requests
      .filter((r) => r.path.endsWith('/diffs/commits'))
      .map((r) => new URLSearchParams(r.query))
      .map((q) => [q.get('baseVersion'), q.get('targetVersion')]);
    expect(ancestry).toEqual([[older, next]]);
    // Each file at the base, and at main's head to see that main did not change it.
    expect(rawReads('package-lock.json')).toEqual([older, next]);
    expect(writes()).toEqual([]);
  });

  it('refuses a base that is not on main (a diverged commit, or none at all), fails the fix and writes nothing', async () => {
    const repo = await freshRepo();
    const item = await claim(repo);
    const side = fake.addCommit(repo.id, {
      parents: [mainOf(repo)],
      files: { 'package.json': packageJson('^1.2.5') },
    });
    fake.setBranch(repo.id, 'side', side);
    fake.clearRequests();
    await expectRefused(item, await result(repo, item, side), 'base_not_on_main');

    // A sha the repository does not have (Azure DevOps answers 404) is no ancestor either, as on
    // GitLab and GitHub: the upload's rule, not an SCM failure.
    await db().delete(dependencyFixes);
    const unknown = await claim(repo);
    fake.clearRequests();
    await expectRefused(unknown, await result(repo, unknown, 'f'.repeat(40)), 'base_not_on_main');
  });

  it('reads a 2 MiB lock file in full, and refuses a 33 MiB one as too_large (RF3)', async () => {
    const base = paddedLock('1.2.5', 9_000);
    expect(Buffer.byteLength(base)).toBeGreaterThan(2 * MiB);
    const repo = await freshRepo(base);
    const item = await claim(repo);
    fake.clearRequests();
    const res = await result(repo, item, mainOf(repo), paddedLock('1.2.6', 9_000));
    expect(res.statusCode, res.body).toBe(202);
    expect(await row(item.id)).toMatchObject({ state: 'committing' });
    expect(rawReads('package-lock.json')).toEqual([mainOf(repo)]);

    // Over FIX_BASE_MAX_BYTES (32 MiB): the read stops at the limit and no part is used.
    const huge = await freshRepo(Buffer.alloc(33 * MiB, 0x61));
    const hugeItem = await claim(huge);
    fake.clearRequests();
    const refused = await result(huge, hugeItem, mainOf(huge));
    await expectRefused(hugeItem, refused, 'too_large');
    expect(refused.json().detail).toBe('package-lock.json');
  });
});
