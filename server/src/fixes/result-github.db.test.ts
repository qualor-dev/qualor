import { createHash } from 'node:crypto';
import type { FixClaimAnswer, FixClaimItem } from '@qualor/shared/fix';
import { and, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { bearer } from '../../test/app';
import { createFakeGitHub, type FakeGitHub } from '../../test/fake-github';
import { enableFixes, seedFix, seedMainVulnerability } from '../../test/fixes';
import { githubTestConfig, mappedGitHubProject } from '../../test/github';
import { createIngestHarness, type IngestHarness, type IngestProject } from '../../test/ingest';
import { mainBranchId } from '../../test/issues';
import { dependencyFixes, jobs } from '../db/schema';
import { FIX_QUEUE } from './jobs';

const REPO_ID = 51;
const NPM = 'https://registry.npmjs.org';

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
          integrity: `sha512-${createHash('sha512').update(version).digest('base64')}`,
        },
      },
    },
    null,
    2,
  )}\n`;

const b64 = (text: string) => Buffer.from(text).toString('base64');

describe('the fix result against GitHub (0.16 fix MRs §6.7, B1; ancestry by compare)', () => {
  let h: IngestHarness;
  let fake: FakeGitHub;
  let project: IngestProject & { connectionId: string };

  const db = () => h.ctx.db;
  const head = () => fake.headOf(REPO_ID, 'main')!;
  const claim = async (): Promise<FixClaimItem> => {
    await seedFix(db(), { projectId: project.id, family: 'js', packageName: 'qf-a' });
    const res = await h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/projects/fixes/claim?projectKey=${encodeURIComponent(project.key)}`,
      headers: bearer(project.token),
      payload: { families: ['js'], branch: 'main', max: 1 },
    });
    expect(res.statusCode, res.body).toBe(200);
    return (res.json() as FixClaimAnswer).items[0]!;
  };
  const result = (item: FixClaimItem, baseSha: string) =>
    h.ctx.app.inject({
      method: 'PUT',
      url: `/api/v0/fixes/${item.id}/result`,
      headers: bearer(project.token),
      payload: {
        generation: item.generation,
        leaseToken: item.leaseToken,
        baseSha,
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
      },
    });
  const row = async (id: string) =>
    (await db().select().from(dependencyFixes).where(eq(dependencyFixes.id, id)))[0]!;
  const commitJobs = () =>
    db()
      .select()
      .from(jobs)
      .where(and(eq(jobs.queue, FIX_QUEUE), sql`${jobs.concurrencyKey} LIKE 'fix:%'`));
  const writes = () =>
    fake.requests.filter((r) => r.method !== 'GET' && !/access_tokens$/.test(r.path));

  beforeAll(async () => {
    fake = await createFakeGitHub();
    fake.addRepository({ id: REPO_ID, owner: 'acme', name: 'fix-result', installationId: 777 });
    fake.addFile(REPO_ID, 'package.json', packageJson('^1.2.5'));
    fake.addFile(REPO_ID, 'package-lock.json', packageLock('1.2.5'));
    h = await createIngestHarness({ config: githubTestConfig(fake) });
    project = await mappedGitHubProject(h, fake, 'FJ-GH', 'acme/fix-result');
    await enableFixes(h, project.id);
    await seedMainVulnerability(
      db(),
      { id: project.id, mainBranchId: await mainBranchId(db(), project.id) },
      {
        ecosystem: 'npm',
        packageName: 'qf-a',
        version: '1.2.5',
        vulnerabilityId: 'CVE-2026-9101',
        severity: 'critical',
        fixedVersion: '1.2.6',
      },
    );
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
    const item = await claim();
    fake.clearRequests();
    const res = await result(item, head());
    expect(res.statusCode, res.body).toBe(202);
    expect(res.json()).toEqual({ state: 'committing' });
    expect(await row(item.id)).toMatchObject({
      state: 'committing',
      baseSha: head(),
      targetVersion: '1.2.6',
      installedVersion: '1.2.5',
      leaseTokenHash: null,
    });
    expect((await row(item.id)).prepared!.additions).toEqual([
      { path: 'package-lock.json', entries: [{ slot: null, name: 'qf-a', version: '1.2.6' }] },
    ]);
    expect((await commitJobs()).map((j) => j.payload)).toEqual([
      { kind: 'commit', fixId: item.id, generation: item.generation, attempt: 0 },
    ]);
    // The base files were read raw, at the base commit.
    expect(
      fake.requests.some(
        (r) =>
          r.path.includes('/contents/package-lock.json?ref=') &&
          String(r.headers.accept).includes('application/vnd.github.raw'),
      ),
    ).toBe(true);
    expect(writes()).toEqual([]);

    await db().delete(dependencyFixes);
    const older = head();
    fake.addFile(REPO_ID, 'README.md', '# app\n');
    const next = await claim();
    const later = await result(next, older);
    expect(later.statusCode, later.body).toBe(202);
    expect(fake.requests.map((r) => r.path)).toContain(
      `/repos/acme/fix-result/compare/${older}...${head()}`,
    );
  });

  it('refuses a base that is not on main (compare: diverged), fails the fix and writes nothing', async () => {
    const item = await claim();
    const side = fake.pushAs(REPO_ID, 'side', { 'package.json': packageJson('^1.2.5') });
    fake.clearRequests();
    const res = await result(item, side);
    expect([res.statusCode, res.json().code, res.json().reason]).toEqual([
      422,
      'UPLOAD_REFUSED',
      'base_not_on_main',
    ]);
    expect(await row(item.id)).toMatchObject({
      state: 'failed',
      failure: { code: 'upload_refused' },
      prepared: null,
    });
    expect(await commitJobs()).toEqual([]);
    expect(writes()).toEqual([]);
  });
});
