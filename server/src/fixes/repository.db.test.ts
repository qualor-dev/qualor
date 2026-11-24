import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  azureFixDeps,
  azurePatConnection,
  azureRepositoryWith,
  azureTestConfig,
  mappedAzureProject,
} from '../../test/azure';
import { createFakeAzureDevOps, type FakeAzureDevOps } from '../../test/fake-azure-devops';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { projects } from '../db/schema';
import { ScmError } from '../scm/provider';
import { openFixRepository, openTrackingRepository, type FixRepository } from './repository';

describe('the fix repository of a project on Azure DevOps (Azure sub-plan 6)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({ deployment: 'server' });
    h = await createIngestHarness({ config: azureTestConfig(fake) });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });

  it('is fixes_disabled only while the connection does not allow fix pull requests; with it on, an Azure repository', async () => {
    const connectionId = await azurePatConnection(h, fake);
    const { id, main } = azureRepositoryWith(fake, 'fix-repository', { 'package.json': '{}\n' });
    const project = await mappedAzureProject(h, connectionId, 'fixes/azure', id);
    const projectRow = async () =>
      (await h.ctx.db.select().from(projects).where(eq(projects.id, project.id)))[0]!;
    const deps = azureFixDeps(h);
    fake.clearRequests();

    // Off (the API's default): no repository to write with, a read-only one to track with (R18).
    expect(await openFixRepository(deps, await projectRow())).toEqual({
      problem: 'fixes_disabled',
    });
    const tracking = await openTrackingRepository(deps, await projectRow());
    expect(tracking).toMatchObject({ writable: false, repo: { provider: 'azure' } });
    expect(fake.requests).toEqual([]);

    const on = await h.ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/scm-connections/${connectionId}`,
      headers: h.orgAdmin.headers,
      payload: { fixMrsAllowed: true },
    });
    expect(on.statusCode, on.body).toBe(200);
    const repo = (await openFixRepository(deps, await projectRow())) as FixRepository;
    expect(repo).toMatchObject({ provider: 'azure', mainBranch: 'main' });
    expect(await repo.branchHead('main')).toBe(main);
    expect(await repo.branchHead('ma')).toBeNull();
    expect(await openTrackingRepository(deps, await projectRow())).toMatchObject({
      writable: true,
    });

    // Ruling T9k: a repository bound to a signal that has aborted sends nothing more.
    const controller = new AbortController();
    const bound = (await openFixRepository(deps, await projectRow(), {
      signal: controller.signal,
    })) as FixRepository;
    controller.abort();
    fake.clearRequests();
    const err = await bound.branchHead('main').catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ScmError);
    expect(fake.requests).toEqual([]);
  });
});
