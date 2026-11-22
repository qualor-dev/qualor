import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  azureConnection,
  mapToAzure,
  recordingListener,
  type RecordingListener,
} from '../../test/azure-pending';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { decorationDeps, PUBLIC_URL } from '../../test/scm';
import { projects } from '../db/schema';
import { createScmRuntime } from '../scm/runtime';
import { parseInternalHosts } from '../scm/url';
import { openFixRepository, openTrackingRepository } from './repository';

describe('the fix repository of a project on Azure DevOps: not available yet (Azure sub-plan 2, Task 2)', () => {
  let h: IngestHarness;
  let listener: RecordingListener;

  beforeAll(async () => {
    listener = await recordingListener();
    // The listener's host is allowed: a request the stub made would reach it.
    h = await createIngestHarness({
      config: { publicUrl: PUBLIC_URL, scmInternalHosts: parseInternalHosts(listener.host) },
    });
  });
  afterAll(async () => {
    await h.close();
    await listener.close();
  });

  it('is a problem, never a repository, even with fix MRs allowed, and nothing is sent', async () => {
    const project = await h.project('fixes/azure');
    // Allowed in the row (the API cannot set it for Azure yet), so the Azure arm itself answers.
    const connection = await azureConnection(h.ctx.db, {
      organizationId: h.organizationId,
      baseUrl: `${listener.url}/DefaultCollection`,
      secretKey: h.ctx.config.secretKey,
      fixMrsAllowed: true,
    });
    await mapToAzure(h.ctx.db, project.id, connection.id);
    const [row] = await h.ctx.db.select().from(projects).where(eq(projects.id, project.id));
    const deps = { db: h.ctx.db, scm: decorationDeps(h).scm, runtime: createScmRuntime() };
    expect(await openFixRepository(deps, row!)).toEqual({ problem: 'fixes_disabled' });
    expect(await openFixRepository(deps, row!, { signal: new AbortController().signal })).toEqual({
      problem: 'fixes_disabled',
    });
    expect(await openTrackingRepository(deps, row!)).toEqual({ problem: 'fixes_disabled' });
    expect(listener.requests).toEqual([]);
  });
});
