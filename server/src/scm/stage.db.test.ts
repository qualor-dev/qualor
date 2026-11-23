import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { azureConnection, mapToAzure, recordingListener } from '../../test/azure-pending';
import type { RecordingListener } from '../../test/azure-pending';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import {
  mappedProject,
  mergeRequestReport,
  queuedDecorations,
  PUBLIC_URL,
  scmTestConfig,
} from '../../test/scm';

const HEAD = 'a'.repeat(40);
const AZURE = {
  projectId: '3f2504e0-4f89-41d3-9a0c-0305e82c3301',
  repositoryId: '0f6c1a5e-3b0d-4c39-9a51-fa6e00000001',
  buildId: '77',
  checkout: 'head',
} as const;

describe('the SCM ingestion stage enqueues the decoration with the report CI context', () => {
  let h: IngestHarness;
  let gitlab: FakeGitLab;
  let listener: RecordingListener;

  beforeAll(async () => {
    gitlab = await createFakeGitLab();
    listener = await recordingListener();
    h = await createIngestHarness({
      config: { publicUrl: PUBLIC_URL, ...scmTestConfig(gitlab) },
    });
    gitlab.addProject({ id: 801, path: 'acme/stage' });
  });
  afterAll(async () => {
    await h.close();
    await gitlab.close();
    await listener.close();
  });

  it('an Azure Pipelines report queues a job whose payload carries azure', async () => {
    const project = await h.project('stage/azure');
    const connection = await azureConnection(h.ctx.db, {
      organizationId: h.organizationId,
      baseUrl: `${listener.url}/DefaultCollection`,
      secretKey: h.ctx.config.secretKey,
    });
    await mapToAzure(h.ctx.db, project.id, connection.id);
    const report = mergeRequestReport(12, HEAD, { projectKey: project.key });
    const analysisId = await project.ingestOk({
      ...report,
      scm: { ...report.scm, provider: 'azure', azure: AZURE },
    });
    const queued = (await queuedDecorations(h)).filter(
      (j) => (j.payload as { analysisId: string }).analysisId === analysisId,
    );
    expect(queued.map((j) => j.payload)).toEqual([
      { analysisId, attempt: 0, gitlab: null, azure: AZURE },
    ]);
  });

  it('a GitLab report queues the payload it always did, with no azure key', async () => {
    const project = await mappedProject(h, gitlab, 'stage/gitlab', 801);
    const analysisId = await project.ingestOk(
      mergeRequestReport(13, HEAD, { projectKey: project.key, gitlab: { projectId: '801' } }),
    );
    const queued = (await queuedDecorations(h)).filter(
      (j) => (j.payload as { analysisId: string }).analysisId === analysisId,
    );
    expect(queued.map((j) => j.payload)).toEqual([
      { analysisId, attempt: 0, gitlab: { projectId: '801' } },
    ]);
  });
});
