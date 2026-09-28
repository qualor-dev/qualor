import { createHmac, randomUUID } from 'node:crypto';
import { eq, inArray } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createFakeGitHub, type FakeGitHub } from '../../test/fake-github';
import {
  githubConnection,
  githubDeps,
  githubTestConfig,
  mappedGitHubProject,
  pullRequestReport,
  WEBHOOK_SECRET,
} from '../../test/github';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { queuedDecorations, runDecorations } from '../../test/scm';
import { analyses, branches, organizations, scmConnections } from '../db/schema';

const HEAD = '1'.repeat(40);

describe('GitHub webhooks (github.md §9)', () => {
  let h: IngestHarness;
  let fake: FakeGitHub;
  let connectionId: string;
  let analysisId: string;
  const sign = (body: string, secret = WEBHOOK_SECRET) =>
    `sha256=${createHmac('sha256', secret).update(body).digest('hex')}`;
  const deliver = (
    event: string,
    payload: unknown,
    options: {
      id?: string;
      signature?: string | null;
      connection?: string;
      contentType?: string;
      delivery?: string;
      /** The sender's address: each throttle test has its own. */
      ip?: string;
    } = {},
  ) => {
    const body = typeof payload === 'string' ? payload : JSON.stringify(payload);
    return h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/github/webhooks/${options.connection ?? connectionId}`,
      remoteAddress: options.ip ?? '127.0.0.1',
      headers: {
        'content-type': options.contentType ?? 'application/json',
        'x-github-event': event,
        'x-github-delivery': options.delivery ?? randomUUID(),
        ...(options.signature === null
          ? {}
          : { 'x-hub-signature-256': options.signature ?? sign(body) }),
      },
      payload: body,
    });
  };
  const rerun = (
    externalId: string | null,
    overrides: { appId?: number; repositoryId?: number } = {},
  ) => ({
    action: 'rerequested',
    check_run: {
      id: 4,
      name: 'qualor/x',
      external_id: externalId,
      app: { id: overrides.appId ?? fake.appId },
    },
    repository: { id: overrides.repositoryId ?? 424242, full_name: 'acme/api' },
    installation: { id: 777 },
  });

  beforeAll(async () => {
    fake = await createFakeGitHub();
    fake.addRepository({ id: 424242, owner: 'acme', name: 'api', installationId: 777 });
    fake.addPull(424242, {
      number: 7,
      title: 'x',
      state: 'open',
      headSha: HEAD,
      baseSha: 'b'.repeat(40),
      files: [],
    });
    h = await createIngestHarness({ config: githubTestConfig(fake) });
    connectionId = await githubConnection(h, fake);
    const project = await mappedGitHubProject(h, fake, 'gh/hooks', 'acme/api', { connectionId });
    analysisId = await project.ingestOk(pullRequestReport(7, HEAD, { projectKey: project.key }));
    await runDecorations(h, githubDeps(h));
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  beforeEach(async () => {
    await runDecorations(h, githubDeps(h)); // start every test with an empty scm queue
  });

  const externalId = () => fake.checkRuns.at(-1)!.externalId!;

  it('answers a signed ping with 204 and does nothing', async () => {
    const res = await deliver('ping', { zen: 'Keep it logically awesome.', hook_id: 1 });
    expect(res.statusCode).toBe(204);
    expect(await queuedDecorations(h)).toEqual([]);
  });

  it('re-decorates when the Re-run button of Qualor’s check run is pressed', async () => {
    const res = await deliver('check_run', rerun(externalId()));
    expect(res.statusCode).toBe(204);
    const [job] = await queuedDecorations(h);
    expect(job?.payload).toMatchObject({
      analysisId,
      attempt: 0,
      reevaluation: true,
      github: { repositoryId: '424242', checkout: 'head' },
    });
  });

  it.each([
    ['another App', () => rerun(externalId(), { appId: 1 })],
    ['another repository', () => rerun(externalId(), { repositoryId: 5 })],
    ['a foreign external id', () => rerun('ci:1234')],
    [
      'an analysis of another connection',
      () => rerun(`qualor:v1:${randomUUID()}:0123456789abcdef`),
    ],
    ['another action', () => ({ ...rerun(externalId()), action: 'completed' })],
  ])('does nothing for %s', async (_, payload) => {
    expect((await deliver('check_run', payload())).statusCode).toBe(204);
    expect(await queuedDecorations(h)).toEqual([]);
  });

  it('does nothing for Qualor’s check run delivered to another connection, even of the same App and secret', async () => {
    const other = await githubConnection(h, fake);
    expect(
      (await deliver('check_run', rerun(externalId()), { connection: other })).statusCode,
    ).toBe(204);
    expect(await queuedDecorations(h)).toEqual([]);
  });

  it('refuses a wrong, missing or SHA-1-only signature with 401, and does nothing', async () => {
    const body = JSON.stringify(rerun(externalId()));
    const ip = '198.51.100.1';
    expect(
      (await deliver('check_run', body, { signature: sign(body, 'another-secret-value'), ip }))
        .statusCode,
    ).toBe(401);
    expect((await deliver('check_run', body, { signature: null, ip })).statusCode).toBe(401);
    expect(
      (
        await deliver('check_run', body, {
          signature: `sha1=${createHmac('sha1', WEBHOOK_SECRET).update(body).digest('hex')}`,
          ip,
        })
      ).statusCode,
    ).toBe(401);
    expect(await queuedDecorations(h)).toEqual([]);
  });

  it('answers 404 alike for an unknown connection, one without a secret, one whose secret no longer decrypts, and a non-id', async () => {
    const without = await githubConnection(h, fake, { webhookSecret: null });
    const rotated = await githubConnection(h, fake);
    // A key copied into webhook_secret_enc (another AAD) reads as no secret, like a rotated server key.
    const [row] = await h.ctx.db
      .select()
      .from(scmConnections)
      .where(eq(scmConnections.id, rotated));
    await h.ctx.db
      .update(scmConnections)
      .set({ webhookSecretEnc: row!.tokenEnc })
      .where(eq(scmConnections.id, rotated));
    const [gitlab] = await h.ctx.db
      .insert(scmConnections)
      .values({
        organizationId: h.organizationId,
        provider: 'gitlab',
        baseUrl: 'https://gitlab.example.com',
        tokenEnc: row!.tokenEnc,
      })
      .returning({ id: scmConnections.id });
    const answers = await Promise.all(
      [randomUUID(), without, rotated, gitlab!.id, 'not-an-id'].map((connection) =>
        deliver('ping', {}, { connection }),
      ),
    );
    expect(answers.map((r) => r.statusCode)).toEqual([404, 404, 404, 404, 404]);
    expect(new Set(answers.map((r) => r.body)).size).toBe(1);
  });

  it('refuses a form or text body with 415 and a body over 1 MiB with 413', async () => {
    expect(
      (
        await deliver('ping', 'payload=%7B%7D', {
          contentType: 'application/x-www-form-urlencoded',
        })
      ).statusCode,
    ).toBe(415);
    // Fastify parses text/plain by default: a string, never checked against the signature of
    // an empty body.
    expect(
      (await deliver('ping', '', { contentType: 'text/plain', signature: sign('') })).statusCode,
    ).toBe(415);
    expect((await deliver('ping', '{}', { contentType: 'text/plain' })).statusCode).toBe(415);
    const big = JSON.stringify({ zen: 'x'.repeat(1024 * 1024) });
    expect((await deliver('ping', big)).statusCode).toBe(413);
  });

  it('ignores a delivery id it has seen', async () => {
    const delivery = randomUUID();
    await deliver('check_run', rerun(externalId()), { delivery });
    await runDecorations(h, githubDeps(h));
    expect((await deliver('check_run', rerun(externalId()), { delivery })).statusCode).toBe(204);
    expect(await queuedDecorations(h)).toEqual([]);
  });

  it('re-decorates in an organisation beyond the old community limit (enterprise.md §8)', async () => {
    // Three organisations older than this one: before 5A it was read-only and nothing re-ran.
    const older = await h.ctx.db
      .insert(organizations)
      .values(
        ['ro-a', 'ro-b', 'ro-c'].map((key) => ({
          key,
          name: key,
          createdAt: new Date('2000-01-01T00:00:00Z'),
        })),
      )
      .returning({ id: organizations.id });
    try {
      expect((await deliver('check_run', rerun(externalId()))).statusCode).toBe(204);
      expect(await queuedDecorations(h)).toHaveLength(1);
    } finally {
      await h.ctx.db.delete(organizations).where(
        inArray(
          organizations.id,
          older.map((o) => o.id),
        ),
      );
    }
  });

  it('does nothing for the rerun of an analysis that is no longer its branch’s latest', async () => {
    const [pr] = await h.ctx.db.select().from(branches).where(eq(branches.kind, 'merge_request'));
    const older = externalId();
    await h.ctx.db.update(branches).set({ lastAnalysisId: null }).where(eq(branches.id, pr!.id));
    expect((await deliver('check_run', rerun(older))).statusCode).toBe(204);
    expect(await queuedDecorations(h)).toEqual([]);
    await h.ctx.db
      .update(branches)
      .set({ lastAnalysisId: analysisId })
      .where(eq(branches.id, pr!.id));
  });

  it('rate-limits failed signatures per address, and still takes a valid one from it', async () => {
    const ip = '198.51.100.2';
    let last = 0;
    for (let i = 0; i < 61; i++)
      last = (await deliver('ping', {}, { signature: 'sha256=' + '0'.repeat(64), ip })).statusCode;
    expect(last).toBe(429);
    expect((await deliver('ping', {}, { ip })).statusCode).toBe(204);
    expect((await deliver('ping', {}, { signature: 'sha256=' + '0'.repeat(64) })).statusCode).toBe(
      401,
    );
  });

  it('refuses a delivery without a GitHub event or delivery id with 400', async () => {
    expect((await deliver('Check-Run', {})).statusCode).toBe(400);
    expect((await deliver('', {})).statusCode).toBe(400);
    expect((await deliver('ping', {}, { delivery: 'not-a-uuid' })).statusCode).toBe(400);
    expect((await deliver('ping', {}, { delivery: '' })).statusCode).toBe(400);
  });

  it('takes a body that is not JSON for an event it does not read', async () => {
    expect((await deliver('ping', 'not json')).statusCode).toBe(204);
    expect((await deliver('check_run', 'not json')).statusCode).toBe(400);
  });

  it.each([
    ['no GitHub context (an older CLI)', null],
    ['no repository id', { checkout: 'head' }],
  ])('does nothing for the rerun of an analysis with %s', async (_, github) => {
    const [row] = await h.ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    const saved = row!.scmContext;
    await h.ctx.db
      .update(analyses)
      .set({ scmContext: { provider: 'github', mergeRequestId: '7', gitlab: null, github } })
      .where(eq(analyses.id, analysisId));
    try {
      expect((await deliver('check_run', rerun(externalId()))).statusCode).toBe(204);
      expect(await queuedDecorations(h)).toEqual([]);
    } finally {
      await h.ctx.db.update(analyses).set({ scmContext: saved }).where(eq(analyses.id, analysisId));
    }
  });

  it('forgets a delivery id whose processing failed, so GitHub’s redelivery counts', async () => {
    const delivery = randomUUID();
    const failing = vi
      .spyOn(h.ctx.db, 'transaction')
      .mockRejectedValueOnce(new Error('database down'));
    try {
      expect((await deliver('check_run', rerun(externalId()), { delivery })).statusCode).toBe(500);
    } finally {
      failing.mockRestore();
    }
    expect((await deliver('check_run', rerun(externalId()), { delivery })).statusCode).toBe(204);
    expect(await queuedDecorations(h)).toHaveLength(1);
  });

  it('never answers with the secret', async () => {
    const res = await deliver('ping', {}, { signature: 'sha256=' + '0'.repeat(64) });
    expect(res.body).not.toContain(WEBHOOK_SECRET);
  });
});
