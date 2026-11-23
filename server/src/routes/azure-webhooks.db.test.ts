import { randomUUID } from 'node:crypto';
import { and, eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { deliverAzureEvent } from '../../test/azure';
import {
  azureShape,
  createFakeAzureDevOps,
  type FakeAzureDevOps,
} from '../../test/fake-azure-devops';
import { createFakeGitHub, type FakeGitHub } from '../../test/fake-github';
import { createFakeLlm, type FakeLlm } from '../../test/fake-llm';
import { githubConnection } from '../../test/github';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { queuedAnswers, refuseAnswerJobs, reviewOff, reviewOn } from '../../test/replies';
import { mergeRequestReport, PUBLIC_URL } from '../../test/scm';
import { encryptionKey } from '../crypto/secrets';
import { branches, jobs, projects, scmConnections } from '../db/schema';
import { AI_REPLY_QUEUE } from '../review/reply-queue';
import { encryptWebhookSecret } from '../scm/github/credentials';
import { parseInternalHosts } from '../scm/url';

/*
 * Azure DevOps service hooks (Azure sub-plan 5, task 6): a pull request comment or update queues one
 * scan of the pull request's branch. The payload is only a pointer; its text is never read.
 */

const SECRET = 'azhook-test-0123456789abcdef';
const OTHER_SECRET = 'azhook-other-0123456789abcdef';
const HEAD = '1'.repeat(40);
const PR = 11;
const recorded = (name: string) =>
  azureShape<{ body: { id: string; resource: { repository: { id: string } } } }>('services', name)
    .body;
const REPOSITORY = recorded('9-event-pr-updated').resource.repository.id;

describe('Azure DevOps service hooks (sub-plan 5, task 6)', () => {
  let h: IngestHarness;
  let fake: FakeAzureDevOps;
  let github: FakeGitHub;
  let llm: FakeLlm;
  let connectionId: string;
  let branchId: string;
  let ipNumber = 1;
  const nextIp = () => `198.51.100.${ipNumber++}`;

  const connect = async (secret: string | null) => {
    const created = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'azure',
        baseUrl: fake.url,
        azureAuth: 'pat',
        token: fake.pat,
      },
    });
    if (created.statusCode !== 201) throw new Error(`connection: ${created.body}`);
    const id = (created.json() as { id: string }).id;
    if (secret !== null) {
      await h.ctx.db
        .update(scmConnections)
        .set({
          webhookSecretEnc: encryptWebhookSecret(encryptionKey(h.ctx.config.secretKey), secret),
        })
        .where(eq(scmConnections.id, id));
    }
    return id;
  };
  /** A project on `connection` mapped to `repository`, its pull request `PR` analysed. */
  const mapped = async (key: string, connection: string, repository: string) => {
    const project = await h.project(key);
    await h.ctx.db
      .update(projects)
      .set({ scmConnectionId: connection, scmProjectRef: repository })
      .where(eq(projects.id, project.id));
    await project.ingestOk(mergeRequestReport(PR, HEAD, { projectKey: project.key }));
    const [branch] = await h.ctx.db
      .select({ id: branches.id })
      .from(branches)
      .where(and(eq(branches.projectId, project.id), eq(branches.kind, 'merge_request')));
    return branch!.id;
  };
  const deliver = (
    name: string,
    options: {
      overrides?: Record<string, unknown>;
      password?: string | null;
      username?: string;
      connection?: string;
      ip?: string;
    } = {},
  ) =>
    // The route is reached through the harness app; the helper only builds the request.
    deliverAzureEvent(
      {
        inject: (request: object) =>
          h.ctx.app.inject({ ...request, remoteAddress: options.ip ?? nextIp() } as never),
      } as never,
      options.connection ?? connectionId,
      name,
      { id: randomUUID(), ...options.overrides },
      options.password === null
        ? undefined
        : {
            password: options.password ?? SECRET,
            ...(options.username === undefined ? {} : { username: options.username }),
          },
    );
  const allJobs = () => h.ctx.db.select().from(jobs).where(eq(jobs.queue, AI_REPLY_QUEUE));
  const clearJobs = () => h.ctx.db.delete(jobs).where(eq(jobs.queue, AI_REPLY_QUEUE));
  const scans = async () =>
    (await queuedAnswers(h.ctx.db, branchId)).jobs.filter(
      (job) => (job.payload as { kind?: string }).kind === 'scan' && job.status === 'queued',
    );
  const raw = (headers: Record<string, string>, payload: string) =>
    h.ctx.app.inject({
      method: 'POST',
      url: `/api/v0/azure-devops/webhooks/${connectionId}`,
      remoteAddress: nextIp(),
      headers,
      payload,
    });
  const basic = (value: string) => `Basic ${Buffer.from(value).toString('base64')}`;
  const asJson = { 'content-type': 'application/json' };

  beforeAll(async () => {
    fake = await createFakeAzureDevOps({ deployment: 'services' });
    github = await createFakeGitHub();
    llm = await createFakeLlm();
    h = await createIngestHarness({
      config: {
        publicUrl: PUBLIC_URL,
        scmInternalHosts: parseInternalHosts(
          `${new URL(fake.url).host},${new URL(github.url).host}`,
        ),
        llmInternalHosts: parseInternalHosts(llm.host),
      },
    });
    connectionId = await connect(SECRET);
    // Azure DevOps matches repository ids without case.
    branchId = await mapped('azhooks/payments', connectionId, REPOSITORY.toUpperCase());
    await reviewOn(h, llm);
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
    await github.close();
    await llm.close();
  });
  beforeEach(clearJobs);

  it('a comment event on a mapped pull request queues one scan, 204', async () => {
    const res = await deliver('comment-created');
    expect(res.statusCode).toBe(204);
    expect(res.body).toBe('');
    expect(await scans()).toHaveLength(1);
    expect(await allJobs()).toHaveLength(1);
  });

  it('an updated event queues one scan, 204', async () => {
    expect((await deliver('pr-updated')).statusCode).toBe(204);
    expect(await scans()).toHaveLength(1);
  });

  it('a replay of the same delivery id is 204 and queues nothing more', async () => {
    const id = randomUUID();
    expect((await deliver('comment-created', { overrides: { id } })).statusCode).toBe(204);
    await clearJobs();
    expect((await deliver('comment-created', { overrides: { id } })).statusCode).toBe(204);
    expect(await allJobs()).toEqual([]);
  });

  it('a wrong password is 401; a missing header, another user and a malformed header are 401 too', async () => {
    const wrong = await deliver('comment-created', { password: 'not-the-secret' });
    expect(wrong.statusCode).toBe(401);
    expect(wrong.json()).toMatchObject({ code: 'UNAUTHENTICATED' });
    expect((await deliver('comment-created', { password: null })).statusCode).toBe(401);
    expect(
      (await deliver('comment-created', { username: 'someone', password: SECRET })).statusCode,
    ).toBe(401);
    const body = JSON.stringify(recorded('9-event-comment-created'));
    for (const authorization of [
      'Bearer abc',
      'Basic',
      'Basic %%%',
      basic('qualor'),
      basic(`qualor:${SECRET}x`),
      basic(`Qualor:${SECRET}`),
    ]) {
      expect((await raw({ ...asJson, authorization }, body)).statusCode).toBe(401);
    }
    expect(await allJobs()).toEqual([]);
  });

  it('counts only wrong credentials: the 61st from one address is 429, a right one from another address is taken', async () => {
    const ip = '203.0.113.9';
    const statuses: number[] = [];
    let throttled: Awaited<ReturnType<typeof deliver>> | undefined;
    for (let i = 0; i < 61; i++) {
      const res = await deliver('comment-created', { password: 'not-the-secret', ip });
      statuses.push(res.statusCode);
      if (res.statusCode === 429) throttled ??= res;
    }
    expect(statuses.slice(0, 60)).toEqual(Array.from({ length: 60 }, () => 401));
    expect(statuses[60]).toBe(429);
    expect(throttled?.headers['retry-after']).toBe('60');
    expect(throttled?.json()).toMatchObject({ code: 'RATE_LIMITED' });
    expect(
      (await deliver('comment-created', { ip: '203.0.113.10', overrides: { id: randomUUID() } }))
        .statusCode,
    ).toBe(204);
    expect(await scans()).toHaveLength(1);
  });

  it('answers 404 alike for an unknown connection, one without a secret, a GitHub connection and a non-id', async () => {
    const without = await connect(null);
    const hub = await githubConnection(h, github, { webhookSecret: SECRET });
    const answers = await Promise.all(
      [randomUUID(), without, hub, 'not-an-id'].map((connection) =>
        deliver('comment-created', { connection }),
      ),
    );
    expect(answers.map((r) => r.statusCode)).toEqual([404, 404, 404, 404]);
    expect(new Set(answers.map((r) => r.body)).size).toBe(1);
    expect(await allJobs()).toEqual([]);
  });

  it('a payload for another repository, another connection or an unknown pull request is 204 and queues nothing', async () => {
    const other = randomUUID();
    expect(
      (await deliver('pr-updated', { overrides: { resource: { repository: { id: other } } } }))
        .statusCode,
    ).toBe(204);
    expect(
      (
        await deliver('comment-created', {
          overrides: { resource: { pullRequest: { repository: { id: other } } } },
        })
      ).statusCode,
    ).toBe(204);
    // The right repository, delivered to a connection that maps none (another organisation's hook).
    const secondary = await connect(OTHER_SECRET);
    expect(
      (await deliver('pr-updated', { connection: secondary, password: OTHER_SECRET })).statusCode,
    ).toBe(204);
    // A pull request that was never analysed.
    expect(
      (await deliver('pr-updated', { overrides: { resource: { pullRequestId: 9_999 } } }))
        .statusCode,
    ).toBe(204);
    expect(await allJobs()).toEqual([]);
  });

  it('a payload whose two repository fields disagree is 204 and queues nothing', async () => {
    const other = randomUUID();
    // The comment event is read by the pull request's repository, the updated one by the resource's.
    expect(
      (
        await deliver('comment-created', {
          overrides: {
            resource: {
              repository: { id: REPOSITORY },
              pullRequest: { repository: { id: other } },
            },
          },
        })
      ).statusCode,
    ).toBe(204);
    expect(await allJobs()).toEqual([]);
    await clearJobs();
    expect(
      (
        await deliver('pr-updated', {
          overrides: {
            resource: {
              repository: { id: other },
              pullRequest: { repository: { id: REPOSITORY } },
            },
          },
        })
      ).statusCode,
    ).toBe(204);
    expect(await allJobs()).toEqual([]);
  });

  it('an envelope without an id is processed, and so is a delivery with an id that is no UUID, both without dedupe', async () => {
    for (const id of [undefined, 'not-a-uuid', 'x'.repeat(200)]) {
      for (let i = 0; i < 2; i++) {
        await clearJobs();
        const rest: Record<string, unknown> = { ...recorded('9-event-comment-created') };
        delete rest.id;
        const body = id === undefined ? rest : { ...rest, id };
        const res = await raw(
          { ...asJson, authorization: basic(`qualor:${SECRET}`) },
          JSON.stringify(body),
        );
        expect(res.statusCode).toBe(204);
        expect(await scans()).toHaveLength(1);
      }
    }
  });

  it('forgets the delivery id when processing fails, so its retry is processed', async () => {
    const id = randomUUID();
    const restore = await refuseAnswerJobs(h.ctx.db, branchId);
    try {
      expect((await deliver('comment-created', { overrides: { id } })).statusCode).toBe(500);
    } finally {
      await restore();
    }
    expect(await allJobs()).toEqual([]);
    expect((await deliver('comment-created', { overrides: { id } })).statusCode).toBe(204);
    expect(await scans()).toHaveLength(1);
  });

  it('does not count right deliveries: after 70 of them, one wrong one from the address is 401', async () => {
    const ip = '203.0.113.50';
    for (let i = 0; i < 70; i++) {
      expect((await deliver('comment-created', { ip })).statusCode).toBe(204);
    }
    expect((await deliver('comment-created', { ip, password: 'not-the-secret' })).statusCode).toBe(
      401,
    );
  });

  it('is 415 for a body that is not JSON, 400 for broken JSON, 204 for an event it does not read', async () => {
    const authorization = basic(`qualor:${SECRET}`);
    expect((await raw({ 'content-type': 'text/plain', authorization }, 'x')).statusCode).toBe(415);
    expect((await raw({ ...asJson, authorization }, '{nope')).statusCode).toBe(400);
    const unknown = { ...recorded('9-event-pr-updated'), eventType: 'git.push', id: randomUUID() };
    expect((await raw({ ...asJson, authorization }, JSON.stringify(unknown))).statusCode).toBe(204);
    expect(
      (await raw({ ...asJson, authorization }, '{"eventType":"git.pullrequest.updated"}'))
        .statusCode,
    ).toBe(204);
    expect(await allJobs()).toEqual([]);
  });

  it('with AI review off, answers 204 and queues nothing', async () => {
    await reviewOff(h);
    try {
      expect((await deliver('comment-created')).statusCode).toBe(204);
      expect(await allJobs()).toEqual([]);
    } finally {
      await reviewOn(h, llm);
    }
  });
});
