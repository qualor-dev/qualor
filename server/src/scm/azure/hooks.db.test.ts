import { and, asc, eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { azureServerConfig, servicesUrlOf, AZURE_TEST_PRINCIPAL } from '../../../test/azure';
import {
  createFakeAzureDevOps,
  type FakeAzureDevOps,
  type FakeAzureRepository,
} from '../../../test/fake-azure-devops';
import { createFakeGitHub, type FakeGitHub } from '../../../test/fake-github';
import { githubConnection } from '../../../test/github';
import { createIngestHarness, type IngestHarness } from '../../../test/ingest';
import { rbacPlugins } from '../../../test/rbac';
import { PUBLIC_URL } from '../../../test/scm';
import { trustTestCa } from '../../../test/tls';
import { encryptionKey } from '../../crypto/secrets';
import { auditEvents, projects, scmConnections } from '../../db/schema';
import { decryptWebhookSecret } from '../github/credentials';
import { WEBHOOK_SECRET_PATTERN } from '../github/app-auth';
import { azureWebhookUrl } from './url';

/*
 * Qualor's service hook subscriptions in Azure DevOps (sub-plan 5, task 7): the generated
 * password, the subscribe route and the connection Test's hook states.
 */

const COMMENT = 'ms.vss-code.git-pullrequest-comment-event';
const UPDATED = 'git.pullrequest.updated';

describe('Azure DevOps service hook subscriptions (sub-plan 5, task 7)', () => {
  let untrust: () => void;
  let h: IngestHarness;
  let http: IngestHarness;
  let fake: FakeAzureDevOps;
  let github: FakeGitHub;
  let api: FakeAzureRepository;
  let web: FakeAzureRepository;
  let docs: FakeAzureRepository;
  /** Every answer, for the check that no stored password is in an answer, audit entry or log. */
  const answers: string[] = [];

  const call = async (
    harness: IngestHarness,
    method: 'POST' | 'GET' | 'PATCH',
    url: string,
    payload?: object,
  ) => {
    const res = await harness.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: harness.orgAdmin.headers,
      ...(payload === undefined ? {} : { payload }),
    });
    answers.push(res.body);
    return res;
  };
  const connect = async (harness: IngestHarness = h) => {
    const res = await call(harness, 'POST', '/scm-connections', {
      organizationId: harness.organizationId,
      provider: 'azure',
      baseUrl: servicesUrlOf(fake),
      azureAuth: 'pat',
      token: fake.pat,
    });
    expect(res.statusCode, res.body).toBe(201);
    return (res.json() as { id: string }).id;
  };
  const mapRepository = async (
    harness: IngestHarness,
    key: string,
    connectionId: string,
    repository: FakeAzureRepository,
  ) => {
    const project = await harness.project(key);
    await harness.ctx.db
      .update(projects)
      .set({ scmConnectionId: connectionId, scmProjectRef: repository.id })
      .where(eq(projects.id, project.id));
  };
  const rowOf = async (id: string) =>
    (await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, id)))[0]!;
  const storedPassword = async (id: string) =>
    decryptWebhookSecret(encryptionKey(h.ctx.config.secretKey), (await rowOf(id)).webhookSecretEnc);
  const rotate = async (id: string) => {
    const res = await call(h, 'POST', `/scm-connections/${id}/azure-hooks/secret`);
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as { url: string | null; user: string; password: string };
  };
  const subscribe = (id: string, harness: IngestHarness = h) =>
    call(harness, 'POST', `/scm-connections/${id}/azure-hooks`);
  type Outcome = 'created' | 'replaced' | 'unchanged' | 'refused';
  const outcomes = (res: { json(): unknown }) =>
    (res.json() as { projects: { projectId: string; comment: Outcome; updated: Outcome }[] })
      .projects;
  const auditOf = async (action: string, id: string) =>
    (
      await h.ctx.db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, action), eq(auditEvents.targetId, id)))
        .orderBy(asc(auditEvents.seq))
    ).map((e) => e.details);

  beforeAll(async () => {
    untrust = trustTestCa();
    fake = await createFakeAzureDevOps({
      deployment: 'services',
      principal: AZURE_TEST_PRINCIPAL,
      repositories: [
        { name: 'api', projectName: 'Payments' },
        { name: 'web', projectName: 'Payments' },
        { name: 'docs', projectName: 'Platform' },
      ],
    });
    github = await createFakeGitHub();
    [api, web, docs] = fake.repositories as [
      FakeAzureRepository,
      FakeAzureRepository,
      FakeAzureRepository,
    ];
    h = await createIngestHarness({
      config: {
        ...azureServerConfig(fake),
        scmInternalHosts: new Set([new URL(fake.url).host, new URL(github.url).host]),
        publicUrl: PUBLIC_URL,
      },
      pluginsFor: rbacPlugins({ now: () => new Date('2027-01-01T00:00:00Z') }),
    });
    http = await createIngestHarness({
      config: { ...azureServerConfig(fake), publicUrl: 'http://qualor.example.com' },
    });
  });
  afterAll(async () => {
    await h.close();
    await http.close();
    await fake.close();
    await github.close();
    untrust();
  });
  afterEach(async () => {
    await h.ctx.db.delete(scmConnections);
    await h.ctx.db.delete(projects);
    await http.ctx.db.delete(scmConnections);
    // The fake keeps its subscriptions between tests; each test starts without any.
    (fake.subscriptions as unknown[]).length = 0;
    fake.clearRequests();
  });

  it('the secret route answers a new password once; the DTO and the audit never carry it', async () => {
    const id = await connect();
    const before = (
      await call(h, 'GET', `/scm-connections?organizationId=${h.organizationId}`)
    ).json() as { items: { azure: { webhookSecretSet: boolean; webhookUrl: string | null } }[] };
    expect(before.items[0]!.azure).toMatchObject({ webhookSecretSet: false, webhookUrl: null });

    const first = await rotate(id);
    expect(first.user).toBe('qualor');
    expect(first.url).toBe(azureWebhookUrl(PUBLIC_URL, id));
    expect(first.password).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(WEBHOOK_SECRET_PATTERN.test(first.password)).toBe(true);
    expect(await storedPassword(id)).toBe(first.password);
    expect((await rowOf(id)).webhookSecretEnc).not.toBeNull();

    const listed = await call(h, 'GET', `/scm-connections?organizationId=${h.organizationId}`);
    expect(listed.body).not.toContain(first.password);
    const connection = (listed.json() as { items: { azure: Record<string, unknown> }[] }).items[0]!;
    expect(connection.azure).toMatchObject({
      webhookSecretSet: true,
      webhookUrl: azureWebhookUrl(PUBLIC_URL, id),
    });
    expect(await auditOf('scm_connection.updated', id)).toEqual([{ changed: ['webhookSecret'] }]);
    const audit = JSON.stringify(await h.ctx.db.select().from(auditEvents));
    expect(audit).not.toContain(first.password);
    expect(h.ctx.logs.join('\n')).not.toContain(first.password);

    const second = await rotate(id);
    expect(second.password).not.toBe(first.password);
    expect(await storedPassword(id)).toBe(second.password);
  });

  it('the secret route answers url null without a public URL, and 404s for a GitHub connection', async () => {
    const id = await connect();
    const noUrl = await createIngestHarness({ config: azureServerConfig(fake) });
    try {
      const other = await connect(noUrl);
      const res = await call(noUrl, 'POST', `/scm-connections/${other}/azure-hooks/secret`);
      expect(res.statusCode).toBe(200);
      expect((res.json() as { url: string | null }).url).toBeNull();
    } finally {
      await noUrl.close();
    }
    expect(id).toBeTruthy();
    const gh = await githubConnection(h, github);
    for (const path of ['azure-hooks/secret', 'azure-hooks']) {
      expect((await call(h, 'POST', `/scm-connections/${gh}/${path}`)).statusCode).toBe(404);
    }
  });

  it('subscribes two subscriptions per Azure project of a mapped repository, with the constraints', async () => {
    const id = await connect();
    await mapRepository(h, 'hooks/api', id, api);
    await mapRepository(h, 'hooks/web', id, web);
    await mapRepository(h, 'hooks/docs', id, docs);
    const res = await subscribe(id);
    expect(res.statusCode, res.body).toBe(200);
    expect(res.body).not.toContain((await storedPassword(id))!);
    expect(outcomes(res)).toEqual(
      [api.projectId, docs.projectId]
        .sort()
        .map((projectId) => ({ projectId, comment: 'created', updated: 'created' })),
    );
    const password = (await storedPassword(id))!;
    expect(password).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(fake.subscriptions).toHaveLength(4);
    for (const s of fake.subscriptions) {
      expect(s.url).toBe(azureWebhookUrl(PUBLIC_URL, id));
      expect(s.username).toBe('qualor');
      expect(s.password).toBe(password);
      expect(s.status).toBe('enabled');
    }
    const byEvent = (event: string) => fake.subscriptions.filter((s) => s.eventType === event);
    expect(byEvent(COMMENT).map((s) => s.resourceVersion)).toEqual(['2.0', '2.0']);
    expect(byEvent(UPDATED).map((s) => s.resourceVersion)).toEqual(['1.0', '1.0']);
    const posted = fake.requests
      .filter((r) => r.method === 'POST' && r.path === '/_apis/hooks/subscriptions')
      .map((r) => JSON.parse(r.body) as Record<string, unknown>);
    expect(posted).toHaveLength(4);
    for (const body of posted) {
      expect(body).toMatchObject({
        publisherId: 'tfs',
        consumerId: 'webHooks',
        consumerActionId: 'httpRequest',
        consumerInputs: {
          url: azureWebhookUrl(PUBLIC_URL, id),
          basicAuthUsername: 'qualor',
          basicAuthPassword: password,
          resourceDetailsToSend: 'all',
          messagesToSend: 'none',
          detailedMessagesToSend: 'none',
        },
      });
      expect(Object.keys(body.publisherInputs as object)).toEqual(['projectId']);
    }
    expect(await auditOf('scm_connection.hooks_updated', id)).toEqual([{ projects: 2 }]);
    // The first call made the secret.
    expect(await auditOf('scm_connection.updated', id)).toEqual([{ changed: ['webhookSecret'] }]);
    const audit = JSON.stringify(await h.ctx.db.select().from(auditEvents));
    expect(audit).not.toContain(password);
    expect(h.ctx.logs.join('\n')).not.toContain(password);
    expect(answers.join('\n')).not.toContain(password);
  });

  it('a second call is unchanged; after a secret rotation Azure DevOps is rewritten', async () => {
    const id = await connect();
    await mapRepository(h, 'hooks/api', id, api);
    expect(outcomes(await subscribe(id))).toEqual([
      { projectId: api.projectId, comment: 'created', updated: 'created' },
    ]);
    expect(outcomes(await subscribe(id))).toEqual([
      { projectId: api.projectId, comment: 'unchanged', updated: 'unchanged' },
    ]);
    expect(fake.subscriptions).toHaveLength(2);

    const rotated = await rotate(id);
    expect(outcomes(await subscribe(id))).toEqual([
      { projectId: api.projectId, comment: 'replaced', updated: 'replaced' },
    ]);
    expect(fake.subscriptions).toHaveLength(2);
    for (const s of fake.subscriptions) expect(s.password).toBe(rotated.password);
    expect(outcomes(await subscribe(id))).toEqual([
      { projectId: api.projectId, comment: 'unchanged', updated: 'unchanged' },
    ]);
  });

  it('rewrites a subscription Azure DevOps put on probation or disabled, and one of an old version', async () => {
    const id = await connect();
    await mapRepository(h, 'hooks/api', id, api);
    await subscribe(id);
    const [comment, updated] = [COMMENT, UPDATED].map((e) =>
      fake.subscriptions.find((s) => s.eventType === e)!,
    ) as [(typeof fake.subscriptions)[number], (typeof fake.subscriptions)[number]];
    fake.setSubscriptionStatus(comment.id, 'onProbation');
    fake.setSubscriptionStatus(updated.id, 'disabledBySystem');
    expect(outcomes(await subscribe(id))).toEqual([
      { projectId: api.projectId, comment: 'replaced', updated: 'replaced' },
    ]);
    expect(fake.subscriptions.map((s) => s.status)).toEqual(['enabled', 'enabled']);
    // The same event on the old version, as an earlier Qualor or a person made it.
    (
      fake.subscriptions.find((s) => s.eventType === COMMENT) as { resourceVersion: string }
    ).resourceVersion = '1.0';
    expect(outcomes(await subscribe(id))).toEqual([
      { projectId: api.projectId, comment: 'replaced', updated: 'unchanged' },
    ]);
    expect(fake.subscriptions.find((s) => s.eventType === COMMENT)!.resourceVersion).toBe('2.0');
  });

  it('leaves the subscriptions of other targets alone', async () => {
    const id = await connect();
    await mapRepository(h, 'hooks/api', id, api);
    await subscribe(id);
    const other = await connect();
    await mapRepository(h, 'hooks/web', other, web);
    expect(outcomes(await subscribe(other))).toEqual([
      { projectId: api.projectId, comment: 'created', updated: 'created' },
    ]);
    expect(fake.subscriptions).toHaveLength(4);
    expect(outcomes(await subscribe(id))).toEqual([
      { projectId: api.projectId, comment: 'unchanged', updated: 'unchanged' },
    ]);
  });

  it('an http public URL is 409 PUBLIC_URL_NOT_HTTPS and sends nothing', async () => {
    const id = await connect(http);
    const res = await subscribe(id, http);
    expect(res.statusCode).toBe(409);
    expect(res.json()).toMatchObject({ code: 'PUBLIC_URL_NOT_HTTPS' });
    expect(fake.subscriptions).toHaveLength(0);
    // Nothing was generated either.
    const [row] = await http.ctx.db.select().from(scmConnections);
    expect(row!.webhookSecretEnc).toBeNull();
  });

  it('a project the identity cannot edit is refused; the others are still created', async () => {
    const id = await connect();
    await mapRepository(h, 'hooks/api', id, api);
    await mapRepository(h, 'hooks/docs', id, docs);
    const forbidden = {
      status: 403,
      body: { message: 'TF401027: You need the Edit subscriptions permission.' },
    };
    fake.inject('POST', /hooks\/subscriptions$/, forbidden, forbidden);
    const res = await subscribe(id);
    expect(res.statusCode, res.body).toBe(200);
    const [first, second] = [api.projectId, docs.projectId].sort();
    expect(outcomes(res)).toEqual([
      { projectId: first, comment: 'refused', updated: 'refused' },
      { projectId: second, comment: 'created', updated: 'created' },
    ]);
    expect(fake.subscriptions).toHaveLength(2);
    // A refusal leaves the next call rewriting everything it can reach.
    const again = outcomes(await subscribe(id));
    expect(again.find((p) => p.projectId === second)).toEqual({
      projectId: second,
      comment: 'replaced',
      updated: 'replaced',
    });
    expect(again.find((p) => p.projectId === first)).toEqual({
      projectId: first,
      comment: 'created',
      updated: 'created',
    });
  });

  it('a version Azure DevOps does not offer is refused', async () => {
    const id = await connect();
    await mapRepository(h, 'hooks/api', id, api);
    fake.inject('GET', /hooks\/publishers\/tfs\/eventTypes$/, {
      status: 200,
      body: {
        count: 2,
        value: [
          { id: COMMENT, supportedResourceVersions: ['1.0'] },
          { id: UPDATED, supportedResourceVersions: ['1.0'] },
        ],
      },
    });
    expect(outcomes(await subscribe(id))).toEqual([
      { projectId: api.projectId, comment: 'refused', updated: 'created' },
    ]);
  });

  it('the Test lists the hook state of each mapped project', async () => {
    const id = await connect();
    await mapRepository(h, 'hooks/api', id, api);
    await mapRepository(h, 'hooks/docs', id, docs);
    const test = async () =>
      (
        (await call(h, 'POST', `/scm-connections/${id}/test`, {})).json() as {
          ok: boolean;
          hooks: { projectId: string; state: string }[] | null;
        }
      ).hooks;
    const sorted = [api.projectId, docs.projectId].sort();
    expect(await test()).toEqual(sorted.map((projectId) => ({ projectId, state: 'missing' })));

    await subscribe(id);
    expect(await test()).toEqual(sorted.map((projectId) => ({ projectId, state: 'enabled' })));

    const ofApi = fake.subscriptions.filter((s) => s.projectId === api.projectId);
    fake.setSubscriptionStatus(ofApi[0]!.id, 'onProbation');
    const ofDocs = fake.subscriptions.filter((s) => s.projectId === docs.projectId);
    fake.setSubscriptionStatus(ofDocs[0]!.id, 'disabledByUser');
    fake.setSubscriptionStatus(ofDocs[1]!.id, 'enabled');
    const states = Object.fromEntries((await test())!.map((p) => [p.projectId, p.state]));
    expect(states).toEqual({ [api.projectId]: 'onProbation', [docs.projectId]: 'disabled' });
  });

  it('the Test reports nothing about hooks for a connection without a mapped repository', async () => {
    const id = await connect();
    const res = await call(h, 'POST', `/scm-connections/${id}/test`, {});
    expect((res.json() as { hooks: unknown }).hooks).toEqual([]);
  });

  it('a GitHub connection answers hooks null in its Test result', async () => {
    const connection = await githubConnection(h, github);
    const res = await call(h, 'POST', `/scm-connections/${connection}/test`, {});
    expect(res.json()).toMatchObject({ ok: true, hooks: null });
    const dto = await call(h, 'GET', `/scm-connections?organizationId=${h.organizationId}`);
    const gh = (dto.json() as { items: { id: string; azure: unknown }[] }).items.find(
      (c) => c.id === connection,
    );
    expect(gh!.azure).toBeNull();
  });
});
