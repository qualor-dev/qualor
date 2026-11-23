import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { createServer as createHttpServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import { and, asc, eq, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_PASSWORD, addMember, createUser, login, type Session } from '../../test/app';
import { AZURE_TEST_PRINCIPAL, azureServerConfig, servicesUrlOf } from '../../test/azure';
import { waitForLockWaiters } from '../../test/db';
import {
  createFakeAzureDevOps,
  recordedAnswer,
  type FakeAzureDevOps,
  type FakeAzureRepository,
} from '../../test/fake-azure-devops';
import { createFakeGitHub, type FakeGitHub, type FakeRepository } from '../../test/fake-github';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { githubTestConfig, WEBHOOK_SECRET } from '../../test/github';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { rbacPlugins } from '../../test/rbac';
import { TEST_IDP, TEST_SP } from '../../test/saml';
import { GITLAB_WEBHOOK_SECRET, PUBLIC_URL, scmTestConfig } from '../../test/scm';
import { trustTestCa } from '../../test/tls';
import { selfSignedRsaCertificate } from '../../test/x509';
import { decryptSecret, encryptionKey, encryptSecret } from '../crypto/secrets';
import {
  auditEvents,
  branches,
  jobs,
  organizations,
  projectMemberships,
  projects,
  scmConnections,
} from '../db/schema';
import { AZURE_CERTIFICATE_PROBLEM_TEXT } from '../scm/azure/certificate';
import { azureClientFor, testAzureConnection } from '../scm/azure/connections';
import {
  MAX_SCM_CONNECTIONS_PER_ORGANIZATION,
  SCM_TOKEN_AAD,
  scmDepsOf,
  testConnection,
  webBaseSql,
} from '../scm/connections';
import { InstallationTokenCache } from '../scm/github/app-auth';
import {
  decryptPrivateKey,
  decryptWebhookSecret,
  WEBHOOK_SECRET_AAD,
} from '../scm/github/credentials';
import { githubWebBase } from '../scm/github/url';
import { GITLAB_FORBIDDEN } from '../scm/gitlab/client';

interface Connection {
  id: string;
  organizationId: string;
  provider: string;
  baseUrl: string;
}

/** An organisation admin's PATCH of a connection. */
const patchConnection = (h: IngestHarness, id: string, payload: Record<string, unknown>) =>
  h.ctx.app.inject({
    method: 'PATCH',
    url: `/api/v0/scm-connections/${id}`,
    headers: h.orgAdmin.headers,
    payload,
  });

const raceConnectionPatches = async (
  h: IngestHarness,
  id: string,
  first: Record<string, unknown>,
  second: Record<string, unknown>,
) => {
  let a: ReturnType<typeof patchConnection> | undefined;
  let b: ReturnType<typeof patchConnection> | undefined;
  await h.ctx.db.transaction(async (tx) => {
    await tx
      .select({ id: scmConnections.id })
      .from(scmConnections)
      .where(eq(scmConnections.id, id))
      .for('update');
    a = patchConnection(h, id, first);
    await waitForLockWaiters(h.ctx.db, 1);
    b = patchConnection(h, id, second);
    await waitForLockWaiters(h.ctx.db, 2);
  });
  return [await a!, await b!] as const;
};

describe('SCM connections API and project mapping (scm.md §2)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;
  let member: Session;
  let outsider: Session;
  const call = (
    method: 'GET' | 'POST' | 'PATCH' | 'DELETE',
    url: string,
    session: Session = h.orgAdmin,
    payload?: unknown,
  ) =>
    h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: session.headers,
      ...(payload === undefined ? {} : { payload: payload as object }),
    });
  const create = async (body: Record<string, unknown> = {}): Promise<Connection> => {
    const res = await call('POST', '/scm-connections', h.orgAdmin, {
      organizationId: h.organizationId,
      provider: 'gitlab',
      baseUrl: fake.url,
      token: fake.token,
      ...body,
    });
    expect(res.statusCode, res.body).toBe(201);
    return res.json() as Connection;
  };

  beforeAll(async () => {
    fake = await createFakeGitLab();
    fake.addProject({ id: 7, path: 'acme/payments/api' });
    // The operator lists the fake's host with its port (scm.md §2.1: an entry without a port
    // allows only the scheme's default one).
    h = await createIngestHarness({
      config: { scmInternalHosts: new Set([new URL(fake.url).host]) },
    });
    const m = await createUser(h.ctx, { username: 'scm-member' });
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
    const o = await createUser(h.ctx, { username: 'scm-outsider' });
    outsider = await login(h.ctx, o.username, o.password);
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });

  it('stores the token encrypted and never returns or logs it', async () => {
    const connection = await create();
    expect(connection).toEqual({
      id: expect.any(String),
      organizationId: h.organizationId,
      provider: 'gitlab',
      baseUrl: fake.url,
      createdAt: expect.any(String),
      github: null,
      // No webhook secret was given, and this server has no QUALOR_PUBLIC_URL to build its URL from.
      gitlab: {
        webhookSecretSet: false,
        webhookSecretReadable: false,
        webhookUrl: null,
        ciSetupAllowed: false,
      },
      azure: null,
      ciSetup: { available: false, reason: 'no_public_url', missing: [] },
      fixMrsAllowed: false,
      problem: null,
    });
    const [row] = await h.ctx.db
      .select()
      .from(scmConnections)
      .where(eq(scmConnections.id, connection.id));
    expect(JSON.stringify(row)).not.toContain(fake.token);
    const key = encryptionKey(h.ctx.config.secretKey);
    expect(decryptSecret(key, row!.tokenEnc, SCM_TOKEN_AAD)).toBe(fake.token);
    // Bound to its column: the same envelope is not a webhook secret.
    expect(decryptSecret(key, row!.tokenEnc, 'webhook_subscriptions.secret_enc')).toBeNull();
    const list = await call('GET', `/scm-connections?organizationId=${h.organizationId}`);
    expect(list.statusCode).toBe(200);
    expect(list.body).not.toContain(fake.token);
    expect(h.ctx.logs.join('\n')).not.toContain(fake.token);
    await call('DELETE', `/scm-connections/${connection.id}`);
  });

  it('has no webhook URL to paste while the server has no QUALOR_PUBLIC_URL, whether a secret is set or not', async () => {
    const connection = await create({ webhookSecret: GITLAB_WEBHOOK_SECRET });
    expect(connection).toMatchObject({
      gitlab: { webhookSecretSet: true, webhookSecretReadable: true, webhookUrl: null },
    });
    await call('DELETE', `/scm-connections/${connection.id}`);
  });

  it('checks the base URL: https or a listed internal host, no credentials, query or fragment', async () => {
    const refused = async (baseUrl: string) => {
      const res = await call('POST', '/scm-connections', h.orgAdmin, {
        organizationId: h.organizationId,
        provider: 'gitlab',
        baseUrl,
        token: 'glpat-x',
      });
      expect(res.statusCode, baseUrl).toBe(422);
      return (res.json() as { errors: { path: string; message: string }[] }).errors[0];
    };
    expect((await refused('http://gitlab.example.com'))?.path).toBe('body.baseUrl');
    expect((await refused('https://localhost'))?.message).toMatch(/QUALOR_SCM_INTERNAL_HOSTS/);
    expect((await refused('https://10.0.0.1'))?.message).toMatch(/non-public/);
    expect((await refused('https://u:p@gitlab.example.com'))?.message).toMatch(/credentials/);
    expect((await refused('https://gitlab.example.com/?private_token=x'))?.message).toMatch(
      /query/,
    );
    const stored = await create({ baseUrl: 'https://GitLab.Example.com/gitlab/' });
    expect(stored.baseUrl).toBe('https://gitlab.example.com/gitlab');
    await call('DELETE', `/scm-connections/${stored.id}`);
  });

  it('refuses a GitHub body with a token, another provider, and a token that is not header-safe', async () => {
    const github = await call('POST', '/scm-connections', h.orgAdmin, {
      organizationId: h.organizationId,
      provider: 'github',
      baseUrl: 'https://github.example.com/api/v3',
      token: 'ghp_x',
    });
    expect(github.statusCode).toBe(422);
    expect(github.json()).toMatchObject({
      errors: expect.arrayContaining([{ path: 'body.token', message: expect.any(String) }]),
    });
    const other = await call('POST', '/scm-connections', h.orgAdmin, {
      organizationId: h.organizationId,
      provider: 'bitbucket',
      baseUrl: 'https://bitbucket.example.com',
      token: 'x',
    });
    expect(other.statusCode).toBe(422);
    expect(other.json()).toMatchObject({ errors: [{ path: 'body.provider' }] });
    const spaced = await call('POST', '/scm-connections', h.orgAdmin, {
      organizationId: h.organizationId,
      provider: 'gitlab',
      baseUrl: 'https://gitlab.example.com',
      token: 'glpat with space',
    });
    expect(spaced.statusCode).toBe(422);
    expect(spaced.json()).toMatchObject({ errors: [{ path: 'body.token' }] });
    expect(spaced.body).not.toContain('glpat with space');
  });

  it('is for org admins only: a member gets 403, an outsider 404, anonymous 401', async () => {
    const connection = await create();
    expect(
      (await call('GET', `/scm-connections?organizationId=${h.organizationId}`, member)).statusCode,
    ).toBe(403);
    expect(
      (await call('PATCH', `/scm-connections/${connection.id}`, member, { token: 'x' })).statusCode,
    ).toBe(403);
    expect((await call('DELETE', `/scm-connections/${connection.id}`, outsider)).statusCode).toBe(
      404,
    );
    expect(
      (await call('POST', `/scm-connections/${connection.id}/test`, outsider, {})).statusCode,
    ).toBe(404);
    const anonymous = await h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/scm-connections?organizationId=${h.organizationId}`,
    });
    expect(anonymous.statusCode).toBe(401);
    await call('DELETE', `/scm-connections/${connection.id}`);
  });

  it('tests the connection and a project with the stored token, in fixed texts', async () => {
    const connection = await create();
    const ok = await call('POST', `/scm-connections/${connection.id}/test`, h.orgAdmin, {
      projectRef: 'acme/payments/api',
    });
    expect(ok.json()).toEqual({
      ok: true,
      user: { username: 'project_7_bot_4b1e2c' },
      project: { id: 7, pathWithNamespace: 'acme/payments/api', accessLevel: 30 },
      problem: null,
      // A GitHub App's alone.
      missingAccess: null,
      // An Azure DevOps connection's alone.
      visible: null,
      hooks: null,
    });
    const missing = await call('POST', `/scm-connections/${connection.id}/test`, h.orgAdmin, {
      projectRef: 'acme/nope',
    });
    expect(missing.json()).toMatchObject({
      ok: false,
      problem: {
        code: 'not_found',
        message: 'The GitLab project was not found, or the token cannot see it',
      },
    });
    // A Maintainer's token says so; a 403 is a missing permission, not a refused token.
    fake.accessLevel = 40;
    try {
      const maintainer = await call('POST', `/scm-connections/${connection.id}/test`, h.orgAdmin, {
        projectRef: '7',
      });
      expect(maintainer.json().project).toMatchObject({ id: 7, accessLevel: 40 });
    } finally {
      fake.accessLevel = 30;
    }
    fake.inject('GET', /^\/projects\/7$/, { status: 403 });
    const forbidden = await call('POST', `/scm-connections/${connection.id}/test`, h.orgAdmin, {
      projectRef: '7',
    });
    expect(forbidden.json().problem).toEqual({
      code: 'permission_missing',
      message: GITLAB_FORBIDDEN.request,
    });
    const badRef = await call('POST', `/scm-connections/${connection.id}/test`, h.orgAdmin, {
      projectRef: '../../user',
    });
    expect(badRef.statusCode).toBe(422);
    const patched = await call('PATCH', `/scm-connections/${connection.id}`, h.orgAdmin, {
      token: 'glpat-wrong',
    });
    expect(patched.statusCode).toBe(200);
    expect(patched.body).not.toContain('glpat-wrong');
    const refused = await call('POST', `/scm-connections/${connection.id}/test`, h.orgAdmin, {});
    expect(refused.json()).toEqual({
      ok: false,
      user: null,
      project: null,
      problem: { code: 'token_refused', message: 'GitLab refused the token (HTTP 401)' },
      missingAccess: null,
      visible: null,
      hooks: null,
    });
    // A token encrypted under another key (QUALOR_SECRET_KEY rotated) is named, not sent.
    await h.ctx.db
      .update(scmConnections)
      .set({
        tokenEnc: encryptSecret(
          encryptionKey('another-secret-key-of-32-characters!'),
          'x',
          SCM_TOKEN_AAD,
        ),
      })
      .where(eq(scmConnections.id, connection.id));
    fake.clearRequests();
    const undecryptable = await call(
      'POST',
      `/scm-connections/${connection.id}/test`,
      h.orgAdmin,
      {},
    );
    expect(undecryptable.json()).toMatchObject({
      ok: false,
      problem: { code: 'undecryptable', message: expect.stringMatching(/cannot be decrypted/) },
    });
    expect(fake.requests).toHaveLength(0);
    await call('DELETE', `/scm-connections/${connection.id}`);
  });

  it(`holds at most ${MAX_SCM_CONNECTIONS_PER_ORGANIZATION} connections per organisation, also under concurrency`, async () => {
    const [org] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'scm-bound', name: 'SCM bound' })
      .returning();
    // The org admin of `default` is not a member of this organisation: 404, as for any outsider.
    const outside = await call('POST', '/scm-connections', h.orgAdmin, {
      organizationId: org!.id,
      provider: 'gitlab',
      baseUrl: 'https://gitlab.example.com',
      token: 'glpat-x',
    });
    expect(outside.statusCode).toBe(404);
    const admin = await login(h.ctx, 'admin', ADMIN_PASSWORD);
    const results = await Promise.all(
      Array.from({ length: MAX_SCM_CONNECTIONS_PER_ORGANIZATION + 3 }, () =>
        call('POST', '/scm-connections', admin, {
          organizationId: org!.id,
          provider: 'gitlab',
          baseUrl: 'https://gitlab.example.com',
          token: 'glpat-x',
        }),
      ),
    );
    expect(results.filter((r) => r.statusCode === 201)).toHaveLength(
      MAX_SCM_CONNECTIONS_PER_ORGANIZATION,
    );
    expect(results.filter((r) => r.statusCode === 409).map((r) => r.json().code)).toEqual([
      'SCM_CONNECTION_LIMIT_REACHED',
      'SCM_CONNECTION_LIMIT_REACHED',
      'SCM_CONNECTION_LIMIT_REACHED',
    ]);
  });

  it('maps a project to a connection of its own organisation and a GitLab project', async () => {
    const connection = await create();
    const project = await h.project('scm/mapped');
    const patch = (body: unknown) => call('PATCH', `/projects/${project.id}`, h.orgAdmin, body);
    const mapped = await patch({
      scmConnectionId: connection.id,
      scmProjectRef: 'acme/payments/api',
    });
    expect(mapped.statusCode, mapped.body).toBe(200);
    expect(mapped.json()).toMatchObject({
      scmConnectionId: connection.id,
      scmProjectRef: 'acme/payments/api',
    });
    expect((await patch({ scmProjectRef: '7' })).json()).toMatchObject({ scmProjectRef: '7' });
    for (const bad of ['acme', '/acme/x', 'acme//x', 'acme/..', 'acme/x?y', 'a'.repeat(256)]) {
      const res = await patch({ scmProjectRef: bad });
      expect(res.statusCode, bad).toBe(422);
      expect((res.json() as { errors: { path: string }[] }).errors[0]?.path).toBe(
        'body.scmProjectRef',
      );
    }
    const [other] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'scm-other', name: 'Other' })
      .returning();
    const [foreign] = await h.ctx.db
      .insert(scmConnections)
      .values({
        organizationId: other!.id,
        provider: 'gitlab',
        baseUrl: 'https://gitlab.example.com',
        tokenEnc: encryptSecret(encryptionKey(h.ctx.config.secretKey), 'x', SCM_TOKEN_AAD),
      })
      .returning();
    const refused = await patch({ scmConnectionId: foreign!.id });
    expect(refused.statusCode).toBe(422);
    expect(refused.json()).toMatchObject({ errors: [{ path: 'body.scmConnectionId' }] });
    // A member cannot change the mapping; deleting the connection unmaps, keeping the ref.
    expect(
      (await call('PATCH', `/projects/${project.id}`, member, { scmProjectRef: null })).statusCode,
    ).toBe(403);
    expect((await call('DELETE', `/scm-connections/${connection.id}`)).statusCode).toBe(204);
    const [row] = await h.ctx.db.select().from(projects).where(eq(projects.id, project.id));
    expect(row).toMatchObject({ scmConnectionId: null, scmProjectRef: '7' });
    expect(await h.ctx.db.select().from(jobs).where(eq(jobs.queue, 'scm'))).toHaveLength(0);
  });

  it('answers the same 404 for a connection that does not exist and one of another organisation', async () => {
    const connection = await create();
    const missingId = '01920000-0000-7000-8000-00000000abcd';
    const pairs: [string, string, 'PATCH' | 'DELETE' | 'POST', unknown][] = [
      [
        `/scm-connections/${connection.id}`,
        `/scm-connections/${missingId}`,
        'PATCH',
        { token: 'x' },
      ],
      [`/scm-connections/${connection.id}`, `/scm-connections/${missingId}`, 'DELETE', undefined],
      [`/scm-connections/${connection.id}/test`, `/scm-connections/${missingId}/test`, 'POST', {}],
    ];
    for (const [existing, missing, method, body] of pairs) {
      const foreign = await call(method, existing, outsider, body);
      const absent = await call(method, missing, outsider, body);
      expect(foreign.statusCode).toBe(404);
      expect(foreign.json()).toEqual(absent.json());
    }
    // The outsider changed nothing.
    const [row] = await h.ctx.db
      .select()
      .from(scmConnections)
      .where(eq(scmConnections.id, connection.id));
    expect(decryptSecret(encryptionKey(h.ctx.config.secretKey), row!.tokenEnc, SCM_TOKEN_AAD)).toBe(
      fake.token,
    );
    // Listing another organisation's connections is the same 404 as a missing organisation.
    const [other] = await h.ctx.db
      .insert(organizations)
      .values({ key: 'scm-list-other', name: 'Other' })
      .returning();
    const foreignList = await call('GET', `/scm-connections?organizationId=${other!.id}`);
    const missingList = await call('GET', `/scm-connections?organizationId=${missingId}`);
    expect(foreignList.statusCode).toBe(404);
    expect(foreignList.json()).toEqual(missingList.json());
    // A member may not test a connection (it would use the stored token).
    expect(
      (await call('POST', `/scm-connections/${connection.id}/test`, member, {})).statusCode,
    ).toBe(403);
    await call('DELETE', `/scm-connections/${connection.id}`);
  });

  it("never echoes GitLab's answer, and never logs or returns a token", async () => {
    const connection = await create();
    const secretish = `glpat-echoed-${fake.token}`;
    for (const status of [400, 422, 500]) {
      fake.inject('GET', /^\/user$/, {
        status,
        body: { message: `${secretish} <script>alert(1)</script>` },
      });
      const res = await call('POST', `/scm-connections/${connection.id}/test`, h.orgAdmin, {});
      expect(res.statusCode).toBe(200);
      expect(res.json()).toEqual({
        ok: false,
        user: null,
        project: null,
        problem: { code: 'http_error', message: `GitLab answered HTTP ${status}` },
        hooks: null,
        missingAccess: null,
        visible: null,
      });
      expect(res.body).not.toContain('glpat-echoed');
      expect(res.body).not.toContain('script');
    }
    fake.inject('GET', /^\/user$/, { status: 200, body: { id: 'not a user', token: secretish } });
    const garbled = await call('POST', `/scm-connections/${connection.id}/test`, h.orgAdmin, {});
    expect(garbled.json()).toMatchObject({
      ok: false,
      problem: { code: 'bad_answer', message: "GitLab's answer was not understood" },
    });
    expect(garbled.body).not.toContain('glpat-echoed');
    const patched = await call('PATCH', `/scm-connections/${connection.id}`, h.orgAdmin, {
      token: 'glpat-replaced-token',
      baseUrl: fake.url,
    });
    expect(patched.body).not.toContain('glpat-replaced-token');
    const logs = h.ctx.logs.join('\n');
    for (const secret of [fake.token, 'glpat-replaced-token', 'glpat-wrong', 'glpat-echoed']) {
      expect(logs).not.toContain(secret);
    }
    await call('DELETE', `/scm-connections/${connection.id}`);
  });

  it('sends nothing to a host the operator no longer lists', async () => {
    const connection = await create();
    const [row] = await h.ctx.db
      .select()
      .from(scmConnections)
      .where(eq(scmConnections.id, connection.id));
    fake.clearRequests();
    const result = await testConnection(
      row!,
      {
        secretKey: h.ctx.config.secretKey,
        internalHosts: new Set(),
        azureTokenOrigin: null,
        azureTestOrigin: null,
      },
      null,
    );
    expect(result).toMatchObject({ ok: false, problem: { code: 'url_not_allowed' } });
    expect(result.problem?.message).toMatch(/QUALOR_SCM_INTERNAL_HOSTS/);
    // A name that is not listed but resolves to the listed address is refused before connecting.
    const byName = await testConnection(
      { ...row!, baseUrl: fake.url.replace('http://127.0.0.1', 'https://gitlab.internal.test') },
      {
        secretKey: h.ctx.config.secretKey,
        internalHosts: new Set(['127.0.0.1']),
        azureTokenOrigin: null,
        azureTestOrigin: null,
        clientOptions: {
          resolve: () => Promise.resolve([{ address: '127.0.0.1', family: 4 }]),
        },
      },
      null,
    );
    expect(byName).toMatchObject({ ok: false, problem: { code: 'not_public' } });
    // A single-label name whose lookup outlasts the connect deadline is unresolved, not a timeout.
    const slowLookup = await testConnection(
      { ...row!, baseUrl: 'https://gitlab-ce' },
      {
        secretKey: h.ctx.config.secretKey,
        internalHosts: new Set(['gitlab-ce']),
        azureTokenOrigin: null,
        azureTestOrigin: null,
        clientOptions: { connectTimeoutMs: 50, resolve: () => new Promise(() => undefined) },
      },
      null,
    );
    expect(slowLookup).toMatchObject({ ok: false, problem: { code: 'unresolved' } });
    expect(fake.requests).toHaveLength(0);
    await call('DELETE', `/scm-connections/${connection.id}`);
  });

  it('needs the token again, in the same request, to change the base URL', async () => {
    const connection = await create();
    const patch = (body: unknown) =>
      call('PATCH', `/scm-connections/${connection.id}`, h.orgAdmin, body);
    // Pointing the stored token at another host (or path) without supplying it is refused, so an
    // org admin cannot redirect a token they were never shown.
    for (const baseUrl of [
      'https://attacker.example',
      `${fake.url}/other`,
      `https://gitlab.example.com`,
    ]) {
      const res = await patch({ baseUrl });
      expect(res.statusCode, baseUrl).toBe(422);
      expect((res.json() as { errors: { path: string }[] }).errors[0]?.path).toBe('body.token');
    }
    const [row] = await h.ctx.db
      .select()
      .from(scmConnections)
      .where(eq(scmConnections.id, connection.id));
    expect(row?.baseUrl).toBe(fake.url);
    // The same address, however spelled, keeps the token.
    const same = await patch({ baseUrl: `${fake.url.toUpperCase().replace('HTTP', 'http')}/` });
    expect(same.statusCode, same.body).toBe(200);
    // A new address with a new token is accepted.
    const moved = await patch({ baseUrl: 'https://gitlab.example.com', token: 'glpat-new' });
    expect(moved.statusCode, moved.body).toBe(200);
    expect(moved.json()).toMatchObject({ baseUrl: 'https://gitlab.example.com' });
    expect(moved.body).not.toContain('glpat-new');
    await call('DELETE', `/scm-connections/${connection.id}`);
  });

  it('checks the stored address again when it writes, so a concurrent change cannot redirect the token', async () => {
    const connection = await create();
    const key = encryptionKey(h.ctx.config.secretKey);
    let pending: ReturnType<typeof call> | undefined;
    // Another admin moves the connection, with its own token, between this request's read and its
    // write. This request names the old address without a token: written blindly, it would send
    // the other admin's token to the old address.
    await h.ctx.db.transaction(async (tx) => {
      await tx
        .select({ id: scmConnections.id })
        .from(scmConnections)
        .where(eq(scmConnections.id, connection.id))
        .for('update');
      pending = call('PATCH', `/scm-connections/${connection.id}`, h.orgAdmin, {
        baseUrl: fake.url,
      });
      await waitForLockWaiters(h.ctx.db, 1);
      await tx
        .update(scmConnections)
        .set({
          baseUrl: 'https://gitlab.example.com',
          tokenEnc: encryptSecret(key, 'glpat-moved', SCM_TOKEN_AAD),
        })
        .where(eq(scmConnections.id, connection.id));
    });
    const res = await pending!;
    expect(res.statusCode, res.body).toBe(422);
    expect((res.json() as { errors: { path: string }[] }).errors[0]?.path).toBe('body.token');
    const [row] = await h.ctx.db
      .select()
      .from(scmConnections)
      .where(eq(scmConnections.id, connection.id));
    expect(row?.baseUrl).toBe('https://gitlab.example.com');
    expect(decryptSecret(key, row!.tokenEnc, SCM_TOKEN_AAD)).toBe('glpat-moved');
    await call('DELETE', `/scm-connections/${connection.id}`);
  });

  it('forgets merge request links that are no longer on the address of the mapped connection (scm.md §8)', async () => {
    const connection = await create();
    const project = await h.project('scm/mr-links');
    expect(
      (
        await call('PATCH', `/projects/${project.id}`, h.orgAdmin, {
          scmConnectionId: connection.id,
          scmProjectRef: '7',
        })
      ).statusCode,
    ).toBe(200);
    const linked = async (name: string, mrUrl: string) =>
      (
        await h.ctx.db
          .insert(branches)
          .values({ projectId: project.id, kind: 'merge_request', name, mrUrl })
          .returning()
      )[0]!;
    const onOld = await linked('1', `${fake.url}/acme/payments/api/-/merge_requests/1`);
    const onNew = await linked('2', 'https://gitlab.example.com/acme/api/-/merge_requests/2');
    const urls = async () =>
      Object.fromEntries(
        (
          await h.ctx.db
            .select({ id: branches.id, mrUrl: branches.mrUrl })
            .from(branches)
            .where(eq(branches.projectId, project.id))
        ).map((b) => [b.id, b.mrUrl]),
      );
    // A token replaced at the same address keeps every link.
    await call('PATCH', `/scm-connections/${connection.id}`, h.orgAdmin, { token: 'glpat-2' });
    expect((await urls())[onOld.id]).toBe(onOld.mrUrl);
    // A new address drops the links that are not on it.
    const moved = await call('PATCH', `/scm-connections/${connection.id}`, h.orgAdmin, {
      baseUrl: 'https://gitlab.example.com',
      token: 'glpat-3',
    });
    expect(moved.statusCode, moved.body).toBe(200);
    expect(await urls()).toMatchObject({ [onOld.id]: null, [onNew.id]: onNew.mrUrl });
    // Mapping the project to another connection does the same against that one's address.
    const other = await create();
    expect(
      (
        await call('PATCH', `/projects/${project.id}`, h.orgAdmin, {
          scmConnectionId: other.id,
        })
      ).statusCode,
    ).toBe(200);
    expect(await urls()).toMatchObject({ [onOld.id]: null, [onNew.id]: null });
    await call('DELETE', `/scm-connections/${connection.id}`);
    await call('DELETE', `/scm-connections/${other.id}`);
  });

  it('lets a mapping change and the deletion of its connection wait for each other, never deadlock', async () => {
    const connection = await create();
    const project = await h.project('scm/lock-order');
    const map = () =>
      call('PATCH', `/projects/${project.id}`, h.orgAdmin, {
        name: 'Lock order',
        scmConnectionId: connection.id,
        scmProjectRef: '7',
      });
    expect((await map()).statusCode).toBe(200);
    let patched: ReturnType<typeof call> | undefined;
    let deleted: ReturnType<typeof call> | undefined;
    // Another transaction holds the project row, so both requests queue behind it: the PATCH
    // first, then the DELETE, whose ON DELETE SET NULL must update the same project row.
    await h.ctx.db.transaction(async (tx) => {
      await tx
        .select({ id: projects.id })
        .from(projects)
        .where(eq(projects.id, project.id))
        .for('no key update');
      patched = map();
      await waitForLockWaiters(h.ctx.db, 1);
      deleted = call('DELETE', `/scm-connections/${connection.id}`);
      await waitForLockWaiters(h.ctx.db, 2);
    });
    // Both lock the connection before the project, so one waits for the other (no 40P01, 503).
    const [p, d] = await Promise.all([patched!, deleted!]);
    expect(p.statusCode, p.body).toBe(200);
    expect(d.statusCode, d.body).toBe(204);
    const [row] = await h.ctx.db.select().from(projects).where(eq(projects.id, project.id));
    expect(row).toMatchObject({ name: 'Lock order', scmConnectionId: null });
  });

  it('reaches only the listed port of an internal host', async () => {
    const port = Number(new URL(fake.url).port);
    const other = port === 65_535 ? port - 1 : port + 1;
    for (const baseUrl of [
      `http://127.0.0.1:${other}`,
      'http://127.0.0.1',
      'https://127.0.0.1:22',
    ]) {
      const res = await call('POST', '/scm-connections', h.orgAdmin, {
        organizationId: h.organizationId,
        provider: 'gitlab',
        baseUrl,
        token: 'glpat-x',
      });
      expect(res.statusCode, baseUrl).toBe(422);
    }
    // A connection saved for the listed port cannot be moved to another port of the host.
    const connection = await create();
    const moved = await call('PATCH', `/scm-connections/${connection.id}`, h.orgAdmin, {
      baseUrl: `http://127.0.0.1:${other}`,
      token: fake.token,
    });
    expect(moved.statusCode).toBe(422);
    expect((moved.json() as { errors: { path: string }[] }).errors[0]?.path).toBe('body.baseUrl');
    await call('DELETE', `/scm-connections/${connection.id}`);
  });
});

describe('GitHub App connections (github.md §2.2, §2.5, D1)', () => {
  let h: IngestHarness;
  let fake: FakeGitHub;
  /** A repository on an installation of its own, whose grant a test sets. */
  const partial: FakeRepository = { id: 8, owner: 'acme', name: 'partial', installationId: 779 };
  const post = (payload: Record<string, unknown>) =>
    h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'github',
        baseUrl: fake.url,
        appId: String(fake.appId),
        privateKey: fake.privateKeyPem,
        ...payload,
      },
    });
  const patch = (id: string, payload: Record<string, unknown>) => patchConnection(h, id, payload);
  const list = async () =>
    (
      await h.ctx.app.inject({
        method: 'GET',
        url: `/api/v0/scm-connections?organizationId=${h.organizationId}`,
        headers: h.orgAdmin.headers,
      })
    ).json().items as { id: string; github: Record<string, unknown> | null }[];
  const rowOf = async (id: string) =>
    (await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, id)))[0]!;
  const errorPaths = (body: string) =>
    (JSON.parse(body) as { errors?: { path: string }[] }).errors?.map((e) => e.path).sort();
  const serverKey = () => encryptionKey(h.ctx.config.secretKey);

  beforeAll(async () => {
    fake = await createFakeGitHub();
    fake.addRepository({ id: 424242, owner: 'acme', name: 'api', installationId: 777 });
    fake.addRepository({ id: 6, owner: 'acme', name: 'bare', installationId: null });
    fake.addRepository({
      id: 7,
      owner: 'acme',
      name: 'nochecks',
      installationId: 778,
      permissions: { metadata: 'read', pull_requests: 'write' },
    });
    fake.addRepository(partial);
    h = await createIngestHarness({ config: githubTestConfig(fake) });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });

  it('stores the App id in plain text, the key and the secret in their own envelopes, and shows neither', async () => {
    const created = await post({ webhookSecret: WEBHOOK_SECRET });
    expect(created.statusCode).toBe(201);
    const id = created.json().id as string;
    expect(created.json().github).toEqual({
      appId: String(fake.appId),
      keyReadable: true,
      webhookSecretSet: true,
      webhookSecretReadable: true,
      webhookUrl: `${PUBLIC_URL}/api/v0/github/webhooks/${id}`,
    });
    // GitLab's fields are a GitLab connection's.
    expect(created.json().gitlab).toBeNull();
    const row = await rowOf(id);
    expect(row.appId).toBe(String(fake.appId));
    expect(
      decryptPrivateKey(serverKey(), row.tokenEnc)?.pkcs8.startsWith('-----BEGIN PRIVATE KEY-----'),
    ).toBe(true);
    expect(decryptWebhookSecret(serverKey(), row.webhookSecretEnc)).toBe(WEBHOOK_SECRET);
    const listed = JSON.stringify(await list());
    for (const body of [
      created.body,
      listed,
      JSON.stringify(row.tokenEnc),
      JSON.stringify(row.webhookSecretEnc),
      h.ctx.logs.join('\n'),
    ]) {
      expect(body).not.toContain('PRIVATE KEY');
      expect(body).not.toContain(WEBHOOK_SECRET);
      expect(body).not.toContain(fake.privateKeyPem.split('\n')[1]!);
    }
  });

  it('a GitLab connection takes none of the GitHub App fields', async () => {
    const created = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'gitlab',
        baseUrl: fake.url,
        token: 'glpat-x',
      },
    });
    const row = await rowOf(created.json().id as string);
    expect([row.appId, row.webhookSecretEnc, created.json().github]).toEqual([null, null, null]);
    // The API refuses the App's own fields; the webhook secret is GitLab's too (migration 0017
    // lets a GitLab row hold one).
    expect(
      errorPaths(
        (await patch(row.id, { appId: '1', privateKey: fake.privateKeyPem, webhookSecret: null }))
          .body,
      ),
    ).toEqual(['body.appId', 'body.privateKey']);
    expect((await patch(row.id, { webhookSecret: WEBHOOK_SECRET })).statusCode).toBe(200);
    const withAppId = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'gitlab',
        baseUrl: fake.url,
        token: 'glpat-x',
        appId: '1',
      },
    });
    expect([withAppId.statusCode, errorPaths(withAppId.body)]).toEqual([422, ['body.appId']]);
    await h.ctx.db.delete(scmConnections).where(eq(scmConnections.id, row.id));
  });

  it.each([
    [{ token: 'glpat-x' }, 'body.token'],
    [{ appId: '12a' }, 'body.appId'],
    [{ appId: '0' }, 'body.appId'],
    [{ appId: '007' }, 'body.appId'],
    [{ appId: '1'.repeat(17) }, 'body.appId'],
    [{ appId: undefined }, 'body.appId'],
    [{ privateKey: 'ghp_notakey' }, 'body.privateKey'],
    [{ webhookSecret: 'short' }, 'body.webhookSecret'],
    [{ baseUrl: 'https://github.com' }, 'body.baseUrl'],
  ])('refuses %j naming %s', async (payload, path) => {
    const res = await post(payload);
    expect(res.statusCode).toBe(422);
    expect(errorPaths(res.body)).toContain(path);
    expect(res.body).not.toContain('PRIVATE KEY');
  });

  it('changes each column on its own, and needs the key and the secret again for a new address', async () => {
    const id = (await post({ webhookSecret: WEBHOOK_SECRET })).json().id as string;
    const before = await rowOf(id);
    expect((await patch(id, { webhookSecret: null })).json().github).toMatchObject({
      webhookSecretSet: false,
      webhookUrl: null,
    });
    expect((await rowOf(id)).tokenEnc).toEqual(before.tokenEnc); // the key untouched
    expect((await patch(id, { webhookSecret: 'n'.repeat(20) })).json().github).toMatchObject({
      appId: String(fake.appId),
      webhookSecretSet: true,
    });
    expect((await patch(id, { appId: '999' })).json().github.appId).toBe('999');
    expect((await rowOf(id)).webhookSecretEnc).not.toBeNull(); // the secret untouched
    expect(errorPaths((await patch(id, { token: 'glpat-x' })).body)).toEqual(['body.token']);
    expect(errorPaths((await patch(id, { appId: '007' })).body)).toEqual(['body.appId']);
    const moved = await patch(id, { baseUrl: 'https://api.github.com' });
    expect([moved.statusCode, errorPaths(moved.body)]).toEqual([
      422,
      ['body.privateKey', 'body.webhookSecret'],
    ]);
    const movedWithKeyOnly = await patch(id, {
      baseUrl: 'https://api.github.com',
      privateKey: fake.privateKeyPem,
    });
    expect([movedWithKeyOnly.statusCode, errorPaths(movedWithKeyOnly.body)]).toEqual([
      422,
      ['body.webhookSecret'],
    ]);
    const movedWithKey = await patch(id, {
      baseUrl: 'https://api.github.com',
      privateKey: fake.privateKeyPem,
      webhookSecret: null,
    });
    expect(movedWithKey.statusCode).toBe(200);
    expect(movedWithKey.json()).toMatchObject({
      baseUrl: 'https://api.github.com',
      github: { appId: '999', keyReadable: true, webhookSecretSet: false },
    });
    // Without a stored secret, the key alone moves it; the same address needs nothing again.
    const back = await patch(id, { baseUrl: fake.url, privateKey: fake.privateKeyPem });
    expect(back.statusCode).toBe(200);
    expect((await patch(id, { baseUrl: fake.url })).statusCode).toBe(200);
    expect(errorPaths((await patch(id, { baseUrl: 'https://github.com' })).body)).toEqual([
      'body.baseUrl',
    ]);
  });

  /**
   * Holds the connection's row lock while `first` and then `second` send their PATCH, so both
   * wait, in that order, on the write; then releases it.
   */
  const race = (id: string, first: Record<string, unknown>, second: Record<string, unknown>) =>
    raceConnectionPatches(h, id, first, second);
  const ELSEWHERE = 'https://github.qualor.invalid/api/v3';

  it('never moves the connection past a webhook secret set meanwhile', async () => {
    const id = (await post({})).json().id as string;
    // Read without a secret, so the move needs none; a concurrent PATCH sets one first.
    const [setSecret, move] = await race(
      id,
      { webhookSecret: WEBHOOK_SECRET },
      { baseUrl: ELSEWHERE, privateKey: fake.privateKeyPem },
    );
    expect(setSecret.statusCode, setSecret.body).toBe(200);
    expect(move.statusCode, move.body).toBe(503);
    expect(move.json()).toMatchObject({ code: 'CONCURRENCY_CONFLICT' });
    const row = await rowOf(id);
    expect(row.baseUrl).toBe(fake.url); // the secret was never carried to another address
    expect(row.webhookSecretEnc).not.toBeNull();
  });

  it('tells a PATCH of the secret alone that lost a race to a move that the address changed', async () => {
    const id = (await post({})).json().id as string;
    const [move, setSecret] = await race(
      id,
      { baseUrl: ELSEWHERE, privateKey: fake.privateKeyPem },
      { webhookSecret: WEBHOOK_SECRET },
    );
    expect(move.statusCode, move.body).toBe(200);
    expect(setSecret.statusCode, setSecret.body).toBe(503);
    expect(setSecret.json()).toMatchObject({ code: 'CONCURRENCY_CONFLICT' });
    expect(setSecret.body).toContain('address');
    expect(setSecret.body).not.toContain('private key');
    const row = await rowOf(id);
    expect([row.baseUrl, row.webhookSecretEnc]).toEqual([ELSEWHERE, null]);
  });

  it('says which envelope no longer decrypts, and takes a new key alone', async () => {
    const id = (await post({ webhookSecret: WEBHOOK_SECRET })).json().id as string;
    const other = encryptionKey('z'.repeat(32));
    await h.ctx.db
      .update(scmConnections)
      .set({
        tokenEnc: encryptSecret(other, 'x', SCM_TOKEN_AAD),
        webhookSecretEnc: encryptSecret(other, 'x', WEBHOOK_SECRET_AAD),
      })
      .where(eq(scmConnections.id, id));
    expect((await list()).find((c) => c.id === id)?.github).toMatchObject({
      appId: String(fake.appId),
      keyReadable: false,
      webhookSecretSet: true,
      webhookSecretReadable: false,
    });
    expect((await patch(id, { privateKey: fake.privateKeyPem })).json().github).toMatchObject({
      keyReadable: true,
      webhookSecretReadable: false,
    });
  });

  it('tests the App and a repository, with the codes of github.md §2.2', async () => {
    const id = (await post({})).json().id as string;
    const test = (projectRef?: string) =>
      h.ctx.app.inject({
        method: 'POST',
        url: `/api/v0/scm-connections/${id}/test`,
        headers: h.orgAdmin.headers,
        payload: projectRef === undefined ? {} : { projectRef },
      });
    expect((await test('acme/api')).json()).toEqual({
      ok: true,
      user: { username: `${fake.slug}[bot]` },
      project: { id: 424242, pathWithNamespace: 'acme/api', accessLevel: null },
      problem: null,
      // The documented App lacks nothing.
      missingAccess: [],
      hooks: null,
      visible: null,
    });
    expect((await test('acme/bare')).json()).toMatchObject({
      problem: { code: 'not_installed' },
      missingAccess: null,
    });
    // Checks and Pull requests are needed by every job: the token request fails the test.
    expect((await test('acme/nochecks')).json()).toMatchObject({
      ok: false,
      problem: { code: 'permission_missing' },
      missingAccess: null,
    });
    // GitHub answers 404 for the installation of a repository it does not show the App.
    expect((await test('acme/nope')).json().problem.code).toBe('not_installed');
    // Without a repository there is no installation to read.
    expect((await test()).json()).toMatchObject({ ok: true, project: null, missingAccess: null });
    for (const bad of ['424242', 'acme/api/x', 'acme/..']) {
      const res = await test(bad);
      expect([res.statusCode, errorPaths(res.body)]).toEqual([422, ['body.projectRef']]);
    }
    await h.ctx.db
      .update(scmConnections)
      .set({ tokenEnc: encryptSecret(encryptionKey('z'.repeat(32)), 'x', SCM_TOKEN_AAD) })
      .where(eq(scmConnections.id, id));
    fake.clearRequests();
    expect((await test()).json().problem.code).toBe('undecryptable');
    expect(fake.requests).toHaveLength(0);
  });

  it('lists what the installation lacks of the rest of what Qualor uses, in a fixed order', async () => {
    const id = (await post({})).json().id as string;
    /** The Test of acme/partial, whose installation grants `permissions` and subscribes to `events`. */
    const missing = async (permissions: Record<string, 'read' | 'write'>, events: string[]) => {
      partial.permissions = permissions;
      partial.events = events;
      const res = await h.ctx.app.inject({
        method: 'POST',
        url: `/api/v0/scm-connections/${id}/test`,
        headers: h.orgAdmin.headers,
        payload: { projectRef: 'acme/partial' },
      });
      // What it lacks is no failure: the test passes.
      expect(res.json()).toMatchObject({ ok: true, problem: null });
      return res.json().missingAccess as unknown;
    };
    /** What every job needs, which the token request checks. */
    const required = { checks: 'write', metadata: 'read', pull_requests: 'write' } as const;
    const full = { ...required, contents: 'write', issues: 'read' } as const;
    const events = ['check_run', 'issue_comment', 'pull_request_review_comment'];
    expect(await missing(full, events)).toEqual([]);
    // Issues to write reads them too; an event the Test does not check is no matter.
    expect(await missing({ ...full, issues: 'write' }, [...events, 'push'])).toEqual([]);
    expect(await missing({ ...required, issues: 'read' }, events)).toEqual(['contents_write']);
    expect(await missing({ ...full, contents: 'read' }, events)).toEqual(['contents_write']);
    expect(await missing({ ...required, contents: 'write' }, events)).toEqual(['issues_read']);
    for (const [event, code] of [
      ['check_run', 'event_check_run'],
      ['issue_comment', 'event_issue_comment'],
      ['pull_request_review_comment', 'event_pull_request_review_comment'],
    ]) {
      expect(
        await missing(
          full,
          events.filter((e) => e !== event),
        ),
        event,
      ).toEqual([code]);
    }
    // All of it, in the order the Test lists it.
    expect(await missing(required, [])).toEqual([
      'contents_write',
      'issues_read',
      'event_check_run',
      'event_issue_comment',
      'event_pull_request_review_comment',
    ]);
  });

  it('maps a project to owner/repo only', async () => {
    const connectionId = (await post({})).json().id as string;
    const project = await h.project('gh/mapping');
    const map = (scmProjectRef: string) =>
      h.ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/projects/${project.id}`,
        headers: h.orgAdmin.headers,
        payload: { scmConnectionId: connectionId, scmProjectRef },
      });
    expect((await map('acme/api')).statusCode).toBe(200);
    for (const bad of ['424242', 'acme/api/x']) {
      const res = await map(bad);
      expect([res.statusCode, errorPaths(res.body)]).toEqual([422, ['body.scmProjectRef']]);
    }
  });

  it.each([
    'https://api.github.com',
    'https://api.octo.ghe.com',
    'https://apixocto.ghe.com',
    'https://ghe.corp/api/v3',
    'https://ghe.corp/x/api/v3',
  ])('webBaseSql agrees with githubWebBase for %s', async (baseUrl) => {
    const result = await h.ctx.db.execute(
      sql`SELECT ${webBaseSql('c')} AS web FROM (SELECT 'github'::text AS provider, ${baseUrl}::text AS base_url) c`,
    );
    expect(result.rows[0]?.web).toBe(githubWebBase(baseUrl));
  });

  it.each([
    {
      provider: 'gitlab',
      baseUrl: 'https://gitlab.example.com',
      expected: 'https://gitlab.example.com',
    },
    { provider: 'github', baseUrl: 'https://api.github.com', expected: 'https://github.com' },
    {
      provider: 'azure',
      baseUrl: 'https://dev.azure.com/acme',
      expected: 'https://dev.azure.com/acme',
    },
    { provider: 'bitbucket', baseUrl: 'https://x', expected: null },
  ])(
    'webBaseSql for provider $provider gives $expected',
    async ({ provider, baseUrl, expected }) => {
      const result = await h.ctx.db.execute(
        sql`SELECT ${webBaseSql('c')} AS web FROM (SELECT ${provider}::text AS provider, ${baseUrl}::text AS base_url) c`,
      );
      expect(result.rows[0]?.web ?? null).toBe(expected);
    },
  );
});

describe('GitLab connections: the webhook secret (6I-4)', () => {
  let h: IngestHarness;
  let fake: FakeGitLab;
  const post = (payload: Record<string, unknown> = {}) =>
    h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'gitlab',
        baseUrl: fake.url,
        token: fake.token,
        ...payload,
      },
    });
  const patch = (id: string, payload: Record<string, unknown>) => patchConnection(h, id, payload);
  const list = async () =>
    (
      await h.ctx.app.inject({
        method: 'GET',
        url: `/api/v0/scm-connections?organizationId=${h.organizationId}`,
        headers: h.orgAdmin.headers,
      })
    ).json().items as { id: string; github: unknown; gitlab: Record<string, unknown> | null }[];
  const rowOf = async (id: string) =>
    (await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, id)))[0]!;
  const errorPaths = (body: string) =>
    (JSON.parse(body) as { errors?: { path: string }[] }).errors?.map((e) => e.path).sort();
  const serverKey = () => encryptionKey(h.ctx.config.secretKey);
  const NEW_SECRET = ['glhook-test-', 'rotated-fedcba9876'].join('');
  /** The webhook URL of a connection: the public address, then the route. */
  const urlOf = (id: string) => `${PUBLIC_URL}/api/v0/gitlab/webhooks/${id}`;

  beforeAll(async () => {
    fake = await createFakeGitLab();
    h = await createIngestHarness({ config: scmTestConfig(fake) });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  // An organisation has at most ten connections: each case starts with none.
  afterEach(async () => {
    await h.ctx.db.delete(scmConnections);
  });

  it('stores the secret in its own envelope, shows neither it nor the token, and gives the URL to paste', async () => {
    const created = await post({ webhookSecret: GITLAB_WEBHOOK_SECRET });
    expect(created.statusCode, created.body).toBe(201);
    const id = created.json().id as string;
    expect(created.json().github).toBeNull();
    expect(created.json().gitlab).toEqual({
      webhookSecretSet: true,
      webhookSecretReadable: true,
      webhookUrl: urlOf(id),
      ciSetupAllowed: false,
    });
    const row = await rowOf(id);
    expect(decryptWebhookSecret(serverKey(), row.webhookSecretEnc)).toBe(GITLAB_WEBHOOK_SECRET);
    // The token is the token's, the secret the secret's: neither envelope opens as the other.
    expect(decryptSecret(serverKey(), row.tokenEnc, SCM_TOKEN_AAD)).toBe(fake.token);
    expect(row.webhookSecretEnc).not.toEqual(row.tokenEnc);
    expect(decryptSecret(serverKey(), row.tokenEnc, WEBHOOK_SECRET_AAD)).toBeNull();
    expect(row.appId).toBeNull();
    expect((await list()).find((c) => c.id === id)).toMatchObject({
      github: null,
      gitlab: { webhookSecretSet: true, webhookSecretReadable: true, webhookUrl: urlOf(id) },
    });
    for (const body of [
      created.body,
      JSON.stringify(await list()),
      JSON.stringify(row.webhookSecretEnc),
      h.ctx.logs.join('\n'),
    ]) {
      expect(body).not.toContain(GITLAB_WEBHOOK_SECRET);
      expect(body).not.toContain(fake.token);
    }
  });

  it('rotates and removes the secret, each on its own, leaving the token alone', async () => {
    const id = (await post({ webhookSecret: GITLAB_WEBHOOK_SECRET })).json().id as string;
    const before = await rowOf(id);
    const rotated = await patch(id, { webhookSecret: NEW_SECRET });
    expect(rotated.statusCode, rotated.body).toBe(200);
    expect(rotated.json().gitlab).toEqual({
      webhookSecretSet: true,
      webhookSecretReadable: true,
      webhookUrl: urlOf(id),
      ciSetupAllowed: false,
    });
    expect(decryptWebhookSecret(serverKey(), (await rowOf(id)).webhookSecretEnc)).toBe(NEW_SECRET);
    expect((await rowOf(id)).tokenEnc).toEqual(before.tokenEnc);
    expect(rotated.body).not.toContain(NEW_SECRET);
    // A new token leaves the secret as it is.
    expect((await patch(id, { token: 'glpat-another-token' })).statusCode).toBe(200);
    expect(decryptWebhookSecret(serverKey(), (await rowOf(id)).webhookSecretEnc)).toBe(NEW_SECRET);
    // null removes it: no secret, no URL to paste.
    const removed = await patch(id, { webhookSecret: null });
    expect(removed.statusCode, removed.body).toBe(200);
    expect(removed.json().gitlab).toEqual({
      webhookSecretSet: false,
      webhookSecretReadable: false,
      webhookUrl: null,
      ciSetupAllowed: false,
    });
    expect((await rowOf(id)).webhookSecretEnc).toBeNull();
    // Removing what is not there is not an error.
    expect((await patch(id, { webhookSecret: null })).statusCode).toBe(200);
    // And one can be set on a connection made without.
    const set = await patch(id, { webhookSecret: GITLAB_WEBHOOK_SECRET });
    expect(set.json().gitlab).toMatchObject({ webhookSecretSet: true, webhookUrl: urlOf(id) });
  });

  it.each([
    ['short', 'short'],
    ['15 characters', 'x'.repeat(15)],
    ['257 characters', 'x'.repeat(257)],
    ['a space', 'secret with a space inside'],
    ['a tab', 'secret\twith-a-tab-inside'],
    ['a letter beyond ASCII', 'sëcret-with-umlaut-123'],
    ['nothing', ''],
  ])('refuses a secret of %s, on creation and on change, and stores nothing', async (_, secret) => {
    const created = await post({ webhookSecret: secret });
    expect([created.statusCode, errorPaths(created.body)]).toEqual([422, ['body.webhookSecret']]);
    const id = (await post({ webhookSecret: GITLAB_WEBHOOK_SECRET })).json().id as string;
    const before = await rowOf(id);
    const changed = await patch(id, { webhookSecret: secret });
    expect([changed.statusCode, errorPaths(changed.body)]).toEqual([422, ['body.webhookSecret']]);
    expect(await rowOf(id)).toEqual(before);
    expect(changed.body).not.toContain(GITLAB_WEBHOOK_SECRET);
  });

  it('still refuses the GitHub App’s own fields on a GitLab connection', async () => {
    const withAppId = await post({ appId: '1', privateKey: fake.token });
    expect([withAppId.statusCode, errorPaths(withAppId.body)]).toEqual([
      422,
      ['body.appId', 'body.privateKey'],
    ]);
    const id = (await post()).json().id as string;
    const changed = await patch(id, { appId: '1', privateKey: fake.token });
    expect([changed.statusCode, errorPaths(changed.body)]).toEqual([
      422,
      ['body.appId', 'body.privateKey'],
    ]);
  });

  it('says that a stored secret no longer decrypts, and takes a new one', async () => {
    const id = (await post({ webhookSecret: GITLAB_WEBHOOK_SECRET })).json().id as string;
    await h.ctx.db
      .update(scmConnections)
      .set({
        webhookSecretEnc: encryptSecret(encryptionKey('z'.repeat(32)), 'x', WEBHOOK_SECRET_AAD),
      })
      .where(eq(scmConnections.id, id));
    // Set, and not readable: the URL is shown, as the GitHub App's is, and the page says so.
    expect((await list()).find((c) => c.id === id)?.gitlab).toEqual({
      webhookSecretSet: true,
      webhookSecretReadable: false,
      webhookUrl: urlOf(id),
      ciSetupAllowed: false,
    });
    expect((await patch(id, { webhookSecret: NEW_SECRET })).json().gitlab).toMatchObject({
      webhookSecretSet: true,
      webhookSecretReadable: true,
    });
  });

  it('needs the secret again, or null to drop it, in the same request, to change the address', async () => {
    const id = (await post({ webhookSecret: GITLAB_WEBHOOK_SECRET })).json().id as string;
    const moved = await patch(id, { baseUrl: 'https://gitlab.example.com' });
    expect([moved.statusCode, errorPaths(moved.body)]).toEqual([
      422,
      ['body.token', 'body.webhookSecret'],
    ]);
    const withToken = await patch(id, {
      baseUrl: 'https://gitlab.example.com',
      token: 'glpat-new',
    });
    expect([withToken.statusCode, errorPaths(withToken.body)]).toEqual([
      422,
      ['body.webhookSecret'],
    ]);
    expect((await rowOf(id)).baseUrl).toBe(fake.url);
    // The secret given again moves it, with the secret as given.
    const again = await patch(id, {
      baseUrl: 'https://gitlab.example.com',
      token: 'glpat-new',
      webhookSecret: NEW_SECRET,
    });
    expect(again.statusCode, again.body).toBe(200);
    expect(decryptWebhookSecret(serverKey(), (await rowOf(id)).webhookSecretEnc)).toBe(NEW_SECRET);
    // null drops it, and moves it back.
    const dropped = await patch(id, { baseUrl: fake.url, token: fake.token, webhookSecret: null });
    expect(dropped.statusCode, dropped.body).toBe(200);
    expect(dropped.json()).toMatchObject({
      baseUrl: fake.url,
      gitlab: { webhookSecretSet: false, webhookUrl: null },
    });
    expect((await rowOf(id)).webhookSecretEnc).toBeNull();
    // The same address, however spelled, needs nothing again; neither does a connection with no secret.
    const keeping = (await post({ webhookSecret: GITLAB_WEBHOOK_SECRET })).json().id as string;
    expect((await patch(keeping, { baseUrl: `${fake.url}/` })).statusCode).toBe(200);
    expect((await rowOf(keeping)).webhookSecretEnc).not.toBeNull();
    const bare = (await post()).json().id as string;
    expect(
      (await patch(bare, { baseUrl: 'https://gitlab.example.com', token: 'glpat-new' })).statusCode,
    ).toBe(200);
  });

  /**
   * Holds the connection's row lock while `first` and then `second` send their PATCH, so both
   * wait, in that order, on the write; then releases it.
   */
  const race = (id: string, first: Record<string, unknown>, second: Record<string, unknown>) =>
    raceConnectionPatches(h, id, first, second);
  const ELSEWHERE = 'https://gitlab.qualor.invalid';

  it('never moves the connection past a webhook secret set meanwhile', async () => {
    const id = (await post()).json().id as string;
    // Read without a secret, so the move needs none; a concurrent PATCH sets one first.
    const [setSecret, move] = await race(
      id,
      { webhookSecret: GITLAB_WEBHOOK_SECRET },
      { baseUrl: ELSEWHERE, token: 'glpat-elsewhere' },
    );
    expect(setSecret.statusCode, setSecret.body).toBe(200);
    expect(move.statusCode, move.body).toBe(503);
    expect(move.json()).toMatchObject({ code: 'CONCURRENCY_CONFLICT' });
    const row = await rowOf(id);
    expect(row.baseUrl).toBe(fake.url); // the secret was never carried to another address
    expect(row.webhookSecretEnc).not.toBeNull();
  });

  it('tells a PATCH of the secret alone that lost a race to a move that the address changed', async () => {
    const id = (await post()).json().id as string;
    const [move, setSecret] = await race(
      id,
      { baseUrl: ELSEWHERE, token: 'glpat-elsewhere' },
      { webhookSecret: GITLAB_WEBHOOK_SECRET },
    );
    expect(move.statusCode, move.body).toBe(200);
    expect(setSecret.statusCode, setSecret.body).toBe(503);
    expect(setSecret.json()).toMatchObject({ code: 'CONCURRENCY_CONFLICT' });
    expect(setSecret.body).toContain('address');
    // Not the 422 that asks the token again: it did not ask to move.
    expect(setSecret.body).not.toContain('token');
    const row = await rowOf(id);
    expect([row.baseUrl, row.webhookSecretEnc]).toEqual([ELSEWHERE, null]);
  });
});

describe('GitLab connections: the CI-setup setting (onboarding)', () => {
  const NOW = new Date('2027-01-01T00:00:00Z');
  let h: IngestHarness;
  let fake: FakeGitLab;
  const post = (payload: Record<string, unknown> = {}) =>
    h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: {
        organizationId: h.organizationId,
        provider: 'gitlab',
        baseUrl: fake.url,
        token: fake.token,
        ...payload,
      },
    });
  const errorPaths = (body: string) =>
    (JSON.parse(body) as { errors?: { path: string }[] }).errors?.map((e) => e.path);

  beforeAll(async () => {
    fake = await createFakeGitLab();
    h = await createIngestHarness({
      config: scmTestConfig(fake),
      pluginsFor: rbacPlugins({ now: () => NOW }),
    });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  afterEach(async () => {
    await h.ctx.db.delete(scmConnections);
  });

  it('is off by default, can be given at creation, and is changed on its own with an audit entry', async () => {
    const plain = await post();
    expect(plain.json().gitlab.ciSetupAllowed).toBe(false);
    const on = await post({ ciSetupAllowed: true });
    expect(on.statusCode, on.body).toBe(201);
    expect(on.json().gitlab.ciSetupAllowed).toBe(true);
    const id = plain.json().id as string;
    const patched = await patchConnection(h, id, { ciSetupAllowed: true });
    expect(patched.statusCode, patched.body).toBe(200);
    expect(patched.json().gitlab.ciSetupAllowed).toBe(true);
    const [row] = await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, id));
    expect(row!.ciSetupAllowed).toBe(true);
    const events = await h.ctx.db
      .select()
      .from(auditEvents)
      .where(and(eq(auditEvents.action, 'scm_connection.updated'), eq(auditEvents.targetId, id)));
    expect(events.map((e) => e.details)).toEqual([{ changed: ['ciSetupAllowed'] }]);
    expect((await patchConnection(h, id, { ciSetupAllowed: false })).json().gitlab).toMatchObject({
      ciSetupAllowed: false,
    });
    expect((await patchConnection(h, id, { ciSetupAllowed: 'yes' })).statusCode).toBe(422);
  });

  it('is not a field of a GitHub connection', async () => {
    const body = {
      organizationId: h.organizationId,
      provider: 'github',
      baseUrl: 'https://github.com',
      appId: '123',
      privateKey: 'x',
      ciSetupAllowed: true,
    };
    const created = await h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: body,
    });
    expect(created.statusCode).toBe(422);
    expect(errorPaths(created.body)).toContain('body.ciSetupAllowed');
    const [github] = await h.ctx.db
      .insert(scmConnections)
      .values({
        organizationId: h.organizationId,
        provider: 'github',
        baseUrl: 'https://github.com',
        appId: '123',
        tokenEnc: { v: 1, iv: 'a', ct: 'b', tag: 'c' },
      })
      .returning();
    const patched = await patchConnection(h, github!.id, { ciSetupAllowed: true });
    expect(patched.statusCode, patched.body).toBe(422);
    expect(errorPaths(patched.body)).toEqual(['body.ciSetupAllowed']);
  });
});

describe('SCM connections: fix merge requests (0.16 fix MRs B2)', () => {
  let h: IngestHarness;
  let fake: FakeGitHub;
  const post = (payload: Record<string, unknown>) =>
    h.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: h.orgAdmin.headers,
      payload: { organizationId: h.organizationId, ...payload },
    });
  const gitlab = (extra: Record<string, unknown> = {}) =>
    post({ provider: 'gitlab', baseUrl: 'https://gitlab.example.com', token: 'glpat-x', ...extra });
  const github = (extra: Record<string, unknown> = {}) =>
    post({
      provider: 'github',
      baseUrl: fake.url,
      appId: String(fake.appId),
      privateKey: fake.privateKeyPem,
      ...extra,
    });
  const updates = async (id: string) =>
    (
      await h.ctx.db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, 'scm_connection.updated'), eq(auditEvents.targetId, id)))
    ).map((e) => e.details);

  beforeAll(async () => {
    fake = await createFakeGitHub();
    h = await createIngestHarness({
      config: githubTestConfig(fake),
      pluginsFor: rbacPlugins({ now: () => new Date('2027-01-01T00:00:00Z') }),
    });
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
  });
  afterEach(async () => {
    await h.ctx.db.delete(scmConnections);
  });

  it('is off on a GitLab and a GitHub connection created without the field, on when asked', async () => {
    expect((await gitlab()).json().fixMrsAllowed).toBe(false);
    expect((await github()).json().fixMrsAllowed).toBe(false);
    const on = await gitlab({ fixMrsAllowed: true });
    expect(on.statusCode, on.body).toBe(201);
    expect(on.json().fixMrsAllowed).toBe(true);
    const onGithub = await github({ fixMrsAllowed: true });
    expect(onGithub.statusCode, onGithub.body).toBe(201);
    expect(onGithub.json().fixMrsAllowed).toBe(true);
  });

  it('is changed on a GitHub connection on its own, with an audit entry naming it', async () => {
    const id = (await github()).json().id as string;
    const patched = await patchConnection(h, id, { fixMrsAllowed: true });
    expect(patched.statusCode, patched.body).toBe(200);
    expect(patched.json().fixMrsAllowed).toBe(true);
    const [row] = await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, id));
    expect(row!.fixMrsAllowed).toBe(true);
    expect(await updates(id)).toEqual([{ changed: ['fixMrsAllowed'] }]);
    expect((await patchConnection(h, id, { fixMrsAllowed: 'yes' })).statusCode).toBe(422);
  });

  it('is for organisation admins only: a project admin gets 403', async () => {
    const id = (await gitlab()).json().id as string;
    const user = await createUser(h.ctx, { username: 'scm-fix-padmin' });
    await addMember(h.ctx, h.organizationId, user.id, 'member');
    const project = await h.project('SCM-FIX');
    await h.ctx.db
      .insert(projectMemberships)
      .values({ projectId: project.id, userId: user.id, role: 'project_admin' });
    const session = await login(h.ctx, user.username, user.password);
    const res = await h.ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/scm-connections/${id}`,
      headers: session.headers,
      payload: { fixMrsAllowed: true },
    });
    expect(res.statusCode).toBe(403);
    const [row] = await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, id));
    expect(row!.fixMrsAllowed).toBe(false);
  });
});

describe('Azure DevOps connections (Azure DevOps design §7.1, §7.2)', () => {
  const NOW = new Date('2027-01-01T00:00:00Z');
  const { tenantId, clientId, secret: SECRET, certificatePem: CERTIFICATE } = AZURE_TEST_PRINCIPAL;
  const OTHER_ID = 'a1b2c3d4-0000-4000-8000-00000000beef';
  const SERVER_TAKES_PAT = 'Azure DevOps Server takes a personal access token';
  const REPOSITORY_ID_TEXT = 'Use the Azure DevOps repository id (pick it from the list)';
  /** A line of the certificate's private key: no answer, row, audit entry or log line holds it. */
  const KEY_LINE = TEST_IDP.keyPem.split('\n')[1]!;
  const certificateOf = (pem: string) => {
    const certificate = new X509Certificate(pem);
    return {
      thumbprint: createHash('sha1').update(certificate.raw).digest('hex').toUpperCase(),
      notAfter: new Date(certificate.validTo).toISOString(),
    };
  };
  const SP_SECRET = { azureAuth: 'service_principal_secret', token: SECRET, tenantId, clientId };
  const SP_CERTIFICATE = {
    azureAuth: 'service_principal_certificate',
    certificate: CERTIFICATE,
    tenantId,
    clientId,
  };

  interface AzureConnection {
    id: string;
    baseUrl: string;
    azure: Record<string, unknown> | null;
  }

  let h: IngestHarness;
  let services: FakeAzureDevOps;
  let server: FakeAzureDevOps;
  let untrust: () => void;
  /** The Services organisation as stored: `https://dev.azure.com/probe-org` (ruling 5). */
  let SERVICES: string;
  let api: FakeAzureRepository;
  /** Every answer of the API in this block, for the check that none holds a credential. */
  const answers: string[] = [];

  const inject = async (method: 'POST' | 'PATCH' | 'GET', url: string, payload?: object) => {
    const res = await h.ctx.app.inject({
      method,
      url: `/api/v0${url}`,
      headers: h.orgAdmin.headers,
      ...(payload === undefined ? {} : { payload }),
    });
    answers.push(res.body);
    return res;
  };
  const post = (payload: Record<string, unknown>) =>
    inject('POST', '/scm-connections', {
      organizationId: h.organizationId,
      provider: 'azure',
      baseUrl: SERVICES,
      ...payload,
    });
  const created = async (payload: Record<string, unknown>): Promise<AzureConnection> => {
    const res = await post(payload);
    expect(res.statusCode, res.body).toBe(201);
    return res.json() as AzureConnection;
  };
  const patch = (id: string, payload: Record<string, unknown>) =>
    inject('PATCH', `/scm-connections/${id}`, payload);
  const test = (id: string, projectRef?: string) =>
    inject('POST', `/scm-connections/${id}/test`, projectRef === undefined ? {} : { projectRef });
  const rowOf = async (id: string) =>
    (await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, id)))[0]!;
  const storedCredential = async (id: string) =>
    decryptSecret(encryptionKey(h.ctx.config.secretKey), (await rowOf(id)).tokenEnc, SCM_TOKEN_AAD);
  const errorPaths = (body: string) =>
    (JSON.parse(body) as { errors?: { path: string }[] }).errors?.map((e) => e.path).sort();
  const auditOf = async (action: string, id?: string) =>
    (
      await h.ctx.db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, action), id ? eq(auditEvents.targetId, id) : undefined))
        .orderBy(asc(auditEvents.seq))
    ).map((e) => e.details);
  /** No credential in `texts`, nor in any answer, audit entry or log line so far. */
  const expectNoCredential = async (...texts: string[]) => {
    const audit = await h.ctx.db.select().from(auditEvents);
    const all = [...texts, ...answers, JSON.stringify(audit), h.ctx.logs.join('\n')];
    // A PEM block's header line (the fixed problem texts name `BEGIN PRIVATE KEY`, without dashes).
    const secrets = [services.pat, server.pat, SECRET, KEY_LINE, 'PRIVATE KEY-----', 'wrong-'];
    for (const secret of [...secrets, 'rotated-secret', 'secret-of-other-tenant']) {
      for (const text of all) expect(text).not.toContain(secret);
    }
  };

  beforeAll(async () => {
    untrust = trustTestCa();
    services = await createFakeAzureDevOps({
      deployment: 'services',
      principal: AZURE_TEST_PRINCIPAL,
      repositories: [
        { name: 'api', projectName: 'Payments' },
        { name: 'web', projectName: 'Payments' },
        { name: 'docs', projectName: 'Platform' },
      ],
    });
    api = services.repositories[0]!;
    server = await createFakeAzureDevOps({
      deployment: 'server',
      repositories: [{ name: 'probe', projectName: 'probe-org' }],
    });
    SERVICES = servicesUrlOf(services);
    h = await createIngestHarness({
      config: azureServerConfig(services, server),
      pluginsFor: rbacPlugins({ now: () => NOW }),
    });
  });
  afterAll(async () => {
    await h.close();
    await services.close();
    await server.close();
    untrust();
  });
  afterEach(async () => {
    await h.ctx.db.delete(scmConnections);
    services.identityAdded = true;
    services.clearRequests();
    server.clearRequests();
  });

  it('creates a connection with each authentication kind; the credential is stored encrypted and never shown', async () => {
    const pat = await created({ azureAuth: 'pat', token: services.pat });
    expect(pat).toEqual({
      id: expect.any(String),
      organizationId: h.organizationId,
      provider: 'azure',
      baseUrl: SERVICES,
      createdAt: expect.any(String),
      github: null,
      gitlab: null,
      azure: {
        deployment: 'services',
        auth: 'pat',
        tenantId: null,
        clientId: null,
        credentialReadable: true,
        certificate: null,
        webhookSecretSet: false,
        webhookUrl: null,
      },
      ciSetup: { available: false, reason: 'not_allowed', missing: [] },
      fixMrsAllowed: false,
      problem: null,
    });
    // The ids arrive in any case and are kept lower-cased.
    const secret = await created({
      ...SP_SECRET,
      tenantId: tenantId.toUpperCase(),
      clientId: clientId.toUpperCase(),
    });
    expect(secret.azure).toEqual({
      deployment: 'services',
      auth: 'service_principal_secret',
      tenantId,
      clientId,
      credentialReadable: true,
      certificate: null,
      webhookSecretSet: false,
      webhookUrl: null,
    });
    const certificate = await created(SP_CERTIFICATE);
    expect(certificate.azure).toEqual({
      deployment: 'services',
      auth: 'service_principal_certificate',
      tenantId,
      clientId,
      credentialReadable: true,
      certificate: certificateOf(TEST_IDP.certPem),
      webhookSecretSet: false,
      webhookUrl: null,
    });
    const onServer = await created({ baseUrl: server.url, azureAuth: 'pat', token: server.pat });
    expect([onServer.baseUrl, onServer.azure]).toEqual([
      server.url,
      expect.objectContaining({ deployment: 'server', auth: 'pat', tenantId: null }),
    ]);
    // One column holds the PAT, the client secret or the certificate with its key, encrypted.
    for (const [connection, plain] of [
      [pat, services.pat],
      [secret, SECRET],
      [certificate, CERTIFICATE],
      [onServer, server.pat],
    ] as const) {
      expect(await storedCredential(connection.id)).toBe(plain);
    }
    expect(await rowOf(secret.id)).toMatchObject({
      azureAuth: 'service_principal_secret',
      azureTenantId: tenantId,
      azureClientId: clientId,
      appId: null,
      webhookSecretEnc: null,
    });
    expect(await rowOf(pat.id)).toMatchObject({ azureTenantId: null, azureClientId: null });
    await inject('GET', `/scm-connections?organizationId=${h.organizationId}`);
    expect(await auditOf('scm_connection.created')).toContainEqual({
      provider: 'azure',
      baseUrl: SERVICES,
    });
    // Creating a connection asks Azure DevOps and Entra nothing.
    expect([services.requests, services.tokenRequests, server.requests]).toEqual([[], [], []]);
    const rows = await h.ctx.db.select().from(scmConnections);
    await expectNoCredential(JSON.stringify(rows));
  });

  it('derives the deployment from the host alone: a service principal only on Services', async () => {
    const legacy = await created({
      baseUrl: 'https://Acme.VisualStudio.com/',
      azureAuth: 'pat',
      token: 'x',
    });
    expect([legacy.baseUrl, legacy.azure?.deployment]).toEqual([
      'https://acme.visualstudio.com',
      'services',
    ]);
    // A host that only looks like Services is a Server, which takes a PAT only.
    for (const baseUrl of [
      server.url,
      'https://dev.azure.com.example.net/acme',
      'https://ado.example.com/tfs/DefaultCollection',
    ]) {
      for (const kind of [SP_SECRET, SP_CERTIFICATE]) {
        const res = await post({ ...kind, baseUrl });
        expect([res.statusCode, res.json().errors], baseUrl).toEqual([
          422,
          [{ path: 'body.azureAuth', message: SERVER_TAKES_PAT }],
        ]);
      }
    }
    const lookalike = await created({
      baseUrl: 'https://dev.azure.com.example.net/acme',
      azureAuth: 'pat',
      token: 'x',
    });
    expect(lookalike.azure?.deployment).toBe('server');
    await expectNoCredential();
  });

  it.each([
    ['a PAT without it', { azureAuth: 'pat' }, ['body.token']],
    [
      'a PAT with ids',
      { azureAuth: 'pat', token: 'x', tenantId, clientId },
      ['body.clientId', 'body.tenantId'],
    ],
    [
      'a PAT with a certificate',
      { azureAuth: 'pat', token: 'x', certificate: CERTIFICATE },
      ['body.certificate'],
    ],
    ['a client secret without it', { ...SP_SECRET, token: undefined }, ['body.token']],
    [
      'a client secret without the ids',
      { azureAuth: 'service_principal_secret', token: 'x' },
      ['body.clientId', 'body.tenantId'],
    ],
    [
      'a client secret with a certificate',
      { ...SP_SECRET, certificate: CERTIFICATE },
      ['body.certificate'],
    ],
    [
      'a certificate without it',
      { ...SP_CERTIFICATE, certificate: undefined },
      ['body.certificate'],
    ],
    ['a certificate with a token', { ...SP_CERTIFICATE, token: 'x' }, ['body.token']],
    [
      'a certificate without the tenant',
      { ...SP_CERTIFICATE, tenantId: undefined },
      ['body.tenantId'],
    ],
    ['an id that is no GUID', { ...SP_SECRET, clientId: 'qualor-app' }, ['body.clientId']],
    ['no kind', { token: 'x' }, ['body.azureAuth']],
    ['an unknown kind', { azureAuth: 'oauth', token: 'x' }, ['body.azureAuth']],
    [
      'a PAT that is not header-safe',
      { azureAuth: 'pat', token: 'pat with space' },
      ['body.token'],
    ],
    [
      "GitLab's and GitHub's fields",
      {
        azureAuth: 'pat',
        token: 'x',
        appId: '1',
        privateKey: 'x',
        webhookSecret: 'w'.repeat(20),
        ciSetupAllowed: false,
        fixMrsAllowed: false,
      },
      [
        'body.appId',
        'body.ciSetupAllowed',
        'body.fixMrsAllowed',
        'body.privateKey',
        'body.webhookSecret',
      ],
    ],
    [
      'dev.azure.com alone',
      { azureAuth: 'pat', token: 'x', baseUrl: 'https://dev.azure.com' },
      ['body.baseUrl'],
    ],
    [
      'an organisation with a path',
      { azureAuth: 'pat', token: 'x', baseUrl: 'https://dev.azure.com/acme/project' },
      ['body.baseUrl'],
    ],
    [
      'an organisation with a port',
      { azureAuth: 'pat', token: 'x', baseUrl: 'https://dev.azure.com:8443/acme' },
      ['body.baseUrl'],
    ],
    [
      'a Server without its collection',
      { azureAuth: 'pat', token: 'x', baseUrl: 'https://ado.example.com' },
      ['body.baseUrl'],
    ],
  ])('refuses %s', async (_, payload, paths) => {
    const res = await post(payload);
    expect([res.statusCode, errorPaths(res.body)], res.body).toEqual([422, paths]);
    expect(res.body).not.toContain('pat with space');
    await expectNoCredential();
  });

  it('says what is wrong with the address and the certificate, in fixed texts', async () => {
    const problems = async (payload: Record<string, unknown>) =>
      ((await post(payload)).json() as { errors: unknown[] }).errors;
    expect(
      await problems({ azureAuth: 'pat', token: 'x', baseUrl: 'https://dev.azure.com' }),
    ).toEqual([{ path: 'body.baseUrl', message: 'Use https://dev.azure.com/<organization>' }]);
    expect(
      await problems({ azureAuth: 'pat', token: 'x', baseUrl: new URL(server.url).origin }),
    ).toEqual([
      {
        path: 'body.baseUrl',
        message: 'Use the collection URL, e.g. https://ado.example.com/DefaultCollection',
      },
    ]);
    for (const [certificate, problem] of [
      ['not a certificate', 'no_certificate'],
      [TEST_IDP.certPem, 'no_key'],
      [`${TEST_SP.certPem}${TEST_IDP.keyPem}`, 'mismatch'],
    ] as const) {
      expect(await problems({ ...SP_CERTIFICATE, certificate }), problem).toEqual([
        { path: 'body.certificate', message: AZURE_CERTIFICATE_PROBLEM_TEXT[problem] },
      ]);
    }
    await expectNoCredential();
  });

  it('needs the credential of the resulting kind again for a new address, kind or ids', async () => {
    const { id } = await created(SP_SECRET);
    const before = await rowOf(id);
    const refused = async (payload: Record<string, unknown>, paths: string[]) => {
      const res = await patch(id, payload);
      expect([res.statusCode, errorPaths(res.body)], JSON.stringify(payload)).toEqual([422, paths]);
      return res.json() as { errors: { path: string; message: string }[] };
    };
    // A new address, tenant or client would send the stored client secret elsewhere.
    expect(
      (await refused({ baseUrl: 'https://dev.azure.com/other-org' }, ['body.token'])).errors,
    ).toEqual([
      {
        path: 'body.token',
        message: 'Changing the address needs the client secret again, in the same request',
      },
    ]);
    await refused({ tenantId: OTHER_ID }, ['body.token']);
    await refused({ clientId: OTHER_ID }, ['body.token']);
    // Another kind needs its own credential and ids, in the same request.
    expect(
      (
        await refused({ azureAuth: 'service_principal_certificate' }, [
          'body.certificate',
          'body.clientId',
          'body.tenantId',
        ])
      ).errors,
    ).toContainEqual({
      path: 'body.certificate',
      message: 'Changing the authentication kind needs the certificate, in the same request',
    });
    await refused({ azureAuth: 'service_principal_certificate', certificate: CERTIFICATE }, [
      'body.clientId',
      'body.tenantId',
    ]);
    await refused({ ...SP_CERTIFICATE, token: SECRET }, ['body.token']);
    await refused({ azureAuth: 'pat' }, ['body.token']);
    await refused({ azureAuth: 'pat', token: services.pat, tenantId }, ['body.tenantId']);
    await refused({ certificate: CERTIFICATE }, ['body.certificate']);
    await refused({ ...SP_CERTIFICATE, certificate: 'not a certificate' }, ['body.certificate']);
    expect(await rowOf(id)).toEqual(before);
    // The same address however spelled, the same kind and ids in any case: nothing again.
    const same = await patch(id, {
      baseUrl: `${SERVICES.replace('https://dev.azure.com', 'https://DEV.Azure.com')}/`,
      azureAuth: 'service_principal_secret',
      tenantId: tenantId.toUpperCase(),
      clientId,
    });
    expect(same.statusCode, same.body).toBe(200);
    expect(await rowOf(id)).toEqual(before);
    // The secret alone, and a new address with it.
    expect((await patch(id, { token: 'rotated-secret' })).statusCode).toBe(200);
    const moved = await patch(id, { baseUrl: 'https://dev.azure.com/other-org', token: SECRET });
    expect(moved.json()).toMatchObject({
      baseUrl: 'https://dev.azure.com/other-org',
      azure: { deployment: 'services', auth: 'service_principal_secret' },
    });
    // A certificate instead of the secret, with the ids; then a new certificate alone.
    const toCertificate = await patch(id, { ...SP_CERTIFICATE, tenantId: tenantId.toUpperCase() });
    expect(toCertificate.json().azure).toEqual({
      deployment: 'services',
      auth: 'service_principal_certificate',
      tenantId,
      clientId,
      credentialReadable: true,
      certificate: certificateOf(TEST_IDP.certPem),
      webhookSecretSet: false,
      webhookUrl: null,
    });
    expect(await storedCredential(id)).toBe(CERTIFICATE);
    expect((await patch(id, { certificate: CERTIFICATE })).statusCode).toBe(200);
    // A PAT instead: the ids go with the service principal.
    const toPat = await patch(id, { azureAuth: 'pat', token: services.pat });
    expect(toPat.json().azure).toEqual({
      deployment: 'services',
      auth: 'pat',
      tenantId: null,
      clientId: null,
      credentialReadable: true,
      certificate: null,
      webhookSecretSet: false,
      webhookUrl: null,
    });
    expect(await rowOf(id)).toMatchObject({
      azureAuth: 'pat',
      azureTenantId: null,
      azureClientId: null,
    });
    expect(await storedCredential(id)).toBe(services.pat);
    // Back to a service principal: its ids again.
    await refused({ azureAuth: 'service_principal_secret', token: SECRET, tenantId }, [
      'body.clientId',
    ]);
    // Names only, in the catalogue's order.
    expect(await auditOf('scm_connection.updated', id)).toEqual([
      { changed: ['token'] },
      { changed: ['baseUrl', 'token'] },
      { changed: ['azureAuth', 'certificate'] },
      { changed: ['certificate'] },
      { changed: ['token', 'azureAuth', 'tenantId', 'clientId'] },
    ]);
    expect([services.requests, services.tokenRequests]).toEqual([[], []]);
    await expectNoCredential();
  });

  it('moves a PAT to a certificate and a certificate to a client secret, each with its credential and ids', async () => {
    const { id } = await created({ azureAuth: 'pat', token: services.pat });
    const refused = async (payload: Record<string, unknown>, paths: string[]) => {
      const res = await patch(id, payload);
      expect([res.statusCode, errorPaths(res.body)], JSON.stringify(payload)).toEqual([422, paths]);
    };
    const toCertificate = 'service_principal_certificate';
    await refused({ azureAuth: toCertificate }, [
      'body.certificate',
      'body.clientId',
      'body.tenantId',
    ]);
    await refused({ azureAuth: toCertificate, certificate: CERTIFICATE }, [
      'body.clientId',
      'body.tenantId',
    ]);
    await refused({ azureAuth: toCertificate, token: services.pat, tenantId, clientId }, [
      'body.certificate',
      'body.token',
    ]);
    expect(await rowOf(id)).toMatchObject({ azureAuth: 'pat', azureTenantId: null });
    const certificate = await patch(id, SP_CERTIFICATE);
    expect(certificate.json().azure).toEqual({
      deployment: 'services',
      auth: 'service_principal_certificate',
      tenantId,
      clientId,
      credentialReadable: true,
      certificate: certificateOf(TEST_IDP.certPem),
      webhookSecretSet: false,
      webhookUrl: null,
    });
    expect(await storedCredential(id)).toBe(CERTIFICATE);
    expect((await test(id)).json()).toMatchObject({
      ok: true,
      user: { username: services.principalUser!.displayName },
    });
    const toSecret = 'service_principal_secret';
    await refused({ azureAuth: toSecret }, ['body.clientId', 'body.tenantId', 'body.token']);
    await refused({ azureAuth: toSecret, token: SECRET }, ['body.clientId', 'body.tenantId']);
    await refused({ ...SP_SECRET, certificate: CERTIFICATE }, ['body.certificate']);
    expect((await rowOf(id)).azureAuth).toBe(toCertificate);
    const secret = await patch(id, SP_SECRET);
    expect(secret.json().azure).toEqual({
      deployment: 'services',
      auth: 'service_principal_secret',
      tenantId,
      clientId,
      credentialReadable: true,
      certificate: null,
      webhookSecretSet: false,
      webhookUrl: null,
    });
    expect(await storedCredential(id)).toBe(SECRET);
    expect((await test(id)).json()).toMatchObject({ ok: true });
    expect(await auditOf('scm_connection.updated', id)).toEqual([
      { changed: ['azureAuth', 'tenantId', 'clientId', 'certificate'] },
      { changed: ['token', 'azureAuth'] },
    ]);
    await expectNoCredential();
  });

  it('shows a stored certificate that has expired, and tests it without asking Entra or Azure DevOps', async () => {
    // A key made here, never written anywhere; its certificate ran out on 2001-01-01.
    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const expiredCertificate = selfSignedRsaCertificate(privateKey, {
      notBefore: '000101000000Z',
      notAfter: '010101000000Z',
    });
    const expired = `${expiredCertificate}${privateKey.export({ type: 'pkcs8', format: 'pem' }).toString()}`;
    // The API takes no expired certificate, so this one expired after it was saved.
    const refused = await post({ ...SP_CERTIFICATE, certificate: expired });
    expect([refused.statusCode, refused.json().errors]).toEqual([
      422,
      [{ path: 'body.certificate', message: AZURE_CERTIFICATE_PROBLEM_TEXT.expired }],
    ]);
    const { id } = await created(SP_CERTIFICATE);
    await h.ctx.db
      .update(scmConnections)
      .set({
        tokenEnc: encryptSecret(encryptionKey(h.ctx.config.secretKey), expired, SCM_TOKEN_AAD),
      })
      .where(eq(scmConnections.id, id));
    const listed = await inject('GET', `/scm-connections?organizationId=${h.organizationId}`);
    expect((listed.json().items as AzureConnection[]).find((c) => c.id === id)?.azure).toEqual({
      deployment: 'services',
      auth: 'service_principal_certificate',
      tenantId,
      clientId,
      credentialReadable: true,
      certificate: { ...certificateOf(expiredCertificate), notAfter: '2001-01-01T00:00:00.000Z' },
      webhookSecretSet: false,
      webhookUrl: null,
    });
    services.clearRequests();
    expect((await test(id)).json()).toEqual({
      ok: false,
      user: null,
      project: null,
      problem: {
        code: 'token_endpoint',
        message: 'The stored certificate has expired; upload a new one',
      },
      missingAccess: null,
      hooks: null,
      visible: null,
    });
    expect([services.requests, services.tokenRequests]).toEqual([[], []]);
    // A new certificate alone replaces it.
    const renewed = await patch(id, { certificate: CERTIFICATE });
    expect(renewed.json().azure.certificate).toEqual(certificateOf(TEST_IDP.certPem));
    expect((await test(id)).json()).toMatchObject({ ok: true });
    await expectNoCredential();
  });

  it('keeps a service principal off a Server address, also when the address moves', async () => {
    const { id } = await created(SP_SECRET);
    const refused = await patch(id, { baseUrl: server.url, token: SECRET });
    expect([refused.statusCode, refused.json().errors]).toEqual([
      422,
      [{ path: 'body.azureAuth', message: SERVER_TAKES_PAT }],
    ]);
    expect((await rowOf(id)).baseUrl).toBe(SERVICES);
    const moved = await patch(id, { baseUrl: server.url, azureAuth: 'pat', token: server.pat });
    expect(moved.json()).toMatchObject({
      baseUrl: server.url,
      azure: { deployment: 'server', auth: 'pat', tenantId: null, clientId: null },
    });
    const toPrincipal = await patch(id, SP_SECRET);
    expect([toPrincipal.statusCode, toPrincipal.json().errors]).toEqual([
      422,
      [{ path: 'body.azureAuth', message: SERVER_TAKES_PAT }],
    ]);
    expect(await rowOf(id)).toMatchObject({ azureAuth: 'pat', baseUrl: server.url });
    await expectNoCredential();
  });

  it("takes none of GitLab's or GitHub's fields, and they take none of its own", async () => {
    const { id } = await created({ azureAuth: 'pat', token: 'x' });
    const own = await patch(id, {
      appId: '1',
      privateKey: 'x',
      webhookSecret: null,
      ciSetupAllowed: true,
      fixMrsAllowed: true,
    });
    expect([own.statusCode, errorPaths(own.body)]).toEqual([
      422,
      [
        'body.appId',
        'body.ciSetupAllowed',
        'body.fixMrsAllowed',
        'body.privateKey',
        'body.webhookSecret',
      ],
    ]);
    expect(own.json().errors[0].message).toBe('Not a field of an Azure DevOps connection');
    const tokenEnc = encryptSecret(encryptionKey(h.ctx.config.secretKey), 'x', SCM_TOKEN_AAD);
    const others = await h.ctx.db
      .insert(scmConnections)
      .values([
        {
          organizationId: h.organizationId,
          provider: 'gitlab',
          baseUrl: 'https://gitlab.example.com',
          tokenEnc,
        },
        {
          organizationId: h.organizationId,
          provider: 'github',
          baseUrl: 'https://api.github.com',
          appId: '1',
          tokenEnc,
        },
      ])
      .returning();
    for (const other of others) {
      const res = await patch(other.id, {
        azureAuth: 'pat',
        tenantId,
        clientId,
        certificate: CERTIFICATE,
      });
      expect([res.statusCode, errorPaths(res.body)], other.provider).toEqual([
        422,
        ['body.azureAuth', 'body.certificate', 'body.clientId', 'body.tenantId'],
      ]);
      const post = await inject('POST', '/scm-connections', {
        organizationId: h.organizationId,
        provider: other.provider,
        baseUrl: other.baseUrl,
        ...(other.provider === 'github' ? { appId: '1', privateKey: 'x' } : { token: 'x' }),
        azureAuth: 'pat',
      });
      expect(post.statusCode, other.provider).toBe(422);
    }
  });

  it('never pairs a credential with a kind, ids or address changed meanwhile, and says the connection changed', async () => {
    /** The answer of a PATCH that lost the race: whatever changed, the same neutral words. */
    const changedMeanwhile = {
      code: 'CONCURRENCY_CONFLICT',
      title: 'The connection changed while this request was handled; reload it and try again',
    };
    const lost = (res: Awaited<ReturnType<typeof patch>>) => {
      expect([res.statusCode, res.headers['retry-after']], res.body).toEqual([503, '1']);
      expect(res.json()).toMatchObject(changedMeanwhile);
    };
    const { id } = await created(SP_SECRET);
    // Both read the client secret connection; the change to a PAT writes first.
    const [toPat, rotate] = await raceConnectionPatches(
      h,
      id,
      { azureAuth: 'pat', token: services.pat },
      { token: 'rotated-secret' },
    );
    expect(toPat.statusCode, toPat.body).toBe(200);
    lost(rotate);
    expect((await rowOf(id)).azureAuth).toBe('pat');
    expect(await storedCredential(id)).toBe(services.pat);
    // A request that names the old tenant without the secret never undoes a new tenant's.
    const other = await created(SP_SECRET);
    const [retenant, stale] = await raceConnectionPatches(
      h,
      other.id,
      { tenantId: OTHER_ID, token: 'secret-of-other-tenant' },
      { tenantId },
    );
    expect(retenant.statusCode, retenant.body).toBe(200);
    lost(stale);
    expect((await rowOf(other.id)).azureTenantId).toBe(OTHER_ID);
    // One that names the old address without the secret is told the same, not to bring it.
    const third = await created(SP_SECRET);
    const [move, named] = await raceConnectionPatches(
      h,
      third.id,
      { baseUrl: 'https://dev.azure.com/other-org', token: SECRET },
      { baseUrl: SERVICES },
    );
    expect(move.statusCode, move.body).toBe(200);
    lost(named);
    expect((await rowOf(third.id)).baseUrl).toBe('https://dev.azure.com/other-org');
  });

  it('tests each kind: who Qualor acts as, and how many repositories and projects it sees', async () => {
    const pat = await created({ azureAuth: 'pat', token: services.pat });
    const secret = await created(SP_SECRET);
    const certificate = await created(SP_CERTIFICATE);
    const onServer = await created({ baseUrl: server.url, azureAuth: 'pat', token: server.pat });
    for (const [connection, who] of [
      [pat, services.patUser],
      [secret, services.principalUser!],
      [certificate, services.principalUser!],
    ] as const) {
      expect((await test(connection.id)).json(), connection.azure?.auth as string).toEqual({
        ok: true,
        user: { username: who.displayName },
        project: null,
        problem: null,
        missingAccess: null,
        visible: { repositories: 3, projects: 2 },
        hooks: [],
      });
    }
    expect((await test(onServer.id)).json()).toEqual({
      ok: true,
      user: { username: server.patUser.displayName },
      project: null,
      problem: null,
      missingAccess: null,
      visible: { repositories: 1, projects: 1 },
      hooks: [],
    });
    // The stored organisation's routes, at design §7.9's versions; one Entra token per test.
    const asked = services.requests.map(
      (r) => `${r.path}?${new URLSearchParams(r.query).get('api-version')}`,
    );
    expect(new Set(asked)).toEqual(
      new Set(['/_apis/connectionData?7.0-preview', '/_apis/git/repositories?7.0']),
    );
    expect(services.tokenRequests).toHaveLength(2);
    // A repository by its id, in any case: `<project>/<repository>`.
    expect((await test(pat.id, api.id.toUpperCase())).json()).toEqual({
      ok: true,
      user: { username: services.patUser.displayName },
      project: { id: api.id, pathWithNamespace: 'Payments/api', accessLevel: null },
      problem: null,
      missingAccess: null,
      visible: { repositories: 3, projects: 2 },
      hooks: [],
    });
    expect((await test(secret.id, OTHER_ID)).json()).toMatchObject({
      ok: false,
      user: null,
      problem: { code: 'not_found' },
      visible: null,
    });
    for (const bad of ['Payments/api', '42', `{${api.id}}`]) {
      const res = await test(pat.id, bad);
      expect([res.statusCode, res.json().errors], bad).toEqual([
        422,
        [{ path: 'body.projectRef', message: REPOSITORY_ID_TEXT }],
      ]);
    }
    await expectNoCredential();
  });

  it('shows the background problem of a connection, and a passing test clears it', async () => {
    const pat = await created({ azureAuth: 'pat', token: services.pat });
    const at = '2026-11-23T10:00:00.000Z';
    await h.ctx.db
      .update(scmConnections)
      .set({ problem: { code: 'token_refused', at } })
      .where(eq(scmConnections.id, pat.id));
    const listed = (
      await inject('GET', `/scm-connections?organizationId=${h.organizationId}`)
    ).json() as {
      items: { id: string; problem: unknown }[];
    };
    expect(listed.items.find((c) => c.id === pat.id)?.problem).toEqual({
      code: 'token_refused',
      at,
    });
    // A failing test leaves it; a passing one clears it.
    const wrong = await created({ azureAuth: 'pat', token: 'wrong-pat' });
    await h.ctx.db
      .update(scmConnections)
      .set({ problem: { code: 'token_refused', at } })
      .where(eq(scmConnections.id, wrong.id));
    expect((await test(wrong.id)).json()).toMatchObject({ ok: false });
    expect((await rowOf(wrong.id)).problem).toEqual({ code: 'token_refused', at });
    expect((await test(pat.id)).json()).toMatchObject({ ok: true });
    expect((await rowOf(pat.id)).problem).toBeNull();
    const after = (
      await inject('GET', `/scm-connections?organizationId=${h.organizationId}`)
    ).json() as {
      items: { id: string; problem: unknown }[];
    };
    expect(after.items.find((c) => c.id === pat.id)?.problem).toBeNull();
  });

  it('names each refusal with its code, in fixed texts', async () => {
    const secret = await created(SP_SECRET);
    const problemOf = async (id: string) => {
      const result = (await test(id)).json() as Record<string, unknown>;
      expect(result).toMatchObject({ ok: false, user: null, project: null, visible: null });
      return result.problem;
    };
    // TF401444: the organisation has not added the service principal.
    services.identityAdded = false;
    expect(await problemOf(secret.id)).toEqual({
      code: 'sign_in_required',
      message: 'The identity is not a member of this organization or has no access level',
    });
    services.identityAdded = true;
    // The recorded 302 to the sign-in page, and a sign-in page answered with 200.
    const connectionData = /^\/_apis\/connectionData$/;
    services.inject('GET', connectionData, recordedAnswer('services', '10-no-credential'));
    services.inject('GET', connectionData, {
      status: 200,
      headers: { 'content-type': 'text/html; charset=utf-8' },
      body: '<html><title>Sign in to your account</title></html>',
    });
    for (let i = 0; i < 2; i++) {
      expect(await problemOf(secret.id)).toEqual({
        code: 'html_answer',
        message: 'Azure DevOps answered with a sign-in page; check the credential',
      });
    }
    // A PAT Azure DevOps refuses (recorded 401), and a client secret Entra refuses.
    const wrongPat = await created({ azureAuth: 'pat', token: 'wrong-pat' });
    expect(await problemOf(wrongPat.id)).toEqual({
      code: 'token_refused',
      message: 'Azure DevOps refused the credential (HTTP 401)',
    });
    const wrongSecret = await created({ ...SP_SECRET, token: 'wrong-secret' });
    services.clearRequests();
    expect(await problemOf(wrongSecret.id)).toEqual({
      code: 'token_endpoint',
      message: 'Microsoft Entra refused the service principal',
    });
    expect(services.requests).toHaveLength(0);
    // A credential encrypted under another key is named, and nothing is sent.
    await h.ctx.db
      .update(scmConnections)
      .set({ tokenEnc: encryptSecret(encryptionKey('z'.repeat(32)), 'x', SCM_TOKEN_AAD) })
      .where(eq(scmConnections.id, secret.id));
    services.clearRequests();
    expect(await problemOf(secret.id)).toEqual({
      code: 'undecryptable',
      message: expect.stringMatching(/cannot be decrypted/),
    });
    expect([services.requests, services.tokenRequests]).toEqual([[], []]);
    const listed = await inject('GET', `/scm-connections?organizationId=${h.organizationId}`);
    expect(
      (listed.json().items as AzureConnection[]).find((c) => c.id === secret.id)?.azure,
    ).toMatchObject({ credentialReadable: false });
    for (const text of answers) {
      for (const words of ['TF401444', 'Object moved', 'AADSTS', 'Sign in to your account']) {
        expect(text).not.toContain(words);
      }
    }
    await expectNoCredential();
  });

  it('blames Microsoft Entra, with a fixed text, when its token endpoint cannot be reached', async () => {
    const row = await rowOf((await created(SP_SECRET)).id);
    // A closed loopback port: the connection fails before any answer.
    const deps = { ...scmDepsOf(h.ctx.config), azureTokenOrigin: 'http://127.0.0.1:1' };
    services.clearRequests();
    const result = await testAzureConnection(row, deps, null);
    expect(result).toMatchObject({
      ok: false,
      user: null,
      problem: {
        code: 'token_endpoint_unreachable',
        message: 'Microsoft Entra could not be reached',
      },
    });
    expect(services.requests).toHaveLength(0);
  });

  it('gives a token endpoint that never answers, or answers 503, its own code', async () => {
    const row = await rowOf((await created(SP_SECRET)).id);
    const stalled = createHttpServer(() => undefined);
    const failing = createHttpServer((_req, res) => {
      res.writeHead(503).end();
    });
    const origins: string[] = [];
    for (const fake of [stalled, failing]) {
      await new Promise<void>((resolve) => fake.listen(0, '127.0.0.1', resolve));
      origins.push(`http://127.0.0.1:${(fake.address() as AddressInfo).port}`);
    }
    try {
      services.clearRequests();
      const base = scmDepsOf(h.ctx.config);
      const slow = await testAzureConnection(
        row,
        { ...base, azureTokenOrigin: origins[0]!, azureClientOptions: { timeoutMs: 200 } },
        null,
      );
      expect(slow).toMatchObject({
        ok: false,
        problem: {
          code: 'token_endpoint_timeout',
          message: 'Microsoft Entra did not answer in time',
        },
      });
      const broken = await testAzureConnection(
        row,
        { ...base, azureTokenOrigin: origins[1]! },
        null,
      );
      expect(broken).toMatchObject({
        ok: false,
        problem: {
          code: 'token_endpoint_error',
          message: 'Microsoft Entra answered with an error',
        },
      });
      expect(services.requests).toHaveLength(0);
    } finally {
      for (const fake of [stalled, failing]) {
        fake.closeAllConnections();
        fake.close();
      }
    }
  });

  it('sends nothing to an address the operator no longer lists or the Azure DevOps rules refuse', async () => {
    const onServer = await created({ baseUrl: server.url, azureAuth: 'pat', token: server.pat });
    const row = await rowOf(onServer.id);
    const deps = (hosts: string[]) => ({
      secretKey: h.ctx.config.secretKey,
      internalHosts: new Set(hosts) as ReadonlySet<string>,
      azureTokenOrigin: null,
      azureTestOrigin: null,
    });
    const listed = [new URL(server.url).host];
    expect(await testAzureConnection(row, deps([]), null)).toMatchObject({
      ok: false,
      problem: {
        code: 'url_not_allowed',
        message: expect.stringMatching(/QUALOR_SCM_INTERNAL_HOSTS/),
      },
    });
    // A row the API would refuse: no collection, or a service principal on a Server.
    expect(
      await testAzureConnection(
        { ...row, baseUrl: new URL(server.url).origin },
        deps(listed),
        null,
      ),
    ).toMatchObject({ ok: false, problem: { code: 'url_not_allowed' } });
    expect(
      await testAzureConnection(
        {
          ...row,
          azureAuth: 'service_principal_secret',
          azureTenantId: tenantId,
          azureClientId: clientId,
        },
        deps(listed),
        null,
      ),
    ).toMatchObject({ ok: false, problem: { code: 'url_not_allowed', message: SERVER_TAKES_PAT } });
    expect(server.requests).toHaveLength(0);
    // The same row, listed: it reaches the fake.
    expect(await testAzureConnection(row, deps(listed), null)).toMatchObject({ ok: true });
  });

  it("keeps a service principal's token in a job's cache across clients, never for another credential", async () => {
    const row = await rowOf((await created(SP_SECRET)).id);
    const deps = scmDepsOf(h.ctx.config);
    const clientOf = (r: typeof row, runtime?: { azureTokens: InstallationTokenCache }) => {
      const made = azureClientFor(r, deps, runtime);
      if ('problem' in made) throw new Error(made.problem);
      return made.client;
    };
    const runtime = { azureTokens: new InstallationTokenCache() };
    await clientOf(row, runtime).connectionData();
    await clientOf(row, runtime).repositories();
    expect([services.tokenRequests.length, runtime.azureTokens.size]).toEqual([1, 1]);
    // Without a job's cache, a client asks Entra once for all its requests.
    const alone = clientOf(row);
    await alone.connectionData();
    await alone.repositories();
    expect(services.tokenRequests).toHaveLength(2);
    // Another secret is another key: Entra is asked, and refuses it.
    const replaced = {
      ...row,
      tokenEnc: encryptSecret(encryptionKey(h.ctx.config.secretKey), 'wrong-secret', SCM_TOKEN_AAD),
    };
    await expect(clientOf(replaced, runtime).connectionData()).rejects.toMatchObject({
      kind: 'auth',
      reason: 'token_endpoint',
    });
    expect(services.tokenRequests).toHaveLength(3);
  });

  it("looks identities up on the identities host: the test origin's prefix, and the same address rules", async () => {
    const row = await rowOf((await created(SP_SECRET)).id);
    const deps = scmDepsOf(h.ctx.config);
    const made = azureClientFor(row, deps);
    if ('problem' in made) throw new Error(made.problem);
    services.clearRequests();
    const descriptor = await made.client.identityDescriptor(services.principalUser!.id);
    expect(descriptor).toMatch(/AadServicePrincipal;/);
    expect(services.requests.map((r) => r.path)).toEqual(['/vssps/_apis/identities']);
    // The identities host is not the base: an internal host list without the fake's host refuses both.
    const unlisted = azureClientFor(row, { ...deps, internalHosts: new Set() });
    expect(unlisted).toMatchObject({ problem: expect.any(String) });
  });
});
