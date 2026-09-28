import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { ADMIN_PASSWORD, addMember, createUser, login, type Session } from '../../test/app';
import { createFakeGitHub, type FakeGitHub } from '../../test/fake-github';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { githubTestConfig, WEBHOOK_SECRET } from '../../test/github';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { PUBLIC_URL } from '../../test/scm';
import { decryptSecret, encryptionKey, encryptSecret } from '../crypto/secrets';
import type { Db } from '../db/client';
import { branches, jobs, organizations, projects, scmConnections } from '../db/schema';
import {
  MAX_SCM_CONNECTIONS_PER_ORGANIZATION,
  SCM_TOKEN_AAD,
  testConnection,
  webBaseSql,
} from '../scm/connections';
import {
  decryptPrivateKey,
  decryptWebhookSecret,
  WEBHOOK_SECRET_AAD,
} from '../scm/github/credentials';
import { githubWebBase } from '../scm/github/url';

/** Polls until `n` backends of this file's own database wait on a lock (never a fixed sleep). */
async function waitForLockWaiters(db: Db, n: number, timeoutMs = 5_000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    const result = await db.execute(sql`
      SELECT count(*)::int AS n FROM pg_stat_activity
       WHERE wait_event_type = 'Lock' AND datname = current_database()`);
    if (Number(result.rows[0]?.n) >= n) return;
    if (Date.now() > deadline) throw new Error(`Timed out waiting for ${n} lock waiter(s)`);
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
}

interface Connection {
  id: string;
  organizationId: string;
  provider: string;
  baseUrl: string;
}

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
      project: { id: 7, pathWithNamespace: 'acme/payments/api' },
      problem: null,
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
      { secretKey: h.ctx.config.secretKey, internalHosts: new Set() },
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
        clientOptions: {
          resolve: () => Promise.resolve([{ address: '127.0.0.1', family: 4 }]),
        },
      },
      null,
    );
    expect(byName).toMatchObject({ ok: false, problem: { code: 'not_public' } });
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
  const patch = (id: string, payload: Record<string, unknown>) =>
    h.ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/scm-connections/${id}`,
      headers: h.orgAdmin.headers,
      payload,
    });
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

  it('keeps a GitLab row’s GitHub columns NULL', async () => {
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
    expect(
      errorPaths((await patch(row.id, { appId: '1', webhookSecret: WEBHOOK_SECRET })).body),
    ).toEqual(['body.appId', 'body.webhookSecret']);
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
  const race = async (
    id: string,
    first: Record<string, unknown>,
    second: Record<string, unknown>,
  ) => {
    let a: ReturnType<typeof patch> | undefined;
    let b: ReturnType<typeof patch> | undefined;
    await h.ctx.db.transaction(async (tx) => {
      await tx
        .select({ id: scmConnections.id })
        .from(scmConnections)
        .where(eq(scmConnections.id, id))
        .for('update');
      a = patch(id, first);
      await waitForLockWaiters(h.ctx.db, 1);
      b = patch(id, second);
      await waitForLockWaiters(h.ctx.db, 2);
    });
    return [await a!, await b!] as const;
  };
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
      project: { id: 424242, pathWithNamespace: 'acme/api' },
      problem: null,
    });
    expect((await test('acme/bare')).json().problem.code).toBe('not_installed');
    expect((await test('acme/nochecks')).json().problem.code).toBe('permission_missing');
    // GitHub answers 404 for the installation of a repository it does not show the App.
    expect((await test('acme/nope')).json().problem.code).toBe('not_installed');
    expect((await test()).json().ok).toBe(true);
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
});
