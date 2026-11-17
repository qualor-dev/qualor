import { and, eq, gt, sql } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { addMember, bearer, createUser, login, type Session } from '../../test/app';
import { createFakeJira, type FakeJira } from '../../test/fake-jira';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { connectJira, jiraTestConfig, seedJiraLink } from '../../test/jira';
import { grantProject, rbacPlugins } from '../../test/rbac';
import { trustTestCa } from '../../test/tls';
import { decryptSecret, encryptionKey, encryptSecret } from '../crypto/secrets';
import {
  auditEvents,
  jiraConnections,
  jiraLinks,
  jobs,
  projectJiraSettings,
  type JiraProblemValue,
} from '../db/schema';
import { JIRA_TOKEN_AAD, runConnectionTest, testJiraConnection } from '../jira/connection';
import { JiraClient } from '../jira/client';
import { JIRA_QUEUE } from '../jira/jobs';
import { JIRA_PROBLEM_TEXT, setConnectionProblem } from '../jira/problems';

const NOW = new Date('2027-01-01T00:00:00Z');
const EMAIL = 'jira-robot@example.test';

describe('the organisation Jira connection (0.16 Jira §6.1, §6.8)', () => {
  let h: IngestHarness;
  let fake: FakeJira;
  let member: Session;
  let projectAdmin: Session;
  let outsider: Session;
  let untrust: () => void;
  /** The audit sequence before the test: only later entries are the test's. */
  let since = 0;
  const org = () => `/api/v0/organizations/${h.organizationId}/jira`;
  const call = (
    method: 'GET' | 'PUT' | 'DELETE' | 'POST',
    url: string,
    payload?: object,
    headers: Record<string, string> = h.orgAdmin.headers,
  ) =>
    h.ctx.app.inject({
      method,
      url,
      headers,
      ...(payload === undefined ? {} : { payload }),
    });
  const put = (payload: object, headers?: Record<string, string>) =>
    call(
      'PUT',
      org(),
      { deployment: 'data_center', siteUrl: fake.url, token: fake.token, ...payload },
      headers,
    );
  const errorPaths = (res: { json(): unknown }) =>
    (res.json() as { errors: { path: string }[] }).errors.map((e) => e.path);
  const events = async (action: string) =>
    (
      await h.ctx.db
        .select()
        .from(auditEvents)
        .where(and(eq(auditEvents.action, action), gt(auditEvents.seq, since)))
        .orderBy(auditEvents.seq)
    ).map((e) => e.details);
  const queuedJobs = () =>
    h.ctx.db
      .select()
      .from(jobs)
      .where(and(eq(jobs.queue, JIRA_QUEUE), eq(jobs.status, 'queued')));
  const mapProject = async (key: string, connectionId: string): Promise<string> => {
    const project = await h.project(key);
    await h.ctx.db.insert(projectJiraSettings).values({
      projectId: project.id,
      connectionId,
      jiraProjectId: '10000',
      jiraProjectKey: 'QUAL',
      jiraProjectName: 'Qualor findings',
      issueTypeId: '10001',
      issueTypeName: 'Bug',
      labelsAvailable: true,
      priorityAvailable: true,
    });
    return project.id;
  };

  beforeAll(async () => {
    untrust = trustTestCa();
    fake = await createFakeJira({ deployment: 'data_center' });
    fake.addProject({ id: '10000', key: 'QUAL', name: 'Qualor findings' });
    h = await createIngestHarness({
      config: jiraTestConfig(fake),
      pluginsFor: rbacPlugins({ now: () => NOW }),
    });
    const m = await createUser(h.ctx, { username: 'jira-member' });
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
    const o = await createUser(h.ctx, { username: 'jira-outsider' });
    outsider = await login(h.ctx, o.username, o.password);
    const p = await createUser(h.ctx, { username: 'jira-project-admin' });
    const project = await h.project('jira/access');
    await grantProject(h.ctx, project.id, p.id, 'project_admin');
    projectAdmin = await login(h.ctx, p.username, p.password);
  });
  afterAll(async () => {
    await h.close();
    await fake.close();
    untrust();
  });
  beforeEach(async () => {
    const [last] = await h.ctx.db
      .select({ seq: sql<number>`coalesce(max(${auditEvents.seq}), 0)` })
      .from(auditEvents);
    since = Number(last?.seq ?? 0);
  });
  afterEach(async () => {
    fake.clearRequests();
    await h.ctx.db.delete(jiraConnections);
    await h.ctx.db.delete(jobs).where(eq(jobs.queue, JIRA_QUEUE));
  });

  it('has nothing yet: GET answers null, Test 409 and DELETE 404', async () => {
    const got = await call('GET', org());
    expect(got.statusCode).toBe(200);
    expect(got.json()).toEqual({ connection: null, publicUrlSet: false });
    const test = await call('POST', `${org()}/test`);
    expect(test.statusCode).toBe(409);
    expect(test.json()).toMatchObject({ code: 'JIRA_NOT_CONNECTED' });
    expect((await call('DELETE', org())).statusCode).toBe(404);
  });

  it('creates a connection, queues the first pass and never returns the token', async () => {
    const res = await put({});
    expect(res.statusCode, res.body).toBe(200);
    expect(res.body).not.toContain(fake.token);
    expect(res.json()).toEqual({
      id: expect.any(String),
      organizationId: h.organizationId,
      deployment: 'data_center',
      siteUrl: fake.url,
      apiUrl: null,
      email: null,
      tokenSet: true,
      tokenReadable: true,
      problem: null,
      mappedProjects: 0,
      links: { pending: 0, created: 0, failed: 0, missing: 0, dismissed: 0 },
      createdAt: expect.any(String),
      updatedAt: expect.any(String),
    });
    const [row] = await h.ctx.db.select().from(jiraConnections);
    expect(JSON.stringify(row!.tokenEnc)).not.toContain(fake.token);
    expect(
      decryptSecret(encryptionKey(h.ctx.config.secretKey), row!.tokenEnc, JIRA_TOKEN_AAD),
    ).toBe(fake.token);
    const queued = await queuedJobs();
    expect(queued).toHaveLength(1);
    expect(queued[0]).toMatchObject({
      payload: { kind: 'sync', organizationId: h.organizationId },
    });
    expect(queued[0]!.runAt.getTime()).toBeLessThanOrEqual(Date.now() + 60_000);
    expect(await events('jira_connection.created')).toEqual([
      { deployment: 'data_center', siteOrigin: fake.url },
    ]);
    const got = (await call('GET', org())).json() as { connection: { id: string } };
    expect(got.connection.id).toBe(res.json().id);
    expect(fake.requests).toHaveLength(0);
  });

  it('connects again after a remove with the first pass now, not at the old pass time (M4)', async () => {
    await connectJira(h, fake);
    // DELETE leaves the old connection's pass queued (T3b), here a day ahead.
    expect((await call('DELETE', org())).statusCode).toBe(204);
    const [old] = await queuedJobs();
    expect(old!.runAt.getTime()).toBeGreaterThan(Date.now() + 60 * 60_000);
    expect((await put({})).statusCode).toBe(200);
    const queued = await queuedJobs();
    expect(queued.map((j) => j.id)).toEqual([old!.id]);
    expect(queued[0]!.runAt.getTime()).toBeLessThanOrEqual(Date.now() + 1_000);
  });

  it('stores the context path without the trailing slash', async () => {
    const res = await put({ siteUrl: `${fake.url}/jira/` });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json().siteUrl).toBe(`${fake.url}/jira`);
  });

  describe('validation', () => {
    it('needs the token on create', async () => {
      const res = await call('PUT', org(), { deployment: 'data_center', siteUrl: fake.url });
      expect(res.statusCode).toBe(422);
      expect(errorPaths(res)).toContain('body.token');
      expect(await h.ctx.db.select().from(jiraConnections)).toHaveLength(0);
    });

    it('needs the email of a Cloud connection', async () => {
      const res = await put({ deployment: 'cloud', siteUrl: 'https://acme.atlassian.net' });
      expect(res.statusCode).toBe(422);
      expect(errorPaths(res)).toEqual(['body.email']);
    });

    it('refuses a Cloud address that is not an atlassian.net site', async () => {
      const res = await put({
        deployment: 'cloud',
        siteUrl: 'https://evil.example',
        email: EMAIL,
      });
      expect(res.statusCode).toBe(422);
      expect(errorPaths(res)).toEqual(['body.siteUrl']);
    });

    it('refuses a Cloud API URL that is not the gateway', async () => {
      const res = await put({
        deployment: 'cloud',
        siteUrl: 'https://acme.atlassian.net',
        email: EMAIL,
        apiUrl: 'https://api.atlassian.com/ex/jira/not-a-uuid',
      });
      expect(res.statusCode).toBe(422);
      expect(errorPaths(res)).toEqual(['body.apiUrl']);
    });

    it('refuses the Cloud-only fields of a Data Center connection', async () => {
      const withEmail = await put({ email: EMAIL });
      expect(withEmail.statusCode).toBe(422);
      expect(errorPaths(withEmail)).toEqual(['body.email']);
      const withApi = await put({
        apiUrl: 'https://api.atlassian.com/ex/jira/0a1b2c3d-0a1b-4c3d-8a1b-0a1b2c3d4e5f',
      });
      expect(withApi.statusCode).toBe(422);
      expect(errorPaths(withApi)).toEqual(['body.apiUrl']);
    });

    it('refuses a token with a space', async () => {
      const res = await put({ token: 'has a space' });
      expect(res.statusCode).toBe(422);
      expect(errorPaths(res)).toEqual(['body.token']);
      expect(res.body).not.toContain('has a space');
    });

    it('refuses a plain http Data Center that is not listed', async () => {
      const res = await put({ siteUrl: 'http://jira.unlisted.example' });
      expect(res.statusCode).toBe(422);
      expect(errorPaths(res)).toEqual(['body.siteUrl']);
    });
  });

  it('treats a new address as a new connection: the token again, and mappings and links go', async () => {
    const id = await connectJira(h, fake);
    const a = await mapProject('jira/a', id);
    const b = await mapProject('jira/b', id);
    for (const projectId of [a, a, b])
      await seedJiraLink(h.ctx.db, { projectId, connectionId: id });
    const moved = { siteUrl: `${fake.url}/jira` };

    const refused = await call('PUT', org(), { deployment: 'data_center', ...moved });
    expect(refused.statusCode).toBe(422);
    expect(errorPaths(refused)).toEqual(['body.token']);
    expect(await h.ctx.db.select().from(projectJiraSettings)).toHaveLength(2);
    expect(await h.ctx.db.select().from(jiraLinks)).toHaveLength(3);
    expect(await events('jira_connection.updated')).toEqual([]);

    const ok = await put(moved);
    expect(ok.statusCode, ok.body).toBe(200);
    expect(ok.json()).toMatchObject({ id, siteUrl: `${fake.url}/jira`, mappedProjects: 0 });
    expect(await h.ctx.db.select().from(projectJiraSettings)).toHaveLength(0);
    expect(await h.ctx.db.select().from(jiraLinks)).toHaveLength(0);
    expect(await events('jira_connection.updated')).toEqual([{ changed: ['siteUrl', 'token'] }]);
  });

  it('keeps mappings and links for a new token and email, clears the problem and runs the pass now', async () => {
    const [created] = await h.ctx.db
      .insert(jiraConnections)
      .values({
        organizationId: h.organizationId,
        deployment: 'cloud',
        siteUrl: 'https://acme.atlassian.net',
        email: 'old@example.test',
        tokenEnc: encryptSecret(encryptionKey(h.ctx.config.secretKey), 'old-token', JIRA_TOKEN_AAD),
        problem: {
          code: 'token_refused',
          message: JIRA_PROBLEM_TEXT.token_refused,
          at: '2027-01-01T00:00:00.000Z',
        } satisfies JiraProblemValue,
      })
      .returning({ id: jiraConnections.id });
    const id = created!.id;
    const projectId = await mapProject('jira/keep', id);
    await seedJiraLink(h.ctx.db, { projectId, connectionId: id });
    // The waiting pass is a day away.
    await h.ctx.db.insert(jobs).values({
      queue: JIRA_QUEUE,
      concurrencyKey: `jira-sync:${h.organizationId}`,
      payload: { kind: 'sync', organizationId: h.organizationId },
      runAt: sql`now() + interval '1 day'`,
    });

    const res = await call('PUT', org(), {
      deployment: 'cloud',
      siteUrl: 'https://acme.atlassian.net',
      email: EMAIL,
      token: 'new-token',
    });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({
      id,
      email: EMAIL,
      problem: null,
      mappedProjects: 1,
      links: { pending: 1 },
    });
    expect(await h.ctx.db.select().from(projectJiraSettings)).toHaveLength(1);
    expect(await h.ctx.db.select().from(jiraLinks)).toHaveLength(1);
    const queued = await queuedJobs();
    expect(queued).toHaveLength(1);
    expect(queued[0]!.runAt.getTime()).toBeLessThanOrEqual(Date.now() + 60_000);
    expect(await events('jira_connection.updated')).toEqual([{ changed: ['email', 'token'] }]);
    expect(JSON.stringify(await events('jira_connection.updated'))).not.toContain(EMAIL);
  });

  it('answers a PUT that changes nothing without an audit entry', async () => {
    await connectJira(h, fake);
    const again = await call('PUT', org(), { deployment: 'data_center', siteUrl: fake.url });
    expect(again.statusCode, again.body).toBe(200);
    expect(await events('jira_connection.updated')).toEqual([]);
  });

  it('deletes the connection with its mappings and links and records their number', async () => {
    const id = await connectJira(h, fake);
    const projectId = await mapProject('jira/del', id);
    for (let i = 0; i < 3; i += 1) await seedJiraLink(h.ctx.db, { projectId, connectionId: id });
    const res = await call('DELETE', org());
    expect(res.statusCode).toBe(204);
    expect(await h.ctx.db.select().from(jiraConnections)).toHaveLength(0);
    expect(await h.ctx.db.select().from(projectJiraSettings)).toHaveLength(0);
    expect(await h.ctx.db.select().from(jiraLinks)).toHaveLength(0);
    expect(await events('jira_connection.deleted')).toEqual([
      { deployment: 'data_center', siteOrigin: fake.url, links: 3 },
    ]);
  });

  describe('test', () => {
    const test = async () => (await call('POST', `${org()}/test`)).json();

    it('answers the user and the projects visible', async () => {
      await connectJira(h, fake);
      expect(await test()).toEqual({
        ok: true,
        user: { displayName: expect.any(String) },
        projectsVisible: 1,
        problem: null,
      });
      expect(fake.requests.every((r) => r.headers.authorization === `Bearer ${fake.token}`)).toBe(
        true,
      );
    });

    it('is not audited', async () => {
      await connectJira(h, fake);
      const before = await h.ctx.db.select().from(auditEvents);
      await test();
      expect(await h.ctx.db.select().from(auditEvents)).toHaveLength(before.length);
    });

    it('reports no_projects with its fixed text', async () => {
      await connectJira(h, fake);
      fake.inject('GET', /\/rest\/api\/2\/project$/, { body: [] });
      const res = await test();
      expect(res).toMatchObject({
        ok: false,
        user: { displayName: expect.any(String) },
        projectsVisible: 0,
        problem: { code: 'no_projects', message: JIRA_PROBLEM_TEXT.no_projects },
      });
    });

    it('reports a refused token', async () => {
      await connectJira(h, fake);
      fake.inject('GET', /\/myself$/, { status: 401, body: { errorMessages: ['nope'] } });
      expect(await test()).toMatchObject({
        ok: false,
        user: null,
        projectsVisible: null,
        problem: { code: 'token_refused', message: JIRA_PROBLEM_TEXT.token_refused },
      });
    });

    it('reports an HTML page as bad_answer (a sign-in proxy)', async () => {
      await connectJira(h, fake);
      fake.inject('GET', /\/myself$/, { body: '<html><body>Sign in</body></html>' });
      expect(await test()).toMatchObject({
        ok: false,
        problem: { code: 'bad_answer', message: JIRA_PROBLEM_TEXT.bad_answer },
      });
    });

    it('clears the stored problem when it passes, and keeps it when it fails', async () => {
      const id = await connectJira(h, fake);
      const stored: JiraProblemValue = {
        code: 'token_refused',
        message: JIRA_PROBLEM_TEXT.token_refused,
        at: '2027-01-01T00:00:00.000Z',
      };
      await h.ctx.db
        .update(jiraConnections)
        .set({ problem: stored })
        .where(eq(jiraConnections.id, id));
      fake.inject('GET', /\/myself$/, { status: 401, body: { errorMessages: ['nope'] } });
      await test();
      const read = async () =>
        (await h.ctx.db.select().from(jiraConnections).where(eq(jiraConnections.id, id)))[0]!
          .problem;
      expect(await read()).toEqual(stored);
      expect((await test()).ok).toBe(true);
      expect(await read()).toBeNull();
    });

    it('keeps a problem a pass recorded while it ran: it clears only what it read', async () => {
      const id = await connectJira(h, fake);
      await setConnectionProblem(h.ctx.db, id, 'token_refused');
      fake.inject('GET', /\/myself$/, {
        passThrough: true,
        before: () => setConnectionProblem(h.ctx.db, id, 'timeout'),
      });
      expect((await test()).ok).toBe(true);
      const [row] = await h.ctx.db.select().from(jiraConnections).where(eq(jiraConnections.id, id));
      expect(row?.problem?.code).toBe('timeout');
    });

    it('reports a token sealed under another key as undecryptable', async () => {
      const id = await connectJira(h, fake);
      await h.ctx.db
        .update(jiraConnections)
        .set({
          tokenEnc: encryptSecret(
            encryptionKey('another-key-of-at-least-32-characters!'),
            'x',
            JIRA_TOKEN_AAD,
          ),
        })
        .where(eq(jiraConnections.id, id));
      expect(await test()).toMatchObject({
        ok: false,
        problem: { code: 'undecryptable', message: JIRA_PROBLEM_TEXT.undecryptable },
      });
      const got = (await call('GET', org())).json() as { connection: { tokenReadable: boolean } };
      expect(got.connection.tokenReadable).toBe(false);
      expect(fake.requests).toHaveLength(0);
    });

    it('refuses an address the operator no longer lists, without a request', async () => {
      await connectJira(h, fake);
      const [row] = await h.ctx.db.select().from(jiraConnections);
      const result = await testJiraConnection(row!, {
        secretKey: h.ctx.config.secretKey,
        internalHosts: new Set(),
      });
      expect(result).toMatchObject({
        ok: false,
        problem: { code: 'url_not_allowed', message: JIRA_PROBLEM_TEXT.url_not_allowed },
      });
      expect(fake.requests).toHaveLength(0);
    });

    it('names the API URL when a Cloud account sees no projects (scoped token on the site URL)', async () => {
      const cloud = await createFakeJira({ deployment: 'cloud', https: true });
      try {
        const client = new JiraClient({
          deployment: 'cloud',
          apiBase: cloud.url,
          auth: { kind: 'basic', email: cloud.email, token: cloud.token },
          allowInternalHosts: true,
        });
        const result = await runConnectionTest(client);
        expect(result.ok).toBe(false);
        expect(result.projectsVisible).toBe(0);
        expect(result.problem?.code).toBe('no_projects');
        expect(result.problem?.message).toContain('https://api.atlassian.com/ex/jira/<cloud id>');
      } finally {
        await cloud.close();
      }
    });

    it('never puts the token or the email of an echoing Jira into an answer or an audit entry', async () => {
      await connectJira(h, fake);
      const echo = {
        status: 401,
        body: {
          errorMessages: [`Bad credentials: Bearer ${fake.token} for ${fake.email} ${EMAIL}`],
          errors: { authorization: `Bearer ${fake.token}`, user: fake.email },
        },
      };
      fake.inject('GET', /\/myself$/, echo);
      const tested = await call('POST', `${org()}/test`);
      const got = await call('GET', org());
      const audit = JSON.stringify(await h.ctx.db.select().from(auditEvents));
      for (const [where, text] of [
        ['the test answer', tested.body],
        ['the connection answer', got.body],
        ['the audit log', audit],
      ] as const) {
        for (const secret of [fake.token, fake.email, EMAIL]) {
          expect(text.includes(secret), `${where} holds a secret`).toBe(false);
        }
      }
      expect(h.ctx.logs.join('\n')).not.toContain(fake.token);
    });
  });

  describe('access', () => {
    it('is for organisation admins only', async () => {
      await connectJira(h, fake);
      for (const [method, url] of [
        ['GET', org()],
        ['PUT', org()],
        ['DELETE', org()],
        ['POST', `${org()}/test`],
      ] as const) {
        const asMember = await call(
          method,
          url,
          method === 'PUT' ? { deployment: 'data_center', siteUrl: fake.url } : undefined,
          projectAdmin.headers,
        );
        expect(asMember.statusCode, `${method} as a member`).toBe(403);
        const asOutsider = await call(
          method,
          url,
          method === 'PUT' ? { deployment: 'data_center', siteUrl: fake.url } : undefined,
          outsider.headers,
        );
        expect(asOutsider.statusCode, `${method} as an outsider`).toBe(404);
      }
      expect((await call('GET', org(), undefined, member.headers)).body).not.toContain(fake.token);
    });

    it('needs the admin scope of a personal token', async () => {
      const made = await h.ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: h.orgAdmin.headers,
        payload: { name: 'jira-read', scopes: ['read'] },
      });
      const readOnly = bearer((made.json() as { token: string }).token);
      const res = await call('GET', org(), undefined, readOnly);
      expect(res.statusCode).toBe(403);
      expect(res.json()).toMatchObject({ code: 'INSUFFICIENT_SCOPE' });
    });
  });

  it('makes one connection of two PUTs at once', async () => {
    const [a, b] = await Promise.all([put({}), put({})]);
    expect(a.statusCode, a.body).toBe(200);
    expect(b.statusCode, b.body).toBe(200);
    expect(await h.ctx.db.select().from(jiraConnections)).toHaveLength(1);
    expect(await events('jira_connection.created')).toHaveLength(1);
    expect(await queuedJobs()).toHaveLength(1);
  });
});
