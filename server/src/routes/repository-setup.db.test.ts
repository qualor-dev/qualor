import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, describe, expect, it } from 'vitest';
import { addMember, createUser, login, type Session } from '../../test/app';
import { createFakeGitHub, type FakeGitHub, type FakeRepository } from '../../test/fake-github';
import { createFakeGitLab, type FakeGitLab } from '../../test/fake-gitlab';
import { createIngestHarness, type IngestHarness } from '../../test/ingest';
import { PUBLIC_URL } from '../../test/scm';
import { scmConnections } from '../db/schema';
import {
  CI_SETUP_CACHE_MS,
  CI_SETUP_FAILURE_CACHE_MS,
  createCiSetupStatus,
} from '../scm/ci-setup-status';

interface Option {
  ref: string;
  name: string;
  defaultBranch: string | null;
  language: string | null;
  archived: boolean;
  project: { id: string; key: string; state: 'mapped' | 'adoptable' } | null;
}
interface Listing {
  items: Option[];
  hasMore: boolean;
}
interface CiSetup {
  available: boolean;
  reason: 'not_allowed' | 'missing_permissions' | 'no_public_url' | null;
  missing: string[];
}

const BOTH = {
  metadata: 'read',
  pull_requests: 'write',
  workflows: 'write',
  secrets: 'write',
} as const;

describe('Listing a connection’s repositories and its CI-setup status', () => {
  let h: IngestHarness;
  let bare: IngestHarness;
  let member: Session;
  let outsider: Session;
  const hosts = new Set<string>();
  const closers: (() => Promise<void>)[] = [];

  const github = async (repos: Omit<FakeRepository, 'id'>[]): Promise<FakeGitHub> => {
    const fake = await createFakeGitHub();
    closers.push(() => fake.close());
    hosts.add(new URL(fake.url).host);
    repos.forEach((repo, i) => fake.addRepository({ ...repo, id: 1000 + i }));
    return fake;
  };
  const gitlab = async (): Promise<FakeGitLab> => {
    const fake = await createFakeGitLab();
    closers.push(() => fake.close());
    hosts.add(new URL(fake.url).host);
    fake.accessLevel = 40;
    return fake;
  };
  const connect = async (
    harness: IngestHarness,
    body: Record<string, unknown>,
  ): Promise<{ id: string; ciSetup: CiSetup }> => {
    const res = await harness.ctx.app.inject({
      method: 'POST',
      url: '/api/v0/scm-connections',
      headers: harness.orgAdmin.headers,
      payload: { organizationId: harness.organizationId, ...body },
    });
    expect(res.statusCode, res.body).toBe(201);
    return res.json() as { id: string; ciSetup: CiSetup };
  };
  const connectGitHub = (fake: FakeGitHub, harness = h) =>
    connect(harness, {
      provider: 'github',
      baseUrl: fake.url,
      appId: String(fake.appId),
      privateKey: fake.privateKeyPem,
    });
  const connectGitLab = (fake: FakeGitLab, extra: Record<string, unknown> = {}, harness = h) =>
    connect(harness, { provider: 'gitlab', baseUrl: fake.url, token: fake.token, ...extra });
  const listed = (id: string, query = '', session: Session = h.orgAdmin) =>
    h.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/scm-connections/${id}/repositories${query}`,
      headers: session.headers,
    });
  const items = async (id: string, query = ''): Promise<Listing> => {
    const res = await listed(id, query);
    expect(res.statusCode, res.body).toBe(200);
    return res.json() as Listing;
  };
  const map = async (key: string, connectionId: string, ref: string): Promise<string> => {
    const project = await h.project(key);
    const res = await h.ctx.app.inject({
      method: 'PATCH',
      url: `/api/v0/projects/${project.id}`,
      headers: h.orgAdmin.headers,
      payload: { scmConnectionId: connectionId, scmProjectRef: ref },
    });
    expect(res.statusCode, res.body).toBe(200);
    return project.id;
  };
  const ciSetupOf = async (harness: IngestHarness, id: string): Promise<CiSetup> => {
    const res = await harness.ctx.app.inject({
      method: 'GET',
      url: `/api/v0/scm-connections?organizationId=${harness.organizationId}`,
      headers: harness.orgAdmin.headers,
    });
    expect(res.statusCode, res.body).toBe(200);
    return (res.json().items as { id: string; ciSetup: CiSetup }[]).find((c) => c.id === id)!
      .ciSetup;
  };

  beforeAll(async () => {
    // The fakes of each test join this set after the app was built: it is read on every call.
    const config = { scmInternalHosts: hosts as ReadonlySet<string>, publicUrl: PUBLIC_URL };
    h = await createIngestHarness({ config });
    bare = await createIngestHarness({
      config: { scmInternalHosts: hosts as ReadonlySet<string> },
    });
    const m = await createUser(h.ctx, { username: 'setup-member' });
    await addMember(h.ctx, h.organizationId, m.id, 'member');
    member = await login(h.ctx, m.username, m.password);
    const o = await createUser(h.ctx, { username: 'setup-outsider' });
    outsider = await login(h.ctx, o.username, o.password);
  });
  afterEach(async () => {
    // An organisation holds at most ten connections.
    await h.ctx.db.delete(scmConnections);
    await bare.ctx.db.delete(scmConnections);
    for (const close of closers.splice(0)) await close();
  });
  afterAll(async () => {
    await h.close();
    await bare.close();
  });

  describe('GitHub', () => {
    it('lists the repositories of every installation with their project state', async () => {
      const fake = await github([
        { owner: 'acme', name: 'api', installationId: 1, language: 'TypeScript' },
        { owner: 'acme', name: 'web', installationId: 1, defaultBranch: 'trunk' },
        { owner: 'acme', name: 'lib', installationId: 1 },
        { owner: 'acme', name: 'old', installationId: 1, archived: true },
        { owner: 'beta', name: 'tool', installationId: 2, permissions: BOTH },
        { owner: 'beta', name: 'taken', installationId: 2 },
      ]);
      const { id } = await connectGitHub(fake);
      // Mapped, compared without case; adoptable by its key; a key that does not match is none.
      const mapped = await map('gh-acme/api-key', id, 'ACME/Api');
      const adoptable = await h.project('acme/web');
      const other = await map('beta/taken', id, 'beta/elsewhere');
      await h.project('Acme/Lib');

      const { items: rows, hasMore } = await items(id);

      expect(hasMore).toBe(false);
      expect(rows).toEqual([
        {
          ref: 'acme/api',
          name: 'acme/api',
          defaultBranch: 'main',
          language: 'TypeScript',
          archived: false,
          project: { id: mapped, key: 'gh-acme/api-key', state: 'mapped' },
        },
        {
          ref: 'acme/web',
          name: 'acme/web',
          defaultBranch: 'trunk',
          language: null,
          archived: false,
          project: { id: adoptable.id, key: 'acme/web', state: 'adoptable' },
        },
        expect.objectContaining({ name: 'acme/lib', archived: false, project: null }),
        expect.objectContaining({ name: 'acme/old', archived: true, project: null }),
        expect.objectContaining({ name: 'beta/tool', project: null }),
        expect.objectContaining({ name: 'beta/taken', project: null }),
      ]);
      expect(other).toBeTruthy();
    });

    it('does not offer a project of another connection as mapped', async () => {
      const fake = await github([{ owner: 'zed', name: 'one', installationId: 1 }]);
      const a = await connectGitHub(fake);
      const b = await connectGitHub(fake);
      const projectId = await map('zed/one', a.id, 'zed/one');
      expect((await items(a.id)).items[0]!.project).toEqual({
        id: projectId,
        key: 'zed/one',
        state: 'mapped',
      });
      // On the other connection the project is mapped, but not to it, so it is not adoptable.
      expect((await items(b.id)).items[0]!.project).toBeNull();
    });

    it('filters the listed repositories by name without case', async () => {
      const fake = await github([
        { owner: 'acme', name: 'api', installationId: 1 },
        { owner: 'acme', name: 'WebShop', installationId: 1 },
        { owner: 'beta', name: 'shopfront', installationId: 2 },
      ]);
      const { id } = await connectGitHub(fake);
      const res = await items(id, '?filter=SHOP');
      expect(res.items.map((r) => r.name)).toEqual(['acme/WebShop', 'beta/shopfront']);
      expect(res.hasMore).toBe(false);
    });

    it('pages across two installations', async () => {
      const repos: Omit<FakeRepository, 'id'>[] = [];
      for (let i = 0; i < 60; i++) {
        repos.push({ owner: 'one', name: `r${String(i).padStart(2, '0')}`, installationId: 1 });
      }
      for (let i = 0; i < 60; i++) {
        repos.push({ owner: 'two', name: `r${String(i).padStart(2, '0')}`, installationId: 2 });
      }
      const fake = await github(repos);
      const { id } = await connectGitHub(fake);
      const first = await items(id);
      const second = await items(id, '?page=2');
      expect(first.items).toHaveLength(100);
      expect(first.hasMore).toBe(true);
      expect(second.items).toHaveLength(20);
      expect(second.hasMore).toBe(false);
      const names = [...first.items, ...second.items].map((r) => r.name);
      expect(new Set(names).size).toBe(120);
      expect(names[0]).toBe('one/r00');
      expect(names[100]).toBe('two/r40');
    });

    it('answers 502 when GitHub fails, without its words', async () => {
      const fake = await github([{ owner: 'acme', name: 'api', installationId: 1 }]);
      const { id } = await connectGitHub(fake);
      fake.inject('GET', /^\/app\/installations/, {
        status: 500,
        body: { message: 'secret-detail' },
      });
      const res = await listed(id);
      expect(res.statusCode).toBe(502);
      expect(res.body).not.toContain('secret-detail');
    });
  });

  describe('GitLab', () => {
    it('lists the projects with their project state', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 7, path: 'acme/payments/api', defaultBranch: 'develop' });
      fake.addProject({ id: 8, path: 'acme/payments/web' });
      fake.addProject({ id: 9, path: 'acme/docs' });
      fake.addProject({ id: 10, path: 'acme/other' });
      const { id } = await connectGitLab(fake);
      const byId = await map('gl-by-id', id, '7');
      const byPath = await map('gl-by-path', id, 'Acme/Payments/WEB');
      const adoptable = await h.project('acme/docs');

      const { items: rows, hasMore } = await items(id);

      expect(hasMore).toBe(false);
      expect(rows).toEqual([
        {
          ref: '7',
          name: 'acme/payments/api',
          defaultBranch: 'develop',
          language: null,
          archived: false,
          project: { id: byId, key: 'gl-by-id', state: 'mapped' },
        },
        expect.objectContaining({
          ref: '8',
          project: { id: byPath, key: 'gl-by-path', state: 'mapped' },
        }),
        expect.objectContaining({
          ref: '9',
          name: 'acme/docs',
          project: { id: adoptable.id, key: 'acme/docs', state: 'adoptable' },
        }),
        expect.objectContaining({ ref: '10', name: 'acme/other', project: null }),
      ]);
    });

    it('passes the filter on as the search and pages', async () => {
      const fake = await gitlab();
      fake.addProject({ id: 1, path: 'g/Alpha' });
      fake.addProject({ id: 2, path: 'g/beta' });
      const { id } = await connectGitLab(fake);
      const res = await items(id, '?filter=ALPHA&page=1');
      expect(res.items.map((r) => r.name)).toEqual(['g/Alpha']);
      const search = fake.requests.find((r) => r.path === '/projects')!.query;
      expect(new URLSearchParams(search).get('search')).toBe('ALPHA');
    });
  });

  describe('access', () => {
    it('refuses a member without org.projects.create and an outsider', async () => {
      const fake = await gitlab();
      const { id } = await connectGitLab(fake);
      expect((await listed(id, '', member)).statusCode).toBe(403);
      expect((await listed(id, '', outsider)).statusCode).toBe(404);
      expect(fake.requests.filter((r) => r.path === '/projects')).toHaveLength(0);
      const missing = await listed('00000000-0000-4000-8000-000000000000');
      expect(missing.statusCode).toBe(404);
    });

    it('rejects a page below 1', async () => {
      const fake = await gitlab();
      const { id } = await connectGitLab(fake);
      expect((await listed(id, '?page=0')).statusCode).toBe(422);
    });
  });

  describe('ciSetup', () => {
    it('GitLab: available only when the connection allows it', async () => {
      const fake = await gitlab();
      const off = await connectGitLab(fake);
      const on = await connectGitLab(fake, { ciSetupAllowed: true });
      expect(off.ciSetup).toEqual({ available: false, reason: 'not_allowed', missing: [] });
      expect(on.ciSetup).toEqual({ available: true, reason: null, missing: [] });
      expect(await ciSetupOf(h, off.id)).toEqual(off.ciSetup);
      expect(await ciSetupOf(h, on.id)).toEqual(on.ciSetup);
      const patched = await h.ctx.app.inject({
        method: 'PATCH',
        url: `/api/v0/scm-connections/${off.id}`,
        headers: h.orgAdmin.headers,
        payload: { ciSetupAllowed: true },
      });
      expect(patched.json().ciSetup).toEqual({ available: true, reason: null, missing: [] });
    });

    it('GitHub: needs Workflows and Secrets (write) on one installation', async () => {
      const full = await github([{ owner: 'a', name: 'x', installationId: 1, permissions: BOTH }]);
      const none = await github([{ owner: 'a', name: 'x', installationId: 1 }]);
      const workflowsOnly = await github([
        {
          owner: 'a',
          name: 'x',
          installationId: 1,
          permissions: { metadata: 'read', workflows: 'write' },
        },
      ]);
      const split = await github([
        {
          owner: 'a',
          name: 'x',
          installationId: 1,
          permissions: { metadata: 'read', workflows: 'write' },
        },
        {
          owner: 'b',
          name: 'y',
          installationId: 2,
          permissions: { metadata: 'read', secrets: 'write' },
        },
      ]);
      expect((await connectGitHub(full)).ciSetup).toEqual({
        available: true,
        reason: null,
        missing: [],
      });
      expect((await connectGitHub(none)).ciSetup).toEqual({
        available: false,
        reason: 'missing_permissions',
        missing: ['workflows_write', 'secrets_write'],
      });
      expect((await connectGitHub(workflowsOnly)).ciSetup).toEqual({
        available: false,
        reason: 'missing_permissions',
        missing: ['secrets_write'],
      });
      // Each is granted somewhere, but no single installation has both.
      expect((await connectGitHub(split)).ciSetup).toEqual({
        available: false,
        reason: 'missing_permissions',
        missing: [],
      });
    });

    it('GitHub: an SCM error means missing permissions, and the answer is kept for a minute', async () => {
      const fake = await github([{ owner: 'a', name: 'x', installationId: 1, permissions: BOTH }]);
      fake.inject('GET', /^\/app\/installations/, { status: 500, body: { message: 'x' } });
      const created = await connectGitHub(fake);
      expect(created.ciSetup).toEqual({
        available: false,
        reason: 'missing_permissions',
        missing: [],
      });
      // The failure was cached with the answer: no second call within the minute.
      const calls = () =>
        fake.requests.filter((r) => r.path.startsWith('/app/installations')).length;
      const before = calls();
      expect(await ciSetupOf(h, created.id)).toEqual(created.ciSetup);
      expect(calls()).toBe(before);
    });

    it('GitHub: reads the permissions once for repeated lists', async () => {
      const fake = await github([{ owner: 'a', name: 'x', installationId: 1, permissions: BOTH }]);
      const created = await connectGitHub(fake);
      const calls = () =>
        fake.requests.filter((r) => r.path.startsWith('/app/installations')).length;
      const before = calls();
      await ciSetupOf(h, created.id);
      await ciSetupOf(h, created.id);
      expect(calls()).toBe(before);
    });

    it('GitHub: reads only the installations, so one whose repositories fail still counts', async () => {
      const fake = await github([{ owner: 'a', name: 'x', installationId: 1, permissions: BOTH }]);
      fake.inject(
        'POST',
        /access_tokens$/,
        ...Array(5).fill({ status: 403, body: { message: 'no' } }),
      );
      const created = await connectGitHub(fake);
      expect(created.ciSetup).toEqual({ available: true, reason: null, missing: [] });
      const paths = fake.requests.map((r) => r.path.split('?')[0]);
      expect(paths.length).toBeGreaterThan(0);
      expect(new Set(paths)).toEqual(new Set(['/app/installations']));
    });

    it('keeps a failed read for 10 s and a successful one for 60 s', async () => {
      const fake = await github([{ owner: 'a', name: 'x', installationId: 1, permissions: BOTH }]);
      const { id } = await connectGitHub(fake);
      const [row] = await h.ctx.db.select().from(scmConnections).where(eq(scmConnections.id, id));
      let clock = 0;
      const status = createCiSetupStatus({
        deps: { secretKey: h.ctx.config.secretKey, internalHosts: hosts as ReadonlySet<string> },
        publicUrl: PUBLIC_URL,
        warn: () => undefined,
        now: () => clock,
      });
      const calls = () =>
        fake.requests.filter((r) => r.path.startsWith('/app/installations')).length;
      fake.clearRequests();
      fake.inject('GET', /^\/app\/installations/, { status: 500, body: { message: 'x' } });
      expect((await status(row!)).reason).toBe('missing_permissions');
      clock = CI_SETUP_FAILURE_CACHE_MS - 1;
      await status(row!);
      expect(calls()).toBe(1);
      clock = CI_SETUP_FAILURE_CACHE_MS;
      expect((await status(row!)).available).toBe(true);
      expect(calls()).toBe(2);
      clock += CI_SETUP_CACHE_MS - 1;
      await status(row!);
      expect(calls()).toBe(2);
      clock += 1;
      await status(row!);
      expect(calls()).toBe(3);
    });

    it('is no_public_url first, on both providers', async () => {
      const gl = await gitlab();
      const gh = await github([{ owner: 'a', name: 'x', installationId: 1 }]);
      const lab = await connectGitLab(gl, { ciSetupAllowed: true }, bare);
      const hub = await connectGitHub(gh, bare);
      expect(lab.ciSetup).toEqual({ available: false, reason: 'no_public_url', missing: [] });
      expect(hub.ciSetup).toEqual({
        available: false,
        reason: 'no_public_url',
        missing: ['workflows_write', 'secrets_write'],
      });
    });
  });
});
