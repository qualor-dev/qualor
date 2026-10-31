import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { uuidv7 } from '../db/ids';
import { adminHeaders, auditRows, ssoContext } from '../../test/sso';
import { trivyArchive, UPDATED_AT } from '../../test/trivy-archive';
import { readVulndbState } from '../vulndb/state';
import { instanceSettings, jobs, vulndbDatasets } from '../db/schema';
import { VULNDB_UPDATE_QUEUE } from '../vulndb/state';

describe('/system/vulnerability-db (API)', () => {
  let ctx: TestContext;
  let admin: Session;
  let orgAdmin: Session;
  const url = '/api/v0/system/vulnerability-db';
  const put = (payload: object, session = admin) =>
    ctx.app.inject({ method: 'PUT', url, headers: session.headers, payload });
  const get = (session = admin) => ctx.app.inject({ method: 'GET', url, headers: session.headers });
  const lastChanged = (): unknown => {
    const line = ctx.logs.filter((l) => l.includes('"vulndb settings changed"')).at(-1);
    return line === undefined ? undefined : (JSON.parse(line) as { fields: unknown }).fields;
  };

  beforeAll(async () => {
    ctx = await createTestContext();
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const u = await createUser(ctx, { username: 'vulndb-org-admin' });
    await addMember(ctx, await organizationId(ctx, 'default'), u.id, 'admin');
    orgAdmin = await login(ctx, u.username, u.password);
  });
  beforeEach(async () => {
    await ctx.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
    await ctx.db.delete(vulndbDatasets);
    await ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb'));
    await ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb_state'));
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('is for instance admins only', async () => {
    expect((await get(orgAdmin)).statusCode).toBe(403);
    expect((await put({ enabled: false }, orgAdmin)).statusCode).toBe(403);
    expect((await ctx.app.inject({ method: 'GET', url })).statusCode).toBe(401);
  });

  it('answers the defaults', async () => {
    const res = await get();
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toEqual({
      enabled: true,
      source: { kind: 'official' },
      intervalHours: 6,
      officialRepository: expect.stringMatching(/^ghcr\.io\//),
      status: 'no_data',
      current: null,
      lastCheckAt: null,
      nextCheckAt: null,
      lastError: null,
      lastRecheck: null,
    });
  });

  it('round-trips a mirror with a write-only password and audits names only', async () => {
    const repository = 'registry.corp:5000/mirror/trivy-db:2';
    const res = await put({
      source: { kind: 'mirror', repository, username: 'u', password: 'sekret-pw' },
      intervalHours: 12,
    });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json().source).toEqual({
      kind: 'mirror',
      repository,
      username: 'u',
      passwordSet: true,
      passwordReadable: true,
    });
    expect(res.json().intervalHours).toBe(12);
    expect(res.body).not.toContain('sekret-pw');
    expect((await get()).body).not.toContain('sekret-pw');
    expect(ctx.logs.join('\n')).not.toContain('sekret-pw');
    expect(lastChanged()).toEqual([
      'intervalHours',
      'source.kind',
      'source.repository',
      'source.username',
      'source.password',
    ]);
    const kept = await put({ source: { kind: 'mirror', repository, username: 'u' } });
    expect(kept.json().source.passwordSet).toBe(true);
    expect(lastChanged()).toEqual([]);
    const removed = await put({ source: { kind: 'mirror', repository, password: null } });
    expect(removed.json().source.passwordSet).toBe(false);
    expect(lastChanged()).toEqual(['source.password']);
    expect((await put({ source: { kind: 'upload' } })).json().source).toEqual({ kind: 'upload' });
    expect((await put({ source: { kind: 'official' }, enabled: false })).json()).toMatchObject({
      source: { kind: 'official' },
      status: 'off',
    });
  });

  it('drops the password when the registry host changes, keeps it on the same host', async () => {
    const a = 'registry.corp:5000/mirror/trivy-db:2';
    await put({ source: { kind: 'mirror', repository: a, username: 'u', password: 'pw' } });
    const sameHost = await put({
      source: { kind: 'mirror', repository: 'REGISTRY.corp:5000/other/path:3'.toLowerCase() },
    });
    expect(sameHost.json().source).toMatchObject({ passwordSet: true, username: 'u' });
    expect(lastChanged()).toEqual(['source.repository']);
    const moved = await put({ source: { kind: 'mirror', repository: 'evil.example/m/t:2' } });
    expect(moved.json().source).toMatchObject({ passwordSet: false, username: 'u' });
    expect(lastChanged()).toEqual(['source.repository', 'source.password']);
    await put({ source: { kind: 'mirror', repository: a, password: 'pw2' } });
    const withPassword = await put({
      source: { kind: 'mirror', repository: 'other.host/m/t:2', password: 'pw3' },
    });
    expect(withPassword.json().source.passwordSet).toBe(true);
  });

  it('answers 422 on a bad repository and on intervalHours 5', async () => {
    for (const repository of ['Bad Repo', 'nohost', 'r.io/a/b', `r.io/a/${'b'.repeat(520)}:1`]) {
      const res = await put({ source: { kind: 'mirror', repository } });
      expect(res.statusCode, repository).toBe(422);
      expect(JSON.stringify(res.json())).toContain('body.source.repository');
    }
    expect((await put({ intervalHours: 5 })).statusCode).toBe(422);
    expect((await put({ extra: 1 })).statusCode).toBe(422);
  });

  it('reports the current dataset and a running update', async () => {
    const id = uuidv7();
    const builtAt = new Date(Date.now() - 3_600_000);
    const digest = `sha256:${'b'.repeat(64)}`;
    await ctx.db.insert(vulndbDatasets).values({
      id,
      kind: 'trivy',
      digest,
      sizeBytes: 123,
      builtAt,
      source: 'official',
      status: 'ready',
      chunkCount: 1,
    });
    await ctx.db.insert(instanceSettings).values({
      key: 'vulndb_state',
      value: { currentDatasetId: id, lastCheckAt: '2026-11-01T00:00:00.000Z' },
    });
    const res = await get();
    expect(res.json()).toMatchObject({
      status: 'up_to_date',
      current: { builtAt: builtAt.toISOString(), sizeBytes: 123, source: 'official', digest },
      lastCheckAt: '2026-11-01T00:00:00.000Z',
    });
    await ctx.db.insert(jobs).values({
      id: uuidv7(),
      queue: VULNDB_UPDATE_QUEUE,
      payload: {},
      status: 'running',
      concurrencyKey: 'vulndb.update',
    });
    expect((await get()).json().status).toBe('updating');
  });

  describe('Update now and its triggers (R5)', () => {
    const post = (session = admin) =>
      ctx.app.inject({ method: 'POST', url: `${url}/update`, headers: session.headers });
    const updateJobs = () =>
      ctx.db
        .select({ status: jobs.status, key: jobs.concurrencyKey })
        .from(jobs)
        .where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
    /** A waiting run a day away, as the schedule leaves it. */
    const parkLater = async () => {
      await ctx.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      await ctx.db.insert(jobs).values({
        id: uuidv7(),
        queue: VULNDB_UPDATE_QUEUE,
        payload: {},
        concurrencyKey: VULNDB_UPDATE_QUEUE,
        runAt: new Date(Date.now() + 86_400_000),
      });
    };
    const dueNow = async () => {
      const rows = await ctx.db
        .select({ runAt: jobs.runAt })
        .from(jobs)
        .where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      return rows.filter((r) => r.runAt.getTime() <= Date.now() + 1000).length;
    };

    it('is for instance admins only', async () => {
      expect((await post(orgAdmin)).statusCode).toBe(403);
      expect((await ctx.app.inject({ method: 'POST', url: `${url}/update` })).statusCode).toBe(401);
      expect(await updateJobs()).toEqual([]);
    });

    it('answers 202 with the settings and leaves one queued job after two presses', async () => {
      const first = await post();
      expect(first.statusCode, first.body).toBe(202);
      expect(first.json()).toMatchObject({ enabled: true, status: 'no_data' });
      expect((await post()).statusCode).toBe(202);
      expect(await updateJobs()).toEqual([{ status: 'queued', key: VULNDB_UPDATE_QUEUE }]);
    });

    it('moves a waiting run to now, and adds none while an update runs', async () => {
      await parkLater();
      expect((await post()).statusCode).toBe(202);
      expect(await dueNow()).toBe(1);
      await ctx.db
        .update(jobs)
        .set({ status: 'running' })
        .where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      const res = await post();
      expect(res.statusCode).toBe(202);
      expect(res.json().status).toBe('updating');
      expect(await updateJobs()).toEqual([{ status: 'running', key: VULNDB_UPDATE_QUEUE }]);
    });

    it('switching monitoring on moves the run to now; other changes leave it', async () => {
      await put({ enabled: false });
      await parkLater();
      expect((await put({ intervalHours: 12 })).statusCode).toBe(200);
      expect(await dueNow()).toBe(0);
      await put({ enabled: true });
      expect(await dueNow()).toBe(1);
    });

    it('choosing a mirror, changing its repository or credentials, or going back to official runs now', async () => {
      const a = 'registry.corp:5000/mirror/trivy-db:2';
      await parkLater();
      await put({ source: { kind: 'mirror', repository: a, username: 'u', password: 'pw' } });
      expect(await dueNow()).toBe(1);
      await parkLater();
      await put({ source: { kind: 'mirror', repository: a } });
      expect(await dueNow()).toBe(0);
      await put({ source: { kind: 'mirror', repository: 'registry.corp:5000/other/trivy-db:2' } });
      expect(await dueNow()).toBe(1);
      await parkLater();
      await put({
        source: {
          kind: 'mirror',
          repository: 'registry.corp:5000/other/trivy-db:2',
          password: 'new',
        },
      });
      expect(await dueNow()).toBe(1);
      await parkLater();
      await put({ source: { kind: 'upload' } });
      expect(await dueNow()).toBe(0);
      await put({ source: { kind: 'official' } });
      expect(await dueNow()).toBe(1);
      await parkLater();
      await put({ source: { kind: 'official' } });
      expect(await dueNow()).toBe(0);
    });

    it('a source change while monitoring is off waits for the switch', async () => {
      await put({ enabled: false });
      await parkLater();
      await put({ source: { kind: 'mirror', repository: 'registry.corp:5000/m/t:2' } });
      expect(await dueNow()).toBe(0);
    });
  });

  describe('PUT /system/vulnerability-db/file', () => {
    const fileUrl = `${url}/file`;
    const upload = (body: Buffer, session = admin, contentType = 'application/gzip') =>
      ctx.app.inject({
        method: 'PUT',
        url: fileUrl,
        headers: { ...session.headers, 'content-type': contentType },
        payload: body,
      });

    it('is for instance admins only', async () => {
      expect((await upload(trivyArchive(), orgAdmin)).statusCode).toBe(403);
      expect(
        (
          await ctx.app.inject({
            method: 'PUT',
            url: fileUrl,
            headers: { 'content-type': 'application/gzip' },
            payload: trivyArchive(),
          })
        ).statusCode,
      ).toBe(401);
    });

    it('makes a valid archive current and audits it', async () => {
      const archive = trivyArchive();
      const res = await upload(archive, admin, 'application/octet-stream');
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toMatchObject({
        status: 'up_to_date',
        lastError: null,
        current: {
          builtAt: new Date(UPDATED_AT).toISOString(),
          sizeBytes: archive.length,
          source: 'upload',
        },
      });
      const [row] = await ctx.db.select().from(vulndbDatasets);
      expect((await readVulndbState(ctx.db)).currentDatasetId).toBe(row?.id);
    });

    it('refuses before reading the body: wrong type, non-admin, anonymous', async () => {
      const big = Buffer.alloc(8 * 1024 * 1024, 1);
      const json = await ctx.app.inject({
        method: 'PUT',
        url: fileUrl,
        headers: { ...admin.headers, 'content-type': 'application/json' },
        payload: big,
      });
      expect(json.statusCode, json.body).toBe(415);
      const nonAdmin = await ctx.app.inject({
        method: 'PUT',
        url: fileUrl,
        headers: {
          ...orgAdmin.headers,
          'content-type': 'application/octet-stream',
          expect: '100-continue',
        },
        payload: big,
      });
      expect(nonAdmin.statusCode).toBe(403);
      const anonymousJson = await ctx.app.inject({
        method: 'PUT',
        url: fileUrl,
        headers: { 'content-type': 'application/json' },
        payload: big,
      });
      expect(anonymousJson.statusCode).toBe(401);
      expect(await ctx.db.select().from(vulndbDatasets)).toHaveLength(0);
    });

    it('audits the upload with its size and build time', async () => {
      const licensed = await ssoContext();
      try {
        const archive = trivyArchive();
        const res = await licensed.app.inject({
          method: 'PUT',
          url: fileUrl,
          headers: { ...(await adminHeaders(licensed)), 'content-type': 'application/gzip' },
          payload: archive,
        });
        expect(res.statusCode, res.body).toBe(200);
        const event = (await auditRows(licensed)).find((e) => e.action === 'vulndb.file_uploaded');
        expect(event?.details).toEqual({
          sizeBytes: archive.length,
          builtAt: new Date(UPDATED_AT).toISOString(),
        });
      } finally {
        await licensed.close();
      }
    });

    it('answers 422 for an invalid archive and keeps the current dataset', async () => {
      const ok = await upload(trivyArchive());
      const digest = ok.json().current.digest;
      const bad = await upload(trivyArchive({ metadata: null }));
      expect(bad.statusCode, bad.body).toBe(422);
      expect(bad.json()).toMatchObject({ code: 'INVALID_DATABASE' });
      expect(bad.json().detail).toContain('metadata.json');
      expect((await get()).json().current.digest).toBe(digest);
      expect(await ctx.db.select().from(vulndbDatasets)).toHaveLength(1);
    });

    it('answers 413 TOO_LARGE for a file over the limit', async () => {
      const small = await createTestContext({
        config: {
          vulndb: {
            dir: '/var/cache/qualor/vulndb',
            trivyPath: '/usr/local/bin/trivy',
            internalHosts: new Set(),
            uploadMaxBytes: 64,
          },
        },
      });
      try {
        const session = await login(small, 'admin', ADMIN_PASSWORD);
        const res = await small.app.inject({
          method: 'PUT',
          url: fileUrl,
          headers: { ...session.headers, 'content-type': 'application/gzip' },
          payload: trivyArchive(),
        });
        expect(res.statusCode, res.body).toBe(413);
        expect(res.json().code).toBe('TOO_LARGE');
      } finally {
        await small.close();
      }
    });
  });
});
