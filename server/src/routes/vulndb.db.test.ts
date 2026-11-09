import { gzipSync } from 'node:zlib';
import { eq, inArray } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
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
import {
  metadataJson,
  trivyArchive,
  UPDATED_AT,
} from '../../../packages/shared/test/trivy-archive';
import { readVulndbState, updateVulndbState } from '../vulndb/state';
import {
  instanceSettings,
  jobs,
  vulndbDatasets,
  vulnerabilityEpss,
  vulnerabilityKev,
} from '../db/schema';
import { rbacContext } from '../../test/rbac';
import { OFFICIAL_EPSS_URL, OFFICIAL_KEV_URL } from '../vulndb/settings';
import { PRIORITY_FILE_MAX_BYTES } from '../vulndb/priority/parse';
import { VULNDB_UPDATE_QUEUE } from '../vulndb/state';
import { RECHECK_QUEUE } from '../vulnerabilities/recheck';
import type * as Store from '../vulndb/store';

/** pruneDatasets, made to fail while `failing` is set. */
const prune = vi.hoisted(() => ({ failing: false }));
vi.mock('../vulndb/store', async (importOriginal) => {
  const actual = await importOriginal<typeof Store>();
  return {
    ...actual,
    pruneDatasets: async (...args: Parameters<typeof actual.pruneDatasets>) => {
      if (prune.failing) throw new Error('prune failed');
      return actual.pruneDatasets(...args);
    },
  };
});

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
      scanners: { enabled: true, policy: 'daily' },
      officialRepository: expect.stringMatching(/^ghcr\.io\//),
      status: 'no_data',
      current: null,
      lastCheckAt: null,
      nextCheckAt: null,
      lastError: null,
      lastRecheckError: null,
      priority: null,
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
      kevUrl: null,
      epssUrl: null,
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

  it('changes the scanner setting by key, audits it and queues no update or re-check', async () => {
    // With monitoring on (the default), where other changes do queue work.
    const queues = [VULNDB_UPDATE_QUEUE, RECHECK_QUEUE];
    await ctx.db.delete(jobs).where(inArray(jobs.queue, queues));
    const res = await put({ scanners: { policy: 'every' } });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toMatchObject({
      enabled: true,
      scanners: { enabled: true, policy: 'every' },
    });
    expect(lastChanged()).toEqual(['scanners.policy']);
    const off = await put({ scanners: { enabled: false } });
    expect(off.json().scanners).toEqual({ enabled: false, policy: 'every' });
    expect(lastChanged()).toEqual(['scanners.enabled']);
    expect(await ctx.db.select().from(jobs).where(inArray(jobs.queue, queues))).toEqual([]);
  });

  it('answers 422 on an unknown key inside scanners', async () => {
    const res = await put({ scanners: { extra: true } });
    expect(res.statusCode).toBe(422);
    expect((await put({ scanners: { policy: 'weekly' } })).statusCode).toBe(422);
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

    it('moves a waiting run to now, and queues one follow-up while an update runs', async () => {
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
      expect((await updateJobs()).map((j) => j.status).sort()).toEqual(['queued', 'running']);
      expect((await post()).statusCode).toBe(202);
      expect(await updateJobs()).toHaveLength(2);
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

    it('a new interval moves the next check to the last one plus the interval, or now (M4)', async () => {
      await parkLater();
      const last = new Date(Date.now() - 2 * 3_600_000);
      await updateVulndbState(ctx.db, (s) => ({
        ...s,
        lastCheckAt: last.toISOString(),
        nextCheckAt: new Date(last.getTime() + 6 * 3_600_000).toISOString(),
      }));
      const runAt = async () =>
        (
          await ctx.db
            .select({ runAt: jobs.runAt })
            .from(jobs)
            .where(eq(jobs.queue, VULNDB_UPDATE_QUEUE))
        ).map((r) => r.runAt.toISOString());
      // 3 h after the last check: an hour from now.
      expect((await put({ intervalHours: 3 })).statusCode).toBe(200);
      const inThree = new Date(last.getTime() + 3 * 3_600_000).toISOString();
      expect(await runAt()).toEqual([inThree]);
      expect((await get()).json().nextCheckAt).toBe(inThree);
      // 1 h after the last check has passed: now.
      await put({ intervalHours: 1 });
      expect(await dueNow()).toBe(1);
      expect(Date.parse((await get()).json().nextCheckAt)).toBeLessThanOrEqual(Date.now() + 1000);
      // An unchanged interval moves nothing.
      await parkLater();
      await put({ intervalHours: 1 });
      expect(await dueNow()).toBe(0);
    });

    it('a new interval never delays a run that is already due', async () => {
      await ctx.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      const dueSince = new Date(Date.now() - 10 * 60_000);
      await ctx.db.insert(jobs).values({
        id: uuidv7(),
        queue: VULNDB_UPDATE_QUEUE,
        payload: {},
        concurrencyKey: VULNDB_UPDATE_QUEUE,
        runAt: dueSince,
      });
      await updateVulndbState(ctx.db, (s) => ({
        ...s,
        lastCheckAt: new Date(Date.now() - 3_600_000).toISOString(),
      }));
      // 24 h after the last check is far ahead, but the waiting run is due and stays so.
      expect((await put({ intervalHours: 24 })).statusCode).toBe(200);
      const [row] = await ctx.db
        .select({ runAt: jobs.runAt })
        .from(jobs)
        .where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      expect(row?.runAt.toISOString()).toBe(dueSince.toISOString());
    });

    it('a new interval before the first check leaves the first one where it is', async () => {
      await parkLater();
      await put({ intervalHours: 3 });
      expect(await dueNow()).toBe(0);
      expect((await get()).json().nextCheckAt).toBeNull();
    });

    it('a source change while monitoring is off waits for the switch', async () => {
      await put({ enabled: false });
      await parkLater();
      await put({ source: { kind: 'mirror', repository: 'registry.corp:5000/m/t:2' } });
      expect(await dueNow()).toBe(0);
    });

    it('also queues a full re-check while the last re-check failed, whatever the source (R19)', async () => {
      const rechecks = () =>
        ctx.db
          .select({ status: jobs.status, payload: jobs.payload })
          .from(jobs)
          .where(eq(jobs.queue, RECHECK_QUEUE));
      await ctx.db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      expect((await post()).statusCode).toBe(202);
      expect(await rechecks()).toEqual([]);
      const failure = { code: 'RECHECK_FAILED', message: 'Trivy failed (TIMEOUT)' };
      await updateVulndbState(ctx.db, (s) => ({ ...s, lastRecheckError: failure }));
      await put({ source: { kind: 'upload' } });
      const res = await post();
      expect(res.statusCode, res.body).toBe(202);
      expect(res.json()).toMatchObject({ lastRecheckError: failure });
      expect(await rechecks()).toEqual([{ status: 'queued', payload: { all: true } }]);
    });

    it('switching monitoring on also queues a full re-check; other changes do not', async () => {
      const rechecks = () =>
        ctx.db
          .select({ status: jobs.status, payload: jobs.payload })
          .from(jobs)
          .where(eq(jobs.queue, RECHECK_QUEUE));
      await ctx.db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      await put({ enabled: false });
      await put({ intervalHours: 12 });
      await put({ source: { kind: 'upload' } });
      expect(await rechecks()).toEqual([]);
      expect((await put({ enabled: true })).statusCode).toBe(200);
      expect(await rechecks()).toEqual([{ status: 'queued', payload: { all: true } }]);
      await put({ enabled: true });
      expect(await rechecks()).toEqual([{ status: 'queued', payload: { all: true } }]);
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
      // Built now: a fixed date goes stale three days later and the status stops being up_to_date.
      const builtAt = new Date(Math.floor(Date.now() / 1000) * 1000).toISOString();
      const archive = trivyArchive({ metadata: metadataJson(2, builtAt) });
      const res = await upload(archive, admin, 'application/octet-stream');
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json()).toMatchObject({
        status: 'up_to_date',
        lastError: null,
        current: {
          builtAt,
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

    it('queues the re-check before it prunes; a failed prune is logged, never a 500', async () => {
      await ctx.db.delete(jobs).where(eq(jobs.queue, RECHECK_QUEUE));
      prune.failing = true;
      try {
        const res = await upload(trivyArchive());
        expect(res.statusCode, res.body).toBe(200);
        expect(res.json()).toMatchObject({ lastError: null, current: { source: 'upload' } });
      } finally {
        prune.failing = false;
      }
      expect(
        await ctx.db
          .select({ payload: jobs.payload })
          .from(jobs)
          .where(eq(jobs.queue, RECHECK_QUEUE)),
      ).toEqual([{ payload: { all: true } }]);
      expect(ctx.logs.some((l) => l.includes('old vulnerability datasets were not pruned'))).toBe(
        true,
      );
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
            maxDownloads: 4,
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

describe('KEV and EPSS on /system/vulnerability-db (API)', () => {
  const url = '/api/v0/system/vulnerability-db';
  const T0 = new Date('2027-01-01T00:00:00Z');
  let licensed: TestContext;
  let community: TestContext;
  let admin: Session;
  let orgAdmin: Session;
  let communityAdmin: Session;
  let priority = true;

  const kevFile = (ids: string[], released = '2026-10-30T14:22:10.123Z'): Buffer =>
    Buffer.from(
      JSON.stringify({
        catalogVersion: '2026.10.30',
        dateReleased: released,
        vulnerabilities: ids.map((cveID) => ({
          cveID,
          dateAdded: '2026-02-03',
          knownRansomwareCampaignUse: 'Unknown',
        })),
      }),
    );
  const epssFile = (ids: string[]): Buffer =>
    gzipSync(
      Buffer.from(
        `#model_version:v2025.03.14,score_date:2026-10-31T00:00:00Z\ncve,epss,percentile\n${ids
          .map((id) => `${id},0.5,0.75`)
          .join('\n')}\n`,
      ),
    );
  const get = (ctx = licensed, session = admin) =>
    ctx.app.inject({ method: 'GET', url, headers: session.headers });
  const put = (payload: object, ctx = licensed, session = admin) =>
    ctx.app.inject({ method: 'PUT', url, headers: session.headers, payload });
  const upload = (
    dataset: 'kev' | 'epss',
    body: Buffer,
    options: { ctx?: TestContext; session?: Session; type?: string; extra?: object } = {},
  ) =>
    (options.ctx ?? licensed).app.inject({
      method: 'PUT',
      url: `${url}/file/${dataset}`,
      headers: {
        ...(options.session ?? admin).headers,
        'content-type': options.type ?? 'application/octet-stream',
        ...options.extra,
      },
      payload: body,
    });

  beforeAll(async () => {
    licensed = await rbacContext({
      now: () => T0,
      edition: (edition) => ({
        ...edition,
        limits: () => ({
          ...edition.limits(),
          vulnerabilities: { ...edition.limits().vulnerabilities, priority },
        }),
      }),
    });
    admin = await login(licensed, 'admin', ADMIN_PASSWORD);
    const u = await createUser(licensed, { username: 'priority-org-admin' });
    await addMember(licensed, await organizationId(licensed, 'default'), u.id, 'admin');
    orgAdmin = await login(licensed, u.username, u.password);
    community = await createTestContext();
    communityAdmin = await login(community, 'admin', ADMIN_PASSWORD);
  });
  beforeEach(async () => {
    priority = true;
    await licensed.db.delete(jobs).where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
    await licensed.db.delete(vulnerabilityKev);
    await licensed.db.delete(vulnerabilityEpss);
    for (const key of ['vulndb', 'vulndb_state', 'vulndb_priority_state']) {
      await licensed.db.delete(instanceSettings).where(eq(instanceSettings.key, key));
    }
  });
  afterAll(async () => {
    await licensed.close();
    await community.close();
  });

  describe('reads', () => {
    it('has priority null without the feature', async () => {
      const res = await get(community, communityAdmin);
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json().priority).toBeNull();
    });

    it('answers an empty state with the official URLs, then the stored fields', async () => {
      const empty = (await get()).json().priority;
      expect(empty.kev).toEqual({
        status: 'no_data',
        officialUrl: OFFICIAL_KEV_URL,
        source: null,
        dataDate: null,
        storedAt: null,
        lastCheckAt: null,
        sizeBytes: null,
        count: null,
        lastError: null,
      });
      expect(empty.epss.officialUrl).toBe(OFFICIAL_EPSS_URL);
      const body = kevFile(['CVE-2024-0001', 'CVE-2024-0002']);
      expect((await upload('kev', body)).statusCode).toBe(200);
      const kev = (await get()).json().priority.kev;
      expect(kev).toMatchObject({
        status: 'up_to_date',
        source: 'upload',
        dataDate: '2026-10-30T14:22:10.123Z',
        sizeBytes: body.length,
        count: 2,
        lastError: null,
      });
      expect(kev.storedAt).toEqual(expect.any(String));
      expect(kev.lastCheckAt).toEqual(expect.any(String));
    });
  });

  describe('mirror URLs', () => {
    const repository = 'registry.corp:5000/mirror/trivy-db:2';
    it('stores a kevUrl, audits the field and queues an update', async () => {
      const res = await put({
        source: { kind: 'mirror', repository, kevUrl: 'https://mirror.example/kev.json' },
      });
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json().source).toMatchObject({
        kind: 'mirror',
        kevUrl: 'https://mirror.example/kev.json',
        epssUrl: null,
      });
      const events = (await auditRows(licensed)).filter(
        (e) => e.action === 'vulndb.settings_updated',
      );
      expect((events.at(-1)?.details as { changed: string[] }).changed).toContain('source.kevUrl');
      const queued = await licensed.db
        .select({ status: jobs.status })
        .from(jobs)
        .where(eq(jobs.queue, VULNDB_UPDATE_QUEUE));
      expect(queued.map((j) => j.status)).toContain('queued');
      // null clears it.
      const cleared = await put({ source: { kind: 'mirror', repository, kevUrl: null } });
      expect(cleared.json().source.kevUrl).toBeNull();
    });

    it.each([
      ['kevUrl', 'http://x/kev.json'],
      ['kevUrl', 'https://u:p@x/kev.json'],
      ['kevUrl', 'https://x/kev.json#a'],
      ['kevUrl', `https://x/${'a'.repeat(2049 - 'https://x/'.length)}`],
      ['epssUrl', 'ftp://x/epss.csv.gz'],
      ['epssUrl', 'not a url'],
    ])('answers 422 at body.source.%s for %s', async (field, value) => {
      const res = await put({ source: { kind: 'mirror', repository, [field]: value } });
      expect(res.statusCode, res.body).toBe(422);
      expect(JSON.stringify(res.json())).toContain(`body.source.${field}`);
    });
  });

  describe('uploads', () => {
    it('stores a KEV catalog, fills the table and audits it', async () => {
      const body = kevFile(['CVE-2024-0001', 'CVE-2024-0002']);
      const res = await upload('kev', body);
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json().priority.kev.source).toBe('upload');
      expect(await licensed.db.select().from(vulnerabilityKev)).toHaveLength(2);
      const events = (await auditRows(licensed)).filter((e) => e.action === 'vulndb.file_uploaded');
      expect(events.at(-1)?.details).toEqual({
        sizeBytes: body.length,
        builtAt: '2026-10-30T14:22:10.123Z',
        dataset: 'kev',
      });
    });

    it('stores a gzipped EPSS file', async () => {
      const body = epssFile(['CVE-2024-0001', 'CVE-2024-0002', 'CVE-2024-0003']);
      const res = await upload('epss', body, { type: 'application/gzip' });
      expect(res.statusCode, res.body).toBe(200);
      expect(res.json().priority.epss).toMatchObject({ source: 'upload', count: 3 });
      expect(await licensed.db.select().from(vulnerabilityEpss)).toHaveLength(3);
      const events = (await auditRows(licensed)).filter((e) => e.action === 'vulndb.file_uploaded');
      expect(events.at(-1)?.details).toMatchObject({ dataset: 'epss' });
    });

    it('answers 422 INVALID_DATA for a bad file and keeps the old rows', async () => {
      await upload('kev', kevFile(['CVE-2024-0001']));
      const bad = await upload('kev', Buffer.from('{"vulnerabilities": 3}'));
      expect(bad.statusCode, bad.body).toBe(422);
      expect(bad.json().code).toBe('INVALID_DATA');
      expect(bad.json().detail).toEqual(expect.any(String));
      expect(await licensed.db.select().from(vulnerabilityKev)).toHaveLength(1);
      expect((await get()).json().priority.kev.count).toBe(1);
    });

    it('answers 413 TOO_LARGE for a declared length over the limit', async () => {
      const res = await upload('kev', Buffer.from('{}'), {
        extra: { 'content-length': String(PRIORITY_FILE_MAX_BYTES + 1) },
      });
      expect(res.statusCode, res.body).toBe(413);
      expect(res.json()).toMatchObject({
        code: 'TOO_LARGE',
        detail: `The file is larger than ${PRIORITY_FILE_MAX_BYTES} bytes`,
      });
    });

    it.each([
      ['kev', 8 * 1024 * 1024 + 1, 'The file is larger than 8388608 bytes when inflated.'],
      ['epss', 64 * 1024 * 1024 + 1, 'The file is larger than 67108864 bytes when inflated.'],
    ] as const)(
      'answers 413 TOO_LARGE with the parse problem for a small %s gzip that inflates past the cap',
      async (dataset, inflated, detail) => {
        const body = gzipSync(Buffer.alloc(inflated, 0x20));
        expect(body.length).toBeLessThan(PRIORITY_FILE_MAX_BYTES);
        const res = await upload(dataset, body, { type: 'application/gzip' });
        expect(res.statusCode, res.body).toBe(413);
        expect(res.json()).toMatchObject({ code: 'TOO_LARGE', detail });
      },
    );

    it('answers 415 for application/json', async () => {
      const res = await upload('kev', kevFile(['CVE-2024-0001']), { type: 'application/json' });
      expect(res.statusCode, res.body).toBe(415);
    });

    it('is for instance admins only', async () => {
      const denied = await upload('kev', kevFile(['CVE-2024-0001']), { session: orgAdmin });
      expect(denied.statusCode).toBe(403);
      const anonymous = await licensed.app.inject({
        method: 'PUT',
        url: `${url}/file/epss`,
        headers: { 'content-type': 'application/octet-stream' },
        payload: epssFile(['CVE-2024-0001']),
      });
      expect(anonymous.statusCode).toBe(401);
    });

    it.each(['kev', 'epss'] as const)(
      'answers 403 FEATURE_NOT_LICENSED for %s before reading the body',
      async (dataset) => {
        const res = await upload(dataset, Buffer.alloc(1024 * 1024, 1), {
          ctx: community,
          session: communityAdmin,
        });
        expect(res.statusCode, res.body).toBe(403);
        expect(res.json().code).toBe('FEATURE_NOT_LICENSED');
        expect(res.body).toContain('The enterprise feature \\"vuln.priority\\" is not licensed');
        // The feature is checked before the type: an unlicensed wrong type is a 403, not a 415.
        const json = await upload(dataset, Buffer.from('{}'), {
          ctx: community,
          session: communityAdmin,
          type: 'application/json',
        });
        expect(json.statusCode).toBe(403);
      },
    );
  });
});
