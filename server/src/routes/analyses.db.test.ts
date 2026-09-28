import { randomBytes } from 'node:crypto';
import { Readable } from 'node:stream';
import { gzipSync } from 'node:zlib';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  addMember,
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  createUser,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { gzipJson, REPORT_CONTENT_TYPE, sampleReport, uploadReport } from '../../test/reports';
import { analyses, analysisReports, jobs } from '../db/schema';

const KEY = 'acme/api';

describe('POST /analyses and the analysis read API', () => {
  let ctx: TestContext;
  let orgAdmin: Session;
  let outsider: Session;
  let projectId: string;
  let projectToken: string;
  let otherProjectToken: string;
  let uploaderPat: string;
  let readOnlyPat: string;
  let strangerPat: string;

  const post = (
    headers: Record<string, string>,
    body: Buffer | Readable,
    query = `?projectKey=${encodeURIComponent(KEY)}`,
  ) =>
    ctx.app.inject({
      method: 'POST',
      url: `/api/v0/analyses${query}`,
      headers: { 'content-type': REPORT_CONTENT_TYPE, 'content-encoding': 'gzip', ...headers },
      payload: body,
    });
  const mintPat = async (session: Session, scopes: string[]) =>
    (
      await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/tokens',
        headers: session.headers,
        payload: { name: 'pat', scopes },
      })
    ).json().token as string;

  beforeAll(async () => {
    ctx = await createTestContext();
    const admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const defaultOrg = await organizationId(ctx, 'default');
    const otherOrg = (
      await ctx.app.inject({
        method: 'POST',
        url: '/api/v0/organizations',
        headers: admin.headers,
        payload: { key: 'other', name: 'Other' },
      })
    ).json().id;
    const a = await createUser(ctx, { username: 'u-admin' });
    const o = await createUser(ctx, { username: 'u-outsider' });
    await addMember(ctx, defaultOrg, a.id, 'admin');
    await addMember(ctx, otherOrg, o.id, 'member');
    orgAdmin = await login(ctx, a.username, a.password);
    outsider = await login(ctx, o.username, o.password);
    projectId = (await createProject(ctx, orgAdmin, { organizationId: defaultOrg, key: KEY })).id;
    const other = await createProject(ctx, orgAdmin, {
      organizationId: defaultOrg,
      key: 'acme/other',
    });
    projectToken = await createProjectToken(ctx, orgAdmin, projectId);
    otherProjectToken = await createProjectToken(ctx, orgAdmin, other.id);
    uploaderPat = await mintPat(orgAdmin, ['analysis:write']);
    readOnlyPat = await mintPat(orgAdmin, ['read']);
    strangerPat = await mintPat(outsider, ['analysis:write', 'read']);
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('accepts a report with 202, stores the gzip as uploaded and enqueues one job', async () => {
    const body = gzipJson(sampleReport());
    const res = await post(bearer(projectToken), body);
    expect(res.statusCode).toBe(202);
    const { analysisId, status, statusUrl } = res.json();
    expect([status, statusUrl]).toEqual(['queued', `/api/v0/analyses/${analysisId}`]);
    const [analysis] = await ctx.db.select().from(analyses).where(eq(analyses.id, analysisId));
    expect(analysis).toMatchObject({ projectId, status: 'queued', branchId: null });
    expect(analysis!.uploadedByTokenId).not.toBeNull();
    const [stored] = await ctx.db
      .select()
      .from(analysisReports)
      .where(eq(analysisReports.analysisId, analysisId));
    expect(stored!.body.equals(body)).toBe(true);
    expect(stored!.sizeBytes).toBe(body.length);
    const queued = await ctx.db.select().from(jobs).where(eq(jobs.queue, 'analysis'));
    expect(
      queued.find((j) => (j.payload as { analysisId: string }).analysisId === analysisId),
    ).toMatchObject({
      status: 'queued',
      concurrencyKey: `analysis:project:${projectId}`,
    });
  });

  it('accepts an analysis:write PAT of an organisation member', async () => {
    expect((await post(bearer(uploaderPat), gzipJson(sampleReport()))).statusCode).toBe(202);
  });

  it('refuses the wrong project, missing scopes and anonymous uploads (401/403/404)', async () => {
    const body = gzipJson(sampleReport());
    const wrongProject = await post(bearer(otherProjectToken), body);
    expect([wrongProject.statusCode, wrongProject.json().code]).toEqual([404, 'PROJECT_NOT_FOUND']);
    // S11: every rejection of this route closes the connection (see the real-socket test for why).
    expect(wrongProject.headers.connection).toBe('close');
    const stranger = await post(bearer(strangerPat), body);
    expect([stranger.statusCode, stranger.json().code]).toEqual([404, 'PROJECT_NOT_FOUND']);
    const unknown = await post(bearer(uploaderPat), body, '?projectKey=acme%2Fnope');
    expect([unknown.statusCode, unknown.json().code]).toEqual([404, 'PROJECT_NOT_FOUND']);
    const readOnly = await post(bearer(readOnlyPat), body);
    expect([readOnly.statusCode, readOnly.json().code]).toEqual([403, 'INSUFFICIENT_SCOPE']);
    expect(readOnly.headers.connection).toBe('close');
    const anonymous = await post({}, body);
    expect(anonymous.statusCode).toBe(401);
    expect(anonymous.headers.connection).toBe('close');
  });

  it('validates the query, the media type, the encoding and the gzip (422/415)', async () => {
    const body = gzipJson(sampleReport());
    expect((await post(bearer(projectToken), body, '')).json().errors[0].path).toBe(
      'query.projectKey',
    );
    const json = await post(
      { ...bearer(projectToken), 'content-type': 'application/json' },
      Buffer.from('{}'),
    );
    expect(json.statusCode).toBe(415);
    const identity = await post({ ...bearer(projectToken), 'content-encoding': 'identity' }, body);
    expect([identity.statusCode, identity.json().code]).toEqual([415, 'UNSUPPORTED_ENCODING']);
    // RFC 9110: Content-Encoding is compared case-insensitively.
    const upperCase = await post({ ...bearer(projectToken), 'content-encoding': 'GZIP' }, body);
    expect(upperCase.statusCode).toBe(202);
    const notGzip = await post(bearer(projectToken), Buffer.from(JSON.stringify(sampleReport())));
    expect([notGzip.statusCode, notGzip.json().code]).toEqual([422, 'REPORT_INVALID']);
    expect(notGzip.headers.connection).toBe('close');
  });

  describe('with small upload limits', () => {
    let small: TestContext;
    let token: string;
    const KiB = 1024;
    beforeAll(async () => {
      small = await createTestContext({
        config: { upload: { maxCompressedBytes: 64 * KiB, maxDecompressedBytes: 256 * KiB } },
      });
      const admin = await login(small, 'admin', ADMIN_PASSWORD);
      const p = await createProject(small, admin, {
        organizationId: await organizationId(small, 'default'),
        key: KEY,
      });
      token = await createProjectToken(small, admin, p.id);
    });
    afterAll(async () => {
      await small.close();
    });
    const send = (payload: Buffer | Readable) =>
      small.app.inject({
        method: 'POST',
        url: `/api/v0/analyses?projectKey=${encodeURIComponent(KEY)}`,
        headers: {
          ...bearer(token),
          'content-type': REPORT_CONTENT_TYPE,
          'content-encoding': 'gzip',
        },
        payload,
      });

    it('413s a body over the compressed limit, declared or streamed', async () => {
      const big = gzipSync(randomBytes(128 * KiB), { level: 0 });
      const declared = await send(big);
      expect([declared.statusCode, declared.json().code]).toEqual([413, 'REPORT_TOO_LARGE']);
      expect(declared.headers.connection).toBe('close');
      const streamed = await send(
        Readable.from([big.subarray(0, 32 * KiB), big.subarray(32 * KiB)]),
      );
      expect([streamed.statusCode, streamed.json().code]).toEqual([413, 'REPORT_TOO_LARGE']);
      expect(streamed.headers.connection).toBe('close');
    });

    it('413s a gzip bomb at the decompressed limit (Review Focus 2)', async () => {
      const bomb = gzipSync(Buffer.alloc(8 * 1024 * KiB), { level: 9 });
      const res = await send(bomb);
      expect([res.statusCode, res.json().code]).toEqual([413, 'REPORT_TOO_LARGE']);
    });
  });

  describe('upload concurrency (S11)', () => {
    let busy: TestContext;
    let busyToken: string;

    beforeAll(async () => {
      busy = await createTestContext({ config: { maxConcurrentUploads: 2 } });
      const admin = await login(busy, 'admin', ADMIN_PASSWORD);
      const p = await createProject(busy, admin, {
        organizationId: await organizationId(busy, 'default'),
        key: KEY,
      });
      busyToken = await createProjectToken(busy, admin, p.id);
    });
    afterAll(async () => {
      await busy.close();
    });

    /**
     * A gzip body split in two: the first half is available immediately, the second half only
     * once `release()` is called. `started` resolves the moment something first reads from the
     * stream, which — since the route only starts reading after it has already accounted for the
     * upload against the concurrency limit — is real evidence that slot was taken, not a guess
     * based on timing.
     */
    function gatedUpload(): { stream: Readable; started: Promise<void>; release: () => void } {
      const body = gzipJson(sampleReport());
      const half = Math.ceil(body.length / 2);
      let notifyStarted: () => void;
      const started = new Promise<void>((resolve) => {
        notifyStarted = resolve;
      });
      let notifyRelease: () => void;
      const gate = new Promise<void>((resolve) => {
        notifyRelease = resolve;
      });
      let reads = 0;
      const stream = new Readable({
        read() {
          reads += 1;
          if (reads === 1) {
            notifyStarted();
            this.push(body.subarray(0, half));
            return;
          }
          void gate.then(() => {
            this.push(body.subarray(half));
            this.push(null);
          });
        },
      });
      return { stream, started, release: () => notifyRelease() };
    }

    it('503s UPLOADS_BUSY (with Retry-After and Connection: close) when the limit is already held, then admits it once a slot frees up', async () => {
      const held = [gatedUpload(), gatedUpload()];
      const responses = held.map((h) =>
        busy.app.inject({
          method: 'POST',
          url: `/api/v0/analyses?projectKey=${encodeURIComponent(KEY)}`,
          headers: {
            ...bearer(busyToken),
            'content-type': REPORT_CONTENT_TYPE,
            'content-encoding': 'gzip',
          },
          payload: h.stream,
        }),
      );
      // Real synchronization: wait for both uploads to actually start being read (and therefore
      // to have already been counted against the limit) before probing the limit — no sleeps.
      await Promise.all(held.map((h) => h.started));

      const thirdBody = gzipJson(sampleReport());
      const busyRes = await busy.app.inject({
        method: 'POST',
        url: `/api/v0/analyses?projectKey=${encodeURIComponent(KEY)}`,
        headers: {
          ...bearer(busyToken),
          'content-type': REPORT_CONTENT_TYPE,
          'content-encoding': 'gzip',
        },
        payload: thirdBody,
      });
      expect(busyRes.statusCode).toBe(503);
      expect(busyRes.json().code).toBe('UPLOADS_BUSY');
      expect(busyRes.headers['retry-after']).toBeDefined();
      expect(busyRes.headers.connection).toBe('close');

      held.forEach((h) => h.release());
      const settled = await Promise.all(responses);
      for (const res of settled) expect(res.statusCode).toBe(202);

      // The two held slots freed up: a new upload is admitted again.
      const afterRes = await busy.app.inject({
        method: 'POST',
        url: `/api/v0/analyses?projectKey=${encodeURIComponent(KEY)}`,
        headers: {
          ...bearer(busyToken),
          'content-type': REPORT_CONTENT_TYPE,
          'content-encoding': 'gzip',
        },
        payload: gzipJson(sampleReport()),
      });
      expect(afterRes.statusCode).toBe(202);
    });
  });

  it('GET /analyses/{id} serves the uploader and org members, with Retry-After while queued', async () => {
    const id = await uploadReport(ctx, bearer(projectToken), KEY, gzipJson(sampleReport()));
    const byToken = await ctx.app.inject({
      method: 'GET',
      url: `/api/v0/analyses/${id}`,
      headers: bearer(projectToken),
    });
    expect(byToken.statusCode).toBe(200);
    expect(byToken.json()).toMatchObject({
      id,
      projectId,
      status: 'queued',
      branch: null,
      revision: null,
      error: null,
      warnings: [],
      engines: [],
    });
    expect(byToken.headers['retry-after']).toBe('2');
    expect(
      (
        await ctx.app.inject({
          method: 'GET',
          url: `/api/v0/analyses/${id}`,
          headers: orgAdmin.headers,
        })
      ).statusCode,
    ).toBe(200);
    expect(
      (
        await ctx.app.inject({
          method: 'GET',
          url: `/api/v0/analyses/${id}`,
          headers: bearer(uploaderPat),
        })
      ).statusCode,
    ).toBe(200);
    expect(
      (
        await ctx.app.inject({
          method: 'GET',
          url: `/api/v0/analyses/${id}`,
          headers: bearer(otherProjectToken),
        })
      ).statusCode,
    ).toBe(404);
    expect(
      (
        await ctx.app.inject({
          method: 'GET',
          url: `/api/v0/analyses/${id}`,
          headers: outsider.headers,
        })
      ).statusCode,
    ).toBe(404);
    expect(
      (await ctx.app.inject({ method: 'GET', url: `/api/v0/analyses/${id}` })).statusCode,
    ).toBe(401);
    expect(
      (
        await ctx.app.inject({
          method: 'GET',
          url: '/api/v0/analyses/nope',
          headers: orgAdmin.headers,
        })
      ).json().errors[0].path,
    ).toBe('params.id');
  });

  it('GET /branches/{id}/analyses validates and authorises (history content is tested in Task 12)', async () => {
    const mainId = (
      await ctx.app.inject({
        method: 'GET',
        url: `/api/v0/projects/${projectId}`,
        headers: orgAdmin.headers,
      })
    ).json().mainBranch.id;
    const res = await ctx.app.inject({
      method: 'GET',
      url: `/api/v0/branches/${mainId}/analyses`,
      headers: orgAdmin.headers,
    });
    expect([res.statusCode, res.json().items]).toEqual([200, []]);
    expect(
      (
        await ctx.app.inject({
          method: 'GET',
          url: `/api/v0/branches/${mainId}/analyses`,
          headers: outsider.headers,
        })
      ).statusCode,
    ).toBe(404);
    expect(
      (
        await ctx.app.inject({
          method: 'GET',
          url: `/api/v0/branches/${mainId}/analyses`,
          headers: bearer(projectToken),
        })
      ).statusCode,
    ).toBe(403);
    expect(
      (await ctx.app.inject({ method: 'GET', url: `/api/v0/branches/${mainId}/analyses` }))
        .statusCode,
    ).toBe(401);
    expect(
      (
        await ctx.app.inject({
          method: 'GET',
          url: `/api/v0/branches/${mainId}/analyses?limit=0`,
          headers: orgAdmin.headers,
        })
      ).json().errors[0].path,
    ).toBe('query.limit');
  });
});
