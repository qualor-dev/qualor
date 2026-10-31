import { createHash, randomBytes } from 'node:crypto';
import { request as httpRequest, type IncomingMessage } from 'node:http';
import type { AddressInfo } from 'node:net';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
  ADMIN_PASSWORD,
  bearer,
  createProject,
  createProjectToken,
  createTestContext,
  login,
  organizationId,
  type Session,
  type TestContext,
} from '../../test/app';
import { trivyArchive } from '../../../packages/shared/test/trivy-archive';
import { instanceSettings, vulndbDatasets } from '../db/schema';
import { updateVulndbState } from '../vulndb/state';
import type * as Store from '../vulndb/store';
import { makeDatasetCurrent, storeDataset } from '../vulndb/store';
import { downloadTimeouts } from './scanner-vulndb';

/** currentDataset, made slow while `slow.ms` is set: the window in which a client can abort. */
const slow = vi.hoisted(() => ({ ms: 0 }));
vi.mock('../vulndb/store', async (importOriginal) => {
  const actual = await importOriginal<typeof Store>();
  return {
    ...actual,
    currentDataset: async (...args: Parameters<typeof actual.currentDataset>) => {
      if (slow.ms > 0) await new Promise((r) => setTimeout(r, slow.ms));
      return actual.currentDataset(...args);
    },
  };
});

const digestOf = (bytes: Buffer): string =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

describe('/scanner/vulnerability-db (API)', () => {
  let ctx: TestContext;
  let admin: Session;
  let token: string;
  const meta = '/api/v0/scanner/vulnerability-db';
  const asProject = (): Record<string, string> => bearer(token);

  async function store(bytes: Buffer, current: boolean): Promise<string> {
    const got = await storeDataset(ctx.db, {
      kind: 'trivy',
      source: 'upload',
      chunks: (async function* () {
        yield bytes;
      })(),
      maxBytes: 1 << 30,
    });
    if (!('dataset' in got)) throw new Error(JSON.stringify(got));
    if (current) {
      await makeDatasetCurrent(ctx.db, got.dataset.id);
      await updateVulndbState(ctx.db, (s) => ({ ...s, currentDatasetId: got.dataset.id }));
    }
    return got.dataset.digest;
  }
  const settings = (payload: object) =>
    ctx.app.inject({
      method: 'PUT',
      url: '/api/v0/system/vulnerability-db',
      headers: admin.headers,
      payload,
    });

  beforeAll(async () => {
    const probe = await createTestContext();
    const base = probe.config.vulndb;
    await probe.close();
    ctx = await createTestContext({ config: { vulndb: { ...base, maxDownloads: 1 } } });
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const project = await createProject(ctx, admin, {
      organizationId: await organizationId(ctx, 'default'),
      key: 'scanner-db',
    });
    token = await createProjectToken(ctx, admin, project.id);
  });
  beforeEach(async () => {
    await ctx.db.delete(vulndbDatasets);
    await ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb'));
    await ctx.db.delete(instanceSettings).where(eq(instanceSettings.key, 'vulndb_state'));
  });
  afterAll(async () => {
    await ctx.close();
  });

  it('answers the metadata to a project token', async () => {
    const old = await store(trivyArchive({ db: Buffer.from('old') }), false);
    const archive = trivyArchive();
    const digest = await store(archive, true);
    const res = await ctx.app.inject({ method: 'GET', url: meta, headers: asProject() });
    expect(res.statusCode, res.body).toBe(200);
    expect(res.json()).toEqual({
      serve: true,
      policy: 'daily',
      current: { digest, sizeBytes: archive.length, builtAt: expect.any(String) },
      accepted: [digest, old],
    });
  });

  it('follows the policy setting', async () => {
    await store(trivyArchive(), true);
    expect((await settings({ scanners: { policy: 'every' } })).statusCode).toBe(200);
    const res = await ctx.app.inject({ method: 'GET', url: meta, headers: asProject() });
    expect(res.json()).toMatchObject({ serve: true, policy: 'every' });
  });

  it.each([
    ['the instance switch is off', { enabled: false }],
    ['the scanner switch is off', { scanners: { enabled: false } }],
  ])('does not serve when %s', async (_name, patch) => {
    const digest = await store(trivyArchive(), true);
    expect((await settings(patch)).statusCode).toBe(200);
    const res = await ctx.app.inject({ method: 'GET', url: meta, headers: asProject() });
    expect(res.json()).toMatchObject({ serve: false, current: null, accepted: [] });
    const dl = await ctx.app.inject({
      method: 'GET',
      url: `${meta}/${digest.slice(7)}`,
      headers: asProject(),
    });
    expect(dl.statusCode).toBe(404);
  });

  it('does not serve without a dataset', async () => {
    const res = await ctx.app.inject({ method: 'GET', url: meta, headers: asProject() });
    expect(res.json()).toMatchObject({ serve: false, current: null, accepted: [] });
  });

  it('streams the archive by digest with its length and etag', async () => {
    const archive = trivyArchive();
    const old = await store(trivyArchive({ db: Buffer.from('old') }), false);
    const digest = await store(archive, true);
    for (const d of [digest, old]) {
      const res = await ctx.app.inject({
        method: 'GET',
        url: `${meta}/${d.slice(7)}`,
        headers: asProject(),
      });
      expect(res.statusCode, res.body).toBe(200);
      expect(res.headers['content-type']).toBe('application/gzip');
      expect(res.headers['content-length']).toBe(String(res.rawPayload.length));
      expect(res.headers['etag']).toBe(`"${d}"`);
      expect(digestOf(res.rawPayload)).toBe(d);
    }
  });

  it('answers 404 for an unknown digest and 400 for a malformed one', async () => {
    await store(trivyArchive(), true);
    const get = (hex: string) =>
      ctx.app.inject({ method: 'GET', url: `${meta}/${hex}`, headers: asProject() });
    const unknown = await get('0'.repeat(64));
    expect([unknown.statusCode, unknown.json().code]).toEqual([404, 'NOT_FOUND']);
    expect((await get('abc')).statusCode).toBe(400);
    expect((await get('A'.repeat(64))).statusCode).toBe(400);
  });

  it('needs a token', async () => {
    expect((await ctx.app.inject({ method: 'GET', url: meta })).statusCode).toBe(401);
    expect(
      (await ctx.app.inject({ method: 'GET', url: `${meta}/${'0'.repeat(64)}` })).statusCode,
    ).toBe(401);
  });

  describe('the download gate (maxDownloads: 1)', () => {
    let port: number;
    beforeAll(async () => {
      await ctx.app.listen({ port: 0, host: '127.0.0.1' });
      port = (ctx.app.server.address() as AddressInfo).port;
    });

    const open = (hex: string): Promise<{ res: IncomingMessage; abort: () => void }> =>
      new Promise((resolve, reject) => {
        const req = httpRequest(
          { host: '127.0.0.1', port, path: `${meta}/${hex}`, headers: asProject() },
          (res) => resolve({ res, abort: () => req.destroy() }),
        );
        req.on('error', (err) => {
          if ((err as { code?: string }).code !== 'ECONNRESET') reject(err);
        });
        req.end();
      });

    it('refuses a second download, and frees the slot after an abort', async () => {
      // Random bytes do not compress: far more than the sockets buffer, so the stream stays open.
      const big = trivyArchive({ db: randomBytes(48 * 1024 * 1024) });
      const hex = (await store(big, true)).slice(7);
      const first = await open(hex);
      expect(first.res.statusCode).toBe(200);
      first.res.pause();

      const busy = await ctx.app.inject({
        method: 'GET',
        url: `${meta}/${hex}`,
        headers: asProject(),
      });
      expect([busy.statusCode, busy.json().code]).toEqual([503, 'DOWNLOADS_BUSY']);
      expect(busy.headers['retry-after']).toBe('5');

      first.abort();
      let status = 0;
      for (let i = 0; i < 50 && status !== 200; i++) {
        await new Promise((r) => setTimeout(r, 100));
        const next = await open(hex);
        status = next.res.statusCode ?? 0;
        next.abort();
        await new Promise((r) => setTimeout(r, 50));
      }
      expect(status).toBe(200);
    }, 60_000);

    it('frees the slot of a client that aborts while the lookups run', async () => {
      const hex = (await store(trivyArchive(), true)).slice(7);
      slow.ms = 400;
      try {
        await new Promise<void>((resolve) => {
          const req = httpRequest(
            { host: '127.0.0.1', port, path: `${meta}/${hex}`, headers: asProject() },
            () => undefined,
          );
          req.on('error', () => resolve());
          req.end();
          setTimeout(() => req.destroy(), 100);
        });
        await new Promise((r) => setTimeout(r, 1_000));
      } finally {
        slow.ms = 0;
      }
      for (let i = 0; i < 3; i++) {
        const res = await ctx.app.inject({
          method: 'GET',
          url: `${meta}/${hex}`,
          headers: asProject(),
        });
        expect(res.statusCode, res.body).toBe(200);
      }
    });

    it('cuts off a reader that stalls, and frees its slot', async () => {
      const big = trivyArchive({ db: randomBytes(48 * 1024 * 1024) });
      const hex = (await store(big, true)).slice(7);
      const before = downloadTimeouts.stallMs;
      downloadTimeouts.stallMs = 500;
      try {
        const first = await open(hex);
        expect(first.res.statusCode).toBe(200);
        first.res.pause();
        // Never read: only the server's stall timer can free the slot.
        let status = 0;
        for (let i = 0; i < 30 && status !== 200; i++) {
          const next = await open(hex);
          status = next.res.statusCode ?? 0;
          next.abort();
          await new Promise((r) => setTimeout(r, 100));
        }
        expect(status).toBe(200);
      } finally {
        downloadTimeouts.stallMs = before;
      }
    }, 60_000);
  });
});
