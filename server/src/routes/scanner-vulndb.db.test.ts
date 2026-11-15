import { createHash, randomBytes } from 'node:crypto';
import { request as httpRequest, type IncomingMessage } from 'node:http';
import type { AddressInfo, Socket } from 'node:net';
import { eq } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import {
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
import { trivyArchive } from '../../../packages/shared/test/trivy-archive';
import { instanceSettings, vulndbDatasets } from '../db/schema';
import { updateVulndbState } from '../vulndb/state';
import type * as Store from '../vulndb/store';
import { makeDatasetCurrent, storeDataset } from '../vulndb/store';
import { downloadTimeouts } from './scanner-vulndb';

/** currentDataset, made slow while `slow.ms` is set: the window in which a client can abort. */
const slow = vi.hoisted(() => ({ ms: 0 }));
/** How many dataset reads have reached their end: a download has yielded its last slice. */
const readsDone = vi.hoisted(() => ({ count: 0 }));
vi.mock('../vulndb/store', async (importOriginal) => {
  const actual = await importOriginal<typeof Store>();
  return {
    ...actual,
    currentDataset: async (...args: Parameters<typeof actual.currentDataset>) => {
      if (slow.ms > 0) await new Promise((r) => setTimeout(r, slow.ms));
      return actual.currentDataset(...args);
    },
    readDatasetChunks: async function* (...args: Parameters<typeof actual.readDatasetChunks>) {
      yield* actual.readDatasetChunks(...args);
      readsDone.count++;
    },
  };
});

const digestOf = (bytes: Buffer): string =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

describe('/scanner/vulnerability-db (API)', () => {
  let ctx: TestContext;
  let admin: Session;
  /** QUALOR_DEMO_USER's session, and an ordinary user's. */
  let guest: Session;
  let reader: Session;
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
    ctx = await createTestContext({
      config: { vulndb: { ...base, maxDownloads: 1 }, demoUser: 'guest' },
    });
    admin = await login(ctx, 'admin', ADMIN_PASSWORD);
    const g = await createUser(ctx, { username: 'guest' });
    guest = await login(ctx, g.username, g.password);
    const r = await createUser(ctx, { username: 'scanner-db-reader' });
    reader = await login(ctx, r.username, r.password);
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

  it('offers the demo account no database, and an ordinary session the same as a token', async () => {
    const digest = await store(trivyArchive(), true);
    const get = (url: string, s: Session) =>
      ctx.app.inject({ method: 'GET', url, headers: s.headers });
    const demoMeta = await get(meta, guest);
    expect(demoMeta.statusCode, demoMeta.body).toBe(200);
    expect(demoMeta.json()).toEqual({ serve: false, policy: 'daily', current: null, accepted: [] });
    const demoDownload = await get(`${meta}/${digest.slice(7)}`, guest);
    expect([demoDownload.statusCode, demoDownload.json().code]).toEqual([404, 'NOT_FOUND']);

    expect((await get(meta, reader)).json()).toMatchObject({ serve: true, current: { digest } });
    const download = await get(`${meta}/${digest.slice(7)}`, reader);
    expect(download.statusCode, download.body).toBe(200);
    expect(digestOf(download.rawPayload)).toBe(digest);
  });

  it('serves a large archive through inject without a stall cut', async () => {
    // Under inject the socket's bytesWritten stays undefined: progress is what the stream yields.
    const big = trivyArchive({ db: randomBytes(48 * 1024 * 1024) });
    const digest = await store(big, true);
    const before = downloadTimeouts.stallMs;
    downloadTimeouts.stallMs = 300;
    try {
      const res = await ctx.app.inject({
        method: 'GET',
        url: `${meta}/${digest.slice(7)}`,
        headers: asProject(),
      });
      expect(res.statusCode).toBe(200);
      expect(digestOf(res.rawPayload)).toBe(digest);
    } finally {
      downloadTimeouts.stallMs = before;
    }
  }, 60_000);

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

    /** A download; `fresh` opens a connection of its own, never a kept-alive one. */
    const open = (
      hex: string,
      { fresh = false }: { fresh?: boolean } = {},
    ): Promise<{ res: IncomingMessage; abort: () => void }> =>
      new Promise((resolve, reject) => {
        const req = httpRequest(
          {
            host: '127.0.0.1',
            port,
            path: `${meta}/${hex}`,
            headers: asProject(),
            ...(fresh ? { agent: false } : {}),
          },
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

    it('ends a download whose dataset is deleted mid-stream, and frees the slot', async () => {
      const big = trivyArchive({ db: randomBytes(48 * 1024 * 1024) });
      const hex = (await store(big, true)).slice(7);
      const first = await open(hex);
      expect(first.res.statusCode).toBe(200);
      first.res.pause();
      // pruneDatasets refuses the current dataset, so delete directly; the chunks cascade.
      await ctx.db.delete(vulndbDatasets);
      const closed = new Promise<boolean>((resolve) => {
        first.res.on('error', () => undefined);
        first.res.on('close', () => resolve(first.res.complete));
      });
      first.res.resume();
      expect(await closed).toBe(false);

      const next = (await store(trivyArchive(), true)).slice(7);
      let status = 0;
      for (let i = 0; i < 50 && status !== 200; i++) {
        const again = await open(next);
        status = again.res.statusCode ?? 0;
        again.abort();
        await new Promise((r) => setTimeout(r, 100));
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

    it('keeps a reader that is slow but steady, long after the stream read ahead of it', async () => {
      const big = trivyArchive({ db: randomBytes(48 * 1024 * 1024) });
      const digest = await store(big, true);
      const before = downloadTimeouts.stallMs;
      // 1.5 s, not less: a loaded test host (the full suite in parallel) delays timers by hundreds
      // of milliseconds, and the stall check must not mistake that for a stalled reader.
      downloadTimeouts.stallMs = 1500;
      try {
        const { res } = await open(digest.slice(7));
        expect(res.statusCode).toBe(200);
        const hash = createHash('sha256');
        let received = 0;
        let sincePause = 0;
        // About 5 MiB/s: the 48 MiB take about 10 s, many times stallMs, and the server has read
        // every chunk from the database long before the socket sent it.
        await new Promise<void>((resolve, reject) => {
          res.on('data', (chunk: Buffer) => {
            hash.update(chunk);
            received += chunk.length;
            sincePause += chunk.length;
            if (sincePause >= 1024 * 1024) {
              sincePause = 0;
              res.pause();
              setTimeout(() => res.resume(), 200);
            }
          });
          res.on('end', resolve);
          res.on('error', reject);
          res.on('close', () => {
            if (!res.complete) reject(new Error(`cut off after ${received} bytes`));
          });
        });
        expect(received).toBe(big.length);
        expect(`sha256:${hash.digest('hex')}`).toBe(digest);
      } finally {
        downloadTimeouts.stallMs = before;
      }
    }, 60_000);

    /**
     * The server's side of the next connection passes each write on `delayMs` late, as the socket
     * of a reader that takes a slice at a time does, and none at all once `stopped()`. The client
     * itself reads at once, so no OS socket buffer decides the pace.
     */
    function throttleNextConnection(delayMs: number, stopped: () => boolean = () => false): void {
      ctx.app.server.once('connection', (socket: Socket) => {
        const write = socket._write.bind(socket);
        const writev = socket._writev?.bind(socket);
        const later = (pass: () => void) =>
          setTimeout(() => {
            if (!stopped()) pass();
          }, delayMs);
        socket._write = (chunk, encoding, callback) =>
          later(() => write(chunk, encoding, callback));
        if (writev) socket._writev = (chunks, callback) => later(() => writev(chunks, callback));
      });
    }

    it('keeps a reader that takes the last slices slowly but steadily', async () => {
      // Two slices. The stream yields the last one while the first is still going out (it reads
      // one slice ahead), so two writes remain after the last yield: 4.3 s, longer than stallMs,
      // while each write takes 2.15 s, less.
      const archive = trivyArchive({ db: randomBytes(400 * 1024) });
      const digest = await store(archive, true);
      const before = downloadTimeouts.stallMs;
      downloadTimeouts.stallMs = 3000;
      try {
        throttleNextConnection(2150);
        const { res } = await open(digest.slice(7), { fresh: true });
        expect(res.statusCode).toBe(200);
        const hash = createHash('sha256');
        let received = 0;
        await new Promise<void>((resolve, reject) => {
          res.on('data', (chunk: Buffer) => {
            hash.update(chunk);
            received += chunk.length;
          });
          res.on('end', resolve);
          res.on('error', reject);
          res.on('close', () => {
            if (!res.complete) reject(new Error(`cut off after ${received} bytes`));
          });
        });
        expect(received).toBe(archive.length);
        expect(`sha256:${hash.digest('hex')}`).toBe(digest);
      } finally {
        downloadTimeouts.stallMs = before;
      }
    }, 60_000);

    it('cuts off a reader that stops at the last slice, and frees its slot', async () => {
      const big = trivyArchive({ db: randomBytes(2 * 1024 * 1024) });
      const hex = (await store(big, true)).slice(7);
      const before = downloadTimeouts.stallMs;
      downloadTimeouts.stallMs = 500;
      const reads = readsDone.count;
      try {
        // Takes a slice every 50 ms until the dataset has been read to its end, then nothing.
        throttleNextConnection(50, () => readsDone.count > reads);
        const first = await open(hex, { fresh: true });
        expect(first.res.statusCode).toBe(200);
        let received = 0;
        const complete = new Promise<boolean>((resolve) => {
          first.res.on('data', (chunk: Buffer) => {
            received += chunk.length;
          });
          first.res.on('error', () => undefined);
          first.res.on('close', () => resolve(first.res.complete));
        });
        // Only the server's stall timer can free the slot.
        let status = 0;
        for (let i = 0; i < 30 && status !== 200; i++) {
          const next = await open(hex);
          status = next.res.statusCode ?? 0;
          next.abort();
          await new Promise((r) => setTimeout(r, 100));
        }
        expect(status).toBe(200);
        expect(readsDone.count).toBeGreaterThan(reads);
        expect(await complete).toBe(false);
        expect(received).toBeLessThan(big.length);
      } finally {
        downloadTimeouts.stallMs = before;
      }
    }, 60_000);
  });
});
