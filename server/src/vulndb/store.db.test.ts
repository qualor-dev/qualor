import { createHash, randomBytes } from 'node:crypto';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import {
  metadataJson,
  tarGz,
  trivyArchive,
  UPDATED_AT,
} from '../../../packages/shared/test/trivy-archive';
import { vulndbChunks, vulndbDatasets } from '../db/schema';
import { OutboundStreamError } from '../http/outbound';
import { readVulndbState, updateVulndbState } from './state';
import {
  CHUNK_BYTES,
  currentDataset,
  makeDatasetCurrent,
  pruneDatasets,
  readDatasetChunks,
  storeDataset,
  type StoreDatasetInput,
} from './store';

const sha256 = (bytes: Buffer): string =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

/** The bytes in pieces of `size`, as a download or an upload delivers them. */
async function* piecesOf(bytes: Buffer, size = 64 * 1024): AsyncGenerator<Buffer> {
  for (let at = 0; at < bytes.length; at += size) {
    await Promise.resolve();
    yield bytes.subarray(at, at + size);
  }
}

async function collect(chunks: AsyncIterable<Buffer>): Promise<Buffer> {
  const parts: Buffer[] = [];
  for await (const part of chunks) parts.push(part);
  return Buffer.concat(parts);
}

describe('dataset storage', () => {
  let t: TestDatabase;
  /** About 17 MiB of incompressible data: three chunks. */
  let big: Buffer;

  beforeAll(async () => {
    t = await createTestDatabase();
    big = trivyArchive({ db: randomBytes(17 * 1024 * 1024) });
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(async () => {
    await t.db.delete(vulndbDatasets);
  });

  const input = (bytes: Buffer, extra: Partial<StoreDatasetInput> = {}): StoreDatasetInput => ({
    kind: 'trivy',
    source: 'official',
    chunks: piecesOf(bytes),
    maxBytes: 2 * 1024 ** 3,
    ...extra,
  });

  async function counts(): Promise<{ datasets: number; chunks: number }> {
    const [d] = await t.db.select({ n: sql<number>`count(*)::int` }).from(vulndbDatasets);
    const [c] = await t.db.select({ n: sql<number>`count(*)::int` }).from(vulndbChunks);
    return { datasets: d?.n ?? -1, chunks: c?.n ?? -1 };
  }

  describe('storeDataset', () => {
    it('stores the archive in 8 MiB chunks and marks it ready', async () => {
      const got = await storeDataset(t.db, input(big, { expectedDigest: sha256(big) }));
      if (!('dataset' in got)) throw new Error(JSON.stringify(got));
      expect(got.dataset).toMatchObject({
        kind: 'trivy',
        source: 'official',
        status: 'ready',
        digest: sha256(big),
        sizeBytes: big.length,
        chunkCount: Math.ceil(big.length / CHUNK_BYTES),
        builtAt: new Date(UPDATED_AT),
      });
      expect(CHUNK_BYTES).toBe(8 * 1024 * 1024);
      expect(got.dataset.chunkCount).toBe(3);
      const sizes = await t.db
        .select({ seq: vulndbChunks.seq, size: sql<number>`length(${vulndbChunks.data})` })
        .from(vulndbChunks)
        .where(eq(vulndbChunks.datasetId, got.dataset.id))
        .orderBy(vulndbChunks.seq);
      expect(sizes).toEqual([
        { seq: 0, size: CHUNK_BYTES },
        { seq: 1, size: CHUNK_BYTES },
        { seq: 2, size: big.length - 2 * CHUNK_BYTES },
      ]);
      expect((await collect(readDatasetChunks(t.db, got.dataset.id))).equals(big)).toBe(true);
    });

    it('accepts an archive without an expected digest, and ./db/ names', async () => {
      const bytes = trivyArchive({ layout: 'dotdb' });
      const got = await storeDataset(t.db, input(bytes, { source: 'upload' }));
      expect(got).toMatchObject({
        dataset: { status: 'ready', source: 'upload', digest: sha256(bytes), chunkCount: 1 },
      });
    });

    it('answers DIGEST_MISMATCH for a wrong digest and leaves no dataset', async () => {
      const got = await storeDataset(
        t.db,
        input(big, { expectedDigest: `sha256:${'0'.repeat(64)}` }),
      );
      expect(got).toMatchObject({ problem: { code: 'DIGEST_MISMATCH' } });
      expect(await counts()).toEqual({ datasets: 0, chunks: 0 });
    });

    it('answers STREAM_FAILED for a stream cut halfway and leaves nothing', async () => {
      async function* cut(): AsyncGenerator<Buffer> {
        yield* piecesOf(big.subarray(0, 9 * 1024 * 1024));
        throw new Error('ECONNRESET');
      }
      const got = await storeDataset(t.db, input(big, { chunks: cut() }));
      expect(got).toMatchObject({ problem: { code: 'STREAM_FAILED' } });
      expect(await counts()).toEqual({ datasets: 0, chunks: 0 });
    });

    it.each([
      ['too_large', 'TOO_LARGE'],
      ['timeout', 'STREAM_FAILED'],
    ] as const)('answers a download that fails with %s as %s', async (cause, code) => {
      async function* failing(): AsyncGenerator<Buffer> {
        yield big.subarray(0, 1024);
        throw new OutboundStreamError(cause, `the download failed: ${cause}`);
      }
      const got = await storeDataset(t.db, input(big, { chunks: failing() }));
      expect(got).toEqual({ problem: { code, message: `the download failed: ${cause}` } });
      expect(await counts()).toEqual({ datasets: 0, chunks: 0 });
    });

    it('answers TOO_LARGE past maxBytes, stops reading, and leaves nothing', async () => {
      let stopped = false;
      async function* endless(): AsyncGenerator<Buffer> {
        try {
          for (;;) yield Buffer.alloc(1024 * 1024);
        } finally {
          stopped = true;
        }
      }
      const got = await storeDataset(
        t.db,
        input(big, { chunks: endless(), maxBytes: 10 * 1024 * 1024 }),
      );
      expect(got).toMatchObject({ problem: { code: 'TOO_LARGE' } });
      expect(stopped).toBe(true);
      expect(await counts()).toEqual({ datasets: 0, chunks: 0 });
    });

    it.each([
      ['no metadata.json', trivyArchive({ metadata: null }), /metadata\.json/],
      ['Version 1', trivyArchive({ metadata: metadataJson(1) }), /Version 1/],
      ['metadata.json that is not JSON', trivyArchive({ metadata: '{"Version":' }), /JSON/],
      ['no UpdatedAt', trivyArchive({ metadata: metadataJson(2, 'yesterday') }), /UpdatedAt/],
      ['no trivy.db', trivyArchive({ db: null }), /trivy\.db/],
      ['an empty trivy.db', trivyArchive({ db: Buffer.alloc(0) }), /trivy\.db/],
      ['a symbolic link', tarGz([{ name: 'trivy.db', type: '2' }]), /only plain files/],
      ['bytes that are not gzip', Buffer.from('not an archive'), /gzip/],
      ['nothing at all', Buffer.alloc(0), /empty/],
    ])('answers INVALID_DATABASE for %s and leaves nothing', async (_what, bytes, message) => {
      const got = await storeDataset(t.db, input(bytes, { source: 'upload' }));
      expect(got).toMatchObject({ problem: { code: 'INVALID_DATABASE' } });
      expect((got as { problem: { message: string } }).problem.message).toMatch(message);
      expect(await counts()).toEqual({ datasets: 0, chunks: 0 });
    });

    it('leaves the datasets that were there', async () => {
      const ok = await storeDataset(t.db, input(trivyArchive()));
      expect('dataset' in ok).toBe(true);
      await storeDataset(t.db, input(trivyArchive({ metadata: null })));
      expect(await counts()).toEqual({ datasets: 1, chunks: 1 });
    });
  });

  describe('makeDatasetCurrent', () => {
    it('names a ready dataset current and clears the last error', async () => {
      const got = await storeDataset(t.db, input(trivyArchive()));
      if (!('dataset' in got)) throw new Error(JSON.stringify(got));
      await updateVulndbState(t.db, (s) => ({ ...s, lastError: { code: 'X', message: 'old' } }));
      expect(await makeDatasetCurrent(t.db, got.dataset.id)).toBe(true);
      const state = await readVulndbState(t.db);
      expect(state.currentDatasetId).toBe(got.dataset.id);
      expect(state.lastError).toBeNull();
    });

    it('answers false for a deleted row and leaves the state alone', async () => {
      const got = await storeDataset(t.db, input(trivyArchive()));
      if (!('dataset' in got)) throw new Error(JSON.stringify(got));
      await t.db.delete(vulndbDatasets).where(eq(vulndbDatasets.id, got.dataset.id));
      const before = await readVulndbState(t.db);
      expect(await makeDatasetCurrent(t.db, got.dataset.id)).toBe(false);
      expect(await readVulndbState(t.db)).toEqual(before);
    });
  });

  describe('readDatasetChunks', () => {
    it('throws for a dataset that does not exist', async () => {
      await expect(
        collect(readDatasetChunks(t.db, '00000000-0000-7000-8000-000000000000')),
      ).rejects.toThrow(/not found/);
    });
  });

  describe('pruneDatasets', () => {
    async function dataset(status: 'ready' | 'incomplete', ageMinutes: number): Promise<string> {
      const [row] = await t.db
        .insert(vulndbDatasets)
        .values({
          kind: 'trivy',
          digest: `sha256:${randomBytes(32).toString('hex')}`,
          sizeBytes: 3,
          source: 'official',
          status,
          chunkCount: 1,
          createdAt: new Date(Date.now() - ageMinutes * 60_000),
        })
        .returning();
      await t.db
        .insert(vulndbChunks)
        .values({ datasetId: row!.id, seq: 0, data: Buffer.from('abc') });
      return row!.id;
    }

    it('keeps the current dataset and the newest other ready one', async () => {
      const oldest = await dataset('ready', 400);
      const old = await dataset('ready', 300);
      const newer = await dataset('ready', 200);
      const newest = await dataset('ready', 100);
      const staleIncomplete = await dataset('incomplete', 61);
      const freshIncomplete = await dataset('incomplete', 5);
      await updateVulndbState(t.db, (s) => ({ ...s, currentDatasetId: oldest }));

      expect(await pruneDatasets(t.db)).toBe(3);

      const left = await t.db.select({ id: vulndbDatasets.id }).from(vulndbDatasets);
      expect(left.map((r) => r.id).sort()).toEqual([oldest, newest, freshIncomplete].sort());
      const chunks = await t.db.select({ id: vulndbChunks.datasetId }).from(vulndbChunks);
      expect(chunks.map((r) => r.id)).not.toContain(old);
      expect(chunks.map((r) => r.id)).not.toContain(newer);
      expect(chunks.map((r) => r.id)).not.toContain(staleIncomplete);
      expect(await currentDataset(t.db, { currentDatasetId: oldest })).toMatchObject({
        id: oldest,
      });
    });

    it('keeps the 2 newest when no dataset is current', async () => {
      await dataset('ready', 30);
      const b = await dataset('ready', 20);
      const c = await dataset('ready', 10);
      await updateVulndbState(t.db, (s) => ({ ...s, currentDatasetId: null }));
      expect(await pruneDatasets(t.db)).toBe(1);
      const left = await t.db.select({ id: vulndbDatasets.id }).from(vulndbDatasets);
      expect(left.map((r) => r.id).sort()).toEqual([b, c].sort());
    });

    it('keeps as many as asked', async () => {
      const a = await dataset('ready', 30);
      await dataset('ready', 20);
      const c = await dataset('ready', 10);
      await updateVulndbState(t.db, (s) => ({ ...s, currentDatasetId: a }));
      expect(await pruneDatasets(t.db, 1)).toBe(1);
      const left = await t.db.select({ id: vulndbDatasets.id }).from(vulndbDatasets);
      expect(left.map((r) => r.id).sort()).toEqual([a, c].sort());
    });
  });
});
