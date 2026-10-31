import { mkdir, mkdtemp, readdir, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { eq } from 'drizzle-orm';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { metadataJson, tarGz, trivyArchive } from '../../test/trivy-archive';
import { vulndbChunks, vulndbDatasets } from '../db/schema';
import { withLocalDatabase, type LocalResult } from './local';
import { storeDataset, type DatasetRow } from './store';

async function* once(bytes: Buffer): AsyncGenerator<Buffer> {
  await Promise.resolve();
  yield bytes;
}

/** The extraction on its own: the cache dir, or the problem. */
const ensure = async (
  db: TestDatabase['db'],
  dir: string,
  dataset: DatasetRow,
): Promise<LocalResult> => {
  const got = await withLocalDatabase(db, dir, dataset, (cacheDir) => Promise.resolve(cacheDir));
  return 'problem' in got ? got : { cacheDir: got.result };
};

describe('local database copy', () => {
  let t: TestDatabase;
  let dir: string;

  beforeAll(async () => {
    t = await createTestDatabase();
  });
  afterAll(async () => {
    await t.close();
  });
  beforeEach(async () => {
    await t.db.delete(vulndbDatasets);
    dir = await mkdtemp(join(tmpdir(), 'qualor-vulndb-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  async function store(db: Buffer, metadata?: string): Promise<DatasetRow> {
    const got = await storeDataset(t.db, {
      kind: 'trivy',
      source: 'official',
      chunks: once(trivyArchive({ db, metadata })),
      maxBytes: 1024 ** 3,
    });
    if (!('dataset' in got)) throw new Error(JSON.stringify(got));
    return got.dataset;
  }

  const prefix = (d: DatasetRow): string => (d.digest ?? '').replace('sha256:', '').slice(0, 16);

  it('extracts the first dataset into <dir>/<digest prefix>/db', async () => {
    const d = await store(Buffer.from('first database'));
    const got = await ensure(t.db, dir, d);
    expect(got).toEqual({ cacheDir: join(dir, prefix(d)) });
    expect(await readFile(join(dir, prefix(d), 'db', 'trivy.db'), 'utf8')).toBe('first database');
    expect(
      JSON.parse(await readFile(join(dir, prefix(d), 'db', 'metadata.json'), 'utf8')),
    ).toMatchObject({ Version: 2 });
    expect(JSON.parse(await readFile(join(dir, 'current.json'), 'utf8'))).toMatchObject({
      digest: d.digest,
    });
    expect((await readdir(dir)).sort()).toEqual(['current.json', prefix(d)].sort());
  });

  it('is a no-op the second time', async () => {
    const d = await store(Buffer.from('same'));
    await ensure(t.db, dir, d);
    const file = join(dir, prefix(d), 'db', 'trivy.db');
    const before = (await stat(file)).mtimeMs;
    await new Promise((r) => setTimeout(r, 30));
    const again = await ensure(t.db, dir, d);
    expect(again).toEqual({ cacheDir: join(dir, prefix(d)) });
    expect((await stat(file)).mtimeMs).toBe(before);
  });

  it('extracts again when the files of the current copy are gone', async () => {
    const d = await store(Buffer.from('gone'));
    await ensure(t.db, dir, d);
    await rm(join(dir, prefix(d), 'db', 'trivy.db'));
    await ensure(t.db, dir, d);
    expect(await readFile(join(dir, prefix(d), 'db', 'trivy.db'), 'utf8')).toBe('gone');
  });

  it('swaps in a new dataset and removes the old directory', async () => {
    const a = await store(Buffer.from('database a'));
    const b = await store(Buffer.from('database b'));
    await ensure(t.db, dir, a);
    const got = await ensure(t.db, dir, b);
    expect(got).toEqual({ cacheDir: join(dir, prefix(b)) });
    expect((await readdir(dir)).sort()).toEqual(['current.json', prefix(b)].sort());
    expect(JSON.parse(await readFile(join(dir, 'current.json'), 'utf8')).digest).toBe(b.digest);
  });

  it('cleans up a partial tmp-* directory left behind', async () => {
    await mkdir(join(dir, 'tmp-deadbeef0123', 'db'), { recursive: true });
    await writeFile(join(dir, 'tmp-deadbeef0123', 'db', 'trivy.db'), 'half');
    const d = await store(Buffer.from('clean'));
    await ensure(t.db, dir, d);
    expect((await readdir(dir)).sort()).toEqual(['current.json', prefix(d)].sort());
  });

  it('leaves unrelated entries of the directory alone', async () => {
    await mkdir(join(dir, 'keep-me'));
    await writeFile(join(dir, 'keep-me', 'file.txt'), 'mine');
    const a = await store(Buffer.from('own a'));
    const b = await store(Buffer.from('own b'));
    await ensure(t.db, dir, a);
    await ensure(t.db, dir, b);
    expect(await readFile(join(dir, 'keep-me', 'file.txt'), 'utf8')).toBe('mine');
    expect((await readdir(dir)).sort()).toEqual(['current.json', 'keep-me', prefix(b)].sort());
  });

  it('answers DISK, naming the directory, when the directory cannot be created', async () => {
    const d = await store(Buffer.from('disk'));
    const blocker = join(dir, 'a-file');
    await writeFile(blocker, 'x');
    const target = join(blocker, 'vulndb');
    const got = await ensure(t.db, target, d);
    expect(got).toMatchObject({ problem: { code: 'DISK' } });
    if (!('problem' in got)) throw new Error('expected a problem');
    expect(got.problem.message).toContain(target);
  });

  it('answers MISSING when the chunks of the dataset are gone', async () => {
    const d = await store(Buffer.from('pruned'));
    await t.db.delete(vulndbDatasets);
    const got = await ensure(t.db, dir, d);
    expect(got).toMatchObject({ problem: { code: 'MISSING' } });
    expect((await readdir(dir)).filter((n) => n.startsWith('tmp-'))).toEqual([]);
  });

  it('answers MISSING when the archive lacks metadata.json', async () => {
    const d = await store(Buffer.from('nometa'));
    // storeDataset refuses such an archive, so swap the stored bytes afterwards.
    await t.db
      .update(vulndbChunks)
      .set({ data: tarGz([{ name: 'trivy.db', data: 'x' }]) })
      .where(eq(vulndbChunks.datasetId, d.id));
    const got = await ensure(t.db, dir, d);
    expect(got).toMatchObject({ problem: { code: 'MISSING' } });
  });

  it('withLocalDatabase pins the dataset while fn runs, against a concurrent refresh', async () => {
    const a = await store(Buffer.from('pinned a'));
    const b = await store(Buffer.from('pinned b'));
    let release: () => void = () => undefined;
    const gate = new Promise<void>((r) => (release = r));
    let started: () => void = () => undefined;
    const running = new Promise<void>((r) => (started = r));
    const first = withLocalDatabase(t.db, dir, a, async (cacheDir) => {
      started();
      await gate;
      return readFile(join(cacheDir, 'db', 'trivy.db'), 'utf8');
    });
    await running;
    let refreshed = false;
    const second = ensure(t.db, dir, b).then((r) => {
      refreshed = true;
      return r;
    });
    await new Promise((r) => setTimeout(r, 100));
    expect(refreshed).toBe(false);
    release();
    expect(await first).toEqual({ result: 'pinned a' });
    expect(await second).toEqual({ cacheDir: join(dir, prefix(b)) });
  });

  it('withLocalDatabase passes a problem through without calling fn', async () => {
    const d = await store(Buffer.from('x'));
    await t.db.delete(vulndbDatasets);
    let called = false;
    const got = await withLocalDatabase(t.db, dir, d, () => {
      called = true;
      return Promise.resolve(1);
    });
    expect(got).toMatchObject({ problem: { code: 'MISSING' } });
    expect(called).toBe(false);
  });

  it('withLocalDatabase: a stop cuts the extraction, removes the partial copy, calls no fn', async () => {
    const d = await store(Buffer.from('stopped'));
    const stop = new AbortController();
    stop.abort();
    let called = false;
    const got = withLocalDatabase(
      t.db,
      dir,
      d,
      () => {
        called = true;
        return Promise.resolve(1);
      },
      { signal: stop.signal },
    );
    await expect(got).rejects.toMatchObject({ name: 'AbortError' });
    expect(called).toBe(false);
    expect(await readdir(dir)).toEqual([]);
  });

  it('keeps metadata.json as stored', async () => {
    const d = await store(Buffer.from('m'), metadataJson(2));
    await ensure(t.db, dir, d);
    expect(await readFile(join(dir, prefix(d), 'db', 'metadata.json'), 'utf8')).toBe(
      metadataJson(2),
    );
  });
});
