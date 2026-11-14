import type * as fs from 'node:fs';
import { mkdtemp, readdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Writable } from 'node:stream';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { trivyArchive } from '../../../packages/shared/test/trivy-archive';
import { vulndbDatasets } from '../db/schema';
import { withLocalDatabase } from './local';
import { storeDataset } from './store';

// A pass-through mock of node:fs: only the test that asks for it makes a write fail.
vi.mock('node:fs', async (importOriginal) => {
  const actual = await importOriginal<typeof fs>();
  return { ...actual, createWriteStream: vi.fn(actual.createWriteStream) };
});

async function* once(bytes: Buffer): AsyncGenerator<Buffer> {
  await Promise.resolve();
  yield bytes;
}

describe('local database copy: a failing disk', () => {
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
    dir = await mkdtemp(join(tmpdir(), 'qualor-vulndb-disk-'));
  });
  afterEach(async () => {
    await rm(dir, { recursive: true, force: true });
  });

  it('answers DISK and leaves no tmp-* directory when a write fails mid-extraction', async () => {
    const got = await storeDataset(t.db, {
      kind: 'trivy',
      source: 'official',
      chunks: once(trivyArchive({ db: Buffer.from('a database that does not fit') })),
      maxBytes: 1024 ** 3,
    });
    if (!('dataset' in got)) throw new Error(JSON.stringify(got));
    const { createWriteStream } = await import('node:fs');
    vi.mocked(createWriteStream).mockImplementationOnce(
      () =>
        new Writable({
          write(_chunk, _encoding, callback) {
            callback(Object.assign(new Error('no space'), { code: 'ENOSPC' }));
          },
        }) as ReturnType<typeof createWriteStream>,
    );
    const result = await withLocalDatabase(t.db, dir, got.dataset, () => Promise.resolve('ran'));
    expect(result).toMatchObject({ problem: { code: 'DISK' } });
    expect((await readdir(dir)).filter((n) => n.startsWith('tmp-'))).toEqual([]);
  });
});
