import type * as fs from 'node:fs';
import type * as fsp from 'node:fs/promises';
import { mkdir, mkdtemp, readdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
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
// Pass-through too: the calls are only recorded, for their order.
vi.mock('node:fs/promises', async (importOriginal) => {
  const actual = await importOriginal<typeof fsp>();
  return { ...actual, mkdir: vi.fn(actual.mkdir), writeFile: vi.fn(actual.writeFile) };
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

  it('marks the extraction directory before it creates anything in it', async () => {
    const got = await storeDataset(t.db, {
      kind: 'trivy',
      source: 'official',
      chunks: once(trivyArchive()),
      maxBytes: 1024 ** 3,
    });
    if (!('dataset' in got)) throw new Error(JSON.stringify(got));
    vi.mocked(mkdir).mockClear();
    vi.mocked(writeFile).mockClear();
    const result = await withLocalDatabase(t.db, dir, got.dataset, () => Promise.resolve('ran'));
    expect(result).toEqual({ result: 'ran' });
    // A crash between two steps must never leave an unmarked tmp-* directory: removeOthers
    // removes only marked ones, so an unmarked one would stay for good.
    const calls = (name: string, fn: typeof mkdir | typeof writeFile) =>
      vi.mocked(fn).mock.calls.map((call, i) => ({
        at: vi.mocked(fn).mock.invocationCallOrder[i] ?? 0,
        what: `${name} ${relative(dir, String(call[0])).replaceAll('\\', '/')}`,
      }));
    const steps = [...calls('mkdir', mkdir), ...calls('writeFile', writeFile)]
      .sort((a, b) => a.at - b.at)
      .map((s) => s.what.replace(/tmp-[0-9a-f]{12}/, 'tmp-*'))
      .filter((s) => s.includes(' tmp-*'));
    expect(steps).toEqual([
      'mkdir tmp-*',
      'writeFile tmp-*/.qualor-vulndb',
      'mkdir tmp-*/db',
      'writeFile tmp-*/db/metadata.json',
    ]);
  });
});
