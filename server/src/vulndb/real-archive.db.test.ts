import { createHash } from 'node:crypto';
import { createReadStream } from 'node:fs';
import { mkdtemp, open, readFile, rm, stat } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createTestDatabase, type TestDatabase } from '../../test/db';
import { withLocalDatabase } from './local';
import { storeDataset } from './store';

/**
 * A real Trivy `db.tar.gz` (the `ghcr.io/aquasecurity/trivy-db:2` layer tools/analyzers/install.sh
 * pins, about 120 MiB) through the archive reader: stored, validated, then extracted. It runs only
 * when QUALOR_TRIVY_DB_ARCHIVE names the downloaded file; the archive never enters the repository.
 */
const ARCHIVE = process.env['QUALOR_TRIVY_DB_ARCHIVE'] ?? '';

/** bbolt's meta page magic (0xED0CDAED, little-endian) after the 16-byte page header. */
const BOLT_MAGIC = Buffer.from([0xed, 0xda, 0x0c, 0xed]);

async function sha256File(path: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(path)) hash.update(chunk as Buffer);
  return `sha256:${hash.digest('hex')}`;
}

describe.skipIf(ARCHIVE === '')('a real Trivy database archive (QUALOR_TRIVY_DB_ARCHIVE)', () => {
  let t: TestDatabase;
  let dir: string;

  beforeAll(async () => {
    t = await createTestDatabase();
    dir = await mkdtemp(join(tmpdir(), 'qualor-vulndb-real-'));
  });
  afterAll(async () => {
    await rm(dir, { recursive: true, force: true });
    await t.close();
  });

  it('is stored, validated and extracted whole', { timeout: 30 * 60_000 }, async () => {
    const digest = await sha256File(ARCHIVE);
    const started = Date.now();
    const stored = await storeDataset(t.db, {
      kind: 'trivy',
      source: 'upload',
      chunks: createReadStream(ARCHIVE, { highWaterMark: 1024 * 1024 }),
      expectedDigest: digest,
      maxBytes: 2 * 1024 ** 3,
    });
    const storeMs = Date.now() - started;
    if (!('dataset' in stored)) throw new Error(JSON.stringify(stored));
    expect(stored.dataset).toMatchObject({ status: 'ready', digest });
    expect(stored.dataset.builtAt).toBeInstanceOf(Date);

    const extracting = Date.now();
    const got = await withLocalDatabase(t.db, dir, stored.dataset, async (cacheDir) => {
      const db = join(cacheDir, 'db', 'trivy.db');
      const head = Buffer.alloc(20);
      const fh = await open(db, 'r');
      try {
        await fh.read(head, 0, 20, 0);
      } finally {
        await fh.close();
      }
      return {
        size: (await stat(db)).size,
        magic: head.subarray(16, 20),
        sha256: await sha256File(db),
        metadata: JSON.parse(await readFile(join(cacheDir, 'db', 'metadata.json'), 'utf8')) as {
          Version?: unknown;
          UpdatedAt?: unknown;
        },
      };
    });
    const extractMs = Date.now() - extracting;
    if (!('result' in got)) throw new Error(JSON.stringify(got));
    expect(got.result.magic).toEqual(BOLT_MAGIC);
    expect(got.result.metadata.Version).toBe(2);
    expect(new Date(String(got.result.metadata.UpdatedAt)).getTime()).toBe(
      stored.dataset.builtAt?.getTime(),
    );
    console.info(
      JSON.stringify({
        archiveBytes: stored.dataset.sizeBytes,
        storeAndValidateMs: storeMs,
        extractAndHashMs: extractMs,
        trivyDbBytes: got.result.size,
        trivyDbSha256: got.result.sha256,
        builtAt: stored.dataset.builtAt?.toISOString(),
      }),
    );
  });
});
