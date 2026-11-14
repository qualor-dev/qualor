import { createHash } from 'node:crypto';
import { closeSync, createReadStream, openSync, readSync, statSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { json, useTestServers } from '../../test/http';
import { useTempDirs } from '../../test/tmp';
import { readDatabaseDate } from '../analyzers/trivy';
import { silentLogger } from '../log';
import { resolveVulnerabilityDb } from './vulndb';

/**
 * A real Trivy `db.tar.gz` (the `ghcr.io/aquasecurity/trivy-db:2` layer tools/analyzers/install.sh
 * pins, about 120 MiB), downloaded from a local fake server and unpacked by the scan. It runs only
 * when QUALOR_TRIVY_DB_ARCHIVE names the downloaded file; the archive never enters the repository.
 */
const ARCHIVE = process.env['QUALOR_TRIVY_DB_ARCHIVE'] ?? '';
const META_PATH = '/api/v0/scanner/vulnerability-db';

const serve = useTestServers();
const tmp = useTempDirs();

async function sha256File(file: string): Promise<string> {
  const hash = createHash('sha256');
  for await (const chunk of createReadStream(file)) hash.update(chunk as Buffer);
  return `sha256:${hash.digest('hex')}`;
}

describe.skipIf(ARCHIVE === '')('a real Trivy database archive (QUALOR_TRIVY_DB_ARCHIVE)', () => {
  it('is downloaded and unpacked whole', { timeout: 30 * 60_000 }, async () => {
    const digest = await sha256File(ARCHIVE);
    const sizeBytes = statSync(ARCHIVE).size;
    const s = await serve((req, res) => {
      const u = new URL(req.url ?? '/', 'http://x');
      if (u.pathname === META_PATH) {
        json(res, 200, {
          serve: true,
          policy: 'daily',
          current: { digest, sizeBytes, builtAt: null },
          accepted: [digest],
        });
        return;
      }
      res.writeHead(200, {
        'content-type': 'application/gzip',
        'content-length': String(sizeBytes),
        etag: `"${digest}"`,
      });
      createReadStream(ARCHIVE).pipe(res);
    });
    const cache = path.join(tmp(), 'cache');
    const started = Date.now();
    const got = await resolveVulnerabilityDb({
      endpoint: { url: s.url, token: 'qlr_prj_real_archive_token', timeoutMs: 60_000 },
      root: tmp(),
      env: { QUALOR_TRIVY_CACHE_DIR: cache },
      log: silentLogger,
      now: () => new Date(),
      tempRoot: tmp(),
    });
    const ms = Date.now() - started;
    try {
      expect(got.warnings).toEqual([]);
      expect(got.dir).toBe(cache);
      const db = path.join(cache, 'db', 'trivy.db');
      // bbolt's meta page magic (0xED0CDAED, little-endian) after the 16-byte page header.
      const head = Buffer.alloc(20);
      const fd = openSync(db, 'r');
      try {
        readSync(fd, head, 0, 20, 0);
      } finally {
        closeSync(fd);
      }
      expect(head.subarray(16, 20)).toEqual(Buffer.from([0xed, 0xda, 0x0c, 0xed]));
      expect(readDatabaseDate(cache)).toMatch(/^\d{4}-\d{2}-\d{2}T/);
      console.info(
        JSON.stringify({
          downloadAndUnpackMs: ms,
          trivyDbBytes: statSync(db).size,
          trivyDbSha256: await sha256File(db),
          updatedAt: readDatabaseDate(cache),
        }),
      );
    } finally {
      await got.cleanup();
    }
  });
});
