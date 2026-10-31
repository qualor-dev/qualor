/**
 * Runtime smoke check for the vulnerability database download, for the Bun-compiled CLI:
 * `bun cli/test/smoke/vulndb-download.ts`. A slow transfer that outlasts the endpoint's
 * `timeoutMs` must succeed, and a wrong digest must fail without leftovers.
 */
import { createHash, randomBytes } from 'node:crypto';
import { mkdtempSync, readdirSync, readFileSync, rmSync } from 'node:fs';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { downloadServerVulndb } from '../../src/server/vulndb';

const archive = randomBytes(4 * 1024 * 1024);
const hex = createHash('sha256').update(archive).digest('hex');
const CHUNK = 256 * 1024;
const STEP_MS = 190; // 16 chunks, about 3 s in all

const server = createServer((_req, res) => {
  res.writeHead(200, { 'content-type': 'application/gzip', 'content-length': archive.length });
  let offset = 0;
  const tick = setInterval(() => {
    res.write(archive.subarray(offset, offset + CHUNK));
    offset += CHUNK;
    if (offset >= archive.length) {
      clearInterval(tick);
      res.end();
    }
  }, STEP_MS);
  res.on('close', () => clearInterval(tick));
});
await new Promise<void>((r) => server.listen(0, '127.0.0.1', r));
const url = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
const ep = { url, token: 'qlr_smoke_token_123456', timeoutMs: 1000 };
const dir = mkdtempSync(path.join(os.tmpdir(), 'qualor-vulndb-smoke-'));
const problems: string[] = [];
try {
  const dest = path.join(dir, 'db.tar.gz');
  const started = Date.now();
  const ok = await downloadServerVulndb(ep, `sha256:${hex}`, archive.length, dest);
  const took = Date.now() - started;
  if (!ok.ok) problems.push(`download failed: ${ok.reason}`);
  else if (createHash('sha256').update(readFileSync(dest)).digest('hex') !== hex)
    problems.push('downloaded file differs');
  if (took <= ep.timeoutMs) problems.push(`transfer took only ${took} ms`);
  console.log(`good download: ${ok.ok ? 'ok' : 'failed'} in ${took} ms`);

  const bad = path.join(dir, 'bad.tar.gz');
  const wrong = `sha256:${'0'.repeat(64)}`;
  const failed = await downloadServerVulndb(ep, wrong, archive.length, bad);
  if (failed.ok) problems.push('a wrong digest succeeded');
  const left = readdirSync(dir).filter((f) => f !== 'db.tar.gz');
  if (left.length > 0) problems.push(`leftovers: ${left.join(', ')}`);
  console.log(`wrong digest: ${failed.ok ? 'ok?!' : failed.reason}`);
} finally {
  server.closeAllConnections();
  server.close();
  rmSync(dir, { recursive: true, force: true });
}
if (problems.length > 0) {
  console.error(`FAIL: ${problems.join('; ')}`);
  process.exit(1);
}
console.log('PASS');
