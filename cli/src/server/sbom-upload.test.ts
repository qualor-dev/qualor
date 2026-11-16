import { writeFileSync } from 'node:fs';
import path from 'node:path';
import { gunzipSync, gzipSync } from 'node:zlib';
import { describe, expect, it } from 'vitest';
import { json, problem, useTestServers } from '../../test/http';
import { useTempDirs } from '../../test/tmp';
import { CliError } from '../errors';
import { silentLogger } from '../log';
import type { HttpResponse } from './http';
import {
  MAX_SBOM_RETRY_ATTEMPTS,
  MAX_SBOM_RETRY_WAIT_MS,
  sbomRetryDelay,
  uploadSbom,
} from './sbom-upload';
import { busyRetryDelay } from './upload';

const tmp = useTempDirs();
const serve = useTestServers();
const TOKEN = 'qlr_prj_secret';
const ep = (url: string) => ({ url, token: TOKEN, timeoutMs: 5_000 });

const answer = {
  version: { id: '0192a4c6-1c2e-7a3b-9f00-0000000000aa', label: '1.4.0', source: 'sbom' },
  format: 'CycloneDX 1.7',
  subject: 'acme/shop:1.4.0',
  distribution: { family: 'debian', version: '12.15' },
  packages: 10,
  osPackages: 8,
  skipped: { noPurl: 1, unsupportedType: 0, duplicate: 2 },
  warnings: [{ code: 'X', message: 'm' }],
  monitoring: { enabled: true, recheckQueued: true },
  extra: 'ignored',
};

function gz(): { file: string; size: number; text: string } {
  const text = JSON.stringify({ bomFormat: 'CycloneDX', pad: 'x'.repeat(50_000) });
  const bytes = gzipSync(Buffer.from(text));
  const file = path.join(tmp(), 'sbom.json.gz');
  writeFileSync(file, bytes);
  return { file, size: bytes.length, text };
}

async function failure(p: Promise<unknown>): Promise<CliError> {
  const err: unknown = await p.catch((e: unknown) => e);
  if (!(err instanceof CliError)) throw new Error(`expected a CliError, got ${String(err)}`);
  return err;
}

describe('uploadSbom', () => {
  it('PUTs the gzip file with the headers the server expects', async () => {
    const { file, size, text } = gz();
    const { url, requests } = await serve((_req, res) => json(res, 201, answer));
    const r = await uploadSbom(
      ep(url),
      { projectKey: 'acme/shop', version: '1.4.0', file, size },
      { log: silentLogger },
    );
    expect(r.status).toBe(201);
    expect(r.answer.version.label).toBe('1.4.0');
    const q = requests[0];
    expect(q?.method).toBe('PUT');
    expect(q?.url).toBe('/api/v0/projects/sbom?projectKey=acme%2Fshop&version=1.4.0');
    expect(q?.headers).toMatchObject({
      'content-type': 'application/json',
      'content-encoding': 'gzip',
      expect: '100-continue',
      'content-length': String(size),
      authorization: `Bearer ${TOKEN}`,
    });
    expect(gunzipSync(q?.body ?? Buffer.alloc(0)).toString()).toBe(text);
  });

  it('leaves out version when none is given, and parses a 200', async () => {
    const { file, size } = gz();
    const { url, requests } = await serve((_req, res) => json(res, 200, answer));
    const r = await uploadSbom(ep(url), { projectKey: 'a/b', file, size }, { log: silentLogger });
    expect(r.status).toBe(200);
    expect(requests[0]?.url).toBe('/api/v0/projects/sbom?projectKey=a%2Fb');
  });

  it('retries 503 UPLOADS_BUSY', async () => {
    const { file, size } = gz();
    let n = 0;
    const waits: number[] = [];
    const { url } = await serve((_req, res) => {
      n += 1;
      if (n < 3) problem(res, 503, 'UPLOADS_BUSY');
      else json(res, 201, answer);
    });
    const r = await uploadSbom(
      ep(url),
      { projectKey: 'a/b', file, size },
      { log: silentLogger, wait: (ms) => Promise.resolve(waits.push(ms)) },
    );
    expect(r.status).toBe(201);
    expect(waits).toHaveLength(2);
  });

  it('gives up with exit 4 when the server stays busy past the attempts', async () => {
    const { file, size } = gz();
    const { url, requests } = await serve((_req, res) => problem(res, 503, 'UPLOADS_BUSY'));
    const err = await failure(
      uploadSbom(
        ep(url),
        { projectKey: 'a/b', file, size },
        { log: silentLogger, wait: () => Promise.resolve() },
      ),
    );
    expect(err.exitCode).toBe(4);
    expect(requests.length).toBeGreaterThan(100);
    expect(requests.length).toBeLessThanOrEqual(MAX_SBOM_RETRY_ATTEMPTS);
  });

  it('refuses 403 with exit 5 and 409 with exit 4, naming the problem', async () => {
    const { file, size } = gz();
    const s403 = await serve((_req, res) => problem(res, 403, 'TOKEN_NOT_ALLOWED'));
    const e403 = await failure(
      uploadSbom(ep(s403.url), { projectKey: 'a/b', file, size }, { log: silentLogger }),
    );
    expect(e403.exitCode).toBe(5);
    const s409 = await serve((_req, res) =>
      json(res, 409, {
        title: 'Label taken',
        detail: 'Use another label',
        code: 'VERSION_LABEL_TAKEN',
        status: 409,
      }),
    );
    const e409 = await failure(
      uploadSbom(ep(s409.url), { projectKey: 'a/b', file, size }, { log: silentLogger }),
    );
    expect(e409.exitCode).toBe(4);
    expect(e409.message).toContain('Use another label');
    expect(e409.message).toContain('VERSION_LABEL_TAKEN');
    expect(e409.message).not.toContain(TOKEN);
  });
});

describe('the busy retry budget', () => {
  it('waits out a slow concurrent upload: more attempts and time than a scan upload', () => {
    const busy = {
      status: 503,
      headers: { 'retry-after': '1' },
      body: Buffer.from(JSON.stringify({ code: 'UPLOADS_BUSY', status: 503, title: 't' })),
    } as unknown as HttpResponse;
    expect(busyRetryDelay(busy, 5, 0)).toBeNull();
    expect(sbomRetryDelay(busy, 5, 0)).toBe(1_000);
    expect(sbomRetryDelay(busy, MAX_SBOM_RETRY_ATTEMPTS, 0)).toBeNull();
    expect(sbomRetryDelay(busy, 2, MAX_SBOM_RETRY_WAIT_MS)).toBeNull();
    expect(MAX_SBOM_RETRY_WAIT_MS).toBeGreaterThanOrEqual(300_000);
  });
});
