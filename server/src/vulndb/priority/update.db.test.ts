import { createHash } from 'node:crypto';
import { gzipSync } from 'node:zlib';
import { eq, sql } from 'drizzle-orm';
import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { testConfig } from '../../../test/config';
import { createTestDatabase, type TestDatabase } from '../../../test/db';
import { instanceSettings } from '../../db/schema';
import type { fetchHttpsFile, HttpsFile, HttpsFileOptions, OciProblem } from '../oci';
import {
  DEFAULT_VULNDB_SETTINGS,
  OFFICIAL_EPSS_URL,
  OFFICIAL_KEV_URL,
  type VulndbSettings,
} from '../settings';
import { readVulndbState, updateVulndbState, VULNDB_STATE_KEY } from '../state';
import { PRIORITY_FILE_MAX_BYTES } from './parse';
import {
  PRIORITY_STATE_KEY,
  readPriorityState,
  updatePriorityState,
  type PriorityDatasetState,
} from './state';
import { checkPriorityDatasets, storePriorityFile, type PriorityUpdateDeps } from './update';

const A = 'CVE-2024-0001';
const B = 'CVE-2024-0002';
const C = 'CVE-2024-0003';
const KEV_RELEASED = '2026-10-30T14:22:10.123Z';
const EPSS_DATE = '2026-10-31T00:00:00Z';
const MIRROR_EPSS = 'https://mirror.corp.example/epss/current.csv.gz';
const OTHER_EPSS = 'https://files.corp.example/epss.csv.gz';
const UPDATE_FAILED = { code: 'UPDATE_FAILED', message: 'The update failed. See the server log' };

const digestOf = (bytes: Buffer): string =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function kevFile(ids: string[], released = KEV_RELEASED): Buffer {
  return Buffer.from(
    JSON.stringify({
      catalogVersion: '2026.10.30',
      dateReleased: released,
      vulnerabilities: ids.map((cveID) => ({
        cveID,
        dateAdded: '2026-02-03',
        knownRansomwareCampaignUse: 'Unknown',
      })),
    }),
  );
}

function epssFile(ids: string[], scoreDate = EPSS_DATE): Buffer {
  const rows = ids.map((id) => `${id},0.5,0.75`).join('\n');
  return gzipSync(
    Buffer.from(
      `#model_version:v2025.03.14,score_date:${scoreDate}\ncve,epss,percentile\n${rows}\n`,
    ),
  );
}

const file = (body: Buffer, etag: string | null = null, lastModified: string | null = null) =>
  ({ kind: 'file', body, etag, lastModified }) as const;

type Answer = HttpsFile | OciProblem | (() => Promise<HttpsFile | OciProblem>);

/** A file server: one answer per URL, and the requests it was sent. */
function fakeFiles(answers: Record<string, Answer>) {
  const calls: { url: string; options: HttpsFileOptions }[] = [];
  const fetch: typeof fetchHttpsFile = async (url, options) => {
    calls.push({ url, options });
    const answer = answers[url];
    if (answer === undefined) return { code: 'NOT_FOUND', message: 'no such file' };
    return typeof answer === 'function' ? answer() : answer;
  };
  return { calls, fetch, answers };
}

let t: TestDatabase;
let now: Date;
const internalHosts = new Set(['mirror.corp.example']);
const deps = (fetch: typeof fetchHttpsFile, more: Partial<PriorityUpdateDeps> = {}) =>
  ({
    db: t.db,
    config: { ...testConfig(), vulndb: { internalHosts } },
    fetchHttpsFile: fetch,
    now: () => now,
    logger: { info: () => undefined, warn: () => undefined },
    ...more,
  }) satisfies PriorityUpdateDeps;
const mirror = (epssUrl: string | null, kevUrl: string | null = null): VulndbSettings => ({
  ...DEFAULT_VULNDB_SETTINGS,
  source: {
    kind: 'mirror',
    repository: 'mirror.corp.example/trivy-db:2',
    username: null,
    passwordEnc: null,
    kevUrl,
    epssUrl,
  },
});
const kevIds = async (): Promise<string[]> =>
  (
    await t.db.execute<{ id: string }>(
      sql`SELECT vulnerability_id AS id FROM vulnerability_kev ORDER BY 1`,
    )
  ).rows.map((r) => r.id);
const epssIds = async (): Promise<string[]> =>
  (
    await t.db.execute<{ id: string }>(
      sql`SELECT vulnerability_id AS id FROM vulnerability_epss ORDER BY 1`,
    )
  ).rows.map((r) => r.id);
const listedAt = async (id: string): Promise<string | undefined> =>
  (
    await t.db.execute<{ at: string }>(
      sql`SELECT listed_at::text AS at FROM vulnerability_kev WHERE vulnerability_id = ${id}`,
    )
  ).rows[0]?.at;

beforeAll(async () => {
  t = await createTestDatabase();
});
afterAll(async () => {
  await t.close();
});
beforeEach(async () => {
  await t.db.execute(sql`DELETE FROM vulnerability_kev`);
  await t.db.execute(sql`DELETE FROM vulnerability_epss`);
  await t.db.delete(instanceSettings).where(eq(instanceSettings.key, PRIORITY_STATE_KEY));
  await t.db.delete(instanceSettings).where(eq(instanceSettings.key, VULNDB_STATE_KEY));
  now = new Date('2026-10-31T06:00:00.000Z');
});

describe('checkPriorityDatasets', () => {
  it('fetches KEV, then EPSS, from the official URLs and stores both with their state', async () => {
    const kev = kevFile([A, B]);
    const epss = epssFile([A, B, C]);
    const files = fakeFiles({
      [OFFICIAL_KEV_URL]: file(kev, '"kev-1"', 'Thu, 30 Oct 2026 14:30:00 GMT'),
      [OFFICIAL_EPSS_URL]: file(epss),
    });
    await checkPriorityDatasets(deps(files.fetch), DEFAULT_VULNDB_SETTINGS);

    expect(files.calls.map((c) => c.url)).toEqual([OFFICIAL_KEV_URL, OFFICIAL_EPSS_URL]);
    for (const { options } of files.calls) {
      expect(options).toMatchObject({ internalHosts, maxBytes: PRIORITY_FILE_MAX_BYTES });
      expect(options.etag ?? null).toBeNull();
      expect(options.lastModified ?? null).toBeNull();
    }
    expect(await kevIds()).toEqual([A, B]);
    expect(await epssIds()).toEqual([A, B, C]);
    const state = await readPriorityState(t.db);
    const at = now.toISOString();
    expect(state.kev).toEqual({
      source: 'official',
      dataDate: KEV_RELEASED,
      storedAt: at,
      refreshedAt: at,
      lastCheckAt: at,
      sizeBytes: kev.length,
      count: 2,
      digest: digestOf(kev),
      etag: '"kev-1"',
      lastModified: 'Thu, 30 Oct 2026 14:30:00 GMT',
      url: OFFICIAL_KEV_URL,
      lastError: null,
      staleNotifiedDigest: null,
    } satisfies PriorityDatasetState);
    expect(state.epss).toEqual({
      source: 'official',
      dataDate: new Date(EPSS_DATE).toISOString(),
      storedAt: at,
      refreshedAt: at,
      lastCheckAt: at,
      sizeBytes: epss.length,
      count: 3,
      digest: digestOf(epss),
      etag: null,
      lastModified: null,
      url: OFFICIAL_EPSS_URL,
      lastError: null,
      staleNotifiedDigest: null,
    } satisfies PriorityDatasetState);
  });

  it('sends the stored validators; a 304 moves the check times only', async () => {
    const files = fakeFiles({
      [OFFICIAL_KEV_URL]: file(kevFile([A, B]), '"kev-1"', 'Thu, 30 Oct 2026 14:30:00 GMT'),
      [OFFICIAL_EPSS_URL]: file(epssFile([A]), '"epss-1"'),
    });
    await checkPriorityDatasets(deps(files.fetch), DEFAULT_VULNDB_SETTINGS);
    const first = now.toISOString();
    await t.db.execute(sql`UPDATE vulnerability_kev SET listed_at = '2020-01-01T00:00:00Z'`);
    await updatePriorityState(t.db, 'kev', (s) => ({
      ...s,
      lastError: { code: 'UNREACHABLE', message: 'old' },
    }));

    now = new Date(now.getTime() + 3_600_000);
    files.answers[OFFICIAL_KEV_URL] = { kind: 'not_modified' };
    files.answers[OFFICIAL_EPSS_URL] = { kind: 'not_modified' };
    await checkPriorityDatasets(deps(files.fetch), DEFAULT_VULNDB_SETTINGS);

    expect(files.calls[2]?.options).toMatchObject({
      etag: '"kev-1"',
      lastModified: 'Thu, 30 Oct 2026 14:30:00 GMT',
    });
    expect(files.calls[3]?.options).toMatchObject({ etag: '"epss-1"' });
    const state = await readPriorityState(t.db);
    for (const s of [state.kev, state.epss]) {
      expect(s).toMatchObject({
        storedAt: first,
        refreshedAt: now.toISOString(),
        lastCheckAt: now.toISOString(),
        lastError: null,
      });
    }
    expect(state.kev.etag).toBe('"kev-1"');
    expect(await listedAt(A)).toMatch(/^2020-01-01/);
  });

  it('rewrites nothing when the same bytes come back without validators', async () => {
    const kev = kevFile([A, B]);
    const epss = epssFile([A, B]);
    const files = fakeFiles({ [OFFICIAL_KEV_URL]: file(kev), [OFFICIAL_EPSS_URL]: file(epss) });
    await checkPriorityDatasets(deps(files.fetch), DEFAULT_VULNDB_SETTINGS);
    const first = now.toISOString();
    await t.db.execute(sql`UPDATE vulnerability_kev SET listed_at = '2020-01-01T00:00:00Z'`);
    // Rows removed by hand come back only if the tables are written again.
    await t.db.execute(sql`DELETE FROM vulnerability_kev WHERE vulnerability_id = ${B}`);
    await t.db.execute(sql`DELETE FROM vulnerability_epss WHERE vulnerability_id = ${B}`);

    now = new Date(now.getTime() + 3_600_000);
    await checkPriorityDatasets(deps(files.fetch), DEFAULT_VULNDB_SETTINGS);

    expect(await kevIds()).toEqual([A]);
    expect(await epssIds()).toEqual([A]);
    expect(await listedAt(A)).toMatch(/^2020-01-01/);
    const state = await readPriorityState(t.db);
    for (const s of [state.kev, state.epss]) {
      expect(s).toMatchObject({
        storedAt: first,
        refreshedAt: now.toISOString(),
        lastCheckAt: now.toISOString(),
        lastError: null,
      });
    }
  });

  it("takes EPSS from the mirror's URL and KEV from the official one", async () => {
    const files = fakeFiles({
      [OFFICIAL_KEV_URL]: file(kevFile([A]), '"kev-1"'),
      [MIRROR_EPSS]: file(epssFile([A]), '"epss-1"'),
    });
    await checkPriorityDatasets(deps(files.fetch), mirror(MIRROR_EPSS));
    expect(files.calls.map((c) => c.url)).toEqual([OFFICIAL_KEV_URL, MIRROR_EPSS]);
    const state = await readPriorityState(t.db);
    expect(state.kev).toMatchObject({ source: 'official', url: OFFICIAL_KEV_URL });
    expect(state.epss).toMatchObject({ source: 'mirror', url: MIRROR_EPSS, etag: '"epss-1"' });

    // Another EPSS URL: the validators of the old one are not sent to it.
    files.answers[OTHER_EPSS] = file(epssFile([A, B]));
    await checkPriorityDatasets(deps(files.fetch), mirror(OTHER_EPSS));
    expect(files.calls.map((c) => c.url).slice(2)).toEqual([OFFICIAL_KEV_URL, OTHER_EPSS]);
    expect(files.calls[2]?.options.etag).toBe('"kev-1"');
    expect(files.calls[3]?.options.etag ?? null).toBeNull();
    expect(files.calls[3]?.options.lastModified ?? null).toBeNull();
    expect((await readPriorityState(t.db)).epss).toMatchObject({ url: OTHER_EPSS, etag: null });
    expect(await epssIds()).toEqual([A, B]);
  });

  it("keeps a dataset's rows when its file is invalid, and still updates the other", async () => {
    const files = fakeFiles({
      [OFFICIAL_KEV_URL]: file(kevFile([A, B]), '"kev-1"'),
      [OFFICIAL_EPSS_URL]: file(epssFile([A])),
    });
    await checkPriorityDatasets(deps(files.fetch), DEFAULT_VULNDB_SETTINGS);
    const before = (await readPriorityState(t.db)).kev;
    const trivyError = { code: 'UNREACHABLE', message: 'The registry did not answer' };
    await updateVulndbState(t.db, (s) => ({ ...s, lastError: trivyError }));

    now = new Date(now.getTime() + 3_600_000);
    files.answers[OFFICIAL_KEV_URL] = file(Buffer.from('not json'), '"kev-bad"');
    files.answers[OFFICIAL_EPSS_URL] = file(epssFile([A, B, C]));
    await checkPriorityDatasets(deps(files.fetch), DEFAULT_VULNDB_SETTINGS);

    expect(await kevIds()).toEqual([A, B]);
    expect(await epssIds()).toEqual([A, B, C]);
    const state = await readPriorityState(t.db);
    expect(state.kev).toEqual({
      ...before,
      lastCheckAt: now.toISOString(),
      lastError: { code: 'INVALID_DATA', message: expect.any(String) as string },
    });
    expect(state.epss).toMatchObject({ lastError: null, count: 3 });
    expect((await readVulndbState(t.db)).lastError).toEqual(trivyError);
  });

  it('writes a download problem as the lastError', async () => {
    const problem: OciProblem = { code: 'UNREACHABLE', message: 'No connection within 3 s' };
    const files = fakeFiles({ [OFFICIAL_KEV_URL]: problem, [OFFICIAL_EPSS_URL]: problem });
    await checkPriorityDatasets(deps(files.fetch), DEFAULT_VULNDB_SETTINGS);
    const state = await readPriorityState(t.db);
    for (const s of [state.kev, state.epss]) {
      expect(s).toMatchObject({
        lastError: problem,
        lastCheckAt: now.toISOString(),
        storedAt: null,
        refreshedAt: null,
      });
    }
  });

  it('turns a thrown error into UPDATE_FAILED, logs it, and still checks the other dataset', async () => {
    const warnings: { fields: unknown; message: unknown }[] = [];
    const files = fakeFiles({
      [OFFICIAL_KEV_URL]: () => Promise.reject(new TypeError(`boom ${OFFICIAL_KEV_URL}`)),
      [OFFICIAL_EPSS_URL]: file(epssFile([A])),
    });
    await checkPriorityDatasets(
      deps(files.fetch, {
        logger: {
          info: () => undefined,
          warn: (fields: unknown, message?: unknown) => void warnings.push({ fields, message }),
        },
      }),
      DEFAULT_VULNDB_SETTINGS,
    );
    const state = await readPriorityState(t.db);
    expect(state.kev).toMatchObject({ lastError: UPDATE_FAILED, lastCheckAt: now.toISOString() });
    expect(state.epss).toMatchObject({ lastError: null, count: 1 });
    expect(warnings).toEqual([
      {
        fields: { component: 'vulndb', dataset: 'kev', errorClass: 'TypeError' },
        message: 'priority data update failed',
      },
    ]);
  });
});

describe('storePriorityFile', () => {
  const none = { etag: null, lastModified: null, url: null };

  it('stores an uploaded file without validators', async () => {
    const body = epssFile([A, B]);
    const got = await storePriorityFile(t.db, 'epss', body, 'upload', none, now);
    const at = now.toISOString();
    expect(got).toEqual({
      source: 'upload',
      dataDate: new Date(EPSS_DATE).toISOString(),
      storedAt: at,
      refreshedAt: at,
      lastCheckAt: at,
      sizeBytes: body.length,
      count: 2,
      digest: digestOf(body),
      etag: null,
      lastModified: null,
      url: null,
      lastError: null,
      staleNotifiedDigest: null,
    } satisfies PriorityDatasetState);
    expect((await readPriorityState(t.db)).epss).toEqual(got);
  });

  it('answers a parse problem and writes no state', async () => {
    await storePriorityFile(t.db, 'kev', kevFile([A]), 'official', none, now);
    const before = await readPriorityState(t.db);
    now = new Date(now.getTime() + 60_000);
    const got = await storePriorityFile(t.db, 'kev', Buffer.from('{}'), 'upload', none, now);
    expect(got).toMatchObject({ problem: { code: 'INVALID_DATA' } });
    expect(await readPriorityState(t.db)).toEqual(before);
    expect(await kevIds()).toEqual([A]);
  });

  it('for the same bytes, writes the validators and the check times only', async () => {
    const body = kevFile([A]);
    await storePriorityFile(t.db, 'kev', body, 'upload', none, now);
    await updatePriorityState(t.db, 'kev', (s) => ({
      ...s,
      lastError: { code: 'UNREACHABLE', message: 'old' },
      staleNotifiedDigest: digestOf(body),
    }));
    const before = (await readPriorityState(t.db)).kev;
    const later = new Date(now.getTime() + 60_000);
    const validators = { etag: '"kev-1"', lastModified: 'x', url: OFFICIAL_KEV_URL };
    const got = await storePriorityFile(t.db, 'kev', body, 'official', validators, later);
    expect(got).toEqual({
      ...before,
      ...validators,
      refreshedAt: later.toISOString(),
      lastCheckAt: later.toISOString(),
      lastError: null,
    });
  });

  it('clears the stale record when it stores a new file', async () => {
    await storePriorityFile(t.db, 'kev', kevFile([A]), 'upload', none, now);
    await updatePriorityState(t.db, 'kev', (s) => ({ ...s, staleNotifiedDigest: s.digest }));
    const got = await storePriorityFile(t.db, 'kev', kevFile([A, B]), 'upload', none, now);
    expect(got).toMatchObject({ staleNotifiedDigest: null, count: 2 });
  });

  it('logs what it stored, with the entries it skipped', async () => {
    const infos: unknown[] = [];
    const body = Buffer.from(
      JSON.stringify({
        catalogVersion: '1',
        dateReleased: KEV_RELEASED,
        vulnerabilities: [
          { cveID: A, dateAdded: '2026-02-03' },
          { cveID: 'not-a-cve', dateAdded: '2026-02-03' },
        ],
      }),
    );
    const logger = { info: (fields: unknown) => void infos.push(fields) };
    await storePriorityFile(t.db, 'kev', body, 'upload', none, now, logger);
    expect(infos).toEqual([
      { component: 'vulndb', dataset: 'kev', count: 1, sizeBytes: body.length, skipped: 1 },
    ]);
    infos.length = 0;
    const epss = epssFile([A]);
    await storePriorityFile(t.db, 'epss', epss, 'upload', none, now, logger);
    expect(infos).toEqual([
      { component: 'vulndb', dataset: 'epss', count: 1, sizeBytes: epss.length },
    ]);
  });
});
