import { createHash } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  lutimesSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  statSync,
  symlinkSync,
  utimesSync,
  writeFileSync,
} from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { gzipSync } from 'node:zlib';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { metadataJson, trivyArchive } from '../../../packages/shared/test/trivy-archive';
import { json, problem, useTestServers } from '../../test/http';
import { useTempDirs } from '../../test/tmp';
import { readDatabaseDate } from '../analyzers/trivy';
import { silentLogger } from '../log';
import type { ServerEndpoint } from '../server/http';
import { resolveVulnerabilityDb, vulnerabilityCacheDir } from './vulndb';

const serve = useTestServers();
const tmp = useTempDirs();
afterEach(() => {
  vi.restoreAllMocks();
});
const TOKEN = 'qlr_prj_vulndb_choice_token';
const NOW = new Date('2026-10-31T12:00:00Z');
const HOUR = 60 * 60 * 1000;
const META_PATH = '/api/v0/scanner/vulnerability-db';
const FETCH_FAILED = 'VULNERABILITY_DB_FETCH_FAILED';
const UNTRUSTED = {
  code: 'VULNERABILITY_DB_CACHE_UNTRUSTED',
  message:
    'QUALOR_TRIVY_CACHE_DIR is inside the repository; its database is used only after the server confirms its checksum. Using the database in the scanner image.',
};
const failed = (reason: string, tail: string) => ({
  code: FETCH_FAILED,
  message: `could not get the vulnerability database from the server (${reason}); ${tail}`,
});
const IMAGE = 'using the database in the scanner image';
const cached = (date: string) => `using the cached copy built ${date}`;

const sha = (b: Buffer) => `sha256:${createHash('sha256').update(b).digest('hex')}`;

interface Dataset {
  archive: Buffer;
  digest: string;
  db: string;
  updatedAt: string;
}

/** A server dataset: a real `db.tar.gz` (trivy.db + metadata.json) and its digest. */
function dataset(updatedAt: string, layout: 'flat' | 'dotdb' = 'flat'): Dataset {
  const db = `bolt database of ${updatedAt}`;
  const archive = trivyArchive({
    metadata: metadataJson(2, updatedAt),
    db: Buffer.from(db),
    layout,
  });
  return { archive, digest: sha(archive), db, updatedAt };
}
const NEW = dataset('2026-10-31T06:00:00Z');
const OLD = dataset('2026-10-30T06:00:00Z', 'dotdb');
/** Not the server's: a valid archive that knows no vulnerabilities. */
const FAKE = dataset('2026-10-31T09:00:00Z');

interface FakeVulndb {
  /** The metadata answer (status 200); a number answers that status as a problem. */
  meta: unknown;
  /** The archives the download route serves, by digest. */
  archives?: Buffer[];
  /** Answers every download with this status instead. */
  downloadStatus?: number;
}

/** The scanner routes of a Qualor server (metadata and download), recording request paths. */
async function fakeServer(
  o: FakeVulndb,
): Promise<{ endpoint: ServerEndpoint; paths: string[]; close: () => Promise<void> }> {
  const paths: string[] = [];
  const s = await serve((req, res) => {
    const u = new URL(req.url ?? '/', 'http://x');
    paths.push(u.pathname);
    if (u.pathname === META_PATH) {
      if (typeof o.meta === 'number') problem(res, o.meta, o.meta === 404 ? 'NOT_FOUND' : 'X');
      else json(res, 200, o.meta);
      return;
    }
    const hex = /^\/api\/v0\/scanner\/vulnerability-db\/([0-9a-f]{64})$/.exec(u.pathname)?.[1];
    const body = o.archives?.find((a) => sha(a) === `sha256:${hex}`);
    if (o.downloadStatus !== undefined || body === undefined) {
      problem(res, o.downloadStatus ?? 404, 'NOT_FOUND');
      return;
    }
    res.writeHead(200, {
      'content-type': 'application/gzip',
      'content-length': String(body.length),
      etag: `"${sha(body)}"`,
    });
    res.end(body);
  });
  const close = () =>
    new Promise<void>((resolve) => {
      s.server.closeAllConnections();
      s.server.close(() => resolve());
    });
  return { endpoint: { url: s.url, token: TOKEN, timeoutMs: 5000 }, paths, close };
}

const downloads = (paths: readonly string[]) => paths.filter((p) => p.startsWith(`${META_PATH}/`));

/** The metadata of a server whose current dataset is `current`. */
function meta(current: Dataset, accepted: Dataset[] = [current], policy = 'daily') {
  return {
    serve: true,
    policy,
    current: {
      digest: current.digest,
      sizeBytes: current.archive.length,
      builtAt: `${current.updatedAt.slice(0, 19)}.000Z`,
    },
    accepted: accepted.map((d) => d.digest),
  };
}

/** A cache directory holding `archive` as db.tar.gz and, when given, a server.json. */
function fillCache(
  dir: string,
  archive: Buffer,
  hint?: { digest: string; fetchedAt: string; builtAt?: string | null },
): string {
  mkdirSync(dir, { recursive: true });
  writeFileSync(path.join(dir, 'db.tar.gz'), archive);
  if (hint !== undefined) {
    writeFileSync(path.join(dir, 'server.json'), JSON.stringify({ builtAt: null, ...hint }));
  }
  return dir;
}

const hoursAgo = (h: number) => new Date(NOW.getTime() - h * HOUR).toISOString();

/** The database a chosen directory holds: trivy.db's text and metadata.json's date. */
function databaseIn(dir: string | null): { db: string; updatedAt: string | null } | null {
  if (dir === null) return null;
  return {
    db: readFileSync(path.join(dir, 'db', 'trivy.db'), 'utf8'),
    updatedAt: readDatabaseDate(dir),
  };
}
const holds = (d: Dataset) => ({ db: d.db, updatedAt: d.updatedAt });

async function choose(o: {
  endpoint: ServerEndpoint | null;
  cache?: string;
  root?: string;
  tempRoot?: string;
  env?: Record<string, string>;
}) {
  return resolveVulnerabilityDb({
    endpoint: o.endpoint,
    root: o.root ?? tmp(),
    env: { ...(o.cache !== undefined && { QUALOR_TRIVY_CACHE_DIR: o.cache }), ...o.env },
    log: silentLogger,
    now: () => NOW,
    tempRoot: o.tempRoot ?? tmp(),
  });
}

describe('vulnerabilityCacheDir (P6)', () => {
  it('is QUALOR_TRIVY_CACHE_DIR when it is absolute, else ~/.cache/qualor/trivy', () => {
    const home = path.join(os.homedir(), '.cache', 'qualor', 'trivy');
    const named = tmp();
    expect(vulnerabilityCacheDir({})).toBe(home);
    expect(vulnerabilityCacheDir({ QUALOR_TRIVY_CACHE_DIR: '' })).toBe(home);
    expect(vulnerabilityCacheDir({ QUALOR_TRIVY_CACHE_DIR: 'relative/dir' })).toBe(home);
    expect(vulnerabilityCacheDir({ QUALOR_TRIVY_CACHE_DIR: named })).toBe(named);
  });
});

describe('resolveVulnerabilityDb: the decision table', () => {
  it('keeps today’s choice without a server (no endpoint, --dry-run): no request, no warning, no cache write', async () => {
    const cache = path.join(tmp(), 'cache');
    const got = await choose({ endpoint: null, cache });
    expect(got.dir).toBeNull();
    expect(got.warnings).toEqual([]);
    expect(existsSync(cache)).toBe(false);
    await got.cleanup();
  });

  it('keeps today’s choice on an older server (missing route): one request, no warning', async () => {
    const server = await fakeServer({ meta: 404 });
    const cache = fillCache(path.join(tmp(), 'cache'), NEW.archive);
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(got).toMatchObject({ dir: null, warnings: [] });
    expect(server.paths).toEqual([META_PATH]);
    await got.cleanup();
  });

  it('keeps today’s choice when the server does not serve a database: no warning, no download', async () => {
    const server = await fakeServer({
      meta: { serve: false, policy: 'daily', current: null, accepted: [] },
      archives: [NEW.archive],
    });
    const cache = fillCache(path.join(tmp(), 'cache'), NEW.archive);
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(got).toMatchObject({ dir: null, warnings: [] });
    expect(server.paths).toEqual([META_PATH]);
    expect(existsSync(path.join(cache, 'db'))).toBe(false);
    await got.cleanup();
  });

  it('uses a cached archive whose sha256 is the current digest, without a download', async () => {
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const cache = fillCache(path.join(tmp(), 'cache'), NEW.archive);
    const got = await choose({ endpoint: server.endpoint, cache });
    // Outside the checkout it is extracted into <cache>/db, for the next runs too (P4).
    expect(got.dir).toBe(cache);
    expect(got.repositoryCacheDir).toBeNull();
    expect(databaseIn(got.dir)).toEqual(holds(NEW));
    expect(got.warnings).toEqual([]);
    expect(server.paths).toEqual([META_PATH]);
    await got.cleanup();
    expect(databaseIn(cache)).toEqual(holds(NEW));
  });

  it('daily: uses an accepted archive fetched 2 hours ago while the server has a newer one, without a download (Review Focus 5)', async () => {
    const server = await fakeServer({ meta: meta(NEW, [NEW, OLD]), archives: [NEW.archive] });
    const cache = fillCache(path.join(tmp(), 'cache'), OLD.archive, {
      digest: OLD.digest,
      fetchedAt: hoursAgo(2),
    });
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(downloads(server.paths)).toEqual([]);
    // The date the report shows (engines[].database.updatedAt) is the cached archive's own.
    expect(databaseIn(got.dir)).toEqual(holds(OLD));
    expect(got.warnings).toEqual([]);
    await got.cleanup();
  });

  it.each([
    ['daily, fetched 24 hours ago', 'daily', hoursAgo(24), OLD.digest],
    ['every, fetched 2 hours ago', 'every', hoursAgo(2), OLD.digest],
    ['daily, server.json names another archive', 'daily', hoursAgo(2), NEW.digest],
    ['daily, server.json without a date', 'daily', 'soon', OLD.digest],
  ])('downloads the current archive otherwise (%s)', async (_name, policy, fetchedAt, hinted) => {
    const server = await fakeServer({
      meta: meta(NEW, [NEW, OLD], policy),
      archives: [NEW.archive],
    });
    const cache = fillCache(path.join(tmp(), 'cache'), OLD.archive, {
      digest: hinted,
      fetchedAt,
    });
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(downloads(server.paths)).toHaveLength(1);
    expect(databaseIn(got.dir)).toEqual(holds(NEW));
    expect(got.warnings).toEqual([]);
    await got.cleanup();
  });

  it('downloads the current archive into an empty cache, extracts it and records server.json', async () => {
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const cache = path.join(tmp(), 'missing', 'cache');
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(server.paths).toEqual([META_PATH, `${META_PATH}/${NEW.digest.slice(7)}`]);
    expect(got.dir).toBe(cache);
    expect(databaseIn(got.dir)).toEqual(holds(NEW));
    expect(got.warnings).toEqual([]);
    expect(readFileSync(path.join(cache, 'db.tar.gz')).equals(NEW.archive)).toBe(true);
    expect(JSON.parse(readFileSync(path.join(cache, 'server.json'), 'utf8'))).toEqual({
      digest: NEW.digest,
      builtAt: '2026-10-31T06:00:00.000Z',
      fetchedAt: NOW.toISOString(),
    });
    expect(readdirSync(cache).sort()).toEqual(['db', 'db.tar.gz', 'server.json']);
    // Readable by all: a CI cache step that runs as another user saves them.
    if (process.platform !== 'win32') {
      for (const name of ['db.tar.gz', 'server.json']) {
        expect(statSync(path.join(cache, name)).mode & 0o777, name).toBe(0o644);
      }
    }
    await got.cleanup();
  });

  it('falls back to a cached archive in accepted when the download fails, with its build date', async () => {
    const server = await fakeServer({ meta: meta(NEW, [NEW, OLD], 'every'), downloadStatus: 500 });
    const cache = fillCache(path.join(tmp(), 'cache'), OLD.archive);
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(downloads(server.paths)).toHaveLength(1);
    expect(databaseIn(got.dir)).toEqual(holds(OLD));
    expect(got.warnings).toEqual([failed('server answered 500', cached('2026-10-30'))]);
    await got.cleanup();
  });

  it('metadata failed: uses a cache outside the checkout whose archive matches server.json', async () => {
    const server = await fakeServer({ meta: 500 });
    const cache = fillCache(path.join(tmp(), 'cache'), OLD.archive, {
      digest: OLD.digest,
      fetchedAt: hoursAgo(72),
    });
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(databaseIn(got.dir)).toEqual(holds(OLD));
    expect(got.warnings).toEqual([failed('server answered 500', cached('2026-10-30'))]);
    expect(server.paths).toEqual([META_PATH]);
    await got.cleanup();
  });

  it('metadata failed: server.json is only a hint, so an archive that does not match it is not used', async () => {
    const server = await fakeServer({ meta: 500 });
    const cache = fillCache(path.join(tmp(), 'cache'), OLD.archive, {
      digest: NEW.digest,
      fetchedAt: hoursAgo(1),
    });
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(got.dir).toBeNull();
    expect(got.warnings).toEqual([failed('server answered 500', IMAGE)]);
    expect(existsSync(path.join(cache, 'db'))).toBe(false);
    await got.cleanup();
  });

  it('metadata failed: never uses a cache inside the checkout, even with a matching server.json (Review Focus 1)', async () => {
    const server = await fakeServer({ meta: 500 });
    const root = tmp();
    const tempRoot = tmp();
    const cache = fillCache(path.join(root, '.qualor', 'trivy'), FAKE.archive, {
      digest: FAKE.digest,
      fetchedAt: hoursAgo(1),
    });
    const got = await choose({ endpoint: server.endpoint, cache, root, tempRoot });
    expect(got.dir).toBeNull();
    // One warning: the failure says the image is used (no VULNERABILITY_DB_CACHE_UNTRUSTED too).
    expect(got.warnings).toEqual([failed('server answered 500', IMAGE)]);
    // Never extracted: nothing in the cache, nothing in the temporary directory.
    expect(readdirSync(cache).sort()).toEqual(['db.tar.gz', 'server.json']);
    expect(readdirSync(tempRoot)).toEqual([]);
    await got.cleanup();
  });

  it('download or metadata failed without a usable cache: the image, one warning', async () => {
    const down = await fakeServer({ meta: meta(NEW), downloadStatus: 500 });
    const a = await choose({ endpoint: down.endpoint, cache: path.join(tmp(), 'cache') });
    expect(a).toMatchObject({ dir: null, warnings: [failed('server answered 500', IMAGE)] });
    await a.cleanup();

    const metaDown = await fakeServer({ meta: 503 });
    const b = await choose({ endpoint: metaDown.endpoint, cache: path.join(tmp(), 'cache') });
    expect(b).toMatchObject({ dir: null, warnings: [failed('server answered 503', IMAGE)] });
    await b.cleanup();

    const gone = await fakeServer({ meta: meta(NEW) });
    await gone.close();
    const c = await choose({ endpoint: gone.endpoint, cache: path.join(tmp(), 'cache') });
    expect(c.dir).toBeNull();
    expect(c.warnings).toEqual([
      {
        code: FETCH_FAILED,
        message: expect.stringMatching(
          /^could not get the vulnerability database from the server \(connection failed: [^)]*\); using the database in the scanner image$/,
        ) as string,
      },
    ]);
    expect(JSON.stringify(c.warnings)).not.toContain(TOKEN);
    await c.cleanup();
  });

  /** The scans that get no database from the server: no server or --dry-run, an older one, serve: false. */
  async function withoutServerDatabase(): Promise<[string, ServerEndpoint | null][]> {
    const older = await fakeServer({ meta: 404 });
    const off = await fakeServer({
      meta: { serve: false, policy: 'daily', current: null, accepted: [] },
    });
    return [
      ['no server or --dry-run', null],
      ['an older server', older.endpoint],
      ['serve: false', off.endpoint],
    ];
  }

  it.each([
    ['missing', () => undefined],
    ['empty', (cache: string) => mkdirSync(cache, { recursive: true })],
    [
      'holding only an archive and server.json',
      (cache: string) =>
        fillCache(cache, NEW.archive, { digest: NEW.digest, fetchedAt: hoursAgo(1) }),
    ],
    [
      'holding leftovers of a killed scan',
      (cache: string) => {
        fillCache(cache, NEW.archive);
        writeFileSync(path.join(cache, 'db.tar.gz.0123456789ab.partial'), 'half');
        writeFileSync(path.join(cache, 'server.json.0123456789ab.tmp'), '{');
        mkdirSync(path.join(cache, 'db.0123456789ab.tmp', 'db'), { recursive: true });
        mkdirSync(path.join(cache, 'db'));
        writeFileSync(path.join(cache, 'db', 'metadata.json'), metadataJson(2, NEW.updatedAt));
      },
    ],
  ])(
    'QUALOR_TRIVY_CACHE_DIR inside the checkout %s, without the server’s database: today’s choice, no warning',
    async (_name, fill) => {
      const root = tmp();
      const cache = path.join(root, 'ci', 'trivy');
      fill(cache);
      const before = existsSync(cache) ? readdirSync(cache).sort() : null;
      for (const [name, endpoint] of await withoutServerDatabase()) {
        const got = await choose({ endpoint, cache, root });
        expect(got.dir, name).toBeNull();
        expect(got.warnings, name).toEqual([]);
        expect(got.repositoryCacheDir, name).toBe('ci/trivy');
        await got.cleanup();
      }
      expect(existsSync(cache) ? readdirSync(cache).sort() : null).toEqual(before);
    },
  );

  it('QUALOR_TRIVY_CACHE_DIR inside the checkout holding a database of its own, without the server’s: the image and VULNERABILITY_DB_CACHE_UNTRUSTED', async () => {
    const root = tmp();
    const cache = fillCache(path.join(root, 'ci', 'trivy'), NEW.archive);
    mkdirSync(path.join(cache, 'db'));
    writeFileSync(path.join(cache, 'db', 'trivy.db'), FAKE.db);
    writeFileSync(path.join(cache, 'db', 'metadata.json'), metadataJson(2, FAKE.updatedAt));
    for (const [name, endpoint] of await withoutServerDatabase()) {
      const got = await choose({ endpoint, cache, root });
      expect(got.dir, name).toBeNull();
      expect(got.warnings, name).toEqual([UNTRUSTED]);
      await got.cleanup();
    }
    expect(readdirSync(cache).sort()).toEqual(['db', 'db.tar.gz']);
    expect(readFileSync(path.join(cache, 'db', 'trivy.db'), 'utf8')).toBe(FAKE.db);
  });

  it('a cache inside the checkout is used once the server confirms its checksum, extracted to a private temporary directory', async () => {
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const root = tmp();
    const tempRoot = tmp();
    const cache = fillCache(path.join(root, '.qualor', 'trivy'), NEW.archive);
    const got = await choose({ endpoint: server.endpoint, cache, root, tempRoot });
    expect(downloads(server.paths)).toEqual([]);
    expect(got.warnings).toEqual([]);
    expect(got.repositoryCacheDir).toBe('.qualor/trivy');
    expect(got.dir).not.toBeNull();
    const dir = got.dir ?? '';
    expect(path.relative(tempRoot, dir).startsWith('..')).toBe(false);
    expect(databaseIn(dir)).toEqual(holds(NEW));
    expect(existsSync(path.join(cache, 'db'))).toBe(false);
    await got.cleanup();
    expect(existsSync(dir)).toBe(false);
    expect(readdirSync(tempRoot)).toEqual([]);
  });

  it('downloads into a cache inside the checkout (the CI caches it), and extracts to a temporary directory', async () => {
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const root = tmp();
    const tempRoot = tmp();
    const cache = path.join(root, '.qualor', 'trivy');
    const got = await choose({ endpoint: server.endpoint, cache, root, tempRoot });
    expect(downloads(server.paths)).toHaveLength(1);
    expect(readFileSync(path.join(cache, 'db.tar.gz')).equals(NEW.archive)).toBe(true);
    expect(readdirSync(cache).sort()).toEqual(['db.tar.gz', 'server.json']);
    expect(databaseIn(got.dir)).toEqual(holds(NEW));
    expect(got.warnings).toEqual([]);
    await got.cleanup();
    expect(readdirSync(tempRoot)).toEqual([]);
  });
});

describe('resolveVulnerabilityDb: a new archive that is not usable keeps the cached one (row 6)', () => {
  it.each(['outside', 'inside'] as const)(
    'uses the accepted cached archive, unchanged, with the warning (cache %s the checkout)',
    async (where) => {
      const broken = trivyArchive({ metadata: null });
      const server = await fakeServer({
        meta: {
          serve: true,
          policy: 'every',
          current: { digest: sha(broken), sizeBytes: broken.length, builtAt: null },
          accepted: [sha(broken), OLD.digest],
        },
        archives: [broken],
      });
      const root = tmp();
      const tempRoot = tmp();
      const cache = fillCache(
        where === 'inside' ? path.join(root, '.qualor', 'trivy') : path.join(tmp(), 'cache'),
        OLD.archive,
      );
      const got = await choose({ endpoint: server.endpoint, cache, root, tempRoot });
      expect(downloads(server.paths)).toHaveLength(1);
      expect(databaseIn(got.dir)).toEqual(holds(OLD));
      expect(got.warnings).toEqual([
        failed('the archive is not a Trivy database', cached('2026-10-30')),
      ]);
      expect(readFileSync(path.join(cache, 'db.tar.gz')).equals(OLD.archive)).toBe(true);
      expect(readdirSync(cache).sort()).toEqual(
        where === 'inside' ? ['db.tar.gz'] : ['db', 'db.tar.gz'],
      );
      await got.cleanup();
      expect(readdirSync(tempRoot)).toEqual([]);
    },
  );
});

describe('resolveVulnerabilityDb: private copies a killed scan left behind', () => {
  const posix = process.platform !== 'win32';
  /** The entry itself (a link too), not what it points to. */
  const present = (p: string) => {
    try {
      lstatSync(p);
      return true;
    } catch {
      return false;
    }
  };

  it('removes this user’s 0700 qualor-vulndb-* directories two days old or more from the temporary directory, and nothing else', async () => {
    const server = await fakeServer({ meta: 404 });
    const tempRoot = tmp();
    const elsewhere = tmp();
    const ago = (hours: number) => new Date(Date.now() - hours * HOUR);
    const make = (
      where: string,
      name: string,
      hours: number,
      o: { kind?: 'dir' | 'file'; mode?: number } = {},
    ) => {
      const p = path.join(where, name);
      if ((o.kind ?? 'dir') === 'dir') {
        mkdirSync(path.join(p, 'db'), { recursive: true });
        writeFileSync(path.join(p, 'db', 'trivy.db'), 'a copy');
        // As mkdtemp makes it.
        chmodSync(p, o.mode ?? 0o700);
      } else {
        writeFileSync(p, 'a file');
      }
      utimesSync(p, ago(hours), ago(hours));
      return p;
    };
    const stale = make(tempRoot, 'qualor-vulndb-AbC123', 49);
    // A link with the name, to an old directory elsewhere: neither is touched.
    const target = make(elsewhere, 'qualor-vulndb-T4rget', 49);
    const link = path.join(tempRoot, 'qualor-vulndb-L1nk00');
    symlinkSync(target, link, 'junction');
    lutimesSync(link, ago(49), ago(49));
    const kept = [
      make(tempRoot, 'qualor-vulndb-xYz789', 0),
      // More than a day old: a scan may still be using it.
      make(tempRoot, 'qualor-vulndb-Day1ok', 30),
      make(tempRoot, 'qualor-review-AbC123', 49),
      make(tempRoot, 'qualor-vulndb-AbC1234', 49),
      make(tempRoot, 'qualor-vulndb-Fi1e00', 49, { kind: 'file' }),
      link,
      target,
      path.join(target, 'db', 'trivy.db'),
      // POSIX: not as mkdtemp makes it, so not this module's.
      ...(posix ? [make(tempRoot, 'qualor-vulndb-M0de55', 49, { mode: 0o755 })] : []),
    ];
    const got = await choose({ endpoint: server.endpoint, cache: path.join(tmp(), 'c'), tempRoot });
    expect(got).toMatchObject({ dir: null, warnings: [] });
    expect(present(stale)).toBe(false);
    for (const p of kept) expect(present(p), p).toBe(true);
    await got.cleanup();
  });
});

describe('resolveVulnerabilityDb: no home directory (R7)', () => {
  it('downloads into a temporary directory when the default cache cannot be named, and never throws', async () => {
    vi.spyOn(os, 'homedir').mockImplementation(() => {
      throw new Error('ENOENT: no home directory for this user');
    });
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const tempRoot = tmp();
    const got = await choose({ endpoint: server.endpoint, tempRoot });
    expect(got.warnings).toEqual([]);
    expect(got.repositoryCacheDir).toBeNull();
    expect(databaseIn(got.dir)).toEqual(holds(NEW));
    expect(path.relative(tempRoot, got.dir ?? '').startsWith('..')).toBe(false);
    await got.cleanup();
    expect(readdirSync(tempRoot)).toEqual([]);
    const none = await choose({ endpoint: null });
    expect(none).toMatchObject({ dir: null, warnings: [], repositoryCacheDir: null });
    const down = await fakeServer({ meta: 500 });
    const failedMeta = await choose({ endpoint: down.endpoint });
    expect(failedMeta).toMatchObject({
      dir: null,
      warnings: [failed('server answered 500', IMAGE)],
    });
  });
});

describe('resolveVulnerabilityDb: a poisoned or broken cache (Review Focus 1)', () => {
  it.each([
    ['a fake archive with a forged server.json', FAKE.archive],
    ['a truncated archive', NEW.archive.subarray(0, Math.floor(NEW.archive.length / 2))],
  ])('rejects %s in the cache and downloads the server’s', async (_name, planted) => {
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const cache = fillCache(path.join(tmp(), 'cache'), planted, {
      digest: NEW.digest,
      fetchedAt: hoursAgo(1),
    });
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(downloads(server.paths)).toHaveLength(1);
    expect(databaseIn(got.dir)).toEqual(holds(NEW));
    expect(readFileSync(path.join(cache, 'db.tar.gz')).equals(NEW.archive)).toBe(true);
    expect(got.warnings).toEqual([]);
    await got.cleanup();
  });

  it('ignores a forged db/ with the current digest’s marker in a cache inside the checkout: the archive is hashed and extracted privately', async () => {
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const root = tmp();
    const tempRoot = tmp();
    const cache = fillCache(path.join(root, '.qualor', 'trivy'), NEW.archive);
    // A branch commits an unpacked database of its own, marked as the server's current one.
    const forged = path.join(cache, 'db');
    mkdirSync(forged);
    writeFileSync(path.join(forged, 'trivy.db'), FAKE.db);
    writeFileSync(path.join(forged, 'metadata.json'), metadataJson(2, FAKE.updatedAt));
    writeFileSync(path.join(forged, 'qualor-digest'), `${NEW.digest}\n`);
    const got = await choose({ endpoint: server.endpoint, cache, root, tempRoot });
    expect(downloads(server.paths)).toEqual([]);
    expect(got.warnings).toEqual([]);
    expect(got.dir).not.toBe(cache);
    expect(path.relative(tempRoot, got.dir ?? '').startsWith('..')).toBe(false);
    expect(databaseIn(got.dir)).toEqual(holds(NEW));
    // Left as it was, and never read.
    expect(readFileSync(path.join(forged, 'trivy.db'), 'utf8')).toBe(FAKE.db);
    await got.cleanup();
    expect(readdirSync(tempRoot)).toEqual([]);
  });

  it('never extracts a rejected archive, even when the download fails too', async () => {
    const server = await fakeServer({ meta: meta(NEW), downloadStatus: 500 });
    const tempRoot = tmp();
    const cache = fillCache(path.join(tmp(), 'cache'), FAKE.archive, {
      digest: NEW.digest,
      fetchedAt: hoursAgo(1),
    });
    const got = await choose({ endpoint: server.endpoint, cache, tempRoot });
    expect(got).toMatchObject({ dir: null, warnings: [failed('server answered 500', IMAGE)] });
    expect(readdirSync(cache).sort()).toEqual(['db.tar.gz', 'server.json']);
    expect(readdirSync(tempRoot)).toEqual([]);
    await got.cleanup();
  });

  it.each([
    ['without metadata.json', trivyArchive({ metadata: null })],
    ['without trivy.db', trivyArchive({ db: null })],
    ['of schema version 1', trivyArchive({ metadata: metadataJson(1) })],
    ['with an unreadable date', trivyArchive({ metadata: metadataJson(2, 'soon') })],
    ['that is not a tar archive', gzipSync(Buffer.from('not a tar archive'.repeat(64)))],
  ])('does not use a server archive %s: like a failed download', async (_name, archive) => {
    const server = await fakeServer({
      meta: {
        serve: true,
        policy: 'daily',
        current: { digest: sha(archive), sizeBytes: archive.length, builtAt: null },
        accepted: [sha(archive)],
      },
      archives: [archive],
    });
    const tempRoot = tmp();
    const cache = path.join(tmp(), 'cache');
    const got = await choose({ endpoint: server.endpoint, cache, tempRoot });
    expect(got.dir).toBeNull();
    expect(got.warnings).toEqual([failed('the archive is not a Trivy database', IMAGE)]);
    expect(existsSync(path.join(cache, 'db'))).toBe(false);
    expect(readdirSync(cache).filter((n) => n.startsWith('db.') && n !== 'db.tar.gz')).toEqual([]);
    await got.cleanup();
    expect(readdirSync(tempRoot)).toEqual([]);
  });
});

describe('resolveVulnerabilityDb: the cache directory', () => {
  it('reuses the extracted database of a cache outside the checkout on the next run', async () => {
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const cache = path.join(tmp(), 'cache');
    const first = await choose({ endpoint: server.endpoint, cache });
    await first.cleanup();
    writeFileSync(path.join(cache, 'db', 'sentinel'), 'kept');
    const second = await choose({ endpoint: server.endpoint, cache });
    expect(second.dir).toBe(cache);
    expect(readFileSync(path.join(cache, 'db', 'sentinel'), 'utf8')).toBe('kept');
    expect(downloads(server.paths)).toHaveLength(1);
    await second.cleanup();
  });

  it('replaces a <cache>/db that carries the current marker but no trivy.db', async () => {
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const cache = fillCache(path.join(tmp(), 'cache'), NEW.archive);
    const live = path.join(cache, 'db');
    mkdirSync(live);
    writeFileSync(path.join(live, 'metadata.json'), metadataJson(2, NEW.updatedAt));
    writeFileSync(path.join(live, 'qualor-digest'), `${NEW.digest}\n`);
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(downloads(server.paths)).toEqual([]);
    expect(got.dir).toBe(cache);
    expect(databaseIn(got.dir)).toEqual(holds(NEW));
    await got.cleanup();
    expect(readdirSync(cache).sort()).toEqual(['db', 'db.tar.gz']);
  });

  it('replaces the extracted database when the archive changes', async () => {
    const cache = path.join(tmp(), 'cache');
    const before = await fakeServer({ meta: meta(OLD), archives: [OLD.archive] });
    const first = await choose({ endpoint: before.endpoint, cache });
    expect(databaseIn(first.dir)).toEqual(holds(OLD));
    await first.cleanup();
    const after = await fakeServer({
      meta: meta(NEW, [NEW, OLD], 'every'),
      archives: [NEW.archive],
    });
    const second = await choose({ endpoint: after.endpoint, cache });
    expect(second.dir).toBe(cache);
    expect(databaseIn(cache)).toEqual(holds(NEW));
    expect(readdirSync(cache).sort()).toEqual(['db', 'db.tar.gz', 'server.json']);
    await second.cleanup();
  });

  it('two scans sharing one cache both end with a valid database (Review Focus 4)', async () => {
    const cache = path.join(tmp(), 'cache');
    const seed = await fakeServer({ meta: meta(OLD), archives: [OLD.archive] });
    await (await choose({ endpoint: seed.endpoint, cache })).cleanup();
    const server = await fakeServer({
      meta: meta(NEW, [NEW, OLD], 'every'),
      archives: [NEW.archive],
    });
    const [a, b] = await Promise.all([
      choose({ endpoint: server.endpoint, cache }),
      choose({ endpoint: server.endpoint, cache }),
    ]);
    for (const got of [a, b]) {
      expect(got.dir).not.toBeNull();
      expect(databaseIn(got.dir)).toEqual(holds(NEW));
    }
    await a.cleanup();
    await b.cleanup();
    expect(databaseIn(cache)).toEqual(holds(NEW));
    expect(readFileSync(path.join(cache, 'db.tar.gz')).equals(NEW.archive)).toBe(true);
    expect(readdirSync(cache).filter((n) => n.endsWith('.partial') || n.endsWith('.tmp'))).toEqual(
      [],
    );
  });

  it('removes partial downloads older than an hour before downloading, and keeps fresh ones', async () => {
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const cache = path.join(tmp(), 'cache');
    mkdirSync(cache);
    const stale = path.join(cache, 'db.0123456789ab.tar.gz.0123456789ab.partial');
    const fresh = path.join(cache, 'db.ba9876543210.tar.gz.ba9876543210.partial');
    writeFileSync(stale, 'half');
    writeFileSync(fresh, 'half');
    const twoHoursAgo = new Date(Date.now() - 2 * HOUR);
    utimesSync(stale, twoHoursAgo, twoHoursAgo);
    const got = await choose({ endpoint: server.endpoint, cache });
    expect(existsSync(stale)).toBe(false);
    expect(existsSync(fresh)).toBe(true);
    expect(databaseIn(got.dir)).toEqual(holds(NEW));
    await got.cleanup();
  });

  it('downloads into a temporary directory, without caching, when the cache cannot be created', async () => {
    const server = await fakeServer({ meta: meta(NEW), archives: [NEW.archive] });
    const blocker = path.join(tmp(), 'file');
    writeFileSync(blocker, 'a file, not a directory');
    const tempRoot = tmp();
    const got = await choose({
      endpoint: server.endpoint,
      cache: path.join(blocker, 'cache'),
      tempRoot,
    });
    expect(got.warnings).toEqual([]);
    expect(databaseIn(got.dir)).toEqual(holds(NEW));
    expect(path.relative(tempRoot, got.dir ?? '').startsWith('..')).toBe(false);
    await got.cleanup();
    expect(readdirSync(tempRoot)).toEqual([]);
  });
});
