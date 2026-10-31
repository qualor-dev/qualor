import { createHash, randomBytes } from 'node:crypto';
import {
  constants,
  createWriteStream,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  renameSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { open, type FileHandle } from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { readTarGz, TarError } from '@qualor/shared/tar';
import { createWorkDir, releaseWorkDir } from '../analyzers/runner';
import { cacheInRepository, readDatabaseDate, vulnerabilityCacheDir } from '../analyzers/trivy';
import type { Logger } from '../log';
import { clean, type ServerEndpoint } from '../server/http';
import { downloadServerVulndb, fetchServerVulndb, type ServerVulndb } from '../server/vulndb';

type Env = Readonly<Record<string, string | undefined>>;

export interface VulnerabilityDbInput {
  /** The server the token may be sent to; null without one and under `--dry-run`. */
  endpoint: ServerEndpoint | null;
  root: string;
  env: Env;
  log: Logger;
  now: () => Date;
  /** Where a private copy is extracted (the system's temporary directory by default). */
  tempRoot?: string;
}

export interface VulnerabilityDbChoice {
  /**
   * The Trivy cache directory (its database in `db/`) the scan uses; null keeps today's choice:
   * `QUALOR_TRIVY_CACHE_DIR` when it is outside the checkout, else the image's.
   */
  dir: string | null;
  /** Report warnings, each code at most once. */
  warnings: { code: string; message: string }[];
  /** Removes the private copy; never throws. Called after the analyzers. */
  cleanup: () => Promise<void>;
}

type Warning = VulnerabilityDbChoice['warnings'][number];
type Current = NonNullable<ServerVulndb['current']>;

const FETCH_FAILED = 'VULNERABILITY_DB_FETCH_FAILED';
const UNTRUSTED: Warning = {
  code: 'VULNERABILITY_DB_CACHE_UNTRUSTED',
  message:
    'QUALOR_TRIVY_CACHE_DIR is inside the repository; its database is used only after the server confirms its checksum. Using the database in the scanner image.',
};
const IMAGE = 'using the database in the scanner image';
const UNUSABLE = 'the archive is not a Trivy database';
const WRITE_FAILED = 'cannot write the database file';

/** The cache files (P4): the archive, and what the server said of it (a hint, never trusted). */
const ARCHIVE = 'db.tar.gz';
const HINT = 'server.json';
/** In an extracted `db/`: the digest of the archive it came from (moves with it on rename). */
const MARKER = 'qualor-digest';

const MAX_ARCHIVE_BYTES = 2 * 1024 ** 3;
const MAX_HINT_BYTES = 4 * 1024;
/** Trivy's metadata.json is 143 bytes (`readDatabaseDate` reads at most 64 KiB). */
const MAX_METADATA_BYTES = 64 * 1024;
const HOUR_MS = 60 * 60 * 1000;
/** P8: `daily` reuses a copy fetched less than this long ago. */
const DAY_MS = 24 * HOUR_MS;
/** A staging directory this old belongs to no running scan (the longest timeout is a day). */
const STAGING_MAX_AGE_MS = 48 * HOUR_MS;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const READ_CHUNK = 1024 * 1024;

const message = (err: unknown) => (err instanceof Error ? err.message : String(err));
const hex6 = () => randomBytes(6).toString('hex');

const failed = (reason: string, tail: string): Warning => ({
  code: FETCH_FAILED,
  message: `could not get the vulnerability database from the server (${reason}); ${tail}`,
});

/** `using the cached copy built <YYYY-MM-DD>`, from the archive's own metadata.json date. */
function cachedTail(updatedAt: string): string {
  const at = new Date(updatedAt);
  return Number.isNaN(at.getTime())
    ? 'using the cached copy'
    : `using the cached copy built ${at.toISOString().slice(0, 10)}`;
}

/** A failure reason as the warning shows it: printable and short. */
const shownReason = (reason: string) => clean(reason).slice(0, 120) || 'unexpected response';

function regularFile(file: string, max: number): boolean {
  try {
    const s = lstatSync(file);
    return s.isFile() && s.size <= max;
  } catch {
    return false;
  }
}

function removeQuietly(target: string, log: Logger): void {
  try {
    rmSync(target, { recursive: true, force: true, maxRetries: 5, retryDelay: 50 });
  } catch (err) {
    log.debug(`could not remove ${target}: ${message(err)}`);
  }
}

/** The digest an extracted `db/` came from, or null. */
function markerOf(db: string): string | null {
  const file = path.join(db, MARKER);
  if (!regularFile(file, 128)) return null;
  try {
    const text = readFileSync(file, 'utf8').trim();
    return DIGEST.test(text) ? text : null;
  } catch {
    return null;
  }
}

interface Hint {
  digest: string;
  /** Epoch milliseconds, or null when server.json gives no valid date. */
  fetchedAt: number | null;
}

/** `server.json`: which archive the cache holds and when it was fetched. A hint only. */
function readHint(cache: string): Hint | null {
  const file = path.join(cache, HINT);
  if (!regularFile(file, MAX_HINT_BYTES)) return null;
  try {
    const value = JSON.parse(readFileSync(file, 'utf8')) as {
      digest?: unknown;
      fetchedAt?: unknown;
    };
    if (typeof value.digest !== 'string' || !DIGEST.test(value.digest)) return null;
    const at = typeof value.fetchedAt === 'string' ? Date.parse(value.fetchedAt) : Number.NaN;
    return { digest: value.digest, fetchedAt: Number.isNaN(at) ? null : at };
  } catch {
    return null;
  }
}

/** Writes `server.json` through a temporary name and a rename (Review Focus 4). */
function writeHint(cache: string, hint: object, log: Logger): void {
  const tmp = path.join(cache, `${HINT}.${hex6()}.tmp`);
  try {
    writeFileSync(tmp, `${JSON.stringify(hint)}\n`, { flag: 'wx', mode: 0o644 });
    renameSync(tmp, path.join(cache, HINT));
  } catch (err) {
    removeQuietly(tmp, log);
    log.debug(`could not write ${HINT} in the vulnerability database cache: ${message(err)}`);
  }
}

/**
 * R4: removes what a killed scan left in the cache: partial downloads and temporary `server.json`
 * files older than an hour, staging directories older than two days. Only the names this module
 * and the download client make, so nothing else in the directory is touched.
 */
function prune(cache: string, log: Logger): void {
  let names: string[];
  try {
    names = readdirSync(cache);
  } catch {
    return;
  }
  const now = Date.now();
  for (const name of names) {
    let maxAge: number;
    if (/^db\.tar\.gz\.[0-9a-f]{12}\.partial$/.test(name)) maxAge = HOUR_MS;
    else if (/^server\.json\.[0-9a-f]{12}\.tmp$/.test(name)) maxAge = HOUR_MS;
    else if (/^db\.[0-9a-f]{12}\.old$/.test(name)) maxAge = HOUR_MS;
    else if (/^db\.[0-9a-f]{12}\.tmp$/.test(name)) maxAge = STAGING_MAX_AGE_MS;
    else continue;
    const target = path.join(cache, name);
    try {
      if (now - lstatSync(target).mtimeMs >= maxAge) removeQuietly(target, log);
    } catch {
      // Gone already (another scan removed it).
    }
  }
}

/** The sha256 of the open file, read from its start (`sha256:<hex>`). */
async function sha256(fh: FileHandle): Promise<string> {
  const hash = createHash('sha256');
  const stream = fh.createReadStream({ start: 0, autoClose: false, highWaterMark: READ_CHUNK });
  for await (const chunk of stream) hash.update(chunk as Buffer);
  return `sha256:${hash.digest('hex')}`;
}

type Failure = {
  reason: string;
  /** The archive itself is unusable (not a write error). */ bad: boolean;
};

/**
 * Extracts the open archive into `db`: `trivy.db` streamed to disk, `metadata.json` checked
 * (schema version 2 and a date) and written; nothing else. Null when done, else why not.
 */
async function unpack(fh: FileHandle, db: string): Promise<Failure | null> {
  // Filled by the entry callback.
  const found: { metadata: Buffer | null; db: boolean } = { metadata: null, db: false };
  try {
    await readTarGz(
      fh.createReadStream({ start: 0, autoClose: false, highWaterMark: READ_CHUNK }),
      (name) => (name === 'trivy.db' ? 'stream' : name === 'metadata.json' ? 'keep' : 'skip'),
      async (entry) => {
        if (entry.want === 'keep') {
          if (found.metadata !== null) throw new TarError('The archive holds metadata.json twice');
          if (entry.data.length > MAX_METADATA_BYTES) {
            throw new TarError('metadata.json is larger than 64 KiB');
          }
          found.metadata = entry.data;
          return;
        }
        if (found.db) throw new TarError('The archive holds trivy.db twice');
        found.db = true;
        await pipeline(
          entry.body,
          createWriteStream(path.join(db, 'trivy.db'), { flags: 'wx', mode: 0o644 }),
        );
      },
    );
  } catch (err) {
    if (err instanceof TarError) return { reason: UNUSABLE, bad: true };
    throw err;
  }
  const meta = found.metadata;
  if (!found.db || meta === null) return { reason: UNUSABLE, bad: true };
  let parsed: unknown;
  try {
    parsed = JSON.parse(meta.toString('utf8'));
  } catch {
    return { reason: UNUSABLE, bad: true };
  }
  const value = parsed as { Version?: unknown; UpdatedAt?: unknown } | null;
  if (
    value === null ||
    typeof value !== 'object' ||
    value.Version !== 2 ||
    typeof value.UpdatedAt !== 'string' ||
    Number.isNaN(new Date(value.UpdatedAt).getTime())
  ) {
    return { reason: UNUSABLE, bad: true };
  }
  writeFileSync(path.join(db, 'metadata.json'), meta, { flag: 'wx', mode: 0o644 });
  return null;
}

/**
 * Renames the extracted `db` to `<cache>/db` (P4, Review Focus 4). An existing one is renamed
 * aside first, then removed, so a reader sees the old directory or the new one, never a
 * half-written one. True when `<cache>/db` now holds `digest`: this scan's copy, or the same one
 * another scan placed first.
 */
function place(db: string, cache: string, digest: string, log: Logger): boolean {
  const live = path.join(cache, 'db');
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      renameSync(db, live);
      return true;
    } catch {
      // `<cache>/db` exists: the same database (keep it), or another one (move it aside).
    }
    if (markerOf(live) === digest && readDatabaseDate(cache) !== null) return true;
    const aside = path.join(cache, `db.${hex6()}.old`);
    try {
      renameSync(live, aside);
    } catch (err) {
      log.debug(`could not move the old vulnerability database aside: ${message(err)}`);
    }
    removeQuietly(aside, log);
  }
  return false;
}

type Used =
  | { ok: true; digest: string; dir: string; updatedAt: string }
  | { ok: false; digest: string | null; failure?: Failure };

/** One scan's choice: the cache directory, a private temporary directory, what to clean up. */
class Choice {
  readonly cache: string;
  readonly archive: string;
  /** P4: inside the checkout, the cache is never trusted alone and never extracted in place. */
  readonly inside: boolean;
  /** P5: `QUALOR_TRIVY_CACHE_DIR` names a directory inside the checkout. */
  readonly namedInside: boolean;
  private work: string | null = null;
  private writable: boolean | undefined;
  private readonly leftovers: string[] = [];

  constructor(private readonly input: VulnerabilityDbInput) {
    this.cache = vulnerabilityCacheDir(input.env);
    this.archive = path.join(this.cache, ARCHIVE);
    this.inside = cacheInRepository(input.root, this.cache);
    const named = input.env['QUALOR_TRIVY_CACHE_DIR'];
    this.namedInside = named !== undefined && named !== '' && path.isAbsolute(named) && this.inside;
  }

  get log(): Logger {
    return this.input.log;
  }

  result(dir: string | null, warnings: Warning[]): VulnerabilityDbChoice {
    return { dir, warnings, cleanup: () => this.cleanup() };
  }

  /** Today's choice, without a warning unless a cache in the checkout is ignored (P5). */
  keep(): VulnerabilityDbChoice {
    return this.result(null, this.namedInside ? [UNTRUSTED] : []);
  }

  /** Today's choice after a failure: one `VULNERABILITY_DB_FETCH_FAILED`. */
  fallback(reason: string): VulnerabilityDbChoice {
    return this.result(null, [failed(shownReason(reason), this.todaysTail())]);
  }

  /**
   * What today's choice reads: a named directory outside the checkout that holds a database
   * (trusted, as today), else the image's.
   */
  private todaysTail(): string {
    const named = this.input.env['QUALOR_TRIVY_CACHE_DIR'];
    if (named === undefined || named === '' || !path.isAbsolute(named) || this.inside) return IMAGE;
    const updatedAt = readDatabaseDate(named);
    return updatedAt === null ? IMAGE : cachedTail(updatedAt);
  }

  /** A private temporary directory for this scan, removed by `cleanup` (and on Ctrl+C). */
  workDir(): string {
    this.work ??= createWorkDir('vulndb', this.input.tempRoot);
    return this.work;
  }

  /** P6: the cache directory exists and takes a file; false (logged at debug) otherwise. */
  cacheWritable(): boolean {
    if (this.writable !== undefined) return this.writable;
    try {
      mkdirSync(this.cache, { recursive: true });
      const probe = path.join(this.cache, `.write-check.${hex6()}`);
      writeFileSync(probe, '', { flag: 'wx' });
      rmSync(probe, { force: true });
      this.writable = true;
    } catch (err) {
      this.log.debug(
        `the vulnerability database cache ${this.cache} cannot be written (${message(err)}); downloading without caching`,
      );
      this.writable = false;
    }
    return this.writable;
  }

  /**
   * Hashes the archive `file` from disk and, when `accept` takes its digest, extracts it from the
   * same open file (a concurrent rename cannot swap it in between). A rejected archive is never
   * extracted. Never throws.
   */
  async use(file: string, accept: (digest: string) => boolean): Promise<Used> {
    let fh: FileHandle | undefined;
    try {
      // A regular file only: never a link, a FIFO (which would block) or a directory.
      if (!regularFile(file, MAX_ARCHIVE_BYTES)) return { ok: false, digest: null };
      // O_NONBLOCK: a FIFO swapped in after the check cannot block the scan.
      fh = await open(file, constants.O_RDONLY | (constants.O_NONBLOCK ?? 0));
      const stat = await fh.stat();
      if (!stat.isFile() || stat.size === 0 || stat.size > MAX_ARCHIVE_BYTES) {
        return { ok: false, digest: null };
      }
      const digest = await sha256(fh);
      if (!accept(digest)) {
        this.log.debug(`the cached vulnerability database archive (${digest}) is not used`);
        return { ok: false, digest };
      }
      const placed = await this.extract(fh, digest);
      return 'reason' in placed
        ? { ok: false, digest, failure: placed }
        : { ok: true, digest, ...placed };
    } catch (err) {
      this.log.debug(`cannot read the vulnerability database archive: ${message(err)}`);
      return { ok: false, digest: null };
    } finally {
      await fh?.close().catch(() => undefined);
    }
  }

  /**
   * Where Trivy reads the verified archive (P4): `<cache>/db`, extracted once and reused while it
   * matches, for a writable cache outside the checkout; else a private temporary copy.
   */
  private async extract(
    fh: FileHandle,
    digest: string,
  ): Promise<{ dir: string; updatedAt: string } | Failure> {
    if (!this.inside) {
      const live = path.join(this.cache, 'db');
      const updatedAt = readDatabaseDate(this.cache);
      if (
        markerOf(live) === digest &&
        updatedAt !== null &&
        regularFile(path.join(live, 'trivy.db'), Number.POSITIVE_INFINITY)
      ) {
        return { dir: this.cache, updatedAt };
      }
    }
    const shared = !this.inside && this.cacheWritable();
    const staging = path.join(shared ? this.cache : this.workDir(), `db.${hex6()}.tmp`);
    const db = path.join(staging, 'db');
    try {
      mkdirSync(db, { recursive: true });
      const problem = await unpack(fh, db);
      const updatedAt = problem === null ? readDatabaseDate(staging) : null;
      if (problem !== null || updatedAt === null) {
        removeQuietly(staging, this.log);
        return problem ?? { reason: UNUSABLE, bad: true };
      }
      writeFileSync(path.join(db, MARKER), `${digest}\n`, { flag: 'wx', mode: 0o644 });
      if (!shared) return { dir: staging, updatedAt };
      if (place(db, this.cache, digest, this.log)) {
        removeQuietly(staging, this.log);
        return { dir: this.cache, updatedAt: readDatabaseDate(this.cache) ?? updatedAt };
      }
      // Another scan holds `<cache>/db` open: this scan reads its own copy, removed afterwards.
      this.leftovers.push(staging);
      return { dir: staging, updatedAt };
    } catch (err) {
      this.log.debug(`cannot extract the vulnerability database: ${message(err)}`);
      removeQuietly(staging, this.log);
      return { reason: WRITE_FAILED, bad: false };
    }
  }

  cleanup(): Promise<void> {
    for (const dir of this.leftovers.splice(0)) removeQuietly(dir, this.log);
    if (this.work !== null) {
      releaseWorkDir(this.work, this.log);
      this.work = null;
    }
    return Promise.resolve();
  }
}

/**
 * The decision table (vuln plan 3, P4–P8). Every archive is hashed from disk on each use;
 * `server.json` only dates it.
 *
 * | Situation | Result |
 * |---|---|
 * | No endpoint, `--dry-run`, Trivy disabled, or a missing route | `dir: null`, no warning |
 * | `serve: false` | `dir: null`, no warning |
 * | Cache archive whose sha256 equals the current digest | extract and use it; no download |
 * | `daily`, the cache `fetchedAt` < 24 h, and its sha256 in `accepted` | extract and use it; no download |
 * | Otherwise | download the current archive into the cache, then extract and use it |
 * | Download failed, with a cached archive whose sha256 is in `accepted` | use the cache, warn `VULNERABILITY_DB_FETCH_FAILED` with its build date |
 * | Metadata failed, the cache directory outside the root, and the archive's sha256 equal to `server.json`'s digest | use the cache, warn `VULNERABILITY_DB_FETCH_FAILED` with its build date (a cache outside the checkout is trusted, as today) |
 * | Metadata failed and the cache directory inside the root | never use it: nothing can verify it. Image, warn `VULNERABILITY_DB_FETCH_FAILED` |
 * | Download or metadata failed, no usable cache | `dir: null` (image), warn `VULNERABILITY_DB_FETCH_FAILED` "…using the database in the scanner image" |
 * | `QUALOR_TRIVY_CACHE_DIR` inside the root and no server-verified archive | image, warn `VULNERABILITY_DB_CACHE_UNTRUSTED` |
 *
 * One warning per scan: a failure warns `VULNERABILITY_DB_FETCH_FAILED` (which says the image is
 * used), anything else that ignores a cache in the checkout `VULNERABILITY_DB_CACHE_UNTRUSTED`.
 * "Trivy disabled" is the caller's (it does not ask). An archive that is not a Trivy database
 * counts as a failed download. Never throws: a scan never fails because of this (spec §13).
 */
export async function resolveVulnerabilityDb(
  input: VulnerabilityDbInput,
): Promise<VulnerabilityDbChoice> {
  let choice: Choice | undefined;
  try {
    choice = new Choice(input);
    return await decide(choice, input);
  } catch (err) {
    input.log.debug(`choosing the vulnerability database failed: ${message(err)}`);
    if (choice === undefined) return { dir: null, warnings: [], cleanup: () => Promise.resolve() };
    await choice.cleanup();
    return choice.fallback('unexpected error');
  }
}

async function decide(c: Choice, input: VulnerabilityDbInput): Promise<VulnerabilityDbChoice> {
  if (input.endpoint === null) return c.keep();
  const meta = await fetchServerVulndb(input.endpoint, c.log);
  if (meta === 'unsupported') return c.keep();
  if ('failed' in meta) return metadataFailed(c, meta.failed);
  if (!meta.serve || meta.current === null) return c.keep();
  return served(c, input, input.endpoint, meta, meta.current);
}

/** The metadata request failed: only a cache outside the checkout, as server.json names it. */
async function metadataFailed(c: Choice, reason: string): Promise<VulnerabilityDbChoice> {
  if (!c.inside) {
    const hint = readHint(c.cache);
    if (hint !== null) {
      const used = await c.use(c.archive, (digest) => digest === hint.digest);
      if (used.ok) {
        return c.result(used.dir, [failed(shownReason(reason), cachedTail(used.updatedAt))]);
      }
    }
  }
  return c.fallback(reason);
}

async function served(
  c: Choice,
  input: VulnerabilityDbInput,
  endpoint: ServerEndpoint,
  meta: ServerVulndb,
  current: Current,
): Promise<VulnerabilityDbChoice> {
  const accepted = new Set([current.digest, ...meta.accepted]);
  const now = input.now().getTime();
  const hint = readHint(c.cache);
  const writable = c.cacheWritable();
  if (writable) prune(c.cache, c.log);
  /** Digests of archives that are not a Trivy database: never tried again. */
  const bad = new Set<string>();
  /** Why the server's database is not used, once something failed. */
  const why: { reason: string | null } = { reason: null };
  const note = (used: Used) => {
    if (used.ok || used.failure === undefined) return;
    if (used.failure.bad && used.digest !== null) bad.add(used.digest);
    why.reason = used.failure.reason;
  };
  const age = hint === null || hint.fetchedAt === null ? null : now - hint.fetchedAt;
  const fresh = age !== null && age < DAY_MS && age > -HOUR_MS;

  // The cached archive: the current one, or (daily) an accepted one fetched less than 24 h ago.
  const cached = await c.use(
    c.archive,
    (digest) =>
      digest === current.digest ||
      (meta.policy === 'daily' && accepted.has(digest) && hint?.digest === digest && fresh),
  );
  if (cached.ok) return c.result(cached.dir, []);
  note(cached);

  // Download the current archive (the cache already holds it when only its extraction failed).
  if (cached.digest !== current.digest) {
    const target = writable ? c.archive : path.join(c.workDir(), ARCHIVE);
    const mib = Math.max(1, Math.round(current.sizeBytes / 1024 / 1024));
    c.log.info(`downloading the vulnerability database from the server (${mib} MiB)`);
    const got = await downloadServerVulndb(endpoint, current.digest, current.sizeBytes, target);
    if (got.ok) {
      const used = await c.use(target, (digest) => accepted.has(digest) && !bad.has(digest));
      if (used.ok) {
        if (writable && used.digest === current.digest) {
          writeHint(
            c.cache,
            {
              digest: current.digest,
              builtAt: current.builtAt,
              fetchedAt: input.now().toISOString(),
            },
            c.log,
          );
        }
        return c.result(used.dir, []);
      }
      note(used);
      why.reason ??= 'unexpected response';
    } else {
      why.reason = got.reason;
    }
  }

  // The download failed: a cached archive the server still accepts (another scan may have just
  // fetched the current one).
  const again = await c.use(c.archive, (digest) => accepted.has(digest) && !bad.has(digest));
  if (again.ok) {
    return c.result(
      again.dir,
      again.digest === current.digest
        ? []
        : [failed(shownReason(why.reason ?? 'unexpected response'), cachedTail(again.updatedAt))],
    );
  }
  return c.fallback(why.reason ?? 'unexpected response');
}
