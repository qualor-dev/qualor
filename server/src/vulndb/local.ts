import { randomBytes } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import type { Executor } from '../db/client';
import {
  datasetEntryWant,
  isGone,
  readDatasetChunks,
  VULNDB_INFLATE_DEADLINE_MS,
  VULNDB_MAX_INFLATED_BYTES,
  type DatasetRow,
} from './store';
import { readTarGz, TarError } from '@qualor/shared/tar';

/**
 * The local, extracted copy of the current Trivy database: `trivy --cache-dir` needs files, the
 * database keeps the archive in chunks. Layout of `dir`:
 *
 *   current.json          { digest }, written atomically (temp file, rename)
 *   <16 hex of digest>/   the cache dir: db/trivy.db and db/metadata.json
 *   work-<12 hex>/        a Trivy run's work directory (vulnerabilities/trivy.ts), not this module's
 *
 * One in-process lock serialises everything that touches `dir`. {@link withLocalDatabase} holds it
 * while its callback runs, so nothing can swap or delete the directory under a re-check.
 * The lock is not reentrant: do not call {@link withLocalDatabase} from inside its callback.
 * Replicas do not share `dir`. Use a dedicated directory: every copy carries a `.qualor-vulndb`
 * marker file, and only marked directories are ever removed.
 */

export type LocalProblemCode = 'DISK' | 'MISSING' | 'BUSY';
export interface LocalProblem {
  code: LocalProblemCode;
  message: string;
}
export type LocalResult = { cacheDir: string } | { problem: LocalProblem };

/** How long a caller waits for the lock before it answers `BUSY` (longer than one Trivy run). */
export const LOCAL_LOCK_WAIT_MS = 20 * 60_000;

/** The marker file every directory this module creates carries; only marked ones are removed. */
export const OWN_MARKER = '.qualor-vulndb';

const DISK_CODES = new Set(['EACCES', 'EPERM', 'EROFS', 'ENOSPC', 'EDQUOT', 'ENOENT', 'ENOTDIR']);

let tail: Promise<unknown> = Promise.resolve();

const BUSY = Symbol('busy');

/**
 * Runs `fn` after every earlier call of `locked` has settled, or answers `BUSY` when that takes
 * longer than `waitMs`. A caller that gave up never runs `fn`, and the chain is not broken.
 *
 * One lock per process, not per directory: each process uses one `QUALOR_VULNDB_DIR` (see the
 * module doc: replicas do not share `dir`), so a global chain is enough.
 */
function locked<T>(fn: () => Promise<T>, waitMs: number): Promise<T | typeof BUSY> {
  let gaveUp = false;
  let timer: NodeJS.Timeout | undefined;
  const turn = tail.then<T | typeof BUSY>(() => {
    clearTimeout(timer);
    return gaveUp ? BUSY : fn();
  });
  tail = turn.catch(() => undefined);
  const timeout = new Promise<typeof BUSY>((resolve) => {
    timer = setTimeout(() => {
      gaveUp = true;
      resolve(BUSY);
    }, waitMs);
  });
  return Promise.race([turn, timeout]);
}

const diskProblem = (dir: string, err: NodeJS.ErrnoException): LocalProblem => ({
  code: 'DISK',
  message: `The vulnerability database cannot be written to ${dir} (${err.code ?? 'error'}). Check that the directory is writable and has free space.`,
});

const isDiskError = (err: unknown): err is NodeJS.ErrnoException =>
  err instanceof Error &&
  typeof (err as NodeJS.ErrnoException).code === 'string' &&
  DISK_CODES.has((err as NodeJS.ErrnoException).code ?? '');

const dirName = (dataset: DatasetRow): string =>
  (dataset.digest ?? '').replace(/^sha256:/, '').slice(0, 16);

const exists = (path: string): Promise<boolean> =>
  stat(path).then(
    (s) => s.isFile(),
    () => false,
  );

async function isCurrent(dir: string, name: string, digest: string): Promise<boolean> {
  try {
    const current = JSON.parse(await readFile(join(dir, 'current.json'), 'utf8')) as {
      digest?: unknown;
    };
    if (current.digest !== digest) return false;
  } catch {
    return false;
  }
  return (
    (await exists(join(dir, name, 'db', 'trivy.db'))) &&
    (await exists(join(dir, name, 'db', 'metadata.json')))
  );
}

/**
 * Names this module creates: a 16-hex digest directory or a `tmp-<12 hex>` extraction directory
 * (both carrying {@link OWN_MARKER}), and a `current.json.tmp-<12 hex>` file. The Trivy runner's
 * `work-<12 hex>` directories in `dir` (vulnerabilities/trivy.ts) are not ours: a run may be
 * using one, and the re-check removes the stale ones itself.
 */
const OWN_DIRECTORY = /^([0-9a-f]{16}|tmp-[0-9a-f]{12})$/;
const OWN_TEMP_FILE = /^current\.json\.tmp-[0-9a-f]{12}$/;

/**
 * Removes our own entries in `dir` except `keep`: marked directories and stale temp files. A
 * directory without the marker is a user's (or a copy of an older version) and stays.
 */
async function removeOthers(dir: string, keep: string): Promise<void> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isFile() && OWN_TEMP_FILE.test(entry.name)) {
      await rm(path, { force: true });
    } else if (
      entry.isDirectory() &&
      entry.name !== keep &&
      OWN_DIRECTORY.test(entry.name) &&
      (await exists(join(path, OWN_MARKER)))
    ) {
      await rm(path, { recursive: true, force: true });
    }
  }
}

/** `chunks`, cut by `signal`: once it aborts, the next chunk throws its reason. */
async function* until(
  chunks: AsyncIterable<Buffer>,
  signal: AbortSignal | undefined,
): AsyncGenerator<Buffer, void, undefined> {
  for await (const chunk of chunks) {
    signal?.throwIfAborted();
    yield chunk;
  }
}

/** Tests only: other caps for unpacking the archive than the defaults. */
export interface LocalLimits {
  maxBytes?: number;
  deadlineMs?: number;
}

async function extract(
  db: Executor,
  dir: string,
  dataset: DatasetRow,
  signal?: AbortSignal,
  limits: LocalLimits = {},
): Promise<LocalResult> {
  const digest = dataset.digest;
  if (digest === null || !/^sha256:[0-9a-f]{64}$/.test(digest)) {
    return { problem: { code: 'MISSING', message: 'The vulnerability dataset has no digest.' } };
  }
  const name = dirName(dataset);
  try {
    await mkdir(dir, { recursive: true });
    if (await isCurrent(dir, name, digest)) {
      await removeOthers(dir, name);
      return { cacheDir: join(dir, name) };
    }
  } catch (err) {
    if (isDiskError(err)) return { problem: diskProblem(dir, err) };
    throw err;
  }

  const tmp = join(dir, `tmp-${randomBytes(6).toString('hex')}`);
  try {
    await mkdir(join(tmp, 'db'), { recursive: true });
    await writeFile(join(tmp, OWN_MARKER), '');
    const found = new Set<string>();
    // Fixed target paths only: an archive entry name is never joined into a path.
    await readTarGz(
      until(readDatasetChunks(db, dataset.id), signal),
      datasetEntryWant,
      async (entry) => {
        found.add(entry.name);
        if (entry.want === 'stream') {
          await pipeline(entry.body, createWriteStream(join(tmp, 'db', 'trivy.db')));
        } else {
          await writeFile(join(tmp, 'db', 'metadata.json'), entry.data);
        }
      },
      {
        maxBytes: limits.maxBytes ?? VULNDB_MAX_INFLATED_BYTES,
        deadline: Date.now() + (limits.deadlineMs ?? VULNDB_INFLATE_DEADLINE_MS),
      },
    );
    if (!found.has('trivy.db') || !found.has('metadata.json')) {
      await rm(tmp, { recursive: true, force: true });
      return {
        problem: {
          code: 'MISSING',
          message: 'The stored vulnerability database is incomplete. Download it again.',
        },
      };
    }
    const target = join(dir, name);
    await rm(target, { recursive: true, force: true });
    await rename(tmp, target);
    const marker = join(dir, `current.json.tmp-${randomBytes(6).toString('hex')}`);
    await writeFile(marker, JSON.stringify({ digest }));
    await rename(marker, join(dir, 'current.json'));
    await removeOthers(dir, name);
    return { cacheDir: target };
  } catch (err) {
    await rm(tmp, { recursive: true, force: true }).catch(() => undefined);
    if (isDiskError(err)) return { problem: diskProblem(dir, err) };
    if (isGone(err) || err instanceof TarError) {
      return {
        problem: {
          code: 'MISSING',
          message: 'The stored vulnerability database is incomplete. Download it again.',
        },
      };
    }
    // Anything else (a database error, a bug, the signal's abort) propagates.
    throw err;
  }
}

/**
 * Ensures `dataset` locally, then runs `fn(cacheDir)` while holding the lock: a refresh or another
 * re-check waits, so the directory cannot change under `fn`. A problem is returned without
 * calling `fn`: `DISK` when the directory cannot be created or written (EACCES, EPERM, EROFS,
 * ENOSPC, EDQUOT, ENOENT, ENOTDIR), `MISSING` when the chunks are gone or the archive lacks a
 * wanted file or is damaged, `BUSY` when the lock stays taken for `lockWaitMs`; other errors (database failures) are thrown. `signal` (the server is stopping) cuts an extraction: it rejects with the
 * signal's reason, and the partial copy is removed.
 */
export function withLocalDatabase<T>(
  db: Executor,
  dir: string,
  dataset: DatasetRow,
  fn: (cacheDir: string) => Promise<T>,
  options: {
    signal?: AbortSignal | undefined;
    limits?: LocalLimits;
    /** Tests only: other than {@link LOCAL_LOCK_WAIT_MS}. */
    lockWaitMs?: number;
  } = {},
): Promise<{ result: T } | { problem: LocalProblem }> {
  const waitMs = options.lockWaitMs ?? LOCAL_LOCK_WAIT_MS;
  return locked(async () => {
    const got = await extract(db, dir, dataset, options.signal, options.limits);
    if ('problem' in got) return got;
    return { result: await fn(got.cacheDir) };
  }, waitMs).then((got) =>
    got === BUSY
      ? {
          problem: {
            code: 'BUSY' as const,
            message: `Another re-check held the local copy of the vulnerability database for too long. Try the re-check again later.`,
          },
        }
      : got,
  );
}
