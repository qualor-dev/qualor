import { randomBytes } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import type { Executor } from '../db/client';
import { readDatasetChunks, type DatasetRow } from './store';
import { readTarGz, TarError } from './tar';

/**
 * The local, extracted copy of the current Trivy database: `trivy --cache-dir` needs files, the
 * database keeps the archive in chunks. Layout of `dir`:
 *
 *   current.json          { digest }, written atomically (temp file, rename)
 *   <16 hex of digest>/   the cache dir: db/trivy.db and db/metadata.json
 *
 * One in-process lock serialises everything that touches `dir`. {@link withLocalDatabase} holds it
 * while its callback runs, so nothing can swap or delete the directory under a re-check.
 * {@link ensureLocalDatabase} takes the lock itself (do not call it from inside a
 * `withLocalDatabase` callback: the lock is not reentrant). Replicas do not share `dir`.
 */

export type LocalProblemCode = 'DISK' | 'MISSING';
export interface LocalProblem {
  code: LocalProblemCode;
  message: string;
}
export type LocalResult = { cacheDir: string } | { problem: LocalProblem };

const DISK_CODES = new Set(['EACCES', 'EPERM', 'EROFS', 'ENOSPC', 'EDQUOT', 'ENOENT', 'ENOTDIR']);

let tail: Promise<unknown> = Promise.resolve();

/** Runs `fn` after every earlier call of `locked` has settled. */
function locked<T>(fn: () => Promise<T>): Promise<T> {
  const run = tail.then(fn, fn);
  tail = run.catch(() => undefined);
  return run;
}

const diskProblem = (dir: string, err: NodeJS.ErrnoException): LocalProblem => ({
  code: 'DISK',
  message: `The vulnerability database cannot be written to ${dir} (${err.code ?? 'error'}). Check that the directory is writable and has free space.`,
});

const isDiskError = (err: unknown): err is NodeJS.ErrnoException =>
  err instanceof Error &&
  typeof (err as NodeJS.ErrnoException).code === 'string' &&
  DISK_CODES.has((err as NodeJS.ErrnoException).code ?? '');

/** readDatasetChunks' errors for a dataset or a chunk that is gone (pruned). */
const isGone = (err: unknown): boolean =>
  err instanceof Error && /^(chunk \d+ of )?vulnerability dataset .* not found$/.test(err.message);

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

/** Names this module creates: a 16-hex digest directory or a `tmp-<12 hex>` extraction directory. */
const OWN_DIRECTORY = /^([0-9a-f]{16}|tmp-[0-9a-f]{12})$/;

/** Removes our own directories in `dir` except `keep`; every other entry is left alone. */
async function removeOthers(dir: string, keep: string): Promise<void> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory() && entry.name !== keep && OWN_DIRECTORY.test(entry.name)) {
      await rm(join(dir, entry.name), { recursive: true, force: true });
    }
  }
}

async function extract(db: Executor, dir: string, dataset: DatasetRow): Promise<LocalResult> {
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
    const found = new Set<string>();
    // Fixed target paths only: an archive entry name is never joined into a path.
    await readTarGz(
      readDatasetChunks(db, dataset.id),
      (n) => (n === 'trivy.db' ? 'stream' : n === 'metadata.json' ? 'keep' : 'skip'),
      async (entry) => {
        found.add(entry.name);
        if (entry.want === 'stream') {
          await pipeline(entry.body, createWriteStream(join(tmp, 'db', 'trivy.db')));
        } else {
          await writeFile(join(tmp, 'db', 'metadata.json'), entry.data);
        }
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
    // Anything else (a database error, a bug) propagates.
    throw err;
  }
}

/**
 * Makes `dataset` the extracted copy in `dir` and answers its cache dir. Takes the lock itself.
 * `DISK`: the directory cannot be created or written (EACCES, EPERM, EROFS, ENOSPC, EDQUOT, ENOENT,
 * ENOTDIR). `MISSING`: the chunks are gone or the archive lacks a wanted file or is damaged. Other
 * errors (database failures) are thrown.
 */
export function ensureLocalDatabase(
  db: Executor,
  dir: string,
  dataset: DatasetRow,
): Promise<LocalResult> {
  return locked(() => extract(db, dir, dataset));
}

/**
 * Ensures `dataset` locally, then runs `fn(cacheDir)` while holding the lock: a refresh or another
 * re-check waits, so the directory cannot change under `fn`. A problem is returned without
 * calling `fn`.
 */
export function withLocalDatabase<T>(
  db: Executor,
  dir: string,
  dataset: DatasetRow,
  fn: (cacheDir: string) => Promise<T>,
): Promise<{ result: T } | { problem: LocalProblem }> {
  return locked(async () => {
    const got = await extract(db, dir, dataset);
    if ('problem' in got) return got;
    return { result: await fn(got.cacheDir) };
  });
}
