import { randomBytes } from 'node:crypto';
import { createWriteStream } from 'node:fs';
import { mkdir, readdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { pipeline } from 'node:stream/promises';
import type { Executor } from '../db/client';
import { datasetEntryWant, readDatasetChunks, type DatasetRow } from './store';
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
 * Replicas do not share `dir`.
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

/**
 * Names this module creates: a 16-hex digest directory or a `tmp-<12 hex>` extraction directory.
 * The Trivy runner's `work-<12 hex>` directories in `dir` (vulnerabilities/trivy.ts) are not ours:
 * a run may be using one, and the re-check removes the stale ones itself.
 */
const OWN_DIRECTORY = /^([0-9a-f]{16}|tmp-[0-9a-f]{12})$/;

/** Removes our own directories in `dir` except `keep`; every other entry is left alone. */
async function removeOthers(dir: string, keep: string): Promise<void> {
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    if (entry.isDirectory() && entry.name !== keep && OWN_DIRECTORY.test(entry.name)) {
      await rm(join(dir, entry.name), { recursive: true, force: true });
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

async function extract(
  db: Executor,
  dir: string,
  dataset: DatasetRow,
  signal?: AbortSignal,
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
 * wanted file or is damaged; other errors (database failures) are thrown. `signal` (the server is stopping) cuts an extraction: it rejects with the
 * signal's reason, and the partial copy is removed.
 */
export function withLocalDatabase<T>(
  db: Executor,
  dir: string,
  dataset: DatasetRow,
  fn: (cacheDir: string) => Promise<T>,
  options: { signal?: AbortSignal | undefined } = {},
): Promise<{ result: T } | { problem: LocalProblem }> {
  return locked(async () => {
    const got = await extract(db, dir, dataset, options.signal);
    if ('problem' in got) return got;
    return { result: await fn(got.cacheDir) };
  });
}
