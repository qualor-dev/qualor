import { parentPort, workerData } from 'node:worker_threads';
import {
  checkFixUpload,
  jsLockfileAdditions,
  newLockEntries,
  pythonLockfileAdditions,
  readGoSum,
  type FixFileChange,
  type FixRule,
  type FixUploadCheck,
  type LockEntry,
} from '@qualor/shared/fix';
import type { FixLockfileAdditions } from '../db/schema';

/*
 * The entry of the worker thread of a fix upload check (checker.ts, rulings T3g, T3k, T3i): it
 * checks the files it is started with by content (`checkFixUpload`, spec §12 B1) and, when they
 * pass, lists the entries each lockfile adds, then posts one answer. A hostile or huge lockfile
 * can take seconds and a lot of memory to read, so this never runs on the thread that serves
 * requests; the checker stops this thread when it takes too long. The server bundle builds this
 * file as its own entry (`dist/fix-check-worker.js`, server/scripts/bundle.ts).
 */

/** What the worker is started with (`workerData`): the fix and each file at `baseSha` and new. */
export type FixCheckJob = FixUploadCheck;

/** The worker's one answer: the first failing rule and its file, or the lockfiles' new entries. */
export type FixCheckAnswer =
  { ok: true; additions: FixLockfileAdditions[] } | { ok: false; rule: FixRule; path: string };

/** Ruling T3i: how each lockfile's new entries are read, by basename (Maven has no lockfile). */
const ADDITIONS: ReadonlyMap<string, (change: FixFileChange) => LockEntry[] | null> = new Map([
  ['package-lock.json', jsLockfileAdditions],
  ['npm-shrinkwrap.json', jsLockfileAdditions],
  ['pnpm-lock.yaml', jsLockfileAdditions],
  ['yarn.lock', jsLockfileAdditions],
  ['uv.lock', pythonLockfileAdditions],
  ['poetry.lock', pythonLockfileAdditions],
  ['go.sum', (change) => newLockEntries(readGoSum(change.base), readGoSum(change.next))],
]);

const basename = (path: string): string => path.slice(path.lastIndexOf('/') + 1);

/**
 * The new entries of every lockfile of the upload, in upload order, or the path of one that
 * cannot be read (it passed the check, so that is not expected; it fails closed all the same).
 */
function additionsOf(
  files: readonly FixFileChange[],
): { additions: FixLockfileAdditions[] } | { path: string } {
  const additions: FixLockfileAdditions[] = [];
  for (const change of files) {
    const read = ADDITIONS.get(basename(change.path));
    if (read === undefined) continue;
    const entries = read(change);
    if (entries === null) return { path: change.path };
    additions.push({
      path: change.path,
      entries: entries.map((e) => ({ slot: e.slot ?? null, name: e.name, version: e.version })),
    });
  }
  return { additions };
}

/** The check of one upload, and its lockfiles' new entries when it passes. */
function checkJob(job: FixCheckJob): FixCheckAnswer {
  const checked = checkFixUpload(job);
  if (!checked.ok) return checked;
  const found = additionsOf(job.files);
  return 'path' in found
    ? { ok: false, rule: 'unparsable', path: found.path }
    : { ok: true, ...found };
}

if (parentPort === null) throw new Error('check-worker is the entry of a worker thread');
parentPort.postMessage(checkJob(workerData as FixCheckJob));
