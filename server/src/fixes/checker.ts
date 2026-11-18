import { Worker } from 'node:worker_threads';
import type { FixCheckAnswer, FixCheckJob } from './check-worker';

/*
 * The server's content check of a fix upload (spec §12 B1, rulings T3g, T3k). Reading a lockfile of
 * up to 32 MiB is synchronous work of seconds and up to about 1.5 GiB, so it runs in a worker
 * thread (check-worker.ts), never on the thread that serves requests, the pattern of the review's
 * masker (review/masker.ts). Each check gets a worker of its own, which is stopped once it has
 * answered, so its memory goes with it. One check runs at a time per server process; later uploads
 * wait for it, in order. A check that passes its time cap, overflows its heap or crashes is
 * refused as `unparsable` (fail closed), naming the largest file of the upload.
 */

/** Ruling T3k: the longest a check may take, its worker's start included. */
export const FIX_CHECK_TIMEOUT_MS = 30_000;
/** Ruling T3k: the old-generation heap of a check's worker, in MiB. */
export const FIX_CHECK_HEAP_MB = 1536;

export interface FixCheckLimits {
  /** {@link FIX_CHECK_TIMEOUT_MS}. */
  timeoutMs: number;
  /** {@link FIX_CHECK_HEAP_MB}. */
  heapMb: number;
  /** The worker's code, for a test of a worker that fails. */
  workerUrl?: URL;
}

/** Why a check was given up, for the log: the time cap passed, or the worker failed. */
export type FixCheckGiveUp = 'timeout' | 'failed';

export type FixCheckOutcome = FixCheckAnswer & { gaveUp?: FixCheckGiveUp };

/**
 * Where the worker's code is, and the node options it starts with, as for the masker: next to the
 * server bundle (`dist/fix-check-worker.js`, server/scripts/bundle.ts), or from source the
 * TypeScript file, loaded through tsx.
 */
function workerEntry(): { url: URL; execArgv: string[] } {
  if (import.meta.url.endsWith('.ts')) {
    return { url: new URL('./check-worker.ts', import.meta.url), execArgv: ['--import', 'tsx'] };
  }
  return {
    url: new URL('./fix-check-worker.js', import.meta.url),
    execArgv: process.execArgv.filter((option) => option === '--enable-source-maps'),
  };
}

/**
 * The file a check that was given up names: the largest of the upload (its text at `baseSha` and
 * its new text together), the first of equals; none for an upload without files.
 */
export function largestPath(files: FixCheckJob['files']): string {
  let largest: { path: string; size: number } | null = null;
  for (const f of files) {
    const size = f.base.length + f.next.length;
    if (largest === null || size > largest.size) largest = { path: f.path, size };
  }
  return largest?.path ?? '';
}

/** Whether a worker's message is an answer of the shape it sends. */
function isAnswer(message: unknown): message is FixCheckAnswer {
  return typeof message === 'object' && message !== null && 'ok' in message;
}

/** One check on a worker of its own, within the limits; the worker is stopped after it. */
function runCheck(job: FixCheckJob, limits: FixCheckLimits): Promise<FixCheckOutcome> {
  const givenUp = (why: FixCheckGiveUp): FixCheckOutcome => ({
    ok: false,
    rule: 'unparsable',
    path: largestPath(job.files),
    gaveUp: why,
  });
  return new Promise((resolve) => {
    const { url, execArgv } =
      limits.workerUrl === undefined ? workerEntry() : { url: limits.workerUrl, execArgv: [] };
    let worker: Worker;
    try {
      worker = new Worker(url, {
        execArgv,
        workerData: job,
        resourceLimits: { maxOldGenerationSizeMb: limits.heapMb },
      });
    } catch {
      resolve(givenUp('failed'));
      return;
    }
    let settled = false;
    const settle = (outcome: FixCheckOutcome) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(outcome);
      void worker.terminate();
    };
    const timer = setTimeout(() => settle(givenUp('timeout')), limits.timeoutMs);
    worker.on('message', (message: unknown) =>
      settle(isAnswer(message) ? message : givenUp('failed')),
    );
    // A heap that overflows (ERR_WORKER_OUT_OF_MEMORY) or an exception: the error, then the exit.
    worker.on('error', () => settle(givenUp('failed')));
    worker.on('exit', () => settle(givenUp('failed')));
  });
}

/** The checks of this process, one after the other: each waits for the one before it. */
let tail: Promise<unknown> = Promise.resolve();

/**
 * Checks an upload by content in a worker thread (rulings T3g, T3k), at most one at a time per
 * process: a later call waits for the earlier ones, in the order they were made. Answers the
 * first failing rule and its file, or the lockfiles' new entries (ruling T3i). A check that takes
 * longer than `timeoutMs` (30 s), needs more heap than `heapMb` (1 536 MiB) or whose worker fails
 * is `unparsable` on {@link largestPath}, with `gaveUp` saying why. Never rejects.
 */
export function checkUploadInWorker(
  job: FixCheckJob,
  limits: Partial<FixCheckLimits> = {},
): Promise<FixCheckOutcome> {
  const resolved: FixCheckLimits = {
    timeoutMs: limits.timeoutMs ?? FIX_CHECK_TIMEOUT_MS,
    heapMb: limits.heapMb ?? FIX_CHECK_HEAP_MB,
    ...(limits.workerUrl === undefined ? {} : { workerUrl: limits.workerUrl }),
  };
  const run = tail.then(() => runCheck(job, resolved));
  tail = run;
  return run;
}
