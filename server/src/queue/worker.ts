import { randomUUID } from 'node:crypto';
import { hostname } from 'node:os';
import type { FastifyBaseLogger } from 'fastify';
import type { Db } from '../db/client';
import { claimJob, completeJob, extendLease, failJob, reapExpiredLeases, type Job } from './queue';

export type JobHandler = (job: Job) => Promise<void>;
export type JobHandlers = Readonly<Record<string, JobHandler>>;
export type WorkerLogger = Pick<FastifyBaseLogger, 'info' | 'warn' | 'error'>;

export const DEFAULT_LEASE_MS = 10 * 60_000;

/** What one lease extension did: see {@link extendLease}; `'error'` means the query itself failed. */
export type HeartbeatOutcome = 'extended' | 'lost' | 'error';

export interface WorkerOptions {
  db: Db;
  handlers: JobHandlers;
  concurrency: number;
  logger: WorkerLogger;
  pollIntervalMs?: number;
  leaseMs?: number;
  reapIntervalMs?: number;
  workerId?: string;
  /**
   * Called after every reap cycle (whether or not any lease was actually reaped), so a caller can
   * reconcile domain state that depends on a job reaching a terminal state outside an explicit
   * `failJob` call — e.g. a worker that crashed mid-run, whose lease `reapExpiredLeases` moves
   * straight to `'dead'` once its attempts are exhausted, with nothing else ever told about it.
   * Kept generic here: this module has no notion of "analysis", only "job".
   */
  afterReap?: (db: Db) => Promise<void>;
  /** How often a running job's lease is extended; default `leaseMs / 3`. */
  heartbeatIntervalMs?: number;
  /** Called after every lease extension attempt (tests use it to synchronise). */
  onHeartbeat?: (job: Job, outcome: HeartbeatOutcome) => void;
}

interface LeaseOptions {
  leaseMs: number;
  heartbeatMs: number;
  onHeartbeat?: ((job: Job, outcome: HeartbeatOutcome) => void) | undefined;
}

function defaultLease(): LeaseOptions {
  return { leaseMs: DEFAULT_LEASE_MS, heartbeatMs: DEFAULT_LEASE_MS / 3 };
}

export interface Worker {
  stop(): Promise<void>;
}

async function claimNext(
  db: Db,
  handlers: JobHandlers,
  workerId: string,
  leaseMs: number,
): Promise<Job | null> {
  for (const queue of Object.keys(handlers)) {
    const job = await claimJob(db, queue, workerId, leaseMs);
    if (job) return job;
  }
  return null;
}

/**
 * Marks a completed job succeeded. `completeJob` is fenced on the claim token, so a lease that
 * expired and was reclaimed by someone else surfaces as `'lost'` here rather than as a thrown
 * error; either way, a failure to record the outcome is logged and swallowed; it must never
 * reject the caller's poll loop (`runUntilIdle`'s `for` loop, `startWorker`'s `loop`).
 */
async function settleCompletion(
  db: Db,
  job: Job,
  workerId: string,
  logger: WorkerLogger,
): Promise<void> {
  try {
    const outcome = await completeJob(db, job, workerId);
    if (outcome === 'lost') {
      logger.warn(
        { jobId: job.id, queue: job.queue, workerId },
        'lease expired before the job could be marked succeeded; another worker may already own it',
      );
    }
  } catch (err) {
    logger.error({ jobId: job.id, queue: job.queue, err }, 'failed to record job completion');
  }
}

/** The failure counterpart of {@link settleCompletion}: same fencing, same swallow-and-log. */
async function settleFailure(
  db: Db,
  job: Job,
  workerId: string,
  err: unknown,
  logger: WorkerLogger,
): Promise<void> {
  try {
    const outcome = await failJob(db, job, workerId, err);
    if (outcome === 'lost') {
      logger.warn(
        { jobId: job.id, queue: job.queue, workerId },
        'lease expired before the failure could be recorded; another worker may already own it',
      );
    } else {
      logger.warn(
        { jobId: job.id, queue: job.queue, attempts: job.attempts, outcome, err },
        'job failed',
      );
    }
  } catch (failErr) {
    logger.error({ jobId: job.id, queue: job.queue, err: failErr }, 'failed to record job failure');
  }
}

/**
 * Extends `job`'s lease every `heartbeatMs` while its handler runs, so a slow but healthy handler
 * never has its job reaped and handed to a second worker. `stop()` waits for an in-flight
 * extension, so a heartbeat can never land after (and race) the completeJob/failJob that follows.
 * A `'lost'` lease stops the heartbeat: the claim is no longer ours to extend.
 */
function startHeartbeat(
  db: Db,
  job: Job,
  workerId: string,
  lease: LeaseOptions,
  logger: WorkerLogger,
): { stop(): Promise<void> } {
  let stopped = false;
  let timer: NodeJS.Timeout | undefined;
  let inFlight: Promise<void> = Promise.resolve();
  const beat = async (): Promise<void> => {
    let outcome: HeartbeatOutcome;
    try {
      outcome = await extendLease(db, job, workerId, lease.leaseMs);
    } catch (err) {
      outcome = 'error';
      logger.warn({ jobId: job.id, queue: job.queue, err }, 'failed to extend the job lease');
    }
    if (outcome === 'lost') {
      stopped = true;
      logger.warn(
        { jobId: job.id, queue: job.queue, workerId },
        'the job lease was lost while its handler was still running; another worker may own it',
      );
    }
    lease.onHeartbeat?.(job, outcome);
  };
  const schedule = (): void => {
    if (stopped) return;
    timer = setTimeout(() => {
      inFlight = beat().then(schedule);
    }, lease.heartbeatMs);
  };
  schedule();
  return {
    stop: async () => {
      stopped = true;
      clearTimeout(timer);
      await inFlight;
    },
  };
}

/** Runs one handler for a claimed job, heartbeating its lease meanwhile. This never throws —
 *  success or failure is always recorded via `settleCompletion`/`settleFailure`, which themselves
 *  never throw. */
async function runJob(
  db: Db,
  handlers: JobHandlers,
  job: Job,
  workerId: string,
  lease: LeaseOptions,
  logger: WorkerLogger,
): Promise<void> {
  const handler = handlers[job.queue];
  const heartbeat = startHeartbeat(db, job, workerId, lease, logger);
  let failure: { err: unknown } | null = null;
  try {
    if (!handler) throw new Error(`no handler for queue "${job.queue}"`);
    await handler(job);
  } catch (err) {
    failure = { err };
  } finally {
    await heartbeat.stop();
  }
  if (failure) await settleFailure(db, job, workerId, failure.err, logger);
  else await settleCompletion(db, job, workerId, logger);
}

/** Runs claimable jobs until none is left right now (tests, one-shot tools). */
export async function runUntilIdle(
  db: Db,
  handlers: JobHandlers,
  logger: WorkerLogger,
): Promise<number> {
  const workerId = `idle:${randomUUID()}`;
  let processed = 0;
  for (;;) {
    const job = await claimNext(db, handlers, workerId, DEFAULT_LEASE_MS);
    if (!job) return processed;
    await runJob(db, handlers, job, workerId, defaultLease(), logger);
    processed += 1;
  }
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve) => {
    if (signal.aborted) {
      resolve();
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = (): void => {
      clearTimeout(timer);
      resolve();
    };
    signal.addEventListener('abort', onAbort, { once: true });
  });
}

export function startWorker(options: WorkerOptions): Worker {
  const workerId = options.workerId ?? `${hostname()}:${process.pid}:${randomUUID().slice(0, 8)}`;
  const leaseMs = options.leaseMs ?? DEFAULT_LEASE_MS;
  const pollMs = options.pollIntervalMs ?? 500;
  const reapMs = options.reapIntervalMs ?? 30_000;
  const lease: LeaseOptions = {
    leaseMs,
    heartbeatMs: options.heartbeatIntervalMs ?? leaseMs / 3,
    onHeartbeat: options.onHeartbeat,
  };
  const controller = new AbortController();
  let lastReap = 0;

  const loop = async (): Promise<void> => {
    while (!controller.signal.aborted) {
      try {
        if (Date.now() - lastReap >= reapMs) {
          lastReap = Date.now();
          const reaped = await reapExpiredLeases(options.db);
          if (reaped > 0) options.logger.warn({ reaped }, 'requeued jobs whose lease expired');
          await options.afterReap?.(options.db);
        }
        const job = await claimNext(options.db, options.handlers, workerId, leaseMs);
        if (job) {
          await runJob(options.db, options.handlers, job, workerId, lease, options.logger);
          continue;
        }
      } catch (err) {
        options.logger.error({ err }, 'job worker loop failed');
      }
      await sleep(pollMs, controller.signal);
    }
  };

  const loops = Array.from({ length: options.concurrency }, () => loop());
  return {
    stop: async () => {
      controller.abort();
      await Promise.all(loops);
    },
  };
}
