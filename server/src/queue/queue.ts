import { and, eq, sql, type SQL } from 'drizzle-orm';
import type { Executor } from '../db/client';
import { PG_UNIQUE_VIOLATION, pgErrorCode } from '../db/errors';
import { first } from '../db/rows';
import { jobs } from '../db/schema';

export interface Job {
  id: string;
  queue: string;
  concurrencyKey: string | null;
  payload: unknown;
  attempts: number;
  maxAttempts: number;
}

export interface EnqueueOptions {
  queue: string;
  payload: unknown;
  concurrencyKey?: string;
  /** A time, or an SQL expression on the database clock (`now() + ...`); default now(). */
  runAt?: Date | SQL;
  maxAttempts?: number;
}

export const DEFAULT_MAX_ATTEMPTS = 5;
const MAX_BACKOFF_SECONDS = 300;

type JobRow = Record<string, unknown> & {
  id: string;
  queue: string;
  concurrency_key: string | null;
  payload: unknown;
  attempts: number;
  max_attempts: number;
};

/** Pass a transaction to enqueue atomically with the rows the job will process. */
export async function enqueue(db: Executor, options: EnqueueOptions): Promise<string> {
  const rows = await db
    .insert(jobs)
    .values({
      queue: options.queue,
      payload: options.payload,
      concurrencyKey: options.concurrencyKey ?? null,
      runAt: options.runAt, // undefined → DEFAULT now(), the database clock
      maxAttempts: options.maxAttempts ?? DEFAULT_MAX_ATTEMPTS,
    })
    .returning({ id: jobs.id });
  return first(rows).id;
}

/** Several jobs in one INSERT (same semantics as {@link enqueue}); returns their ids in order. */
export async function enqueueMany(
  db: Executor,
  options: readonly EnqueueOptions[],
): Promise<string[]> {
  if (options.length === 0) return [];
  const rows = await db
    .insert(jobs)
    .values(
      options.map((o) => ({
        queue: o.queue,
        payload: o.payload,
        concurrencyKey: o.concurrencyKey ?? null,
        runAt: o.runAt,
        maxAttempts: o.maxAttempts ?? DEFAULT_MAX_ATTEMPTS,
      })),
    )
    .returning({ id: jobs.id });
  return rows.map((r) => r.id);
}

export async function claimJob(
  db: Executor,
  queue: string,
  workerId: string,
  leaseMs: number,
): Promise<Job | null> {
  try {
    const result = await db.execute<JobRow>(sql`
      UPDATE jobs
         SET status = 'running', attempts = attempts + 1, locked_by = ${workerId},
             locked_until = now() + make_interval(secs => ${leaseMs / 1000}), updated_at = now()
       WHERE id = (
         SELECT j.id FROM jobs j
          WHERE j.status = 'queued' AND j.queue = ${queue} AND j.run_at <= now()
            AND (j.concurrency_key IS NULL OR NOT EXISTS (
                  SELECT 1 FROM jobs o
                   WHERE o.concurrency_key = j.concurrency_key
                     AND (o.status = 'running' OR (o.status = 'queued' AND o.id < j.id))))
          ORDER BY j.run_at, j.id
          LIMIT 1
          FOR UPDATE SKIP LOCKED)
      RETURNING id, queue, concurrency_key, payload, attempts, max_attempts`);
    const row = result.rows[0];
    if (!row) return null;
    return {
      id: row.id,
      queue: row.queue,
      concurrencyKey: row.concurrency_key,
      payload: row.payload,
      attempts: row.attempts,
      maxAttempts: row.max_attempts,
    };
  } catch (err) {
    // Another worker started a job with the same key between our check and our update; the
    // unique partial index refused a second running row. Nothing is claimable for us right now.
    if (pgErrorCode(err) === PG_UNIQUE_VIOLATION) return null;
    throw err;
  }
}

/**
 * Marks a claimed job as succeeded, fenced on the claim token: the row is only touched when it
 * is still `running` under *this* claim (`attempts` unchanged since `claimJob` returned it, and
 * still `locked_by` this `workerId`). If the lease expired and `reapExpiredLeases` requeued and
 * someone else reclaimed the job in the meantime, `attempts` has moved on, the fence matches no
 * row, and this returns `'lost'` instead of silently freeing a slot another worker is using.
 *
 * Handlers must be idempotent and must finish well within `leaseMs`: a handler that overruns its
 * lease can still race a reclaiming worker to completion, and only the fence — not the caller —
 * decides which of them the database believes.
 */
export async function completeJob(
  db: Executor,
  job: Job,
  workerId: string,
): Promise<'completed' | 'lost'> {
  const rows = await db
    .update(jobs)
    .set({ status: 'succeeded', lockedBy: null, lockedUntil: null })
    .where(
      and(
        eq(jobs.id, job.id),
        eq(jobs.status, 'running'),
        eq(jobs.attempts, job.attempts),
        eq(jobs.lockedBy, workerId),
      ),
    )
    .returning({ id: jobs.id });
  return rows.length > 0 ? 'completed' : 'lost';
}

export function backoffSeconds(attempts: number): number {
  return Math.min(MAX_BACKOFF_SECONDS, 2 ** attempts);
}

const MAX_ERROR_MESSAGE_LENGTH = 2_000;

/**
 * Ruling S13 #4 (same reasoning as `http/logger.ts`'s `errSerializer`, task 6 review ruling S7):
 * drizzle-orm's `DrizzleQueryError` embeds the failed query *and its bind params* verbatim in its
 * `message`/`stack`. A handler's write of analysis data (engines/warnings/etc., all derived from
 * the uploaded report) failing a check constraint would otherwise put the report's own content —
 * potentially a secret, a canary string, anything a scanner found — straight into
 * `jobs.last_error`, a column with none of pino's redaction. Keep only the constructor name and
 * the Postgres SQLSTATE (if any); never the query text or its params.
 */
function isDbQueryError(error: unknown): error is Error {
  return error instanceof Error && ('query' in error || 'params' in error);
}

/** A thrown value's message, never "[object Object]" for a plain thrown object. */
function errorMessage(error: unknown): string {
  if (isDbQueryError(error)) {
    const code = pgErrorCode(error);
    return `${error.constructor.name}: database query failed${code ? ` (${code})` : ''}`;
  }
  if (error instanceof Error) return error.message;
  if (typeof error === 'string') return error;
  try {
    return JSON.stringify(error) ?? String(error);
  } catch {
    return String(error);
  }
}

/**
 * A display-safe, storable version of a thrown value: Postgres `text` rejects the NUL byte, so
 * it is stripped rather than left to reject the whole update, and the result is capped so it
 * always fits `last_error`.
 */
function describeError(error: unknown): string {
  return errorMessage(error).split('\u0000').join('').slice(0, MAX_ERROR_MESSAGE_LENGTH);
}

/**
 * Records a claimed job's failure, fenced on the claim token exactly like {@link completeJob}: if
 * the lease already expired and someone else reclaimed the job, this returns `'lost'` and leaves
 * the current claim's row untouched instead of requeuing or burying work that is no longer this
 * caller's to decide.
 */
export async function failJob(
  db: Executor,
  job: Job,
  workerId: string,
  error: unknown,
): Promise<'queued' | 'dead' | 'lost'> {
  const outcome = job.attempts >= job.maxAttempts ? 'dead' : 'queued';
  const message = describeError(error);
  const result = await db.execute(sql`
    UPDATE jobs
       SET status = ${outcome}, locked_by = NULL, locked_until = NULL, last_error = ${message},
           run_at = now() + make_interval(secs => ${backoffSeconds(job.attempts)}), updated_at = now()
     WHERE id = ${job.id} AND status = 'running' AND attempts = ${job.attempts}
       AND locked_by = ${workerId}`);
  return (result.rowCount ?? 0) > 0 ? outcome : 'lost';
}

/**
 * Pushes a running job's lease `leaseMs` past the database's `now()`, fenced on the claim exactly
 * like {@link completeJob}: once the lease has been reaped (and possibly reclaimed by another
 * worker) this returns `'lost'` and touches nothing. The worker calls it periodically while a
 * handler runs, so a long job (tracking 100k issues) never outlives its lease just by being slow.
 */
export async function extendLease(
  db: Executor,
  job: Job,
  workerId: string,
  leaseMs: number,
): Promise<'extended' | 'lost'> {
  const result = await db.execute(sql`
    UPDATE jobs
       SET locked_until = now() + make_interval(secs => ${leaseMs / 1000}), updated_at = now()
     WHERE id = ${job.id} AND status = 'running' AND attempts = ${job.attempts}
       AND locked_by = ${workerId}`);
  return (result.rowCount ?? 0) > 0 ? 'extended' : 'lost';
}

export async function reapExpiredLeases(db: Executor): Promise<number> {
  const result = await db.execute(sql`
    UPDATE jobs
       SET status = CASE WHEN attempts >= max_attempts THEN 'dead' ELSE 'queued' END,
           locked_by = NULL, locked_until = NULL, last_error = 'lease expired', updated_at = now()
     WHERE status = 'running' AND locked_until < now()`);
  return result.rowCount ?? 0;
}
