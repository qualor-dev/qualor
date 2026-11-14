import { pgErrorCode } from './errors';

/** serialization_failure (also a transition whose decision pairs changed) and deadlock_detected. */
const CONFLICTS = new Set(['40001', '40P01']);

/**
 * Runs `fn`, a whole transaction, again when it fails with SQLSTATE 40001 or 40P01 (read through
 * `cause`, as drizzle wraps driver errors): the transaction rolled back, so a new attempt starts
 * from nothing. At most `attempts` runs; the last one's error is thrown, so a caller over HTTP
 * still answers 503 `CONCURRENCY_CONFLICT`. Every other error is thrown at once.
 */
export async function withConflictRetry<T>(fn: () => Promise<T>, attempts = 3): Promise<T> {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await fn();
    } catch (err) {
      const code = pgErrorCode(err);
      if (attempt >= attempts || code === undefined || !CONFLICTS.has(code)) throw err;
    }
  }
}
