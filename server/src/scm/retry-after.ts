import type { IncomingHttpHeaders } from 'node:http';

/** A `Retry-After` (or `RateLimit-Reset`) is clamped to 1 s – 15 min. */
export const MAX_RETRY_AFTER_SECONDS = 15 * 60;

/** Seconds from `Retry-After` (seconds or an HTTP date), else `RateLimit-Reset` (epoch seconds). */
export function retryAfterSeconds(headers: IncomingHttpHeaders, nowMs = Date.now()): number | null {
  const clamp = (s: number) => Math.min(MAX_RETRY_AFTER_SECONDS, Math.max(1, Math.ceil(s)));
  const retryAfter = headers['retry-after'];
  if (typeof retryAfter === 'string' && retryAfter.trim() !== '') {
    const seconds = Number(retryAfter);
    if (Number.isFinite(seconds) && seconds >= 0) return clamp(seconds);
    const date = Date.parse(retryAfter);
    if (!Number.isNaN(date)) return clamp((date - nowMs) / 1000);
  }
  const reset = headers['ratelimit-reset'];
  if (typeof reset === 'string' && /^\d{1,12}$/.test(reset)) {
    return clamp(Number(reset) - nowMs / 1000);
  }
  return null;
}
