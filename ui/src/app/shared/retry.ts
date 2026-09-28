import { signal } from '@angular/core';

/** Without a usable `Retry-After`, wait this long; a longer one is capped (it is a hint). */
const DEFAULT_SECONDS = 1;
const MAX_SECONDS = 60;

/**
 * A change the server refused with 503 `CONCURRENCY_CONFLICT`, offered again once its
 * `Retry-After` has passed (`waiting` until then). The owner calls `clear()` when the change no
 * longer applies (another item, destroyed page).
 */
export class RetryOffer<T> {
  readonly pending = signal<T | null>(null);
  readonly waiting = signal(false);
  private timer: ReturnType<typeof setTimeout> | undefined;

  offer(value: T, retryAfter: number | null): void {
    this.clear();
    this.pending.set(value);
    this.waiting.set(true);
    const seconds = Math.min(retryAfter ?? DEFAULT_SECONDS, MAX_SECONDS);
    this.timer = setTimeout(() => this.waiting.set(false), seconds * 1000);
  }

  /** The pending change, once it may be sent again; the offer is then used up. */
  take(): T | null {
    if (this.waiting()) return null;
    const value = this.pending();
    this.clear();
    return value;
  }

  clear(): void {
    clearTimeout(this.timer);
    this.timer = undefined;
    this.pending.set(null);
    this.waiting.set(false);
  }
}
