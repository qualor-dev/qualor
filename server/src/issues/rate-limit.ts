import { ProblemError } from '../http/problem';

/**
 * scm.md §7, ruling G7: a bound on the issue changes (transitions and severity overrides) one user
 * can make, so a member cannot drive unbounded gate re-evaluations, webhook deliveries and GitLab
 * decorations by toggling issues. A token bucket per user, in this process's memory (like the
 * login throttle): a burst as large as one bulk transition, then a steady rate. A request is
 * charged one token per distinct issue it names, whether or not the issue changes, and is refused whole,
 * without taking anything, when the tokens are not there.
 */

/** The steady rate: issue changes per minute and user. */
export const ISSUE_CHANGES_PER_MINUTE = 120;
/** The burst: one full bulk transition (`POST /issues/bulk-transition` takes up to 500 ids). */
export const ISSUE_CHANGES_BURST = 500;

export interface IssueChangeLimiterOptions {
  perMinute: number;
  burst: number;
  now?: () => number;
  /** Users tracked at once; beyond it, full buckets (which equal no bucket) are dropped first. */
  maxKeys?: number;
}

export class IssueChangeLimiter {
  private readonly buckets = new Map<string, { tokens: number; at: number }>();
  private readonly perMs: number;
  private readonly burst: number;
  private readonly now: () => number;
  private readonly maxKeys: number;

  constructor(options: IssueChangeLimiterOptions) {
    this.perMs = options.perMinute / 60_000;
    this.burst = options.burst;
    this.now = options.now ?? Date.now;
    this.maxKeys = options.maxKeys ?? 10_000;
  }

  get size(): number {
    return this.buckets.size;
  }

  /**
   * Takes `n` tokens (at most the burst) of `key`'s bucket: null when they were there, else the
   * whole seconds to wait until they are (for `Retry-After`).
   */
  take(key: string, n: number): number | null {
    const now = this.now();
    const tokens = this.tokens(key, now);
    const need = Math.min(n, this.burst);
    if (tokens >= need) {
      this.buckets.delete(key);
      this.buckets.set(key, { tokens: tokens - need, at: now });
      if (this.buckets.size > this.maxKeys) this.evict(now);
      return null;
    }
    return Math.max(1, Math.ceil((need - tokens) / this.perMs / 1_000));
  }

  /** What {@link take} would answer, without taking anything. */
  peek(key: string, n: number): number | null {
    const tokens = this.tokens(key, this.now());
    const need = Math.min(n, this.burst);
    return tokens >= need ? null : Math.max(1, Math.ceil((need - tokens) / this.perMs / 1_000));
  }

  /** Gives `n` tokens back to `key` (a charge whose action did not happen), at most the burst. */
  refund(key: string, n: number): void {
    const bucket = this.buckets.get(key);
    if (!bucket) return;
    const now = this.now();
    const tokens = Math.min(this.burst, this.tokens(key, now) + n);
    if (tokens >= this.burst) this.buckets.delete(key);
    else this.buckets.set(key, { tokens, at: now });
  }

  private tokens(key: string, now: number): number {
    const bucket = this.buckets.get(key);
    if (!bucket) return this.burst;
    return Math.min(this.burst, bucket.tokens + (now - bucket.at) * this.perMs);
  }

  private evict(now: number): void {
    for (const key of this.buckets.keys()) {
      if (this.tokens(key, now) >= this.burst) this.buckets.delete(key);
    }
    // Still too many: the least recently charged go (their users get a full bucket back).
    for (const key of this.buckets.keys()) {
      if (this.buckets.size <= this.maxKeys) break;
      this.buckets.delete(key);
    }
  }
}

/** Charges `n` issue changes to a user, or throws 429 `RATE_LIMITED` with `Retry-After`. */
export type ChargeIssueChanges = (userId: string, n: number) => void;

/**
 * One app's G7 bound (ruling G7), shared by every route that changes issues or acts on them for a
 * person (issue transitions and severity overrides; posting an AI fix suggestion, llm.md §8.2).
 */
export function issueChangeCharge(
  limiter = new IssueChangeLimiter({
    perMinute: ISSUE_CHANGES_PER_MINUTE,
    burst: ISSUE_CHANGES_BURST,
  }),
): ChargeIssueChanges {
  return (userId, n) => {
    const wait = limiter.take(userId, n);
    if (wait !== null) {
      throw new ProblemError(429, 'RATE_LIMITED', `Too many issue changes; retry in ${wait} s`, {
        headers: { 'retry-after': String(wait) },
      });
    }
  };
}
