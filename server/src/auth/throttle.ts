export interface ThrottleOptions {
  max: number;
  windowMs: number;
  maxKeys?: number;
  now?: () => number;
}

/**
 * Fixed-window counter per key, used for the per-username login limit (api.md §2). The per-IP
 * limit is @fastify/rate-limit; it cannot key on a body field. In memory and bounded: each
 * replica counts on its own, which is acceptable for a brute-force brake.
 */
export class LoginThrottle {
  private readonly hits = new Map<string, { count: number; resetAt: number }>();
  private readonly max: number;
  private readonly windowMs: number;
  private readonly maxKeys: number;
  private readonly now: () => number;

  constructor(options: ThrottleOptions) {
    this.max = options.max;
    this.windowMs = options.windowMs;
    this.maxKeys = options.maxKeys ?? 10_000;
    this.now = options.now ?? Date.now;
  }

  get size(): number {
    return this.hits.size;
  }

  hit(key: string): boolean {
    const now = this.now();
    let entry = this.hits.get(key);
    if (!entry || entry.resetAt <= now) {
      this.hits.delete(key);
      entry = { count: 0, resetAt: now + this.windowMs };
      this.hits.set(key, entry);
      if (this.hits.size > this.maxKeys) this.evict(now);
    }
    entry.count += 1;
    return entry.count <= this.max;
  }

  /** Whether `key` has used up its current window; counts no hit. */
  exhausted(key: string): boolean {
    const entry = this.hits.get(key);
    return entry !== undefined && entry.resetAt > this.now() && entry.count >= this.max;
  }

  private evict(now: number): void {
    for (const [key, value] of this.hits) {
      if (value.resetAt <= now) this.hits.delete(key);
    }
    for (const key of this.hits.keys()) {
      if (this.hits.size <= this.maxKeys) break;
      this.hits.delete(key);
    }
  }
}
