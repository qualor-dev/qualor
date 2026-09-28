import { describe, expect, it } from 'vitest';
import { IssueChangeLimiter } from './rate-limit';

describe('the per-user bound on issue changes (scm.md §7, ruling G7)', () => {
  it('allows a burst, then the steady rate, and says how long to wait', () => {
    let now = 0;
    const limiter = new IssueChangeLimiter({ perMinute: 120, burst: 500, now: () => now });
    expect(limiter.take('u', 500)).toBeNull(); // one full bulk transition
    expect(limiter.take('u', 1)).toBe(1); // 2 per second: half a second, rounded up
    expect(limiter.take('u', 10)).toBe(5);
    now = 500;
    expect(limiter.take('u', 1)).toBeNull();
    expect(limiter.take('u', 1)).toBe(1);
    now = 60_500;
    expect(limiter.take('u', 120)).toBeNull();
    expect(limiter.take('u', 1)).toBe(1);
  });

  it('refuses without taking anything, so a refused bulk costs nothing', () => {
    let now = 0;
    const limiter = new IssueChangeLimiter({ perMinute: 120, burst: 10, now: () => now });
    expect(limiter.take('u', 8)).toBeNull();
    expect(limiter.take('u', 5)).toBe(2);
    expect(limiter.take('u', 2)).toBeNull();
    now = 5_000;
    expect(limiter.take('u', 10)).toBeNull();
  });

  it('peeks without taking, and refunds up to the burst', () => {
    const limiter = new IssueChangeLimiter({ perMinute: 60, burst: 2, now: () => 0 });
    expect(limiter.peek('u', 1)).toBeNull();
    expect(limiter.take('u', 2)).toBeNull();
    expect(limiter.peek('u', 1)).toBe(1);
    expect(limiter.peek('u', 1)).toBe(1);
    limiter.refund('u', 1);
    expect(limiter.peek('u', 1)).toBeNull();
    expect(limiter.take('u', 1)).toBeNull();
    expect(limiter.take('u', 1)).toBe(1);
    // Never beyond the burst, and nothing for a user never charged.
    limiter.refund('u', 5);
    limiter.refund('v', 5);
    expect(limiter.take('u', 2)).toBeNull();
    expect(limiter.take('u', 1)).toBe(1);
    expect(limiter.size).toBe(1);
  });

  it('charges at most the burst, and keeps users apart', () => {
    const limiter = new IssueChangeLimiter({ perMinute: 120, burst: 10, now: () => 0 });
    expect(limiter.take('u', 11)).toBeNull();
    expect(limiter.take('u', 10)).toBe(5);
    expect(limiter.take('v', 10)).toBeNull();
    expect(limiter.take('u', 1)).toBe(1);
  });

  it('bounds its memory: a user whose bucket is full again is forgotten first', () => {
    let now = 0;
    const limiter = new IssueChangeLimiter({
      perMinute: 60,
      burst: 1,
      now: () => now,
      maxKeys: 2,
    });
    limiter.take('a', 1);
    limiter.take('b', 1);
    now = 2_000;
    limiter.take('c', 1);
    expect(limiter.size).toBeLessThanOrEqual(2);
    expect(limiter.take('c', 1)).toBe(1);
  });
});
