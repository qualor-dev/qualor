import { describe, expect, it } from 'vitest';
import { LoginThrottle } from './throttle';

describe('LoginThrottle', () => {
  it('allows max hits per window per key, then blocks until the window resets', () => {
    let now = 0;
    const throttle = new LoginThrottle({ max: 3, windowMs: 1_000, now: () => now });
    expect([throttle.hit('a'), throttle.hit('a'), throttle.hit('a'), throttle.hit('a')]).toEqual([
      true,
      true,
      true,
      false,
    ]);
    expect(throttle.hit('b')).toBe(true);
    now = 1_000;
    expect(throttle.hit('a')).toBe(true);
  });

  it('exhausted() says whether a key used its window up, without counting a hit', () => {
    let now = 0;
    const throttle = new LoginThrottle({ max: 2, windowMs: 1_000, now: () => now });
    expect(throttle.exhausted('a')).toBe(false);
    throttle.hit('a');
    expect(throttle.exhausted('a')).toBe(false);
    throttle.hit('a');
    expect([throttle.exhausted('a'), throttle.exhausted('a'), throttle.exhausted('b')]).toEqual([
      true,
      true,
      false,
    ]);
    now = 1_000;
    expect(throttle.exhausted('a')).toBe(false);
  });

  it('bounds memory by evicting expired keys, then the oldest', () => {
    const now = 0;
    const throttle = new LoginThrottle({ max: 1, windowMs: 1_000, maxKeys: 2, now: () => now });
    throttle.hit('a');
    throttle.hit('b');
    throttle.hit('c');
    expect(throttle.size).toBe(2);
    expect(throttle.hit('c')).toBe(false);
    expect(throttle.hit('a')).toBe(true); // evicted, so it starts a fresh window
  });
});
